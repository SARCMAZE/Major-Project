"""L3 Processor - LSTM-based final review over L2 output.

This stage reads L2 JSONL records, builds short sequences of flow-level
features, trains a compact LSTM autoencoder, and emits a final review record
for each alert with a reconstruction-based pattern score.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset


DEFAULT_INPUT = "l2_output1-6PP.JSONL"
DEFAULT_OUTPUT = "l3_output_review.jsonl"

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def parse_args():
    parser = argparse.ArgumentParser(description="L3 Processor - LSTM final review over L2 output")
    parser.add_argument("--input", "-i", default=DEFAULT_INPUT)
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT)
    parser.add_argument("--window-size", type=int, default=8)
    parser.add_argument("--hidden-size", type=int, default=48)
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--learning-rate", type=float, default=0.0015)
    parser.add_argument("--max-records", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def safe_float(value, default=0.0):
    try:
        if value in (None, ""):
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def parse_timestamp(value):
    if not value:
        return None

    text = str(value).strip()
    candidates = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
    ]

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        pass

    for fmt in candidates:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def stable_hash(text, modulus=1000):
    if text in (None, ""):
        return 0.0
    digest = hashlib.sha1(str(text).encode("utf-8")).hexdigest()
    return (int(digest[:8], 16) % modulus) / float(modulus)


def severity_to_number(severity):
    try:
        return float(SEVERITY_ORDER.index(str(severity).upper()) + 1)
    except Exception:
        return 0.0


def protocol_to_number(protocol):
    if protocol in (None, ""):
        return 0.0
    try:
        number = int(float(protocol))
        return float(number)
    except Exception:
        text = str(protocol).upper()
        mapping = {"ICMP": 1.0, "TCP": 6.0, "UDP": 17.0}
        return mapping.get(text, 0.0)


def normalized_port(value):
    return math.log1p(max(0.0, safe_float(value, 0.0)))


def normalized_value(value):
    return math.log1p(max(0.0, safe_float(value, 0.0)))


def unpack_l2_analysis(record):
    raw = record.get("l2_analysis")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}


def load_l2_records(input_path, max_records=None):
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    records = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append(record)

    def sort_key(record):
        timestamp = parse_timestamp(record.get("timestamp"))
        return timestamp or datetime.min

    records.sort(key=sort_key)

    if max_records and len(records) > max_records:
        step = max(1, len(records) // max_records)
        records = records[::step][:max_records]

    return records


def build_feature_matrix(records):
    rows = []
    for record in records:
        analysis = unpack_l2_analysis(record)
        timestamp = parse_timestamp(record.get("timestamp"))
        hour_of_day = float(timestamp.hour + timestamp.minute / 60.0) if timestamp else 0.0

        flow_bytes = safe_float(record.get("flowBytesPerSec", record.get("flow_bytes_s", 0.0)), 0.0)
        flow_packets = safe_float(record.get("flowPacketsPerSec", record.get("flow_packets_s", 0.0)), 0.0)
        total_packets = safe_float(record.get("total_packets", 0.0), 0.0)
        l1_score = safe_float(record.get("l1Score", record.get("l1_score", 0.0)), 0.0)

        l2_risk = safe_float(analysis.get("risk_score"), 0.0)
        l2_confidence = safe_float(analysis.get("confidence_score"), 0.0)
        attack_type = analysis.get("attack_type") or record.get("attackType") or record.get("label") or "Unknown"

        row = np.array(
            [
                l1_score,
                normalized_value(flow_bytes),
                normalized_value(flow_packets),
                normalized_value(total_packets),
                normalized_port(record.get("dstPort", record.get("dst_port", 0.0))),
                normalized_port(record.get("srcPort", record.get("src_port", 0.0))),
                protocol_to_number(record.get("protocol")),
                severity_to_number(record.get("severity")),
                l2_risk,
                l2_confidence,
                stable_hash(record.get("srcIp") or record.get("src_ip")),
                stable_hash(record.get("dstIp") or record.get("dst_ip")),
                stable_hash(attack_type),
                hour_of_day / 24.0,
                normalized_value(flow_bytes / (flow_packets + 1.0)),
                float(record.get("confidence", 0.0) or 0.0),
            ],
            dtype=np.float32,
        )
        rows.append(row)

    return np.vstack(rows)


def build_windows(features, window_size):
    windows = []
    for index in range(len(features)):
        start = max(0, index - window_size + 1)
        window = features[start : index + 1]
        if len(window) < window_size:
            pad_source = window[:1] if len(window) else np.zeros((1, features.shape[1]), dtype=np.float32)
            pad = np.repeat(pad_source, window_size - len(window), axis=0)
            window = np.vstack([pad, window]) if len(window) else pad
        windows.append(window)
    return np.stack(windows).astype(np.float32)


def normalize(features):
    mean = features.mean(axis=0, keepdims=True)
    std = features.std(axis=0, keepdims=True)
    std[std < 1e-6] = 1.0
    return (features - mean) / std, mean, std


class LSTMAutoEncoder(nn.Module):
    def __init__(self, input_size, hidden_size):
        super().__init__()
        self.encoder = nn.LSTM(input_size=input_size, hidden_size=hidden_size, batch_first=True)
        self.decoder = nn.LSTM(input_size=hidden_size, hidden_size=hidden_size, batch_first=True)
        self.output = nn.Linear(hidden_size, input_size)

    def forward(self, inputs):
        _, (hidden, _) = self.encoder(inputs)
        latent = hidden[-1]
        repeated = latent.unsqueeze(1).repeat(1, inputs.size(1), 1)
        decoded, _ = self.decoder(repeated)
        return self.output(decoded)


def train_model(model, loader, epochs, learning_rate, verbose=False):
    device = torch.device("cpu")
    model.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    loss_fn = nn.MSELoss()

    model.train()
    for epoch in range(epochs):
        running_loss = 0.0
        batches = 0
        for batch in loader:
            inputs = batch[0].to(device)
            optimizer.zero_grad(set_to_none=True)
            outputs = model(inputs)
            loss = loss_fn(outputs, inputs)
            loss.backward()
            optimizer.step()
            running_loss += float(loss.item())
            batches += 1

        if verbose:
            average_loss = running_loss / batches if batches else 0.0
            print(f"Epoch {epoch + 1}/{epochs} - loss: {average_loss:.6f}")


def reconstruction_errors(model, windows):
    device = torch.device("cpu")
    model.eval()
    errors = []
    with torch.no_grad():
        for window in windows:
            inputs = torch.from_numpy(window).unsqueeze(0).to(device)
            outputs = model(inputs)
            error = torch.mean((outputs - inputs) ** 2).item()
            errors.append(error)
    return np.array(errors, dtype=np.float32)


def derive_review(record, pattern_score, anomaly_score):
    analysis = unpack_l2_analysis(record)
    l2_attack = analysis.get("attack_type") or "Unknown"
    l2_risk = safe_float(analysis.get("risk_score"), 0.0)
    l2_confidence = safe_float(analysis.get("confidence_score"), 0.0)

    is_flagged = False

    if pattern_score >= 80 or l2_risk >= 8:
        final_review = "Critical Escalation"
        severity = "CRITICAL"
        recommendation = "Escalate immediately, isolate the source, and review adjacent flows for spread."
        is_flagged = True
        explanation = (
            f"LSTM reconstruction is highly anomalous ({pattern_score:.1f}/100) and L2 already flagged "
            f"{l2_attack} with high risk."
        )
    elif pattern_score >= 55 or l2_risk >= 6:
        final_review = "High-Risk Pattern"
        severity = "HIGH"
        recommendation = "Correlate with surrounding traffic, confirm with logs, and prepare containment actions."
        is_flagged = True
        explanation = f"LSTM found a strong recurring anomaly pattern ({pattern_score:.1f}/100) over the L2 signals."
    elif pattern_score >= 40 and (l2_risk >= 4 or l2_confidence <= 0.45):
        final_review = "Guarded Pattern"
        severity = "MEDIUM"
        recommendation = "Monitor the host, inspect related flows, and keep a short-term watchlist."
        is_flagged = True
        explanation = f"The sequence is mildly unusual ({pattern_score:.1f}/100) but not yet critical."
    else:
        final_review = "Low Concern"
        severity = "LOW"
        recommendation = "Continue monitoring; no immediate containment is required."
        explanation = f"The LSTM reconstruction is stable and the sequence looks normal ({pattern_score:.1f}/100)."

    confidence = min(1.0, 0.28 + (pattern_score / 180.0) + (l2_confidence * 0.45))
    derived_risk = int(max(0, min(10, round(max(l2_risk, pattern_score / 12.0)))))

    return {
        "final_review": final_review,
        "attack_type": final_review,
        "risk_score": derived_risk,
        "confidence_score": round(confidence, 2),
        "pattern_score": round(float(pattern_score), 2),
        "anomaly_score": round(float(anomaly_score), 6),
        "severity": severity,
        "is_flagged": is_flagged,
        "explanation": explanation,
        "recommendation": recommendation,
        "source_attack_type": l2_attack,
        "source_risk_score": round(l2_risk, 2),
    }


def write_output(records, analyses, output_path):
    path = Path(output_path)
    written = 0
    with path.open("w", encoding="utf-8") as handle:
        for record, analysis in zip(records, analyses):
            if not analysis.get("is_flagged"):
                continue
            enriched = dict(record)
            enriched["l3_analysis"] = analysis
            enriched["severity"] = analysis["severity"]
            enriched["status"] = "reviewed"
            handle.write(json.dumps(enriched, ensure_ascii=False) + "\n")
            written += 1

    if written == 0:
        ranked = sorted(
            zip(records, analyses),
            key=lambda item: item[1].get("pattern_score", 0.0),
            reverse=True,
        )[: min(5, len(records))]
        with path.open("w", encoding="utf-8") as handle:
            for record, analysis in ranked:
                enriched = dict(record)
                enriched["l3_analysis"] = analysis
                enriched["severity"] = analysis["severity"]
                enriched["status"] = "reviewed"
                enriched["l3_analysis"]["is_flagged"] = True
                handle.write(json.dumps(enriched, ensure_ascii=False) + "\n")
        written = len(ranked)

    return written


def main():
    args = parse_args()
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)

    records = load_l2_records(args.input, max_records=args.max_records)
    if not records:
        raise RuntimeError(f"No L2 records found in {args.input}")

    features = build_feature_matrix(records)
    normalized_features, _, _ = normalize(features)
    windows = build_windows(normalized_features, args.window_size)

    tensor = torch.from_numpy(windows)
    loader = DataLoader(TensorDataset(tensor), batch_size=args.batch_size, shuffle=True, drop_last=False)

    model = LSTMAutoEncoder(input_size=windows.shape[-1], hidden_size=args.hidden_size)
    train_model(model, loader, args.epochs, args.learning_rate, verbose=args.verbose)

    errors = reconstruction_errors(model, windows)
    threshold = float(np.percentile(errors, 90)) if len(errors) > 1 else float(errors.max() if len(errors) else 1.0)
    threshold = threshold if threshold > 1e-8 else 1.0

    analyses = []
    for record, error in zip(records, errors):
        pattern_score = min(100.0, (error / threshold) * 100.0)
        analyses.append(derive_review(record, pattern_score, error))

    written = write_output(records, analyses, args.output)

    average_pattern = float(np.mean([item["pattern_score"] for item in analyses]))
    critical_count = sum(1 for item in analyses if item["severity"] == "CRITICAL")
    high_count = sum(1 for item in analyses if item["severity"] == "HIGH")
    flagged_count = sum(1 for item in analyses if item["is_flagged"])

    print(f"L3 complete. Input alerts: {len(records):,}")
    print(f"Average pattern score: {average_pattern:.2f}")
    print(f"Critical reviews: {critical_count:,} | High reviews: {high_count:,} | Flagged for output: {flagged_count:,}")
    print(f"Rows written to L3 output: {written:,}")
    print(f"Output written to: {args.output}")


if __name__ == "__main__":
    main()