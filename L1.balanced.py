import json
from datetime import datetime
import statistics

INPUT_FILE  = r"C:\Users\SHREYAS KUMAR\Downloads\Combined_CIC_Data.json"
OUTPUT_FILE = r"C:\Users\SHREYAS KUMAR\Downloads\l1_output5.jsonl"
STATS_FILE  = r"C:\Users\SHREYAS KUMAR\Downloads\l1_stats.txt"

SENSITIVE_PORTS = {21, 22, 23, 3389, 445, 80, 443, 8080, 8443}

def get_float(log, key):
    try:
        return float(log.get(key, 0))
    except:
        return 0

def log_time(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

# ---------------------------
# Scoring Logic
# ---------------------------
def calculate_score(log):
    score = 0

    flow_bytes_s       = get_float(log, "flow bytes/s")
    flow_packets_s     = get_float(log, "flow packets/s")
    syn_flag           = get_float(log, "syn flag count")
    rst_flag           = get_float(log, "rst flag count")
    pkt_std            = get_float(log, "packet length std")
    down_up_ratio      = get_float(log, "down/up ratio")
    fwd_pkt_len_mean   = get_float(log, "fwd packet length mean")
    bwd_pkt_len_mean   = get_float(log, "bwd packet length mean")
    flow_iat_mean      = get_float(log, "flow iat mean")
    flow_iat_std       = get_float(log, "flow iat std")
    fwd_iat_total      = get_float(log, "fwd iat total")
    active_mean        = get_float(log, "active mean")
    idle_mean          = get_float(log, "idle mean")
    fin_flag           = get_float(log, "fin flag count")
    urg_flag           = get_float(log, "urg flag count")
    psh_flag           = get_float(log, "psh flag count")
    fwd_packets        = get_float(log, "total fwd packets")
    bwd_packets        = get_float(log, "total backward packets")
    total_packets      = fwd_packets + bwd_packets
    dst_port           = int(get_float(log, "destination port"))

    # ---------------- CORE SIGNALS ----------------
    if flow_bytes_s > 200000:
        score += 2
    elif flow_bytes_s > 100000:
        score += 1

    if flow_packets_s > 800:
        score += 2
    elif flow_packets_s > 400:
        score += 1

    if syn_flag > 3:
        score += 2
    elif syn_flag > 1:
        score += 1

    if dst_port in SENSITIVE_PORTS:
        score += 2

    # ---------------- SUPPORT SIGNALS ----------------
    if rst_flag > 2:
        score += 1

    if pkt_std > 250:
        score += 1

    if down_up_ratio > 5:
        score += 1

    if total_packets > 100:
        score += 1

    if urg_flag > 0:
        score += 2          # URG is almost always suspicious

    if fin_flag > 5:
        score += 1

    if psh_flag > 10:
        score += 1

    # ---------------- IAT / TIMING SIGNALS ----------------
    if flow_iat_mean < 500 and flow_packets_s > 300:
        score += 1          # rapid fire packets

    if flow_iat_std > 100000:
        score += 1          # highly irregular timing

    if fwd_iat_total < 1000 and fwd_packets > 50:
        score += 1          # very fast fwd bursts

    if idle_mean > 0 and active_mean > 0:
        if idle_mean / active_mean > 5:
            score += 1      # long idle then burst

    # ---------------- PACKET SIZE SIGNALS ----------------
    if fwd_pkt_len_mean < 10 and fwd_packets > 20:
        score += 1          # tiny packets = possible scan

    if bwd_pkt_len_mean > 1400:
        score += 1          # max-size backwards = bulk exfil

    if fwd_pkt_len_mean > 0 and bwd_pkt_len_mean > 0:
        ratio = bwd_pkt_len_mean / fwd_pkt_len_mean
        if ratio > 10:
            score += 1      # massive asymmetry

    # ---------------- BOOST CONDITIONS ----------------
    if syn_flag > 3 and flow_packets_s > 600:
        score += 2

    if dst_port in SENSITIVE_PORTS and total_packets > 100:
        score += 1

    if flow_bytes_s > 200000 and flow_packets_s > 800 and syn_flag > 3:
        score += 2          # triple threat combo

    if urg_flag > 0 and dst_port in SENSITIVE_PORTS:
        score += 2          # URG on sensitive port = high confidence

    if rst_flag > 2 and syn_flag > 2:
        score += 1          # SYN+RST pattern = scan/probe

    return score


# ---------------------------
# Main Processing
# ---------------------------
def process_logs():
    start = datetime.now()
    log_time("🚀 L1 Processing + Stats Collection Started")

    # Stats collectors
    stat_keys = [
        "flow bytes/s", "flow packets/s", "syn flag count",
        "rst flag count", "packet length std", "down/up ratio",
        "fwd packet length mean", "bwd packet length mean",
        "flow iat mean", "flow iat std", "fwd iat total",
        "active mean", "idle mean",
    ]
    stats       = {k: [] for k in stat_keys}
    stats["total_packets"] = []
    port_counts = {}
    protocol_counts = {}

    SAMPLE_EVERY = 10   # collect stats on every 10th row (saves memory)

    count   = 0
    flagged = 0

    with open(INPUT_FILE, "r") as f_in, open(OUTPUT_FILE, "w") as f_out:
        for line in f_in:
            try:
                log = json.loads(line)
                count += 1

                # ---------- STATS SAMPLING ----------
                if count % SAMPLE_EVERY == 0:
                    for k in stat_keys:
                        stats[k].append(get_float(log, k))
                    stats["total_packets"].append(
                        get_float(log, "total fwd packets") +
                        get_float(log, "total backward packets")
                    )
                    port = int(get_float(log, "destination port"))
                    port_counts[port] = port_counts.get(port, 0) + 1
                    proto = str(log.get("protocol", "unknown"))
                    protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

                # ---------- SCORING & FLAGGING ----------
                score = calculate_score(log)
                flag  = False

                if score >= 6:
                    flag = True

                elif (
                    get_float(log, "flow bytes/s")    > 150000 and
                    get_float(log, "flow packets/s")  > 500    and
                    get_float(log, "syn flag count")  > 1
                ):
                    flag  = True
                    score += 1

                # ---------- OUTPUT ----------
                if flag:
                    output_log = {
                        "flow_id":        log.get("flow id"),
                        "src_ip":         log.get("source ip"),
                        "src_port":       log.get("source port"),
                        "dst_ip":         log.get("destination ip"),
                        "dst_port":       log.get("destination port"),
                        "protocol":       log.get("protocol"),
                        "timestamp":      log.get("timestamp"),
                        "flow_bytes_s":   get_float(log, "flow bytes/s"),
                        "flow_packets_s": get_float(log, "flow packets/s"),
                        "total_packets":  get_float(log, "total fwd packets") + get_float(log, "total backward packets"),
                        "pkt_std":        get_float(log, "packet length std"),
                        "syn_flag":       get_float(log, "syn flag count"),
                        "rst_flag":       get_float(log, "rst flag count"),
                        "urg_flag":       get_float(log, "urg flag count"),
                        "fin_flag":       get_float(log, "fin flag count"),
                        "psh_flag":       get_float(log, "psh flag count"),
                        "down_up_ratio":  get_float(log, "down/up ratio"),
                        "fwd_pkt_len_mean": get_float(log, "fwd packet length mean"),
                        "bwd_pkt_len_mean": get_float(log, "bwd packet length mean"),
                        "flow_iat_mean":  get_float(log, "flow iat mean"),
                        "flow_iat_std":   get_float(log, "flow iat std"),
                        "active_mean":    get_float(log, "active mean"),
                        "idle_mean":      get_float(log, "idle mean"),
                        "l1_score":       score,
                        "severity": (
                            "HIGH"   if score >= 10 else
                            "MEDIUM" if score >= 7  else
                            "LOW"
                        ),
                        "status": "flagged"
                    }
                    f_out.write(json.dumps(output_log) + "\n")
                    flagged += 1

                if count % 50000 == 0:
                    elapsed = datetime.now() - start
                    log_time(f"Processed: {count:,} | Flagged: {flagged:,} | Elapsed: {elapsed}")

            except:
                continue

    # ---------------------------
    # Print + Save Stats
    # ---------------------------
    def percentile(sorted_list, p):
        if not sorted_list:
            return 0
        idx = int(len(sorted_list) * p)
        return sorted_list[min(idx, len(sorted_list) - 1)]

    lines_out = []
    lines_out.append("=" * 65)
    lines_out.append(f"  L1 STATS REPORT — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines_out.append("=" * 65)
    lines_out.append(f"  Total Processed : {count:,}")
    lines_out.append(f"  Total Flagged   : {flagged:,}")
    lines_out.append(f"  Flagged Rate    : {(flagged/count*100):.3f}%")
    lines_out.append(f"  Execution Time  : {datetime.now() - start}")
    lines_out.append("")

    all_stat_keys = stat_keys + ["total_packets"]
    for key in all_stat_keys:
        values = stats[key]
        if not values:
            continue
        vs = sorted(values)
        n  = len(vs)
        mean = sum(vs) / n
        try:
            stdev = statistics.stdev(vs)
        except:
            stdev = 0
        non_zero = [v for v in vs if v > 0]

        lines_out.append(f"📊 {key}")
        lines_out.append(f"   min={vs[0]:.2f}   max={vs[-1]:.2f}   mean={mean:.2f}   stdev={stdev:.2f}")
        lines_out.append(f"   p50={percentile(vs,0.50):.2f}   p75={percentile(vs,0.75):.2f}   p90={percentile(vs,0.90):.2f}   p95={percentile(vs,0.95):.2f}   p99={percentile(vs,0.99):.2f}")
        lines_out.append(f"   non_zero={len(non_zero):,} ({100*len(non_zero)/n:.1f}%)")
        lines_out.append("")

    lines_out.append("🔌 Top 20 Destination Ports:")
    for port, cnt in sorted(port_counts.items(), key=lambda x: -x[1])[:20]:
        lines_out.append(f"   Port {port:>6}: {cnt:>7,} flows  ({100*cnt/sum(port_counts.values()):.2f}%)")

    lines_out.append("\n📡 Protocol Distribution:")
    for proto, cnt in sorted(protocol_counts.items(), key=lambda x: -x[1]):
        lines_out.append(f"   Protocol {proto}: {cnt:,} ({100*cnt/sum(protocol_counts.values()):.2f}%)")

    full_output = "\n".join(lines_out)
    print("\n" + full_output)

    with open(STATS_FILE, "w") as sf:
        sf.write(full_output)

    log_time(f"📁 Output saved  → {OUTPUT_FILE}")
    log_time(f"📊 Stats saved   → {STATS_FILE}")
    log_time("✅ All Done!")


if __name__ == "__main__":
    process_logs()