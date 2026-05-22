import os
import time
import json
import logging
import requests
import threading
from datetime import datetime
from backend.app import config
from backend.app.database import SessionLocal, RawLog, SecurityAlert
from backend.app.redis_client import pubsub_client
from backend.app.ml_anomaly import anomaly_detector
from backend.app.correlation import correlation_engine

logger = logging.getLogger("SOC-TriageAgent")
logging.basicConfig(level=logging.INFO)

# Global flag to stop tailer
_tailer_running = False
_tailer_thread = None

# L2 Rule-Based Heuristic Analysis (Deterministic Fallback)
def generate_heuristic_l2_analysis(source: str, log: dict, score: int) -> tuple[str, str, str]:
    """
    Analyzes log fields to determine:
    (attack_type, explanation, recommendation)
    """
    attack_type = "Suspicious Activity"
    explanation = f"Flagged dynamic {source} log with threat score {score}."
    recommendation = "Investigate active network logs, monitor source IP, and verify credentials."

    if source == "network":
        syn_count = log.get("syn_flag_count", 0)
        flow_bytes = log.get("flow_bytes_s", 0)
        packet_std = log.get("packet_length_std", 0)

        if syn_count > 5:
            attack_type = "DDoS SYN Flood Attempt"
            explanation = (
                f"High frequency of SYN packets ({syn_count}) detected from source IP. "
                "The attacker is attempting to exhaust connection resources via incomplete TCP handshakes."
            )
            recommendation = (
                "Enable TCP SYN cookies on the target system. Configure edge firewalls to rate-limit "
                "or drop excessive SYN requests from this source IP."
            )
        elif flow_bytes > 300000:
            attack_type = "Potential Data Exfiltration / Flooding"
            explanation = (
                f"Massive network bandwidth consumption ({flow_bytes} bytes/sec) detected. "
                "This indicates potential large-scale unauthorized data extraction or heavy protocol flooding."
            )
            recommendation = (
                "Temporarily throttle bandwidth for this IP address. Audit egress traffic to verify "
                "if sensitive data is being transmitted to an unauthorized external network destination."
            )
        elif packet_std > 300:
            attack_type = "Anomalous Traffic Fingerprint"
            explanation = (
                f"Highly anomalous packet size standard deviation ({packet_std}) detected. "
                "This footprint strongly suggests custom tunneling tools, command & control (C2) beacons, or encrypted exfiltration."
            )
            recommendation = (
                "Conduct deep packet inspection (DPI) on the network flows between these endpoints. "
                "Check for suspicious protocol fields or custom SSH/HTTP tunnels."
            )

    elif source == "web":
        path = log.get("path", "")
        status = log.get("status_code", 200)
        ua = log.get("user_agent", "")

        if "etc/passwd" in path or "passwd" in path:
            attack_type = "Local File Inclusion (LFI) Attack"
            explanation = (
                f"Attacker attempted LFI by requesting administrative file '{path}'. "
                "They are seeking to read configuration files, system credentials, or local passwords."
            )
            recommendation = (
                "Review application code to ensure input sanitization and block file path traversal. "
                "Configure absolute paths and strict directory limitations in Nginx or Apache."
            )
        elif "UNION" in path or "'" in path or "OR" in path or "select" in path.lower():
            attack_type = "SQL Injection (SQLi) Attempt"
            explanation = (
                f"Database query syntax tokens (UNION/OR/select) found in web request URI: '{path}'. "
                "The attacker is attempting to exploit SQL injection vulnerabilities to manipulate queries."
            )
            recommendation = (
                "Enforce prepared statements with parameterized inputs in all database operations. "
                "Deploy WAF rules to reject requests containing active database keywords in query parameters."
            )
        elif status in [401, 403]:
            attack_type = "Unauthorized Web Resource Scanning"
            explanation = (
                f"Multiple failed web page visits (HTTP status {status}) on path '{path}'. "
                "This pattern is indicative of rapid automated directory structure brute forcing."
            )
            recommendation = (
                "Verify if the source user-agent is standard. Enable rate-limiting rules at the Application Gateway "
                "or block the IP if unauthorized attempts continue."
            )

    elif source == "auth":
        status = log.get("auth_status", "")
        user = log.get("user", "")

        if status == "failed":
            attack_type = "SSH/System Brute Force Attempt"
            explanation = (
                f"Failed login attempt for user accounts (Target: '{user}') detected. "
                "Multiple credential failures suggest active dictionary brute-forcing or credential stuffing."
            )
            recommendation = (
                "Implement strict account lockout policies. Mandate multi-factor authentication (MFA) for administrative access. "
                "Install and configure Fail2Ban on system auth servers to automatically block offending IPs."
            )

    elif source == "db":
        rows = log.get("rows_affected", 0)
        duration = log.get("query_duration_ms", 0)
        query = log.get("query", "")

        if rows > 100000:
            attack_type = "Database Bulk Table Exfiltration"
            explanation = (
                f"An abnormally high volume of rows ({rows}) was returned from database query: '{query}'. "
                "This suggests a security breach where a threat actor is trying to dump entire user tables."
            )
            recommendation = (
                "Immediately audit access credentials associated with the database user. "
                "Enforce hard caps on database response sizing inside the API layer."
            )
        elif duration > 10000:
            attack_type = "Resource Exhaustion SQL Injection / Denial of Service"
            explanation = (
                f"A database query took {duration} ms to execute. "
                "Slow queries can be timed SQL injection payloads (e.g. sleep calls) or queries specifically crafted to crash database pools."
            )
            recommendation = (
                "Establish strict query timeout rules. Terminate orphaned backend database processes and "
                "ensure all queries are optimized with appropriate indexing."
            )

    elif source == "cloud":
        event = log.get("event_name", "")
        mfa = log.get("mfa_used", "true")

        if event == "CreateAccessKey":
            attack_type = "Cloud Credential Persistence / Access Creation"
            explanation = (
                "IAM Access Key creation was triggered. Mutation of access keys is a common "
                "post-exploitation behavior to establish persistent backdoor access without a visual account profile."
            )
            recommendation = (
                "Immediately query the user to confirm if the API key creation was authorized. "
                "If not, revoke the API key immediately and lock the AWS user account."
            )
        elif mfa == "false" or mfa is False:
            attack_type = "Sensitive AWS IAM Call without MFA"
            explanation = (
                f"Cloud event '{event}' was executed by administrative credentials with MFA DISABLED. "
                "Operating sensitive cloud resources without MFA increases the risk of account takeover."
            )
            recommendation = (
                "Configure AWS SCPs (Service Control Policies) that deny IAM mutations if Multi-Factor Authentication (MFA) is not present. "
                "Enable absolute MFA requirements for all IAM roles."
            )

    return attack_type, explanation, recommendation


# GenAI Gemini Integration
def generate_genai_l2_analysis(source: str, log: dict, score: int) -> tuple[str, str, str]:
    """
    Attempts to call Gemini API to get intelligent security summaries.
    Falls back to rules if API fails or is not configured.
    """
    # 1. Fallback if no key is configured
    if not config.GEMINI_API_KEY:
        return generate_heuristic_l2_analysis(source, log, score)

    # 2. Call Gemini
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={config.GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}
    
    prompt = f"""
    You are an expert L2 Security Operations Center (SOC) Analyst.
    Analyze this raw suspicious security log and provide a professional, structured incident report.
    
    LOG SOURCE: {source}
    L1 SUSPICION SCORE: {score}
    RAW LOG ENTRY:
    {json.dumps(log, indent=2)}
    
    Format your response EXACTLY as a JSON object with these 3 keys:
    1. "attack_type": a concise 2-4 word categorization (e.g. "SQL Injection Attack", "SSH Brute Force")
    2. "explanation": a detailed, highly technical paragraph explaining exactly what the attacker is doing based on the log fields and why it is a risk.
    3. "recommendation": a concise bulleted list of 2-3 specific, actionable mitigation steps the client should take immediately to isolate the threat and patch the vulnerability.

    Return ONLY the raw JSON block without markdown wrappers like ```json or ```.
    """

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ]
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=5.0)
        if response.status_code == 200:
            res_data = response.json()
            # Extract text
            candidates = res_data.get("candidates", [])
            if candidates:
                text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
                # Clean markdown blocks if LLM still returned them
                if text_content.startswith("```"):
                    lines = text_content.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines[-1].startswith("```"):
                        lines = lines[:-1]
                    text_content = "\n".join(lines).strip()
                
                parsed = json.loads(text_content)
                attack_type = parsed.get("attack_type", "Suspicious Log Activity")
                explanation = parsed.get("explanation", f"Analyst review of {source} telemetry.")
                recommendation = parsed.get("recommendation", "Review active threat profile.")
                return attack_type, explanation, recommendation
        else:
            logger.warning(f"Gemini API returned status code {response.status_code}. Using deterministic SOC rule fallback.")
    except Exception as e:
        logger.error(f"Failed to communicate with Gemini API: {e}. Using deterministic SOC rule fallback.")

    return generate_heuristic_l2_analysis(source, log, score)


# Individual Log Parser & Triage Normalizer
def normalize_and_score_log(source: str, log: dict) -> dict:
    """
    Normalizes log fields across all 5 schemas and calculates base risk score.
    Returns standard dictionary layout for alerts.
    """
    # 1. Normalize IPs
    source_ip = log.get("source_ip") or log.get("ip") or log.get("client_ip") or "0.0.0.0"
    destination_ip = log.get("destination_ip") or "10.0.0.5"

    score = 0
    is_anomaly = False
    anomaly_prob = 0.0

    # 2. Run Anomaly Model if it is a network flow
    if source == "network":
        flow_bytes = float(log.get("flow_bytes_s", 0))
        flow_packets = float(log.get("flow_packets_s", 0))
        packet_std = float(log.get("packet_length_std", 0))
        
        is_anomaly, anomaly_prob = anomaly_detector.predict_anomaly(flow_bytes, flow_packets, packet_std)
        if is_anomaly:
            score += 3  # Boost L1 score if ML flags it

    # 3. Apply Deterministic L1 Rules
    if source == "network":
        if log.get("flow_bytes_s", 0) > 500000:
            score += 3
        if log.get("flow_packets_s", 0) > 3000:
            score += 2
        if log.get("syn_flag_count", 0) > 5:
            score += 2

    elif source == "web":
        path = log.get("path", "")
        status = log.get("status_code", 200)
        if "etc/passwd" in path or "UNION" in path or "'" in path or "OR" in path:
            score += 4
        if status in [401, 403]:
            score += 1

    elif source == "auth":
        status = log.get("auth_status", "")
        if status == "failed":
            score += 2

    elif source == "db":
        rows = log.get("rows_affected", 0)
        duration = log.get("query_duration_ms", 0)
        if rows > 100000:
            score += 4
        if duration > 10000:
            score += 1

    elif source == "cloud":
        event = log.get("event_name", "")
        mfa = log.get("mfa_used", "true")
        if event == "CreateAccessKey":
            score += 3
        if mfa == "false" or mfa is False:
            score += 2

    # Map L1 score to baseline Severity string
    severity = "INFO"
    if score >= 6:
        severity = "HIGH"
    elif score >= 4:
        severity = "MEDIUM"
    elif score >= 1:
        severity = "LOW"

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "l1_score": score,
        "severity": severity,
        "is_anomaly": bool(is_anomaly),
        "anomaly_prob": float(anomaly_prob)
    }


# Main tailing loop
def run_tailer():
    global _tailer_running
    logger.info("Initializing active triage watchers on log files...")

    # Log directories and files
    log_files = {
        "network": os.path.join(config.LOGS_DIR, "network_flow.log"),
        "web": os.path.join(config.LOGS_DIR, "web_access.log"),
        "auth": os.path.join(config.LOGS_DIR, "system_auth.log"),
        "db": os.path.join(config.LOGS_DIR, "db_audit.log"),
        "cloud": os.path.join(config.LOGS_DIR, "cloud_trail.log")
    }

    # Open handles and seek to end to only parse real-time newly written logs
    handles = {}
    for name, path in log_files.items():
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("")
        h = open(path, "r", encoding="utf-8")
        h.seek(0, os.SEEK_END)
        handles[name] = h
        logger.info(f"Successfully tailing log source: {os.path.basename(path)}")

    _tailer_running = True
    logger.info("L1/L2 SOC Triage Agent Daemon successfully started and listening...")

    while _tailer_running:
        new_activity = False
        
        for source, handle in handles.items():
            line = handle.readline()
            if line:
                new_activity = True
                try:
                    log_data = json.loads(line.strip())
                    
                    # 1. Store Raw Log Entry to Postgres / SQLite
                    db = SessionLocal()
                    try:
                        raw_record = RawLog(
                            source=source,
                            payload=log_data
                        )
                        db.add(raw_record)
                        db.commit()
                    except Exception as ex:
                        logger.error(f"Failed to record raw log entry: {ex}")
                        db.rollback()
                    finally:
                        db.close()

                    # 2. Normalize and Evaluate Threat Score
                    analysis = normalize_and_score_log(source, log_data)
                    source_ip = analysis["source_ip"]
                    
                    # 3. Dynamic IP Correlation & Risk Accumulation
                    db = SessionLocal()
                    try:
                        dyn_risk, should_escalate = correlation_engine.correlate_event(
                            db=db,
                            ip=source_ip,
                            source=source,
                            label=f"Suspicious Log Activity ({source.upper()})",
                            severity=analysis["severity"],
                            base_score=analysis["l1_score"]
                        )
                        db.close()
                    except Exception as ex:
                        logger.error(f"Failed correlating IP dynamic state: {ex}")
                        db.rollback()
                        db.close()
                        dyn_risk = float(analysis["l1_score"])
                        should_escalate = (dyn_risk >= 15.0)

                    # Determine ultimate threat status
                    # Alert rules: if baseline score >= 4 or ML anomaly is flagged or dynamic risk is high (escalated)
                    is_suspicious = (analysis["l1_score"] >= 4) or analysis["is_anomaly"] or should_escalate
                    
                    if is_suspicious:
                        # Escalation state
                        status = "escalated" if should_escalate else "flagged"
                        final_severity = "CRITICAL" if (should_escalate and dyn_risk > 20.0) else analysis["severity"]
                        if final_severity == "INFO" and is_suspicious:
                            final_severity = "MEDIUM" # Escalate baseline info anomalies to Medium

                        # Invoke L2 enrichment (GenAI or fallback heuristics)
                        attack_type, explanation, recommendation = generate_genai_l2_analysis(
                            source=source,
                            log=log_data,
                            score=int(dyn_risk)
                        )

                        # Create Alert representation
                        alert_id = f"alert-{int(time.time() * 1000)}-{os.urandom(3).hex()}"
                        alert_dict = {
                            "id": alert_id,
                            "timestamp": datetime.utcnow().isoformat(),
                            "source": source,
                            "source_ip": source_ip,
                            "destination_ip": analysis["destination_ip"],
                            "l1_score": int(dyn_risk), # Store final dynamic correlated risk score
                            "severity": final_severity,
                            "attack_type": attack_type,
                            "explanation": explanation,
                            "recommendation": recommendation,
                            "is_anomaly": analysis["is_anomaly"],
                            "anomaly_score": float(analysis["anomaly_prob"]),
                            "status": status,
                            "raw_payload": log_data
                        }

                        # Save Alert record to db
                        db = SessionLocal()
                        try:
                            alert_record = SecurityAlert(
                                id=alert_dict["id"],
                                timestamp=datetime.fromisoformat(alert_dict["timestamp"]),
                                source=alert_dict["source"],
                                source_ip=alert_dict["source_ip"],
                                destination_ip=alert_dict["destination_ip"],
                                l1_score=alert_dict["l1_score"],
                                severity=alert_dict["severity"],
                                attack_type=alert_dict["attack_type"],
                                explanation=alert_dict["explanation"],
                                recommendation=alert_dict["recommendation"],
                                is_anomaly=alert_dict["is_anomaly"],
                                anomaly_score=alert_dict["anomaly_score"],
                                status=alert_dict["status"],
                                raw_payload=alert_dict["raw_payload"]
                            )
                            db.add(alert_record)
                            db.commit()
                            logger.info(f"[ALERT TRIGGERED] Source: {source.upper()} | Attacker IP: {source_ip} | Dynamic Risk: {dyn_risk:.1f} | Severity: {final_severity}")
                        except Exception as ex:
                            logger.error(f"Failed to save security alert: {ex}")
                            db.rollback()
                        finally:
                            db.close()

                        # 4. Stream to WebSockets/SSE via Redis PubSub
                        try:
                            pubsub_client.publish(config.ALERT_CHANNEL, alert_dict)
                        except Exception as ex:
                            logger.error(f"Failed streaming alert over Redis: {ex}")

                except Exception as e:
                    logger.error(f"Error triage parsing incoming log line: {e}")

        # Sleep to reduce cpu cycle usage
        if not new_activity:
            time.sleep(0.1)

    # Clean handles
    for h in handles.values():
        h.close()


def start_triage_agent():
    global _tailer_thread, _tailer_running
    if _tailer_running:
        logger.warning("L1/L2 Triage tailer is already running.")
        return
    _tailer_thread = threading.Thread(target=run_tailer, daemon=True)
    _tailer_thread.start()


def stop_triage_agent():
    global _tailer_running, _tailer_thread
    logger.info("Stopping L1/L2 Triage tailer daemon...")
    _tailer_running = False
    if _tailer_thread:
        _tailer_thread.join(timeout=3.0)
        _tailer_thread = None
