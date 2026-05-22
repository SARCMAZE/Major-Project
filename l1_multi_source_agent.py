import os
import time
import json
from collections import defaultdict
from datetime import datetime

LOG_DIR = "./logs"
OUTPUT_FILE = "./data/dataset.jsonl"
os.makedirs("./data", exist_ok=True)

# IP threat state history
ip_activity_cache = defaultdict(lambda: {
    "network_alerts": 0,
    "failed_logins": 0,
    "web_anomalies": 0,
    "db_dumps": 0,
    "cloud_anomalies": 0,
    "timestamp": datetime.now()
})

def calculate_multi_source_score(ip, source, log):
    score = 0
    cache = ip_activity_cache[ip]
    cache["timestamp"] = datetime.now()
    
    # 1. Individual Source Rules
    if source == "network":
        bytes_s = log.get("flow_bytes_s", 0)
        packets_s = log.get("flow_packets_s", 0)
        if bytes_s > 500000: score += 3
        if packets_s > 3000: score += 2
        if log.get("syn_flag_count", 0) > 5: score += 2
        
    elif source == "web":
        path = log.get("path", "")
        status = log.get("status_code", 200)
        if "etc/passwd" in path or "UNION" in path or "'" in path:
            score += 4
            cache["web_anomalies"] += 1
        if status in [401, 403]:
            score += 1
            
    elif source == "auth":
        status = log.get("auth_status", "")
        if status == "failed":
            score += 2
            cache["failed_logins"] += 1
            
    elif source == "db":
        rows = log.get("rows_affected", 0)
        duration = log.get("query_duration_ms", 0)
        if rows > 100000:
            score += 4
            cache["db_dumps"] += 1
        if duration > 10000:
            score += 1
            
    elif source == "cloud":
        event = log.get("event_name", "")
        mfa = log.get("mfa_used", "true")
        if event == "CreateAccessKey":
            score += 3
            cache["cloud_anomalies"] += 1
        if mfa == "false":
            score += 2

    # 2. Multi-Source Correlation (Threat Multiplier)
    # Attackers executing complex chains should be boosted
    sources_triggered = sum([
        1 if cache["failed_logins"] > 0 else 0,
        1 if cache["web_anomalies"] > 0 else 0,
        1 if cache["db_dumps"] > 0 else 0,
        1 if cache["cloud_anomalies"] > 0 else 0,
    ])
    
    if sources_triggered >= 2:
        score += (sources_triggered * 2)  # Boost score by 4, 6 or 8

    return score

def watch_logs():
    print("[L1 CORRELATOR DAEMON] Initializing active watchers on ./logs/ directory...")
    
    files = {
        "network": f"{LOG_DIR}/network_flow.log",
        "web": f"{LOG_DIR}/web_access.log",
        "auth": f"{LOG_DIR}/system_auth.log",
        "db": f"{LOG_DIR}/db_audit.log",
        "cloud": f"{LOG_DIR}/cloud_trail.log"
    }
    
    # Open handles and seek to end to read only new logs
    handles = {}
    for name, path in files.items():
        if not os.path.exists(path):
            open(path, "w").close()
        h = open(path, "r")
        h.seek(0, os.SEEK_END)
        handles[name] = h
        print(f"[*] Tailing active file: {os.path.basename(path)}")
        
    print(f"[+] Alert database initialized: {os.path.abspath(OUTPUT_FILE)}")
    print("\n[>>>] L1 Correlation Daemon is listening for security threats in real-time...\n")
    
    while True:
        new_activity = False
        for source, handle in handles.items():
            line = handle.readline()
            if line:
                new_activity = True
                try:
                    log = json.loads(line.strip())
                    ip = log.get("source_ip") or log.get("ip") or log.get("client_ip")
                    if not ip: continue
                    
                    score = calculate_multi_source_score(ip, source, log)
                    
                    if score >= 6:
                        severity = "HIGH" if score >= 10 else "MEDIUM"
                        alert = {
                            "flow id": f"alert-{int(time.time()*1000)}",
                            "source ip": ip,
                            "destination ip": log.get("destination_ip", "10.0.0.5"),
                            "label": f"Suspicious Activity ({source.upper()})",
                            "l1_score": score,
                            "severity": severity,
                            "status": f"Flagged dynamic {source} log with threat score {score}.",
                            "timestamp": log.get("timestamp")
                        }
                        
                        # Write straight to Next.js data directory
                        with open(OUTPUT_FILE, "a") as f_out:
                            f_out.write(json.dumps(alert) + "\n")
                            
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] [ALERT] ALERT TRIGGERED [{severity}] - Source: {source.upper()} [ALERT]")
                        print(f"   IP: {ip} | Score: {score} | Threat: Correlated {source.upper()} Threat")
                        print(f"   Reason: Flagged dynamic {source} log with threat score {score}.\n")
                except Exception as e:
                    print(f"Error parsing line: {e}")
                    
        if not new_activity:
            time.sleep(0.1) # Cool down CPU

if __name__ == "__main__":
    watch_logs()
