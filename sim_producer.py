import json
import time
import random
from datetime import datetime
import os

LOG_DIR = "./logs"
os.makedirs(LOG_DIR, exist_ok=True)

IPS = [f"192.168.1.{i}" for i in range(10, 100)]
ATTACKER_IPS = ["198.51.100.42", "203.0.113.88", "185.220.101.5"]

def generate_network_log(ip, is_attack=False):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": ip,
        "destination_ip": "10.0.0.5",
        "destination_port": random.choice([80, 443, 22, 3306]) if not is_attack else 22,
        "flow_bytes_s": random.randint(1000, 15000) if not is_attack else random.randint(300000, 800000),
        "flow_packets_s": random.randint(10, 200) if not is_attack else random.randint(2000, 5000),
        "syn_flag_count": 0 if not is_attack else random.choice([0, 10]),
        "rst_flag_count": 0,
        "packet_length_std": random.randint(50, 150) if not is_attack else random.randint(300, 600)
    }

def generate_web_log(ip, is_attack=False):
    path = "/" if not is_attack else random.choice(["/admin/config.php", "/login?user=admin' OR '1'='1", "/etc/passwd"])
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "method": "GET" if not is_attack else "POST",
        "path": path,
        "status_code": 200 if not is_attack else random.choice([401, 403, 404]),
        "user_agent": "Mozilla/5.0" if not is_attack else "sqlmap/1.8.2#stable"
    }

def generate_auth_log(ip, is_attack=False):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "user": "developer" if not is_attack else "root",
        "auth_status": "success" if not is_attack else "failed",
        "process": "sshd"
    }

def generate_db_log(ip, is_attack=False):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "client_ip": ip,
        "db_user": "app_user" if not is_attack else "root",
        "query": "SELECT * FROM products WHERE id = 5" if not is_attack else "SELECT * FROM users; -- DUMPING TABLE",
        "rows_affected": random.randint(1, 10) if not is_attack else random.randint(50000, 200000),
        "query_duration_ms": random.randint(2, 20) if not is_attack else random.randint(5000, 15000)
    }

def generate_cloud_log(ip, is_attack=False):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": ip,
        "arn": "arn:aws:iam::123456789012:user/developer" if not is_attack else "arn:aws:iam::123456789012:user/admin-bypass",
        "event_name": "DescribeInstances" if not is_attack else "CreateAccessKey",
        "mfa_used": "true" if not is_attack else "false"
    }

def stream_logs():
    print("[*] Starting simulated security log streams...")
    while True:
        # Determine if we spawn a normal log or an attack cycle
        is_attack = random.random() < 0.15
        ip = random.choice(IPS) if not is_attack else random.choice(ATTACKER_IPS)
        
        # Randomly choose which log source updates
        source = random.choice(["network", "web", "auth", "db", "cloud"])
        
        if source == "network":
            log = generate_network_log(ip, is_attack)
            with open(f"{LOG_DIR}/network_flow.log", "a") as f:
                f.write(json.dumps(log) + "\n")
                
        elif source == "web":
            log = generate_web_log(ip, is_attack)
            with open(f"{LOG_DIR}/web_access.log", "a") as f:
                f.write(json.dumps(log) + "\n")
                
        elif source == "auth":
            log = generate_auth_log(ip, is_attack)
            with open(f"{LOG_DIR}/system_auth.log", "a") as f:
                f.write(json.dumps(log) + "\n")
                
        elif source == "db":
            log = generate_db_log(ip, is_attack)
            with open(f"{LOG_DIR}/db_audit.log", "a") as f:
                f.write(json.dumps(log) + "\n")
                
        elif source == "cloud":
            log = generate_cloud_log(ip, is_attack)
            with open(f"{LOG_DIR}/cloud_trail.log", "a") as f:
                f.write(json.dumps(log) + "\n")
                
        time.sleep(random.uniform(0.1, 0.8)) # Variable streaming speed

if __name__ == "__main__":
    stream_logs()
