import os
import json
import time
import random
import logging
import threading
from datetime import datetime
from backend.app import config

logger = logging.getLogger("SOC-Emulator")

# Base assets
IPS = [f"192.168.1.{i}" for i in range(10, 100)]
ATTACKER_IPS = ["198.51.100.42", "203.0.113.88", "185.220.101.5", "45.143.203.14", "82.221.105.12"]

_emulator_running = False
_emulator_thread = None
_interval_override = None

def generate_network_log(ip: str, is_attack: bool = False) -> dict:
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

def generate_web_log(ip: str, is_attack: bool = False) -> dict:
    path = "/" if not is_attack else random.choice([
        "/admin/config.php",
        "/login?user=admin' OR '1'='1",
        "/etc/passwd",
        "/wp-admin/install.php",
        "/api/users?search=UNION SELECT NULL,username,password FROM users"
    ])
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "method": "GET" if not is_attack else "POST",
        "path": path,
        "status_code": 200 if not is_attack else random.choice([401, 403, 404]),
        "user_agent": "Mozilla/5.0" if not is_attack else "sqlmap/1.8.2#stable"
    }

def generate_auth_log(ip: str, is_attack: bool = False) -> dict:
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "user": "developer" if not is_attack else random.choice(["root", "admin", "db_root"]),
        "auth_status": "success" if not is_attack else "failed",
        "process": "sshd"
    }

def generate_db_log(ip: str, is_attack: bool = False) -> dict:
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "client_ip": ip,
        "db_user": "app_user" if not is_attack else "root",
        "query": "SELECT * FROM products WHERE id = 5" if not is_attack else "SELECT * FROM users; -- DUMPING TABLE",
        "rows_affected": random.randint(1, 10) if not is_attack else random.randint(120000, 250000),
        "query_duration_ms": random.randint(2, 20) if not is_attack else random.randint(12000, 18000)
    }

def generate_cloud_log(ip: str, is_attack: bool = False) -> dict:
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": ip,
        "arn": "arn:aws:iam::123456789012:user/developer" if not is_attack else "arn:aws:iam::123456789012:user/admin-bypass",
        "event_name": "DescribeInstances" if not is_attack else "CreateAccessKey",
        "mfa_used": "true" if not is_attack else "false"
    }

def run_emulator():
    global _emulator_running, _interval_override
    logger.info(f"Emulator threat simulation engine starting, streaming files into: {config.LOGS_DIR}")
    
    # Ensure logs folder exists
    os.makedirs(config.LOGS_DIR, exist_ok=True)

    log_paths = {
        "network": os.path.join(config.LOGS_DIR, "network_flow.log"),
        "web": os.path.join(config.LOGS_DIR, "web_access.log"),
        "auth": os.path.join(config.LOGS_DIR, "system_auth.log"),
        "db": os.path.join(config.LOGS_DIR, "db_audit.log"),
        "cloud": os.path.join(config.LOGS_DIR, "cloud_trail.log")
    }

    _emulator_running = True

    while _emulator_running:
        try:
            # Determine if this entry is a cyber attack or standard corporate activity
            is_attack = random.random() < 0.15
            ip = random.choice(IPS) if not is_attack else random.choice(ATTACKER_IPS)
            
            # Select random log stream update
            source = random.choice(["network", "web", "auth", "db", "cloud"])
            
            # Generate log content
            if source == "network":
                log = generate_network_log(ip, is_attack)
            elif source == "web":
                log = generate_web_log(ip, is_attack)
            elif source == "auth":
                log = generate_auth_log(ip, is_attack)
            elif source == "db":
                log = generate_db_log(ip, is_attack)
            else: # cloud
                log = generate_cloud_log(ip, is_attack)

            # Append JSON string to log file on disk
            target_file = log_paths[source]
            with open(target_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log) + "\n")
            
        except Exception as e:
            logger.error(f"Error generating log in emulator loop: {e}")

        # Sleep interval (ranges from config limits or override)
        current_sleep = _interval_override
        if current_sleep is None:
            current_sleep = random.uniform(config.EMULATOR_MIN_INTERVAL, config.EMULATOR_MAX_INTERVAL)
            
        time.sleep(current_sleep)


def start_emulator():
    global _emulator_thread, _emulator_running
    if _emulator_running:
        logger.warning("Emulator threat generator is already active.")
        return
    _emulator_thread = threading.Thread(target=run_emulator, daemon=True)
    _emulator_thread.start()
    logger.info("Threat Emulator daemon successfully launched.")


def stop_emulator():
    global _emulator_running, _emulator_thread
    logger.info("Stopping Threat Emulator daemon...")
    _emulator_running = False
    if _emulator_thread:
        _emulator_thread.join(timeout=3.0)
        _emulator_thread = None
    logger.info("Threat Emulator daemon successfully stopped.")


def set_emulator_speed(speed_seconds: float):
    global _interval_override
    if speed_seconds <= 0.0:
        _interval_override = None # Restore random defaults
    else:
        _interval_override = speed_seconds
    logger.info(f"Emulator stream interval manually overridden to: {speed_seconds}s")
