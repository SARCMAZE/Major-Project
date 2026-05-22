# Security Logs Taxonomy & Threat Simulation Guide

This reference guide provides an educational breakdown of the **5 diverse security log sources** utilized in our real-time SOC simulation pipeline. Use this document to study, understand, and explain the architecture of your pipeline to your mentors.

---

## 1. Directory Structure

In an enterprise SIEM, log collectors forward security events to designated files on a central server. Our pipeline models this structure inside the `./logs/` directory:

```text
├── logs/
│   ├── network_flow.log    <-- Network traffic metrics (DDoS, port scans)
│   ├── web_access.log      <-- HTTP requests (SQL injection, paths)
│   ├── system_auth.log     <-- System login logs (SSH authentication)
│   ├── db_audit.log        <-- Database audit events (mass queries, drops)
│   └── cloud_trail.log     <-- Cloud management/identity API audits
```

---

## 2. Detailed Log Schemas & Attack Indicators

### 📊 Source 1: Network Flow Logs (`network_flow.log`)
* **Real-World Equivalent**: AWS VPC Flow Logs, Suricata Network IDS, NetFlow.
* **Purpose**: Tracks binary metadata of network packets entering and exiting our systems. It does not look at packet payloads, but focuses on volumes, packet sizes, and TCP flags.

#### Data Schema Example:
```json
{
  "timestamp": "2026-05-22T14:45:00.124Z",
  "source_ip": "198.51.100.42",
  "destination_ip": "10.0.0.5",
  "destination_port": 22,
  "flow_bytes_s": 420000.5,
  "flow_packets_s": 2500.0,
  "syn_flag_count": 8,
  "rst_flag_count": 0,
  "packet_length_std": 320.4
}
```

#### 🛡️ Simulated Attack Vectors (What to tell your mentor):
1. **DDoS Attack**: Indicated by extremely high network packet throughput (`flow_packets_s > 2000`) and high bandwidth (`flow_bytes_s > 300000`).
2. **SYN Flood Scan**: Indicated by a high quantity of SYN flags (`syn_flag_count > 5`) without corresponding data payloads, representing an attacker scanning for open ports.

---

### 🌐 Source 2: Web Server Access Logs (`web_access.log`)
* **Real-World Equivalent**: Nginx, Apache HTTP Server Access Logs.
* **Purpose**: Records all incoming HTTP requests made to public web applications.

#### Data Schema Example:
```json
{
  "timestamp": "2026-05-22T14:45:15.589Z",
  "ip": "198.51.100.42",
  "method": "POST",
  "path": "/login?user=admin' OR '1'='1",
  "status_code": 401,
  "user_agent": "sqlmap/1.8.2#stable"
}
```

#### 🛡️ Simulated Attack Vectors (What to tell your mentor):
1. **SQL Injection (SQLi)**: Triggered when malicious SQL keywords (`' OR '1'='1`, `UNION SELECT`) are passed into request paths or parameters.
2. **Path Traversal / Local File Inclusion (LFI)**: Detection of queries attempting to read critical OS configurations (e.g., requests containing `../../etc/passwd` or `/win.ini`).
3. **Web Brute Force**: Indicated by a high frequency of `401 Unauthorized` or `403 Forbidden` status codes from a single IP targeting dynamic authentication portals.

---

### 🔑 Source 3: OS Authentication Logs (`system_auth.log`)
* **Real-World Equivalent**: Linux system security logs (`/var/log/auth.log`), Windows Security Event Log ID 4625 (Failed Logon).
* **Purpose**: Records all user authentication attempts, shell commands, and administrative access actions.

#### Data Schema Example:
```json
{
  "timestamp": "2026-05-22T14:45:30.912Z",
  "ip": "198.51.100.42",
  "user": "root",
  "auth_status": "failed",
  "process": "sshd"
}
```

#### 🛡️ Simulated Attack Vectors (What to tell your mentor):
1. **SSH Brute-Force attack**: Characterized by a flurry of `failed` authentication attempts for high-privilege usernames (e.g., `root`, `administrator`) originating from an untrusted external IP address.
2. **Unauthorized Privilege Escalation**: Tracking successful `sudo` actions executed by standard non-privileged users immediately following failed login sequences.

---

### 🗄️ Source 4: Database Audit Logs (`db_audit.log`)
* **Real-World Equivalent**: PostgreSQL pgAudit logs, MySQL General/Slow Query Logs.
* **Purpose**: Audits query executions inside database engines, capturing structural modifications and read activities.

#### Data Schema Example:
```json
{
  "timestamp": "2026-05-22T14:45:45.002Z",
  "client_ip": "198.51.100.42",
  "db_user": "root",
  "query": "SELECT * FROM users; -- DUMPING TABLE",
  "rows_affected": 85000,
  "query_duration_ms": 12500
}
```

#### 🛡️ Simulated Attack Vectors (What to tell your mentor):
1. **Data Exfiltration (Mass Dump)**: Identified when a query fetches an abnormally large volume of records (`rows_affected > 50000`) or runs for a long duration, indicating an attacker downloading entire database tables.
2. **Unauthorized Schema Destruction**: Detections of queries containing administrative destructive actions (like `DROP DATABASE` or `DROP TABLE`) originating from standard application IPs.

---

### ☁️ Source 5: Cloud Management Logs (`cloud_trail.log`)
* **Real-World Equivalent**: AWS CloudTrail, Google Cloud Audit Logs.
* **Purpose**: Tracks identity and API administration activity within infrastructure controls.

#### Data Schema Example:
```json
{
  "timestamp": "2026-05-22T14:46:00.344Z",
  "source_ip": "198.51.100.42",
  "arn": "arn:aws:iam::123456789012:user/admin-temp",
  "event_name": "CreateAccessKey",
  "mfa_used": "false"
}
```

#### 🛡️ Simulated Attack Vectors (What to tell your mentor):
1. **Backdoor Identity Creation**: Captures administrative API calls (e.g., `CreateAccessKey`, `CreateUser`) performed from external IPs without Multi-Factor Authentication (`mfa_used: false`).
2. **Geographical Anomaly (Impossible Travel)**: Accounts logging in from IP addresses belonging to hostile subnets or distinct geological locations in a short timeframe.

---

## 3. High-Value Presentation Talking Points

When presenting this architecture to your mentors, use these talking points to establish the academic and professional value of your engineering choices:

> 💡 **Point 1: Emulating Safe DevSecOps Pipelines**
> *"Rather than relying solely on static dataset files, we engineered a continuous **Threat Emulation Engine** that generates streams of multi-layered cyber attacks in standard, industry-compliant logs. This emulates an active enterprise environment without needing to launch dangerous live exploits against production servers."*

> 💡 **Point 2: True Heuristic Log shipping**
> *"Our Level-1 Security Agent runs in the background as a real-time system watcher. It implements a file-tailing mechanism that reads the tail end of active files dynamically. This ensures that the L1 detection model is entirely decoupled from the database generation. If we hook our L1 agent to a real Apache server log folder right now, it will begin processing live cyber threats with zero code changes."*

> 💡 **Point 3: Multi-Source Threat Correlation**
> *"Standard security agents only analyze one file at a time. Our L1 agent implements a state caching engine that correlates activities across all 5 files. If a single IP address executes a port scan, fails an SSH login, and then attempts an SQL Injection, the L1 agent dynamically compiles these logs, increases the risk threat multiplier, and escalates the alert to the Level-2 Gemini AI for instant triage."*
