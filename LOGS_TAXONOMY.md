# Security Logs Taxonomy Study Guide

This study guide explains the data structures, schemas, and attack vectors simulated by our multi-source SIEM ingestion pipeline. This documentation serves as a reference to explain the realism of our framework to mentors.

---

## 1. Network Flow Logs (`network_flow.log`)

* **Real-world equivalent**: AWS VPC Flow Logs, Suricata IPS/IDS telemetry.
* **Purpose**: Capture network packet metrics to identify volume, frequency, and connection states.

### Data Schema
| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | String (ISO 8601) | Time the event was captured. |
| `source_ip` | String | Initiating host IP. |
| `destination_ip` | String | Target host IP. |
| `destination_port` | Integer | Network service port. |
| `flow_bytes_s` | Integer | Total bytes transferred per second. |
| `flow_packets_s` | Integer | Total network packets processed per second. |
| `syn_flag_count` | Integer | Count of TCP SYN packets (high values indicate port scans). |
| `rst_flag_count` | Integer | Count of TCP RST packets (indicates port scan rejection or tear down). |
| `packet_length_std` | Integer | Standard deviation of packet sizes (anomalous values show automated tools). |

### Simulated Attack Signatures
* **SYN Flood / Port Scan**: High packet rates (`flow_packets_s > 3000`) and high `syn_flag_count` pointing to target port `22` (SSH) or `3306` (MySQL).
* **Data Exfiltration**: Extremely high byte flow (`flow_bytes_s > 500,000`) to an external or suspicious destination IP.

---

## 2. Web Access Logs (`web_access.log`)

* **Real-world equivalent**: Nginx / Apache Access Logs.
* **Purpose**: Records HTTP request paths, methods, status responses, and client agent identities.

### Data Schema
| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | String (ISO 8601) | Time the HTTP request hit the server. |
| `ip` | String | Client host IP. |
| `method` | String | HTTP method (GET, POST, etc.). |
| `path` | String | Resource request path. |
| `status_code` | Integer | HTTP response status (200, 401, 403, 404). |
| `user_agent` | String | Client identity header. |

### Simulated Attack Signatures
* **SQL Injection (SQLi)**: URI parameters containing malicious queries e.g., `/login?user=admin' OR '1'='1`.
* **Directory Traversal**: Attempts to access system files outside the web root e.g., `/etc/passwd` or `../../boot.ini`.
* **Automated Scans**: Out-of-the-box vulnerability tools flagged via specific User-Agent strings like `sqlmap/1.8.2#stable`.

---

## 3. OS Authentication Logs (`system_auth.log`)

* **Real-world equivalent**: `/var/log/auth.log` (Linux) or Windows Security Event IDs 4624/4625.
* **Purpose**: Logs user authentication statuses, administrative access promotions, and SSH daemon events.

### Data Schema
| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | String (ISO 8601) | Log generation timestamp. |
| `ip` | String | Originating client host IP. |
| `user` | String | Target login user account name. |
| `auth_status` | String | Login outcome (`success` or `failed`). |
| `process` | String | System process handling the login (`sshd`, `sudo`, `pam`). |

### Simulated Attack Signatures
* **Brute-Force Attack**: Multiple sequential failed attempts (`auth_status: failed`) targeting sensitive accounts like `root` or `administrator`.
* **Credential Stuffing**: Multiple failures across distinct user names from a single source IP.

---

## 4. Database Audit Logs (`db_audit.log`)

* **Real-world equivalent**: PostgreSQL Audit Logging (pgAudit), MongoDB slow query telemetry.
* **Purpose**: Audits query behaviors, administrative queries, and massive data pulls.

### Data Schema
| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | String (ISO 8601) | Timestamp of query execution. |
| `client_ip` | String | Host IP executing the query. |
| `db_user` | String | Database role account. |
| `query` | String | SQL / MongoDB query string. |
| `rows_affected` | Integer | Total records returned or modified by the statement. |
| `query_duration_ms` | Integer | Query computation duration. |

### Simulated Attack Signatures
* **Database Dump / Bulk Read**: Execution of wildcards like `SELECT * FROM users` returning massive records (`rows_affected > 100,000`).
* **Slow Query Attack / Denial of Service**: Inefficient SQL syntax causing high processing time (`query_duration_ms > 10,000`).

---

## 5. Cloud Identity Logs (`cloud_trail.log`)

* **Real-world equivalent**: AWS CloudTrail, Okta System Logs.
* **Purpose**: Monitor control plane API calls, credential generations, and administrative mutations.

### Data Schema
| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | String (ISO 8601) | Timestamp of the API transaction. |
| `source_ip` | String | Host initiating the cloud API request. |
| `arn` | String | Amazon Resource Name or identity reference. |
| `event_name` | String | Management API method called (`DescribeInstances`, `CreateAccessKey`). |
| `mfa_used` | String | Indicates if Multi-Factor Authentication was enabled (`true` or `false`). |

### Simulated Attack Signatures
* **MFA Bypass**: Critical operations (e.g. `CreateAccessKey`) executed without MFA verification (`mfa_used: false`).
* **Privilege Escalation**: Key provisioning outside of corporate networks or from unknown external IPs.

---

## 6. Multi-Source Threat Correlation (L1 Engine Logic)

The primary power of our **Level 1 (L1) Correlator Engine** is that it doesn't analyze logs in a vacuum. Instead, it maintains a **sliding window of activity cached by IP address**.

When a single IP generates alerts across **multiple sources** (e.g. scans a network, triggers an authentication failure, runs an injection, and executes a database dump), the L1 engine applies a **multiplication boost**:

$$\text{Final Threat Score} = \text{Sum of Individual Scores} + (\text{Number of Unique Sources} \times 2)$$

This replicates corporate-grade SIEM behavior by automatically rising the threat posture of coordinated, multi-stage attacks.
