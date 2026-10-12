# SentinelLog — Threat Model & Security Considerations

**Document Version:** 1.0.0  
**Application Version:** 2.4.0  

---

## 1. System Overview & Assets

SentinelLog is a log parsing and security incident correlation utility.

### Critical Assets:
- **Integrity of Security Reports:** Detection alerts and incident metrics must accurately reflect input logs without tampering.
- **System Availability:** The log ingestion pipeline and API must withstand oversized, malformed, or hostile log entries without resource starvation or crashing.
- **Confidentiality:** Log contents must not be leaked to unauthorized endpoints or written to untrusted directories.

---

## 2. STRIDE Threat Analysis

| STRIDE Category | Potential Threat | SentinelLog Mitigation |
| :--- | :--- | :--- |
| **Spoofing** | Attacker injects forged log lines with spoofed source IPs into plain text logs. | **Design Limitation:** SentinelLog analyzes logs as recorded; it cannot verify network origin cryptographically. Documentation explicitly warns that IP presence is not proof of attribution. |
| **Tampering** | Concurrent processes corrupt or partially overwrite generated JSON security reports during write. | **Mitigation:** Safe atomic writes using `tempfile.NamedTemporaryFile` + `os.fsync()` + `os.replace()`. |
| **Repudiation** | Analyst or auditor cannot verify how an incident was grouped. | **Mitigation:** Every incident includes constituent `alert_ids`, full `evidence` snapshots, and human-readable `correlation_reasons`. |
| **Information Disclosure** | Stack traces, server file paths, or private data leak in API error responses. | **Mitigation:** Production error handlers sanitize outputs, return structured JSON HTTP errors (`{"error": "...", "detail": "..."}`), and avoid printing secrets. |
| **Denial of Service** | Oversized log files or ReDoS input cause out-of-memory or CPU hangs. | **Mitigation:** Streaming ingestion generators ($O(1)$ memory), 50 MB max file limits, and 4,096 char line truncation limits. |
| **Elevation of Privilege** | Container execution compromised by root breakout. | **Mitigation:** Dockerfile runs as unprivileged user `sentinel` (UID 10001) with read-only application files. |

---

## 3. Realistic Limitations & Disclaimers

1. **Rule-Based Indicators Only:** SentinelLog evaluates deterministic patterns. It is not an AI/ML anomaly detection system and cannot detect zero-day techniques outside its configured rules.
2. **Not a Production SIEM:** Built as a lightweight portfolio and demonstration tool. It does not replace enterprise SIEMs like Splunk, Microsoft Sentinel, or Wazuh.
3. **Attribution Boundary:** An IPv4 address is an endpoint identifier (often a shared NAT, corporate proxy, or VPN egress), never a verified individual human actor.
