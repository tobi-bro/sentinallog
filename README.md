# SentinelLog 🛡️

**A Modular Security Log Analysis, Threat Detection & Incident Investigation Platform.**

[![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-70%20Passed-brightgreen.svg)](tests/)
[![Security: Bandit](https://img.shields.io/badge/Security-Bandit%20Clean-success.svg)](https://github.com/PyCQA/bandit)
[![Dependencies: pip--audit](https://img.shields.io/badge/Dependencies-Audited%20Clean-success.svg)](https://github.com/pypa/pip-audit)
[![Docker](https://img.shields.io/badge/Docker-Non--Root%20Hardened-blue.svg)](Dockerfile)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-blue.svg)](.github/workflows/tests.yml)

SentinelLog parses application logs, identifies suspicious security indicators (such as repeated failed logins and unauthorized access attempts), correlates related alerts into time-bounded incidents, and provides interactive triage through an interactive CLI, a REST API, and a modern Web Dashboard.

---

## 🌟 Key Features

* **Secure Streaming Ingestion:** Memory-efficient generator streaming with 50 MB max file limits and 4,096 char line truncation guards.
* **Strict Validation:** IPv4 octet bounds (`0–255`) and ISO-8601 timestamp parsing.
* **Threat Detection Engine:**
  * `RULE-AUTH-001`: Repeated failed logins (configurable 3 attempts within rolling 5-minute window).
  * `RULE-AUTH-002`: Unauthorized access indicator detection.
* **Incident Correlation (Anti-Chaining):**
  * Correlates alerts by source IPv4 within a strict 5-minute rolling window.
  * Invariant: $\text{last\_seen} - \text{first\_seen} \le \text{window\_minutes}$, preventing transitive chaining from bridging unrelated events.
  * Deterministic RFC 4122 v5 incident UUIDs.
* **Delivery Interfaces:**
  * **Interactive Terminal CLI:** Rich menu with statistics, alert reviews, and incident breakdowns.
  * **FastAPI REST API:** Headless triage endpoints (`/health`, `/api/v1/analyze`, `/api/v1/incidents`).
  * **Web SOC Dashboard:** Glassmorphic dark-mode web interface with timeline cards and report exports.
* **Atomic JSON Reports:** Corruption-resistant atomic file replacement using temporary files and `os.replace`.
* **DevSecOps & Containerization:** Hardened non-root `Dockerfile` (UID 10001) and CI pipeline.

---

## 🏗️ Architecture

```text
Raw Logs ──> [1. Secure Ingestion] ──> [2. Parser & Normalizer]
                                                 │
                                                 ▼
                                      [3. Threat Detection]
                                                 │
                                                 ▼
                                      [4. Incident Correlator]
                                                 │
                                 ┌───────────────┴───────────────┐
                                 ▼                               ▼
                      [5. Atomic Reporting]          [6. Delivery Layers]
                      security_report.json            • Interactive CLI
                                                      • FastAPI REST API
                                                      • Web SOC Dashboard
```

Detailed architectural diagrams and layer descriptions are available in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🚀 Quickstart Guide

### 1. Clone & Set Up (Windows PowerShell)

```powershell
# Clone repository
git clone https://github.com/tobi-bro/sentinellog.git
cd sentinellog

# Create and activate virtual environment
py -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Interactive CLI

```powershell
python main.py
```

### 3. Analyze a Specific Log File

```powershell
python main.py --file logs/sample.log --report reports/security_report.json
```

### 4. Start Web Dashboard & REST API

```powershell
python main.py --web --port 8000
```
- **Web Dashboard:** Open [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs:** Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🐳 Docker Deployment

SentinelLog runs as an unprivileged user (`sentinel`, UID 10001) with read-only file capabilities:

```bash
# Build hardened image
docker build -t sentinellog:2.4.0 .

# Run container
docker run -d -p 8000:8000 --name sentinellog sentinellog:2.4.0
```

---

## 🧪 Testing & DevSecOps Verification

```powershell
# Run the complete test suite (70 automated tests)
python -m pytest -v

# Run Bandit static security analysis (SAST)
python -m bandit -r . -x ./.venv,./.git,./.pytest_cache,./tests

# Run dependency vulnerability audit (SCA)
pip-audit -r requirements.txt
```

---

## 📚 Documentation Index

- [Project Audit & Baseline](docs/PROJECT_AUDIT.md)
- [System Architecture Specification](docs/ARCHITECTURE.md)
- [Detection Rules & Correlation Guide](docs/DETECTION_RULES.md)
- [Threat Model (STRIDE)](docs/THREAT_MODEL.md)
- [Automated Testing Strategy](docs/TESTING.md)
- [Deployment & Operations Guide](docs/DEPLOYMENT.md)
- [Changelog](CHANGELOG.md)

---

## ⚠️ Security Disclaimer & Attribution Boundary

SentinelLog uses rule-based indicators to identify potentially suspicious log activity.
1. **Indicator Only:** An alert indicates an event sequence requiring analyst review; it does not confirm a successful breach or malicious intent.
2. **Attribution Boundary:** Network IPv4 addresses identify transmission endpoints (which may be proxies, VPNs, or shared NAT gateways), never a verified human individual.
3. SentinelLog is designed as a cybersecurity engineering and DevSecOps demonstration project, not a replacement for commercial enterprise SIEMs.

---

## 👤 Author

**Tobi**
GitHub: [https://github.com/tobi-bro](https://github.com/tobi-bro)
*Built as a practical cybersecurity and DevSecOps engineering portfolio project.*