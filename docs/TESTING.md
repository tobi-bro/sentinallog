# SentinelLog — Automated Testing & Quality Assurance Guide

**Document Version:** 1.0.0  
**Application Version:** 2.4.0  

---

## 1. Test Suite Overview

SentinelLog maintains a 100% passing automated test suite with **70 unit and integration tests** executing in under 1 second.

```text
tests/
├── test_main.py         # Baseline parsing, alert detection, incident correlation & reporting (50 tests)
├── test_ingestion.py    # File path validation, streaming, size boundaries, encoding resilience (8 tests)
├── test_detection.py    # Custom configuration, threshold evaluation, alert creation (4 tests)
└── test_api.py          # FastAPI REST endpoints, Pydantic schemas, HTML dashboard (8 tests)
```

---

## 2. Running Tests Locally

### In Windows PowerShell:
```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Run the complete test suite with verbose output
python -m pytest -v

# Run a specific test module
python -m pytest tests/test_ingestion.py -v
```

### Static Analysis & Dependency Checks:
```powershell
# Run Bandit SAST scan
python -m bandit -r . -x ./.venv,./.git,./.pytest_cache,./tests

# Run pip-audit vulnerability scan
pip-audit -r requirements.txt
```

---

## 3. Test Categories & Verification Focus

1. **Negative & Edge-Case Testing:**
   - Non-existent files, directory paths passed as log targets.
   - Files exceeding 50 MB limits.
   - Non-UTF8 byte sequences (e.g. `\xff\xfe`).
   - Unrecognized severity levels and malformed timestamps.
2. **Deterministic Invariants:**
   - Input alert dictionaries are never mutated (`copy.deepcopy` verified).
   - Strict bounded time-window prevents transitive chaining ($t_{\text{end}} - t_{\text{start}} \le 5\text{m}$).
   - Missing or invalid source IPs and timestamps are never dropped from raw alerts, but safely excluded from time-bounded incidents.
3. **Atomic Reporting:**
   - Report generation verifies atomic temporary file creation, fsync, and replace logic.
