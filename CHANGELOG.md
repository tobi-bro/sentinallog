# Changelog

All notable changes to the SentinelLog project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.4.0] — 2026-10-12
### Added
- **Incident Correlation Engine:** Aggregates alerts by shared IPv4 within bounded 5-minute rolling windows.
- **Anti-Chaining Invariant:** Bounded window logic guarantees `last_seen - first_seen <= window_minutes` preventing transitive time creep.
- **FastAPI REST API:** Headless triage endpoints (`/health`, `/api/v1/analyze`, `/api/v1/alerts`, `/api/v1/incidents`, `/api/v1/reports/latest`).
- **Interactive SOC Web Dashboard:** Dark-mode cyber defense UI with incident timeline cards, alert filters, and live report export.
- **Secure Log Ingestion Layer:** Streaming generators with 50 MB max file limits and 4,096 char line truncation guards.
- **Hardened Docker Container:** Non-root execution (`sentinel` user, UID 10001) with built-in health checks.
- **Centralized Configuration:** Config dataclass for detection thresholds and path parameters.
- **Comprehensive Documentation Suite:** `docs/ARCHITECTURE.md`, `docs/DETECTION_RULES.md`, `docs/THREAT_MODEL.md`, `docs/TESTING.md`, `docs/DEPLOYMENT.md`, `docs/PROJECT_AUDIT.md`.
- **Expanded Test Suite:** 70 automated tests covering parsing, ingestion, detection, correlation, and API layers.

### Changed
- Refactored monolithic `main.py` into modular package `sentinellog/` while maintaining 100% backward-compatible function and constant exports.
- Atomic JSON report writing now includes structured `"incidents"` collection and analyst disclaimers.

---

## [2.3.0] — Earlier Baseline
### Added
- ISO timestamp validation and IPv4 octet numerical boundary checks (`0–255`).
- Repeated failed login threshold detection (3 attempts in 5-minute window).
- Atomic JSON report generation using `tempfile.NamedTemporaryFile` and `os.replace`.
- 31 passing automated unit tests in `tests/test_main.py`.
- Static analysis via Bandit and vulnerability auditing via pip-audit in GitHub Actions.
