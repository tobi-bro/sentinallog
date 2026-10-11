# SentinelLog

**A Python-based security log analyzer for Windows application logs.**

SentinelLog parses log entries, summarizes severity levels, and identifies suspicious activity using configurable rule-based checks.

## Features

- Parse `INFO`, `WARNING`, `ERROR`, and unknown severity levels.
- Validate timestamps and extract IPv4 addresses.
- Detect repeated failed login attempts.
- Identify unauthorized-access indicators.
- Display log statistics and frequent source IP addresses.
- Generate JSON security reports.
- Provide an interactive command-line menu.
- Run automated tests with pytest.

## Technology Stack

- Python
- pytest
- JSON
- Git and GitHub

## Project Structure

```text
SentinelLog/
├── main.py
├── logs/
│   └── sample.log
├── reports/
│   └── report_generator.py
├── tests/
│   └── test_main.py
├── .gitignore
└── README.md
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/tobi-bro/sentinallog.git
cd sentinallog
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

Install the dependencies required by the project. If a `requirements.txt` file is available, run:

```powershell
pip install -r requirements.txt
```

Otherwise, install the project's required packages individually.

### 4. Run SentinelLog

```powershell
py main.py
```

Follow the interactive menu to analyze logs, view statistics, or inspect security alerts.

## Running Tests

Run the automated test suite from the project root:

```powershell
py -m pytest -v
```

The initial project test suite passed all 21 tests.

## Security Considerations

SentinelLog uses rule-based detection to identify potentially suspicious log activity. Its alerts are indicators for further investigation, not proof of a confirmed attack.

Detection accuracy depends on log format, data quality, and detection rules. The current version is a learning and portfolio project, not a replacement for a production SIEM or endpoint detection platform.

Use synthetic or authorized log data when testing.

## Future Improvements

- Configurable detection thresholds.
- Improved log-format validation and error handling.
- Additional security detection rules.
- Expanded unit and integration tests.
- Continuous integration with GitHub Actions.
- Static analysis and dependency vulnerability checks.
- Docker-based execution and deployment.

## Author

**Tobi**

GitHub: https://github.com/tobi-bro

---

*Built as a hands-on cybersecurity and Python development project.*