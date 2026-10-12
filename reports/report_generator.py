"""
SentinelLog Report Generator.

Backward-compatible interface for atomic JSON report generation.
"""

from pathlib import Path

from sentinellog.config import DEFAULT_CONFIG
from sentinellog.reporting import save_json_report

DEFAULT_REPORT_PATH = DEFAULT_CONFIG.default_report_path

__all__ = ["DEFAULT_REPORT_PATH", "save_json_report"]

if __name__ == "__main__":
    sample_report = {
        "total_events": 1,
        "severity_counts": {
            "INFO": 1,
            "WARNING": 0,
            "ERROR": 0,
            "UNKNOWN": 0,
        },
        "source_ip_counts": {},
        "failed_login_counts": {},
        "malformed_entries": [],
        "alerts": [],
        "incidents": [],
    }

    output = save_json_report(sample_report)
    print(f"JSON report saved to: {output}")
