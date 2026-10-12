"""
SentinelLog Configuration Module.

Provides centralized, validated configuration defaults for detection thresholds,
time windows, file size boundaries, and severity rankings.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Tuple


@dataclass(frozen=True)
class SentinelConfig:
    """Central configuration parameters for SentinelLog."""

    app_name: str = "SentinelLog"
    version: str = "2.4.0"
    default_log_file: Path = Path("logs/sample.log")
    default_report_path: Path = Path("reports/security_report.json")

    # Ingestion constraints
    max_file_size_bytes: int = 50 * 1024 * 1024  # 50 MB
    max_line_length: int = 4096

    # Detection rules & thresholds
    failed_login_threshold: int = 3
    failed_login_window_minutes: int = 5
    correlation_window_minutes: int = 5

    # Log severity levels
    log_levels: Tuple[str, ...] = ("INFO", "WARNING", "ERROR", "UNKNOWN")

    # Severity ranking
    severity_rank: Dict[str, int] = field(
        default_factory=lambda: {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }
    )

    def validate(self) -> None:
        """Validate configuration sanity."""
        if self.failed_login_threshold < 1:
            raise ValueError("failed_login_threshold must be at least 1")
        if self.failed_login_window_minutes <= 0:
            raise ValueError("failed_login_window_minutes must be positive")
        if self.correlation_window_minutes <= 0:
            raise ValueError("correlation_window_minutes must be positive")
        if self.max_file_size_bytes <= 0:
            raise ValueError("max_file_size_bytes must be positive")


DEFAULT_CONFIG = SentinelConfig()
