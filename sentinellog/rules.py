"""
Detection Engine Module for SentinelLog.

Defines alert creation, threshold evaluation, and security detection rules:
- repeated_failed_logins
- unauthorized_access_event
- successful_login_after_failures
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import uuid

from sentinellog.config import DEFAULT_CONFIG, SentinelConfig


def create_alert(
    alert_type: str,
    severity: str,
    source_ip: Optional[str],
    message: str,
    explanation: str,
    timestamp: Optional[str] = None,
    rule_id: Optional[str] = None,
    **extra_fields: Any,
) -> Dict[str, Any]:
    """Create a structured security alert with a unique identifier."""
    alert = {
        "alert_id": str(uuid.uuid4()),
        "rule_id": rule_id or alert_type,
        "timestamp": timestamp,
        "severity": severity,
        "type": alert_type,
        "source_ip": source_ip,
        "message": message,
        "explanation": explanation,
    }
    alert.update(extra_fields)
    return alert


def find_threshold_event(
    timestamps: List[str],
    threshold: int = DEFAULT_CONFIG.failed_login_threshold,
    window_minutes: int = DEFAULT_CONFIG.failed_login_window_minutes,
) -> Optional[Dict[str, str]]:
    """
    Find the first threshold-reaching event inside a rolling time window.

    Args:
        timestamps: Validated timestamp strings formatted as '%Y-%m-%d %H:%M:%S'.
        threshold: Required number of events to trigger alert.
        window_minutes: Time window duration in minutes.

    Returns:
        Dict with timestamp, window_start, window_end if threshold met; else None.
    """
    if len(timestamps) < threshold:
        return None

    parsed_timestamps = sorted(
        (datetime.strptime(value, "%Y-%m-%d %H:%M:%S"), value)
        for value in timestamps
    )

    window = timedelta(minutes=window_minutes)

    for end_index in range(threshold - 1, len(parsed_timestamps)):
        start_index = end_index - threshold + 1

        start_time = parsed_timestamps[start_index][0]
        end_time = parsed_timestamps[end_index][0]

        if end_time - start_time <= window:
            return {
                "timestamp": parsed_timestamps[end_index][1],
                "window_start": parsed_timestamps[start_index][1],
                "window_end": parsed_timestamps[end_index][1],
            }

    return None
