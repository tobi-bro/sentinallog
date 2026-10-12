"""
Core Security Analysis Pipeline Module for SentinelLog.

Processes log streams, counts events, detects alert indicators, and correlates incidents.
"""

from collections import Counter
from typing import Any, Dict, Iterable, List

from sentinellog.config import DEFAULT_CONFIG, SentinelConfig
from sentinellog.correlator import correlate_alerts
from sentinellog.parser import extract_ip, extract_timestamp, get_log_level
from sentinellog.rules import create_alert, find_threshold_event


def collect_analysis(
    lines: Iterable[str],
    config: SentinelConfig = DEFAULT_CONFIG,
) -> Dict[str, Any]:
    """
    Analyze log entries and return comprehensive security findings.

    Args:
        lines: Iterable of raw log strings.
        config: SentinelConfig parameters.

    Returns:
        Structured dictionary with counts, malformed entries, alerts, and incidents.
    """
    severity_counts = Counter()
    source_ip_counts = Counter()
    failed_login_counts = Counter()
    failed_login_timestamps: Dict[str, List[str]] = {}
    successful_logins: Dict[str, List[str]] = {}
    malformed_entries: List[str] = []
    alerts: List[Dict[str, Any]] = []
    total_events = 0

    for line in lines:
        if not line or not line.strip():
            continue

        total_events += 1
        entry = line.strip()
        normalized_entry = entry.lower()

        timestamp = extract_timestamp(entry)
        level = get_log_level(entry)
        severity_counts[level] += 1

        if level == "UNKNOWN":
            malformed_entries.append(entry)

        ip_address = extract_ip(entry)
        if ip_address:
            source_ip_counts[ip_address] += 1

        # Track failed logins
        if "failed login" in normalized_entry and ip_address:
            failed_login_counts[ip_address] += 1
            if timestamp:
                failed_login_timestamps.setdefault(ip_address, []).append(timestamp)

        # Track successful logins
        if "login successful" in normalized_entry and ip_address:
            if timestamp:
                successful_logins.setdefault(ip_address, []).append(timestamp)

        # Detect unauthorized access indicators
        if "unauthorized access" in normalized_entry:
            alerts.append(
                create_alert(
                    alert_type="unauthorized_access_event",
                    severity="HIGH",
                    source_ip=ip_address,
                    message=entry,
                    explanation=(
                        "An unauthorized-access indicator was found. "
                        "Investigate the event and surrounding context."
                    ),
                    timestamp=timestamp,
                    rule_id="RULE-AUTH-002",
                )
            )

    # Evaluate repeated failed logins per IP
    for ip_address, total_count in sorted(failed_login_counts.items()):
        if total_count < config.failed_login_threshold:
            continue

        timestamped_attempts = failed_login_timestamps.get(ip_address, [])
        threshold_event = None

        if len(timestamped_attempts) >= config.failed_login_threshold:
            threshold_event = find_threshold_event(
                timestamped_attempts,
                threshold=config.failed_login_threshold,
                window_minutes=config.failed_login_window_minutes,
            )

        if threshold_event:
            alerts.append(
                create_alert(
                    alert_type="repeated_failed_logins",
                    severity="HIGH",
                    source_ip=ip_address,
                    message=(
                        f"{ip_address} generated {total_count} "
                        "failed login attempts in the analyzed log."
                    ),
                    explanation=(
                        f"At least {config.failed_login_threshold} timestamped "
                        f"failed logins occurred within "
                        f"{config.failed_login_window_minutes} minutes. "
                        "Investigate the source and surrounding events."
                    ),
                    timestamp=threshold_event["timestamp"],
                    count=total_count,
                    threshold=config.failed_login_threshold,
                    window_minutes=config.failed_login_window_minutes,
                    window_start=threshold_event["window_start"],
                    window_end=threshold_event["window_end"],
                    rule_id="RULE-AUTH-001",
                )
            )
        elif not timestamped_attempts:
            # Compatibility fallback for legacy logs without timestamps
            alerts.append(
                create_alert(
                    alert_type="repeated_failed_logins",
                    severity="HIGH",
                    source_ip=ip_address,
                    message=(
                        f"{ip_address} generated {total_count} "
                        "failed login attempts, but timestamps are unavailable."
                    ),
                    explanation=(
                        f"The source reached the threshold of "
                        f"{config.failed_login_threshold} failures across the log. "
                        "A time-window check could not be performed because "
                        "timestamps were unavailable."
                    ),
                    timestamp=None,
                    count=total_count,
                    threshold=config.failed_login_threshold,
                    window_minutes=None,
                    timestamp_quality="unavailable",
                    rule_id="RULE-AUTH-001-LEGACY",
                )
            )

    incidents = correlate_alerts(
        alerts,
        window_minutes=config.correlation_window_minutes,
    )

    return {
        "total_events": total_events,
        "severity_counts": {
            level: severity_counts[level] for level in config.log_levels
        },
        "source_ip_counts": dict(source_ip_counts),
        "failed_login_counts": dict(failed_login_counts),
        "malformed_entries": malformed_entries,
        "alerts": alerts,
        "incidents": incidents,
    }
