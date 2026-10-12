"""
Tests for SentinelLog Detection Engine & Rule Extensibility.
"""

import pytest

from sentinellog.analyzer import collect_analysis
from sentinellog.config import SentinelConfig
from sentinellog.rules import create_alert, find_threshold_event


def test_config_validation():
    with pytest.raises(ValueError, match="failed_login_threshold must be at least 1"):
        SentinelConfig(failed_login_threshold=0).validate()

    with pytest.raises(ValueError, match="failed_login_window_minutes must be positive"):
        SentinelConfig(failed_login_window_minutes=-1).validate()

    with pytest.raises(ValueError, match="correlation_window_minutes must be positive"):
        SentinelConfig(correlation_window_minutes=0).validate()


def test_custom_threshold_detection():
    # Test with custom threshold = 2 attempts within 2 minutes
    custom_cfg = SentinelConfig(
        failed_login_threshold=2,
        failed_login_window_minutes=2,
    )

    lines = [
        "2026-10-11 10:00:00 WARNING Failed login from 10.0.0.1",
        "2026-10-11 10:01:00 WARNING Failed login from 10.0.0.1",
    ]

    results = collect_analysis(lines, config=custom_cfg)
    alerts = [a for a in results["alerts"] if a["type"] == "repeated_failed_logins"]

    assert len(alerts) == 1
    assert alerts[0]["count"] == 2
    assert alerts[0]["threshold"] == 2
    assert alerts[0]["window_minutes"] == 2


def test_find_threshold_event_sub_threshold():
    timestamps = ["2026-10-11 10:00:00"]
    assert find_threshold_event(timestamps, threshold=3) is None


def test_create_alert_custom_rule():
    alert = create_alert(
        alert_type="brute_force_indicator",
        severity="CRITICAL",
        source_ip="198.51.100.5",
        message="Suspicious high-frequency attempt",
        explanation="Testing custom rule injection",
        timestamp="2026-10-11 12:00:00",
        rule_id="RULE-CUSTOM-999",
        analyst_notes="Requires immediate review",
    )

    assert alert["rule_id"] == "RULE-CUSTOM-999"
    assert alert["severity"] == "CRITICAL"
    assert alert["analyst_notes"] == "Requires immediate review"
    assert alert["alert_id"]
