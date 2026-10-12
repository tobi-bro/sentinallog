
import copy
import json

import pytest

from main import (
    FAILED_LOGIN_THRESHOLD,
    FAILED_LOGIN_WINDOW_MINUTES,
    collect_analysis,
    correlate_alerts,
    create_alert,
    extract_ip,
    extract_timestamp,
    get_log_level,
)
from reports.report_generator import save_json_report


def test_get_log_level():
    assert get_log_level("INFO Application started") == "INFO"
    assert get_log_level("WARNING Disk space low") == "WARNING"
    assert get_log_level("ERROR Database unavailable") == "ERROR"


def test_severity_word_inside_message():
    assert get_log_level("INFO User reported an error") == "INFO"


def test_severity_not_at_start_is_unknown():
    assert get_log_level("Something INFO happened") == "UNKNOWN"


def test_invalid_severity_prefix():
    assert get_log_level("INFORMATION Application started") == "UNKNOWN"


def test_valid_iso_timestamp():
    line = "2026-10-11 10:00:00 INFO Application started"
    assert get_log_level(line) == "INFO"
    assert extract_timestamp(line) == "2026-10-11 10:00:00"


def test_invalid_timestamp():
    line = "2026-13-45 10:00:00 INFO Application started"
    assert get_log_level(line) == "UNKNOWN"
    assert extract_timestamp(line) is None


def test_invalid_timestamp_format():
    line = "2026/10/11 10:00:00 INFO Application started"
    assert extract_timestamp(line) is None


def test_timestamp_without_severity():
    line = "2026-10-11 10:00:00 Application started"
    assert get_log_level(line) == "UNKNOWN"


def test_case_insensitive_severity():
    assert get_log_level("info Application started") == "INFO"
    assert get_log_level("warning Disk space low") == "WARNING"
    assert get_log_level("error Database unavailable") == "ERROR"


def test_extract_ip():
    assert extract_ip("INFO Connection from 192.0.2.10") == "192.0.2.10"


def test_extract_ip_missing():
    assert extract_ip("INFO Application started") is None


def test_invalid_ip():
    assert extract_ip("INFO Connection from 999.999.999.999") is None


def test_repeated_failed_login_detection():
    lines = [
        "2026-10-11 10:00:00 WARNING Failed login from 192.0.2.10",
        "2026-10-11 10:01:00 WARNING Failed login from 192.0.2.10",
        "2026-10-11 10:02:00 WARNING Failed login from 192.0.2.10",
    ]

    results = collect_analysis(lines)

    alerts = [
        alert
        for alert in results["alerts"]
        if alert["type"] == "repeated_failed_logins"
    ]

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.0.2.10"
    assert alerts[0]["count"] == 3
    assert alerts[0]["timestamp"] == "2026-10-11 10:02:00"
    assert alerts[0]["window_minutes"] == FAILED_LOGIN_WINDOW_MINUTES


def test_no_repeated_login_alert_below_threshold():
    lines = [
        "2026-10-11 10:00:00 WARNING Failed login from 192.0.2.11",
        "2026-10-11 10:01:00 WARNING Failed login from 192.0.2.11",
    ]

    results = collect_analysis(lines)

    assert not any(
        alert["type"] == "repeated_failed_logins"
        for alert in results["alerts"]
    )


def test_unauthorized_access_detection():
    lines = [
        "2026-10-11 10:00:00 ERROR Unauthorized access from 192.0.2.12"
    ]

    results = collect_analysis(lines)

    alerts = [
        alert
        for alert in results["alerts"]
        if alert["type"] == "unauthorized_access_event"
    ]

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["source_ip"] == "192.0.2.12"


def test_security_alert_contains_timestamp_and_unique_id():
    lines = [
        "2026-10-11 10:00:00 ERROR Unauthorized access from 192.0.2.13"
    ]

    results = collect_analysis(lines)
    alert = results["alerts"][0]

    assert alert["alert_id"]
    assert alert["timestamp"] == "2026-10-11 10:00:00"
    assert alert["type"] == "unauthorized_access_event"


def test_each_alert_has_a_unique_id():
    lines = [
        "2026-10-11 10:00:00 ERROR Unauthorized access from 192.0.2.14",
        "2026-10-11 10:01:00 ERROR Unauthorized access from 192.0.2.15",
    ]

    results = collect_analysis(lines)
    alert_ids = [alert["alert_id"] for alert in results["alerts"]]

    assert len(alert_ids) == 2
    assert len(set(alert_ids)) == 2


def test_normal_messages_do_not_generate_alerts():
    lines = [
        "2026-10-11 10:00:00 INFO Application started",
        "2026-10-11 10:01:00 INFO User logged in successfully",
    ]

    results = collect_analysis(lines)
    assert results["alerts"] == []


def test_empty_log_entries():
    results = collect_analysis(["", "\n", "   \n"])

    assert results["total_events"] == 0
    assert results["alerts"] == []
    assert results["malformed_entries"] == []


def test_malformed_log_entry():
    results = collect_analysis(["This is not a valid log entry"])

    assert results["total_events"] == 1
    assert results["severity_counts"]["UNKNOWN"] == 1
    assert "This is not a valid log entry" in results["malformed_entries"]


def test_unknown_entries_are_collected():
    lines = [
        "2026-10-11 10:00:00 INFO Application started",
        "Unrecognized log format",
    ]

    results = collect_analysis(lines)

    assert results["malformed_entries"] == ["Unrecognized log format"]


def test_unknown_entries_saved_to_json(tmp_path):
    results = collect_analysis(["Unrecognized log format"])

    report_path = tmp_path / "report.json"
    saved_path = save_json_report(results, report_path)

    with open(saved_path, "r", encoding="utf-8") as file:
        report = json.load(file)

    # The report generator nests analysis data inside "results".
    assert report["results"]["malformed_entries"] == [
        "Unrecognized log format"
    ]


def test_report_generator_rejects_non_dictionary():
    with pytest.raises(TypeError):
        save_json_report(["not", "a", "dictionary"])


def test_repeated_failed_login_alert_uses_threshold_timestamp():
    lines = [
        "2026-10-11 10:00:01 WARNING Failed login from 192.0.2.16",
        "2026-10-11 10:00:05 WARNING Failed login from 192.0.2.16",
        "2026-10-11 10:00:09 WARNING Failed login from 192.0.2.16",
        "2026-10-11 10:00:12 WARNING Failed login from 192.0.2.16",
    ]

    results = collect_analysis(lines)

    alert = next(
        alert
        for alert in results["alerts"]
        if alert["type"] == "repeated_failed_logins"
    )

    assert alert["timestamp"] == "2026-10-11 10:00:09"
    assert alert["count"] == 4


def test_failed_logins_outside_window_do_not_trigger_alert():
    lines = [
        "2026-10-11 10:00:00 WARNING Failed login from 192.0.2.20",
        "2026-10-11 10:03:00 WARNING Failed login from 192.0.2.20",
        "2026-10-11 10:06:00 WARNING Failed login from 192.0.2.20",
    ]

    results = collect_analysis(lines)

    repeated_login_alerts = [
        alert
        for alert in results["alerts"]
        if alert["type"] == "repeated_failed_logins"
    ]

    assert repeated_login_alerts == []


def test_failed_logins_within_window_trigger_alert():
    lines = [
        "2026-10-11 10:00:00 WARNING Failed login from 192.0.2.21",
        "2026-10-11 10:02:00 WARNING Failed login from 192.0.2.21",
        "2026-10-11 10:04:00 WARNING Failed login from 192.0.2.21",
    ]

    results = collect_analysis(lines)

    alerts = [
        alert
        for alert in results["alerts"]
        if alert["type"] == "repeated_failed_logins"
    ]

    assert len(alerts) == 1
    assert alerts[0]["timestamp"] == "2026-10-11 10:04:00"
    assert alerts[0]["window_start"] == "2026-10-11 10:00:00"
    assert alerts[0]["window_end"] == "2026-10-11 10:04:00"


def test_failed_logins_are_tracked_per_ip():
    lines = [
        "2026-10-11 10:00:00 WARNING Failed login from 192.0.2.30",
        "2026-10-11 10:01:00 WARNING Failed login from 192.0.2.31",
        "2026-10-11 10:02:00 WARNING Failed login from 192.0.2.30",
        "2026-10-11 10:03:00 WARNING Failed login from 192.0.2.31",
        "2026-10-11 10:04:00 WARNING Failed login from 192.0.2.30",
    ]

    results = collect_analysis(lines)

    alerts = [
        alert
        for alert in results["alerts"]
        if alert["type"] == "repeated_failed_logins"
    ]

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "192.0.2.30"


def test_failed_logins_without_timestamps_use_legacy_fallback():
    lines = [
        "WARNING Failed login from 192.0.2.40",
        "WARNING Failed login from 192.0.2.40",
        "WARNING Failed login from 192.0.2.40",
    ]

    results = collect_analysis(lines)

    alerts = [
        alert
        for alert in results["alerts"]
        if alert["type"] == "repeated_failed_logins"
    ]

    assert len(alerts) == 1
    assert alerts[0]["timestamp"] is None
    assert alerts[0]["timestamp_quality"] == "unavailable"
    assert alerts[0]["window_minutes"] is None


def test_failed_logins_with_timestamps_outside_window_do_not_use_fallback():
    lines = [
        "2026-10-11 10:00:00 WARNING Failed login from 192.0.2.41",
        "2026-10-11 10:03:00 WARNING Failed login from 192.0.2.41",
        "2026-10-11 10:06:00 WARNING Failed login from 192.0.2.41",
    ]

    results = collect_analysis(lines)

    assert not any(
        alert["type"] == "repeated_failed_logins"
        for alert in results["alerts"]
    )


def test_failed_login_threshold_configuration():
    assert FAILED_LOGIN_THRESHOLD == 3
    assert FAILED_LOGIN_WINDOW_MINUTES == 5


def test_create_alert_preserves_extra_fields():
    alert = create_alert(
        alert_type="test_alert",
        severity="LOW",
        source_ip="192.0.2.50",
        message="Test event",
        explanation="Test explanation",
        timestamp="2026-10-11 10:00:00",
        count=3,
    )

    assert alert["type"] == "test_alert"
    assert alert["count"] == 3
    assert alert["alert_id"]


# =====================================================================
# Phase 3: Incident Correlation & Advanced Reporting Tests
# =====================================================================


def test_correlate_alerts_empty():
    assert correlate_alerts([]) == []


def test_correlate_alerts_invalid_window_raises():
    alert = {
        "alert_id": "a1",
        "timestamp": "2026-10-11 10:00:00",
        "severity": "HIGH",
        "type": "unauthorized_access_event",
        "source_ip": "192.0.2.10",
        "message": "Test alert",
    }
    with pytest.raises(ValueError):
        correlate_alerts([alert], window_minutes=0)
    with pytest.raises(ValueError):
        correlate_alerts([alert], window_minutes=-5)
    with pytest.raises(TypeError):
        correlate_alerts([alert], window_minutes="five")


def test_correlate_alerts_invalid_alerts_type_raises():
    with pytest.raises(TypeError):
        correlate_alerts("not-a-list")


def test_correlate_alerts_single_eligible_alert():
    alert = {
        "alert_id": "a1",
        "timestamp": "2026-10-11 10:00:00",
        "severity": "HIGH",
        "type": "unauthorized_access_event",
        "source_ip": "192.0.2.10",
        "message": "Test alert 1",
    }
    incidents = correlate_alerts([alert])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["incident_id"]
    assert inc["source_ip"] == "192.0.2.10"
    assert inc["first_seen"] == "2026-10-11 10:00:00"
    assert inc["last_seen"] == "2026-10-11 10:00:00"
    assert inc["severity"] == "HIGH"
    assert inc["alert_ids"] == ["a1"]
    assert inc["alert_count"] == 1
    assert len(inc["evidence"]) == 1
    assert len(inc["correlation_reasons"]) > 0


def test_correlate_alerts_within_five_minute_window():
    alerts = [
        {
            "alert_id": "a1",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Test alert 1",
        },
        {
            "alert_id": "a2",
            "timestamp": "2026-10-11 10:04:00",
            "severity": "HIGH",
            "type": "repeated_failed_logins",
            "source_ip": "192.0.2.10",
            "message": "Test alert 2",
        },
    ]
    incidents = correlate_alerts(alerts, window_minutes=5)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["source_ip"] == "192.0.2.10"
    assert inc["first_seen"] == "2026-10-11 10:00:00"
    assert inc["last_seen"] == "2026-10-11 10:04:00"
    assert inc["alert_ids"] == ["a1", "a2"]
    assert inc["alert_count"] == 2


def test_correlate_alerts_exact_boundary():
    alerts = [
        {
            "alert_id": "a1",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Test alert 1",
        },
        {
            "alert_id": "a2",
            "timestamp": "2026-10-11 10:05:00",
            "severity": "HIGH",
            "type": "repeated_failed_logins",
            "source_ip": "192.0.2.10",
            "message": "Test alert 2",
        },
    ]
    incidents = correlate_alerts(alerts, window_minutes=5)
    assert len(incidents) == 1
    assert incidents[0]["alert_count"] == 2
    assert incidents[0]["alert_ids"] == ["a1", "a2"]


def test_correlate_alerts_outside_window():
    alerts = [
        {
            "alert_id": "a1",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Test alert 1",
        },
        {
            "alert_id": "a2",
            "timestamp": "2026-10-11 10:05:01",
            "severity": "HIGH",
            "type": "repeated_failed_logins",
            "source_ip": "192.0.2.10",
            "message": "Test alert 2",
        },
    ]
    incidents = correlate_alerts(alerts, window_minutes=5)
    assert len(incidents) == 2
    assert incidents[0]["alert_ids"] == ["a1"]
    assert incidents[1]["alert_ids"] == ["a2"]


def test_correlate_alerts_bounded_window_prevents_chaining():
    # Events at 10:00, 10:04, 10:07.
    # Naive chaining would cluster all three because 10:04 is <=5m from 10:00, and 10:07 is <=5m from 10:04.
    # But 10:07 is 7m away from the start (10:00).
    # Strict bounded rule clusters [10:00, 10:04] and starts a new incident for [10:07].
    alerts = [
        {
            "alert_id": "a1",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Alert 1",
        },
        {
            "alert_id": "a2",
            "timestamp": "2026-10-11 10:04:00",
            "severity": "HIGH",
            "type": "repeated_failed_logins",
            "source_ip": "192.0.2.10",
            "message": "Alert 2",
        },
        {
            "alert_id": "a3",
            "timestamp": "2026-10-11 10:07:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Alert 3",
        },
    ]
    incidents = correlate_alerts(alerts, window_minutes=5)
    assert len(incidents) == 2
    assert incidents[0]["alert_ids"] == ["a1", "a2"]
    assert incidents[1]["alert_ids"] == ["a3"]


def test_correlate_alerts_different_ips_remain_separate():
    alerts = [
        {
            "alert_id": "a1",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Alert from IP 1",
        },
        {
            "alert_id": "a2",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.20",
            "message": "Alert from IP 2",
        },
    ]
    incidents = correlate_alerts(alerts, window_minutes=5)
    assert len(incidents) == 2
    assert {inc["source_ip"] for inc in incidents} == {"192.0.2.10", "192.0.2.20"}


def test_correlate_alerts_missing_or_invalid_ip_uncorrelated():
    alerts = [
        {
            "alert_id": "a1",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": None,
            "message": "No IP",
        },
        {
            "alert_id": "a2",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "999.999.999.999",
            "message": "Invalid IP",
        },
    ]
    incidents = correlate_alerts(alerts)
    assert incidents == []


def test_correlate_alerts_missing_or_invalid_timestamp_uncorrelated():
    alerts = [
        {
            "alert_id": "a1",
            "timestamp": None,
            "severity": "HIGH",
            "type": "repeated_failed_logins",
            "source_ip": "192.0.2.10",
            "message": "No timestamp",
        },
        {
            "alert_id": "a2",
            "timestamp": "invalid-timestamp",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Bad timestamp",
        },
    ]
    incidents = correlate_alerts(alerts)
    assert incidents == []


def test_correlate_alerts_preserves_input_immutability():
    original_alerts = [
        {
            "alert_id": "a1",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Alert 1",
            "tags": ["initial"],
        }
    ]
    snapshot = copy.deepcopy(original_alerts)
    correlate_alerts(original_alerts)
    assert original_alerts == snapshot


def test_correlate_alerts_preserves_alert_ids():
    alerts = [
        {
            "alert_id": "uuid-special-1",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Alert 1",
        },
        {
            "alert_id": "uuid-special-2",
            "timestamp": "2026-10-11 10:02:00",
            "severity": "HIGH",
            "type": "repeated_failed_logins",
            "source_ip": "192.0.2.10",
            "message": "Alert 2",
        },
    ]
    incidents = correlate_alerts(alerts)
    assert incidents[0]["alert_ids"] == ["uuid-special-1", "uuid-special-2"]


def test_correlate_alerts_severity_hierarchy():
    alerts = [
        {
            "alert_id": "a1",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "LOW",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Low severity",
        },
        {
            "alert_id": "a2",
            "timestamp": "2026-10-11 10:02:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "High severity",
        },
    ]
    incidents = correlate_alerts(alerts)
    assert incidents[0]["severity"] == "HIGH"


def test_correlate_alerts_evidence_and_reasons():
    alerts = [
        {
            "alert_id": "a1",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Auth failure",
        }
    ]
    incidents = correlate_alerts(alerts)
    inc = incidents[0]
    assert isinstance(inc["evidence"], list)
    assert inc["evidence"][0]["alert_id"] == "a1"
    assert isinstance(inc["correlation_reasons"], list)
    assert any("192.0.2.10" in reason for reason in inc["correlation_reasons"])
    assert any("investigat" in reason.lower() for reason in inc["correlation_reasons"])


def test_correlate_alerts_deterministic_grouping():
    alerts = [
        {
            "alert_id": "a2",
            "timestamp": "2026-10-11 10:02:00",
            "severity": "HIGH",
            "type": "repeated_failed_logins",
            "source_ip": "192.0.2.10",
            "message": "Alert 2",
        },
        {
            "alert_id": "a1",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Alert 1",
        },
    ]
    res1 = correlate_alerts(alerts)
    res2 = correlate_alerts(alerts)
    assert res1[0]["alert_ids"] == res2[0]["alert_ids"]
    assert res1[0]["first_seen"] == res2[0]["first_seen"]
    assert res1[0]["last_seen"] == res2[0]["last_seen"]


def test_correlate_alerts_duplicate_alert_ids_handled_safely():
    alerts = [
        {
            "alert_id": "dup-id",
            "timestamp": "2026-10-11 10:00:00",
            "severity": "HIGH",
            "type": "unauthorized_access_event",
            "source_ip": "192.0.2.10",
            "message": "Event 1",
        },
        {
            "alert_id": "dup-id",
            "timestamp": "2026-10-11 10:01:00",
            "severity": "HIGH",
            "type": "repeated_failed_logins",
            "source_ip": "192.0.2.10",
            "message": "Event 2",
        },
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert incidents[0]["alert_count"] == 2
    assert len(incidents[0]["evidence"]) == 2


def test_collect_analysis_integrates_incidents():
    lines = [
        "2026-10-11 10:00:00 WARNING Failed login from 192.0.2.10",
        "2026-10-11 10:01:00 WARNING Failed login from 192.0.2.10",
        "2026-10-11 10:02:00 WARNING Failed login from 192.0.2.10",
        "2026-10-11 10:03:00 ERROR Unauthorized access from 192.0.2.10",
    ]
    results = collect_analysis(lines)
    assert "incidents" in results
    assert "alerts" in results
    assert len(results["alerts"]) == 2
    assert len(results["incidents"]) == 1
    inc = results["incidents"][0]
    assert inc["source_ip"] == "192.0.2.10"
    assert inc["alert_count"] == 2
    assert inc["first_seen"] == "2026-10-11 10:02:00"
    assert inc["last_seen"] == "2026-10-11 10:03:00"


def test_incidents_json_serialization(tmp_path):
    lines = [
        "2026-10-11 10:00:00 ERROR Unauthorized access from 192.0.2.10",
        "2026-10-11 10:01:00 ERROR Unauthorized access from 192.0.2.10",
    ]
    results = collect_analysis(lines)
    report_file = tmp_path / "incident_report.json"
    saved_path = save_json_report(results, report_file)
    with open(saved_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "incidents" in data["results"]
    assert len(data["results"]["incidents"]) == 1
    assert data["results"]["incidents"][0]["source_ip"] == "192.0.2.10"
