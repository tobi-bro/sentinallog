
import json

from main import (
    FAILED_LOGIN_THRESHOLD,
    FAILED_LOGIN_WINDOW_MINUTES,
    collect_analysis,
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
    import pytest

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
