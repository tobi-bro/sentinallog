import json
import re

import pytest

from main import get_log_level, extract_ip, collect_analysis
from reports.report_generator import save_json_report


def test_get_log_level():
    assert get_log_level(
        "2026-10-10 10:15:02 INFO Login successful"
    ) == "INFO"

    assert get_log_level(
        "2026-10-10 10:15:10 WARNING Failed login"
    ) == "WARNING"

    assert get_log_level(
        "2026-10-10 10:15:14 ERROR Database failed"
    ) == "ERROR"


def test_severity_word_inside_message():
    assert get_log_level(
        "2026-10-10 10:15:02 INFO User reported an ERROR message"
    ) == "INFO"


def test_severity_not_at_start_is_unknown():
    assert get_log_level("User reported an ERROR message") == "UNKNOWN"


def test_invalid_severity_prefix():
    assert get_log_level(
        "2026-10-10 10:15:02 DEBUG Application started"
    ) == "UNKNOWN"


def test_valid_iso_timestamp():
    assert get_log_level(
        "2026-10-10T10:15:02 INFO Application started"
    ) == "INFO"


def test_invalid_timestamp():
    assert get_log_level(
        "2026-19-45 28:75:99 INFO Invalid date"
    ) == "UNKNOWN"


def test_invalid_timestamp_format():
    assert get_log_level(
        "2026-10-10 10:15 INFO Missing seconds"
    ) == "UNKNOWN"


def test_timestamp_without_severity():
    assert get_log_level(
        "2026-10-10 10:15:02 Application started"
    ) == "UNKNOWN"


def test_case_insensitive_severity():
    assert get_log_level("info Application started") == "INFO"
    assert get_log_level("warning Disk space low") == "WARNING"
    assert get_log_level("error Database failed") == "ERROR"


def test_extract_ip():
    assert extract_ip(
        "Failed login from 203.0.113.25"
    ) == "203.0.113.25"


def test_extract_ip_missing():
    assert extract_ip("Login successful") is None


def test_invalid_ip():
    assert extract_ip(
        "Failed login from 999.999.999.999"
    ) is None


def test_repeated_failed_login_detection():
    lines = [
        "2026-10-10 10:15:10 WARNING Failed login from 203.0.113.25",
        "2026-10-10 10:15:12 WARNING Failed login from 203.0.113.25",
        "2026-10-10 10:15:14 WARNING Failed login from 203.0.113.25",
    ]

    results = collect_analysis(lines)

    assert results["total_events"] == 3
    assert results["failed_login_counts"]["203.0.113.25"] == 3

    alert = next(
        alert for alert in results["alerts"]
        if alert["type"] == "repeated_failed_logins"
    )
    assert alert["severity"] == "HIGH"
    assert alert["count"] == 3


def test_no_repeated_login_alert_below_threshold():
    lines = [
        "2026-10-10 10:15:10 WARNING Failed login from 203.0.113.25",
        "2026-10-10 10:15:12 WARNING Failed login from 203.0.113.25",
    ]

    results = collect_analysis(lines)

    assert not any(
        alert["type"] == "repeated_failed_logins"
        for alert in results["alerts"]
    )


def test_unauthorized_access_detection():
    lines = [
        "2026-10-10 10:17:00 ERROR Unauthorized access attempt from 198.51.100.42"
    ]

    results = collect_analysis(lines)

    alert = next(
        alert for alert in results["alerts"]
        if alert["type"] == "unauthorized_access_event"
    )

    assert alert["severity"] == "HIGH"
    assert alert["source_ip"] == "198.51.100.42"


def test_security_alert_contains_timestamp_and_unique_id():
    lines = [
        "2026-10-10 10:17:00 ERROR Unauthorized access attempt from 198.51.100.42"
    ]

    results = collect_analysis(lines)

    alert = next(
        alert for alert in results["alerts"]
        if alert["type"] == "unauthorized_access_event"
    )

    assert alert["timestamp"] == "2026-10-10 10:17:00"
    assert isinstance(alert["alert_id"], str)
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        alert["alert_id"],
    )


def test_each_alert_has_a_unique_id():
    lines = [
        "2026-10-10 10:17:00 ERROR Unauthorized access from 198.51.100.42",
        "2026-10-10 10:18:00 ERROR Unauthorized access from 198.51.100.43",
    ]

    results = collect_analysis(lines)
    alert_ids = [alert["alert_id"] for alert in results["alerts"]]

    assert len(alert_ids) == 2
    assert len(set(alert_ids)) == 2


def test_normal_messages_do_not_generate_alerts():
    lines = [
        "2026-10-10 10:15:02 INFO Login successful from 192.168.1.10",
        "2026-10-10 10:15:03 INFO Application started",
    ]

    results = collect_analysis(lines)

    assert results["alerts"] == []


def test_empty_log_entries():
    results = collect_analysis(["", "\n", "   "])

    assert results["total_events"] == 0
    assert results["severity_counts"]["INFO"] == 0
    assert results["severity_counts"]["UNKNOWN"] == 0
    assert results["alerts"] == []


def test_malformed_log_entry():
    results = collect_analysis(["unexpected application log format"])

    assert results["total_events"] == 1
    assert results["severity_counts"]["UNKNOWN"] == 1
    assert results["malformed_entries"] == [
        "unexpected application log format"
    ]


def test_unknown_entries_are_collected():
    results = collect_analysis([
        "unexpected application log format",
        "INFO Application started",
    ])

    assert results["severity_counts"]["UNKNOWN"] == 1
    assert results["malformed_entries"] == [
        "unexpected application log format"
    ]


def test_unknown_entries_saved_to_json(tmp_path):
    results = collect_analysis([
        "unexpected application log format",
        "INFO Application started",
    ])

    output_file = tmp_path / "test_report.json"
    saved_path = save_json_report(results, output_file)

    assert saved_path == output_file
    assert output_file.is_file()

    with output_file.open("r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["project"] == "SentinelLog"
    assert report["results"]["total_events"] == 2
    assert report["results"]["malformed_entries"] == [
        "unexpected application log format"
    ]


def test_report_generator_rejects_non_dictionary(tmp_path):
    output_file = tmp_path / "invalid.json"

    with pytest.raises(TypeError):
        save_json_report([], output_file)

    assert not output_file.exists()


def test_repeated_failed_login_alert_uses_threshold_timestamp():
    from main import collect_analysis

    lines = [
        "2026-10-11 10:00:01 WARNING Failed login from 192.0.2.10",
        "2026-10-11 10:00:05 WARNING Failed login from 192.0.2.10",
        "2026-10-11 10:00:09 WARNING Failed login from 192.0.2.10",
        "2026-10-11 10:00:12 WARNING Failed login from 192.0.2.10",
    ]

    results = collect_analysis(lines)

    alert = next(
        alert
        for alert in results["alerts"]
        if alert["type"] == "repeated_failed_logins"
    )

    assert alert["timestamp"] == "2026-10-11 10:00:09"
    assert alert["count"] == 4
