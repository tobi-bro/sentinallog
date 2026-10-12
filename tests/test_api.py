"""
Tests for SentinelLog REST API & Dashboard Functions.
"""

from fastapi import HTTPException
import pytest

from sentinellog.api import (
    LogAnalysisPayload,
    analyze_log_content,
    get_health,
    get_incident_detail,
    get_latest_report,
    get_web_dashboard,
    list_sample_alerts,
    list_sample_incidents,
)


def test_api_health_endpoint():
    data = get_health()
    assert data.status == "healthy"
    assert data.application == "SentinelLog"
    assert data.version == "2.4.0"


def test_api_analyze_valid_payload():
    payload = LogAnalysisPayload(
        content=(
            "2026-10-11 10:00:00 WARNING Failed login from 192.0.2.10\n"
            "2026-10-11 10:01:00 WARNING Failed login from 192.0.2.10\n"
            "2026-10-11 10:02:00 WARNING Failed login from 192.0.2.10\n"
        )
    )
    data = analyze_log_content(payload)
    assert data["total_events"] == 3
    assert len(data["alerts"]) == 1
    assert len(data["incidents"]) == 1
    assert data["incidents"][0]["source_ip"] == "192.0.2.10"


def test_api_analyze_empty_payload_raises():
    payload = LogAnalysisPayload(content="   ")
    with pytest.raises(HTTPException) as exc:
        analyze_log_content(payload)
    assert exc.value.status_code == 400
    assert "cannot be empty" in exc.value.detail


def test_api_list_sample_alerts():
    alerts = list_sample_alerts()
    assert isinstance(alerts, list)


def test_api_list_sample_incidents():
    incidents = list_sample_incidents()
    assert isinstance(incidents, list)


def test_api_get_incident_detail():
    incidents = list_sample_incidents()
    if incidents:
        first_id = incidents[0]["incident_id"]
        detail = get_incident_detail(first_id)
        assert detail["incident_id"] == first_id

    with pytest.raises(HTTPException) as exc:
        get_incident_detail("non-existent-id")
    assert exc.value.status_code == 404


def test_api_get_latest_report():
    report = get_latest_report()
    assert "results" in report
    assert report["project"] == "SentinelLog"


def test_api_get_dashboard_html():
    response = get_web_dashboard()
    assert "text/html" in response.headers["content-type"]
    assert "SentinelLog" in response.body.decode("utf-8")
