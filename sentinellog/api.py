"""
FastAPI REST API & Web Dashboard Backend for SentinelLog.

Provides RESTful endpoints for headless security analysis, alert inspection,
incident correlation, and serves the browser-based dashboard.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
import uvicorn

from sentinellog.analyzer import collect_analysis
from sentinellog.config import DEFAULT_CONFIG, SentinelConfig
from sentinellog.ingestion import load_logs_safely
from sentinellog.reporting import save_json_report


app = FastAPI(
    title="SentinelLog Security API",
    description="Automated application log security analysis, threat detection, and incident correlation API.",
    version=DEFAULT_CONFIG.version,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable secure local CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent / "static"
_ANALYSIS_CACHE: Dict[str, Any] = {}


def get_cached_analysis(force_refresh: bool = False) -> Dict[str, Any]:
    """Retrieve or compute the current analysis state."""
    global _ANALYSIS_CACHE
    if not _ANALYSIS_CACHE or force_refresh:
        lines = load_logs_safely()
        _ANALYSIS_CACHE = collect_analysis(lines)
    return _ANALYSIS_CACHE


# -----------------------------------------------------------------------------
# Pydantic Schemas
# -----------------------------------------------------------------------------

class HealthStatus(BaseModel):
    status: str = Field(..., examples=["healthy"])
    application: str = Field(..., examples=["SentinelLog"])
    version: str = Field(..., examples=["2.4.0"])
    timestamp: str = Field(..., examples=["2026-10-12T15:00:00Z"])


class LogAnalysisPayload(BaseModel):
    content: str = Field(..., description="Raw log contents to analyze")
    failed_login_threshold: Optional[int] = Field(None, ge=1, le=100)
    window_minutes: Optional[int] = Field(None, ge=1, le=1440)


class AnalysisSummary(BaseModel):
    total_events: int
    severity_counts: Dict[str, int]
    source_ip_counts: Dict[str, int]
    failed_login_counts: Dict[str, int]
    malformed_entries: List[str]
    alerts: List[Dict[str, Any]]
    incidents: List[Dict[str, Any]]


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@app.get("/health", response_model=HealthStatus, tags=["System"])
def get_health() -> HealthStatus:
    """Return system liveness and version info."""
    return HealthStatus(
        status="healthy",
        application=DEFAULT_CONFIG.app_name,
        version=DEFAULT_CONFIG.version,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.post(
    "/api/v1/analyze",
    response_model=AnalysisSummary,
    status_code=status.HTTP_200_OK,
    tags=["Analysis"],
)
def analyze_log_content(payload: LogAnalysisPayload) -> Dict[str, Any]:
    """Analyze raw log text supplied in JSON payload."""
    global _ANALYSIS_CACHE
    if not payload.content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Log content cannot be empty.",
        )

    config = SentinelConfig(
        failed_login_threshold=payload.failed_login_threshold or DEFAULT_CONFIG.failed_login_threshold,
        failed_login_window_minutes=payload.window_minutes or DEFAULT_CONFIG.failed_login_window_minutes,
        correlation_window_minutes=payload.window_minutes or DEFAULT_CONFIG.correlation_window_minutes,
    )

    lines = [line.strip() for line in payload.content.splitlines() if line.strip()]
    results = collect_analysis(lines, config=config)
    _ANALYSIS_CACHE = results
    return results


@app.post(
    "/api/v1/analyze/raw",
    response_model=AnalysisSummary,
    status_code=status.HTTP_200_OK,
    tags=["Analysis"],
)
async def upload_raw_log_stream(request: Request) -> Dict[str, Any]:
    """Analyze raw text log stream without requiring multipart parsing."""
    global _ANALYSIS_CACHE
    body = await request.body()
    if len(body) > DEFAULT_CONFIG.max_file_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Content exceeds maximum allowed size of {DEFAULT_CONFIG.max_file_size_bytes} bytes.",
        )

    decoded = body.decode("utf-8", errors="replace")
    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    if not lines:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded content contains no valid log records.",
        )

    results = collect_analysis(lines)
    _ANALYSIS_CACHE = results
    return results


@app.get("/api/v1/alerts", tags=["Triage"])
def list_sample_alerts() -> List[Dict[str, Any]]:
    """List security alerts from the current analysis state."""
    results = get_cached_analysis()
    return results.get("alerts", [])


@app.get("/api/v1/incidents", tags=["Triage"])
def list_sample_incidents() -> List[Dict[str, Any]]:
    """List correlated incidents from the current analysis state."""
    results = get_cached_analysis()
    return results.get("incidents", [])


@app.get("/api/v1/incidents/{incident_id}", tags=["Triage"])
def get_incident_detail(incident_id: str) -> Dict[str, Any]:
    """Fetch incident detail by unique identifier."""
    results = get_cached_analysis()
    for inc in results.get("incidents", []):
        if inc.get("incident_id") == incident_id:
            return inc

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Incident with ID '{incident_id}' not found.",
    )


@app.get("/api/v1/reports/latest", tags=["Reporting"])
def get_latest_report() -> Dict[str, Any]:
    """Retrieve the latest JSON analysis report or generate one from default sample."""
    results = get_cached_analysis()
    report_file = save_json_report(results)

    with open(report_file, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
def get_web_dashboard() -> HTMLResponse:
    """Serve the modern SentinelLog SOC web dashboard."""
    html_file = STATIC_DIR / "index.html"
    if not html_file.is_file():
        return HTMLResponse(
            "<h2>SentinelLog API is running. Dashboard HTML template not found.</h2>"
        )
    return HTMLResponse(html_file.read_text(encoding="utf-8"))


def run_api_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start uvicorn server for the SentinelLog API."""
    print(f"\n[INFO] Starting SentinelLog API & Web Dashboard at http://{host}:{port}")
    print(f"[INFO] OpenAPI Swagger docs available at http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port, log_level="info")
