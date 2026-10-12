"""
Reporting Module for SentinelLog.

Handles atomic JSON serialization, investigation summaries, and terminal formatting.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, Optional, Union

from sentinellog.config import DEFAULT_CONFIG


def save_json_report(
    report_data: Dict[str, Any],
    output_file: Union[str, Path] = DEFAULT_CONFIG.default_report_path,
) -> Path:
    """
    Write analysis results to a JSON report atomically.

    Uses a named temporary file in the destination folder, flushes, fsyncs,
    and replaces the target file to ensure atomic, corruption-resistant writes.
    """
    if not isinstance(report_data, dict):
        raise TypeError("report_data must be a dictionary")

    report_path = Path(output_file)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    document = {
        "project": DEFAULT_CONFIG.app_name,
        "report_version": DEFAULT_CONFIG.version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": (
            "SentinelLog alerts and incidents are rule-based security indicators "
            "intended for triage and investigation. They do not constitute proof "
            "of malicious intent or individual human attribution."
        ),
        "results": report_data,
    }

    temporary_path: Optional[Path] = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=report_path.parent,
            prefix=f".{report_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            json.dump(
                document,
                file,
                indent=4,
                ensure_ascii=False,
                allow_nan=False,
            )
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary_path, report_path)
        temporary_path = None

    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass

    return report_path


def format_investigation_summary(results: Dict[str, Any]) -> str:
    """Format analysis results into a structured markdown investigation report."""
    lines = [
        f"# SentinelLog Security Investigation Report",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Executive Summary",
        f"- **Total Events Analyzed:** {results.get('total_events', 0)}",
        f"- **Security Alerts Triggered:** {len(results.get('alerts', []))}",
        f"- **Correlated Incidents:** {len(results.get('incidents', []))}",
        "",
        "### Event Severity Distribution",
    ]

    for level, count in results.get("severity_counts", {}).items():
        lines.append(f"- **{level}:** {count}")

    lines.extend(["", "## Correlated Incidents"])
    incidents = results.get("incidents", [])
    if not incidents:
        lines.append("_No incidents detected._")
    else:
        for inc in incidents:
            lines.extend([
                f"### Incident {inc['incident_id']} [{inc['severity']}]",
                f"- **Source IP:** `{inc['source_ip']}`",
                f"- **Timespan:** {inc['first_seen']} to {inc['last_seen']}",
                f"- **Linked Alerts:** {inc['alert_count']}",
                "- **Correlation Reasons:**",
            ])
            for reason in inc.get("correlation_reasons", []):
                lines.append(f"  - {reason}")
            lines.append("")

    return "\n".join(lines)
