
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_REPORT_PATH = Path("reports/security_report.json")


def save_json_report(report_data, output_file=DEFAULT_REPORT_PATH):
    """Write analysis results to a JSON report."""
    if not isinstance(report_data, dict):
        raise TypeError("report_data must be a dictionary")

    report_path = Path(output_file)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    document = {
        "project": "SentinelLog",
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": report_data,
    }

    temporary_path = None

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

        # The temporary file is in the same directory to support replacement.
        os.replace(temporary_path, report_path)
        temporary_path = None

    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass

    return report_path


if __name__ == "__main__":
    sample_report = {
        "total_events": 1,
        "severity_counts": {
            "INFO": 1,
            "WARNING": 0,
            "ERROR": 0,
            "UNKNOWN": 0,
        },
        "source_ip_counts": {},
        "failed_login_counts": {},
        "malformed_entries": [],
        "alerts": [],
    }

    output = save_json_report(sample_report)
    print(f"JSON report saved to: {output}")
