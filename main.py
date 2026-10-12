"""
SentinelLog — Security Log Analyzer & Incident Investigation Platform.

Main entry point providing interactive CLI, batch analysis, and web dashboard dispatch.
"""

import argparse
from datetime import datetime
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from sentinellog.analyzer import collect_analysis
from sentinellog.config import DEFAULT_CONFIG
from sentinellog.correlator import _build_incident, correlate_alerts
from sentinellog.ingestion import load_logs_safely, stream_log_lines, validate_log_path
from sentinellog.parser import (
    DATE_PREFIX_PATTERN,
    IPV4_PATTERN,
    LOG_LEVEL_PATTERN,
    TIMESTAMP_PATTERN,
    extract_ip,
    extract_timestamp,
    get_log_level,
)
from sentinellog.reporting import format_investigation_summary, save_json_report
from sentinellog.rules import create_alert, find_threshold_event


# Backward-compatible global constants
APP_NAME = DEFAULT_CONFIG.app_name
VERSION = DEFAULT_CONFIG.version
LOG_FILE = DEFAULT_CONFIG.default_log_file

LOG_LEVELS = DEFAULT_CONFIG.log_levels
FAILED_LOGIN_THRESHOLD = DEFAULT_CONFIG.failed_login_threshold
FAILED_LOGIN_WINDOW_MINUTES = DEFAULT_CONFIG.failed_login_window_minutes
SEVERITY_RANK = DEFAULT_CONFIG.severity_rank


def display_banner() -> None:
    """Print the application banner and metadata."""
    print("=" * 45)
    print(f"           {APP_NAME}")
    print("       Security Log Analyzer")
    print("=" * 45)
    print(f"Version: {VERSION}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


def display_menu() -> None:
    """Display the interactive terminal menu."""
    print("\n--- MAIN MENU ---")
    print("1. Analyze log file and generate report")
    print("2. View log statistics")
    print("3. View security alerts and incidents")
    print("4. Start Web Dashboard / API server")
    print("5. Exit")


def load_logs(file_path: Optional[Path] = None) -> List[str]:
    """Read application logs safely using streaming ingestion."""
    target = file_path or LOG_FILE
    if not Path(target).is_file():
        print(f"\n[ERROR] Log file not found: {target}")
        return []

    try:
        return load_logs_safely(target)
    except (OSError, ValueError) as error:
        print(f"\n[ERROR] Unable to read log file: {error}")
        return []


def print_analysis_report(results: Dict[str, Any], log_file: Path = LOG_FILE) -> None:
    """Print the analysis results in the terminal."""
    print("\n--- LOG ANALYSIS REPORT ---")
    print(f"Log file: {log_file}")
    print(f"Total entries: {results['total_events']}")

    for level, count in results["severity_counts"].items():
        print(f"{level}: {count}")

    print("\n--- FAILED LOGIN SUMMARY ---")
    if results["failed_login_counts"]:
        for ip_address, count in sorted(
            results["failed_login_counts"].items(),
            key=lambda item: (-item[1], item[0]),
        ):
            print(f"{ip_address}: {count} failed login attempt(s)")
    else:
        print("No failed login attempts with identifiable IP addresses.")

    print("\n--- UNKNOWN / MALFORMED ENTRIES ---")
    if results["malformed_entries"]:
        for entry in results["malformed_entries"]:
            print(f"[UNKNOWN] {entry}")
    else:
        print("No unknown-severity entries found.")

    print("\n--- SECURITY ALERTS ---")
    if results["alerts"]:
        for alert in results["alerts"]:
            print(
                f"[{alert['severity']}] {alert['type']} | "
                f"ID: {alert['alert_id']} | "
                f"Time: {alert['timestamp'] or 'Unavailable'} | "
                f"{alert['message']}"
            )
    else:
        print("No events matched the current alert rules.")

    print("\n--- CORRELATED INCIDENTS ---")
    if results.get("incidents"):
        for incident in results["incidents"]:
            print(
                f"[{incident['severity']}] Incident {incident['incident_id']} | "
                f"IP: {incident['source_ip']} | "
                f"Alerts: {incident['alert_count']} | "
                f"Timespan: {incident['first_seen']} -> {incident['last_seen']}"
            )
            for reason in incident["correlation_reasons"]:
                print(f"  * {reason}")
    else:
        print("No correlated incidents identified.")

    print(
        "\nNote: Alerts and incidents are rule-based indicators, "
        "not proof that an attack occurred."
    )


def analyze_logs(file_path: Optional[Path] = None, output_report: Optional[Path] = None) -> None:
    """Analyze logs, display terminal summary, and export JSON report."""
    target_file = file_path or LOG_FILE
    lines = load_logs(target_file)

    if not any(line.strip() for line in lines):
        print("\nNo log entries to analyze.")
        return

    results = collect_analysis(lines)
    print_analysis_report(results, log_file=target_file)

    try:
        report_dest = output_report or DEFAULT_CONFIG.default_report_path
        saved_path = save_json_report(results, report_dest)
        print(f"\nJSON report saved to: {saved_path}")
    except (OSError, TypeError, ValueError) as error:
        print(f"\n[ERROR] Could not save JSON report: {error}")


def view_statistics(file_path: Optional[Path] = None) -> None:
    """Display summary log metrics and top talkers."""
    lines = load_logs(file_path)

    if not any(line.strip() for line in lines):
        print("\nNo statistics available.")
        return

    results = collect_analysis(lines)
    print("\n--- LOG STATISTICS ---")
    print(f"Total entries: {results['total_events']}")

    for level, count in results["severity_counts"].items():
        print(f"{level}: {count}")

    print("\n--- MOST FREQUENT SOURCE IPs ---")
    ip_counts = results["source_ip_counts"]

    if ip_counts:
        for ip_address, count in sorted(
            ip_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )[:5]:
            print(f"{ip_address}: {count} event(s)")
    else:
        print("No IP addresses found.")


def view_alerts(file_path: Optional[Path] = None) -> None:
    """Display security alerts and incidents."""
    lines = load_logs(file_path)

    if not any(line.strip() for line in lines):
        print("\nNo alerts available.")
        return

    results = collect_analysis(lines)
    print("\n--- SECURITY ALERTS ---")

    if not results["alerts"]:
        print("No events matched the current alert rules.")
    else:
        for alert in results["alerts"]:
            print(
                f"[{alert['severity']}] {alert['type']} | "
                f"ID: {alert['alert_id']} | "
                f"Time: {alert['timestamp'] or 'Unavailable'} | "
                f"Source IP: {alert['source_ip'] or 'Unknown'} | "
                f"{alert['message']}"
            )

    print("\n--- CORRELATED INCIDENTS ---")
    if not results.get("incidents"):
        print("No correlated incidents identified.")
    else:
        for incident in results["incidents"]:
            print(
                f"[{incident['severity']}] Incident {incident['incident_id']} | "
                f"IP: {incident['source_ip']} | "
                f"Alerts: {incident['alert_count']} | "
                f"Timespan: {incident['first_seen']} -> {incident['last_seen']}"
            )

    print(
        "\nNote: Investigate alerts and incidents before drawing conclusions. "
        "These rules can produce false positives and false negatives."
    )


def start_web_server(port: int = 8000) -> None:
    """Launch the lightweight dashboard and REST API server."""
    from sentinellog.api import run_api_server
    run_api_server(port=port)


def interactive_cli() -> None:
    """Run interactive menu mode."""
    display_banner()

    while True:
        display_menu()
        choice = input("\nChoose an option (1-5): ").strip()

        if choice == "1":
            analyze_logs()
        elif choice == "2":
            view_statistics()
        elif choice == "3":
            view_alerts()
        elif choice == "4":
            start_web_server()
        elif choice == "5":
            print("\nSentinelLog closed. Goodbye!")
            break
        else:
            print("\n[ERROR] Invalid choice. Enter a number from 1 to 5.")


def main() -> None:
    """CLI argument dispatcher."""
    parser = argparse.ArgumentParser(
        description="SentinelLog — Security Log Analyzer & Incident Investigation Platform."
    )
    parser.add_argument(
        "--file",
        "-f",
        type=Path,
        help="Path to the log file to analyze.",
    )
    parser.add_argument(
        "--report",
        "-r",
        type=Path,
        help="Path where the JSON report should be saved.",
    )
    parser.add_argument(
        "--web",
        "-w",
        action="store_true",
        help="Start the lightweight web dashboard and REST API.",
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=8000,
        help="Port for the web dashboard server (default: 8000).",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"{APP_NAME} {VERSION}",
    )

    args = parser.parse_args()

    if args.web:
        start_web_server(port=args.port)
    elif args.file:
        analyze_logs(file_path=args.file, output_report=args.report)
    else:
        interactive_cli()


if __name__ == "__main__":
    main()
