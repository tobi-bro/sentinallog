
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
import re
import uuid

from reports.report_generator import save_json_report


APP_NAME = "SentinelLog"
VERSION = "2.3.0"
LOG_FILE = Path("logs/sample.log")

LOG_LEVELS = ("INFO", "WARNING", "ERROR", "UNKNOWN")
FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_WINDOW_MINUTES = 5

TIMESTAMP_PATTERN = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(.*)$"
)
DATE_PREFIX_PATTERN = re.compile(r"^\s*\d{4}-\d{2}-\d{2}\b")
LOG_LEVEL_PATTERN = re.compile(
    r"^\s*(INFO|WARNING|ERROR)\b",
    re.IGNORECASE,
)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def display_banner():
    print("=" * 45)
    print(f"           {APP_NAME}")
    print("       Security Log Analyzer")
    print("=" * 45)
    print(f"Version: {VERSION}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


def display_menu():
    print("\n--- MAIN MENU ---")
    print("1. Analyze log file and generate report")
    print("2. View log statistics")
    print("3. View security alerts")
    print("4. Exit")


def load_logs():
    """Read application logs from the configured file."""
    if not LOG_FILE.is_file():
        print(f"\n[ERROR] Log file not found: {LOG_FILE}")
        return []

    try:
        with LOG_FILE.open("r", encoding="utf-8") as file:
            return file.readlines()
    except (OSError, UnicodeError) as error:
        print(f"\n[ERROR] Unable to read log file: {error}")
        return []


def get_log_level(line):
    """Return the severity for a supported log format."""
    timestamp_match = TIMESTAMP_PATTERN.match(line)

    if timestamp_match:
        timestamp_text = timestamp_match.group(1).replace("T", " ")
        message = timestamp_match.group(2)

        try:
            datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return "UNKNOWN"

        level_match = LOG_LEVEL_PATTERN.match(message)
        return level_match.group(1).upper() if level_match else "UNKNOWN"

    if DATE_PREFIX_PATTERN.match(line):
        return "UNKNOWN"

    level_match = LOG_LEVEL_PATTERN.match(line)
    return level_match.group(1).upper() if level_match else "UNKNOWN"


def extract_timestamp(line):
    """Return a validated timestamp, or None if unavailable."""
    timestamp_match = TIMESTAMP_PATTERN.match(line)

    if not timestamp_match:
        return None

    timestamp_text = timestamp_match.group(1).replace("T", " ")

    try:
        parsed = datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def create_alert(
    alert_type,
    severity,
    source_ip,
    message,
    explanation,
    timestamp=None,
    **extra_fields,
):
    """Create a security alert with a unique identifier."""
    alert = {
        "alert_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "severity": severity,
        "type": alert_type,
        "source_ip": source_ip,
        "message": message,
        "explanation": explanation,
    }
    alert.update(extra_fields)
    return alert


def extract_ip(line):
    """Extract a valid IPv4 address from a log entry."""
    match = IPV4_PATTERN.search(line)

    if not match:
        return None

    ip_address = match.group(0)

    try:
        octets = [int(part) for part in ip_address.split(".")]
    except ValueError:
        return None

    if len(octets) != 4 or not all(
        0 <= octet <= 255 for octet in octets
    ):
        return None

    return ip_address


def find_threshold_event(timestamps):
    """
    Find the first threshold-reaching event inside a rolling time window.

    timestamps must contain validated timestamp strings.
    Returns the threshold event details, or None if no window qualifies.
    """
    parsed_timestamps = sorted(
        (
            datetime.strptime(value, "%Y-%m-%d %H:%M:%S"),
            value,
        )
        for value in timestamps
    )

    window = timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)

    for end_index in range(
        FAILED_LOGIN_THRESHOLD - 1,
        len(parsed_timestamps),
    ):
        start_index = end_index - FAILED_LOGIN_THRESHOLD + 1

        start_time = parsed_timestamps[start_index][0]
        end_time = parsed_timestamps[end_index][0]

        if end_time - start_time <= window:
            return {
                "timestamp": parsed_timestamps[end_index][1],
                "window_start": parsed_timestamps[start_index][1],
                "window_end": parsed_timestamps[end_index][1],
            }

    return None


def collect_analysis(lines):
    """Analyze log entries without reading files or printing output."""
    severity_counts = Counter()
    source_ip_counts = Counter()
    failed_login_counts = Counter()
    failed_login_timestamps = {}
    malformed_entries = []
    alerts = []
    total_events = 0

    for line in lines:
        if not line.strip():
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

        if "failed login" in normalized_entry and ip_address:
            failed_login_counts[ip_address] += 1

            if timestamp:
                failed_login_timestamps.setdefault(ip_address, []).append(
                    timestamp
                )

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
                )
            )

    for ip_address, total_count in sorted(failed_login_counts.items()):
        if total_count < FAILED_LOGIN_THRESHOLD:
            continue

        timestamped_attempts = failed_login_timestamps.get(
            ip_address, []
        )

        threshold_event = None

        if len(timestamped_attempts) >= FAILED_LOGIN_THRESHOLD:
            threshold_event = find_threshold_event(timestamped_attempts)

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
                        f"At least {FAILED_LOGIN_THRESHOLD} timestamped "
                        f"failed logins occurred within "
                        f"{FAILED_LOGIN_WINDOW_MINUTES} minutes. "
                        "Investigate the source and surrounding events."
                    ),
                    timestamp=threshold_event["timestamp"],
                    count=total_count,
                    threshold=FAILED_LOGIN_THRESHOLD,
                    window_minutes=FAILED_LOGIN_WINDOW_MINUTES,
                    window_start=threshold_event["window_start"],
                    window_end=threshold_event["window_end"],
                )
            )

        elif not timestamped_attempts:
            # Compatibility fallback for legacy logs without timestamps.
            # This is not equivalent to verified time-window detection.
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
                        f"{FAILED_LOGIN_THRESHOLD} failures across the log. "
                        "A time-window check could not be performed because "
                        "timestamps were unavailable."
                    ),
                    timestamp=None,
                    count=total_count,
                    threshold=FAILED_LOGIN_THRESHOLD,
                    window_minutes=None,
                    timestamp_quality="unavailable",
                )
            )

    return {
        "total_events": total_events,
        "severity_counts": {
            level: severity_counts[level] for level in LOG_LEVELS
        },
        "source_ip_counts": dict(source_ip_counts),
        "failed_login_counts": dict(failed_login_counts),
        "malformed_entries": malformed_entries,
        "alerts": alerts,
    }


def print_analysis_report(results):
    """Print the analysis results in the terminal."""
    print("\n--- LOG ANALYSIS REPORT ---")
    print(f"Log file: {LOG_FILE}")
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

    print(
        "\nNote: Alerts are rule-based indicators, "
        "not proof that an attack occurred."
    )


def analyze_logs():
    lines = load_logs()

    if not any(line.strip() for line in lines):
        print("\nNo log entries to analyze.")
        return

    results = collect_analysis(lines)
    print_analysis_report(results)

    try:
        report_path = save_json_report(results)
        print(f"\nJSON report saved to: {report_path}")
    except (OSError, TypeError, ValueError) as error:
        print(f"\n[ERROR] Could not save JSON report: {error}")


def view_statistics():
    lines = load_logs()

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


def view_alerts():
    lines = load_logs()

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

    print(
        "\nNote: Investigate alerts before drawing conclusions. "
        "These rules can produce false positives and false negatives."
    )


def main():
    display_banner()

    while True:
        display_menu()
        choice = input("\nChoose an option (1-4): ").strip()

        if choice == "1":
            analyze_logs()
        elif choice == "2":
            view_statistics()
        elif choice == "3":
            view_alerts()
        elif choice == "4":
            print("\nSentinelLog closed. Goodbye!")
            break
        else:
            print("\n[ERROR] Invalid choice. Enter a number from 1 to 4.")


if __name__ == "__main__":
    main()
