"""
Log Parser & Normalization Module for SentinelLog.

Extracts ISO-style timestamps, validated IPv4 addresses, and log severities.
"""

from datetime import datetime
import re
from typing import Optional


TIMESTAMP_PATTERN = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(.*)$"
)
DATE_PREFIX_PATTERN = re.compile(r"^\s*\d{4}-\d{2}-\d{2}\b")
LOG_LEVEL_PATTERN = re.compile(
    r"^\s*(INFO|WARNING|ERROR)\b",
    re.IGNORECASE,
)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_timestamp(line: str) -> Optional[str]:
    """Return a validated timestamp string, or None if unavailable."""
    if not isinstance(line, str):
        return None

    match = TIMESTAMP_PATTERN.match(line)
    if not match:
        return None

    timestamp_text = match.group(1).replace("T", " ")

    try:
        parsed = datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def extract_ip(line: str) -> Optional[str]:
    """Extract a valid IPv4 address from a log entry with 0-255 octet bounds."""
    if not isinstance(line, str):
        return None

    match = IPV4_PATTERN.search(line)
    if not match:
        return None

    ip_address = match.group(0)

    try:
        octets = [int(part) for part in ip_address.split(".")]
    except ValueError:
        return None

    if len(octets) != 4 or not all(0 <= octet <= 255 for octet in octets):
        return None

    return ip_address


def get_log_level(line: str) -> str:
    """Return the severity for a supported log format (INFO, WARNING, ERROR, UNKNOWN)."""
    if not isinstance(line, str):
        return "UNKNOWN"

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
