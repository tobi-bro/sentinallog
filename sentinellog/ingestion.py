"""
Secure Log Ingestion Module for SentinelLog.

Handles file validation, size limits, line streaming, and encoding resilience.
"""

from pathlib import Path
from typing import Generator, List, Union

from sentinellog.config import DEFAULT_CONFIG, SentinelConfig


def validate_log_path(
    file_path: Union[str, Path],
    config: SentinelConfig = DEFAULT_CONFIG,
) -> Path:
    """
    Validate that the specified path is an accessible, regular file within size limits.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If path is a directory or exceeds max allowed size.
        PermissionError: If the file cannot be accessed.
    """
    path = Path(file_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {path}")

    try:
        file_size = path.stat().st_size
    except OSError as err:
        raise PermissionError(f"Cannot access log file metadata: {err}") from err

    if file_size > config.max_file_size_bytes:
        raise ValueError(
            f"Log file size ({file_size} bytes) exceeds maximum limit "
            f"({config.max_file_size_bytes} bytes)."
        )

    return path


def stream_log_lines(
    file_path: Union[str, Path],
    config: SentinelConfig = DEFAULT_CONFIG,
) -> Generator[str, None, None]:
    """
    Stream log lines safely one by one from disk to conserve memory.

    Sanitizes each line to prevent buffer overruns by truncating oversized lines
    and replacing undecodable bytes with unicode replacement characters.
    """
    validated_path = validate_log_path(file_path, config=config)

    with validated_path.open(
        mode="r",
        encoding="utf-8",
        errors="replace",
        newline=None,
    ) as file:
        for line in file:
            stripped = line.rstrip("\r\n")
            if len(stripped) > config.max_line_length:
                # Sanitize oversized record without crashing
                stripped = stripped[: config.max_line_length]
            yield stripped


def load_logs_safely(
    file_path: Union[str, Path] = DEFAULT_CONFIG.default_log_file,
    config: SentinelConfig = DEFAULT_CONFIG,
) -> List[str]:
    """Convenience helper to read lines using stream_log_lines."""
    try:
        return list(stream_log_lines(file_path, config=config))
    except (FileNotFoundError, ValueError, PermissionError):
        return []
