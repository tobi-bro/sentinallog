"""
Tests for SentinelLog Secure Ingestion Module.
"""

from pathlib import Path
import pytest

from sentinellog.config import SentinelConfig
from sentinellog.ingestion import (
    load_logs_safely,
    stream_log_lines,
    validate_log_path,
)


def test_validate_log_path_success(tmp_path):
    log_file = tmp_path / "valid.log"
    log_file.write_text("2026-10-11 10:00:00 INFO Test log\n", encoding="utf-8")

    validated = validate_log_path(log_file)
    assert validated == log_file.resolve()


def test_validate_log_path_missing_raises(tmp_path):
    missing_file = tmp_path / "non_existent.log"
    with pytest.raises(FileNotFoundError):
        validate_log_path(missing_file)


def test_validate_log_path_directory_raises(tmp_path):
    with pytest.raises(ValueError, match="not a regular file"):
        validate_log_path(tmp_path)


def test_validate_log_path_oversized_raises(tmp_path):
    oversized_file = tmp_path / "oversized.log"
    oversized_file.write_bytes(b"A" * 1024)

    small_config = SentinelConfig(max_file_size_bytes=512)
    with pytest.raises(ValueError, match="exceeds maximum limit"):
        validate_log_path(oversized_file, config=small_config)


def test_stream_log_lines_yields_lines(tmp_path):
    log_file = tmp_path / "stream.log"
    log_file.write_bytes(b"line 1\nline 2\r\nline 3\n")

    lines = [line for line in stream_log_lines(log_file) if line.strip()]
    assert lines == ["line 1", "line 2", "line 3"]


def test_stream_log_lines_truncates_oversized_record(tmp_path):
    log_file = tmp_path / "long_line.log"
    long_line = "X" * 100
    log_file.write_text(long_line + "\n", encoding="utf-8")

    config = SentinelConfig(max_line_length=20)
    lines = list(stream_log_lines(log_file, config=config))
    assert len(lines) == 1
    assert len(lines[0]) == 20
    assert lines[0] == "X" * 20


def test_stream_log_lines_replaces_corrupt_bytes(tmp_path):
    log_file = tmp_path / "corrupt.log"
    # Write invalid UTF-8 byte sequence (0xFF, 0xFE in isolation)
    log_file.write_bytes(b"Valid prefix \xff\xfe valid suffix\n")

    lines = list(stream_log_lines(log_file))
    assert len(lines) == 1
    assert "Valid prefix" in lines[0]
    assert "valid suffix" in lines[0]


def test_load_logs_safely_handles_errors():
    # Calling with nonexistent file returns empty list gracefully
    lines = load_logs_safely("non_existent_file_xyz_123.log")
    assert lines == []
