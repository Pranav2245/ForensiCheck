"""
forensic_core.py — ForensiCheck Core Hashing & Validation Engine

This module implements:
  • SHA-256 hash calculation (chunk-based for large files)
  • Hash comparison with hexadecimal normalization
  • Result data structures for validation reporting

All hashing logic lives here, separate from the Streamlit UI,
so it can be unit-tested independently.

Author:  Pranav Sharma (500121423)
Project: DF-PBL-030 — Forensic Tool Validation Study
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, BinaryIO

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HASH_ALGORITHM = "sha256"
DEFAULT_CHUNK_SIZE = 8192  # 8 KiB — balances memory use and I/O efficiency
VALID_HEX_CHARS = set("0123456789abcdef")
SHA256_HEX_LENGTH = 64


# ---------------------------------------------------------------------------
# Enums & Data Classes
# ---------------------------------------------------------------------------

class TestStatus(Enum):
    """Possible outcomes for a single validation test."""
    __test__ = False
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_EXECUTED = "NOT EXECUTED"
    ERROR = "ERROR"


@dataclass
class ValidationResult:
    """Holds the outcome of a single known-answer test."""
    test_id: str
    test_name: str
    filename: str
    file_size: int = 0
    expected_hash: str = ""
    observed_hash: str = ""
    status: TestStatus = TestStatus.NOT_EXECUTED
    timestamp: str = ""
    notes: str = ""
    error_details: str = ""

    def to_dict(self) -> dict:
        """Serialise to a plain dict for table display / CSV export."""
        return {
            "Test ID": self.test_id,
            "Test Name": self.test_name,
            "Filename": self.filename,
            "File Size (bytes)": self.file_size,
            "Expected SHA-256": self.expected_hash,
            "Observed SHA-256": self.observed_hash,
            "Status": self.status.value,
            "Timestamp": self.timestamp,
            "Notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Hash Calculation
# ---------------------------------------------------------------------------

def calculate_sha256(file_path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Calculate the SHA-256 hash of a file using chunk-based reading.

    Parameters
    ----------
    file_path : Path
        Absolute or relative path to the file.
    chunk_size : int
        Number of bytes read per iteration (default 8 KiB).

    Returns
    -------
    str
        Lower-case hexadecimal SHA-256 digest.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    PermissionError
        If the file cannot be read.
    OSError
        For other I/O errors.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not file_path.is_file():
        raise ValueError(f"Path is not a regular file: {file_path}")

    hasher = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def calculate_sha256_from_stream(
    stream: BinaryIO, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> str:
    """
    Calculate the SHA-256 hash from an open binary stream.

    Useful for Streamlit uploaded files (which expose a file-like object).

    Parameters
    ----------
    stream : BinaryIO
        An open binary-mode file-like object.
    chunk_size : int
        Bytes per read.

    Returns
    -------
    str
        Lower-case hexadecimal SHA-256 digest.
    """
    hasher = hashlib.sha256()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.hexdigest()


def calculate_sha256_from_bytes(data: bytes) -> str:
    """
    Calculate the SHA-256 hash of raw bytes.

    Parameters
    ----------
    data : bytes
        Arbitrary byte string.

    Returns
    -------
    str
        Lower-case hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Hash Validation Helpers
# ---------------------------------------------------------------------------

def normalize_hash(hex_string: str) -> str:
    """
    Normalise a hexadecimal hash string for comparison.

    Strips whitespace, converts to lower-case.
    """
    return hex_string.strip().lower()


def is_valid_sha256_hex(hex_string: str) -> bool:
    """
    Return True if *hex_string* is a syntactically valid SHA-256 hex digest.
    """
    normalised = normalize_hash(hex_string)
    if len(normalised) != SHA256_HEX_LENGTH:
        return False
    return all(c in VALID_HEX_CHARS for c in normalised)


def compare_hashes(expected: str, observed: str) -> TestStatus:
    """
    Compare two SHA-256 hex strings (case-insensitive).

    Returns TestStatus.PASS on match, TestStatus.FAIL otherwise.
    """
    if normalize_hash(expected) == normalize_hash(observed):
        return TestStatus.PASS
    return TestStatus.FAIL


# ---------------------------------------------------------------------------
# High-Level Validation Runner
# ---------------------------------------------------------------------------

def run_validation(
    file_path: Path,
    expected_hash: str,
    test_id: str,
    test_name: str,
    notes: str = "",
) -> ValidationResult:
    """
    Execute a single known-answer validation test.

    1. Calculates the SHA-256 hash of the file at *file_path*.
    2. Compares it to the *expected_hash*.
    3. Returns a fully populated ValidationResult.
    """
    result = ValidationResult(
        test_id=test_id,
        test_name=test_name,
        filename=file_path.name,
        expected_hash=normalize_hash(expected_hash),
    )

    try:
        file_path = Path(file_path)
        result.file_size = file_path.stat().st_size
        observed = calculate_sha256(file_path)
        result.observed_hash = observed
        result.status = compare_hashes(expected_hash, observed)
    except Exception as exc:
        result.status = TestStatus.ERROR
        result.error_details = str(exc)
        result.notes = f"Error: {exc}"

    result.timestamp = datetime.now(timezone.utc).isoformat()
    if notes and not result.notes:
        result.notes = notes
    return result


def get_file_size(file_path: Path) -> int:
    """Return file size in bytes, or 0 if the file cannot be stat-ed."""
    try:
        return Path(file_path).stat().st_size
    except OSError:
        return 0
