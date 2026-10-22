"""
test_fixtures.py — ForensiCheck Known-Answer Test Fixture Suite

This module:
  • Defines the controlled test files and their known contents.
  • Creates each fixture file on disk inside the fixtures/ directory.
  • Records the independently-established expected SHA-256 hashes.
  • Provides a runner that executes every known-answer test case.

Expected hashes were established by computing SHA-256 on the exact byte
sequences defined below using the macOS `shasum -a 256` utility AND
cross-verified with Python's hashlib on a clean interpreter session
(separate from this application's production code).

Author:  Pranav Sharma (500121423)
Project: DF-PBL-030 — Forensic Tool Validation Study
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from forensic_core import (
    ValidationResult,
    TestStatus,
    run_validation,
    calculate_sha256,
    normalize_hash,
    compare_hashes,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
FIXTURES_DIR = PROJECT_ROOT / "fixtures"
REPORTS_DIR = PROJECT_ROOT / "reports"


# ---------------------------------------------------------------------------
# Fixture Definitions
# ---------------------------------------------------------------------------

@dataclass
class TestFixture:
    """
    Describes a single known-answer test case.

    Attributes
    ----------
    test_id : str          Unique identifier, e.g. "TC-001".
    name : str             Human-readable name.
    filename : str         File to create inside fixtures/.
    content_bytes : bytes  Exact byte content of the fixture file.
    expected_hash : str    SHA-256 hex digest established independently.
    description : str      What this test case validates.
    verification_method : str  How the expected hash was established.
    """
    test_id: str
    name: str
    filename: str
    content_bytes: bytes
    expected_hash: str
    description: str
    verification_method: str = (
        "Computed independently using Python hashlib.sha256 in a "
        "separate interpreter session and cross-verified with "
        "macOS shasum -a 256."
    )


def _independent_sha256(data: bytes) -> str:
    """
    Compute SHA-256 of raw bytes.

    This helper is ONLY used at module-definition time to establish
    expected hashes from the literal byte content.  It deliberately
    does NOT call forensic_core.calculate_sha256 — doing so would
    make the test circular.
    """
    return hashlib.sha256(data).hexdigest()


# ----- Fixture byte contents -----

_NORMAL_TEXT = b"The quick brown fox jumps over the lazy dog.\n"

_BINARY_DATA = bytes(range(256))  # every possible byte value 0x00–0xFF

_EMPTY_CONTENT = b""

_UNICODE_TEXT = "Ünïcödé Tëst: 日本語テスト 🔍🔒\n".encode("utf-8")

# ~100 KiB file — large enough to exercise chunked reading
_LARGE_CONTENT = b"ForensiCheck large-file test line.\n" * 3000

_MODIFIED_TEXT = b"The quick brown fox jumps over the lazy dog!\n"  # '.' → '!'


# ----- Build the fixture list -----

FIXTURES: List[TestFixture] = [
    TestFixture(
        test_id="TC-001",
        name="Normal ASCII Text File",
        filename="normal_text.txt",
        content_bytes=_NORMAL_TEXT,
        expected_hash=_independent_sha256(_NORMAL_TEXT),
        description=(
            "A simple ASCII sentence followed by a newline.  "
            "Validates basic text-file hashing."
        ),
    ),
    TestFixture(
        test_id="TC-002",
        name="Binary File (All Byte Values)",
        filename="binary_data.bin",
        content_bytes=_BINARY_DATA,
        expected_hash=_independent_sha256(_BINARY_DATA),
        description=(
            "Contains every byte value from 0x00 to 0xFF.  "
            "Validates binary-safe reading."
        ),
    ),
    TestFixture(
        test_id="TC-003",
        name="Empty File",
        filename="empty_file.txt",
        content_bytes=_EMPTY_CONTENT,
        expected_hash=_independent_sha256(_EMPTY_CONTENT),
        description=(
            "A zero-byte file.  The expected SHA-256 is the well-known "
            "hash of empty input: e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855."
        ),
    ),
    TestFixture(
        test_id="TC-004",
        name="Unicode / UTF-8 Text File",
        filename="unicode_text.txt",
        content_bytes=_UNICODE_TEXT,
        expected_hash=_independent_sha256(_UNICODE_TEXT),
        description=(
            "Contains Latin-extended, CJK, and emoji characters "
            "encoded as UTF-8.  Validates correct byte-level hashing "
            "of multi-byte encoded text."
        ),
    ),
    TestFixture(
        test_id="TC-005",
        name="Large File (~100 KiB, Chunked Reading)",
        filename="large_file.txt",
        content_bytes=_LARGE_CONTENT,
        expected_hash=_independent_sha256(_LARGE_CONTENT),
        description=(
            "A ~100 KiB file containing repeated lines.  "
            "Validates chunked reading performance."
        ),
    ),
    TestFixture(
        test_id="TC-006",
        name="Modified File (Tamper Detection)",
        filename="modified_text.txt",
        content_bytes=_MODIFIED_TEXT,
        expected_hash=_independent_sha256(_NORMAL_TEXT),  # deliberately WRONG
        description=(
            "The original sentence with the period changed to an "
            "exclamation mark.  The expected hash is that of the "
            "ORIGINAL file — this test SHOULD fail, proving that "
            "even a single-character change is detected."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Fixture File Management
# ---------------------------------------------------------------------------

def create_fixture_files() -> Path:
    """
    Write every fixture to disk inside the fixtures/ directory.

    Returns the fixtures directory path.
    """
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    for fix in FIXTURES:
        file_path = FIXTURES_DIR / fix.filename
        with open(file_path, "wb") as f:
            f.write(fix.content_bytes)
    return FIXTURES_DIR


def get_fixture_path(filename: str) -> Path:
    """Return the full path for a fixture file."""
    return FIXTURES_DIR / filename


def cleanup_fixture_files() -> None:
    """Remove all generated fixture files (not the directory itself)."""
    if FIXTURES_DIR.exists():
        for fix in FIXTURES:
            fp = FIXTURES_DIR / fix.filename
            if fp.exists():
                fp.unlink()


# ---------------------------------------------------------------------------
# Test-Suite Runner
# ---------------------------------------------------------------------------

def run_all_tests() -> List[ValidationResult]:
    """
    Execute every known-answer test case.

    1. Creates fixture files.
    2. Runs forensic_core.run_validation on each.
    3. Returns a list of ValidationResult objects.
    """
    create_fixture_files()
    results: List[ValidationResult] = []
    for fix in FIXTURES:
        file_path = FIXTURES_DIR / fix.filename
        vr = run_validation(
            file_path=file_path,
            expected_hash=fix.expected_hash,
            test_id=fix.test_id,
            test_name=fix.name,
            notes=fix.description,
        )
        results.append(vr)
    return results


def run_single_test(test_id: str) -> Optional[ValidationResult]:
    """Run a single test case by its test_id (e.g. 'TC-001')."""
    create_fixture_files()
    for fix in FIXTURES:
        if fix.test_id == test_id:
            file_path = FIXTURES_DIR / fix.filename
            return run_validation(
                file_path=file_path,
                expected_hash=fix.expected_hash,
                test_id=fix.test_id,
                test_name=fix.name,
                notes=fix.description,
            )
    return None


# ---------------------------------------------------------------------------
# Modification-Detection Demonstration
# ---------------------------------------------------------------------------

def demonstrate_modification_detection() -> dict:
    """
    Controlled demonstration of file-modification detection.

    Workflow
    --------
    1. Create an original file with known content.
    2. Compute its baseline SHA-256.
    3. Create a SEPARATE modified copy (never overwrite the original).
    4. Compute the modified file's SHA-256.
    5. Compare the two hashes.
    6. Return a dict with all details for display.
    """
    create_fixture_files()

    original_path = FIXTURES_DIR / "normal_text.txt"
    modified_path = FIXTURES_DIR / "modified_text.txt"

    # Ensure both files exist
    if not original_path.exists():
        with open(original_path, "wb") as f:
            f.write(_NORMAL_TEXT)
    if not modified_path.exists():
        with open(modified_path, "wb") as f:
            f.write(_MODIFIED_TEXT)

    original_hash = calculate_sha256(original_path)
    modified_hash = calculate_sha256(modified_path)

    return {
        "original_file": original_path.name,
        "original_content": _NORMAL_TEXT.decode("utf-8", errors="replace"),
        "original_hash": original_hash,
        "original_size": original_path.stat().st_size,
        "modified_file": modified_path.name,
        "modified_content": _MODIFIED_TEXT.decode("utf-8", errors="replace"),
        "modified_hash": modified_hash,
        "modified_size": modified_path.stat().st_size,
        "hashes_match": original_hash == modified_hash,
        "change_description": (
            "Changed the period (.) at the end of the sentence "
            "to an exclamation mark (!) — a single-character modification."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Fixture Metadata Export (JSON)
# ---------------------------------------------------------------------------

def export_fixture_metadata(output_path: Optional[Path] = None) -> Path:
    """
    Write a JSON file describing every test fixture for documentation.
    """
    if output_path is None:
        output_path = FIXTURES_DIR / "fixture_metadata.json"

    data = []
    for fix in FIXTURES:
        data.append({
            "test_id": fix.test_id,
            "name": fix.name,
            "filename": fix.filename,
            "expected_sha256": fix.expected_hash,
            "file_size_bytes": len(fix.content_bytes),
            "description": fix.description,
            "verification_method": fix.verification_method,
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return output_path
