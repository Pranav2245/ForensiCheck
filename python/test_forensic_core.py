"""
tests/test_forensic_core.py — Automated Unit Tests for ForensiCheck

Covers:
  • Correct SHA-256 calculation of known contents
  • Empty-file handling
  • Binary-data processing
  • Unicode / UTF-8 text
  • Large-file chunked reading
  • Altered-file detection
  • Hash comparison (match / mismatch)
  • Invalid hash-input validation
  • File-read error handling

Run with:  python -m pytest tests/ -v

Author:  Pranav Sharma (500121423)
Project: DF-PBL-030 — Forensic Tool Validation Study
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path

# Ensure current directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

# Module under test
from forensic_core import (
    calculate_sha256,
    calculate_sha256_from_bytes,
    calculate_sha256_from_stream,
    compare_hashes,
    is_valid_sha256_hex,
    normalize_hash,
    run_validation,
    TestStatus,
    ValidationResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_tmp(content: bytes, suffix: str = ".tmp") -> Path:
    """Write *content* to a temp file and return its Path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content)
    os.close(fd)
    return Path(path)


def _expected(data: bytes) -> str:
    """Reference SHA-256 calculated independently of forensic_core."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Test: SHA-256 of known content
# ---------------------------------------------------------------------------

class TestSHA256Calculation:

    def test_known_ascii_text(self):
        data = b"The quick brown fox jumps over the lazy dog.\n"
        tmp = _write_tmp(data)
        try:
            assert calculate_sha256(tmp) == _expected(data)
        finally:
            tmp.unlink()

    def test_empty_file(self):
        """SHA-256 of empty input is a well-known constant."""
        data = b""
        tmp = _write_tmp(data)
        try:
            result = calculate_sha256(tmp)
            assert result == _expected(data)
            assert result == (
                "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855"
            )
        finally:
            tmp.unlink()

    def test_binary_data(self):
        data = bytes(range(256))
        tmp = _write_tmp(data, suffix=".bin")
        try:
            assert calculate_sha256(tmp) == _expected(data)
        finally:
            tmp.unlink()

    def test_unicode_utf8(self):
        text = "Ünïcödé Tëst: 日本語テスト 🔍🔒\n"
        data = text.encode("utf-8")
        tmp = _write_tmp(data)
        try:
            assert calculate_sha256(tmp) == _expected(data)
        finally:
            tmp.unlink()

    def test_large_file_chunked(self):
        """~100 KiB — tests chunk-based reading."""
        data = b"ForensiCheck large-file test line.\n" * 3000
        tmp = _write_tmp(data)
        try:
            assert calculate_sha256(tmp) == _expected(data)
        finally:
            tmp.unlink()

    def test_single_byte(self):
        data = b"\x00"
        tmp = _write_tmp(data)
        try:
            assert calculate_sha256(tmp) == _expected(data)
        finally:
            tmp.unlink()

    def test_from_bytes(self):
        data = b"hello forensics"
        assert calculate_sha256_from_bytes(data) == _expected(data)

    def test_from_stream(self):
        data = b"stream test content"
        tmp = _write_tmp(data)
        try:
            with open(tmp, "rb") as fh:
                assert calculate_sha256_from_stream(fh) == _expected(data)
        finally:
            tmp.unlink()


# ---------------------------------------------------------------------------
# Test: Altered-file detection
# ---------------------------------------------------------------------------

class TestAlterationDetection:

    def test_single_char_change_detected(self):
        original = b"The quick brown fox jumps over the lazy dog.\n"
        modified = b"The quick brown fox jumps over the lazy dog!\n"
        assert _expected(original) != _expected(modified)

        tmp_orig = _write_tmp(original)
        tmp_mod = _write_tmp(modified)
        try:
            h1 = calculate_sha256(tmp_orig)
            h2 = calculate_sha256(tmp_mod)
            assert h1 != h2
        finally:
            tmp_orig.unlink()
            tmp_mod.unlink()

    def test_appended_byte_detected(self):
        original = b"evidence"
        modified = original + b"\x00"
        tmp_orig = _write_tmp(original)
        tmp_mod = _write_tmp(modified)
        try:
            assert calculate_sha256(tmp_orig) != calculate_sha256(tmp_mod)
        finally:
            tmp_orig.unlink()
            tmp_mod.unlink()


# ---------------------------------------------------------------------------
# Test: Hash comparison
# ---------------------------------------------------------------------------

class TestHashComparison:

    def test_matching_hashes(self):
        h = "aabbccdd" * 8  # 64 hex chars
        assert compare_hashes(h, h) == TestStatus.PASS

    def test_case_insensitive_match(self):
        h_lower = "aabbccdd" * 8
        h_upper = h_lower.upper()
        assert compare_hashes(h_lower, h_upper) == TestStatus.PASS

    def test_mismatched_hashes(self):
        h1 = "aa" * 32
        h2 = "bb" * 32
        assert compare_hashes(h1, h2) == TestStatus.FAIL

    def test_whitespace_stripped(self):
        h = "  aabbccdd" * 8 + "  "
        assert normalize_hash(h).startswith("aabbccdd")


# ---------------------------------------------------------------------------
# Test: Hash format validation
# ---------------------------------------------------------------------------

class TestHashValidation:

    def test_valid_hash(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert is_valid_sha256_hex(h)

    def test_too_short(self):
        assert not is_valid_sha256_hex("abcdef")

    def test_too_long(self):
        assert not is_valid_sha256_hex("a" * 65)

    def test_invalid_chars(self):
        assert not is_valid_sha256_hex("g" * 64)

    def test_empty_string(self):
        assert not is_valid_sha256_hex("")

    def test_mixed_case_valid(self):
        h = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        assert is_valid_sha256_hex(h)


# ---------------------------------------------------------------------------
# Test: run_validation integration
# ---------------------------------------------------------------------------

class TestRunValidation:

    def test_pass_result(self):
        data = b"test content for validation"
        tmp = _write_tmp(data)
        try:
            result = run_validation(
                file_path=tmp,
                expected_hash=_expected(data),
                test_id="T-001",
                test_name="Unit test pass",
            )
            assert result.status == TestStatus.PASS
            assert result.observed_hash == _expected(data)
            assert result.file_size == len(data)
            assert result.timestamp  # non-empty
        finally:
            tmp.unlink()

    def test_fail_result(self):
        data = b"test content"
        wrong_hash = "00" * 32
        tmp = _write_tmp(data)
        try:
            result = run_validation(
                file_path=tmp,
                expected_hash=wrong_hash,
                test_id="T-002",
                test_name="Unit test fail",
            )
            assert result.status == TestStatus.FAIL
        finally:
            tmp.unlink()

    def test_file_not_found_error(self):
        result = run_validation(
            file_path=Path("/nonexistent/file.txt"),
            expected_hash="00" * 32,
            test_id="T-003",
            test_name="Missing file",
        )
        assert result.status == TestStatus.ERROR
        assert "not found" in result.error_details.lower() or "No such file" in result.error_details

    def test_to_dict(self):
        data = b"dict test"
        tmp = _write_tmp(data)
        try:
            result = run_validation(
                file_path=tmp,
                expected_hash=_expected(data),
                test_id="T-004",
                test_name="Dict test",
            )
            d = result.to_dict()
            assert d["Test ID"] == "T-004"
            assert d["Status"] == "PASS"
        finally:
            tmp.unlink()


# ---------------------------------------------------------------------------
# Test: File-read errors
# ---------------------------------------------------------------------------

class TestFileReadErrors:

    def test_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            calculate_sha256(Path("/does/not/exist.txt"))

    def test_directory_instead_of_file(self, tmp_path):
        with pytest.raises(ValueError, match="not a regular file"):
            calculate_sha256(tmp_path)
