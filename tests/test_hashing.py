import pytest
import hashlib
from pathlib import Path

from core.hash_manager import compute_sha256, compute_sha256_bytes


@pytest.mark.unit
def test_compute_sha256_known_content(tmp_path: Path):
    test_file = tmp_path / "test.txt"
    content = b"POLARIS Forensic Evidence Hashing Test"
    test_file.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    actual = compute_sha256(test_file)

    assert actual == expected


@pytest.mark.unit
def test_compute_sha256_bytes():
    data = b"Forensic integrity data chunk"
    expected = hashlib.sha256(data).hexdigest()
    assert compute_sha256_bytes(data) == expected


@pytest.mark.unit
def test_compute_sha256_empty_file(tmp_path: Path):
    empty_file = tmp_path / "empty.dat"
    empty_file.write_bytes(b"")

    expected = hashlib.sha256(b"").hexdigest()
    assert compute_sha256(empty_file) == expected


@pytest.mark.unit
def test_compute_sha256_large_content(tmp_path: Path):
    large_file = tmp_path / "large.dat"
    chunk = b"A" * 1024 * 100  # 100 KB
    large_file.write_bytes(chunk)

    expected = hashlib.sha256(chunk).hexdigest()
    assert compute_sha256(large_file) == expected


@pytest.mark.unit
def test_sha256_consistency(tmp_path: Path):
    f1 = tmp_path / "f1.txt"
    f2 = tmp_path / "f2.txt"
    f1.write_text("identical content", encoding="utf-8")
    f2.write_text("identical content", encoding="utf-8")

    assert compute_sha256(f1) == compute_sha256(f2)
