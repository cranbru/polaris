import pytest
import zipfile
from pathlib import Path

from packaging.zip_builder import ZipBuilder


@pytest.mark.unit
def test_zip_builder_creates_package(tmp_case_dir: Path):
    # Add dummy evidence and metadata
    (tmp_case_dir / "evidence" / "execution" / "test.txt").write_text("dummy evidence", encoding="utf-8")
    (tmp_case_dir / "metadata" / "meta.txt").write_text("metadata", encoding="utf-8")

    builder = ZipBuilder(tmp_case_dir)
    zip_path, zip_hash = builder.build_package()

    assert zip_path.exists()
    assert zip_path.suffix == ".zip"
    assert len(zip_hash) == 64  # SHA-256 length

    hash_file = tmp_case_dir / "archive" / f"{zip_path.name}.sha256"
    assert hash_file.exists()
    assert zip_hash in hash_file.read_text(encoding="utf-8")

    # Verify zip content
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        assert any("test.txt" in n for n in names)
        # Ensure archive itself is not in the zip
        assert not any("archive" in n for n in names)
