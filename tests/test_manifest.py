import pytest
import csv
import json
from pathlib import Path

from core.collector_base import CollectionResult, FileEvidence
from core.manifest import ManifestManager, ManifestEntry
from core.hash_manager import compute_sha256
from config.settings import CollectionStatus, ArtifactCategory


@pytest.mark.unit
def test_manifest_add_result_and_write(tmp_case_dir: Path):
    mgr = ManifestManager(tmp_case_dir)

    test_file = tmp_case_dir / "evidence" / "execution" / "test.exe"
    test_file.write_text("fake binary", encoding="utf-8")

    res = CollectionResult(
        module_id="prefetch",
        module_name="Prefetch Files",
        category=ArtifactCategory.EXECUTION,
        status=CollectionStatus.SUCCESS,
        acquired_files=[
            FileEvidence(
                evidence_id="pf_test",
                original_path="C:\\Windows\\Prefetch\\test.exe",
                acquired_path=str(test_file),
                filename="test.exe",
                extension=".exe",
                file_size=len("fake binary"),
            )
        ],
    )
    mgr.add_collection_result(res)
    csv_path, json_path = mgr.write_manifest()

    assert csv_path.exists()
    assert json_path.exists()

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert len(data) == 1
    assert data[0]["evidence_id"] == "pf_test"
    assert data[0]["sha256"] != ""


@pytest.mark.unit
def test_manifest_verification_unmodified(tmp_case_dir: Path):
    mgr = ManifestManager(tmp_case_dir)

    test_file = tmp_case_dir / "evidence" / "execution" / "clean.exe"
    test_file.write_text("clean evidence", encoding="utf-8")

    res = CollectionResult(
        module_id="mod",
        module_name="Mod",
        category=ArtifactCategory.EXECUTION,
        status=CollectionStatus.SUCCESS,
        acquired_files=[
            FileEvidence(
                evidence_id="ev_clean",
                original_path="C:\\orig\\clean.exe",
                acquired_path=str(test_file),
                filename="clean.exe",
                extension=".exe",
                file_size=test_file.stat().st_size,
            )
        ],
    )
    mgr.add_collection_result(res)
    mgr.write_manifest()

    report = mgr.verify()
    assert len(report["verified"]) == 1
    assert len(report["modified"]) == 0
    assert len(report["missing"]) == 0


@pytest.mark.unit
def test_manifest_verification_detects_modified(tmp_case_dir: Path):
    mgr = ManifestManager(tmp_case_dir)

    test_file = tmp_case_dir / "evidence" / "execution" / "tampered.exe"
    test_file.write_text("original", encoding="utf-8")

    res = CollectionResult(
        module_id="mod",
        module_name="Mod",
        category=ArtifactCategory.EXECUTION,
        status=CollectionStatus.SUCCESS,
        acquired_files=[
            FileEvidence(
                evidence_id="ev_tamper",
                original_path="C:\\orig\\tampered.exe",
                acquired_path=str(test_file),
                filename="tampered.exe",
                extension=".exe",
                file_size=test_file.stat().st_size,
            )
        ],
    )
    mgr.add_collection_result(res)
    mgr.write_manifest()

    # Tamper with file
    test_file.write_text("tampered bytes here!", encoding="utf-8")

    report = mgr.verify()
    assert len(report["verified"]) == 0
    assert len(report["modified"]) == 1
    assert report["modified"][0]["evidence_id"] == "ev_tamper"


@pytest.mark.unit
def test_manifest_verification_detects_missing(tmp_case_dir: Path):
    mgr = ManifestManager(tmp_case_dir)

    test_file = tmp_case_dir / "evidence" / "execution" / "deleted.exe"
    test_file.write_text("will be deleted", encoding="utf-8")

    res = CollectionResult(
        module_id="mod",
        module_name="Mod",
        category=ArtifactCategory.EXECUTION,
        status=CollectionStatus.SUCCESS,
        acquired_files=[
            FileEvidence(
                evidence_id="ev_del",
                original_path="C:\\orig\\deleted.exe",
                acquired_path=str(test_file),
                filename="deleted.exe",
                extension=".exe",
                file_size=test_file.stat().st_size,
            )
        ],
    )
    mgr.add_collection_result(res)
    mgr.write_manifest()

    # Delete the file
    test_file.unlink()

    report = mgr.verify()
    assert len(report["missing"]) == 1
    assert report["missing"][0]["evidence_id"] == "ev_del"
