import pytest
from pathlib import Path

from core.case_manager import CaseManager, CaseMetadata


@pytest.mark.unit
def test_create_case_directory_structure(tmp_path: Path):
    mgr = CaseManager(tmp_path)
    case_dir, metadata = mgr.create_case(case_id="CASE-TEST-001", profile="quick", examiner="Examiner 1")

    assert case_dir.exists()
    assert (case_dir / "evidence").exists()
    assert (case_dir / "manifests").exists()
    assert (case_dir / "reports").exists()
    assert (case_dir / "timeline").exists()
    assert (case_dir / "metadata" / "case_metadata.json").exists()
    assert metadata.case_id == "CASE-TEST-001"
    assert metadata.examiner == "Examiner 1"


@pytest.mark.unit
def test_load_metadata(tmp_path: Path):
    mgr = CaseManager(tmp_path)
    case_dir, _ = mgr.create_case(case_id="CASE-TEST-002", profile="full", description="Incident test")

    loaded = mgr.load_metadata(case_dir)
    assert loaded is not None
    assert loaded.case_id == "CASE-TEST-002"
    assert loaded.profile == "full"
    assert loaded.description == "Incident test"


@pytest.mark.unit
def test_list_cases(tmp_path: Path):
    mgr = CaseManager(tmp_path)
    mgr.create_case("CASE-A")
    mgr.create_case("CASE-B")

    cases = mgr.list_cases()
    assert "CASE-A" in cases
    assert "CASE-B" in cases


@pytest.mark.unit
def test_case_directory_independence(tmp_path: Path):
    mgr = CaseManager(tmp_path)
    c1, _ = mgr.create_case("CASE-1")
    c2, _ = mgr.create_case("CASE-2")

    (c1 / "evidence" / "file1.txt").write_text("c1 data", encoding="utf-8")
    assert not (c2 / "evidence" / "file1.txt").exists()
