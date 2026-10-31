import pytest
from pathlib import Path

from core.collector_base import CollectionResult, FileEvidence
from core.evidence_manager import EvidenceManager
from config.settings import CollectionStatus, ArtifactCategory


@pytest.mark.unit
def test_evidence_manager_add_and_get(tmp_case_dir: Path):
    mgr = EvidenceManager(tmp_case_dir)
    res = CollectionResult(
        module_id="test_mod",
        module_name="Test Module",
        category=ArtifactCategory.SYSTEM,
        status=CollectionStatus.SUCCESS,
        acquired_files=[
            FileEvidence(evidence_id="ev_1", original_path="C:\\orig.txt", acquired_path=str(tmp_case_dir / "orig.txt"), filename="orig.txt")
        ],
        artifact_count=1,
    )
    mgr.add_result(res)

    files = mgr.get_all_evidence_files()
    assert len(files) == 1
    assert files[0].evidence_id == "ev_1"


@pytest.mark.unit
def test_evidence_manager_filter_category(tmp_case_dir: Path):
    mgr = EvidenceManager(tmp_case_dir)
    mgr.add_result(CollectionResult(
        module_id="sys", module_name="Sys", category=ArtifactCategory.SYSTEM, status=CollectionStatus.SUCCESS
    ))
    mgr.add_result(CollectionResult(
        module_id="reg", module_name="Reg", category=ArtifactCategory.REGISTRY, status=CollectionStatus.SUCCESS
    ))

    sys_res = mgr.get_results_by_category("system")
    assert len(sys_res) == 1
    assert sys_res[0].module_id == "sys"


@pytest.mark.unit
def test_evidence_manager_summary(tmp_case_dir: Path):
    mgr = EvidenceManager(tmp_case_dir)
    mgr.add_result(CollectionResult(
        module_id="m1", module_name="M1", category=ArtifactCategory.SYSTEM, status=CollectionStatus.SUCCESS, artifact_count=2
    ))
    mgr.add_result(CollectionResult(
        module_id="m2", module_name="M2", category=ArtifactCategory.EXECUTION, status=CollectionStatus.FAILED, errors=["Access denied"]
    ))

    summary = mgr.get_summary()
    assert summary["total_modules"] == 2
    assert summary["total_files"] == 2
    assert summary["status_counts"]["SUCCESS"] == 1
    assert summary["status_counts"]["FAILED"] == 1
    assert len(summary["errors"]) == 1


@pytest.mark.unit
def test_evidence_manager_save_and_load(tmp_case_dir: Path):
    mgr = EvidenceManager(tmp_case_dir)
    mgr.add_result(CollectionResult(
        module_id="m1", module_name="M1", category=ArtifactCategory.SYSTEM, status=CollectionStatus.SUCCESS
    ))
    saved_path = mgr.save_results()
    assert saved_path.exists()

    mgr2 = EvidenceManager(tmp_case_dir)
    loaded = mgr2.load_results()
    assert len(loaded) == 1
    assert loaded[0].module_id == "m1"
