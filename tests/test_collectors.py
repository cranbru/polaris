import pytest
from pathlib import Path

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from config.settings import CollectionStatus, ArtifactCategory


class DummyCollector(CollectorBase):
    module_id = "dummy_collector"
    module_name = "Dummy Collector"
    category = ArtifactCategory.SYSTEM
    required_privileges = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        src = self.case_dir / "dummy_src.txt"
        src.write_text("dummy test content", encoding="utf-8")
        evidence = self.copy_file(src, self.evidence_dir)
        if evidence:
            result.acquired_files.append(evidence)
            result.status = CollectionStatus.SUCCESS
        else:
            result.status = CollectionStatus.FAILED
        return result


class FailingCollector(CollectorBase):
    module_id = "failing_collector"
    module_name = "Failing Collector"
    category = ArtifactCategory.SYSTEM
    required_privileges = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        raise RuntimeError("Intentional test crash in collector")


@pytest.mark.unit
def test_collector_copy_file(tmp_case_dir: Path):
    collector = DummyCollector(tmp_case_dir, parse=True)
    src_file = tmp_case_dir / "source.txt"
    src_file.write_text("Hello forensics", encoding="utf-8")

    evidence = collector.copy_file(src_file, collector.evidence_dir, "ev_id_01")
    assert evidence is not None
    assert evidence.filename == "source.txt"
    assert Path(evidence.acquired_path).exists()
    assert evidence.file_size > 0


@pytest.mark.unit
def test_collector_save_text(tmp_case_dir: Path):
    collector = DummyCollector(tmp_case_dir, parse=True)
    evidence = collector.save_text("Test log data", "test.log", collector.evidence_dir)

    assert evidence is not None
    assert evidence.filename == "test.log"
    assert (collector.evidence_dir / "test.log").read_text(encoding="utf-8") == "Test log data"


@pytest.mark.unit
def test_collector_save_json(tmp_case_dir: Path):
    collector = DummyCollector(tmp_case_dir, parse=True)
    data = {"key": "value", "items": [1, 2, 3]}
    evidence = collector.save_json(data, "test.json", collector.parsed_dir)

    assert evidence is not None
    assert evidence.filename == "test.json"
    assert (collector.parsed_dir / "test.json").exists()


@pytest.mark.unit
def test_collector_collect_lifecycle(tmp_case_dir: Path):
    collector = DummyCollector(tmp_case_dir, parse=True)
    result = collector.collect()

    assert result.status == CollectionStatus.SUCCESS
    assert result.artifact_count == 1
    assert len(result.acquired_files) == 1
    assert result.collection_start != ""
    assert result.collection_end != ""


@pytest.mark.unit
def test_collector_unhandled_exception(tmp_case_dir: Path):
    collector = FailingCollector(tmp_case_dir, parse=True)
    result = collector.collect()

    assert result.status == CollectionStatus.FAILED
    assert len(result.errors) > 0
    assert "Intentional test crash" in result.errors[0]
