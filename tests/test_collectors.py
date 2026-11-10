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


@pytest.mark.unit
def test_all_expected_collectors_registered():
    from core.engine import get_registered_collectors
    registered = get_registered_collectors()
    expected_modules = [
        "prefetch",
        "amcache",
        "shimcache",
        "bam",
        "dam",
        "srum",
        "userassist",
        "pca",
        "powershell",
        "eventlogs",
        "lnk_files",
        "jump_lists",
        "recent_docs",
        "shellbags",
        "recycle_bin",
        "registry_hives",
        "registry_artifacts",
        "browser_chrome",
        "browser_edge",
        "browser_firefox",
        "usb_devices",
        "persistence",
        "network_info",
        "system_info",
        "sensitive_files",
    ]
    for module_id in expected_modules:
        assert module_id in registered, f"Missing registered collector for {module_id}"


@pytest.mark.unit
def test_sensitive_file_collector(tmp_case_dir: Path, monkeypatch):
    from collectors.sensitive_files.sensitive_file_collector import (
        SensitiveFileCollector,
        _is_sensitive_file,
    )

    # 1. Test helper matching
    assert _is_sensitive_file(Path("passwords.txt")) is True
    assert _is_sensitive_file(Path("backupcodes.txt")) is True
    assert _is_sensitive_file(Path("backup_codes.txt")) is True
    assert _is_sensitive_file(Path("wallet.dat")) is True
    assert _is_sensitive_file(Path(".env")) is True
    assert _is_sensitive_file(Path("WINWORD.EXE-AB6EC2FA.pf")) is False
    assert _is_sensitive_file(Path("normal_document.docx")) is False

    # 2. Test collection with mock scan roots
    fake_root = tmp_case_dir.parent / "fake_user_dir"
    fake_root.mkdir(parents=True)
    
    # Matching normal size file
    cred_file = fake_root / "passwords.txt"
    cred_file.write_text("user:admin\npass:secret123", encoding="utf-8")

    # Matching oversized file
    large_cred = fake_root / "backupcodes.txt"
    large_cred.write_bytes(b"A" * 100)

    # Ignored binary file
    ignored_bin = fake_root / "app.exe"
    ignored_bin.write_bytes(b"\x00" * 10)

    # Monkeypatch scan roots to point only to our fake dir
    monkeypatch.setattr(
        "collectors.sensitive_files.sensitive_file_collector._get_scan_roots",
        lambda: [fake_root],
    )
    # Monkeypatch size limit to test cap handling
    monkeypatch.setattr(
        "collectors.sensitive_files.sensitive_file_collector.MAX_FILE_SIZE_BYTES",
        50,  # 50 bytes cap
    )

    collector = SensitiveFileCollector(tmp_case_dir, parse=True)
    result = collector.collect()

    assert result.status == CollectionStatus.SUCCESS
    # passwords.txt should be copied (under 50 bytes)
    copied_names = [Path(f.acquired_path).name for f in result.acquired_files]
    assert any("passwords" in name for name in copied_names)

    # Verify inventory was created in parsed dir
    inv_file = tmp_case_dir / "parsed" / "user_activity" / "sensitive_files" / "sensitive_files_inventory.json"
    assert inv_file.exists()
    import json
    inv_data = json.loads(inv_file.read_text(encoding="utf-8"))
    assert len(inv_data) == 2  # passwords.txt and backupcodes.txt
    
    # passwords.txt copied
    pass_entry = next(e for e in inv_data if "passwords.txt" in e["filename"])
    assert pass_entry["copied"] is True

    # backupcodes.txt skipped due to size limit
    backup_entry = next(e for e in inv_data if "backupcodes.txt" in e["filename"])
    assert backup_entry["copied"] is False
    assert "size limit" in backup_entry["skipped_reason"]

