from pathlib import Path

import pytest

from core.collector_base import CollectorBase


class CopyCollector(CollectorBase):
    module_id = "copy_fixture"
    module_name = "Copy fixture"

    def _collect(self, result):
        return result


@pytest.mark.parametrize("copied_bytes", [b"", b"incomplete cloud download"])
def test_failed_copy_leaves_no_unregistered_evidence(tmp_case_dir, monkeypatch, copied_bytes):
    collector = CopyCollector(tmp_case_dir)
    source = tmp_case_dir / "cloud-passwords.txt"
    source.write_bytes(b"source is still here")

    def failed_cloud_copy(src, destination):
        Path(destination).write_bytes(copied_bytes)
        raise OSError("Cloud file provider unavailable")

    monkeypatch.setattr("core.collector_base.shutil.copy2", failed_cloud_copy)
    assert collector.copy_file(source, collector.evidence_dir) is None
    assert not list(collector.evidence_dir.iterdir())
    assert source.read_bytes() == b"source is still here"
    assert not list((tmp_case_dir / ".staging").iterdir())


def test_failed_raw_copy_preserves_previous_destination(tmp_case_dir, monkeypatch):
    collector = CopyCollector(tmp_case_dir)
    source = tmp_case_dir / "source.txt"
    source.write_bytes(b"new bytes")
    destination = collector.evidence_dir / "existing.txt"
    destination.write_bytes(b"preserved evidence")

    def failed_copy(src, temporary):
        Path(temporary).write_bytes(b"partial")
        raise PermissionError("Cannot read cloud source")

    monkeypatch.setattr("core.collector_base.shutil.copy2", failed_copy)
    assert collector.copy_file_raw(source, destination) is None
    assert destination.read_bytes() == b"preserved evidence"


def test_failed_output_write_preserves_previous_destination(tmp_case_dir, monkeypatch):
    collector = CopyCollector(tmp_case_dir)
    destination = collector.evidence_dir / "command.txt"
    destination.write_bytes(b"earlier capture")
    original_write = Path.write_text

    def failed_write(path, *args, **kwargs):
        if path.suffix == ".partial":
            path.write_bytes(b"partial")
            raise OSError("Disk full")
        return original_write(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", failed_write)
    assert collector.save_text("new capture", destination.name, collector.evidence_dir) is None
    assert destination.read_bytes() == b"earlier capture"


def test_successful_copies_still_preserve_unique_outputs(tmp_case_dir):
    collector = CopyCollector(tmp_case_dir)
    source = tmp_case_dir / "source.txt"
    source.write_bytes(b"complete evidence")
    first = collector.copy_file(source, collector.evidence_dir)
    second = collector.copy_file(source, collector.evidence_dir)
    assert first.acquired_path != second.acquired_path
    assert Path(first.acquired_path).read_bytes() == Path(second.acquired_path).read_bytes() == source.read_bytes()
    assert first.file_size == second.file_size == len(b"complete evidence")


def test_sensitive_scan_excludes_current_output_with_any_folder_name(tmp_path, monkeypatch):
    from collectors.sensitive_files.sensitive_file_collector import SensitiveFileCollector
    source_root = tmp_path / "user"
    source_root.mkdir()
    (source_root / "passwords.txt").write_text("fixture")
    case = source_root / "custom-output"
    collector = SensitiveFileCollector(case)
    (collector.evidence_dir / "private.key").write_text("previous output")
    monkeypatch.setattr("collectors.sensitive_files.sensitive_file_collector._get_scan_roots", lambda: [source_root, case])
    result = collector.collect()
    assert any(Path(item.original_path).name == "passwords.txt" for item in result.acquired_files)
    assert not any(Path(item.original_path).is_relative_to(case) for item in result.acquired_files
                   if item.original_path != "live_system_command")
