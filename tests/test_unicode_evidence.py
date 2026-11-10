import json
import sys
import zipfile
from pathlib import Path

import pytest

from core.manifest import ManifestManager
from core.evidence_manager import EvidenceManager
from core.collector_base import CollectionResult, FileEvidence
from core.hash_manager import compute_sha256
from config.settings import ArtifactCategory, CollectionStatus
from archive.zip_builder import ZipBuilder


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS permits unpaired UTF-16 filename code units")
def test_malformed_ntfs_filename_survives_metadata_and_archive(tmp_case_dir):
    evidence = tmp_case_dir / "evidence" / "user_activity" / "shortcut-\udfc6\ud83c⚡\udea9\ud83d.lnk"
    evidence.write_bytes(b"preserve these original bytes")
    result = CollectionResult(module_id="lnk_files", module_name="Shortcuts", category=ArtifactCategory.USER_ACTIVITY,
                              status=CollectionStatus.SUCCESS, acquired_files=[FileEvidence(
                                  evidence_id="fixture", acquired_path=str(evidence), original_path=str(evidence),
                                  filename=evidence.name, file_size=evidence.stat().st_size)], artifact_count=1)
    manifests = ManifestManager(tmp_case_dir)
    manifests.add_collection_result(result)
    manifests.write_manifest()
    loaded = ManifestManager(tmp_case_dir)
    loaded.load_manifest()
    assert loaded.entries[0].acquired_path == str(evidence)
    assert loaded.verify()["missing"] == []
    assert len(loaded.verify()["verified"]) == 1
    evidence_manager = EvidenceManager(tmp_case_dir)
    evidence_manager.add_result(result)
    evidence_manager.save_results()
    assert EvidenceManager(tmp_case_dir).load_results()[0].acquired_files[0].acquired_path == str(evidence)
    archive, digest = ZipBuilder(tmp_case_dir).build_package()
    with zipfile.ZipFile(archive) as bundle:
        mapping = json.loads(bundle.read("_POLARIS_ARCHIVE_FILENAME_MAP.json"))
        assert mapping[0]["source_path"] == evidence.relative_to(tmp_case_dir).as_posix()
        assert bundle.read(mapping[0]["archive_path"]) == evidence.read_bytes()
        assert bundle.testzip() is None
    assert compute_sha256(archive) == digest
    assert evidence.exists()


def test_non_ascii_unicode_names_stay_unchanged_in_zip(tmp_case_dir):
    evidence = tmp_case_dir / "evidence" / "execution" / "evidence-⚡-日本語.txt"
    evidence.write_bytes(b"fixture")
    archive, _ = ZipBuilder(tmp_case_dir).build_package()
    with zipfile.ZipFile(archive) as bundle:
        assert evidence.relative_to(tmp_case_dir).as_posix() in bundle.namelist()
        assert "_POLARIS_ARCHIVE_FILENAME_MAP.json" not in bundle.namelist()
