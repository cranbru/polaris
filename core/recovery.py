"""Finish local reports/archive from preserved evidence without reacquisition.

The original manifest is loaded for verification, never regenerated. Original
failure metadata is copied into a recovery history folder before updates.
"""
from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from config.settings import CollectionStatus, get_iso_timestamp, get_timestamp
from core.case_manager import CaseManager
from core.evidence_manager import EvidenceManager
from core.manifest import ManifestManager
from core.progress import CancellationToken, ProgressTracker, processing_context
from reports.html_report import HtmlReportGenerator
from reports.pdf_report import PdfReportGenerator
from archive.zip_builder import ZipBuilder
from utils.logging_config import setup_logging


def recover_saved_case(case_dir: Path, callback=lambda event: None, token=None) -> dict:
    case_dir = case_dir.resolve()
    manager = CaseManager(case_dir.parent)
    metadata = manager.load_metadata(case_dir)
    if metadata is None:
        raise ValueError("A saved case metadata file is required for recovery.")
    manifest = ManifestManager(case_dir)
    manifest.load_manifest()
    if not manifest.entries:
        raise ValueError("A nonempty original acquisition manifest is required for recovery.")
    token = token or CancellationToken()
    tracker = ProgressTracker([("verifying", "Verifying", 25), ("reporting", "Reporting", 35),
                               ("finalizing", "Finalizing", 40)], callback)
    token.check()
    history = case_dir / "metadata" / "recovery_history" / f"{get_timestamp()}-{uuid.uuid4().hex[:6]}"
    history.mkdir(parents=True)
    for name in ("mission_result.json", "case_metadata.json"):
        saved = case_dir / "metadata" / name
        if saved.exists():
            shutil.copy2(saved, history / name)
    result_file = case_dir / "metadata" / "mission_result.json"
    result = json.loads(result_file.read_text(encoding="utf-8")) if result_file.exists() else {}
    result.update({"case_dir": str(case_dir), "case_id": case_dir.name, "outputs": {},
                   "state": "RUNNING", "recovered_at": get_iso_timestamp(), "reacquired": False})
    if "error" in result:
        result["original_error"] = result.pop("error")
    evidence = EvidenceManager(case_dir)
    evidence.load_results()
    result["artifact_count"] = evidence.get_summary()["total_files"]
    warnings = result.setdefault("warnings", [])
    warnings.append("Reports and archive recovered from saved evidence. No collectors or external AI were run. Original manifest seals retained.")
    logger = setup_logging(case_dir)

    def save():
        manager.update_metadata(case_dir, metadata)
        result_file.write_text(json.dumps(result, indent=2, ensure_ascii=True), encoding="utf-8")

    try:
        with processing_context(token):
            tracker.update("verifying", "Rechecking the original acquisition manifest")
            verification = manifest.verify(progress_callback=lambda done, total: tracker.update(
                "verifying", "Verifying saved evidence", done, total))
            # Provide candidates for legacy metadata that replaced malformed
            # filename characters. Matching bytes do not silently repair a seal
            # or remove the missing/unregistered discrepancy.
            aliases = []
            for missing in verification["missing"]:
                for extra in verification["unexpected"]:
                    if (missing["original_sha256"] and missing["original_sha256"] == extra["sha256"]
                            and Path(missing["path"]).parent == Path(extra["path"]).parent):
                        aliases.append({"evidence_id": missing["evidence_id"], "recorded_path": missing["path"],
                                        "candidate_path": extra["path"], "sha256": extra["sha256"],
                                        "note": "Bytes match the original seal; path differs. Original manifest retained for review."})
            verification["path_alias_candidates"] = aliases
            path = manifest.write_verification_report(verification)
            counts = {k: len(verification[k]) for k in ("verified", "modified", "missing", "unexpected", "errors")}
            result.update({"verification": counts, "verified_count": counts["verified"]})
            result["outputs"]["verification"] = str(path)
            integrity_gaps = any(counts[k] for k in ("modified", "missing", "unexpected", "errors"))
            result["integrity_status"] = "REVIEW_REQUIRED" if integrity_gaps else "VERIFIED"
            result["matched_path_alias_count"] = len(aliases)
            if integrity_gaps:
                warnings.append(f"Integrity review required: {counts['modified']} modified, {counts['missing']} missing, "
                                f"{counts['errors']} unreadable, {counts['unexpected']} unregistered files retained.")
            tracker.finish_stage("verifying", "Original hashes rechecked")
            token.check()
            tracker.update("reporting", "Generating reports from saved evidence", 0, 2)
            result["outputs"]["report"] = str(HtmlReportGenerator(case_dir).generate(include_ai=False))
            tracker.update("reporting", "Generating PDF from saved evidence", 1, 2)
            token.check()
            result["outputs"]["pdf"] = str(PdfReportGenerator(case_dir).generate(include_ai=False))
            tracker.finish_stage("reporting", "Local reports saved")
            result["state"] = "FINALIZING"
            metadata.status = "finalizing"
            metadata.warnings = warnings
            save()
            tracker.update("finalizing", "Packaging saved evidence and diagnostics")
            archive, digest = ZipBuilder(case_dir).build_package(progress_callback=lambda done, total, name:
                tracker.update("finalizing", "Archiving saved evidence", done, total, detail=name))
            result["outputs"]["archive"] = str(archive)
            result["archive_sha256"] = digest
            token.check()
            tracker.finish_stage("finalizing", "Archive saved and hashed")
            collection_gaps = any(r.errors or r.status in {CollectionStatus.FAILED, CollectionStatus.PARTIAL,
                                                           CollectionStatus.SKIPPED} for r in evidence.results)
            result["state"] = "FAILED" if integrity_gaps or collection_gaps else "COMPLETED"
            result["completion_reason"] = "integrity_gaps" if integrity_gaps else "collection_gaps" if collection_gaps else "success"
            metadata.status = "partial" if result["state"] == "FAILED" else "completed"
            save()
            logger.info("Recovered reports and archive from existing case; original manifests unchanged")
            tracker.finish(result["state"], "Reports recovered; review recorded gaps" if result["state"] == "FAILED" else "Reports recovered")
    except Exception as error:
        result["state"] = "CANCELLED" if token.event.is_set() else "FAILED"
        result["error"] = str(error)
        metadata.status = result["state"].lower()
        try:
            save()
        except OSError:
            pass
        logger.exception("Saved-case recovery interrupted")
        tracker.finish(result["state"], "Recovery stopped", error=str(error))
    return result
