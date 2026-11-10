"""Run existing forensic operations without coupling them to a terminal or GUI."""
from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from config.settings import CollectionProfile, CollectionStatus, get_timestamp, get_iso_timestamp
from config.ai_settings import AISettings, AIProviderType
from core.case_manager import CaseManager
from core.engine import AcquisitionEngine
from core.timeline import TimelineBuilder
from core.progress import CancellationToken, AcquisitionCancelled, ProgressTracker, processing_context
from analysis.rules import RulesEngine
from analysis.correlation import CorrelationEngine
from analysis.investigator_notes import InvestigatorNotesManager
from reports.html_report import HtmlReportGenerator
from reports.pdf_report import PdfReportGenerator
from archive.zip_builder import ZipBuilder


@dataclass
class MissionOptions:
    output_dir: Path
    modules: list[str]
    profile: str = "quick"
    parse: bool = True
    case_id: str = ""
    examiner: str = ""
    description: str = ""
    ai_settings: AISettings | None = None


def run_mission(options: MissionOptions, callback: Callable, token: CancellationToken,
                consent_callback: Callable | None = None) -> dict:
    """Every stage below calls a real existing operation. No simulated progress."""
    stages = [("initializing", "Initializing", 4), ("collecting", "Collecting / parsing", 58)]
    if options.parse:
        stages += [("analyzing", "Analyzing", 12), ("timeline", "Timeline", 5)]
    stages += [("verifying", "Verifying", 7)]
    if options.ai_settings and options.ai_settings.enabled:
        stages += [("intelligence", "Intelligence", 5)]
    stages += [("reporting", "Reporting", 7), ("finalizing", "Finalizing", 5)]
    tracker = ProgressTracker(stages, callback)
    result = {"state": "INITIALIZING", "case_dir": "", "outputs": {}, "warnings": [], "modules": [],
              "workflow_completed": False}
    engine = None
    metadata = None
    manager = None
    case_dir = None

    def observe(operation, detail):
        tracker.update(tracker.current, operation, tracker.completed, None, detail=detail)

    def save_result():
        if case_dir:
            path = case_dir / "metadata" / "mission_result.json"
            path.write_text(json.dumps(result, indent=2, ensure_ascii=True), encoding="utf-8")

    def preserve_metadata():
        if metadata and manager:
            try:
                manager.update_metadata(case_dir, metadata)
            except OSError as diagnostic_error:
                result["warnings"].append(f"Could not save case metadata: {diagnostic_error}")

    try:
        with processing_context(token, observe):
            tracker.update("initializing", "Initializing Polaris Engine…")
            token.check()
            cid = options.case_id or f"CASE-{get_timestamp()}-{uuid.uuid4().hex[:6].upper()}"
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", cid):
                raise ValueError("Case IDs may contain letters, numbers, underscores and hyphens.")
            if not options.modules:
                raise ValueError("Select at least one supported collector.")
            manager = CaseManager(options.output_dir.resolve())
            if (manager.base_dir / cid).exists():
                raise ValueError("That case already exists. Choose a new case ID to preserve earlier evidence.")
            case_dir, metadata = manager.create_case(cid, options.profile, options.examiner, options.description)
            result["case_dir"] = str(case_dir)
            result["case_id"] = cid
            metadata.status = "running"
            metadata.collection_start = get_iso_timestamp()
            manager.update_metadata(case_dir, metadata)
            engine = AcquisitionEngine(case_dir, CollectionProfile(options.profile), options.parse, options.modules)
            tracker.finish_stage("initializing", "Engine initialized")

            def collected(name, completed, total):
                tracker.update("collecting", f"Collecting {name}", completed, total,
                               detail=f"{completed} of {total} selected collectors processed")
            tracker.update("collecting", "Discovering evidence sources…", 0, len(options.modules))
            evidence = engine.run(progress_callback=collected)
            token.check()
            result["modules"] = [{"id": r.module_id, "name": r.module_name, "status": r.status.value,
                                  "files": r.artifact_count, "errors": r.errors, "warnings": r.warnings}
                                 for r in evidence.results]
            summary = evidence.get_summary()
            result["artifact_count"] = summary["total_files"]
            for item in evidence.results:
                result["warnings"].extend(f"{item.module_name}: {warning}" for warning in item.warnings)
                result["warnings"].extend(f"{item.module_name}: {error}" for error in item.errors)
                if item.status != CollectionStatus.SUCCESS:
                    result["warnings"].append(f"{item.module_name}: {item.status.value}")
            metadata.total_artifacts = summary["total_files"]
            metadata.successful = len(evidence.get_results_by_status(CollectionStatus.SUCCESS))
            metadata.failed = len(evidence.get_results_by_status(CollectionStatus.FAILED))
            metadata.skipped = len(evidence.get_results_by_status(CollectionStatus.SKIPPED))
            tracker.finish_stage("collecting", "Selected collectors processed")
            if not evidence.get_all_evidence_files():
                raise RuntimeError("No evidence was acquired. Review collector diagnostics and administrator permissions.")

            if options.parse:
                tracker.update("analyzing", "Analyzing execution traces…")
                findings = RulesEngine(case_dir).run_all_rules(
                    progress_callback=lambda done, total, name: tracker.update(
                        "analyzing", "Evaluating forensic rules", done, total * 2, detail=name))
                token.check()
                findings += CorrelationEngine(case_dir).correlate(
                    progress_callback=lambda done, total, name: tracker.update(
                        "analyzing", "Correlating artifact observations", total + done, total * 2, detail=name))
                InvestigatorNotesManager(case_dir).save_findings(findings)
                result["finding_count"] = len(findings)
                tracker.finish_stage("analyzing", "Forensic analysis saved")
                tracker.update("timeline", "Building evidence timeline…")
                timeline = TimelineBuilder(case_dir)
                timeline.build_from_parsed(progress_callback=lambda done, total, name: tracker.update(
                    "timeline", "Reading parsed timeline records", done, total, detail=name))
                token.check()
                timeline.write_timeline()
                result["event_count"] = len(timeline.events)
                tracker.finish_stage("timeline", "Evidence timeline saved")

            tracker.update("verifying", "Verifying acquired evidence…")
            manifest = engine.manifest_manager
            verification = manifest.verify(progress_callback=lambda done, total: tracker.update(
                "verifying", "Verifying SHA-256 integrity", done, total,
                detail=f"{done} of {total} files checked"))
            verification_path = manifest.write_verification_report(verification)
            result["outputs"]["verification"] = str(verification_path)
            result["verification"] = {k: len(verification[k]) for k in
                                      ("verified", "missing", "modified", "errors", "unexpected")}
            result["verified_count"] = len(verification["verified"])
            integrity_gaps = any(verification[k] for k in ("missing", "modified", "errors", "unexpected"))
            result["integrity_status"] = "REVIEW_REQUIRED" if integrity_gaps else "VERIFIED"
            if integrity_gaps:
                counts = result["verification"]
                result["warnings"].append(
                    "Evidence verification requires review: "
                    f"{counts['modified']} modified, {counts['missing']} missing, "
                    f"{counts['errors']} unreadable, {counts['unexpected']} unregistered files. "
                    "Reports and archive retain these discrepancies.")
            tracker.finish_stage("verifying", "Verification finished with discrepancies" if integrity_gaps else "Evidence hashes verified")

            ai = options.ai_settings
            include_ai = False
            if ai and ai.enabled:
                tracker.update("intelligence", "Preparing selected evidence for AI review…")
                if integrity_gaps:
                    result["warnings"].append("AI skipped: resolve evidence verification discrepancies before external analysis.")
                elif ai.provider == AIProviderType.OFFLINE:
                    # Build a case-specific local summary from actual completed operations.
                    content = (f"### Offline forensic summary\n\n"
                               f"Acquired **{result['artifact_count']}** files across **{len(evidence.results)}** collectors.\n\n"
                               f"Verified **{result['verified_count']}** hashes.\n\n"
                               f"Recorded **{result.get('finding_count', 0)}** rule/correlation findings and "
                               f"**{result.get('event_count', 0)}** timeline events.\n\n"
                               f"Collection gaps: {'; '.join(result['warnings']) or 'None recorded'}.\n\n"
                               "Review source artifacts and limitations before drawing conclusions. No external AI request was made.")
                    (case_dir / "metadata" / "ai_analysis.json").write_text(json.dumps({
                        "provider": "offline", "model": "deterministic case summary", "content": content,
                        "analysis_timestamp": get_iso_timestamp(), "evidence_reference_count": result.get("finding_count", 0),
                        "is_error": False}), encoding="utf-8")
                    include_ai = True
                elif not ai.has_valid_key() or not ai.model:
                    result["warnings"].append("AI skipped: configure a provider key and model to enable external analysis.")
                else:
                    from ai.analyzer import StellarIntelligenceAnalyzer
                    analyzer = StellarIntelligenceAnalyzer(case_dir, ai)
                    packet = analyzer.prepare_analysis()
                    (case_dir / "metadata" / "ai_input_preview.json").write_text(
                        json.dumps(packet, indent=2, ensure_ascii=False), encoding="utf-8")
                    tracker.update("intelligence", "Awaiting examiner approval to share selected evidence…")
                    approved = consent_callback(packet) if consent_callback else False
                    token.check()
                    if approved:
                        ai.consent_granted = True
                        tracker.update("intelligence", f"Analyzing with {ai.provider.value}…")
                        payload = analyzer.run_analysis(prepared=packet)
                        include_ai = not payload.get("is_error")
                        if payload.get("is_error"):
                            result["warnings"].append("AI analysis failed; diagnostic information was preserved.")
                        elif payload.get("provider") == "offline":
                            result["warnings"].append("External AI was unavailable; the existing offline fallback was used.")
                    else:
                        result["warnings"].append("External AI declined. Evidence acquisition continues locally.")
                tracker.finish_stage("intelligence", "Intelligence stage finished")

            tracker.update("reporting", "Generating forensic HTML report…", 0, 2)
            token.check()
            html_path = HtmlReportGenerator(case_dir).generate(include_ai=include_ai)
            result["outputs"]["report"] = str(html_path)
            tracker.update("reporting", "Generating forensic PDF report…", 1, 2)
            token.check()
            pdf_path = PdfReportGenerator(case_dir).generate(include_ai=include_ai)
            result["outputs"]["pdf"] = str(pdf_path)
            token.check()
            tracker.finish_stage("reporting", "Forensic reports saved")

            tracker.update("finalizing", "Packaging preserved evidence…")
            result["state"] = "FINALIZING"
            metadata.status = "finalizing"
            metadata.collection_end = get_iso_timestamp()
            metadata.warnings = result["warnings"]
            manager.update_metadata(case_dir, metadata)
            save_result()
            archive, archive_hash = ZipBuilder(case_dir).build_package(progress_callback=lambda done, total, name:
                tracker.update("finalizing", "Packaging evidence archive", done, total, detail=name))
            token.check()
            result["outputs"]["archive"] = str(archive)
            result["archive_sha256"] = archive_hash
            tracker.finish_stage("finalizing", "Evidence archive saved and hashed")
            # Missing/uninstalled artifact types are collection gaps, not fake evidence.
            has_failures = integrity_gaps or any(r.errors or r.status in {CollectionStatus.FAILED, CollectionStatus.PARTIAL, CollectionStatus.SKIPPED}
                               for r in evidence.results)
            state = "FAILED" if has_failures else "COMPLETED"
            result["state"] = state
            result["completion_reason"] = "integrity_gaps" if integrity_gaps else "collection_gaps" if has_failures else "success"
            result["workflow_completed"] = True
            metadata.status = "partial" if has_failures else "completed"
            manager.update_metadata(case_dir, metadata)
            save_result()
            tracker.finish(state, "Reports ready — integrity review required" if integrity_gaps else
                           "Finished with collection gaps" if has_failures else "Investigation complete",
                           detail="Reports and available evidence have been preserved." if has_failures else
                           f"{result['artifact_count']} files acquired · {result['verified_count']} hashes verified",
                           workflow_completed=True)
    except (Exception, KeyboardInterrupt) as error:
        cancelled = isinstance(error, AcquisitionCancelled)
        result["state"] = "CANCELLED" if cancelled else "FAILED"
        result["workflow_completed"] = False
        result["error"] = str(error)
        # Recover previous and partial collector results even when cancellation
        # occurs between modules or while flushing a manifest.
        if engine:
            try:
                engine.manifest_manager.write_manifest()
                engine.evidence_manager.save_results()
            except OSError:
                pass
        if metadata and manager:
            metadata.status = result["state"].lower()
            metadata.collection_end = get_iso_timestamp()
            preserve_metadata()
        if case_dir:
            logging.getLogger("polaris").exception("Mission interrupted")
            try:
                (case_dir / "logs" / "mission_error.txt").write_text(str(error), encoding="utf-8")
                save_result()
            except OSError:
                pass
        tracker.finish(result["state"], "Acquisition cancelled" if cancelled else "Acquisition needs attention",
                       error=str(error), detail="Available evidence and diagnostics were preserved.")
    return result
