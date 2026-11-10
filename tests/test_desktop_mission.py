import json
import zipfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from config.ai_settings import AISettings, AIProviderType
from config.settings import ArtifactCategory, CollectionStatus
from core.collector_base import CollectorBase
from core.progress import CancellationToken, AcquisitionCancelled
from core.mission import MissionOptions, run_mission


@pytest.fixture
def fixture_collectors(monkeypatch):
    from core import engine
    calls = []

    class FixtureCollector(CollectorBase):
        module_id = "fixture"
        module_name = "Fixture Collector"
        category = ArtifactCategory.SYSTEM

        def _collect(self, result):
            calls.append(self.module_id)
            evidence = self.save_text("A known fixture, never live evidence", ".env", self.evidence_dir)
            result.acquired_files.append(evidence)
            if self.parse:
                self.save_json([{ "timestamp": "2026-01-01T01:00:00Z", "event_type": "fixture" }],
                               "fixture.json", self.parsed_dir)
            result.status = CollectionStatus.SUCCESS
            return result

    class DisabledCollector(FixtureCollector):
        module_id = "disabled"

    class FailingCollector(FixtureCollector):
        module_id = "failing"

        def _collect(self, result):
            raise RuntimeError("Fixture collector failed")

    class CancelledCollector(FixtureCollector):
        module_id = "cancelled"

        def _collect(self, result):
            super()._collect(result)
            raise AcquisitionCancelled("Stopped fixture after acquiring one file")

    monkeypatch.setattr(engine, "COLLECTOR_REGISTRY", {c.module_id:c for c in
                        [FixtureCollector, DisabledCollector, FailingCollector, CancelledCollector]})
    monkeypatch.setattr(engine, "_import_all_collectors", lambda: None)
    monkeypatch.setattr(engine, "save_system_info", lambda case: None)
    monkeypatch.setattr(engine, "check_privilege", lambda privilege: True)
    return calls


def test_real_pipeline_preserves_outputs_and_excludes_disabled(tmp_path, fixture_collectors):
    events = []
    result = run_mission(MissionOptions(tmp_path, ["fixture"], ai_settings=AISettings(enabled=False)),
                         events.append, CancellationToken())
    assert result["state"] == "COMPLETED", result
    assert fixture_collectors == ["fixture"]
    assert result["artifact_count"] == result["verified_count"] == 1
    assert all(Path(p).exists() for p in result["outputs"].values())
    assert events[-1].percentage == 100
    assert all(e.percentage is None or e.percentage < 100 for e in events[:-1])
    assert any(e.state == "INDETERMINATE" for e in events)
    assert {e.stage for e in events} == {"initializing", "collecting", "analyzing", "timeline", "verifying", "reporting", "finalizing"}
    with zipfile.ZipFile(result["outputs"]["archive"]) as archive:
        assert "evidence/system/.env" in archive.namelist()
        assert archive.testzip() is None


@pytest.mark.parametrize("module,state", [("cancelled", "CANCELLED"), ("failing", "FAILED")])
def test_interrupted_mission_preserves_diagnostics(tmp_path, fixture_collectors, module, state):
    events = []
    result = run_mission(MissionOptions(tmp_path, [module]), events.append, CancellationToken())
    assert result["state"] == state
    assert events[-1].state == state and events[-1].percentage < 100
    case = Path(result["case_dir"])
    assert (case / "metadata" / "mission_result.json").exists()
    assert (case / "logs" / "mission_error.txt").exists()
    if state == "CANCELLED":
        assert (case / "evidence" / "system" / ".env").exists()
        assert json.loads((case / "metadata" / "collection_results.json").read_text())


def test_collection_gap_retains_reports_but_is_not_success(tmp_path, fixture_collectors):
    events = []
    result = run_mission(MissionOptions(tmp_path, ["fixture", "failing"]), events.append, CancellationToken())
    assert result["state"] == "FAILED"
    assert Path(result["outputs"]["report"]).exists()
    assert Path(result["outputs"]["archive"]).exists()
    assert events[-1].percentage == 100
    assert events[-1].workflow_completed and result["workflow_completed"]
    assert result["completion_reason"] == "collection_gaps"
    assert all(event.percentage is None or event.percentage < 100 for event in events[:-1])


@pytest.mark.parametrize("mode", ["disabled", "declined", "missing-key", "offline"])
def test_ai_privacy_gates(tmp_path, fixture_collectors, monkeypatch, mode):
    for name in ("OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    generate = Mock(side_effect=AssertionError("External generation must not run"))
    monkeypatch.setattr("ai.analyzer.StellarIntelligenceAnalyzer.run_analysis", generate)
    ai = AISettings(enabled=mode != "disabled", provider=AIProviderType.OPENAI,
                    model="selected-model", session_api_key="fixture-key" if mode == "declined" else "")
    if mode == "offline":
        ai.provider = AIProviderType.OFFLINE
    consent = Mock(return_value=False)
    result = run_mission(MissionOptions(tmp_path, ["fixture"], ai_settings=ai),
                         lambda event: None, CancellationToken(), consent)
    assert result["state"] == "COMPLETED", result
    generate.assert_not_called()
    assert consent.call_count == (1 if mode == "declined" else 0)
    if mode == "declined":
        assert "prompt" in consent.call_args.args[0]


def test_metadata_write_failure_still_emits_failed(tmp_path, fixture_collectors, monkeypatch):
    from core.case_manager import CaseManager
    monkeypatch.setattr(CaseManager, "update_metadata", Mock(side_effect=OSError("Disk full fixture")))
    events = []
    result = run_mission(MissionOptions(tmp_path, ["fixture"]), events.append, CancellationToken())
    assert result["state"] == events[-1].state == "FAILED"
    assert "Disk full" in result["error"]
    assert result["workflow_completed"] is False
    assert events[-1].percentage < 100


@pytest.mark.parametrize("discrepancy", ["unexpected", "modified"])
def test_integrity_discrepancies_generate_flagged_outputs_without_ai(tmp_path, fixture_collectors, monkeypatch, discrepancy):
    from core.manifest import ManifestManager
    original_verify = ManifestManager.verify

    def verify_with_discrepancy(manager, *args, **kwargs):
        target = manager.case_dir / "evidence" / "system" / ("unregistered.txt" if discrepancy == "unexpected" else ".env")
        target.write_bytes(b"" if discrepancy == "unexpected" else b"changed evidence")
        return original_verify(manager, *args, **kwargs)

    monkeypatch.setattr(ManifestManager, "verify", verify_with_discrepancy)
    generate = Mock(side_effect=AssertionError("Never send disputed evidence to external AI"))
    monkeypatch.setattr("ai.analyzer.StellarIntelligenceAnalyzer.run_analysis", generate)
    consent = Mock(return_value=True)
    ai = AISettings(enabled=True, provider=AIProviderType.OPENAI, model="chosen-model", session_api_key="fixture-key")
    events = []
    result = run_mission(MissionOptions(tmp_path, ["fixture"], ai_settings=ai), events.append, CancellationToken(), consent)
    assert result["state"] == "FAILED"
    assert result["completion_reason"] == "integrity_gaps"
    assert result["verification"][discrepancy] == 1
    assert all(Path(p).exists() for p in result["outputs"].values())
    assert set(result["outputs"]) == {"report", "pdf", "verification", "archive"}
    assert events[-1].percentage == 100
    assert result["workflow_completed"] and events[-1].workflow_completed
    generate.assert_not_called()
    consent.assert_not_called()
    html = Path(result["outputs"]["report"]).read_text(encoding="utf-8")
    assert "Unregistered Files" in html
    assert "Integrity Review Required:" in html
    with zipfile.ZipFile(result["outputs"]["archive"]) as archive:
        if discrepancy == "unexpected":
            assert "evidence/system/unregistered.txt" in archive.namelist()


def test_saved_case_recovery_preserves_original_seals_and_failure_history(tmp_path, fixture_collectors, monkeypatch):
    from core.recovery import recover_saved_case
    result = run_mission(MissionOptions(tmp_path, ["fixture"]), lambda event: None, CancellationToken())
    case = Path(result["case_dir"])
    manifest_file = case / "manifests" / "SHA256_MANIFEST.json"
    original_manifest = manifest_file.read_bytes()
    result_file = case / "metadata" / "mission_result.json"
    original_result = result_file.read_bytes()
    orphan = case / "evidence" / "system" / "cloud-leftover.txt"
    orphan.write_bytes(b"")
    engine_run = Mock(side_effect=AssertionError("Recovery must not acquire new evidence"))
    monkeypatch.setattr("core.engine.AcquisitionEngine.run", engine_run)
    recovered = recover_saved_case(case)
    assert recovered["state"] == "FAILED"
    assert recovered["completion_reason"] == "integrity_gaps"
    assert recovered["verification"] == {"verified": 1, "modified": 0, "missing": 0, "unexpected": 1, "errors": 0}
    assert manifest_file.read_bytes() == original_manifest
    assert orphan.exists() and orphan.stat().st_size == 0
    assert recovered["reacquired"] is False
    assert all(Path(p).exists() for p in recovered["outputs"].values())
    history = list((case / "metadata" / "recovery_history").glob("*/mission_result.json"))
    assert len(history) == 1 and history[0].read_bytes() == original_result
    engine_run.assert_not_called()
