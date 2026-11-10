"""Shell launch failures must not turn finished acquisitions into failed work."""
from unittest.mock import Mock

import pytest

from desktop.bridge import DesktopBridge
from desktop.settings import SettingsStore
from desktop.secrets import SecretStore


@pytest.mark.parametrize("state,finished", [("COMPLETED", True), ("FAILED", True), ("FAILED", False), ("CANCELLED", False)])
def test_report_and_case_folder_open_once_only_after_workflow_completion(tmp_path, monkeypatch, state, finished):
    report = tmp_path / "report.html"
    report.write_text("QA report")
    result = {"state": state, "workflow_completed": finished, "case_dir": str(tmp_path),
              "outputs": {"report": str(report)}, "warnings": ["Preserved collection note"]}
    monkeypatch.setattr("desktop.bridge.run_mission", Mock(return_value=result))
    launch = Mock()
    monkeypatch.setattr("desktop.bridge.os.startfile", launch, raising=False)
    bridge = DesktopBridge(SettingsStore(tmp_path / "prefs.json"), SecretStore(tmp_path / "keys"))
    bridge._send = Mock()
    bridge._run(None)
    assert bridge._result["state"] == state
    if finished:
        assert [call.args[0] for call in launch.call_args_list] == [str(report.resolve()), str(tmp_path.resolve())]
    else:
        launch.assert_not_called()
    assert bridge._result["warnings"] == ["Preserved collection note"]
    bridge._send.assert_called_once_with("result", bridge._result)


def test_auto_open_failure_still_opens_other_output_and_preserves_finished_state(tmp_path, monkeypatch):
    report = tmp_path / "report.html"
    report.write_text("QA report")
    result = {"state": "FAILED", "workflow_completed": True, "case_dir": str(tmp_path),
              "outputs": {"report": str(report)}, "warnings": ["Collector partial"]}
    monkeypatch.setattr("desktop.bridge.run_mission", Mock(return_value=result))
    launch = Mock(side_effect=[OSError("No associated application"), None])
    monkeypatch.setattr("desktop.bridge.os.startfile", launch, raising=False)
    bridge = DesktopBridge(SettingsStore(tmp_path / "prefs.json"), SecretStore(tmp_path / "keys"))
    bridge._send = Mock()
    bridge._run(None)
    assert launch.call_count == 2
    assert bridge._result["workflow_completed"]
    assert bridge._result["state"] == "FAILED"
    assert bridge._result["warnings"] == ["Collector partial"]
    assert len(bridge._result["output_open_errors"]) == 1
    assert "No associated application" in bridge._result["output_open_errors"][0]
