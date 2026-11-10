"""Opt-in Windows desktop smoke check. Runs only System Information, with AI off.

Run from the repository: python -m tests.run_desktop_live_check
Evidence stays in the temporary QA folder, outside the project.
"""
import json
import tempfile
from pathlib import Path

from core.mission import MissionOptions, run_mission
from core.progress import CancellationToken
from config.ai_settings import AISettings


def main():
    root = Path(tempfile.gettempdir()) / "polaris-ui-validation"
    root.mkdir(exist_ok=True)
    events = []
    result = run_mission(MissionOptions(root / "cases", ["system_info"],
                                      examiner="Desktop QA", ai_settings=AISettings(enabled=False)),
                         lambda event: events.append(event.to_dict()), CancellationToken())
    (root / "live-run.json").write_text(json.dumps({"events": events, "result": result}), encoding="utf-8")
    print(json.dumps({"state": result["state"], "files": result.get("artifact_count"),
                      "verified": result.get("verified_count"), "events": len(events),
                      "case_dir": result["case_dir"], "error": result.get("error")}, indent=2))
    assert result["state"] == "COMPLETED", result.get("error")
    assert events[-1]["percentage"] == 100
    assert all(e["percentage"] is None or e["percentage"] < 100 for e in events[:-1])


if __name__ == "__main__":
    main()
