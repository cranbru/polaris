from pathlib import Path
from config.settings import DEFAULT_OUTPUT_DIR
from cli.mission_control import render_mission_control


def show_dashboard(base_dir: Path = DEFAULT_OUTPUT_DIR, case_id: str | None = None) -> None:
    render_mission_control(base_dir=base_dir, active_case=case_id)
