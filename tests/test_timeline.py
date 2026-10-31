import pytest
import json
from pathlib import Path

from core.timeline import TimelineBuilder, TimelineEvent


@pytest.mark.unit
def test_timeline_add_and_sort(tmp_case_dir: Path):
    builder = TimelineBuilder(tmp_case_dir)

    e1 = TimelineEvent(timestamp="2026-10-31T12:00:00", event_description="Event 2")
    e2 = TimelineEvent(timestamp="2026-10-31T10:00:00", event_description="Event 1")
    e3 = TimelineEvent(timestamp="2026-10-31T14:00:00", event_description="Event 3")

    builder.add_events([e1, e2, e3])
    builder.sort_events()

    assert builder.events[0].event_description == "Event 1"
    assert builder.events[1].event_description == "Event 2"
    assert builder.events[2].event_description == "Event 3"


@pytest.mark.unit
def test_timeline_write_csv_and_json(tmp_case_dir: Path):
    builder = TimelineBuilder(tmp_case_dir)
    builder.add_event(TimelineEvent(
        timestamp="2026-10-31T10:00:00",
        event_category="Execution",
        event_description="Process started",
        source_artifact="Prefetch",
        user="SYSTEM",
    ))

    csv_path = builder.write_timeline()
    assert csv_path.exists()
    assert (tmp_case_dir / "timeline" / "TIMELINE.json").exists()


@pytest.mark.unit
def test_timeline_build_from_parsed(tmp_case_dir: Path):
    parsed_dir = tmp_case_dir / "parsed" / "execution"
    parsed_dir.mkdir(parents=True, exist_ok=True)

    test_data = [
        {"timestamp": "2026-10-31T09:00:00", "executable": "cmd.exe", "user": "admin"},
        {"timestamp": "2026-10-31T09:30:00", "executable": "powershell.exe", "user": "admin"},
    ]
    with open(parsed_dir / "parsed_exec.json", "w", encoding="utf-8") as f:
        json.dump(test_data, f)

    builder = TimelineBuilder(tmp_case_dir)
    builder.build_from_parsed()

    assert len(builder.events) == 2
    builder.sort_events()
    assert "cmd.exe" in builder.events[0].process_or_application or "cmd.exe" in builder.events[0].event_description
