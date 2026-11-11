import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from config.settings import TIMELINE_CSV, Severity, Confidence, get_iso_timestamp


class TimelineEvent(BaseModel):
    timestamp: str
    event_id: str = ""
    event_type: str = ""
    source_record_id: str = ""
    source_field: str = ""
    source_evidence_path: str = ""
    browser: str = ""
    profile: str = ""
    original_timestamp: str = ""
    timezone: str = ""
    event_category: str = ""
    event_description: str = ""
    source_artifact: str = ""
    evidence_id: str = ""
    user: str = ""
    process_or_application: str = ""
    severity: str = Severity.INFO.value
    confidence: str = Confidence.MEDIUM.value


def _sanitize_dict(d: dict) -> dict:
    sanitized = {}
    for k, v in d.items():
        if isinstance(v, str):
            sanitized[k] = v.encode("utf-8", errors="replace").decode("utf-8")
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_dict(v)
        else:
            sanitized[k] = v
    return sanitized


class TimelineBuilder:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.timeline_dir = case_dir / "timeline"
        self.timeline_dir.mkdir(parents=True, exist_ok=True)
        self.events: list[TimelineEvent] = []

    def add_event(self, event: TimelineEvent) -> None:
        self.events.append(event)

    def add_events(self, events: list[TimelineEvent]) -> None:
        self.events.extend(events)

    def sort_events(self) -> None:
        def chronological_key(event):
            try:
                instant = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
                # Preserve legacy naive timestamps while ordering aware events by UTC.
                return instant.replace(tzinfo=timezone.utc) if instant.tzinfo is None else instant.astimezone(timezone.utc)
            except (ValueError, TypeError, OverflowError):
                return datetime.max.replace(tzinfo=timezone.utc)
        self.events.sort(key=chronological_key)

    def filter_by_category(self, category: str) -> list[TimelineEvent]:
        return [e for e in self.events if e.event_category == category]

    def filter_by_severity(self, severity: str) -> list[TimelineEvent]:
        return [e for e in self.events if e.severity == severity]

    def build_from_parsed(self, progress_callback=None) -> None:
        parsed_dir = self.case_dir / "parsed"
        if not parsed_dir.exists():
            return

        from core.progress import check_cancelled
        files = list(parsed_dir.rglob("*.json"))
        for index, json_file in enumerate(files, 1):
            check_cancelled()
            try:
                with open(json_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for record in data:
                        check_cancelled()
                        if json_file.relative_to(parsed_dir).parts[0] == "browsers":
                            from parsers.browsers.events import browser_events
                            self.events.extend(TimelineEvent(**event) for event in browser_events(record, json_file.stem))
                            continue
                        event = self._record_to_event(record, json_file.stem)
                        if event:
                            self.events.append(event)
            except (json.JSONDecodeError, OSError):
                pass
            if progress_callback:
                progress_callback(index, len(files), json_file.name)

    def _record_to_event(self, record: dict, source: str) -> TimelineEvent | None:
        timestamp = ""
        for key in ["timestamp", "Timestamp", "time", "Time", "datetime",
                     "last_execution", "LastExecutionTime", "created", "modified",
                     "TimeCreated", "install_date", "start_time", "event_time"]:
            if key in record and record[key]:
                timestamp = str(record[key])
                break

        if not timestamp:
            return None

        description_parts = []
        for key in ["event_description", "description", "name", "executable",
                     "path", "message", "EventMessage", "command", "url"]:
            if key in record and record[key]:
                description_parts.append(f"{key}={record[key]}")
                break

        category = record.get("event_category", record.get("category", source))
        user = record.get("user", record.get("User", record.get("username", "")))
        process = record.get("process", record.get("executable", record.get("name", "")))

        return TimelineEvent(
            timestamp=str(timestamp),
            original_timestamp=str(timestamp),
            timezone=str(record.get("timezone", "")),
            event_category=str(category),
            event_description=" | ".join(description_parts) if description_parts else source,
            source_artifact=source,
            evidence_id=str(record.get("evidence_id", "")),
            user=str(user) if user else "",
            process_or_application=str(process) if process else "",
            severity=str(record.get("severity", Severity.INFO.value)),
            confidence=str(record.get("confidence", Confidence.MEDIUM.value)),
        )

    def write_timeline(self) -> Path:
        self.sort_events()
        csv_path = self.timeline_dir / TIMELINE_CSV

        fieldnames = list(TimelineEvent.model_fields.keys())
        with open(csv_path, "w", newline="", encoding="utf-8", errors="replace") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for event in self.events:
                writer.writerow(_sanitize_dict(event.model_dump()))

        json_path = self.timeline_dir / "TIMELINE.json"
        with open(json_path, "w", encoding="utf-8", errors="replace") as f:
            json.dump(
                [_sanitize_dict(e.model_dump()) for e in self.events],
                f,
                indent=2,
                ensure_ascii=False,
            )

        return csv_path
