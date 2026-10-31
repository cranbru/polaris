from __future__ import annotations

import csv
import json
import logging
import re
from pathlib import Path
from typing import Optional

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp
from utils.subprocess_utils import run_command

logger = logging.getLogger("polaris.eventlogs")

TARGET_LOGS: list[str] = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Windows Defender/Operational",
    "Windows PowerShell",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "Microsoft-Windows-Sysmon/Operational",
]


def _safe_log_filename(log_name: str) -> str:
    return log_name.replace("/", "_").replace("\\", "_").replace(" ", "_")


def _parse_text_events(text_output: str, log_name: str) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    current: dict[str, str] = {}
    current_key: str = ""

    for line in text_output.splitlines():
        if not line.strip():
            if current:
                current["SourceLog"] = log_name
                events.append(current)
                current = {}
                current_key = ""
            continue

        if ":" in line and not line.startswith("  ") and not line.startswith("\t"):
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            current_key = key
            current[key] = value
        elif current_key:
            current[current_key] = current[current_key] + " " + line.strip()

    if current:
        current["SourceLog"] = log_name
        events.append(current)

    return events


def _normalize_event(raw: dict[str, str]) -> dict[str, str]:
    return {
        "EventID": raw.get("Event ID", raw.get("EventID", "")),
        "Provider": raw.get("Provider Name", raw.get("ProviderName", raw.get("Source", ""))),
        "TimeCreated": raw.get("Date", raw.get("TimeCreated", "")),
        "Computer": raw.get("Computer", ""),
        "Level": raw.get("Level", raw.get("Keywords", "")),
        "UserID": raw.get("User ID", raw.get("Security UserID", raw.get("UserId", ""))),
        "Message": raw.get("Description", raw.get("Message", "")),
        "SourceLog": raw.get("SourceLog", ""),
    }


@register_collector("eventlogs")
class EventLogCollector(CollectorBase):
    module_id: str = "eventlogs"
    module_name: str = "Windows Event Logs"
    category: ArtifactCategory = ArtifactCategory.EVENTLOGS
    source_locations: list[str] = [r"C:\Windows\System32\winevt\Logs"]
    required_privileges: str = "admin"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        evtx_dir = self.evidence_dir / "evtx_raw"
        evtx_dir.mkdir(parents=True, exist_ok=True)

        all_parsed_events: list[dict[str, str]] = []
        logs_succeeded: int = 0
        logs_failed: int = 0

        for log_name in TARGET_LOGS:
            safe_name = _safe_log_filename(log_name)
            try:
                self._export_evtx(log_name, safe_name, evtx_dir, result)
                logs_succeeded += 1
            except Exception as e:
                logs_failed += 1
                result.warnings.append(f"Failed to export EVTX for {log_name}: {e}")

            if self.parse:
                try:
                    events = self._query_and_parse(log_name)
                    all_parsed_events.extend(events)
                except Exception as e:
                    result.warnings.append(f"Failed to parse {log_name}: {e}")

        if self.parse and all_parsed_events:
            self._save_parsed_output(all_parsed_events, result)

        if logs_succeeded == 0:
            result.status = CollectionStatus.FAILED
            result.errors.append("Failed to export any event logs")
        elif logs_failed > 0:
            result.status = CollectionStatus.PARTIAL
        else:
            result.status = CollectionStatus.SUCCESS

        return result

    def _export_evtx(
        self,
        log_name: str,
        safe_name: str,
        evtx_dir: Path,
        result: CollectionResult,
    ) -> None:
        dest_path = evtx_dir / f"{safe_name}.evtx"
        returncode, stdout, stderr = run_command(
            ["wevtutil.exe", "epl", log_name, str(dest_path)],
            timeout=120,
        )

        if returncode != 0:
            error_lower = stderr.lower() if stderr else ""
            if "the specified channel could not be found" in error_lower or "0x3a9f" in error_lower:
                result.warnings.append(f"Log not available on this system: {log_name}")
                return
            result.warnings.append(f"wevtutil epl failed for {log_name}: {stderr.strip()}")
            return

        if dest_path.exists() and dest_path.stat().st_size > 0:
            evidence = FileEvidence(
                evidence_id=f"evtx_{safe_name}",
                original_path=log_name,
                acquired_path=str(dest_path),
                filename=dest_path.name,
                extension=".evtx",
                file_size=dest_path.stat().st_size,
                collection_timestamp=get_iso_timestamp(),
            )
            result.acquired_files.append(evidence)
        else:
            result.warnings.append(f"EVTX export produced empty file for {log_name}")

    def _query_and_parse(self, log_name: str) -> list[dict[str, str]]:
        returncode, stdout, stderr = run_command(
            ["wevtutil.exe", "qe", log_name, "/f:text", "/c:5000"],
            timeout=180,
        )

        if returncode != 0:
            return []

        raw_events = _parse_text_events(stdout, log_name)
        return [_normalize_event(e) for e in raw_events]

    def _save_parsed_output(
        self,
        events: list[dict[str, str]],
        result: CollectionResult,
    ) -> None:
        json_evidence = self.save_json(
            events,
            "eventlogs_parsed.json",
            self.parsed_dir,
            evidence_id="eventlogs_parsed_json",
        )
        if json_evidence:
            result.acquired_files.append(json_evidence)
            result.parsed_output_files.append(json_evidence.acquired_path)

        csv_path = self.parsed_dir / "eventlogs_parsed.csv"
        try:
            fieldnames = ["EventID", "Provider", "TimeCreated", "Computer", "Level", "UserID", "Message", "SourceLog"]
            with open(csv_path, "w", newline="", encoding="utf-8", errors="replace") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for event in events:
                    clean_event = {k: str(v).encode("utf-8", errors="replace").decode("utf-8") for k, v in event.items()}
                    writer.writerow(clean_event)

            csv_evidence = FileEvidence(
                evidence_id="eventlogs_parsed_csv",
                original_path="parsed_output",
                acquired_path=str(csv_path),
                filename=csv_path.name,
                extension=".csv",
                file_size=csv_path.stat().st_size,
                collection_timestamp=get_iso_timestamp(),
            )
            result.acquired_files.append(csv_evidence)
            result.parsed_output_files.append(str(csv_path))
        except OSError as e:
            result.warnings.append(f"Failed to save parsed CSV: {e}")

        result.parser_name = "wevtutil_text_parser"
        result.parser_version = "1.0"
        result.parser_status = "completed"
