"""Persistence mechanism artifact collector."""

from __future__ import annotations

import json
import logging
import os
import re
import csv
from io import StringIO
from pathlib import Path
from typing import Optional

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp
from utils.subprocess_utils import run_command, run_powershell

logger = logging.getLogger("polaris")

SUSPICIOUS_PATH_PATTERNS = [
    r"\\temp\\",
    r"\\tmp\\",
    r"\\appdata\\local\\temp\\",
    r"\\downloads\\",
    r"\\public\\",
    r"\\programdata\\[^\\]+\.[^\\]+$",
    r"\\users\\public\\",
]

SUSPICIOUS_COMMAND_PATTERNS = [
    r"-enc\s",
    r"-encodedcommand\s",
    r"frombase64string",
    r"invoke-expression",
    r"iex\s*\(",
    r"downloadstring",
    r"downloadfile",
    r"hidden\s+-w",
    r"-windowstyle\s+hidden",
    r"bypass\s+-nop",
    r"mshta\s",
    r"regsvr32\s.*\/s.*\/u",
    r"rundll32\s.*javascript",
    r"certutil\s.*-urlcache",
    r"bitsadmin\s.*\/transfer",
]


def _is_suspicious_path(path: str) -> bool:
    path_lower = path.lower()
    return any(re.search(pattern, path_lower) for pattern in SUSPICIOUS_PATH_PATTERNS)


def _is_suspicious_command(command: str) -> bool:
    cmd_lower = command.lower()
    return any(re.search(pattern, cmd_lower) for pattern in SUSPICIOUS_COMMAND_PATTERNS)


def _flag_entry(entry: dict) -> dict:
    """Add a 'flagged' boolean to an entry based on suspicious indicators."""
    flagged = False
    flag_reasons: list[str] = []

    path_fields = ["path", "image_path", "binary_path", "task_to_run", "command"]
    for field in path_fields:
        value = entry.get(field, "")
        if value and _is_suspicious_path(str(value)):
            flagged = True
            flag_reasons.append(f"suspicious_path:{field}")

    cmd_fields = ["task_to_run", "command", "binary_path"]
    for field in cmd_fields:
        value = entry.get(field, "")
        if value and _is_suspicious_command(str(value)):
            flagged = True
            flag_reasons.append(f"suspicious_command:{field}")

    entry["flagged"] = flagged
    entry["flag_reasons"] = flag_reasons
    return entry


def _parse_services_output(raw: str) -> list[dict]:
    """Parse PowerShell Get-Service output (CSV format)."""
    services: list[dict] = []
    try:
        reader = csv.DictReader(StringIO(raw))
        for row in reader:
            service = {
                "name": row.get("Name", ""),
                "display_name": row.get("DisplayName", ""),
                "status": row.get("Status", ""),
                "start_type": row.get("StartType", ""),
                "binary_path": row.get("BinaryPathName", ""),
                "service_type": row.get("ServiceType", ""),
            }
            services.append(_flag_entry(service))
    except Exception as e:
        logger.debug(f"Service parsing error: {e}")
    return services


def _parse_schtasks_csv(raw: str) -> list[dict]:
    """Parse schtasks /query /fo CSV /v output."""
    tasks: list[dict] = []
    try:
        reader = csv.DictReader(StringIO(raw))
        for row in reader:
            task = {
                "task_name": row.get("TaskName", ""),
                "next_run_time": row.get("Next Run Time", ""),
                "status": row.get("Status", ""),
                "logon_mode": row.get("Logon Mode", ""),
                "last_run_time": row.get("Last Run Time", ""),
                "last_result": row.get("Last Result", ""),
                "author": row.get("Author", ""),
                "task_to_run": row.get("Task To Run", ""),
                "run_as_user": row.get("Run As User", ""),
                "schedule_type": row.get("Schedule Type", ""),
            }
            tasks.append(_flag_entry(task))
    except Exception as e:
        logger.debug(f"Scheduled task parsing error: {e}")
    return tasks


def _parse_run_keys(raw: str) -> list[dict]:
    """Parse reg query output for Run/RunOnce keys."""
    entries: list[dict] = []
    current_key = ""

    for line in raw.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue
        if line_stripped.startswith("HKEY_"):
            current_key = line_stripped
            continue
        if "REG_" in line_stripped:
            parts = re.split(r"\s{2,}", line_stripped, maxsplit=2)
            if len(parts) >= 3:
                entry = {
                    "registry_key": current_key,
                    "name": parts[0].strip(),
                    "type": parts[1].strip(),
                    "command": parts[2].strip(),
                }
                entries.append(_flag_entry(entry))

    return entries


def _parse_drivers_csv(raw: str) -> list[dict]:
    """Parse driverquery /v /fo CSV output."""
    drivers: list[dict] = []
    try:
        reader = csv.DictReader(StringIO(raw))
        for row in reader:
            driver = {
                "module_name": row.get("Module Name", ""),
                "display_name": row.get("Display Name", ""),
                "driver_type": row.get("Driver Type", ""),
                "start_mode": row.get("Start Mode", ""),
                "state": row.get("State", ""),
                "status": row.get("Status", ""),
                "path": row.get("Path", ""),
            }
            drivers.append(_flag_entry(driver))
    except Exception as e:
        logger.debug(f"Driver parsing error: {e}")
    return drivers


@register_collector("persistence")
class PersistenceCollector(CollectorBase):
    module_id = "persistence"
    module_name = "Persistence Artifacts"
    category = ArtifactCategory.PERSISTENCE
    source_locations = [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Scheduled Tasks",
        "Windows Services",
        "Startup Folders",
        "Installed Drivers",
        "WMI Subscriptions",
    ]
    required_privileges = "admin"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        collected_any = False

        collected_any |= self._collect_services(result)
        collected_any |= self._collect_scheduled_tasks(result)
        collected_any |= self._collect_startup_folders(result)
        collected_any |= self._collect_run_keys(result)
        collected_any |= self._collect_drivers(result)
        collected_any |= self._collect_wmi_subscriptions(result)

        if self.parse:
            self._generate_summary(result)

        result.status = CollectionStatus.SUCCESS if collected_any else CollectionStatus.FAILED
        return result

    def _collect_services(self, result: CollectionResult) -> bool:
        rc, stdout, stderr = run_powershell(
            "Get-CimInstance Win32_Service | "
            "Select-Object Name, DisplayName, State, StartMode, PathName, ServiceType | "
            "ConvertTo-Csv -NoTypeInformation"
        )
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, "services_raw.csv", self.evidence_dir / "persistence")
            if ev:
                ev.metadata = {"source": "Win32_Service (CIM)", "volatile": True, "acquisition_timestamp": get_iso_timestamp()}
                result.acquired_files.append(ev)

            if self.parse:
                services = self._parse_services_cim(stdout)
                if services:
                    parsed_dir = self.parsed_dir / "persistence"
                    j_ev = self.save_json(services, "services_parsed.json", parsed_dir)
                    if j_ev:
                        result.parsed_output_files.append(j_ev.acquired_path)
                        result.acquired_files.append(j_ev)

                    csv_ev = self._write_csv(
                        services,
                        ["name", "display_name", "status", "start_type", "binary_path", "flagged", "flag_reasons"],
                        "services_parsed.csv",
                        parsed_dir,
                    )
                    if csv_ev:
                        result.parsed_output_files.append(csv_ev.acquired_path)
                        result.acquired_files.append(csv_ev)
            return True
        else:
            result.warnings.append(f"Service collection failed: {stderr.strip()}")
        return False

    def _parse_services_cim(self, raw: str) -> list[dict]:
        """Parse CIM Win32_Service CSV output."""
        services: list[dict] = []
        try:
            reader = csv.DictReader(StringIO(raw))
            for row in reader:
                service = {
                    "name": row.get("Name", ""),
                    "display_name": row.get("DisplayName", ""),
                    "status": row.get("State", ""),
                    "start_type": row.get("StartMode", ""),
                    "binary_path": row.get("PathName", ""),
                    "service_type": row.get("ServiceType", ""),
                }
                services.append(_flag_entry(service))
        except Exception as e:
            logger.debug(f"CIM service parsing error: {e}")
        return services

    def _collect_scheduled_tasks(self, result: CollectionResult) -> bool:
        rc, stdout, stderr = run_command(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            timeout=120,
        )
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, "scheduled_tasks_raw.csv", self.evidence_dir / "persistence")
            if ev:
                ev.metadata = {"source": "schtasks", "volatile": True, "acquisition_timestamp": get_iso_timestamp()}
                result.acquired_files.append(ev)

            if self.parse:
                tasks = _parse_schtasks_csv(stdout)
                if tasks:
                    parsed_dir = self.parsed_dir / "persistence"
                    j_ev = self.save_json(tasks, "scheduled_tasks_parsed.json", parsed_dir)
                    if j_ev:
                        result.parsed_output_files.append(j_ev.acquired_path)
                        result.acquired_files.append(j_ev)

                    csv_ev = self._write_csv(
                        tasks,
                        ["task_name", "status", "task_to_run", "run_as_user", "author", "schedule_type", "flagged", "flag_reasons"],
                        "scheduled_tasks_parsed.csv",
                        parsed_dir,
                    )
                    if csv_ev:
                        result.parsed_output_files.append(csv_ev.acquired_path)
                        result.acquired_files.append(csv_ev)
            return True
        else:
            result.warnings.append(f"Scheduled tasks collection failed: {stderr.strip()}")
        return False

    def _collect_startup_folders(self, result: CollectionResult) -> bool:
        collected = False
        startup_paths = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]

        entries: list[dict] = []
        for startup_dir in startup_paths:
            if not startup_dir.exists():
                continue
            try:
                for item in startup_dir.iterdir():
                    if item.is_file():
                        entry = {
                            "name": item.name,
                            "path": str(item),
                            "size": item.stat().st_size,
                            "startup_folder": str(startup_dir),
                        }
                        entries.append(_flag_entry(entry))
                        collected = True
            except (OSError, PermissionError) as e:
                result.warnings.append(f"Startup folder access error: {startup_dir}: {e}")

        if entries:
            ev = self.save_json(entries, "startup_folders.json", self.evidence_dir / "persistence")
            if ev:
                ev.metadata = {"source": "startup_folders", "volatile": False}
                result.acquired_files.append(ev)

            if self.parse:
                parsed_dir = self.parsed_dir / "persistence"
                csv_ev = self._write_csv(
                    entries,
                    ["name", "path", "size", "startup_folder", "flagged", "flag_reasons"],
                    "startup_folders.csv",
                    parsed_dir,
                )
                if csv_ev:
                    result.parsed_output_files.append(csv_ev.acquired_path)
                    result.acquired_files.append(csv_ev)

        return collected

    def _collect_run_keys(self, result: CollectionResult) -> bool:
        run_key_paths = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        ]

        all_raw: list[str] = []
        all_entries: list[dict] = []
        collected = False

        for key_path in run_key_paths:
            rc, stdout, stderr = run_command(
                ["reg", "query", key_path],
                timeout=30,
            )
            if rc == 0 and stdout.strip():
                all_raw.append(f"=== {key_path} ===\n{stdout}")
                entries = _parse_run_keys(stdout)
                all_entries.extend(entries)
                collected = True

        if all_raw:
            combined = "\n\n".join(all_raw)
            ev = self.save_text(combined, "run_keys_raw.txt", self.evidence_dir / "persistence")
            if ev:
                ev.metadata = {"source": "Run/RunOnce registry keys", "volatile": False}
                result.acquired_files.append(ev)

        if self.parse and all_entries:
            parsed_dir = self.parsed_dir / "persistence"
            j_ev = self.save_json(all_entries, "run_keys_parsed.json", parsed_dir)
            if j_ev:
                result.parsed_output_files.append(j_ev.acquired_path)
                result.acquired_files.append(j_ev)

            csv_ev = self._write_csv(
                all_entries,
                ["registry_key", "name", "type", "command", "flagged", "flag_reasons"],
                "run_keys_parsed.csv",
                parsed_dir,
            )
            if csv_ev:
                result.parsed_output_files.append(csv_ev.acquired_path)
                result.acquired_files.append(csv_ev)

        return collected

    def _collect_drivers(self, result: CollectionResult) -> bool:
        rc, stdout, stderr = run_command(
            ["driverquery", "/v", "/fo", "CSV"],
            timeout=120,
        )
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, "drivers_raw.csv", self.evidence_dir / "persistence")
            if ev:
                ev.metadata = {"source": "driverquery", "volatile": True, "acquisition_timestamp": get_iso_timestamp()}
                result.acquired_files.append(ev)

            if self.parse:
                drivers = _parse_drivers_csv(stdout)
                if drivers:
                    parsed_dir = self.parsed_dir / "persistence"
                    j_ev = self.save_json(drivers, "drivers_parsed.json", parsed_dir)
                    if j_ev:
                        result.parsed_output_files.append(j_ev.acquired_path)
                        result.acquired_files.append(j_ev)
            return True
        else:
            result.warnings.append(f"Driver query failed: {stderr.strip()}")
        return False

    def _collect_wmi_subscriptions(self, result: CollectionResult) -> bool:
        wmi_classes = ["__EventFilter", "__EventConsumer", "__FilterToConsumerBinding"]
        collected = False
        all_wmi: dict[str, list[dict]] = {}

        for wmi_class in wmi_classes:
            rc, stdout, stderr = run_powershell(
                f"Get-WMIObject -Namespace root\\subscription -Class {wmi_class} 2>$null | "
                f"Select-Object * | ConvertTo-Json -Depth 5"
            )
            if rc == 0 and stdout.strip():
                ev = self.save_text(
                    stdout,
                    f"wmi_{wmi_class.strip('_').lower()}.json",
                    self.evidence_dir / "persistence",
                )
                if ev:
                    ev.metadata = {"source": f"WMI {wmi_class}", "volatile": True, "acquisition_timestamp": get_iso_timestamp()}
                    result.acquired_files.append(ev)
                    collected = True

                try:
                    parsed = json.loads(stdout)
                    if isinstance(parsed, dict):
                        parsed = [parsed]
                    all_wmi[wmi_class] = parsed
                except (json.JSONDecodeError, TypeError):
                    all_wmi[wmi_class] = []

        if self.parse and all_wmi:
            parsed_dir = self.parsed_dir / "persistence"
            j_ev = self.save_json(all_wmi, "wmi_subscriptions_parsed.json", parsed_dir)
            if j_ev:
                result.parsed_output_files.append(j_ev.acquired_path)
                result.acquired_files.append(j_ev)

        return collected

    def _generate_summary(self, result: CollectionResult) -> None:
        """Generate a summary of all flagged persistence entries."""
        flagged_items: list[dict] = []

        for parsed_file_path in result.parsed_output_files:
            p = Path(parsed_file_path)
            if not p.exists() or not p.suffix == ".json":
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and item.get("flagged"):
                            flagged_items.append({
                                "source_file": p.name,
                                **{k: v for k, v in item.items()},
                            })
            except (json.JSONDecodeError, OSError):
                continue

        if flagged_items:
            parsed_dir = self.parsed_dir / "persistence"
            ev = self.save_json(flagged_items, "flagged_persistence_entries.json", parsed_dir)
            if ev:
                result.parsed_output_files.append(ev.acquired_path)
                result.acquired_files.append(ev)

        result.parser_name = "polaris_persistence_parser"
        result.parser_version = "1.0"
        result.parser_status = "completed"

    def _write_csv(
        self,
        data: list[dict],
        fieldnames: list[str],
        filename: str,
        dest_dir: Path,
    ) -> Optional[FileEvidence]:
        if not data:
            return None
        dest_dir.mkdir(parents=True, exist_ok=True)
        buf = StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in data:
            sanitized = {}
            for k, v in row.items():
                if isinstance(v, list):
                    sanitized[k] = "; ".join(str(i) for i in v)
                else:
                    sanitized[k] = v
            writer.writerow(sanitized)
        return self.save_text(buf.getvalue(), filename, dest_dir)
