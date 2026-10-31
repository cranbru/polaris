"""System information artifact collector."""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import csv
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Optional

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp
from utils.subprocess_utils import run_command, run_powershell

logger = logging.getLogger("polaris")


def _parse_systeminfo_output(raw: str) -> dict:
    """Parse 'systeminfo' output into a structured dictionary."""
    info: dict = {}
    current_key = ""
    multiline_keys = {"Hotfix(s)", "Network Card(s)"}

    for line in raw.splitlines():
        if not line.strip():
            continue

        if ":" in line and not line.startswith(" "):
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            current_key = key
            info[key] = value
        elif current_key and line.startswith(" "):
            existing = info.get(current_key, "")
            if isinstance(existing, list):
                existing.append(line.strip())
            else:
                info[current_key] = [existing, line.strip()] if existing else [line.strip()]

    return info


def _extract_system_summary(parsed_info: dict) -> dict:
    """Extract key fields from parsed systeminfo output."""
    return {
        "hostname": parsed_info.get("Host Name", ""),
        "os_name": parsed_info.get("OS Name", ""),
        "os_version": parsed_info.get("OS Version", ""),
        "os_build_type": parsed_info.get("OS Build Type", ""),
        "registered_owner": parsed_info.get("Registered Owner", ""),
        "system_manufacturer": parsed_info.get("System Manufacturer", ""),
        "system_model": parsed_info.get("System Model", ""),
        "system_type": parsed_info.get("System Type", ""),
        "processor": parsed_info.get("Processor(s)", ""),
        "total_physical_memory": parsed_info.get("Total Physical Memory", ""),
        "available_physical_memory": parsed_info.get("Available Physical Memory", ""),
        "domain": parsed_info.get("Domain", ""),
        "logon_server": parsed_info.get("Logon Server", ""),
        "boot_device": parsed_info.get("Boot Device", ""),
        "system_boot_time": parsed_info.get("System Boot Time", ""),
        "original_install_date": parsed_info.get("Original Install Date", ""),
        "time_zone": parsed_info.get("Time Zone", ""),
        "hotfixes": parsed_info.get("Hotfix(s)", ""),
    }


def _parse_tasklist_csv(raw: str) -> list[dict]:
    """Parse 'tasklist /v /fo CSV' output into structured records."""
    processes: list[dict] = []
    try:
        reader = csv.DictReader(StringIO(raw))
        for row in reader:
            processes.append({
                "image_name": row.get("Image Name", ""),
                "pid": row.get("PID", ""),
                "session_name": row.get("Session Name", ""),
                "session_num": row.get("Session#", ""),
                "mem_usage": row.get("Mem Usage", ""),
                "status": row.get("Status", ""),
                "user_name": row.get("User Name", ""),
                "cpu_time": row.get("CPU Time", ""),
                "window_title": row.get("Window Title", ""),
            })
    except Exception as e:
        logger.debug(f"Tasklist parsing error: {e}")
    return processes


def _parse_net_user_output(raw: str) -> list[str]:
    """Parse 'net user' output to extract usernames."""
    users: list[str] = []
    capture = False
    for line in raw.splitlines():
        if "---" in line:
            capture = True
            continue
        if capture:
            if line.startswith("The command completed"):
                break
            parts = line.split()
            users.extend(parts)
    return users


@register_collector("system_info")
class SystemInfoCollector(CollectorBase):
    module_id = "system_info"
    module_name = "System Information"
    category = ArtifactCategory.SYSTEM
    source_locations = ["Live system state"]
    required_privileges = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        collected_any = False
        dest_dir = self.evidence_dir / "system"
        acquisition_ts = get_iso_timestamp()

        collected_any |= self._collect_systeminfo(dest_dir, acquisition_ts, result)
        collected_any |= self._collect_python_sysinfo(dest_dir, acquisition_ts, result)
        collected_any |= self._collect_local_users(dest_dir, acquisition_ts, result)
        collected_any |= self._collect_processes(dest_dir, acquisition_ts, result)
        collected_any |= self._collect_services(dest_dir, acquisition_ts, result)

        result.status = CollectionStatus.SUCCESS if collected_any else CollectionStatus.FAILED
        return result

    def _collect_systeminfo(self, dest_dir: Path, acquisition_ts: str, result: CollectionResult) -> bool:
        rc, stdout, stderr = run_command(["systeminfo"], timeout=120)
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, "systeminfo_raw.txt", dest_dir)
            if ev:
                ev.metadata = {
                    "source": "systeminfo command",
                    "volatile": True,
                    "acquisition_timestamp": acquisition_ts,
                }
                result.acquired_files.append(ev)

            if self.parse:
                parsed_info = _parse_systeminfo_output(stdout)
                summary = _extract_system_summary(parsed_info)

                parsed_dir = self.parsed_dir / "system"
                parsed_dir.mkdir(parents=True, exist_ok=True)

                full_ev = self.save_json(parsed_info, "systeminfo_full.json", parsed_dir)
                if full_ev:
                    result.parsed_output_files.append(full_ev.acquired_path)
                    result.acquired_files.append(full_ev)

                sum_ev = self.save_json(summary, "system_summary.json", parsed_dir)
                if sum_ev:
                    result.parsed_output_files.append(sum_ev.acquired_path)
                    result.acquired_files.append(sum_ev)

                result.parser_name = "polaris_system_parser"
                result.parser_version = "1.0"
                result.parser_status = "completed"

            return True
        else:
            result.warnings.append(f"systeminfo command failed: {stderr.strip()}")
        return False

    def _collect_python_sysinfo(self, dest_dir: Path, acquisition_ts: str, result: CollectionResult) -> bool:
        """Collect system info via Python's platform module as supplemental data."""
        try:
            now = datetime.now(tz=timezone.utc)
            local_now = datetime.now()

            py_info = {
                "hostname": platform.node(),
                "platform": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.architecture()[0],
                "processor": platform.processor(),
                "machine": platform.machine(),
                "python_version": platform.python_version(),
                "current_utc_time": now.isoformat(),
                "current_local_time": local_now.isoformat(),
                "timezone_offset_seconds": local_now.utcoffset().total_seconds() if local_now.utcoffset() else None,
                "timezone_name": str(local_now.astimezone().tzinfo),
                "acquisition_timestamp": acquisition_ts,
            }

            ev = self.save_json(py_info, "platform_info.json", dest_dir)
            if ev:
                ev.metadata = {
                    "source": "Python platform module",
                    "volatile": True,
                    "acquisition_timestamp": acquisition_ts,
                }
                result.acquired_files.append(ev)
                return True
        except Exception as e:
            result.warnings.append(f"Python platform info failed: {e}")
        return False

    def _collect_local_users(self, dest_dir: Path, acquisition_ts: str, result: CollectionResult) -> bool:
        rc, stdout, stderr = run_command(["net", "user"], timeout=30)
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, "net_user_raw.txt", dest_dir)
            if ev:
                ev.metadata = {
                    "source": "net user command",
                    "volatile": True,
                    "acquisition_timestamp": acquisition_ts,
                }
                result.acquired_files.append(ev)

            if self.parse:
                users = _parse_net_user_output(stdout)
                if users:
                    parsed_dir = self.parsed_dir / "system"
                    parsed_dir.mkdir(parents=True, exist_ok=True)
                    u_ev = self.save_json(
                        {"local_users": users, "user_count": len(users)},
                        "local_users.json",
                        parsed_dir,
                    )
                    if u_ev:
                        result.parsed_output_files.append(u_ev.acquired_path)
                        result.acquired_files.append(u_ev)
            return True
        else:
            result.warnings.append(f"net user command failed: {stderr.strip()}")
        return False

    def _collect_processes(self, dest_dir: Path, acquisition_ts: str, result: CollectionResult) -> bool:
        rc, stdout, stderr = run_command(["tasklist", "/v", "/fo", "CSV"], timeout=60)
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, "tasklist_raw.csv", dest_dir)
            if ev:
                ev.metadata = {
                    "source": "tasklist command",
                    "volatile": True,
                    "acquisition_timestamp": acquisition_ts,
                }
                result.acquired_files.append(ev)

            if self.parse:
                processes = _parse_tasklist_csv(stdout)
                if processes:
                    parsed_dir = self.parsed_dir / "system"
                    parsed_dir.mkdir(parents=True, exist_ok=True)

                    p_ev = self.save_json(processes, "processes_parsed.json", parsed_dir)
                    if p_ev:
                        result.parsed_output_files.append(p_ev.acquired_path)
                        result.acquired_files.append(p_ev)

                    fieldnames = ["image_name", "pid", "session_name", "mem_usage", "status", "user_name", "cpu_time"]
                    buf = StringIO()
                    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(processes)
                    csv_ev = self.save_text(buf.getvalue(), "processes_parsed.csv", parsed_dir)
                    if csv_ev:
                        result.parsed_output_files.append(csv_ev.acquired_path)
                        result.acquired_files.append(csv_ev)
            return True
        else:
            result.warnings.append(f"tasklist command failed: {stderr.strip()}")
        return False

    def _collect_services(self, dest_dir: Path, acquisition_ts: str, result: CollectionResult) -> bool:
        rc, stdout, stderr = run_command(
            ["sc", "query", "state=", "all"],
            timeout=60,
        )
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, "sc_query_all.txt", dest_dir)
            if ev:
                ev.metadata = {
                    "source": "sc query state= all",
                    "volatile": True,
                    "acquisition_timestamp": acquisition_ts,
                }
                result.acquired_files.append(ev)
            return True
        else:
            result.warnings.append(f"sc query failed: {stderr.strip()}")
        return False
