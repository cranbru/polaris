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

logger = logging.getLogger("polaris.registry_artifacts")

REGISTRY_ARTIFACTS: dict[str, dict[str, str | bool]] = {
    "installed_apps": {
        "key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "recursive": True,
        "description": "Installed Applications",
    },
    "startup_hklm_run": {
        "key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "recursive": False,
        "description": "HKLM Startup Run",
    },
    "startup_hklm_runonce": {
        "key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "recursive": False,
        "description": "HKLM Startup RunOnce",
    },
    "startup_hkcu_run": {
        "key": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "recursive": False,
        "description": "HKCU Startup Run",
    },
    "startup_hkcu_runonce": {
        "key": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "recursive": False,
        "description": "HKCU Startup RunOnce",
    },
    "usbstor": {
        "key": r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",
        "recursive": True,
        "description": "USB Storage History",
    },
    "mounted_devices": {
        "key": r"HKLM\SYSTEM\MountedDevices",
        "recursive": False,
        "description": "Mounted Devices",
    },
    "services": {
        "key": r"HKLM\SYSTEM\CurrentControlSet\Services",
        "recursive": False,
        "description": "Windows Services",
    },
    "network_profiles": {
        "key": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
        "recursive": True,
        "description": "Network Profiles",
    },
}


def _reg_query(key_path: str, recursive: bool = False, timeout: int = 120) -> tuple[int, str, str]:
    cmd = ["reg", "query", key_path]
    if recursive:
        cmd.append("/s")
    return run_command(cmd, timeout=timeout)


def _reg_export(key_path: str, output_file: Path, timeout: int = 60) -> tuple[int, str, str]:
    return run_command(
        ["reg", "export", key_path, str(output_file), "/y"],
        timeout=timeout,
    )


def _parse_reg_query_output(output: str, artifact_name: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current_key: str = ""

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("HKEY_"):
            current_key = stripped
            continue

        parts = stripped.split(maxsplit=2)
        if len(parts) >= 3:
            value_name = parts[0]
            value_type = parts[1]
            value_data = parts[2]

            records.append({
                "artifact": artifact_name,
                "registry_key": current_key,
                "value_name": value_name,
                "value_type": value_type,
                "value_data": value_data,
            })
        elif len(parts) == 1 and current_key:
            records.append({
                "artifact": artifact_name,
                "registry_key": current_key,
                "value_name": "",
                "value_type": "KEY",
                "value_data": stripped,
            })

    return records


def _parse_services_keys(output: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("HKEY_"):
            service_name = stripped.rsplit("\\", 1)[-1] if "\\" in stripped else stripped
            records.append({
                "artifact": "services",
                "registry_key": stripped,
                "value_name": "ServiceName",
                "value_type": "KEY",
                "value_data": service_name,
            })

    return records


def _parse_installed_apps(output: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current_app: dict[str, str] = {}
    current_key: str = ""

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            if current_app:
                current_app["artifact"] = "installed_apps"
                records.append(current_app)
                current_app = {}
            continue

        if stripped.startswith("HKEY_"):
            if current_app:
                current_app["artifact"] = "installed_apps"
                records.append(current_app)
                current_app = {}
            current_key = stripped
            current_app["registry_key"] = current_key
            continue

        parts = stripped.split(maxsplit=2)
        if len(parts) >= 3:
            value_name = parts[0]
            value_data = parts[2]

            if value_name == "DisplayName":
                current_app["display_name"] = value_data
            elif value_name == "DisplayVersion":
                current_app["version"] = value_data
            elif value_name == "Publisher":
                current_app["publisher"] = value_data
            elif value_name == "InstallDate":
                current_app["install_date"] = value_data
            elif value_name == "InstallLocation":
                current_app["install_location"] = value_data
            elif value_name == "UninstallString":
                current_app["uninstall_string"] = value_data

    if current_app:
        current_app["artifact"] = "installed_apps"
        records.append(current_app)

    return records


@register_collector("registry_artifacts")
class RegistryArtifactsCollector(CollectorBase):
    module_id: str = "registry_artifacts"
    module_name: str = "Registry Forensic Artifacts"
    category: ArtifactCategory = ArtifactCategory.REGISTRY
    source_locations: list[str] = [
        str(v["key"]) for v in REGISTRY_ARTIFACTS.values()
    ]
    required_privileges: str = "admin"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        export_dir = self.evidence_dir / "registry_artifacts"
        export_dir.mkdir(parents=True, exist_ok=True)

        artifacts_succeeded: int = 0
        artifacts_failed: int = 0
        all_records: list[dict[str, str]] = []
        apps_records: list[dict[str, str]] = []

        for artifact_name, artifact_info in REGISTRY_ARTIFACTS.items():
            key_path = str(artifact_info["key"])
            recursive = bool(artifact_info.get("recursive", False))

            reg_file = export_dir / f"{artifact_name}.reg"
            export_rc, _, export_err = _reg_export(key_path, reg_file)

            if export_rc == 0 and reg_file.exists() and reg_file.stat().st_size > 0:
                evidence = FileEvidence(
                    evidence_id=f"regartifact_{artifact_name}_reg",
                    original_path=key_path,
                    acquired_path=str(reg_file),
                    filename=reg_file.name,
                    extension=".reg",
                    file_size=reg_file.stat().st_size,
                    collection_timestamp=get_iso_timestamp(),
                )
                result.acquired_files.append(evidence)
                artifacts_succeeded += 1
            else:
                artifacts_failed += 1
                result.warnings.append(
                    f"Failed to export {artifact_name} ({key_path}): {export_err.strip() if export_err else 'unknown'}"
                )

            if self.parse:
                query_rc, query_out, query_err = _reg_query(key_path, recursive=recursive)
                if query_rc == 0 and query_out.strip():
                    if artifact_name == "services":
                        records = _parse_services_keys(query_out)
                    elif artifact_name == "installed_apps":
                        records = _parse_installed_apps(query_out)
                        apps_records.extend(records)
                        continue
                    else:
                        records = _parse_reg_query_output(query_out, artifact_name)

                    all_records.extend(records)

        if self.parse:
            self._save_parsed_output(all_records, apps_records, result)

        if artifacts_succeeded == 0:
            result.status = CollectionStatus.FAILED
            result.errors.append("Failed to export any registry artifacts")
        elif artifacts_failed > 0:
            result.status = CollectionStatus.PARTIAL
        else:
            result.status = CollectionStatus.SUCCESS

        return result

    def _save_parsed_output(
        self,
        records: list[dict[str, str]],
        apps_records: list[dict[str, str]],
        result: CollectionResult,
    ) -> None:
        if records:
            json_evidence = self.save_json(
                records,
                "registry_artifacts_parsed.json",
                self.parsed_dir,
                evidence_id="regartifacts_parsed_json",
            )
            if json_evidence:
                result.acquired_files.append(json_evidence)
                result.parsed_output_files.append(json_evidence.acquired_path)

            csv_path = self.parsed_dir / "registry_artifacts_parsed.csv"
            try:
                fieldnames = ["artifact", "registry_key", "value_name", "value_type", "value_data"]
                with open(csv_path, "w", newline="", encoding="utf-8", errors="replace") as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                    writer.writeheader()
                    for record in records:
                        clean_record = {k: str(v).encode("utf-8", errors="replace").decode("utf-8") for k, v in record.items()}
                        writer.writerow(clean_record)

                csv_evidence = FileEvidence(
                    evidence_id="regartifacts_parsed_csv",
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
                result.warnings.append(f"Failed to save registry artifacts CSV: {e}")

        if apps_records:
            apps_json = self.save_json(
                apps_records,
                "installed_apps.json",
                self.parsed_dir,
                evidence_id="installed_apps_json",
            )
            if apps_json:
                result.acquired_files.append(apps_json)
                result.parsed_output_files.append(apps_json.acquired_path)

            apps_csv_path = self.parsed_dir / "installed_apps.csv"
            try:
                app_fields = [
                    "artifact", "registry_key", "display_name", "version",
                    "publisher", "install_date", "install_location", "uninstall_string",
                ]
                with open(apps_csv_path, "w", newline="", encoding="utf-8", errors="replace") as f:
                    writer = csv.DictWriter(f, fieldnames=app_fields, extrasaction="ignore")
                    writer.writeheader()
                    for record in apps_records:
                        clean_rec = {k: str(v).encode("utf-8", errors="replace").decode("utf-8") for k, v in record.items()}
                        writer.writerow(clean_rec)

                apps_csv_evidence = FileEvidence(
                    evidence_id="installed_apps_csv",
                    original_path="parsed_output",
                    acquired_path=str(apps_csv_path),
                    filename=apps_csv_path.name,
                    extension=".csv",
                    file_size=apps_csv_path.stat().st_size,
                    collection_timestamp=get_iso_timestamp(),
                )
                result.acquired_files.append(apps_csv_evidence)
                result.parsed_output_files.append(str(apps_csv_path))
            except OSError as e:
                result.warnings.append(f"Failed to save installed apps CSV: {e}")

        result.parser_name = "reg_query_parser"
        result.parser_version = "1.0"
        result.parser_status = "completed"
