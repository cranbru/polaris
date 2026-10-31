import json
import logging
import re
from pathlib import Path
from typing import Any

from config.settings import Severity, Confidence
from analysis.finding_models import Finding

logger = logging.getLogger("polaris")

SUSPICIOUS_PATHS = [
    r"\\temp\\",
    r"\\tmp\\",
    r"\\appdata\\local\\temp\\",
    r"\\downloads\\",
    r"\\perflogs\\",
    r"\\public\\",
]


class RulesEngine:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.findings: list[Finding] = []

    def run_all_rules(self) -> list[Finding]:
        self.findings.clear()
        parsed_dir = self.case_dir / "parsed"
        if not parsed_dir.exists():
            return self.findings

        for json_file in parsed_dir.rglob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._analyze_file_data(json_file, data)
            except Exception as e:
                logger.debug(f"Failed to analyze {json_file}: {e}")

        findings_path = self.case_dir / "metadata" / "findings.json"
        findings_path.parent.mkdir(parents=True, exist_ok=True)
        with open(findings_path, "w", encoding="utf-8") as f:
            json.dump([f.model_dump() for f in self.findings], f, indent=2, ensure_ascii=False)

        return self.findings

    def _analyze_file_data(self, source_path: Path, data: Any) -> None:
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    self._check_record(source_path, item)
        elif isinstance(data, dict):
            self._check_record(source_path, data)

    def _check_record(self, source_path: Path, record: dict) -> None:
        self._rule_suspicious_execution_path(source_path, record)
        self._rule_encoded_powershell(source_path, record)
        self._rule_suspicious_service(source_path, record)
        self._rule_suspicious_scheduled_task(source_path, record)
        self._rule_removable_media_execution(source_path, record)

    def _rule_suspicious_execution_path(self, source_path: Path, record: dict) -> None:
        path_str = ""
        for key in ["path", "executable", "target_path", "image_path", "Image"]:
            val = record.get(key)
            if val and isinstance(val, str):
                path_str = val.lower()
                break

        if not path_str:
            return

        for sus in SUSPICIOUS_PATHS:
            if sus in path_str:
                self.findings.append(Finding(
                    title="Process / Artifact Located in Suspicious Directory",
                    description=f"Artifact executed or located in volatile/unusual directory: {path_str}",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    source_artifacts=[source_path.name],
                    rule_name="SuspiciousPathRule",
                    category="Execution",
                    raw_evidence=record,
                    recommendations=[
                        "Investigate child processes and parent process lineage.",
                        "Extract and verify digital signature of the target binary.",
                    ],
                ))
                break

    def _rule_encoded_powershell(self, source_path: Path, record: dict) -> None:
        cmd_str = ""
        for key in ["command", "command_line", "CommandLine", "ScriptBlockText", "message", "arguments"]:
            val = record.get(key)
            if val and isinstance(val, str):
                cmd_str = val
                break

        if not cmd_str:
            return

        pattern = r"-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]{10,})"
        match = re.search(pattern, cmd_str, re.IGNORECASE)
        if match:
            self.findings.append(Finding(
                title="Base64 Encoded PowerShell Command Detected",
                description=f"Command execution contained encoded payload: {cmd_str[:200]}...",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                source_artifacts=[source_path.name],
                rule_name="EncodedPowerShellRule",
                category="Command Execution",
                raw_evidence=record,
                recommendations=[
                    "Decode the Base64 payload to inspect script actions.",
                    "Review PowerShell ScriptBlock and Operational event logs.",
                ],
            ))

    def _rule_suspicious_service(self, source_path: Path, record: dict) -> None:
        svc_name = record.get("service_name") or record.get("Name")
        bin_path = record.get("binary_path") or record.get("PathName") or record.get("image_path")
        if not bin_path or not isinstance(bin_path, str):
            return

        lower_path = bin_path.lower()
        if any(p in lower_path for p in [r"\\temp\\", r"\\tmp\\", r"\\users\\public\\"]):
            self.findings.append(Finding(
                title="Service Registered from Non-Standard Directory",
                description=f"Service '{svc_name}' points to executable in non-standard location: {bin_path}",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                source_artifacts=[source_path.name],
                rule_name="SuspiciousServicePathRule",
                category="Persistence",
                raw_evidence=record,
                recommendations=[
                    "Verify legitimacy of service executable.",
                    "Check creation time of service in System Event Log (Event ID 7045).",
                ],
            ))

    def _rule_suspicious_scheduled_task(self, source_path: Path, record: dict) -> None:
        action = record.get("action") or record.get("TaskToRun") or record.get("command")
        if not action or not isinstance(action, str):
            return

        lower_act = action.lower()
        if any(tool in lower_act for tool in ["powershell", "cmd.exe", "mshta", "wscript", "cscript", "certutil", "bitsadmin"]):
            if any(sus in lower_act for sus in SUSPICIOUS_PATHS) or "http" in lower_act:
                self.findings.append(Finding(
                    title="Suspicious Scheduled Task Action",
                    description=f"Scheduled task executes script engine with unusual parameters/path: {action[:200]}",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    source_artifacts=[source_path.name],
                    rule_name="SuspiciousTaskRule",
                    category="Persistence",
                    raw_evidence=record,
                    recommendations=[
                        "Inspect task XML in C:\\Windows\\System32\\Tasks.",
                        "Determine creator user account and creation time.",
                    ],
                ))

    def _rule_removable_media_execution(self, source_path: Path, record: dict) -> None:
        path_str = record.get("path") or record.get("target_path") or ""
        if isinstance(path_str, str) and len(path_str) >= 2:
            drive_letter = path_str[:2].upper()
            if drive_letter not in ["C:", "D:"] and drive_letter.endswith(":"):
                self.findings.append(Finding(
                    title="Execution / Activity on Secondary or Removable Drive",
                    description=f"Artifact points to drive {drive_letter}: {path_str}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    source_artifacts=[source_path.name],
                    rule_name="RemovableDriveActivityRule",
                    category="Execution",
                    raw_evidence=record,
                    recommendations=[
                        "Correlate drive letter with MountedDevices and USBSTOR registry entries.",
                    ],
                ))
