from pathlib import Path
from typing import Any

from config.settings import Severity
from analysis.finding_models import Finding, GroundingLevel, EvidenceConfidence
from analysis.rules.base_rule import BaseRule


class NonStandardServicePathRule(BaseRule):
    rule_id = "POLARIS-PERSIST-001"
    rule_name = "Service Executable Registered in Non-Standard Path"
    category = "Persistence"
    description = "Detects Windows services whose binaries point to user-writable, temporary, or unprivileged directories."

    def evaluate(self, source_path: Path, record: dict[str, Any]) -> Finding | None:
        svc_name = record.get("service_name") or record.get("Name")
        bin_path = record.get("binary_path") or record.get("PathName") or record.get("image_path")
        if not bin_path or not isinstance(bin_path, str):
            return None

        lower_path = bin_path.lower()
        matched = None
        for sus in ["\\temp\\", "\\tmp\\", "\\users\\public\\", "\\appdata\\"]:
            if sus in lower_path:
                matched = sus
                break

        if not matched:
            return None

        return Finding(
            title=f"Service Configured with Volatile Binary: {svc_name or 'Unknown'}",
            description=f"Service '{svc_name}' references executable path in '{matched}': {bin_path}",
            severity=Severity.CRITICAL,
            confidence=EvidenceConfidence.HIGH,
            grounding=GroundingLevel.OBSERVED,
            category=self.category,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            source_artifacts=[source_path.name],
            evidence_ids=[str(record.get("evidence_id", f"svc_{svc_name}"))],
            observed_facts=f"Service binary pathname is set to '{bin_path}'.",
            analytical_interpretation="Services running from user-writable directories bypass privilege separation and frequently indicate persistent backdoor installation.",
            supporting_indicators=[f"Service identifier: {svc_name}", f"Location matched: {matched}"],
            alternative_explanations=["Legacy standalone tool or non-standard user-installed developer utility."],
            why_it_matters="Windows Service persistence (MITRE ATT&CK T1543.003) enables SYSTEM-level execution during machine boot.",
            recommendations=[
                "Check System Event Log for Event ID 7045 (A new service was installed in the system).",
                "Acquire the binary and verify digital signatures and hashes.",
                "Review security descriptors and service account identity."
            ],
            limitations="Service may be stopped or deleted between acquisition and analysis.",
            raw_evidence=record,
        )


class SuspiciousScheduledTaskRule(BaseRule):
    rule_id = "POLARIS-PERSIST-002"
    rule_name = "Scheduled Task with Script Engine or Remote Action"
    category = "Persistence"
    description = "Detects scheduled tasks configured to launch script interpreters or execute remote payloads."

    def evaluate(self, source_path: Path, record: dict[str, Any]) -> Finding | None:
        action = record.get("action") or record.get("TaskToRun") or record.get("command")
        task_name = record.get("task_name") or record.get("TaskName", "Unknown Task")
        if not action or not isinstance(action, str):
            return None

        lower_act = action.lower()
        is_script = any(tool in lower_act for tool in ["powershell", "cmd.exe", "mshta", "wscript", "cscript", "certutil", "bitsadmin"])
        is_suspicious = any(p in lower_act for p in ["\\temp\\", "\\tmp\\", "\\public\\", "http://", "https://"])

        if is_script and is_suspicious:
            return Finding(
                title=f"Suspicious Scheduled Task Action: {task_name}",
                description=f"Task '{task_name}' executes script interpreter with unusual path/URL: {action[:160]}",
                severity=Severity.HIGH,
                confidence=EvidenceConfidence.MODERATE,
                grounding=GroundingLevel.OBSERVED,
                category=self.category,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                source_artifacts=[source_path.name],
                evidence_ids=[str(record.get("evidence_id", f"task_{task_name}"))],
                observed_facts=f"Task action: {action}",
                analytical_interpretation="Scheduled tasks executing scripts from temporary paths or remote URLs represent common persistence and recurring execution vectors.",
                supporting_indicators=[f"Task name: {task_name}", f"Action: {action}"],
                alternative_explanations=["Third-party updater or automated backup maintenance task."],
                why_it_matters="Scheduled tasks (MITRE ATT&CK T1053.005) allow scheduled re-infection or persistent beaconing.",
                recommendations=[
                    "Examine C:\\Windows\\System32\\Tasks XML definition for the task author and creation date.",
                    "Review TaskScheduler Operational event log (Event ID 106, 200)."
                ],
                limitations="Task trigger conditions (e.g. at logon, daily) require full XML inspection.",
                raw_evidence=record,
            )
        return None
