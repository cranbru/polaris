from pathlib import Path
from typing import Any

from config.settings import Severity
from analysis.finding_models import Finding, GroundingLevel, EvidenceConfidence
from analysis.rules.base_rule import BaseRule

SUSPICIOUS_PATHS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\perflogs\\",
    "\\public\\",
]

LOLBINS = [
    "certutil.exe", "mshta.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe",
    "regsvr32.exe", "rundll32.exe", "installutil.exe", "msbuild.exe"
]


class SuspiciousPathExecutionRule(BaseRule):
    rule_id = "POLARIS-EXEC-001"
    rule_name = "Execution from Volatile / Temporary Path"
    category = "Execution"
    description = "Detects binary execution originating from temporary, unprivileged, or volatile user directories."

    def evaluate(self, source_path: Path, record: dict[str, Any]) -> Finding | None:
        path_str = ""
        for key in ["path", "executable", "target_path", "image_path", "Image"]:
            val = record.get(key)
            if val and isinstance(val, str):
                path_str = val.lower()
                break

        if not path_str:
            return None

        matched_pattern = None
        for sus in SUSPICIOUS_PATHS:
            if sus in path_str:
                matched_pattern = sus
                break

        if not matched_pattern:
            return None

        file_name = Path(path_str).name
        timestamp = str(record.get("timestamp", record.get("TimeCreated", record.get("last_execution", ""))))

        return Finding(
            title=f"Executable Launched from Volatile Location: {file_name}",
            description=f"Artifact executed from path containing '{matched_pattern}': {path_str}",
            severity=Severity.HIGH,
            confidence=EvidenceConfidence.HIGH,
            grounding=GroundingLevel.OBSERVED,
            category=self.category,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            source_artifacts=[source_path.name],
            evidence_ids=[str(record.get("evidence_id", f"{source_path.stem}_{file_name}"))],
            timestamps=[timestamp] if timestamp else [],
            observed_facts=f"Binary '{file_name}' was recorded executing from '{path_str}' in artifact '{source_path.name}'.",
            analytical_interpretation="Legitimate software rarely executes directly from user temporary folders unless part of an installer or malicious payload drop.",
            supporting_indicators=[f"Directory match: {matched_pattern}", f"Source log: {source_path.name}"],
            alternative_explanations=[
                "Legitimate software installer or updater executing setup stub from Temp directory.",
                "Custom enterprise script staged in public directory."
            ],
            why_it_matters="Dropping and executing payloads in %TEMP% or %APPDATA% is a standard MITRE ATT&CK T1059 / T1204 technique used to bypass standard directory write restrictions.",
            recommendations=[
                "Extract the binary if still resident and verify its cryptographic hash and Authenticode signature.",
                "Examine process creation events (Event ID 4688 or Sysmon Event 1) for parent process lineage.",
                "Inspect network telemetry for connections established during the execution window."
            ],
            limitations="File modification or deletion prior to acquisition may prevent binary recovery.",
            raw_evidence=record,
        )


class LOLBinExecutionRule(BaseRule):
    rule_id = "POLARIS-EXEC-002"
    rule_name = "Living-off-the-Land Binary (LOLBin) Invocation"
    category = "Execution"
    description = "Detects invocation of Windows dual-use binaries known to be leveraged for defense evasion or proxy execution."

    def evaluate(self, source_path: Path, record: dict[str, Any]) -> Finding | None:
        cmd_str = ""
        for key in ["command", "command_line", "CommandLine", "arguments", "executable"]:
            val = record.get(key)
            if val and isinstance(val, str):
                cmd_str = val.lower()
                break

        if not cmd_str:
            return None

        matched_bin = None
        for bin_name in LOLBINS:
            if bin_name in cmd_str:
                matched_bin = bin_name
                break

        if not matched_bin:
            return None

        # Check for suspicious parameters (e.g. url, base64, script)
        is_suspicious_args = any(arg in cmd_str for arg in ["http://", "https://", "javascript:", "vbscript:", "-decode", "/e:"])
        if not is_suspicious_args:
            return None

        return Finding(
            title=f"Suspicious LOLBin Invocation: {matched_bin}",
            description=f"Dual-use system binary '{matched_bin}' executed with external or scripting arguments: {cmd_str[:180]}...",
            severity=Severity.HIGH,
            confidence=EvidenceConfidence.HIGH,
            grounding=GroundingLevel.OBSERVED,
            category=self.category,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            source_artifacts=[source_path.name],
            evidence_ids=[str(record.get("evidence_id", f"{source_path.stem}_{matched_bin}"))],
            observed_facts=f"Binary '{matched_bin}' was invoked with arguments: {cmd_str}",
            analytical_interpretation="LOLBins are frequently weaponized by adversaries to proxy execution of untrusted scripts or download remote payloads.",
            supporting_indicators=[f"Binary identified: {matched_bin}", f"Suspicious parameter pattern detected"],
            alternative_explanations=["Administrative maintenance script or software installer."],
            why_it_matters="Execution of LOLBins with URL arguments often indicates living-off-the-land download cradles (T1105).",
            recommendations=[
                "Inspect DNS cache and proxy logs for connections to URLs passed in arguments.",
                "Review parent process to determine if spawned by browser, document, or command shell."
            ],
            limitations="Argument string may be truncated if originating from certain event logs.",
            raw_evidence=record,
        )
