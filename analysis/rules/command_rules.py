import re
from pathlib import Path
from typing import Any

from config.settings import Severity
from analysis.finding_models import Finding, GroundingLevel, EvidenceConfidence
from analysis.rules.base_rule import BaseRule


class EncodedPowerShellRule(BaseRule):
    rule_id = "POLARIS-CMD-001"
    rule_name = "Base64 Encoded PowerShell Execution"
    category = "Command Execution"
    description = "Detects obfuscated PowerShell executions utilizing Base64 encoded payload arguments."

    def evaluate(self, source_path: Path, record: dict[str, Any]) -> Finding | None:
        cmd_str = ""
        for key in ["command", "command_line", "CommandLine", "ScriptBlockText", "message", "arguments"]:
            val = record.get(key)
            if val and isinstance(val, str):
                cmd_str = val
                break

        if not cmd_str:
            return None

        pattern = r"-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]{12,})"
        match = re.search(pattern, cmd_str, re.IGNORECASE)
        if not match:
            return None

        encoded_payload = match.group(1)

        return Finding(
            title="Base64 Encoded PowerShell Command Detected",
            description=f"PowerShell executed with an encoded command block: {cmd_str[:160]}...",
            severity=Severity.HIGH,
            confidence=EvidenceConfidence.HIGH,
            grounding=GroundingLevel.OBSERVED,
            category=self.category,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            source_artifacts=[source_path.name],
            evidence_ids=[str(record.get("evidence_id", f"{source_path.stem}_powershell_enc"))],
            observed_facts=f"Command execution contained Base64 string payload ({len(encoded_payload)} chars).",
            analytical_interpretation="Attackers routinely use the -EncodedCommand parameter to evade command-line string inspection and logging filters.",
            supporting_indicators=[f"Encoded snippet: {encoded_payload[:40]}..."],
            alternative_explanations=["Legitimate software management frameworks (e.g. SCCM, Intune, Chocolatey) occasionally encode complex scripts."],
            why_it_matters="Command obfuscation (MITRE ATT&CK T1027 / T1059.001) hides intended execution syntax from basic host-level monitoring.",
            recommendations=[
                "Decode the Base64 payload (using UTF-16LE decoding) to reveal the original script text.",
                "Review PowerShell Event ID 4104 (ScriptBlock Logging) for deobfuscated runtime AST execution."
            ],
            limitations="Does not automatically deobfuscate multi-layered script packing.",
            raw_evidence=record,
        )
