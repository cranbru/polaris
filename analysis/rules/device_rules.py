from pathlib import Path
from typing import Any

from config.settings import Severity
from analysis.finding_models import Finding, GroundingLevel, EvidenceConfidence
from analysis.rules.base_rule import BaseRule


class RemovableMediaExecutionRule(BaseRule):
    rule_id = "POLARIS-DEV-001"
    rule_name = "Execution from Removable / Secondary Media"
    category = "Removable Media"
    description = "Detects execution traces pointing to removable drives or non-system volume mount points."

    def evaluate(self, source_path: Path, record: dict[str, Any]) -> Finding | None:
        path_str = record.get("path") or record.get("target_path") or ""
        if not isinstance(path_str, str) or len(path_str) < 2:
            return None

        drive_letter = path_str[:2].upper()
        if drive_letter not in ["C:", "D:"] and drive_letter.endswith(":"):
            return Finding(
                title=f"Activity on Removable Drive {drive_letter}",
                description=f"Artifact record points to non-system drive {drive_letter}: {path_str}",
                severity=Severity.MEDIUM,
                confidence=EvidenceConfidence.LOW,
                grounding=GroundingLevel.OBSERVED,
                category=self.category,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                source_artifacts=[source_path.name],
                evidence_ids=[str(record.get("evidence_id", f"drive_{drive_letter}"))],
                observed_facts=f"Path target references drive {drive_letter}.",
                analytical_interpretation="Software execution from USB flash drives or external drives can represent data exfiltration staging or malicious tool execution.",
                supporting_indicators=[f"Target path: {path_str}"],
                alternative_explanations=["Legitimate user accessing personal documents or external media storage."],
                why_it_matters="Initial access via removable media (MITRE ATT&CK T1091) or tool execution bypassing local endpoint logging.",
                recommendations=[
                    "Correlate drive letter with MountedDevices and USBSTOR registry keys to identify physical device serial.",
                    "Review SetupAPI.dev.log for device first-connected and last-removed timestamps."
                ],
                limitations="Drive letters can be reused by different physical USB devices over time.",
                raw_evidence=record,
            )
        return None
