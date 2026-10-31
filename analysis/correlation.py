import json
import logging
from pathlib import Path
from collections import defaultdict

from config.settings import Severity
from analysis.finding_models import Finding, GroundingLevel, EvidenceConfidence

logger = logging.getLogger("polaris")


class CorrelationEngine:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.correlations: list[Finding] = []

    def correlate(self) -> list[Finding]:
        self.correlations.clear()
        parsed_dir = self.case_dir / "parsed"
        if not parsed_dir.exists():
            return self.correlations

        executables_executed: dict[str, list[dict]] = defaultdict(list)
        executables_persistent: dict[str, list[dict]] = defaultdict(list)
        executables_running: dict[str, list[dict]] = defaultdict(list)
        usb_devices: list[dict] = []
        user_drive_targets: list[dict] = []

        for json_file in parsed_dir.rglob("*.json"):
            if json_file.name in ["findings.json", "ai_analysis.json", "TIMELINE.json"]:
                continue

            try:
                with open(json_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                if not isinstance(data, list):
                    continue

                for item in data:
                    if not isinstance(item, dict):
                        continue

                    category = json_file.parent.name.lower()
                    exe_name = self._extract_exe_name(item)

                    if exe_name:
                        rec = {"file": json_file.name, "record": item}
                        if category in ["execution", "user_activity"]:
                            executables_executed[exe_name.lower()].append(rec)
                        elif category == "persistence":
                            executables_persistent[exe_name.lower()].append(rec)
                        elif category in ["system", "network"]:
                            executables_running[exe_name.lower()].append(rec)

                    if category == "devices" or "usb" in json_file.name:
                        usb_devices.append(item)

                    # Check for non-C drive target in LNK / Jump lists
                    target_path = item.get("target_path", "")
                    if isinstance(target_path, str) and len(target_path) >= 2 and target_path[1] == ":":
                        drive = target_path[:2].upper()
                        if drive not in ["C:", "D:"]:
                            user_drive_targets.append({"path": target_path, "source": json_file.name, "record": item})

            except Exception as e:
                logger.debug(f"Correlation parsing error on {json_file}: {e}")

        # Correlation 1: Runtime/Executed Binary that is also a configured persistence hook
        common_persistence = (set(executables_executed.keys()) | set(executables_running.keys())) & set(executables_persistent.keys())
        for exe in common_persistence:
            exec_sources = [r["file"] for r in executables_executed.get(exe, []) + executables_running.get(exe, [])]
            persist_sources = [r["file"] for r in executables_persistent.get(exe, [])]
            all_sources = list(set(exec_sources + persist_sources))

            self.correlations.append(Finding(
                title=f"Correlated Execution and Persistence: {exe}",
                description=f"Binary '{exe}' was identified across both active execution artifacts and configured persistence entries ({', '.join(all_sources)}).",
                severity=Severity.HIGH,
                confidence=EvidenceConfidence.HIGH,
                grounding=GroundingLevel.CORRELATED,
                category="Correlation",
                rule_id="POLARIS-CORR-001",
                rule_name="Execution-Persistence Cross Correlation",
                source_artifacts=all_sources,
                observed_facts=f"Binary '{exe}' appears in execution records ({', '.join(set(exec_sources))}) and persistence configurations ({', '.join(set(persist_sources))}).",
                analytical_interpretation="A binary present in both execution traces and persistence mechanisms was deliberately maintained across machine boots and executed during the investigation window.",
                supporting_indicators=[f"Cross-artifact presence across {len(all_sources)} sources", f"Binary: {exe}"],
                alternative_explanations=["Standard third-party enterprise utility installed to start automatically."],
                why_it_matters="Adversaries establish persistence (MITRE ATT&CK TA0003) to maintain long-term access following initial execution.",
                recommendations=[
                    f"Inspect the complete file path of '{exe}' in both sources to confirm identical binary location.",
                    "Verify file hash against Authenticode catalogs and Threat Intelligence feeds."
                ],
                limitations="Timestamp resolution depends on the specific source artifact (e.g. registry vs prefetch).",
            ))

        # Correlation 2: User Activity on External Volume with Registered USB Devices
        if user_drive_targets and usb_devices:
            for target in user_drive_targets[:5]:
                p = target["path"]
                src = target["source"]
                self.correlations.append(Finding(
                    title=f"Correlated USB Removable Storage File Access: {Path(p).name}",
                    description=f"User activity artifact '{src}' references file on external volume '{p[:2]}' while USB storage devices are registered.",
                    severity=Severity.MEDIUM,
                    confidence=EvidenceConfidence.MODERATE,
                    grounding=GroundingLevel.CORRELATED,
                    category="Correlation",
                    rule_id="POLARIS-CORR-002",
                    rule_name="User Activity - USB Hardware Correlation",
                    source_artifacts=[src, "usb_devices"],
                    observed_facts=f"LNK/JumpList points to '{p}', and USBSTOR/MountedDevices records presence of removable storage.",
                    analytical_interpretation="Indicates direct interaction with files stored on removable flash media or external storage volumes.",
                    supporting_indicators=[f"Target path: {p}", f"Source artifact: {src}"],
                    alternative_explanations=["User opened personal documents or business files from a company-provided thumb drive."],
                    why_it_matters="Potential data exfiltration (T1052.001) or introduction of unmanaged external payloads.",
                    recommendations=[
                        "Correlate volume serial numbers in LNK extra data block with MountedDevices drive mapping.",
                        "Inspect USB connect/disconnect event logs (Kernel-PnP Event 2003) for precise device session timing."
                    ],
                    limitations="Volume GUIDs and drive letters may reassign across different USB insertion events.",
                ))

        return self.correlations

    def _extract_exe_name(self, record: dict) -> str:
        for key in ["executable", "process_name", "image_name", "filename", "name", "Image"]:
            val = record.get(key)
            if val and isinstance(val, str) and val.lower().endswith(".exe"):
                return Path(val).name
        return ""
