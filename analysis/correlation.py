import json
import logging
from pathlib import Path
from collections import defaultdict

from config.settings import Severity, Confidence
from analysis.finding_models import Finding

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

        executables_executed: set[str] = set()
        executables_persistent: dict[str, list[str]] = defaultdict(list)
        executables_running: set[str] = set()

        for json_file in parsed_dir.rglob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, list):
                    continue

                for item in data:
                    if not isinstance(item, dict):
                        continue

                    category = json_file.parent.name.lower()
                    exe_name = self._extract_exe_name(item)
                    if not exe_name:
                        continue

                    if category in ["execution", "user_activity"]:
                        executables_executed.add(exe_name.lower())
                    elif category == "persistence":
                        executables_persistent[exe_name.lower()].append(json_file.name)
                    elif category in ["system", "network"]:
                        executables_running.add(exe_name.lower())

            except Exception as e:
                logger.debug(f"Correlation error on {json_file}: {e}")

        # Correlate: Running or executed binary that is also registered in persistence
        common = (executables_executed | executables_running) & set(executables_persistent.keys())
        for exe in common:
            sources = executables_persistent[exe]
            self.correlations.append(Finding(
                title=f"Correlated Execution and Persistence: {exe}",
                description=f"Binary '{exe}' was identified in both execution/runtime data and persistence mechanisms ({', '.join(set(sources))}).",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                source_artifacts=list(set(sources)),
                rule_name="ExecutionPersistenceCorrelation",
                category="Correlation",
                recommendations=[
                    f"Check startup frequency and origin of '{exe}'.",
                    "Verify file hashes against known threat intelligence databases.",
                ],
            ))

        return self.correlations

    def _extract_exe_name(self, record: dict) -> str:
        for key in ["executable", "process_name", "image_name", "filename", "name", "Image"]:
            val = record.get(key)
            if val and isinstance(val, str) and val.endswith(".exe"):
                return Path(val).name
        return ""
