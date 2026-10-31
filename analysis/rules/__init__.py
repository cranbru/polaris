import json
import logging
from pathlib import Path
from typing import Any

from analysis.finding_models import Finding
from analysis.rules.base_rule import BaseRule
from analysis.rules.execution_rules import SuspiciousPathExecutionRule, LOLBinExecutionRule
from analysis.rules.command_rules import EncodedPowerShellRule
from analysis.rules.persistence_rules import NonStandardServicePathRule, SuspiciousScheduledTaskRule
from analysis.rules.device_rules import RemovableMediaExecutionRule

logger = logging.getLogger("polaris")


class RulesEngine:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.findings: list[Finding] = []
        self.rules: list[BaseRule] = [
            SuspiciousPathExecutionRule(),
            LOLBinExecutionRule(),
            EncodedPowerShellRule(),
            NonStandardServicePathRule(),
            SuspiciousScheduledTaskRule(),
            RemovableMediaExecutionRule(),
        ]

    def register_rule(self, rule: BaseRule) -> None:
        self.rules.append(rule)

    def run_all_rules(self) -> list[Finding]:
        self.findings.clear()
        parsed_dir = self.case_dir / "parsed"
        if not parsed_dir.exists():
            return self.findings

        for json_file in parsed_dir.rglob("*.json"):
            if json_file.name in ["findings.json", "ai_analysis.json", "TIMELINE.json"]:
                continue

            try:
                with open(json_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                self._analyze_file_data(json_file, data)
            except Exception as e:
                logger.debug(f"Failed to analyze {json_file}: {e}")

        findings_path = self.case_dir / "metadata" / "findings.json"
        findings_path.parent.mkdir(parents=True, exist_ok=True)
        with open(findings_path, "w", encoding="utf-8", errors="replace") as f:
            json.dump([f.model_dump() for f in self.findings], f, indent=2, ensure_ascii=False)

        return self.findings

    def _analyze_file_data(self, source_path: Path, data: Any) -> None:
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    self._evaluate_record(source_path, item)
        elif isinstance(data, dict):
            self._evaluate_record(source_path, data)

    def _evaluate_record(self, source_path: Path, record: dict) -> None:
        for rule in self.rules:
            try:
                finding = rule.evaluate(source_path, record)
                if finding:
                    self.findings.append(finding)
            except Exception as e:
                logger.debug(f"Error evaluating rule {rule.rule_id}: {e}")


__all__ = ["RulesEngine", "BaseRule"]
