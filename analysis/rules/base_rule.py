from abc import ABC, abstractmethod
from typing import Any
from pathlib import Path

from analysis.finding_models import Finding


class BaseRule(ABC):
    rule_id: str = "POLARIS-RULE-000"
    rule_name: str = "Base Rule"
    category: str = "General"
    description: str = ""

    @abstractmethod
    def evaluate(self, source_path: Path, record: dict[str, Any]) -> Finding | None:
        pass
