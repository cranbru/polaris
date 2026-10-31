import json
from pathlib import Path
from typing import Optional

from analysis.finding_models import Finding, FindingStatus
from config.settings import Severity, get_iso_timestamp


class InvestigatorNotesManager:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.findings_path = case_dir / "metadata" / "findings.json"

    def load_findings(self) -> list[Finding]:
        if not self.findings_path.exists():
            return []
        try:
            with open(self.findings_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [Finding(**item) for item in data]
        except Exception:
            return []

    def save_findings(self, findings: list[Finding]) -> None:
        self.findings_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.findings_path, "w", encoding="utf-8") as f:
            json.dump([f.model_dump() for f in findings], f, indent=2, ensure_ascii=False)

    def add_note_to_finding(self, finding_id: str, note_text: str, author: str = "Investigator") -> bool:
        findings = self.load_findings()
        updated = False
        timestamp = get_iso_timestamp()

        for f in findings:
            if f.finding_id == finding_id:
                formatted_note = f"[{timestamp}] ({author}): {note_text}"
                f.investigator_notes.append(formatted_note)
                updated = True
                break

        if updated:
            self.save_findings(findings)
        return updated

    def update_finding_status(self, finding_id: str, new_status: FindingStatus) -> bool:
        findings = self.load_findings()
        updated = False

        for f in findings:
            if f.finding_id == finding_id:
                f.status = new_status
                updated = True
                break

        if updated:
            self.save_findings(findings)
        return updated

    def filter_findings(
        self,
        severity: Optional[str] = None,
        status: Optional[FindingStatus] = None,
        category: Optional[str] = None,
    ) -> list[Finding]:
        findings = self.load_findings()
        results = []

        for f in findings:
            if severity:
                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                if sev_val.lower() != severity.lower():
                    continue

            if status and f.status != status:
                continue

            if category and f.category.lower() != category.lower():
                continue

            results.append(f)

        return results
