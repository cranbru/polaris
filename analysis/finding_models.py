import uuid
from typing import Optional

from pydantic import BaseModel, Field

from config.settings import Severity, Confidence, get_iso_timestamp


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str
    description: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    source_artifacts: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    timestamps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    rule_name: str = ""
    category: str = ""
    raw_evidence: dict = Field(default_factory=dict)
    created_at: str = Field(default_factory=get_iso_timestamp)


class FindingSummary(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    categories: dict[str, int] = Field(default_factory=dict)
    top_findings: list[Finding] = Field(default_factory=list)
    generated_at: str = Field(default_factory=get_iso_timestamp)

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "FindingSummary":
        severity_counts = {s: 0 for s in Severity}
        categories: dict[str, int] = {}

        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            cat = f.category or "uncategorized"
            categories[cat] = categories.get(cat, 0) + 1

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))
        top_findings = sorted_findings[:10]

        return cls(
            total_findings=len(findings),
            critical=severity_counts.get(Severity.CRITICAL, 0),
            high=severity_counts.get(Severity.HIGH, 0),
            medium=severity_counts.get(Severity.MEDIUM, 0),
            low=severity_counts.get(Severity.LOW, 0),
            info=severity_counts.get(Severity.INFO, 0),
            categories=categories,
            top_findings=top_findings,
        )
