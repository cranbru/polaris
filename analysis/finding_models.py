import uuid
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from config.settings import Severity, get_iso_timestamp


class GroundingLevel(str, Enum):
    OBSERVED = "OBSERVED"        # Directly supported by acquired evidence
    CORRELATED = "CORRELATED"    # Supported by multiple related artifacts
    INFERRED = "INFERRED"        # An interpretation requiring additional validation
    UNCONFIRMED = "UNCONFIRMED"  # A hypothesis that cannot yet be established


class EvidenceConfidence(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"


class FindingStatus(str, Enum):
    NEW = "NEW"
    IN_REVIEW = "IN_REVIEW"
    CONFIRMED = "CONFIRMED"
    BENIGN = "BENIGN"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"FND-{str(uuid.uuid4())[:8].upper()}")
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: EvidenceConfidence = EvidenceConfidence.MODERATE
    grounding: GroundingLevel = GroundingLevel.OBSERVED
    status: FindingStatus = FindingStatus.NEW
    
    category: str = "General"
    rule_id: str = ""
    rule_name: str = ""
    
    # Evidence Grounding
    source_artifacts: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    source_record_ids: list[str] = Field(default_factory=list)
    timestamps: list[str] = Field(default_factory=list)
    
    # Explainability Framework
    observed_facts: str = ""
    analytical_interpretation: str = ""
    supporting_indicators: list[str] = Field(default_factory=list)
    alternative_explanations: list[str] = Field(default_factory=list)
    why_it_matters: str = ""
    recommendations: list[str] = Field(default_factory=list)
    limitations: str = ""
    
    # Investigator Annotations
    investigator_notes: list[str] = Field(default_factory=list)
    raw_evidence: dict = Field(default_factory=dict)
    created_at: str = Field(default_factory=get_iso_timestamp)


class FindingSummary(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    grounding_counts: dict[str, int] = Field(default_factory=dict)
    categories: dict[str, int] = Field(default_factory=dict)
    top_findings: list[Finding] = Field(default_factory=list)
    generated_at: str = Field(default_factory=get_iso_timestamp)

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "FindingSummary":
        severity_counts = {s: 0 for s in Severity}
        grounding_counts = {g.value: 0 for g in GroundingLevel}
        categories: dict[str, int] = {}

        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            grounding_counts[f.grounding.value] = grounding_counts.get(f.grounding.value, 0) + 1
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

        return cls(
            total_findings=len(findings),
            critical=severity_counts.get(Severity.CRITICAL, 0),
            high=severity_counts.get(Severity.HIGH, 0),
            medium=severity_counts.get(Severity.MEDIUM, 0),
            low=severity_counts.get(Severity.LOW, 0),
            info=severity_counts.get(Severity.INFO, 0),
            grounding_counts=grounding_counts,
            categories=categories,
            top_findings=sorted_findings[:10],
        )
