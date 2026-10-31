import pytest
from analysis.finding_models import Finding, FindingSummary, GroundingLevel, EvidenceConfidence
from config.settings import Severity


@pytest.mark.unit
def test_finding_model_explainability_attributes():
    finding = Finding(
        title="Unusual Binary Execution",
        severity=Severity.HIGH,
        confidence=EvidenceConfidence.HIGH,
        grounding=GroundingLevel.OBSERVED,
        category="Execution",
        source_artifacts=["prefetch"],
        evidence_ids=["ev_pf_001"],
        observed_facts="Process evil.exe was observed executing at 10:15:00 UTC",
        analytical_interpretation="Execution from temp folder indicates probable dropped payload.",
        why_it_matters="Attacker staged file in volatile path to bypass application controls.",
        recommendations=["Acquire binary hash and correlate with event logs."],
    )

    assert finding.finding_id.startswith("FND-")
    assert finding.grounding == GroundingLevel.OBSERVED
    assert finding.confidence == EvidenceConfidence.HIGH
    assert finding.severity == Severity.HIGH
    assert len(finding.evidence_ids) == 1
    assert "evil.exe" in finding.observed_facts


@pytest.mark.unit
def test_finding_summary_grounding_counts():
    f1 = Finding(title="F1", severity=Severity.HIGH, grounding=GroundingLevel.OBSERVED)
    f2 = Finding(title="F2", severity=Severity.MEDIUM, grounding=GroundingLevel.CORRELATED)
    f3 = Finding(title="F3", severity=Severity.LOW, grounding=GroundingLevel.INFERRED)

    summary = FindingSummary.from_findings([f1, f2, f3])
    assert summary.total_findings == 3
    assert summary.high == 1
    assert summary.medium == 1
    assert summary.grounding_counts.get("OBSERVED") == 1
    assert summary.grounding_counts.get("CORRELATED") == 1
    assert summary.grounding_counts.get("INFERRED") == 1
