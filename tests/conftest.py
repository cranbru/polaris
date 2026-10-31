import pytest
from pathlib import Path


@pytest.fixture
def tmp_case_dir(tmp_path: Path) -> Path:
    case_dir = tmp_path / "TEST-CASE-001"
    subdirs = [
        "evidence/execution",
        "evidence/eventlogs",
        "evidence/registry",
        "evidence/user_activity",
        "evidence/browsers",
        "evidence/devices",
        "evidence/persistence",
        "evidence/network",
        "evidence/system",
        "parsed",
        "parsed/execution",
        "parsed/eventlogs",
        "parsed/registry",
        "parsed/user_activity",
        "parsed/browsers",
        "parsed/devices",
        "parsed/persistence",
        "parsed/network",
        "parsed/system",
        "timeline",
        "manifests",
        "logs",
        "metadata",
        "reports",
        "verification",
        "archive",
    ]
    for d in subdirs:
        (case_dir / d).mkdir(parents=True, exist_ok=True)
    return case_dir


@pytest.fixture
def sample_evidence_file(tmp_case_dir: Path) -> Path:
    f = tmp_case_dir / "evidence" / "execution" / "sample_binary.exe"
    f.write_text("dummy binary executable content for unit testing", encoding="utf-8")
    return f
