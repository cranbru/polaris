import pytest
import json
from pathlib import Path

from core.case_manager import CaseManager
from core.evidence_manager import EvidenceManager
from core.manifest import ManifestManager
from reports.html_report import HtmlReportGenerator
from reports.pdf_report import PdfReportGenerator


@pytest.mark.unit
def test_html_report_generation(tmp_case_dir: Path):
    case_mgr = CaseManager(tmp_case_dir.parent)
    case_mgr.create_case(tmp_case_dir.name, profile="full", examiner="DFIR Lead")

    sysinfo = {"hostname": "TEST-HOST", "os_version": "Windows 11", "username": "investigator"}
    sys_path = tmp_case_dir / "metadata" / "system_info.json"
    with open(sys_path, "w", encoding="utf-8") as f:
        json.dump(sysinfo, f)

    gen = HtmlReportGenerator(tmp_case_dir)
    out = gen.generate()

    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "POLARIS Forensic Acquisition & Analysis Report" in content
    assert "TEST-HOST" in content
    assert "DFIR Lead" in content


@pytest.mark.unit
def test_pdf_report_generation(tmp_case_dir: Path):
    case_mgr = CaseManager(tmp_case_dir.parent)
    case_mgr.create_case(tmp_case_dir.name, profile="quick")

    gen = PdfReportGenerator(tmp_case_dir)
    out = gen.generate()

    assert out.exists()
    header = out.read_bytes()[:5]
    assert header == b"%PDF-"
