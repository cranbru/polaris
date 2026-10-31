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


@pytest.mark.unit
def test_ai_markdown_rendering():
    from reports.markdown_render import render_ai_markdown_to_html

    sample_md = (
        "### 1. Executive Summary\n\n"
        "Observed execution of `malware.exe` on host.\n\n"
        "**OBSERVED:**\n"
        "* **Artifact:** Prefetch execution confirmed.\n"
        "    * Details: Run count 5.\n"
        "**INFERRED:** Potential initial access.\n"
    )
    rendered = render_ai_markdown_to_html(sample_md)

    assert '<h3 class="ai-heading">1. Executive Summary</h3>' in rendered
    assert '<code class="ai-inline-code">malware.exe</code>' in rendered
    assert '<span class="badge badge-info ai-badge">OBSERVED</span>' in rendered
    assert '<span class="badge badge-medium ai-badge">INFERRED</span>' in rendered
    assert '<ul class="ai-list">' in rendered
    assert '<ul class="ai-sublist">' in rendered


@pytest.mark.unit
def test_html_report_with_ai_analysis(tmp_case_dir: Path):
    case_mgr = CaseManager(tmp_case_dir.parent)
    case_mgr.create_case(tmp_case_dir.name, profile="full")

    ai_data = {
        "case_id": tmp_case_dir.name,
        "provider": "gemini",
        "model": "gemini-1.5-pro",
        "analysis_timestamp": "2026-10-31T15:00:00",
        "evidence_reference_count": 12,
        "content": "### 1. Assessment\n\n**OBSERVED:** Suspicious PowerShell activity.",
    }
    ai_path = tmp_case_dir / "metadata" / "ai_analysis.json"
    with open(ai_path, "w", encoding="utf-8") as f:
        json.dump(ai_data, f)

    gen = HtmlReportGenerator(tmp_case_dir)
    out = gen.generate(include_ai=True)

    assert out.exists()
    html_content = out.read_text(encoding="utf-8")
    assert "Stellar Intelligence" in html_content
    assert "GEMINI" in html_content
    assert "gemini-1.5-pro" in html_content
    assert '<h3 class="ai-heading">1. Assessment</h3>' in html_content
    assert "OBSERVED" in html_content
