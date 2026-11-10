import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from config.settings import LIVE_ACQUISITION_WARNING, TOOL_NAME, TOOL_TAGLINE
from core.case_manager import CaseManager
from core.evidence_manager import EvidenceManager
from core.manifest import ManifestManager
from core.timeline import TimelineBuilder
from analysis.rules import RulesEngine
from analysis.correlation import CorrelationEngine
from reports.evidence_inspector import build_evidence_tree, get_polaris_created_evidence_files


class HtmlReportGenerator:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.reports_dir = case_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, include_ai: bool = True) -> Path:
        case_mgr = CaseManager(self.case_dir.parent)
        metadata = case_mgr.load_metadata(self.case_dir)

        evidence_mgr = EvidenceManager(self.case_dir)
        evidence_mgr.load_results()
        evidence_summary = evidence_mgr.get_summary()

        manifest_mgr = ManifestManager(self.case_dir)
        manifest_entries = manifest_mgr.load_manifest()

        sysinfo_path = self.case_dir / "metadata" / "system_info.json"
        system_info = {}
        if sysinfo_path.exists():
            try:
                with open(sysinfo_path, "r", encoding="utf-8") as f:
                    system_info = json.load(f)
            except Exception:
                pass

        verification = manifest_mgr.verify()

        from analysis.investigator_notes import InvestigatorNotesManager
        notes = InvestigatorNotesManager(self.case_dir)
        if notes.findings_path.exists():
            all_findings = notes.load_findings()
        else:
            all_findings = RulesEngine(self.case_dir).run_all_rules() + CorrelationEngine(self.case_dir).correlate()
            notes.save_findings(all_findings)

        ai_analysis = {}
        if include_ai:
            ai_path = self.case_dir / "metadata" / "ai_analysis.json"
            if ai_path.exists():
                try:
                    with open(ai_path, "r", encoding="utf-8") as f:
                        ai_analysis = json.load(f)
                except Exception:
                    pass

            if not ai_analysis or not ai_analysis.get("content"):
                ai_md_path = self.case_dir / "metadata" / "ai_analysis.md"
                if ai_md_path.exists():
                    try:
                        md_content = ai_md_path.read_text(encoding="utf-8", errors="replace")
                        ai_analysis = {
                            "provider": "AI",
                            "model": "Stellar Intelligence",
                            "analysis_timestamp": "Archived",
                            "content": md_content,
                            "evidence_reference_count": "Available",
                        }
                    except Exception:
                        pass

            if "content" in ai_analysis and ai_analysis["content"]:
                from reports.markdown_render import render_ai_markdown_to_html
                ai_analysis["content_html"] = render_ai_markdown_to_html(ai_analysis["content"])

        timeline_builder = TimelineBuilder(self.case_dir)
        timeline_builder.build_from_parsed()
        timeline_builder.sort_events()

        failures = []
        for res in evidence_mgr.results:
            for err in res.errors:
                failures.append({"module": res.module_name, "type": "Error", "message": err})
            for warn in res.warnings:
                failures.append({"module": res.module_name, "type": "Warning", "message": warn})

        import sys
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            template_dir = Path(sys._MEIPASS) / "reports" / "templates"
            if not template_dir.exists():
                template_dir = Path(__file__).parent / "templates"
        else:
            template_dir = Path(__file__).parent / "templates"
        env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
        template = env.get_template("report.html")

        evidence_tree = build_evidence_tree(self.case_dir)
        created_files = get_polaris_created_evidence_files(self.case_dir)

        rendered_html = template.render(
            tool_name=TOOL_NAME,
            tagline=TOOL_TAGLINE,
            case=metadata or {},
            system=system_info,
            evidence_summary=evidence_summary,
            collection_failures=failures,
            findings=[],  # Omit Heuristic & Correlated Findings per user requirement
            evidence_tree=evidence_tree,
            created_files=created_files,
            ai_analysis=ai_analysis,
            timeline_events=timeline_builder.events,
            manifest_entries=manifest_entries,
            verification=verification,
            live_warning=LIVE_ACQUISITION_WARNING,
        )

        out_path = self.reports_dir / "report.html"
        out_path.write_text(rendered_html, encoding="utf-8", errors="replace")
        return out_path
