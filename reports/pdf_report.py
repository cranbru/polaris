import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

from config.theme import CelestialPalette
from config.settings import TOOL_NAME, TOOL_TAGLINE, TOOL_SUBTITLE, LIVE_ACQUISITION_WARNING
from core.case_manager import CaseManager
from core.evidence_manager import EvidenceManager
from core.manifest import ManifestManager
from core.timeline import TimelineBuilder
from analysis.rules import RulesEngine
from analysis.correlation import CorrelationEngine


class PdfReportGenerator:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.reports_dir = case_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, include_ai: bool = True) -> Path:
        out_path = self.reports_dir / "report.pdf"
        doc = SimpleDocTemplate(
            str(out_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "CelestialTitle",
            parent=styles["Heading1"],
            fontSize=20,
            textColor=colors.HexColor(CelestialPalette.AURORA_CYAN),
            alignment=1,  # Center
            spaceAfter=4,
        )
        subtitle_style = ParagraphStyle(
            "CelestialSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor(CelestialPalette.MUTED_BLUE),
            alignment=1,
            spaceAfter=14,
        )
        h2_style = ParagraphStyle(
            "CelestialH2",
            parent=styles["Heading2"],
            fontSize=12,
            textColor=colors.HexColor(CelestialPalette.STELLAR_BLUE),
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "CelestialBody",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1E293B"),
        )
        code_style = ParagraphStyle(
            "CelestialCode",
            parent=styles["Normal"],
            fontSize=6.5,
            leading=8,
            fontName="Courier",
            textColor=colors.HexColor("#334155"),
        )

        elements = []

        # Cover Banner
        banner_content = [
            [Paragraph(f"<b>{TOOL_NAME}</b>", title_style)],
            [Paragraph(f"{TOOL_SUBTITLE}<br/><i>\"{TOOL_TAGLINE}\"</i>", subtitle_style)],
        ]
        t_banner = Table(banner_content, colWidths=[540])
        t_banner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(CelestialPalette.MIDNIGHT_NAVY)),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("PADDING", (0, 0), (-1, -1), 16),
            ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor(CelestialPalette.STELLAR_BLUE)),
        ]))
        elements.append(t_banner)
        elements.append(Spacer(1, 10))

        # Notice
        warning_p = Paragraph(f"<b>Forensic Notice:</b> {LIVE_ACQUISITION_WARNING}", body_style)
        w_table = Table([[warning_p]], colWidths=[540])
        w_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(CelestialPalette.STELLAR_BLUE)),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(w_table)
        elements.append(Spacer(1, 10))

        # Case Summary
        case_mgr = CaseManager(self.case_dir.parent)
        metadata = case_mgr.load_metadata(self.case_dir)

        elements.append(Paragraph("1. Mission Case & Target Telemetry", h2_style))
        case_data = [
            ["Case ID", metadata.case_id if metadata else "N/A", "Examiner", (metadata.examiner if metadata else "") or "N/A"],
            ["Created", metadata.created_at[:19] if metadata else "N/A", "Profile", metadata.profile if metadata else "Standard"],
            ["Host", metadata.hostname if metadata else "N/A", "Platform", (metadata.os_version if metadata else "")[:28]],
        ]
        t_case = Table(case_data, colWidths=[80, 190, 80, 190])
        t_case.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F1F5F9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_case)
        elements.append(Spacer(1, 10))

        # Acquisition summary
        evidence_mgr = EvidenceManager(self.case_dir)
        evidence_mgr.load_results()
        summary = evidence_mgr.get_summary()

        elements.append(Paragraph("2. Celestial Collector Telemetry", h2_style))
        status_str = ", ".join(f"{k}: {v}" for k, v in summary["status_counts"].items())
        acq_data = [
            ["Total Evidence Files", str(summary["total_files"]), "Total Modules Run", str(summary["total_modules"])],
            ["Status Breakdown", status_str, "", ""],
        ]
        t_acq = Table(acq_data, colWidths=[120, 150, 120, 150])
        t_acq.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F1F5F9")),
            ("SPAN", (1, 1), (3, 1)),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_acq)
        elements.append(Spacer(1, 10))

        # Findings
        rules_engine = RulesEngine(self.case_dir)
        rule_findings = rules_engine.run_all_rules()
        correlator = CorrelationEngine(self.case_dir)
        correlations = correlator.correlate()
        all_findings = rule_findings + correlations

        elements.append(Paragraph("3. Explainable Findings & Observations", h2_style))
        if all_findings:
            find_data = [["Severity", "Grounding", "Rule / Title", "Analytical Interpretation"]]
            for f in all_findings[:15]:
                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                ground_val = f.grounding.value if hasattr(f.grounding, "value") else str(f.grounding)
                interp = f.analytical_interpretation or f.description
                find_data.append([
                    sev_val.upper(),
                    ground_val,
                    Paragraph(f"<b>{f.title[:35]}</b>", body_style),
                    Paragraph(interp[:160], body_style),
                ])
            t_find = Table(find_data, colWidths=[55, 65, 160, 260])
            t_find.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(CelestialPalette.MIDNIGHT_NAVY)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(t_find)
        else:
            elements.append(Paragraph("No anomalous indicators detected by automated analysis rules.", body_style))
        elements.append(Spacer(1, 10))

        # AI Analysis Section
        if include_ai:
            ai_path = self.case_dir / "metadata" / "ai_analysis.json"
            if ai_path.exists():
                try:
                    with open(ai_path, "r", encoding="utf-8") as f:
                        ai_data = json.load(f)
                    elements.append(Paragraph("4. Stellar Intelligence (AI Analysis Summary)", h2_style))
                    ai_meta = Paragraph(
                        f"<b>Provider:</b> {ai_data.get('provider', '').upper()} ({ai_data.get('model', '')}) | "
                        f"<b>Timestamp:</b> {ai_data.get('analysis_timestamp', '')}",
                        body_style
                    )
                    ai_text = Paragraph(ai_data.get("content", "")[:900] + "...", body_style)
                    t_ai = Table([[ai_meta], [ai_text]], colWidths=[540])
                    t_ai.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(CelestialPalette.STELLAR_BLUE)),
                        ("PADDING", (0, 0), (-1, -1), 6),
                    ]))
                    elements.append(t_ai)
                    elements.append(Spacer(1, 10))
                except Exception:
                    pass

        # Manifest Sample
        manifest_mgr = ManifestManager(self.case_dir)
        manifest_entries = manifest_mgr.load_manifest()

        elements.append(Paragraph("5. Evidence Vault - Cryptographic Manifest (Sample)", h2_style))
        man_data = [["Category", "Filename", "Size", "SHA-256 Checksum"]]
        for e in manifest_entries[:20]:
            man_data.append([
                e.category,
                e.filename[:25],
                f"{e.file_size} B",
                Paragraph(e.sha256, code_style),
            ])
        t_man = Table(man_data, colWidths=[75, 130, 45, 290])
        t_man.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("FONTSIZE", (0, 0), (-1, -1), 6.5),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t_man)

        doc.build(elements)
        return out_path
