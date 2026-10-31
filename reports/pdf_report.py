import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from config.settings import TOOL_NAME, TOOL_TAGLINE, LIVE_ACQUISITION_WARNING
from core.case_manager import CaseManager
from core.evidence_manager import EvidenceManager
from core.manifest import ManifestManager
from core.timeline import TimelineBuilder
from analysis.rules import RulesEngine


class PdfReportGenerator:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.reports_dir = case_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> Path:
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
            "PolarisTitle",
            parent=styles["Heading1"],
            fontSize=18,
            textColor=colors.HexColor("#032f62"),
            spaceAfter=4,
        )
        subtitle_style = ParagraphStyle(
            "PolarisSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#586069"),
            spaceAfter=14,
        )
        h2_style = ParagraphStyle(
            "PolarisH2",
            parent=styles["Heading2"],
            fontSize=13,
            textColor=colors.HexColor("#032f62"),
            spaceBefore=10,
            spaceAfter=6,
        )
        body_style = styles["Normal"]
        code_style = ParagraphStyle(
            "PolarisCode",
            parent=styles["Normal"],
            fontSize=7,
            fontName="Courier",
        )

        elements = []

        elements.append(Paragraph(f"{TOOL_NAME} Forensic Report", title_style))
        elements.append(Paragraph(f"{TOOL_TAGLINE}", subtitle_style))

        warning_p = Paragraph(f"<b>Notice:</b> {LIVE_ACQUISITION_WARNING}", body_style)
        w_table = Table([[warning_p]], colWidths=[540])
        w_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFBDD")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D9D0A5")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(w_table)
        elements.append(Spacer(1, 10))

        # Case & System Info
        case_mgr = CaseManager(self.case_dir.parent)
        metadata = case_mgr.load_metadata(self.case_dir)

        elements.append(Paragraph("1. Case Summary", h2_style))
        case_data = [
            ["Case ID", metadata.case_id if metadata else "N/A", "Examiner", (metadata.examiner if metadata else "") or "N/A"],
            ["Created", metadata.created_at if metadata else "N/A", "Profile", metadata.profile if metadata else "N/A"],
            ["Host", metadata.hostname if metadata else "N/A", "OS", (metadata.os_version if metadata else "")[:30]],
        ]
        t_case = Table(case_data, colWidths=[80, 190, 80, 190])
        t_case.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F8FF")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F1F8FF")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E1E4E8")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_case)
        elements.append(Spacer(1, 10))

        # Acquisition summary
        evidence_mgr = EvidenceManager(self.case_dir)
        evidence_mgr.load_results()
        summary = evidence_mgr.get_summary()

        elements.append(Paragraph("2. Evidence Summary", h2_style))
        status_str = ", ".join(f"{k}: {v}" for k, v in summary["status_counts"].items())
        acq_data = [
            ["Total Evidence Files", str(summary["total_files"]), "Total Modules", str(summary["total_modules"])],
            ["Status Breakdown", status_str, "", ""],
        ]
        t_acq = Table(acq_data, colWidths=[120, 150, 120, 150])
        t_acq.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F8FF")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F1F8FF")),
            ("SPAN", (1, 1), (3, 1)),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E1E4E8")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_acq)
        elements.append(Spacer(1, 10))

        # Findings
        rules_engine = RulesEngine(self.case_dir)
        findings = rules_engine.run_all_rules()

        elements.append(Paragraph("3. Automated Analysis Findings", h2_style))
        if findings:
            find_data = [["Severity", "Rule / Title", "Category", "Description"]]
            for f in findings[:20]:
                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                desc_p = Paragraph(f.description[:150], body_style)
                find_data.append([sev_val.upper(), f.title[:30], f.category, desc_p])
            t_find = Table(find_data, colWidths=[55, 125, 80, 280])
            t_find.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#032F62")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E1E4E8")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_find)
        else:
            elements.append(Paragraph("No anomalous findings detected.", body_style))
        elements.append(Spacer(1, 10))

        # Integrity & Manifest Sample
        manifest_mgr = ManifestManager(self.case_dir)
        manifest_entries = manifest_mgr.load_manifest()

        elements.append(Paragraph("4. Cryptographic Manifest (Sample)", h2_style))
        man_data = [["Category", "Filename", "Size", "SHA-256"]]
        for e in manifest_entries[:25]:
            man_data.append([
                e.category,
                e.filename[:25],
                f"{e.file_size} B",
                Paragraph(e.sha256, code_style),
            ])
        t_man = Table(man_data, colWidths=[80, 130, 50, 280])
        t_man.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F8FF")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E1E4E8")),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t_man)

        doc.build(elements)
        return out_path
