import os
import shutil
import tempfile
import subprocess
import json
import html
import re
import logging
from pathlib import Path
from typing import Optional

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
from reports.evidence_inspector import build_evidence_tree, get_polaris_created_evidence_files

logger = logging.getLogger("polaris.pdf_report")


def find_headless_browser() -> Optional[str]:
    """Locates a headless Chromium-based browser (Edge, Chrome, Chromium, Brave) for 1:1 HTML-to-PDF conversion."""
    env_browser = os.environ.get("POLARIS_BROWSER_PATH")
    if env_browser and Path(env_browser).is_file():
        return env_browser

    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    local_app_data = os.environ.get("LOCALAPPDATA", "")

    windows_candidates = [
        # Microsoft Edge (standard Windows 10/11 built-in)
        Path(program_files_x86) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        Path(program_files) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        # Google Chrome
        Path(program_files) / "Google" / "Chrome" / "Application" / "chrome.exe",
        Path(program_files_x86) / "Google" / "Chrome" / "Application" / "chrome.exe",
        # User installations
        Path(local_app_data) / "Microsoft" / "Edge" / "Application" / "msedge.exe" if local_app_data else None,
        Path(local_app_data) / "Google" / "Chrome" / "Application" / "chrome.exe" if local_app_data else None,
        # Brave Browser
        Path(program_files) / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
        Path(local_app_data) / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe" if local_app_data else None,
    ]

    for cand in windows_candidates:
        if cand and cand.is_file():
            return str(cand)

    for name in ["msedge", "chrome", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave"]:
        found = shutil.which(name)
        if found and Path(found).is_file():
            return found

    return None


class PdfReportGenerator:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.reports_dir = case_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, include_ai: bool = True) -> Path:
        """Generates PDF report as an exact replica of the HTML report."""
        out_path = self.reports_dir / "report.pdf"

        # Ensure HTML report is generated and up-to-date
        from reports.html_report import HtmlReportGenerator
        html_gen = HtmlReportGenerator(self.case_dir)
        html_path = html_gen.generate(include_ai=include_ai)

        # 1. Convert HTML report directly to PDF via headless browser (exact converted version)
        if self._convert_html_to_pdf_browser(html_path, out_path):
            logger.info(f"Generated exact converted PDF from HTML: {out_path}")
            return out_path

        # 2. Fallback to ReportLab if no browser is available
        logger.warning("No headless browser found; falling back to ReportLab generation.")
        return self._generate_reportlab_fallback(out_path, include_ai=include_ai)

    def _convert_html_to_pdf_browser(self, html_path: Path, out_path: Path) -> bool:
        """Converts HTML file directly to PDF using headless Chromium (Edge/Chrome)."""
        browser_exe = find_headless_browser()
        if not browser_exe:
            return False

        temp_user_data = None
        try:
            temp_user_data = tempfile.mkdtemp(prefix="polaris_pdf_")
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

            # Modern Chromium headless conversion
            cmd = [
                browser_exe,
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                f"--user-data-dir={temp_user_data}",
                "--allow-file-access-from-files",
                "--no-pdf-header-footer",
                f"--print-to-pdf={out_path.resolve()}",
                html_path.resolve().as_uri(),
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=45, creationflags=flags)
            if out_path.exists() and out_path.stat().st_size > 1000:
                return True

            # Legacy headless fallback
            cmd[1] = "--headless"
            subprocess.run(cmd, capture_output=True, text=True, timeout=45, creationflags=flags)
            if out_path.exists() and out_path.stat().st_size > 1000:
                return True
        except Exception as e:
            logger.warning(f"Browser HTML-to-PDF conversion error: {e}")
        finally:
            if temp_user_data and Path(temp_user_data).exists():
                try:
                    shutil.rmtree(temp_user_data, ignore_errors=True)
                except Exception:
                    pass

        return False

    def _generate_reportlab_fallback(self, out_path: Path, include_ai: bool = True) -> Path:
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
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor(CelestialPalette.STELLAR_BLUE),
            spaceBefore=14,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "CelestialBody",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#0F172A"),
        )
        code_style = ParagraphStyle(
            "CelestialCode",
            parent=styles["Normal"],
            fontName="Courier-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#0F172A"),
        )
        h3_style = ParagraphStyle(
            "CelestialH3",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=colors.HexColor(CelestialPalette.MIDNIGHT_NAVY),
            spaceBefore=8,
            spaceAfter=4,
        )
        bullet_style = ParagraphStyle(
            "CelestialBullet",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            leftIndent=12,
            textColor=colors.HexColor("#0F172A"),
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
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_case)
        elements.append(Spacer(1, 10))

        # AI Analysis Section (Shifted to top right after basic case info)
        if include_ai:
            ai_data = None
            ai_path = self.case_dir / "metadata" / "ai_analysis.json"
            if ai_path.exists():
                try:
                    with open(ai_path, "r", encoding="utf-8") as f:
                        ai_data = json.load(f)
                except Exception as e:
                    logger.warning(f"Failed to read ai_analysis.json: {e}")

            if not ai_data or not ai_data.get("content"):
                ai_md_path = self.case_dir / "metadata" / "ai_analysis.md"
                if ai_md_path.exists():
                    try:
                        md_text = ai_md_path.read_text(encoding="utf-8", errors="replace")
                        ai_data = {
                            "provider": "AI",
                            "model": "Stellar Intelligence",
                            "analysis_timestamp": "Archived",
                            "content": md_text,
                        }
                    except Exception as e:
                        logger.warning(f"Failed to read ai_analysis.md: {e}")

            if ai_data and ai_data.get("content"):
                try:
                    elements.append(Paragraph("2. Stellar Intelligence (AI Analysis Summary)", h2_style))
                    ai_meta = Paragraph(
                        f"<b>Provider:</b> {ai_data.get('provider', '').upper()} ({ai_data.get('model', '')}) | "
                        f"<b>Timestamp:</b> {ai_data.get('analysis_timestamp', '')}",
                        body_style,
                    )
                    t_ai = Table([[ai_meta]], colWidths=[540])
                    t_ai.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(CelestialPalette.STELLAR_BLUE)),
                        ("PADDING", (0, 0), (-1, -1), 6),
                    ]))
                    elements.append(t_ai)
                    elements.append(Spacer(1, 6))

                    raw_content = ai_data.get("content", "")
                    for line in raw_content.splitlines():
                        s_line = line.strip()
                        if not s_line:
                            continue
                        if s_line.startswith("### "):
                            h_text = html.escape(s_line[4:])
                            elements.append(Paragraph(f"<b>{h_text}</b>", h3_style))
                            elements.append(Spacer(1, 2))
                        elif s_line.startswith("* ") or s_line.startswith("- "):
                            b_text = html.escape(s_line[2:])
                            b_text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", b_text)
                            elements.append(Paragraph(f"&bull; {b_text}", bullet_style))
                        else:
                            p_text = html.escape(s_line)
                            p_text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", p_text)
                            elements.append(Paragraph(p_text, body_style))
                            elements.append(Spacer(1, 3))
                    elements.append(Spacer(1, 10))
                except Exception as e:
                    logger.warning(f"Failed to render AI section in PDF: {e}")

        # Section 3: Evidence Vault Directory Structure
        evidence_tree = build_evidence_tree(self.case_dir)
        elements.append(Paragraph("3. Evidence Vault & Directory Tree Structure", h2_style))
        tree_lines = evidence_tree.get("ascii_tree", [])
        if tree_lines:
            tree_text = "<br/>".join(html.escape(line) for line in tree_lines[:35])
            if len(tree_lines) > 35:
                tree_text += f"<br/><i>... and {len(tree_lines) - 35} additional directory nodes</i>"
            elements.append(Paragraph(tree_text, code_style))
        else:
            elements.append(Paragraph("No evidence files recorded in directory tree.", body_style))
        elements.append(Spacer(1, 10))

        # Section 4: Polaris-Generated Evidence Files & Content Previews
        created_files = get_polaris_created_evidence_files(self.case_dir)
        elements.append(Paragraph("4. Polaris-Generated Evidence Files & Content Previews", h2_style))
        if created_files:
            file_data = [["Category", "Filename", "Records", "Size", "Content Preview"]]
            for item in created_files[:14]:
                sample_preview = ""
                if item.get("sample_records") and isinstance(item["sample_records"], list) and len(item["sample_records"]) > 0:
                    first_r = item["sample_records"][0]
                    sample_preview = ", ".join(f"{k}: {str(v)[:20]}" for k, v in list(first_r.items())[:3])
                elif item.get("sample_text"):
                    sample_preview = item["sample_text"].replace("\n", " ")[:60]

                file_data.append([
                    item.get("category", "General"),
                    Paragraph(f"<b>{item.get('filename', '')}</b>", body_style),
                    str(item.get("record_count", "")),
                    item.get("size_formatted", ""),
                    Paragraph(html.escape(sample_preview[:80]), code_style),
                ])
            t_files = Table(file_data, colWidths=[65, 120, 45, 50, 260])
            t_files.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(CelestialPalette.MIDNIGHT_NAVY)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_files)
        else:
            elements.append(Paragraph("No extracted evidence files available for preview.", body_style))
        elements.append(Spacer(1, 10))

        # Section 5: Acquisition summary
        evidence_mgr = EvidenceManager(self.case_dir)
        evidence_mgr.load_results()
        summary = evidence_mgr.get_summary()

        elements.append(Paragraph("5. Celestial Collector Telemetry", h2_style))
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
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_acq)
        elements.append(Spacer(1, 10))

        # Section 6: Manifest Sample
        manifest_mgr = ManifestManager(self.case_dir)
        manifest_entries = manifest_mgr.load_manifest()

        elements.append(Paragraph("6. Evidence Vault - Cryptographic Manifest (Sample)", h2_style))
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
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_man)
        elements.append(Spacer(1, 10))

        # Section 7: Verification Status
        verification = manifest_mgr.verify()
        elements.append(Paragraph("7. Evidence Cryptographic Verification Status", h2_style))
        ver_data = [
            ["Status", "Observation"],
            ["Confirmed Unmodified", f"{len(verification.get('verified', []))} files verified"],
            ["Discrepancies / Modified", f"{len(verification.get('modified', []))} files flagged"],
            ["Missing Evidence Files", f"{len(verification.get('missing', []))} files missing"],
        ]
        t_ver = Table(ver_data, colWidths=[160, 360])
        t_ver.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(CelestialPalette.MIDNIGHT_NAVY)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_ver)

        doc.build(elements)
        return out_path
