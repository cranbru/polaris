import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.text import Text

from config.theme import CelestialPalette, CELESTIAL_NAMES
from config.settings import TOOL_NAME, TOOL_VERSION, DEFAULT_OUTPUT_DIR
from core.permissions import is_admin, get_windows_version
from core.case_manager import CaseManager
from core.engine import get_registered_collectors, _import_all_collectors
from core.evidence_manager import EvidenceManager
from core.manifest import ManifestManager

console = Console()

SECTIONS = [
    ("[01] MISSION CONTROL", "Core Mission Overview and Telemetry"),
    ("[02] CELESTIAL COLLECTOR", "Forensic Artifact Acquisition Engine"),
    ("[03] OBSERVATORY", "Artifact Parsing, Heuristic Rules & Correlation"),
    ("[04] CONSTELLATION", "Unified Chronological Forensic Timeline"),
    ("[05] STELLAR INTELLIGENCE", "Evidence-Grounded AI Analysis Engine"),
    ("[06] EVIDENCE VAULT", "Cryptographic SHA-256 Seal & Verification"),
    ("[07] NORTHSTAR REPORT", "Publication-Grade HTML & PDF Reports"),
    ("[08] MISSION ARCHIVE", "Containerized Evidence Preservation"),
    ("[09] SETTINGS", "Engine Configuration & AI Providers"),
]


def render_mission_control(base_dir: Path = DEFAULT_OUTPUT_DIR, active_case: str | None = None) -> None:
    _import_all_collectors()
    registered = get_registered_collectors()
    case_mgr = CaseManager(base_dir)
    cases = case_mgr.list_cases()

    # Section Grid
    nav_table = Table(
        title="Celestial Navigation Matrix",
        header_style=f"bold {CelestialPalette.AURORA_CYAN}",
        border_style=CelestialPalette.STELLAR_BLUE,
        show_header=False,
    )
    nav_table.add_column("Code", style=f"bold {CelestialPalette.AURORA_CYAN}", width=26)
    nav_table.add_column("Mission Role", style=CelestialPalette.MUTED_BLUE)

    for code, desc in SECTIONS:
        nav_table.add_row(code, desc)

    # Telemetry Panel
    admin_status = (
        f"[{CelestialPalette.SUCCESS_GREEN}]Elevated (Administrator)[/]"
        if is_admin()
        else f"[{CelestialPalette.WARNING_AMBER}]Standard User (Elevation Recommended)[/]"
    )

    telemetry = (
        f"[bold {CelestialPalette.STARLIGHT_WHITE}]POLARIS MISSION CONTROL[/] [dim]v{TOOL_VERSION}[/]\n\n"
        f"- [bold {CelestialPalette.AURORA_CYAN}]Operating System:[/] {get_windows_version()}\n"
        f"- [bold {CelestialPalette.AURORA_CYAN}]Security Context:[/] {admin_status}\n"
        f"- [bold {CelestialPalette.AURORA_CYAN}]Registered Collectors:[/] {len(registered)} modules operational\n"
        f"- [bold {CelestialPalette.AURORA_CYAN}]Mission Directory:[/] [underline]{base_dir.resolve()}[/underline]\n"
        f"- [bold {CelestialPalette.AURORA_CYAN}]Recorded Missions:[/] {len(cases)} case archives found"
    )

    console.print(Panel(
        telemetry,
        title=f"[{CelestialPalette.AURORA_CYAN}]* MISSION CONTROL TELEMETRY *[/]",
        border_style=CelestialPalette.STELLAR_BLUE,
    ))
    console.print(nav_table)

    # Active or Recent Case Telemetry
    target_case_id = active_case or (cases[0] if cases else None)
    if target_case_id:
        _render_case_telemetry(base_dir, target_case_id)
    else:
        console.print(f"\n[{CelestialPalette.MUTED_BLUE}]No active mission records found. Run [bold {CelestialPalette.AURORA_CYAN}]polaris collect --profile quick[/] to begin acquisition.[/]\n")


def _render_case_telemetry(base_dir: Path, case_id: str) -> None:
    case_dir = base_dir / case_id
    case_mgr = CaseManager(base_dir)
    meta = case_mgr.load_metadata(case_dir)

    ev_mgr = EvidenceManager(case_dir)
    ev_mgr.load_results()
    summary = ev_mgr.get_summary()

    man_mgr = ManifestManager(case_dir)
    manifest = man_mgr.load_manifest()

    # Check for findings
    findings_path = case_dir / "metadata" / "findings.json"
    findings_count = 0
    if findings_path.exists():
        try:
            with open(findings_path, "r", encoding="utf-8") as f:
                findings_count = len(json.load(f))
        except Exception:
            pass

    # Check AI analysis status
    ai_status_path = case_dir / "metadata" / "ai_analysis.json"
    ai_status = f"[{CelestialPalette.SUCCESS_GREEN}]COMPLETE[/]" if ai_status_path.exists() else f"[{CelestialPalette.MUTED_BLUE}]PENDING[/]"

    status_table = Table(
        title=f"Active Mission Telemetry: {case_id}",
        header_style=f"bold {CelestialPalette.STELLAR_BLUE}",
        border_style=CelestialPalette.AURORA_CYAN,
    )
    status_table.add_column("Parameter", style=CelestialPalette.AURORA_CYAN)
    status_table.add_column("Observation", style=f"bold {CelestialPalette.STARLIGHT_WHITE}")

    status_table.add_row("Case Identifier", meta.case_id if meta else case_id)
    status_table.add_row("Examiner / Officer", (meta.examiner if meta else "") or "N/A")
    status_table.add_row("Collection Profile", (meta.profile if meta else "") or "Standard")
    status_table.add_row("Total Files Acquired", str(summary.get("total_files", len(manifest))))
    status_table.add_row("Successful Collectors", str(summary.get("status_counts", {}).get("SUCCESS", 0)))
    status_table.add_row("Skipped / Inaccessible", str(summary.get("status_counts", {}).get("SKIPPED", 0)))
    status_table.add_row("Identified Findings", str(findings_count))
    status_table.add_row("Evidence Vault Status", f"[{CelestialPalette.SUCCESS_GREEN}]{len(manifest)} Files Hashed (SHA-256)[/]")
    status_table.add_row("Stellar Intelligence", ai_status)

    console.print(status_table)
