from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from config.theme import CelestialPalette
from config.settings import TOOL_NAME, TOOL_VERSION, TOOL_TAGLINE, LIVE_ACQUISITION_WARNING
from cli.celestial_banner import render_banner

console = Console()


def print_banner(animated: bool = False) -> None:
    render_banner(animated=animated)


def print_warning(text: str = LIVE_ACQUISITION_WARNING) -> None:
    console.print(Panel(
        f"[bold {CelestialPalette.WARNING_AMBER}]CELESTIAL FORENSIC NOTICE:[/] {text}",
        border_style=CelestialPalette.WARNING_AMBER,
    ))


def display_collection_summary(summary: dict) -> None:
    table = Table(
        title="Celestial Collector - Mission Acquisition Summary",
        header_style=f"bold {CelestialPalette.AURORA_CYAN}",
        border_style=CelestialPalette.STELLAR_BLUE,
    )
    table.add_column("Metric", style=CelestialPalette.AURORA_CYAN)
    table.add_column("Value", style=f"bold {CelestialPalette.STARLIGHT_WHITE}")

    table.add_row("Total Modules Run", str(summary.get("total_modules", 0)))
    table.add_row("Total Files Acquired", str(summary.get("total_files", 0)))

    status_counts = summary.get("status_counts", {})
    for status, count in status_counts.items():
        if status == "SUCCESS":
            color = CelestialPalette.SUCCESS_GREEN
        elif status == "PARTIAL":
            color = CelestialPalette.WARNING_AMBER
        else:
            color = CelestialPalette.CRITICAL_RED
        table.add_row(f"Status: {status}", f"[{color}]{count}[/{color}]")

    console.print(table)


def display_verification_results(report: dict) -> None:
    table = Table(
        title="Evidence Vault - Integrity Verification Report",
        header_style=f"bold {CelestialPalette.STELLAR_BLUE}",
        border_style=CelestialPalette.AURORA_CYAN,
    )
    table.add_column("Integrity Status", style="bold")
    table.add_column("Count", style=CelestialPalette.AURORA_CYAN)

    table.add_row(f"[{CelestialPalette.SUCCESS_GREEN}]VERIFIED (Cryptographically Sealed)[/]", str(len(report.get("verified", []))))
    table.add_row(f"[{CelestialPalette.CRITICAL_RED}]MODIFIED (Hash Discrepancy)[/]", str(len(report.get("modified", []))))
    table.add_row(f"[{CelestialPalette.WARNING_AMBER}]MISSING (Evidence Absent)[/]", str(len(report.get("missing", []))))
    table.add_row(f"[{CelestialPalette.NEBULA_VIOLET}]UNEXPECTED (Untracked Files)[/]", str(len(report.get("unexpected", []))))

    console.print(table)
