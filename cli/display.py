from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from config.settings import TOOL_NAME, TOOL_VERSION, TOOL_TAGLINE, LIVE_ACQUISITION_WARNING

console = Console()


def print_banner() -> None:
    banner_text = Text()
    banner_text.append(f"* {TOOL_NAME} ", style="bold cyan")
    banner_text.append(f"v{TOOL_VERSION}\n", style="bold white")
    banner_text.append(f'"{TOOL_TAGLINE}"\n', style="italic bright_black")
    console.print(Panel(banner_text, border_style="cyan"))


def print_warning(text: str = LIVE_ACQUISITION_WARNING) -> None:
    console.print(Panel(f"[bold yellow]WARNING:[/] {text}", border_style="yellow"))


def display_collection_summary(summary: dict) -> None:
    table = Table(title="Acquisition Summary", header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total Modules Run", str(summary.get("total_modules", 0)))
    table.add_row("Total Files Acquired", str(summary.get("total_files", 0)))

    status_counts = summary.get("status_counts", {})
    for status, count in status_counts.items():
        style = "green" if status == "SUCCESS" else ("yellow" if status == "PARTIAL" else "red")
        table.add_row(f"Status: {status}", f"[{style}]{count}[/{style}]")

    console.print(table)


def display_verification_results(report: dict) -> None:
    table = Table(title="Evidence Verification Report", header_style="bold blue")
    table.add_column("Status", style="bold")
    table.add_column("Count", style="cyan")

    table.add_row("[green]VERIFIED (Unmodified)[/]", str(len(report.get("verified", []))))
    table.add_row("[red]MODIFIED (Hash mismatch)[/]", str(len(report.get("modified", []))))
    table.add_row("[yellow]MISSING (Not found)[/]", str(len(report.get("missing", []))))
    table.add_row("[magenta]UNEXPECTED (Untracked)[/]", str(len(report.get("unexpected", []))))

    console.print(table)
