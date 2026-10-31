from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config.settings import TOOL_NAME, TOOL_VERSION, TOOL_TAGLINE, DEFAULT_OUTPUT_DIR
from core.permissions import is_admin, get_windows_version
from core.case_manager import CaseManager
from core.engine import get_registered_collectors, _import_all_collectors

console = Console()


def show_dashboard(base_dir: Path = DEFAULT_OUTPUT_DIR) -> None:
    _import_all_collectors()
    registered = get_registered_collectors()
    case_mgr = CaseManager(base_dir)
    cases = case_mgr.list_cases()

    admin_status = "[green]Elevated (Administrator)[/]" if is_admin() else "[yellow]Standard User (Some artifacts restricted)[/]"

    overview = (
        f"[bold cyan]{TOOL_NAME} Digital Forensics Engine[/bold cyan] (v{TOOL_VERSION})\n"
        f"[italic]{TOOL_TAGLINE}[/italic]\n\n"
        f"- [bold]Host OS:[/] {get_windows_version()}\n"
        f"- [bold]Privilege:[/] {admin_status}\n"
        f"- [bold]Registered Collectors:[/] {len(registered)} modules\n"
        f"- [bold]Active Cases Found:[/] {len(cases)} in [underline]{base_dir}[/underline]"
    )

    console.print(Panel(overview, title=f"* {TOOL_NAME} Forensic Console", border_style="cyan"))

    if cases:
        table = Table(title="Existing Cases", header_style="bold blue")
        table.add_column("Case ID", style="bold green")
        table.add_column("Created", style="white")
        table.add_column("Examiner", style="cyan")
        table.add_column("Profile", style="yellow")

        for cid in cases:
            meta = case_mgr.load_metadata(base_dir / cid)
            if meta:
                table.add_row(meta.case_id, meta.created_at[:19], meta.examiner or "N/A", meta.profile or "N/A")
            else:
                table.add_row(cid, "Unknown", "Unknown", "Unknown")

        console.print(table)
    else:
        console.print("[dim]No cases recorded yet. Run 'polaris collect --profile quick' to begin.[/dim]")
