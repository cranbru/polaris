from rich.console import Console
from rich.table import Table

from config.artifact_catalog import ARTIFACT_CATALOG

console = Console()


def prompt_custom_modules() -> list[str]:
    console.print("\n[bold cyan]Available Forensic Modules:[/bold cyan]\n")

    table = Table(header_style="bold magenta")
    table.add_column("No.", style="cyan", width=4)
    table.add_column("Module ID", style="bold green")
    table.add_column("Artifact Name", style="white")
    table.add_column("Category", style="yellow")
    table.add_column("Privileges", style="red")

    module_list = list(ARTIFACT_CATALOG.keys())
    for idx, mid in enumerate(module_list, 1):
        info = ARTIFACT_CATALOG[mid]
        table.add_row(
            str(idx),
            mid,
            info["name"],
            info["category"].value if hasattr(info["category"], "value") else str(info["category"]),
            info["privileges"],
        )

    console.print(table)
    console.print("\nEnter comma-separated numbers or Module IDs to collect (or 'all' for all):")
    selection = input("> ").strip()

    if not selection or selection.lower() == "all":
        return module_list

    selected_ids = []
    tokens = [t.strip() for t in selection.split(",") if t.strip()]
    for token in tokens:
        if token.isdigit():
            idx = int(token) - 1
            if 0 <= idx < len(module_list):
                selected_ids.append(module_list[idx])
        elif token in ARTIFACT_CATALOG:
            selected_ids.append(token)

    return list(dict.fromkeys(selected_ids))
