import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from config.settings import (
    TOOL_NAME,
    TOOL_VERSION,
    TOOL_TAGLINE,
    CollectionProfile,
    DEFAULT_OUTPUT_DIR,
    LIVE_ACQUISITION_WARNING,
    get_timestamp,
)
from core.case_manager import CaseManager
from core.engine import AcquisitionEngine
from core.manifest import ManifestManager
from core.timeline import TimelineBuilder
from cli.display import (
    print_banner,
    print_warning,
    display_collection_summary,
    display_verification_results,
)
from cli.dashboard import show_dashboard
from cli.interactive import prompt_custom_modules
from analysis.rules import RulesEngine
from analysis.correlation import CorrelationEngine
from reports.html_report import HtmlReportGenerator
from reports.pdf_report import PdfReportGenerator
from packaging.zip_builder import ZipBuilder

app = typer.Typer(
    name="polaris",
    help=f"{TOOL_NAME} — {TOOL_TAGLINE}",
    add_completion=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("[dim]Use [bold]polaris --help[/bold] to see available commands.[/dim]\n")


@app.command(name="dashboard", help="Display Polaris system status and recorded cases.")
def cmd_dashboard(
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Cases directory path"),
):
    print_banner()
    show_dashboard(output)


@app.command(name="collect", help="Acquire forensic artifacts according to the selected profile.")
def cmd_collect(
    profile: CollectionProfile = typer.Option(CollectionProfile.FULL, "--profile", "-p", help="Acquisition profile"),
    case_id: Optional[str] = typer.Option(None, "--case-id", "-c", help="Unique identifier for the investigation"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory for case storage"),
    examiner: str = typer.Option("", "--examiner", "-e", help="Name or badge ID of the forensic examiner"),
    description: str = typer.Option("", "--description", "-d", help="Description of the case"),
    no_parse: bool = typer.Option(False, "--no-parse", help="Acquire raw evidence only, skip parsing"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI components (Part 2 preview)"),
):
    print_banner()
    print_warning()

    cid = case_id or f"CASE-{get_timestamp()}"
    case_mgr = CaseManager(output)
    case_dir, metadata = case_mgr.create_case(
        case_id=cid,
        profile=profile.value,
        examiner=examiner,
        description=description,
    )

    console.print(f"[bold green]Case initialized:[/] [cyan]{cid}[/] at {case_dir}")

    selected_modules = None
    if profile == CollectionProfile.CUSTOM:
        selected_modules = prompt_custom_modules()
        console.print(f"[cyan]Selected {len(selected_modules)} modules for custom acquisition.[/cyan]")

    engine = AcquisitionEngine(
        case_dir=case_dir,
        profile=profile,
        parse=not no_parse,
        selected_modules=selected_modules,
    )

    with console.status("[bold green]Executing forensic acquisition...[/bold green]"):
        evidence_mgr = engine.run()

    metadata.status = "acquired"
    metadata.total_artifacts = sum(r.artifact_count for r in evidence_mgr.results)
    case_mgr.update_metadata(case_dir, metadata)

    summary = evidence_mgr.get_summary()
    display_collection_summary(summary)


@app.command(name="analyze", help="Execute automated heuristic rules and cross-artifact correlation.")
def cmd_analyze(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier to analyze"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
):
    print_banner()
    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold red]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    console.print(f"[bold cyan]Running automated DFIR analysis on case:[/] {case}")
    rules_engine = RulesEngine(case_dir)
    findings = rules_engine.run_all_rules()

    correlation_engine = CorrelationEngine(case_dir)
    correlations = correlation_engine.correlate()

    all_findings = findings + correlations

    table = Table(title=f"Analysis Findings for {case}", header_style="bold magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Rule", style="yellow")
    table.add_column("Title", style="white")

    for f in all_findings:
        sev_color = "red" if f.severity == "high" or f.severity == "critical" else "yellow"
        table.add_row(f"[{sev_color}]{f.severity.value if hasattr(f.severity, 'value') else f.severity}[/{sev_color}]", f.category, f.rule_name, f.title)

    console.print(table)
    console.print(f"\n[green]Analysis completed. Total findings: {len(all_findings)}[/green]")


@app.command(name="timeline", help="Synthesize and export a unified forensic timeline from parsed evidence.")
def cmd_timeline(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
):
    print_banner()
    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold red]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    builder = TimelineBuilder(case_dir)
    builder.build_from_parsed()
    csv_path = builder.write_timeline()

    console.print(f"[bold green]Forensic timeline generated successfully![/bold green]")
    console.print(f"Total Events: [cyan]{len(builder.events)}[/cyan]")
    console.print(f"CSV Export: [underline]{csv_path}[/underline]")


@app.command(name="verify", help="Cryptographically verify all acquired evidence against the SHA-256 manifest.")
def cmd_verify(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
):
    print_banner()
    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold red]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    manifest_mgr = ManifestManager(case_dir)
    entries = manifest_mgr.load_manifest()
    if not entries:
        console.print(f"[bold yellow]Notice:[/] No manifest entries found in {case_dir / 'manifests'}.")
        raise typer.Exit(1)

    report = manifest_mgr.verify()
    rep_file = manifest_mgr.write_verification_report(report)
    display_verification_results(report)
    console.print(f"Detailed verification report: [underline]{rep_file}[/underline]")


@app.command(name="report", help="Generate functional HTML and PDF forensic reports.")
def cmd_report(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
):
    print_banner()
    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold red]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    console.print(f"[bold cyan]Generating reports for {case}...[/bold cyan]")
    html_gen = HtmlReportGenerator(case_dir)
    html_path = html_gen.generate()
    console.print(f"[green]HTML Report generated:[/] {html_path}")

    pdf_gen = PdfReportGenerator(case_dir)
    pdf_path = pdf_gen.generate()
    console.print(f"[green]PDF Report generated:[/] {pdf_path}")


@app.command(name="package", help="Create a sealed forensic ZIP package with SHA-256 hash.")
def cmd_package(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
):
    print_banner()
    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold red]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    builder = ZipBuilder(case_dir)
    zip_path, zip_hash = builder.build_package()

    console.print(f"[bold green]Evidence Package Created Successfully![/bold green]")
    console.print(f"Archive: [cyan]{zip_path}[/cyan]")
    console.print(f"SHA-256: [bold yellow]{zip_hash}[/bold yellow]")


@app.command(name="all", help="Execute complete automated pipeline: acquisition, parsing, analysis, timeline, verify, report, package.")
def cmd_all(
    profile: CollectionProfile = typer.Option(CollectionProfile.FULL, "--profile", "-p", help="Acquisition profile"),
    case_id: Optional[str] = typer.Option(None, "--case-id", "-c", help="Case identifier"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory"),
    examiner: str = typer.Option("", "--examiner", "-e", help="Examiner name"),
    description: str = typer.Option("", "--description", "-d", help="Case description"),
    no_parse: bool = typer.Option(False, "--no-parse", help="Skip parsing"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI"),
):
    print_banner()
    print_warning()

    cid = case_id or f"CASE-{get_timestamp()}"
    console.print(f"\n[bold magenta]=== STAGE 1: Forensic Acquisition ===[/bold magenta]")
    case_mgr = CaseManager(output)
    case_dir, metadata = case_mgr.create_case(
        case_id=cid,
        profile=profile.value,
        examiner=examiner,
        description=description,
    )
    engine = AcquisitionEngine(case_dir=case_dir, profile=profile, parse=not no_parse)
    evidence_mgr = engine.run()
    summary = evidence_mgr.get_summary()
    display_collection_summary(summary)

    console.print(f"\n[bold magenta]=== STAGE 2: Automated Analysis & Rules ===[/bold magenta]")
    try:
        rules_engine = RulesEngine(case_dir)
        findings = rules_engine.run_all_rules()
        correlator = CorrelationEngine(case_dir)
        correlations = correlator.correlate()
        console.print(f"[green]Analysis complete: {len(findings)} findings, {len(correlations)} correlations.[/green]")
    except Exception as e:
        console.print(f"[yellow]Analysis warning:[/] {e}")

    console.print(f"\n[bold magenta]=== STAGE 3: Unified Timeline Synthesis ===[/bold magenta]")
    try:
        t_builder = TimelineBuilder(case_dir)
        t_builder.build_from_parsed()
        t_builder.write_timeline()
        console.print(f"[green]Timeline complete: {len(t_builder.events)} events recorded.[/green]")
    except Exception as e:
        console.print(f"[yellow]Timeline warning:[/] {e}")

    console.print(f"\n[bold magenta]=== STAGE 4: Cryptographic Verification ===[/bold magenta]")
    try:
        manifest_mgr = ManifestManager(case_dir)
        manifest_mgr.load_manifest()
        v_rep = manifest_mgr.verify()
        manifest_mgr.write_verification_report(v_rep)
        display_verification_results(v_rep)
    except Exception as e:
        console.print(f"[yellow]Verification warning:[/] {e}")

    console.print(f"\n[bold magenta]=== STAGE 5: Reporting ===[/bold magenta]")
    try:
        h_rep = HtmlReportGenerator(case_dir).generate()
        p_rep = PdfReportGenerator(case_dir).generate()
        console.print(f"[green]Reports generated:[/] {h_rep.name}, {p_rep.name}")
    except Exception as e:
        console.print(f"[yellow]Reporting warning:[/] {e}")

    console.print(f"\n[bold magenta]=== STAGE 6: Packaging & Sealing ===[/bold magenta]")
    try:
        z_path, z_hash = ZipBuilder(case_dir).build_package()
        console.print(f"[green]Sealed package:[/] {z_path}")
        console.print(f"[bold yellow]SHA-256:[/] {z_hash}")
    except Exception as e:
        console.print(f"[yellow]Packaging warning:[/] {e}")

    console.print(f"\n[bold green]* Full Polaris workflow completed for {cid} *[/bold green]\n")
