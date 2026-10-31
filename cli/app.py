import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from config.theme import CelestialPalette
from config.settings import (
    TOOL_NAME,
    TOOL_VERSION,
    TOOL_TAGLINE,
    CollectionProfile,
    DEFAULT_OUTPUT_DIR,
    LIVE_ACQUISITION_WARNING,
    get_timestamp,
)
from config.ai_settings import load_ai_settings, save_ai_settings, AIProviderType
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
from cli.settings_manager import display_settings, update_settings
from analysis.rules import RulesEngine
from analysis.correlation import CorrelationEngine
from analysis.investigator_notes import InvestigatorNotesManager
from ai.analyzer import StellarIntelligenceAnalyzer
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
        console.print(f"[{CelestialPalette.MUTED_BLUE}]Use [bold {CelestialPalette.AURORA_CYAN}]polaris --help[/] to view celestial navigation commands.[/]\n")


@app.command(name="dashboard", help="[01] Display Mission Control dashboard, telemetry, and case status.")
def cmd_dashboard(
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Cases base directory path"),
    case: Optional[str] = typer.Option(None, "--case", "-c", help="Focus telemetry on specific Case ID"),
):
    print_banner()
    show_dashboard(output, case_id=case)


@app.command(name="settings", help="[09] View or configure AI providers, models, and investigation settings.")
def cmd_settings(
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="Set AI provider (openai, anthropic, gemini, offline)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Set custom model name"),
    enable: Optional[bool] = typer.Option(None, "--enable/--disable", help="Enable or disable AI analysis"),
):
    print_banner()
    if provider or model or (enable is not None):
        update_settings(provider=provider, model=model, enable=enable)
    else:
        display_settings()


@app.command(name="collect", help="[02] Acquire forensic artifacts according to the selected profile.")
def cmd_collect(
    profile: CollectionProfile = typer.Option(CollectionProfile.FULL, "--profile", "-p", help="Acquisition profile"),
    case_id: Optional[str] = typer.Option(None, "--case-id", "-c", help="Unique identifier for the investigation"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory for case storage"),
    examiner: str = typer.Option("", "--examiner", "-e", help="Name or badge ID of the forensic examiner"),
    description: str = typer.Option("", "--description", "-d", help="Description of the case"),
    no_parse: bool = typer.Option(False, "--no-parse", help="Acquire raw evidence only, skip parsing"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI post-analysis stage"),
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

    console.print(f"[bold {CelestialPalette.SUCCESS_GREEN}]Mission Initialized:[/] [bold {CelestialPalette.AURORA_CYAN}]{cid}[/] at {case_dir}")

    selected_modules = None
    if profile == CollectionProfile.CUSTOM:
        selected_modules = prompt_custom_modules()
        console.print(f"[{CelestialPalette.AURORA_CYAN}]Selected {len(selected_modules)} modules for custom acquisition.[/]")

    engine = AcquisitionEngine(
        case_dir=case_dir,
        profile=profile,
        parse=not no_parse,
        selected_modules=selected_modules,
    )

    with console.status(f"[bold {CelestialPalette.AURORA_CYAN}]Executing Celestial Collector...[/]"):
        evidence_mgr = engine.run()

    metadata.status = "acquired"
    metadata.total_artifacts = sum(r.artifact_count for r in evidence_mgr.results)
    case_mgr.update_metadata(case_dir, metadata)

    summary = evidence_mgr.get_summary()
    display_collection_summary(summary)


@app.command(name="analyze", help="[03] Execute Observatory deterministic rules and cross-artifact correlation.")
def cmd_analyze(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier to analyze"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
):
    print_banner()
    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold {CelestialPalette.CRITICAL_RED}]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    console.print(f"[bold {CelestialPalette.AURORA_CYAN}]Running Observatory DFIR Analysis on:[/] {case}")
    rules_engine = RulesEngine(case_dir)
    findings = rules_engine.run_all_rules()

    correlation_engine = CorrelationEngine(case_dir)
    correlations = correlation_engine.correlate()

    all_findings = findings + correlations

    # Save aggregated findings
    notes_mgr = InvestigatorNotesManager(case_dir)
    notes_mgr.save_findings(all_findings)

    table = Table(title=f"Observatory Findings for {case}", header_style=f"bold {CelestialPalette.STELLAR_BLUE}", border_style=CelestialPalette.AURORA_CYAN)
    table.add_column("Severity", style="bold")
    table.add_column("Grounding", style=CelestialPalette.MUTED_BLUE)
    table.add_column("Category", style=CelestialPalette.AURORA_CYAN)
    table.add_column("Rule / Title", style=f"bold {CelestialPalette.STARLIGHT_WHITE}")

    for f in all_findings:
        sev_color = CelestialPalette.CRITICAL_RED if f.severity in ["high", "critical"] else CelestialPalette.WARNING_AMBER
        table.add_row(
            f"[{sev_color}]{f.severity.value if hasattr(f.severity, 'value') else f.severity}[/]",
            f.grounding.value if hasattr(f.grounding, 'value') else str(f.grounding),
            f.category,
            f.title,
        )

    console.print(table)
    console.print(f"\n[{CelestialPalette.SUCCESS_GREEN}]Analysis completed. Total findings: {len(all_findings)}[/]")


@app.command(name="findings", help="[03] Query and inspect explainable findings with confidence and validation steps.")
def cmd_findings(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity (critical, high, medium, low, info)"),
    category: Optional[str] = typer.Option(None, "--category", help="Filter by artifact category"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Cases base directory"),
):
    print_banner()
    case_dir = output / case
    notes_mgr = InvestigatorNotesManager(case_dir)
    filtered = notes_mgr.filter_findings(severity=severity, category=category)

    if not filtered:
        console.print(f"[{CelestialPalette.MUTED_BLUE}]No findings match the specified criteria for {case}.[/]")
        return

    for idx, f in enumerate(filtered, 1):
        sev_color = CelestialPalette.CRITICAL_RED if f.severity in ["high", "critical"] else CelestialPalette.WARNING_AMBER
        header = f"[{sev_color}][{f.severity.upper()}][/] [{CelestialPalette.AURORA_CYAN}][{f.grounding}][/] {f.title} ({f.finding_id})"
        details = (
            f"• [bold]Category:[/] {f.category}  |  [bold]Rule:[/] {f.rule_id} ({f.rule_name})\n"
            f"• [bold]Observed Facts:[/] {f.observed_facts or f.description}\n"
            f"• [bold]Analytical Context:[/] {f.analytical_interpretation or 'Behavior matches defined rule'}\n"
            f"• [bold]Why it matters:[/] {f.why_it_matters or 'Indicates potential security or operational anomaly.'}\n"
            f"• [bold]Recommended Validation:[/] {', '.join(f.recommendations) if f.recommendations else 'Examine source artifact'}\n"
            f"• [bold]Status:[/] {f.status.value}"
        )
        console.print(f"\n[bold]{idx}. {header}[/]")
        console.print(details)


@app.command(name="ai", help="[05] Execute Stellar Intelligence grounded forensic analysis.")
def cmd_ai(
    case: Optional[str] = typer.Option(None, "--case", "-c", help="Case identifier to analyze"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="AI provider (openai, anthropic, gemini, offline)"),
    offline: bool = typer.Option(False, "--offline", help="Force offline deterministic analysis mode"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
):
    print_banner()
    settings = load_ai_settings()
    if provider:
        try:
            settings.provider = AIProviderType(provider.lower())
        except ValueError:
            console.print(f"[{CelestialPalette.CRITICAL_RED}]Invalid provider: {provider}[/]")
            raise typer.Exit(1)

    if offline:
        settings.provider = AIProviderType.OFFLINE

    if not case:
        # If no case provided, simply display configured AI status
        display_settings()
        return

    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold {CelestialPalette.CRITICAL_RED}]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    console.print(f"[bold {CelestialPalette.AURORA_CYAN}]Executing Stellar Intelligence on:[/] {case} ([italic]{settings.provider.value.upper()}[/])")
    analyzer = StellarIntelligenceAnalyzer(case_dir, settings)
    result = analyzer.run_analysis(offline_override=offline)

    if result.get("is_error"):
        console.print(f"[bold {CelestialPalette.CRITICAL_RED}]AI Analysis Error:[/] {result.get('error_message')}")
    else:
        console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Stellar Intelligence analysis completed successfully![/]")
        console.print(f"Report: [underline]{case_dir / 'metadata' / 'ai_analysis.md'}[/underline]")


@app.command(name="timeline", help="[04] Synthesize Constellation unified forensic timeline.")
def cmd_timeline(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
):
    print_banner()
    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold {CelestialPalette.CRITICAL_RED}]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    builder = TimelineBuilder(case_dir)
    builder.build_from_parsed()
    csv_path = builder.write_timeline()

    console.print(f"[bold {CelestialPalette.SUCCESS_GREEN}]Constellation timeline generated successfully![/]")
    console.print(f"Total Chronological Events: [{CelestialPalette.AURORA_CYAN}]{len(builder.events)}[/]")
    console.print(f"CSV Export: [underline]{csv_path}[/underline]")


@app.command(name="verify", help="[06] Evidence Vault: verify cryptographic SHA-256 evidence integrity.")
def cmd_verify(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
):
    print_banner()
    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold {CelestialPalette.CRITICAL_RED}]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    manifest_mgr = ManifestManager(case_dir)
    entries = manifest_mgr.load_manifest()
    if not entries:
        console.print(f"[bold {CelestialPalette.WARNING_AMBER}]Notice:[/] No manifest entries found in {case_dir / 'manifests'}.")
        raise typer.Exit(1)

    report = manifest_mgr.verify()
    rep_file = manifest_mgr.write_verification_report(report)
    display_verification_results(report)
    console.print(f"Detailed verification report: [underline]{rep_file}[/underline]")


@app.command(name="report", help="[07] Generate Northstar forensic report (HTML & PDF).")
def cmd_report(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    include_ai: bool = typer.Option(True, "--include-ai", help="Include AI intelligence section if available"),
    without_ai: bool = typer.Option(False, "--without-ai", help="Exclude AI intelligence section"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
):
    print_banner()
    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold {CelestialPalette.CRITICAL_RED}]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    should_include_ai = include_ai and not without_ai

    console.print(f"[bold {CelestialPalette.AURORA_CYAN}]Generating Northstar reports for {case}...[/]")
    html_gen = HtmlReportGenerator(case_dir)
    html_path = html_gen.generate(include_ai=should_include_ai)
    console.print(f"[{CelestialPalette.SUCCESS_GREEN}]HTML Report generated:[/] {html_path}")

    pdf_gen = PdfReportGenerator(case_dir)
    pdf_path = pdf_gen.generate(include_ai=should_include_ai)
    console.print(f"[{CelestialPalette.SUCCESS_GREEN}]PDF Report generated:[/] {pdf_path}")


@app.command(name="package", help="[08] Mission Archive: build sealed evidence ZIP container.")
def cmd_package(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
):
    print_banner()
    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold {CelestialPalette.CRITICAL_RED}]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    builder = ZipBuilder(case_dir)
    zip_path, zip_hash = builder.build_package()

    console.print(f"[bold {CelestialPalette.SUCCESS_GREEN}]Mission Archive Sealed Successfully![/]")
    console.print(f"Container: [{CelestialPalette.AURORA_CYAN}]{zip_path}[/]")
    console.print(f"SHA-256 Seal: [bold {CelestialPalette.WARNING_AMBER}]{zip_hash}[/]")


@app.command(name="all", help="Execute complete automated pipeline: acquisition, observatory, constellation, verify, intelligence, report, archive.")
def cmd_all(
    profile: CollectionProfile = typer.Option(CollectionProfile.FULL, "--profile", "-p", help="Acquisition profile"),
    case_id: Optional[str] = typer.Option(None, "--case-id", "-c", help="Case identifier"),
    provider: Optional[str] = typer.Option(None, "--provider", help="AI provider for analysis stage"),
    offline: bool = typer.Option(False, "--offline", help="Run AI in offline deterministic mode"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory"),
    examiner: str = typer.Option("", "--examiner", "-e", help="Examiner name"),
    description: str = typer.Option("", "--description", "-d", help="Case description"),
    no_parse: bool = typer.Option(False, "--no-parse", help="Skip parsing"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI intelligence stage"),
):
    print_banner()
    print_warning()

    cid = case_id or f"CASE-{get_timestamp()}"
    console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== STAGE 1: Celestial Collector (Acquisition) ===[/]")
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

    console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== STAGE 2: Observatory (Heuristics & Correlation) ===[/]")
    try:
        rules_engine = RulesEngine(case_dir)
        findings = rules_engine.run_all_rules()
        correlator = CorrelationEngine(case_dir)
        correlations = correlator.correlate()
        all_findings = findings + correlations
        InvestigatorNotesManager(case_dir).save_findings(all_findings)
        console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Observatory analysis complete: {len(all_findings)} findings identified.[/]")
    except Exception as e:
        console.print(f"[{CelestialPalette.WARNING_AMBER}]Observatory warning:[/] {e}")

    console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== STAGE 3: Constellation (Timeline Synthesis) ===[/]")
    try:
        t_builder = TimelineBuilder(case_dir)
        t_builder.build_from_parsed()
        t_builder.write_timeline()
        console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Timeline complete: {len(t_builder.events)} events recorded.[/]")
    except Exception as e:
        console.print(f"[{CelestialPalette.WARNING_AMBER}]Timeline warning:[/] {e}")

    console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== STAGE 4: Evidence Vault (Cryptographic Verification) ===[/]")
    try:
        manifest_mgr = ManifestManager(case_dir)
        manifest_mgr.load_manifest()
        v_rep = manifest_mgr.verify()
        manifest_mgr.write_verification_report(v_rep)
        display_verification_results(v_rep)
    except Exception as e:
        console.print(f"[{CelestialPalette.WARNING_AMBER}]Verification warning:[/] {e}")

    if not no_ai:
        console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== STAGE 5: Stellar Intelligence (AI Analysis) ===[/]")
        try:
            settings = load_ai_settings()
            if provider:
                settings.provider = AIProviderType(provider.lower())
            if offline:
                settings.provider = AIProviderType.OFFLINE
            analyzer = StellarIntelligenceAnalyzer(case_dir, settings)
            ai_res = analyzer.run_analysis(offline_override=offline)
            if not ai_res.get("is_error"):
                console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Stellar Intelligence synthesis complete ({settings.provider.value.upper()}).[/]")
            else:
                console.print(f"[{CelestialPalette.WARNING_AMBER}]AI note:[/] {ai_res.get('error_message')}")
        except Exception as e:
            console.print(f"[{CelestialPalette.WARNING_AMBER}]AI warning:[/] {e}")

    console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== STAGE 6: Northstar Report Generation ===[/]")
    try:
        h_rep = HtmlReportGenerator(case_dir).generate(include_ai=not no_ai)
        p_rep = PdfReportGenerator(case_dir).generate(include_ai=not no_ai)
        console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Reports generated:[/] {h_rep.name}, {p_rep.name}")
    except Exception as e:
        console.print(f"[{CelestialPalette.WARNING_AMBER}]Reporting warning:[/] {e}")

    console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== STAGE 7: Mission Archive Packaging ===[/]")
    try:
        z_path, z_hash = ZipBuilder(case_dir).build_package()
        console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Sealed package:[/] {z_path}")
        console.print(f"[bold {CelestialPalette.WARNING_AMBER}]SHA-256:[/] {z_hash}")
    except Exception as e:
        console.print(f"[{CelestialPalette.WARNING_AMBER}]Packaging warning:[/] {e}")

    console.print(f"\n[bold {CelestialPalette.SUCCESS_GREEN}]* Full Polaris Mission Completed for {cid} *[/]\n")
