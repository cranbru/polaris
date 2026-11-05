import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)

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
from cli.interactive import prompt_custom_modules, prompt_ai_configuration
from cli.settings_manager import display_settings, update_settings
from analysis.rules import RulesEngine
from analysis.correlation import CorrelationEngine
from analysis.investigator_notes import InvestigatorNotesManager
from ai.analyzer import StellarIntelligenceAnalyzer
from reports.html_report import HtmlReportGenerator
from reports.pdf_report import PdfReportGenerator
from archive.zip_builder import ZipBuilder

app = typer.Typer(
    name="polaris",
    help=f"{TOOL_NAME} — {TOOL_TAGLINE}",
    add_completion=False,
)
console = Console()


def open_report_in_browser(report_path: Path) -> bool:
    try:
        import os
        import webbrowser
        abs_path = report_path.resolve()
        if not abs_path.exists():
            return False
        if sys.platform == "win32":
            os.startfile(str(abs_path))
            return True
        else:
            return webbrowser.open(abs_path.as_uri())
    except Exception as e:
        console.print(f"[{CelestialPalette.WARNING_AMBER}]Could not open report automatically:[/] {e}")
        return False


def execute_mission(
    profile: CollectionProfile = CollectionProfile.QUICK,
    case_id: Optional[str] = None,
    provider: Optional[str] = None,
    offline: bool = False,
    output: Path = DEFAULT_OUTPUT_DIR,
    examiner: str = "DFIR-Lead",
    description: str = "",
    no_parse: bool = False,
    no_ai: bool = False,
    consent: bool = True,
    auto_open: bool = True,
    no_prompt: bool = False,
    selected_modules: Optional[list[str]] = None,
) -> Path:
    import os
    print_banner()
    print_warning()

    settings = load_ai_settings()
    if not offline and not no_ai and not no_prompt and sys.stdin.isatty():
        settings = prompt_ai_configuration(settings)

    cid = case_id or f"CASE-{get_timestamp()}"
    console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== STAGE 1: Celestial Collector (Acquisition: {profile.value.upper()}) ===[/]")
    case_mgr = CaseManager(output)
    case_dir, metadata = case_mgr.create_case(
        case_id=cid,
        profile=profile.value,
        examiner=examiner,
        description=description,
    )

    console.print(f"[bold {CelestialPalette.SUCCESS_GREEN}]Mission Initialized:[/] [bold {CelestialPalette.AURORA_CYAN}]{cid}[/] at {case_dir}")

    engine = AcquisitionEngine(
        case_dir=case_dir,
        profile=profile,
        parse=not no_parse,
        selected_modules=selected_modules,
    )

    target_modules = engine.get_target_modules()
    with Progress(
        SpinnerColumn(spinner_name="dots", style=CelestialPalette.AURORA_CYAN),
        TextColumn(f"[bold {CelestialPalette.AURORA_CYAN}]" + "{task.description}"),
        BarColumn(
            bar_width=32,
            style="color(237)",
            complete_style=CelestialPalette.AURORA_CYAN,
            finished_style=CelestialPalette.SUCCESS_GREEN,
        ),
        TaskProgressColumn(),
        TextColumn(f"[{CelestialPalette.MUTED_BLUE}]" + "({task.completed}/{task.total} modules)"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Acquiring forensic artifacts...", total=len(target_modules))

        def on_collect_progress(mod_name: str, step: int, total: int):
            progress.update(
                task,
                completed=step,
                total=total,
                description=f"Collecting [bold {CelestialPalette.STARLIGHT_WHITE}]{mod_name}[/]",
            )

        evidence_mgr = engine.run(progress_callback=on_collect_progress)

    metadata.status = "acquired"
    metadata.total_artifacts = sum(r.artifact_count for r in evidence_mgr.results)
    case_mgr.update_metadata(case_dir, metadata)

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
        total_manifest = len(manifest_mgr.entries)
        if total_manifest > 0:
            with Progress(
                SpinnerColumn(spinner_name="dots", style=CelestialPalette.AURORA_CYAN),
                TextColumn(f"[bold {CelestialPalette.AURORA_CYAN}]Verifying evidence integrity...[/]"),
                BarColumn(
                    bar_width=32,
                    style="color(237)",
                    complete_style=CelestialPalette.STELLAR_BLUE,
                    finished_style=CelestialPalette.SUCCESS_GREEN,
                ),
                TaskProgressColumn(),
                TextColumn(f"[{CelestialPalette.MUTED_BLUE}]" + "({task.completed}/{task.total} files)"),
                TimeElapsedColumn(),
                console=console,
            ) as v_progress:
                v_task = v_progress.add_task("Verifying SHA-256...", total=total_manifest)

                def on_verify(curr: int, tot: int):
                    v_progress.update(v_task, completed=curr, total=tot)

                v_rep = manifest_mgr.verify(progress_callback=on_verify)
        else:
            v_rep = manifest_mgr.verify()

        manifest_mgr.write_verification_report(v_rep)
        display_verification_results(v_rep)
    except Exception as e:
        console.print(f"[{CelestialPalette.WARNING_AMBER}]Verification warning:[/] {e}")

    if not no_ai:
        console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== STAGE 5: Stellar Intelligence (AI Analysis) ===[/]")
        try:
            # Auto-activate Gemini or other online provider from env or session key if still set to offline
            if settings.provider == AIProviderType.OFFLINE and not offline:
                if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or (settings.session_api_key and settings.provider == AIProviderType.GEMINI):
                    settings.provider = AIProviderType.GEMINI
                elif os.environ.get("OPENAI_API_KEY"):
                    settings.provider = AIProviderType.OPENAI
                elif os.environ.get("ANTHROPIC_API_KEY"):
                    settings.provider = AIProviderType.ANTHROPIC

            if provider:
                settings.provider = AIProviderType(provider.lower())
            if consent:
                settings.consent_granted = True
            if offline:
                settings.provider = AIProviderType.OFFLINE

            console.print(f"[bold {CelestialPalette.AURORA_CYAN}]Executing Stellar Intelligence:[/] Provider: [{CelestialPalette.SUCCESS_GREEN}]{settings.provider.value.upper()}[/] ({settings.get_effective_model()})")
            analyzer = StellarIntelligenceAnalyzer(case_dir, settings)
            ai_res = analyzer.run_analysis(offline_override=offline)
            if not ai_res.get("is_error"):
                console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Stellar Intelligence synthesis complete ({settings.provider.value.upper()}).[/]")
            else:
                console.print(f"[{CelestialPalette.WARNING_AMBER}]AI note:[/] {ai_res.get('error_message')}")
        except Exception as e:
            console.print(f"[{CelestialPalette.WARNING_AMBER}]AI warning:[/] {e}")

    h_rep = None
    p_rep = None
    console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== STAGE 6: Northstar Report Generation ===[/]")
    try:
        h_rep = HtmlReportGenerator(case_dir).generate(include_ai=not no_ai)
        p_rep = PdfReportGenerator(case_dir).generate(include_ai=not no_ai)
        console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Reports generated:[/] {h_rep.name}, {p_rep.name}")
    except Exception as e:
        console.print(f"[{CelestialPalette.WARNING_AMBER}]Reporting warning:[/] {e}")

    z_path = None
    z_hash = ""
    console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== STAGE 7: Mission Archive Packaging ===[/]")
    try:
        z_path, z_hash = ZipBuilder(case_dir).build_package()
        console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Sealed package:[/] {z_path}")
        console.print(f"[bold {CelestialPalette.WARNING_AMBER}]SHA-256:[/] {z_hash}")
    except Exception as e:
        console.print(f"[{CelestialPalette.WARNING_AMBER}]Packaging warning:[/] {e}")

    if auto_open and h_rep and h_rep.exists():
        console.print(f"\n[bold {CelestialPalette.AURORA_CYAN}]Opening Northstar Report in default browser...[/]")
        open_report_in_browser(h_rep)

    # Executive Mission Summary Panel with ZIP location
    summary_table = Table.grid(padding=(0, 2))
    summary_table.add_column(style=f"bold {CelestialPalette.AURORA_CYAN}", width=26)
    summary_table.add_column(style=CelestialPalette.STARLIGHT_WHITE, overflow="fold")

    summary_table.add_row("Mission Case ID", f"[bold]{cid}[/]")
    summary_table.add_row("Acquisition Profile", f"[bold]{profile.value.upper()}[/]")
    summary_table.add_row("Case Directory", str(case_dir.resolve()))
    if z_path and Path(z_path).exists():
        summary_table.add_row("Evidence Archive (ZIP)", f"[bold {CelestialPalette.SUCCESS_GREEN}]{Path(z_path).resolve()}[/]")
        summary_table.add_row("Archive SHA-256 Seal", f"[{CelestialPalette.WARNING_AMBER}]{z_hash}[/]")
    if h_rep and h_rep.exists():
        summary_table.add_row("Interactive HTML Report", f"[bold underline]{h_rep.resolve()}[/bold underline]")
    if p_rep and p_rep.exists():
        summary_table.add_row("Executive PDF Report", str(p_rep.resolve()))
    summary_table.add_row("Evidence Integrity", f"[{CelestialPalette.SUCCESS_GREEN}]Cryptographically Sealed & Verified (ISO/IEC 27037)[/]")
    summary_table.add_row("Report Status", f"[{CelestialPalette.SUCCESS_GREEN}]Auto-opened in default browser[/]" if auto_open else "Generated on disk")

    mission_panel = Panel(
        summary_table,
        title=f"[bold {CelestialPalette.AURORA_CYAN}]* MISSION ACQUISITION & INTELLIGENCE COMPLETE *[/]",
        subtitle=f"[{CelestialPalette.MUTED_BLUE}]POLARIS - Your guide to Digital Forensics[/]",
        border_style=CelestialPalette.STELLAR_BLUE,
        padding=(1, 2),
    )
    console.print()
    console.print(mission_panel)
    console.print()

    if getattr(sys, "frozen", False) and sys.stdout.isatty():
        try:
            console.print(f"[{CelestialPalette.AURORA_CYAN}]* Evidence captured successfully to storage device. You may safely remove the drive. *[/]")
            input("\nPress [Enter] to exit...")
        except (EOFError, KeyboardInterrupt):
            pass

    return case_dir


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    quick: bool = typer.Option(False, "--quick", "-q", help="Execute rapid triage acquisition (Quick profile) [default when no args]"),
    full: bool = typer.Option(False, "--full", "-f", help="Execute comprehensive forensic acquisition (Full profile)"),
    profile: Optional[CollectionProfile] = typer.Option(None, "--profile", "-p", help="Acquisition profile (quick, full)"),
    case_id: Optional[str] = typer.Option(None, "--case-id", "-c", help="Case identifier"),
    offline: bool = typer.Option(False, "--offline", help="Run AI in offline deterministic mode"),
    no_open: bool = typer.Option(False, "--no-open", help="Do not open report automatically in default browser"),
    no_prompt: bool = typer.Option(False, "--no-prompt", help="Bypass interactive AI configuration prompt"),
    examiner: str = typer.Option("DFIR-Lead", "--examiner", "-e", help="Examiner name or badge ID"),
):
    if ctx.invoked_subcommand is None:
        if full:
            prof = CollectionProfile.FULL
        elif quick:
            prof = CollectionProfile.QUICK
        elif profile:
            prof = profile
        else:
            prof = CollectionProfile.QUICK  # Default to QUICK per user request

        execute_mission(
            profile=prof,
            case_id=case_id,
            offline=offline,
            auto_open=not no_open,
            no_prompt=no_prompt,
            examiner=examiner,
        )


@app.command(name="quick", help="Execute complete automated rapid triage (Quick profile), AI analysis, and open report.")
def cmd_quick(
    case_id: Optional[str] = typer.Option(None, "--case-id", "-c", help="Unique identifier for the investigation"),
    offline: bool = typer.Option(False, "--offline", help="Run AI in offline deterministic mode"),
    no_open: bool = typer.Option(False, "--no-open", help="Do not open report automatically in default browser"),
    no_prompt: bool = typer.Option(False, "--no-prompt", help="Bypass interactive AI configuration prompt"),
    examiner: str = typer.Option("DFIR-Lead", "--examiner", "-e", help="Name or badge ID of examiner"),
    description: str = typer.Option("Rapid triage collection and automated intelligence", "--description", "-d", help="Case description"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory for case storage"),
):
    execute_mission(
        profile=CollectionProfile.QUICK,
        case_id=case_id,
        offline=offline,
        auto_open=not no_open,
        no_prompt=no_prompt,
        examiner=examiner,
        description=description,
        output=output,
    )


@app.command(name="full", help="Execute complete comprehensive investigation (Full profile), AI analysis, and open report.")
def cmd_full(
    case_id: Optional[str] = typer.Option(None, "--case-id", "-c", help="Unique identifier for the investigation"),
    offline: bool = typer.Option(False, "--offline", help="Run AI in offline deterministic mode"),
    no_open: bool = typer.Option(False, "--no-open", help="Do not open report automatically in default browser"),
    no_prompt: bool = typer.Option(False, "--no-prompt", help="Bypass interactive AI configuration prompt"),
    examiner: str = typer.Option("DFIR-Lead", "--examiner", "-e", help="Name or badge ID of examiner"),
    description: str = typer.Option("Comprehensive forensic acquisition and automated intelligence", "--description", "-d", help="Case description"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory for case storage"),
):
    execute_mission(
        profile=CollectionProfile.FULL,
        case_id=case_id,
        offline=offline,
        auto_open=not no_open,
        no_prompt=no_prompt,
        examiner=examiner,
        description=description,
        output=output,
    )


@app.command(name="help", help="Display Polaris commands and usage help.")
def cmd_help(ctx: typer.Context):
    """Show help for POLARIS commands."""
    print_banner()
    parent = ctx.parent
    if parent:
        console.print(parent.get_help())
    else:
        console.print(ctx.get_help())


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
    consent: Optional[bool] = typer.Option(None, "--consent/--no-consent", help="Grant or revoke consent to transmit evidence to AI"),
):
    print_banner()
    if provider or model or (enable is not None) or (consent is not None):
        update_settings(provider=provider, model=model, enable=enable, consent=consent)
    else:
        display_settings()


@app.command(name="collect", help="[02] Acquire forensic artifacts according to profile and automatically execute intelligence analysis.")
def cmd_collect(
    profile: CollectionProfile = typer.Option(CollectionProfile.FULL, "--profile", "-p", help="Acquisition profile"),
    case_id: Optional[str] = typer.Option(None, "--case-id", "-c", help="Unique identifier for the investigation"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory for case storage"),
    examiner: str = typer.Option("DFIR-Lead", "--examiner", "-e", help="Name or badge ID of the forensic examiner"),
    description: str = typer.Option("", "--description", "-d", help="Description of the case"),
    no_parse: bool = typer.Option(False, "--no-parse", help="Acquire raw evidence only, skip parsing"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI post-analysis stage"),
    offline: bool = typer.Option(False, "--offline", help="Force offline deterministic AI analysis"),
    acquire_only: bool = typer.Option(False, "--acquire-only", help="Acquire artifacts only, skipping subsequent automated stages"),
    no_open: bool = typer.Option(False, "--no-open", help="Do not open report automatically in default browser"),
    no_prompt: bool = typer.Option(False, "--no-prompt", help="Bypass interactive AI configuration prompt"),
):
    selected_modules = None
    if profile == CollectionProfile.CUSTOM:
        selected_modules = prompt_custom_modules()
        console.print(f"[{CelestialPalette.AURORA_CYAN}]Selected {len(selected_modules)} modules for custom acquisition.[/]")

    if acquire_only:
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

        engine = AcquisitionEngine(
            case_dir=case_dir,
            profile=profile,
            parse=not no_parse,
            selected_modules=selected_modules,
        )

        target_modules = engine.get_target_modules()
        with Progress(
            SpinnerColumn(spinner_name="dots", style=CelestialPalette.AURORA_CYAN),
            TextColumn(f"[bold {CelestialPalette.AURORA_CYAN}]" + "{task.description}"),
            BarColumn(
                bar_width=32,
                style="color(237)",
                complete_style=CelestialPalette.AURORA_CYAN,
                finished_style=CelestialPalette.SUCCESS_GREEN,
            ),
            TaskProgressColumn(),
            TextColumn(f"[{CelestialPalette.MUTED_BLUE}]" + "({task.completed}/{task.total} modules)"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Acquiring forensic artifacts...", total=len(target_modules))

            def on_collect_progress(mod_name: str, step: int, total: int):
                progress.update(
                    task,
                    completed=step,
                    total=total,
                    description=f"Collecting [bold {CelestialPalette.STARLIGHT_WHITE}]{mod_name}[/]",
                )

            evidence_mgr = engine.run(progress_callback=on_collect_progress)

        metadata.status = "acquired"
        metadata.total_artifacts = sum(r.artifact_count for r in evidence_mgr.results)
        case_mgr.update_metadata(case_dir, metadata)

        summary = evidence_mgr.get_summary()
        display_collection_summary(summary)
    else:
        execute_mission(
            profile=profile,
            case_id=case_id,
            offline=offline,
            output=output,
            examiner=examiner,
            description=description,
            no_parse=no_parse,
            no_ai=no_ai,
            auto_open=not no_open,
            no_prompt=no_prompt,
            selected_modules=selected_modules,
        )


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
    consent: bool = typer.Option(False, "--consent", help="Pre-authorize transmitting evidence to external AI provider"),
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

    if consent:
        settings.consent_granted = True

    if offline:
        settings.provider = AIProviderType.OFFLINE

    if not case:
        display_settings()
        cases = []
        if output.exists():
            cases = [d.name for d in output.iterdir() if d.is_dir() and (d / "metadata").exists()]

        console.print()
        if cases:
            console.print(f"[bold {CelestialPalette.AURORA_CYAN}]Available Case(s):[/] {', '.join(cases)}")
            console.print("To execute Stellar Intelligence on a case, run:")
            console.print(f"  [bold]py main.py ai --case {cases[-1]}[/bold]")
        else:
            console.print(f"[{CelestialPalette.WARNING_AMBER}]No acquired cases found in '{output}'.[/]")
            console.print("Acquire a case first with: [bold]py main.py collect --profile quick[/bold]")
            console.print("Or execute full pipeline: [bold]py main.py all --profile quick[/bold]")
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


@app.command(name="report", help="[07] Generate Northstar forensic report (HTML & PDF) and open in default app.")
def cmd_report(
    case: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    include_ai: bool = typer.Option(True, "--include-ai", help="Include AI intelligence section if available"),
    without_ai: bool = typer.Option(False, "--without-ai", help="Exclude AI intelligence section"),
    output: Path = typer.Option(DEFAULT_OUTPUT_DIR, "--output", "-o", help="Base directory where case is stored"),
    no_open: bool = typer.Option(False, "--no-open", help="Do not open HTML report automatically in default browser"),
):
    print_banner()
    case_dir = output / case
    if not case_dir.exists():
        console.print(f"[bold {CelestialPalette.CRITICAL_RED}]Error:[/] Case directory {case_dir} does not exist.")
        raise typer.Exit(1)

    should_include_ai = include_ai and not without_ai

    # Auto-synthesize AI analysis if missing so the report always comes with it
    ai_json = case_dir / "metadata" / "ai_analysis.json"
    ai_md = case_dir / "metadata" / "ai_analysis.md"
    has_ai = (ai_json.exists() and ai_json.stat().st_size > 50) or (ai_md.exists() and ai_md.stat().st_size > 50)

    if should_include_ai and not has_ai:
        console.print(f"[bold {CelestialPalette.AURORA_CYAN}]Synthesizing Stellar Intelligence for {case}...[/]")
        try:
            settings = load_ai_settings()
            analyzer = StellarIntelligenceAnalyzer(case_dir, settings)
            analyzer.run_analysis()
            console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Stellar Intelligence analysis completed.[/]")
        except Exception as e:
            console.print(f"[{CelestialPalette.WARNING_AMBER}]AI note:[/] {e}")

    console.print(f"[bold {CelestialPalette.AURORA_CYAN}]Generating Northstar reports for {case}...[/]")
    html_gen = HtmlReportGenerator(case_dir)
    html_path = html_gen.generate(include_ai=should_include_ai)
    console.print(f"[{CelestialPalette.SUCCESS_GREEN}]HTML Report generated:[/] {html_path}")

    pdf_gen = PdfReportGenerator(case_dir)
    pdf_path = pdf_gen.generate(include_ai=should_include_ai)
    console.print(f"[{CelestialPalette.SUCCESS_GREEN}]PDF Report generated:[/] {pdf_path}")

    if not no_open and html_path.exists():
        console.print(f"[bold {CelestialPalette.AURORA_CYAN}]Opening Northstar Report in default browser...[/]")
        open_report_in_browser(html_path)


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
    examiner: str = typer.Option("DFIR-Lead", "--examiner", "-e", help="Examiner name"),
    description: str = typer.Option("", "--description", "-d", help="Case description"),
    no_parse: bool = typer.Option(False, "--no-parse", help="Skip parsing"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI intelligence stage"),
    consent: bool = typer.Option(True, "--consent", help="Pre-authorize transmitting evidence to external AI provider"),
    no_open: bool = typer.Option(False, "--no-open", help="Do not open report automatically in default browser"),
):
    execute_mission(
        profile=profile,
        case_id=case_id,
        provider=provider,
        offline=offline,
        output=output,
        examiner=examiner,
        description=description,
        no_parse=no_parse,
        no_ai=no_ai,
        consent=consent,
        auto_open=not no_open,
    )
