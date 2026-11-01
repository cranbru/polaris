import os
import sys
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.table import Table

from config.theme import CelestialPalette
from config.ai_settings import AISettings, AIProviderType, load_ai_settings, save_ai_settings
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


def prompt_ai_configuration(settings: Optional[AISettings] = None) -> AISettings:
    """Interactive pre-mission prompt to configure AI provider and API keys."""
    if settings is None:
        settings = load_ai_settings()

    # Check for active keys in environment
    gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or (settings.session_api_key if settings.provider == AIProviderType.GEMINI else "")
    openai_key = os.environ.get("OPENAI_API_KEY") or (settings.session_api_key if settings.provider == AIProviderType.OPENAI else "")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY") or (settings.session_api_key if settings.provider == AIProviderType.ANTHROPIC else "")

    active_provider = None
    if gemini_key:
        active_provider = "GEMINI"
    elif openai_key:
        active_provider = "OPENAI"
    elif anthropic_key:
        active_provider = "ANTHROPIC"

    console.print(f"\n[bold {CelestialPalette.STELLAR_BLUE}]=== [05] STELLAR INTELLIGENCE - Neural Analysis Configuration ===[/]")

    if active_provider:
        console.print(
            f"[{CelestialPalette.AURORA_CYAN}]Active AI key detected:[/] "
            f"[bold {CelestialPalette.SUCCESS_GREEN}]{active_provider}[/] ({settings.get_effective_model()})"
        )
        prompt_msg = "Do you want to configure or change an AI API key for explainable AI analysis? (y/N): "
    else:
        console.print(f"[{CelestialPalette.MUTED_BLUE}]No external AI keys detected in current environment.[/]")
        prompt_msg = "Do you want to add an AI API key for explainable AI analysis? (y/N): "

    try:
        ans = input(prompt_msg).strip().lower()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Bypassing AI configuration prompt.[/]")
        return settings

    if ans not in ["y", "yes"]:
        if not active_provider:
            console.print(f"[{CelestialPalette.AURORA_CYAN}]Engaging Stellar Intelligence in Offline Deterministic mode.[/]")
            settings.provider = AIProviderType.OFFLINE
        else:
            console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Using active {active_provider} credentials for intelligence synthesis.[/]")
            if active_provider == "GEMINI":
                settings.provider = AIProviderType.GEMINI
            elif active_provider == "OPENAI":
                settings.provider = AIProviderType.OPENAI
            elif active_provider == "ANTHROPIC":
                settings.provider = AIProviderType.ANTHROPIC
        settings.consent_granted = True
        return settings

    # Display clean celestial provider selection menu
    menu_table = Table(
        title="[bold]Stellar Intelligence — Select AI Neural Engine[/bold]",
        header_style=f"bold {CelestialPalette.AURORA_CYAN}",
        border_style=CelestialPalette.STELLAR_BLUE,
    )
    menu_table.add_column("No.", style="cyan", width=4)
    menu_table.add_column("AI Provider", style=f"bold {CelestialPalette.STARLIGHT_WHITE}", width=20)
    menu_table.add_column("Recommended Model", style=CelestialPalette.AURORA_CYAN, width=28)
    menu_table.add_column("Description", style=CelestialPalette.MUTED_BLUE)

    menu_table.add_row("1", "Google Gemini", "gemini-1.5-pro", "Fast, high token budget (Recommended)")
    menu_table.add_row("2", "OpenAI", "gpt-4o", "Multimodal, high reasoning depth")
    menu_table.add_row("3", "Anthropic Claude", "claude-3-5-sonnet-20241022", "High forensic reasoning accuracy")
    menu_table.add_row("4", "Manual / Custom", "Custom Model Identifier", "Specify custom base provider & model")
    menu_table.add_row("5", "Offline Mode", "offline-deterministic", "Deterministic heuristic rules only (no key)")

    console.print(menu_table)

    try:
        choice = input("\nSelect AI Provider [1-5] (default: 1): ").strip()
    except (KeyboardInterrupt, EOFError):
        choice = "1"

    if not choice:
        choice = "1"

    if choice == "1":
        # Google Gemini
        settings.provider = AIProviderType.GEMINI
        console.print(f"\n[bold {CelestialPalette.AURORA_CYAN}]Configuring Google Gemini Engine[/]")
        key_input = input("Enter Gemini / Google API Key (e.g., AIza...): ").strip()
        if key_input:
            os.environ["GEMINI_API_KEY"] = key_input
            os.environ["GOOGLE_API_KEY"] = key_input
            settings.session_api_key = key_input
        elif gemini_key:
            console.print(f"[{CelestialPalette.AURORA_CYAN}]Retaining existing Gemini key from environment.[/]")
        else:
            console.print(f"[{CelestialPalette.WARNING_AMBER}]No API key entered. Engaging offline fallback.[/]")
            settings.provider = AIProviderType.OFFLINE
            return settings

        model_input = input("Enter Gemini Model Identifier [default: gemini-1.5-pro]: ").strip()
        settings.model = model_input or "gemini-1.5-pro"
        settings.consent_granted = True
        save_ai_settings(settings)
        console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Stellar Intelligence configured: Google Gemini ({settings.model})[/]")

    elif choice == "2":
        # OpenAI
        settings.provider = AIProviderType.OPENAI
        console.print(f"\n[bold {CelestialPalette.AURORA_CYAN}]Configuring OpenAI Engine[/]")
        key_input = input("Enter OpenAI API Key (e.g., sk-...): ").strip()
        if key_input:
            os.environ["OPENAI_API_KEY"] = key_input
            settings.session_api_key = key_input
        elif openai_key:
            console.print(f"[{CelestialPalette.AURORA_CYAN}]Retaining existing OpenAI key from environment.[/]")
        else:
            console.print(f"[{CelestialPalette.WARNING_AMBER}]No API key entered. Engaging offline fallback.[/]")
            settings.provider = AIProviderType.OFFLINE
            return settings

        model_input = input("Enter OpenAI Model Identifier [default: gpt-4o]: ").strip()
        settings.model = model_input or "gpt-4o"
        settings.consent_granted = True
        save_ai_settings(settings)
        console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Stellar Intelligence configured: OpenAI ({settings.model})[/]")

    elif choice == "3":
        # Anthropic Claude
        settings.provider = AIProviderType.ANTHROPIC
        console.print(f"\n[bold {CelestialPalette.AURORA_CYAN}]Configuring Anthropic Claude Engine[/]")
        key_input = input("Enter Anthropic API Key (e.g., sk-ant-...): ").strip()
        if key_input:
            os.environ["ANTHROPIC_API_KEY"] = key_input
            settings.session_api_key = key_input
        elif anthropic_key:
            console.print(f"[{CelestialPalette.AURORA_CYAN}]Retaining existing Anthropic key from environment.[/]")
        else:
            console.print(f"[{CelestialPalette.WARNING_AMBER}]No API key entered. Engaging offline fallback.[/]")
            settings.provider = AIProviderType.OFFLINE
            return settings

        model_input = input("Enter Anthropic Model Identifier [default: claude-3-5-sonnet-20241022]: ").strip()
        settings.model = model_input or "claude-3-5-sonnet-20241022"
        settings.consent_granted = True
        save_ai_settings(settings)
        console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Stellar Intelligence configured: Anthropic Claude ({settings.model})[/]")

    elif choice == "4":
        # Manual / Custom
        console.print(f"\n[bold {CelestialPalette.AURORA_CYAN}]Manual AI Configuration[/]")
        base_p = input("Enter Base Provider [gemini / openai / anthropic] (default: gemini): ").strip().lower() or "gemini"
        if base_p in ["gemini", "openai", "anthropic"]:
            settings.provider = AIProviderType(base_p)
        else:
            settings.provider = AIProviderType.GEMINI

        custom_model = input("Enter Custom Model Identifier (e.g., gemini-2.5-flash): ").strip()
        settings.model = custom_model or settings.get_effective_model()

        custom_key = input("Enter API Key: ").strip()
        if custom_key:
            settings.session_api_key = custom_key
            if settings.provider == AIProviderType.GEMINI:
                os.environ["GEMINI_API_KEY"] = custom_key
                os.environ["GOOGLE_API_KEY"] = custom_key
            elif settings.provider == AIProviderType.OPENAI:
                os.environ["OPENAI_API_KEY"] = custom_key
            elif settings.provider == AIProviderType.ANTHROPIC:
                os.environ["ANTHROPIC_API_KEY"] = custom_key

        settings.consent_granted = True
        save_ai_settings(settings)
        console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Stellar Intelligence configured with custom model ({settings.model})[/]")

    elif choice == "5":
        settings.provider = AIProviderType.OFFLINE
        settings.model = "offline-deterministic"
        settings.consent_granted = True
        save_ai_settings(settings)
        console.print(f"[{CelestialPalette.AURORA_CYAN}]Stellar Intelligence set to Offline Deterministic mode.[/]")

    return settings
