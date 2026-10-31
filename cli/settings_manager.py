from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config.theme import CelestialPalette
from config.ai_settings import load_ai_settings, save_ai_settings, AIProviderType

console = Console()


def display_settings() -> None:
    import os
    settings = load_ai_settings()

    table = Table(
        title="[09] SETTINGS - Celestial Intelligence Configuration",
        header_style=f"bold {CelestialPalette.AURORA_CYAN}",
        border_style=CelestialPalette.STELLAR_BLUE,
    )
    table.add_column("Parameter", style=CelestialPalette.AURORA_CYAN, width=28)
    table.add_column("Current Value", style=f"bold {CelestialPalette.STARLIGHT_WHITE}")
    table.add_column("Security Note", style=CelestialPalette.MUTED_BLUE)

    enabled_color = CelestialPalette.SUCCESS_GREEN if settings.enabled else CelestialPalette.WARNING_AMBER
    table.add_row("AI Engine Enabled", f"[{enabled_color}]{settings.enabled}[/]", "Toggles automated AI analysis")
    table.add_row("Configured Provider", settings.provider.value.upper(), "OpenAI, Anthropic, Gemini, Offline")
    table.add_row("Model Identifier", settings.get_effective_model(), "Provider-specific neural model")

    if settings.provider == AIProviderType.OFFLINE:
        key_status = f"[{CelestialPalette.MUTED_BLUE}]Not required (Offline Mode)[/]"
    elif settings.has_valid_key():
        key_status = f"[{CelestialPalette.SUCCESS_GREEN}]{settings.masked_api_key()}[/]"
    else:
        key_status = f"[{CelestialPalette.CRITICAL_RED}][NOT CONFIGURED][/]"

    table.add_row("Active Provider Key", key_status, "Protected in Environment Variables")
    table.add_row("Redaction Filter", str(settings.redaction_enabled), "Strips PII & secrets before reasoning")
    table.add_row("Investigator Consent", str(settings.consent_granted), "Explicit approval to transmit evidence")
    table.add_row("Max Output Tokens", str(settings.max_output_tokens), "Inference token budget")
    table.add_row("Sampling Temperature", str(settings.temperature), "Lower is more deterministic")

    console.print(table)

    gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")

    detected = []
    if gemini_key:
        masked_g = f"{gemini_key[:4]}...{gemini_key[-4:]}" if len(gemini_key) > 8 else "********"
        detected.append(f"GEMINI_API_KEY: [{CelestialPalette.SUCCESS_GREEN}]{masked_g}[/]")
    if openai_key:
        masked_o = f"{openai_key[:4]}...{openai_key[-4:]}" if len(openai_key) > 8 else "********"
        detected.append(f"OPENAI_API_KEY: [{CelestialPalette.SUCCESS_GREEN}]{masked_o}[/]")
    if anthropic_key:
        masked_a = f"{anthropic_key[:4]}...{anthropic_key[-4:]}" if len(anthropic_key) > 8 else "********"
        detected.append(f"ANTHROPIC_API_KEY: [{CelestialPalette.SUCCESS_GREEN}]{masked_a}[/]")

    if detected:
        console.print(f"[{CelestialPalette.AURORA_CYAN}]Detected Shell API Keys:[/] " + " | ".join(detected))
    else:
        console.print(f"[{CelestialPalette.MUTED_BLUE}]Note:[/] No external API keys detected in current shell session.")


def update_settings(
    provider: str | None = None,
    model: str | None = None,
    enable: bool | None = None,
    consent: bool | None = None,
) -> None:
    settings = load_ai_settings()
    if provider:
        try:
            settings.provider = AIProviderType(provider.lower())
        except ValueError:
            console.print(f"[{CelestialPalette.CRITICAL_RED}]Invalid provider: {provider}. Options: openai, anthropic, gemini, offline[/]")
            return
    if model:
        settings.model = model
    if enable is not None:
        settings.enabled = enable
    if consent is not None:
        settings.consent_granted = consent

    save_ai_settings(settings)
    console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Settings updated successfully.[/]")
    display_settings()
