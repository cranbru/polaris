from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config.theme import CelestialPalette
from config.ai_settings import load_ai_settings, save_ai_settings, AIProviderType

console = Console()


def display_settings() -> None:
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
    table.add_row("API Key Status", settings.masked_api_key(), "Protected in Environment Variables")
    table.add_row("Redaction Filter", str(settings.redaction_enabled), "Strips PII & secrets before reasoning")
    table.add_row("Investigator Consent", str(settings.consent_granted), "Explicit approval to transmit evidence")
    table.add_row("Max Output Tokens", str(settings.max_output_tokens), "Inference token budget")
    table.add_row("Sampling Temperature", str(settings.temperature), "Lower is more deterministic")

    console.print(table)


def update_settings(provider: str | None = None, model: str | None = None, enable: bool | None = None) -> None:
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

    save_ai_settings(settings)
    console.print(f"[{CelestialPalette.SUCCESS_GREEN}]Settings updated successfully.[/]")
    display_settings()
