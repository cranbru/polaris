import sys
from rich.console import Console
from rich.panel import Panel
from config.theme import CelestialPalette
from config.ai_settings import AISettings, AIProviderType

console = Console()


def request_ai_consent(settings: AISettings, evidence_categories: list[str]) -> bool:
    if settings.provider == AIProviderType.OFFLINE:
        return True

    if settings.consent_granted:
        return True

    if not sys.stdin.isatty():
        # Non-interactive mode requires explicit consent_granted in settings
        return False

    notice = (
        f"[bold {CelestialPalette.WARNING_AMBER}]STELLAR INTELLIGENCE - PRIVACY & CONSENT NOTICE[/]\n\n"
        f"You are about to submit structured artifact observations to external AI provider: "
        f"[bold {CelestialPalette.AURORA_CYAN}]{settings.provider.value.upper()}[/] ({settings.get_effective_model()}).\n\n"
        f"• Categories to be analyzed: [italic]{', '.join(evidence_categories)}[/]\n"
        f"• Sensitive fields (passwords, cookies, active sessions) are strictly excluded by collectors.\n"
        f"• Automatic PII and token redaction filter is: [{'green' if settings.redaction_enabled else 'red'}]{'ACTIVE' if settings.redaction_enabled else 'DISABLED'}[/]\n"
        f"• Full offline analysis is available via: [bold]--offline[/bold]\n"
    )

    console.print(Panel(notice, border_style=CelestialPalette.WARNING_AMBER))
    choice = input("Do you authorize transmitting structured findings to the external AI model? (y/N): ").strip().lower()

    if choice in ["y", "yes"]:
        settings.consent_granted = True
        return True

    console.print(f"[{CelestialPalette.MUTED_BLUE}]Consent declined. Falling back to offline deterministic mode.[/]")
    return False
