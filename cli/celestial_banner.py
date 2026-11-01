import os
import sys
import time
from rich.console import Console
from rich.text import Text
from rich.panel import Panel

from config.theme import CelestialPalette
from config.settings import TOOL_NAME, TOOL_VERSION, TOOL_TAGLINE, TOOL_SUBTITLE
from core.permissions import get_windows_version, is_admin

console = Console()

NORTH_STAR_ASCII = r"""
                     .
                    / \
                   --*--
                    \ /
                     '
          .           |           .
           \          |          /
            \       +---+       /
             \      | * |      /
       -------+-----+---+-----+-------
             /      | * |      \
            /       +---+       \
           /          |          \
          '           |           '
                     .
                    / \
                   --*--
                    \ /
                     '
"""

POLARIS_TEXT_LOGO = r"""
    //   ) ) //   ) ) / /        // | |     //   ) )    / /    //   ) ) 
   //___/ / //   / / / /        //__| |    //___/ /    / /    ((        
  / ____ / //   / / / /        / ___  |   / ___ (     / /       \\      
 //       //   / / / /        //    | |  //   | |    / /          ) )   
//       ((___/ / / /____/ / //     | | //    | | __/ /___ ((___ / /    
"""


def render_banner(animated: bool = False) -> None:
    if animated and sys.stdout.isatty() and not os.environ.get("POLARIS_NO_ANIMATION"):
        _render_animated_banner()
    else:
        _render_static_banner()


def _render_static_banner() -> None:
    logo_text = Text(POLARIS_TEXT_LOGO, style=f"bold {CelestialPalette.AURORA_CYAN}")
    
    subtitle = Text()
    subtitle.append(f"  {TOOL_NAME} ", style=f"bold {CelestialPalette.STARLIGHT_WHITE}")
    subtitle.append(f"v{TOOL_VERSION}  |  ", style=f"bold {CelestialPalette.STELLAR_BLUE}")
    subtitle.append(f'"{TOOL_TAGLINE}"\n', style=f"italic {CelestialPalette.MUTED_BLUE}")
    subtitle.append(f"  {TOOL_SUBTITLE}\n", style=f"{CelestialPalette.NEBULA_VIOLET}")

    admin_str = "ELEVATED (ADMIN)" if is_admin() else "STANDARD USER"
    admin_color = CelestialPalette.SUCCESS_GREEN if is_admin() else CelestialPalette.WARNING_AMBER
    
    info_text = Text()
    info_text.append(f"  Host: {get_windows_version()}  ", style=CelestialPalette.MUTED_BLUE)
    info_text.append(f"[{admin_str}]\n", style=f"bold {admin_color}")

    combined = Text()
    combined.append_text(logo_text)
    combined.append_text(subtitle)
    combined.append_text(info_text)

    panel = Panel(
        combined,
        border_style=CelestialPalette.STELLAR_BLUE,
        subtitle=f"[{CelestialPalette.AURORA_CYAN}]Celestial Forensics Platform[/]",
        subtitle_align="right",
    )
    console.print(panel)


def _render_animated_banner() -> None:
    frames = [
        "       *       ",
        "     --*--     ",
        "   \\ --*-- /   ",
        "  --+--*--+--  ",
        "   / --*-- \\   ",
        "     --*--     ",
        "       *       ",
    ]
    for frame in frames:
        sys.stdout.write(f"\r\033[96m    {frame}  [Aligning celestial navigation matrix...]\033[0m")
        sys.stdout.flush()
        time.sleep(0.04)
    sys.stdout.write("\r" + " " * 70 + "\r")
    sys.stdout.flush()
    _render_static_banner()
