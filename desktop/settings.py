"""Persist non-secret desktop preferences and resolve real collector presets."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict

from config.settings import CollectionProfile, get_default_output_dir
from config.profiles import get_modules_for_profile
from config.artifact_catalog import ARTIFACT_CATALOG
from core.engine import get_registered_collectors


DESCRIPTIONS = {
    "prefetch": "Application launch artifacts and Prefetch files.",
    "amcache": "Application inventory and compatibility hive files.",
    "shimcache": "Application compatibility cache registry exports.",
    "bam": "Background application activity and execution timestamps.",
    "dam": "Desktop application activity registry records.",
    "srum": "System resource and network usage database files.",
    "userassist": "UserAssist registry records and decoded application names.",
    "pca": "Program Compatibility Assistant launch records.",
    "eventlogs": "Security, System, Defender, PowerShell and other event logs.",
    "lnk_files": "Shortcut targets, arguments and file metadata.",
    "jump_lists": "Recent application destinations and embedded shortcuts.",
    "recent_docs": "RecentDocs and file-dialog history registry exports.",
    "shellbags": "Windows folder-view history and user hive artifacts.",
    "recycle_bin": "Deleted-file paths and deletion timestamps from $I files.",
    "registry_hives": "System and user hives, including SAM and SECURITY when permitted.",
    "registry_artifacts": "Installed software, startup entries and registry artifacts.",
    "browser_chrome": "Chrome history, downloads and bookmarks.",
    "browser_edge": "Edge history, downloads and bookmarks.",
    "browser_firefox": "Firefox browsing history and visit records.",
    "usb_devices": "USB device registry history, mounts and SetupAPI logs.",
    "persistence": "Services, scheduled tasks, startup entries, drivers and WMI.",
    "network_info": "Current connections, listening ports, DNS, ARP and routes.",
    "system_info": "Endpoint information, current processes, users and services.",
    "powershell": "PowerShell event logs and optional command history.",
    "sensitive_files": "Off by default. Credential, key and wallet files; may require a longer scan.",
}


def get_config_path() -> Path:
    # Preferences follow the portable executable. Keys stay in the user's OS vault.
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / ".polaris_desktop.json"
    return Path(__file__).resolve().parent.parent / ".polaris_desktop.json"


def supported_modules():
    registered = get_registered_collectors()
    return [mid for mid in ARTIFACT_CATALOG if mid in registered]


def profile_modules(profile: str):
    if profile not in ("quick", "full"):
        raise ValueError("Choose Quick or Full acquisition.")
    supported = set(supported_modules())
    # Desktop presets keep secret-file scanning opt-in. Explicit selection and
    # Enable All Supported still allow it; CLI profiles retain their scope.
    return [mid for mid in get_modules_for_profile(CollectionProfile(profile))
            if mid in supported and mid != "sensitive_files"]


class DesktopSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")
    profile: str = "quick"
    modules: list[str] = Field(default_factory=lambda: profile_modules("quick"))
    ai_enabled: bool = False
    ai_provider: str = "offline"
    ai_model: str = ""
    ai_models: dict[str, str] = Field(default_factory=dict)
    parse: bool = True
    reduced_motion: bool = False
    output_dir: str = Field(default_factory=lambda: str(get_default_output_dir().resolve()))
    examiner: str = ""
    description: str = ""

    def validate_plan(self):
        if self.profile not in {"quick", "full"}:
            raise ValueError("Invalid acquisition preset.")
        supported = set(supported_modules())
        selected = list(dict.fromkeys(self.modules))
        if not selected:
            raise ValueError("Enable at least one collector before acquisition.")
        unknown = set(selected) - supported
        if unknown:
            raise ValueError("Unsupported collector selection: " + ", ".join(sorted(unknown)))
        registered = get_registered_collectors()
        for mid in selected:
            for dependency in getattr(registered[mid], "dependencies", ()):
                if dependency not in selected:
                    raise ValueError(f"{ARTIFACT_CATALOG[mid]['name']} requires {dependency}. Enable it explicitly.")
        if self.ai_provider not in {"offline", "openai", "gemini", "anthropic"}:
            raise ValueError("This AI provider is not implemented.")
        if self.ai_model and not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,200}", self.ai_model):
            raise ValueError("Use a valid provider model identifier.")
        if not self.output_dir.strip():
            raise ValueError("Choose a case output folder.")
        self.modules = selected
        return selected


class SettingsStore:
    def __init__(self, path: Path | None = None):
        self.path = path or get_config_path()

    def load(self):
        try:
            settings = DesktopSettings.model_validate_json(self.path.read_text(encoding="utf-8"))
            settings.modules = [m for m in settings.modules if m in supported_modules()]
            if not settings.modules:
                settings.modules = profile_modules("quick")
            if settings.profile not in {"quick", "full"}:
                settings.profile = "quick"
            return settings
        except (OSError, ValueError):
            return DesktopSettings()

    def save(self, settings: DesktopSettings):
        settings.validate_plan()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(settings.model_dump_json(indent=2), encoding="utf-8")
        os.replace(temporary, self.path)


def collector_catalog():
    registered = get_registered_collectors()
    return [{"id": mid, "name": "Sensitive Files & Secrets" if mid == "sensitive_files" else ARTIFACT_CATALOG[mid]["name"],
             "description": DESCRIPTIONS.get(mid, "Windows forensic artifacts."),
             "category": ARTIFACT_CATALOG[mid]["category"].value,
             "privileges": registered[mid].required_privileges,
             "dependencies": list(getattr(registered[mid], "dependencies", ())),
             "sensitive": mid in {"sensitive_files", "registry_hives", "powershell"}}
            for mid in supported_modules()]
