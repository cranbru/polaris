from enum import Enum
from pathlib import Path
from datetime import datetime


class CollectionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class ArtifactCategory(str, Enum):
    EXECUTION = "execution"
    EVENTLOGS = "eventlogs"
    USER_ACTIVITY = "user_activity"
    REGISTRY = "registry"
    BROWSERS = "browsers"
    DEVICES = "devices"
    PERSISTENCE = "persistence"
    NETWORK = "network"
    SYSTEM = "system"
    POWERSHELL = "powershell"


class CollectionProfile(str, Enum):
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


import sys

def get_default_output_dir() -> Path:
    """Returns portable directory next to executable if frozen (e.g. on USB drive), else current cases/ folder."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "cases"
    return Path("cases")


DEFAULT_OUTPUT_DIR = get_default_output_dir()
DEFAULT_LOG_LEVEL = "INFO"
TOOL_NAME = "POLARIS"
TOOL_VERSION = "2.0.0"
TOOL_TAGLINE = "Your guide to Digital Forensics"
TOOL_SUBTITLE = "WINDOWS DIGITAL FORENSICS & INTELLIGENCE SUITE"

HASH_ALGORITHM = "sha256"
MANIFEST_CSV = "SHA256_MANIFEST.csv"
MANIFEST_JSON = "SHA256_MANIFEST.json"
TIMELINE_CSV = "TIMELINE.csv"

LIVE_ACQUISITION_WARNING = (
    "WARNING: Live forensic acquisition can affect system state and is NOT "
    "equivalent to write-blocked disk imaging. Evidence collected from a "
    "running system may be modified by ongoing system activity."
)

SENSITIVE_COLLECTION_WARNING = (
    "WARNING: Command histories (e.g., PSReadLine) may contain sensitive "
    "information including passwords, API keys, and personal data."
)


def get_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def get_iso_timestamp() -> str:
    return datetime.now().isoformat()
