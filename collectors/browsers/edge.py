"""Microsoft Edge acquisition for the Windows account running POLARIS."""
from pathlib import Path

from config.settings import ArtifactCategory
from core.engine import register_collector
from collectors.browsers.common import BrowserCollector, find_profiles
from parsers.browsers.chromium import parse_history, webkit_to_iso

SAFE_FILES = ["History", "Bookmarks"]
WAL_FILES = []  # SQLite backup includes committed WAL transactions.
FORBIDDEN_FILES = {"Cookies", "Login Data", "Web Data", "Cookies-journal"}


def _find_edge_profiles() -> list[Path]:
    return find_profiles("LOCALAPPDATA", "Microsoft/Edge/User Data", ["History", "Bookmarks", "Preferences", "Extensions"])


def _parse_history_db(db_path: Path) -> tuple[list[dict], list[dict]]:
    data = parse_history(db_path, [])
    return data["history"], data["downloads"]


@register_collector("browser_edge")
class EdgeCollector(BrowserCollector):
    module_id = "browser_edge"
    module_name = "Microsoft Edge"
    browser = "Edge"
    slug = "edge"
    category = ArtifactCategory.BROWSERS
    source_locations = ["%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\*"]

    def find_profiles(self):
        return _find_edge_profiles()
