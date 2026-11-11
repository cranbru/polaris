"""Google Chrome acquisition for the Windows account running POLARIS."""
from pathlib import Path

from config.settings import ArtifactCategory
from core.engine import register_collector
from collectors.browsers.common import BrowserCollector, find_profiles
from parsers.browsers.chromium import parse_history, webkit_to_iso

SAFE_FILES = ["History", "Bookmarks"]
WAL_FILES = []  # SQLite backup includes committed WAL transactions.
FORBIDDEN_FILES = {"Cookies", "Login Data", "Web Data", "Cookies-journal"}


def _find_chrome_profiles() -> list[Path]:
    return find_profiles("LOCALAPPDATA", "Google/Chrome/User Data", ["History", "Bookmarks", "Preferences", "Extensions"])


def _parse_history_db(db_path: Path) -> tuple[list[dict], list[dict]]:
    data = parse_history(db_path, [])
    return data["history"], data["downloads"]


@register_collector("browser_chrome")
class ChromeCollector(BrowserCollector):
    module_id = "browser_chrome"
    module_name = "Google Chrome"
    browser = "Chrome"
    slug = "chrome"
    category = ArtifactCategory.BROWSERS
    source_locations = ["%LOCALAPPDATA%\\Google\\Chrome\\User Data\\*"]

    def find_profiles(self):
        return _find_chrome_profiles()
