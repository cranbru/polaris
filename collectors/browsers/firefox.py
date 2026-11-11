"""Mozilla Firefox acquisition for the Windows account running POLARIS."""
from pathlib import Path

from config.settings import ArtifactCategory
from core.engine import register_collector
from collectors.browsers.common import BrowserCollector, find_profiles
from parsers.browsers.firefox import parse_places, prtime_to_iso

SAFE_FILES = ["places.sqlite", "permissions.sqlite"]
FORBIDDEN_FILES = {"cookies.sqlite", "logins.json", "key4.db", "cert9.db", "signons.sqlite", "formhistory.sqlite"}


def _find_firefox_profiles() -> list[Path]:
    return find_profiles("APPDATA", "Mozilla/Firefox/Profiles", ["places.sqlite", "prefs.js", "extensions.json", "permissions.sqlite"])


def _parse_places_db(db_path: Path) -> tuple[list[dict], list[dict]]:
    data = parse_places(db_path, [])
    return data["places"], data["visits"]


@register_collector("browser_firefox")
class FirefoxCollector(BrowserCollector):
    module_id = "browser_firefox"
    module_name = "Mozilla Firefox"
    browser = "Firefox"
    slug = "firefox"
    category = ArtifactCategory.BROWSERS
    source_locations = ["%APPDATA%\\Mozilla\\Firefox\\Profiles\\*"]

    def find_profiles(self):
        return _find_firefox_profiles()
