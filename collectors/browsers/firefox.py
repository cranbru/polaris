"""Mozilla Firefox browser artifact collector."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import csv
from io import StringIO
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp

logger = logging.getLogger("polaris")

SAFE_FILES = ["places.sqlite", "places.sqlite-wal", "places.sqlite-shm"]
FORBIDDEN_FILES = {"cookies.sqlite", "logins.json", "key4.db", "cert9.db", "signons.sqlite"}


def prtime_to_iso(prtime: int) -> str:
    """Convert Firefox PRTime (microseconds since Unix epoch) to ISO string."""
    if not prtime or prtime <= 0:
        return ""
    try:
        epoch_seconds = prtime / 1_000_000
        dt = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
        return dt.isoformat()
    except (OSError, ValueError, OverflowError):
        return ""


def _find_firefox_profiles() -> list[Path]:
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return []
    profiles_dir = Path(appdata) / "Mozilla" / "Firefox" / "Profiles"
    if not profiles_dir.exists():
        return []
    profiles: list[Path] = []
    try:
        for entry in profiles_dir.iterdir():
            if entry.is_dir() and (entry / "places.sqlite").exists():
                profiles.append(entry)
    except (OSError, PermissionError):
        pass
    return profiles


def _parse_places_db(db_path: Path) -> tuple[list[dict], list[dict]]:
    """Parse Firefox places.sqlite. Returns (places, visits)."""
    places: list[dict] = []
    visits: list[dict] = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro&nolock=1", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT url, title, visit_count, last_visit_date FROM moz_places "
                "WHERE visit_count > 0 ORDER BY last_visit_date DESC"
            )
            for row in cursor.fetchall():
                places.append({
                    "url": row["url"],
                    "title": row["title"] or "",
                    "visit_count": row["visit_count"],
                    "last_visit_date_raw": row["last_visit_date"],
                    "last_visit_date": prtime_to_iso(row["last_visit_date"] or 0),
                })
        except sqlite3.OperationalError as e:
            logger.debug(f"Firefox moz_places error: {e}")

        try:
            cursor.execute(
                "SELECT hv.visit_date, hv.visit_type, hp.url, hp.title "
                "FROM moz_historyvisits hv "
                "JOIN moz_places hp ON hv.place_id = hp.id "
                "ORDER BY hv.visit_date DESC "
                "LIMIT 50000"
            )
            for row in cursor.fetchall():
                visits.append({
                    "url": row["url"],
                    "title": row["title"] or "",
                    "visit_date_raw": row["visit_date"],
                    "visit_date": prtime_to_iso(row["visit_date"] or 0),
                    "visit_type": row["visit_type"],
                })
        except sqlite3.OperationalError as e:
            logger.debug(f"Firefox moz_historyvisits error: {e}")

        conn.close()
    except (sqlite3.Error, OSError) as e:
        logger.debug(f"Failed to parse Firefox places DB {db_path}: {e}")
    return places, visits


@register_collector("browser_firefox")
class FirefoxCollector(CollectorBase):
    module_id = "browser_firefox"
    module_name = "Mozilla Firefox"
    category = ArtifactCategory.BROWSERS
    source_locations = ["%APPDATA%\\Mozilla\\Firefox\\Profiles\\*"]
    required_privileges = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        profiles = _find_firefox_profiles()
        if not profiles:
            result.status = CollectionStatus.NOT_AVAILABLE
            result.warnings.append("No Firefox profiles found")
            return result

        collected_any = False
        all_places: list[dict] = []
        all_visits: list[dict] = []

        for profile_path in profiles:
            profile_name = profile_path.name
            dest_dir = self.evidence_dir / "firefox" / profile_name

            for filename in SAFE_FILES:
                src = profile_path / filename
                if src.exists():
                    evidence = self.copy_file(src, dest_dir, f"firefox_{profile_name}_{filename}")
                    if evidence:
                        evidence.metadata = {"browser": "Firefox", "profile": profile_name}
                        result.acquired_files.append(evidence)
                        collected_any = True
                    else:
                        result.warnings.append(f"Failed to copy {src}")

            if self.parse:
                places_src = profile_path / "places.sqlite"
                if places_src.exists():
                    acquired_places = dest_dir / "places.sqlite"
                    db_to_parse = acquired_places if acquired_places.exists() else places_src
                    places, visits = _parse_places_db(db_to_parse)

                    for entry in places:
                        entry["profile"] = profile_name
                    for entry in visits:
                        entry["profile"] = profile_name

                    all_places.extend(places)
                    all_visits.extend(visits)

        if self.parse and (all_places or all_visits):
            parsed_dir = self.parsed_dir / "firefox"
            parsed_dir.mkdir(parents=True, exist_ok=True)

            if all_places:
                ev = self.save_json(all_places, "firefox_places.json", parsed_dir)
                if ev:
                    result.parsed_output_files.append(ev.acquired_path)
                    result.acquired_files.append(ev)

                csv_ev = self._write_csv(
                    all_places,
                    ["profile", "url", "title", "visit_count", "last_visit_date"],
                    "firefox_places.csv",
                    parsed_dir,
                )
                if csv_ev:
                    result.parsed_output_files.append(csv_ev.acquired_path)
                    result.acquired_files.append(csv_ev)

            if all_visits:
                ev = self.save_json(all_visits, "firefox_visits.json", parsed_dir)
                if ev:
                    result.parsed_output_files.append(ev.acquired_path)
                    result.acquired_files.append(ev)

                csv_ev = self._write_csv(
                    all_visits,
                    ["profile", "url", "title", "visit_date", "visit_type"],
                    "firefox_visits.csv",
                    parsed_dir,
                )
                if csv_ev:
                    result.parsed_output_files.append(csv_ev.acquired_path)
                    result.acquired_files.append(csv_ev)

            result.parser_name = "polaris_firefox_parser"
            result.parser_version = "1.0"
            result.parser_status = "completed"

        result.status = CollectionStatus.SUCCESS if collected_any else CollectionStatus.FAILED
        return result

    def _write_csv(
        self,
        data: list[dict],
        fieldnames: list[str],
        filename: str,
        dest_dir: Path,
    ) -> Optional[FileEvidence]:
        if not data:
            return None
        buf = StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(data)
        return self.save_text(buf.getvalue(), filename, dest_dir)
