"""Microsoft Edge browser artifact collector."""

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

SAFE_FILES = ["History", "Bookmarks", "History-journal"]
WAL_FILES = ["History-wal", "History-shm"]
FORBIDDEN_FILES = {"Cookies", "Login Data", "Web Data", "Cookies-journal"}

WEBKIT_EPOCH_DELTA = 11644473600


def webkit_to_iso(webkit_timestamp: int) -> str:
    """Convert Edge/WebKit timestamp (microseconds since 1601-01-01) to ISO string."""
    if not webkit_timestamp or webkit_timestamp <= 0:
        return ""
    try:
        epoch_seconds = (webkit_timestamp / 1_000_000) - WEBKIT_EPOCH_DELTA
        if epoch_seconds < 0:
            return ""
        dt = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
        return dt.isoformat()
    except (OSError, ValueError, OverflowError):
        return ""


def _find_edge_profiles() -> list[Path]:
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if not local_app_data:
        return []
    user_data = Path(local_app_data) / "Microsoft" / "Edge" / "User Data"
    if not user_data.exists():
        return []
    profiles: list[Path] = []
    try:
        for entry in user_data.iterdir():
            if entry.is_dir() and (entry / "History").exists():
                profiles.append(entry)
    except (OSError, PermissionError):
        pass
    return profiles


def _parse_history_db(db_path: Path) -> tuple[list[dict], list[dict]]:
    """Parse Edge History SQLite DB. Returns (urls, downloads)."""
    urls: list[dict] = []
    downloads: list[dict] = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro&nolock=1", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC"
            )
            for row in cursor.fetchall():
                urls.append({
                    "url": row["url"],
                    "title": row["title"],
                    "visit_count": row["visit_count"],
                    "last_visit_time_raw": row["last_visit_time"],
                    "last_visit_time": webkit_to_iso(row["last_visit_time"]),
                })
        except sqlite3.OperationalError as e:
            logger.debug(f"Edge urls table error: {e}")

        try:
            cursor.execute(
                "SELECT target_path, tab_url, start_time, end_time FROM downloads ORDER BY start_time DESC"
            )
            for row in cursor.fetchall():
                downloads.append({
                    "target_path": row["target_path"],
                    "tab_url": row["tab_url"],
                    "start_time_raw": row["start_time"],
                    "start_time": webkit_to_iso(row["start_time"]),
                    "end_time_raw": row["end_time"],
                    "end_time": webkit_to_iso(row["end_time"]),
                })
        except sqlite3.OperationalError as e:
            logger.debug(f"Edge downloads table error: {e}")

        conn.close()
    except (sqlite3.Error, OSError) as e:
        logger.debug(f"Failed to parse Edge History DB {db_path}: {e}")
    return urls, downloads


@register_collector("browser_edge")
class EdgeCollector(CollectorBase):
    module_id = "browser_edge"
    module_name = "Microsoft Edge"
    category = ArtifactCategory.BROWSERS
    source_locations = ["%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\*"]
    required_privileges = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        profiles = _find_edge_profiles()
        if not profiles:
            result.status = CollectionStatus.NOT_AVAILABLE
            result.warnings.append("No Edge profiles found")
            return result

        collected_any = False
        all_urls: list[dict] = []
        all_downloads: list[dict] = []

        for profile_path in profiles:
            profile_name = profile_path.name
            dest_dir = self.evidence_dir / "edge" / profile_name

            for filename in SAFE_FILES + WAL_FILES:
                src = profile_path / filename
                if src.exists():
                    evidence = self.copy_file(src, dest_dir, f"edge_{profile_name}_{filename}")
                    if evidence:
                        evidence.metadata = {"browser": "Edge", "profile": profile_name}
                        result.acquired_files.append(evidence)
                        collected_any = True
                    else:
                        result.warnings.append(f"Failed to copy {src}")

            if self.parse:
                history_src = profile_path / "History"
                if history_src.exists():
                    acquired_history = dest_dir / "History"
                    db_to_parse = acquired_history if acquired_history.exists() else history_src
                    urls, downloads = _parse_history_db(db_to_parse)

                    for entry in urls:
                        entry["profile"] = profile_name
                    for entry in downloads:
                        entry["profile"] = profile_name

                    all_urls.extend(urls)
                    all_downloads.extend(downloads)

        if self.parse and (all_urls or all_downloads):
            parsed_dir = self.parsed_dir / "edge"
            parsed_dir.mkdir(parents=True, exist_ok=True)

            if all_urls:
                ev = self.save_json(all_urls, "edge_history.json", parsed_dir)
                if ev:
                    result.parsed_output_files.append(ev.acquired_path)
                    result.acquired_files.append(ev)

                csv_ev = self._write_csv(
                    all_urls,
                    ["profile", "url", "title", "visit_count", "last_visit_time"],
                    "edge_history.csv",
                    parsed_dir,
                )
                if csv_ev:
                    result.parsed_output_files.append(csv_ev.acquired_path)
                    result.acquired_files.append(csv_ev)

            if all_downloads:
                ev = self.save_json(all_downloads, "edge_downloads.json", parsed_dir)
                if ev:
                    result.parsed_output_files.append(ev.acquired_path)
                    result.acquired_files.append(ev)

                csv_ev = self._write_csv(
                    all_downloads,
                    ["profile", "target_path", "tab_url", "start_time", "end_time"],
                    "edge_downloads.csv",
                    parsed_dir,
                )
                if csv_ev:
                    result.parsed_output_files.append(csv_ev.acquired_path)
                    result.acquired_files.append(csv_ev)

            result.parser_name = "polaris_edge_parser"
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
