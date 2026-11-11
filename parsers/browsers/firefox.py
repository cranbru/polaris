"""Firefox Places and site permission adapters."""
import json
import sqlite3
from pathlib import Path

from parsers.browsers.sqlite_utils import open_snapshot, rows, convert_times, timestamp_to_iso


def prtime_to_iso(value):
    return timestamp_to_iso(value)


def parse_places(path: Path, warnings: list[str], downloads_only=False) -> dict[str, list[dict]]:
    data = {name: [] for name in ("places", "visits", "bookmarks", "downloads")}
    try:
        with open_snapshot(path) as connection:
            places = rows(connection, "moz_places", ["id", "url", "title", "visit_count", "last_visit_date", "typed", "hidden", "frecency", "guid"], warnings, required=not downloads_only, required_fields=("id", "url"))
            place_map = {row.get("id"): row for row in places}
            for row in places:
                row["source_record_id"] = f"moz_places:{row.get('id', '')}"
                data["places"].append(convert_times(row, ["last_visit_date"], prtime_to_iso))
            visits = rows(connection, "moz_historyvisits", ["id", "place_id", "visit_date", "visit_type", "from_visit", "session"], warnings, required=not downloads_only, required_fields=("id", "place_id", "visit_date"))
            visit_map = {row.get("id"): row for row in visits}
            for row in visits:
                place = place_map.get(row.get("place_id"), {})
                referrer = visit_map.get(row.get("from_visit"), {})
                row.update(url=place.get("url", ""), title=place.get("title", ""),
                           referrer_url=place_map.get(referrer.get("place_id"), {}).get("url", ""),
                           source_record_id=f"moz_historyvisits:{row.get('id', '')}")
                data["visits"].append(convert_times(row, ["visit_date"], prtime_to_iso))

            bookmarks = rows(connection, "moz_bookmarks", ["id", "type", "fk", "parent", "position", "title", "dateAdded", "lastModified", "guid"], warnings)
            bookmark_map = {row.get("id"): row for row in bookmarks}
            for row in bookmarks:
                if row.get("type") != 1:
                    continue
                folder, seen, parent = [], set(), row.get("parent")
                while parent in bookmark_map and parent not in seen:
                    seen.add(parent)
                    folder.append(bookmark_map[parent].get("title") or "")
                    parent = bookmark_map[parent].get("parent")
                row.update(url=place_map.get(row.get("fk"), {}).get("url", ""),
                           folder="/".join(reversed([name for name in folder if name])),
                           source_record_id=f"moz_bookmarks:{row.get('id', '')}")
                row["date_added"] = row.pop("dateAdded", None)
                row["last_modified"] = row.pop("lastModified", None)
                data["bookmarks"].append(convert_times(row, ["date_added", "last_modified"], prtime_to_iso))

            attrs = rows(connection, "moz_anno_attributes", ["id", "name"], warnings)
            attr_map = {row.get("id"): row.get("name") for row in attrs}
            download_map = {}
            for row in rows(connection, "moz_annos", ["id", "place_id", "anno_attribute_id", "content", "dateAdded", "lastModified"], warnings):
                name = attr_map.get(row.get("anno_attribute_id"))
                if name not in {"downloads/destinationFileURI", "downloads/metaData"}:
                    continue
                entry = download_map.setdefault(row.get("place_id"), {
                    "source_record_id": f"moz_annos:place:{row.get('place_id')}",
                    "url": place_map.get(row.get("place_id"), {}).get("url", ""),
                    "annotation_ids": [],
                })
                entry["annotation_ids"].append(row.get("id"))
                if name == "downloads/destinationFileURI":
                    entry["target_path"] = row.get("content", "")
                    entry["start_time_raw"] = row.get("dateAdded")
                    entry["start_time"] = prtime_to_iso(row.get("dateAdded"))
                    entry["start_time_semantics"] = "download annotation creation"
                else:
                    try:
                        metadata = json.loads(row.get("content") or "{}")
                        for key in ("state", "fileSize"):
                            if key in metadata:
                                entry[key] = metadata[key]
                        entry["end_time_raw"] = metadata.get("endTime")
                        entry["end_time"] = timestamp_to_iso(metadata.get("endTime"), units=1000)
                    except (ValueError, TypeError):
                        warnings.append(f"Malformed Firefox download metadata at annotation {row.get('id')}")
            data["downloads"].extend(download_map.values())
            # Old Firefox releases used a standalone downloads database/table.
            for row in rows(connection, "moz_downloads", ["id", "name", "source", "target", "startTime", "endTime", "state", "currBytes", "maxBytes", "mimeType"], warnings):
                row.update(url=row.pop("source", ""), target_path=row.pop("target", ""),
                           start_time=row.pop("startTime", None), end_time=row.pop("endTime", None),
                           source_record_id=f"moz_downloads:{row.get('id', '')}")
                data["downloads"].append(convert_times(row, ["start_time", "end_time"], prtime_to_iso))
    except (sqlite3.Error, OSError) as error:
        warnings.append(f"Unable to parse captured places.sqlite: {error}")
    return data


def parse_permissions(path: Path, warnings: list[str]) -> list[dict]:
    records = []
    try:
        with open_snapshot(path) as connection:
            for row in rows(connection, "moz_perms", ["id", "origin", "type", "permission", "expireType", "expireTime", "modificationTime"], warnings, required=True):
                row["source_record_id"] = f"moz_perms:{row.get('id', '')}"
                records.append(convert_times(row, ["expireTime", "modificationTime"], lambda value: timestamp_to_iso(value, units=1000)))
    except (sqlite3.Error, OSError) as error:
        warnings.append(f"Unable to parse captured permissions.sqlite: {error}")
    return records
