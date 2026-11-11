"""Chromium history, download, search and bookmark adapters (no credentials)."""
import json
import sqlite3
from pathlib import Path

from core.progress import check_cancelled
from parsers.browsers.sqlite_utils import open_snapshot, rows, convert_times, timestamp_to_iso


def webkit_to_iso(value):
    return timestamp_to_iso(value, epoch_year=1601)


def parse_history(path: Path, warnings: list[str]) -> dict[str, list[dict]]:
    data = {name: [] for name in ("history", "visits", "downloads", "searches")}
    try:
        with open_snapshot(path) as connection:
            urls = rows(connection, "urls", ["id", "url", "title", "visit_count", "typed_count", "last_visit_time", "hidden"], warnings, required=True, required_fields=("id", "url"))
            url_map = {row.get("id"): row for row in urls}
            for row in urls:
                row["source_record_id"] = f"urls:{row.get('id', '')}"
                data["history"].append(convert_times(row, ["last_visit_time"], webkit_to_iso))

            visits = rows(connection, "visits", ["id", "url", "visit_time", "from_visit", "transition", "visit_duration", "opener_visit"], warnings, required=True, required_fields=("id", "url", "visit_time"))
            visit_map = {row.get("id"): row for row in visits}
            for row in visits:
                url_id = row.get("url")
                url = url_map.get(url_id, {})
                previous = visit_map.get(row.get("from_visit"), {})
                row.update(url_id=url_id, url=url.get("url", ""), title=url.get("title", ""),
                           referrer_url=url_map.get(previous.get("url_id", previous.get("url")), {}).get("url", ""),
                           source_record_id=f"visits:{row.get('id', '')}")
                if "transition" in row and isinstance(row["transition"], int):
                    row["transition_core"] = row["transition"] & 0xFF
                data["visits"].append(convert_times(row, ["visit_time"], webkit_to_iso))

            chains = rows(connection, "downloads_url_chains", ["id", "chain_index", "url"], warnings)
            chain_map: dict[int, list[dict]] = {}
            for row in chains:
                chain_map.setdefault(row.get("id"), []).append(row)
            for row in rows(connection, "downloads", ["id", "guid", "current_path", "target_path", "start_time", "end_time", "received_bytes", "total_bytes", "state", "danger_type", "interrupt_reason", "opened", "tab_url", "tab_referrer_url", "site_url", "referrer", "mime_type", "original_mime_type", "last_access_time", "transient", "url"], warnings):
                chain = sorted(chain_map.get(row.get("id"), []), key=lambda item: item.get("chain_index", 0))
                row["url_chain"] = [item.get("url", "") for item in chain]
                row["source_record_id"] = f"downloads:{row.get('id', '')}"
                data["downloads"].append(convert_times(row, ["start_time", "end_time", "last_access_time"], webkit_to_iso))

            for row in rows(connection, "keyword_search_terms", ["keyword_id", "url_id", "term", "normalized_term"], warnings):
                row.update(url=url_map.get(row.get("url_id"), {}).get("url", ""),
                           source_record_id=f"keyword_search_terms:{row.get('keyword_id', '')}:{row.get('url_id', '')}")
                # A URL's last visit is not a timestamp of this particular search.
                data["searches"].append(row)
    except (sqlite3.Error, OSError) as error:
        warnings.append(f"Unable to parse captured History: {error}")
    return data


def parse_bookmarks(path: Path, warnings: list[str]) -> list[dict]:
    records = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        stack = [(node, "") for node in data.get("roots", {}).values() if isinstance(node, dict)]
        while stack:
            check_cancelled()
            node, parent = stack.pop()
            if node.get("type") == "url":
                record = {key: node[key] for key in ("id", "guid", "name", "url", "date_added", "date_last_used") if key in node}
                record.update(folder=parent, source_record_id=f"bookmarks:{node.get('id', node.get('guid', ''))}")
                records.append(convert_times(record, ["date_added", "date_last_used"], webkit_to_iso))
            else:
                folder = "/".join(filter(None, (parent, str(node.get("name", "")))))
                stack.extend((child, folder) for child in node.get("children", []) if isinstance(child, dict))
    except (OSError, ValueError, AttributeError, TypeError) as error:
        warnings.append(f"Unable to parse captured Bookmarks: {error}")
    return records
