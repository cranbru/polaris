"""Semantic browser timeline events with stable links to captured source records."""
import hashlib
from datetime import datetime, timezone

EVENT_FIELDS = {
    "visits": [("visit_time", "Browser visit"), ("visit_date", "Browser visit")],
    "downloads": [("start_time", "Download started"), ("end_time", "Download completed or ended"), ("last_access_time", "Download last accessed")],
    "bookmarks": [("date_added", "Bookmark added"), ("last_modified", "Bookmark modified"), ("date_last_used", "Bookmark last used")],
    "extensions": [("first_install_time", "Extension installation recorded"), ("last_update_time", "Extension update recorded"), ("installDate", "Extension installation recorded"), ("updateDate", "Extension update recorded")],
    "permissions": [("last_modified", "Site permission modified"), ("modificationTime", "Site permission modified")],
}


def browser_events(record, source):
    if not isinstance(record, dict):
        return []
    dataset = source.split("_", 1)[-1]
    fields = EVENT_FIELDS.get(dataset, [])
    events = []
    for field, description in fields:
        value = record.get(field)
        if not value:
            continue
        try:
            instant = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if instant.tzinfo is None:
                continue  # Browser adapters emit explicit UTC, never guess a timezone.
            timestamp = instant.astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError, OverflowError):
            continue
        identity = "|".join(str(record.get(key, "")) for key in ("browser", "profile", "evidence_id", "source_record_id")) + "|" + field
        target = record.get("url") or record.get("target_path") or record.get("origin") or record.get("name") or record.get("id") or record.get("extension_id", "")
        if field == "start_time" and record.get("start_time_semantics"):
            description = "Download annotation created"
        events.append({
            "event_id": hashlib.sha256(identity.encode("utf-8", errors="surrogatepass")).hexdigest(),
            "timestamp": timestamp, "original_timestamp": str(record.get(field + "_raw", value)),
            "timezone": "UTC", "event_category": "browsers", "event_description": f"{description}: {target}",
            "event_type": description, "source_artifact": source, "source_field": field,
            "source_record_id": str(record.get("source_record_id", "")),
            "source_evidence_path": str(record.get("source_evidence_path", "")),
            "evidence_id": str(record.get("evidence_id", "")), "user": str(record.get("user", "")),
            "browser": str(record.get("browser", "")), "profile": str(record.get("profile", "")),
            "process_or_application": str(record.get("browser", "")),
        })
    return events
