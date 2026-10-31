from datetime import datetime, timezone
from typing import Optional


def parse_windows_filetime(filetime: int) -> Optional[datetime]:
    if filetime <= 0:
        return None
    try:
        epoch_diff = 116444736000000000
        if filetime < epoch_diff:
            return None
        timestamp = (filetime - epoch_diff) / 10_000_000
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OSError, ValueError, OverflowError):
        return None


def parse_unix_timestamp(ts: float) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OSError, ValueError, OverflowError):
        return None


def format_timestamp(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return dt.isoformat()


def safe_isoformat(value: str | datetime | None) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def filetime_to_iso(filetime: int) -> str:
    dt = parse_windows_filetime(filetime)
    return format_timestamp(dt)
