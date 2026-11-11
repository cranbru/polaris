"""Read captured, standalone SQLite snapshots without modifying evidence."""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.progress import check_cancelled


def timestamp_to_iso(value, epoch_year=1970, units=1_000_000):
    try:
        number = int(value)
        if number <= 0:
            return ""
        return (datetime(epoch_year, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=number * (1_000_000 // units))).isoformat()
    except (TypeError, ValueError, OverflowError):
        return ""


@contextmanager
def open_snapshot(path: Path):
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def columns(connection, table):
    # Names are internal adapter constants, never evidence values.
    return {row["name"] for row in connection.execute(f'PRAGMA table_info("{table}")')}


def rows(connection, table, fields, warnings, required=False, required_fields=()):
    available = columns(connection, table)
    if not available:
        if required:
            warnings.append(f"Required browser table unavailable: {table}")
        return []
    missing = set(required_fields) - available
    if missing:
        warnings.append(f"Unsupported browser schema in {table}; missing fields: {', '.join(sorted(missing))}")
        return []
    selected = [field for field in fields if field in available]
    if not selected:
        warnings.append(f"Unsupported browser schema: {table}")
        return []
    try:
        query = ", ".join(f'"{field}"' for field in selected)
        records = []
        for index, row in enumerate(connection.execute(f'SELECT {query} FROM "{table}"')):
            if index % 256 == 0:
                check_cancelled()
            records.append(dict(row))
        return records
    except sqlite3.Error as error:
        warnings.append(f"Unable to parse {table}: {error}")
        return []


def convert_times(record, fields, converter):
    for field in fields:
        if field in record:
            record[field + "_raw"] = record[field]
            record[field] = converter(record[field])
    return record
