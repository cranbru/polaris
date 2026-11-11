"""Sanitized browser fixtures exercise acquisition, consumers and exclusions."""
import csv
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from collectors.browsers.chrome import ChromeCollector
from collectors.browsers.edge import EdgeCollector
from collectors.browsers.firefox import FirefoxCollector
from config.settings import CollectionStatus
from core.hash_manager import compute_sha256
from core.manifest import ManifestManager
from core.progress import AcquisitionCancelled, CancellationToken, processing_context
from core.timeline import TimelineBuilder, TimelineEvent
from parsers.browsers.chromium import parse_history, webkit_to_iso
from parsers.browsers.firefox import parse_places, prtime_to_iso
from reports.evidence_inspector import get_polaris_created_evidence_files

WEBKIT = 13_438_713_600_000_000
UNIX_US = 1_794_240_000_000_000


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def chromium_db(path):
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);
        CREATE TABLE downloads (id INTEGER, target_path TEXT, tab_url TEXT, start_time INTEGER, end_time INTEGER, state INTEGER, received_bytes INTEGER, total_bytes INTEGER, danger_type INTEGER, interrupt_reason INTEGER, mime_type TEXT);
        CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
        CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER, term TEXT);
    """)
    connection.executemany("INSERT INTO urls VALUES (?, ?, ?, ?, ?, ?)", [
        (1, "https://example.test/?token=fixture-secret", "=SUM(1,2)", 2, 1, WEBKIT + 2_000_000),
        (2, "https://download.test/file", "Download", 1, 0, WEBKIT + 3_000_000),
    ])
    connection.executemany("INSERT INTO visits VALUES (?, ?, ?, ?, ?, ?)", [
        (1, 1, WEBKIT, 0, 1, 1_000_000), (2, 1, WEBKIT + 2_000_000, 1, 0, 2_000_000),
        (3, 2, WEBKIT + 3_000_000, 2, 0x40000001, 1_000_000),
    ])
    connection.execute("INSERT INTO downloads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (7, "C:/Downloads/fixture.bin", "https://example.test", WEBKIT + 4_000_000, WEBKIT + 5_000_000, 1, 100, 100, 0, 0, "application/octet-stream"))
    connection.executemany("INSERT INTO downloads_url_chains VALUES (?, ?, ?)",
                           [(7, 1, "https://cdn.test/file"), (7, 0, "https://download.test/file")])
    connection.execute("INSERT INTO keyword_search_terms VALUES (1, 1, 'incident response')")
    connection.commit()
    return connection


def firefox_db(path):
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, from_visit INTEGER);
        CREATE TABLE moz_bookmarks (id INTEGER, type INTEGER, fk INTEGER, parent INTEGER, title TEXT, dateAdded INTEGER, lastModified INTEGER);
        CREATE TABLE moz_anno_attributes (id INTEGER, name TEXT);
        CREATE TABLE moz_annos (id INTEGER, place_id INTEGER, anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER, lastModified INTEGER);
    """)
    connection.execute("INSERT INTO moz_places VALUES (1, 'https://firefox.test/file', 'Fixture', 2, ?)", (UNIX_US + 1_000_000,))
    connection.executemany("INSERT INTO moz_historyvisits VALUES (?, 1, ?, 1, ?)", [(1, UNIX_US, 0), (2, UNIX_US + 1_000_000, 1)])
    connection.executemany("INSERT INTO moz_bookmarks VALUES (?, ?, ?, ?, ?, ?, ?)", [
        (1, 2, None, 0, "Bookmarks Menu", UNIX_US, UNIX_US),
        (2, 1, 1, 1, "Useful fixture", UNIX_US, UNIX_US + 1_000_000),
    ])
    connection.executemany("INSERT INTO moz_anno_attributes VALUES (?, ?)", [(1, "downloads/destinationFileURI"), (2, "downloads/metaData")])
    connection.executemany("INSERT INTO moz_annos VALUES (?, 1, ?, ?, ?, ?)", [
        (1, 1, "file:///C:/Downloads/firefox.bin", UNIX_US, UNIX_US),
        (2, 2, json.dumps({"state": 1, "fileSize": 321, "endTime": (UNIX_US + 2_000_000) // 1000}), UNIX_US, UNIX_US + 2_000_000),
    ])
    connection.commit()
    connection.close()


@pytest.fixture
def browser_environment(tmp_path, monkeypatch):
    local, roaming = tmp_path / "Local # data", tmp_path / "Roaming"
    local.mkdir()
    roaming.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(roaming))
    monkeypatch.setenv("USERNAME", "fixture-user")
    return local, roaming


@pytest.mark.parametrize("collector_type,root,slug", [
    (ChromeCollector, "Google/Chrome/User Data", "chrome"),
    (EdgeCollector, "Microsoft/Edge/User Data", "edge"),
])
def test_chromium_extended_capture_and_consumers(tmp_case_dir, browser_environment, collector_type, root, slug):
    profile = browser_environment[0] / root / "Profile #1"
    profile.mkdir(parents=True)
    chromium_db(profile / "History").close()
    write_json(profile / "Bookmarks", {"roots": {"bookmark_bar": {"type": "folder", "name": "Work", "children": [
        {"type": "url", "id": "10", "name": "Fixture", "url": "https://bookmark.test", "date_added": str(WEBKIT)}]}}})
    write_json(profile / "Preferences", {"homepage": "https://home.test", "password": "do-not-capture", "profile": {"content_settings": {"exceptions": {
        "notifications": {"https://notify.test,*": {"setting": 1, "last_modified": str(WEBKIT), "secret": "do-not-capture"}}}}},
        "extensions": {"settings": {"fixture-extension": {"state": 1, "oauth_token": "do-not-capture", "first_install_time": str(WEBKIT)}}}})
    write_json(profile / "Extensions/fixture-extension/1.0/manifest.json", {"name": "Fixture extension", "version": "1.0", "permissions": ["tabs"], "host_permissions": ["https://example.test/*"], "private_key": "do-not-capture"})
    for name in ("Cookies", "Login Data", "Web Data", "Local State", "Sessions/Session_123", "Local Extension Settings/fixture-extension/store.log"):
        path = profile / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("do-not-capture")

    result = collector_type(tmp_case_dir).collect()
    assert result.status == CollectionStatus.SUCCESS, result.warnings + result.errors
    parsed = tmp_case_dir / "parsed/browsers" / slug
    visits = json.loads((parsed / f"{slug}_visits.json").read_text())
    assert len(visits) == 3
    assert visits[2]["referrer_url"].startswith("https://example.test")
    assert visits[2]["transition_core"] == 1
    downloads = json.loads((parsed / f"{slug}_downloads.json").read_text())
    assert downloads[0]["url_chain"] == ["https://download.test/file", "https://cdn.test/file"]
    assert downloads[0]["total_bytes"] == 100
    assert json.loads((parsed / f"{slug}_bookmarks.json").read_text())[0]["folder"] == "Work"
    assert json.loads((parsed / f"{slug}_searches.json").read_text())[0]["term"] == "incident response"
    assert json.loads((parsed / f"{slug}_extensions.json").read_text())[0]["state"] == 1
    assert json.loads((parsed / f"{slug}_permissions.json").read_text())[0]["setting"] == 1
    for evidence in result.acquired_files:
        if evidence.filename != "History":
            assert "do-not-capture" not in Path(evidence.acquired_path).read_text(encoding="utf-8")
    assert {Path(item.acquired_path).name for item in result.acquired_files}.isdisjoint({"Cookies", "Login Data", "Web Data", "Local State"})
    with (parsed / f"{slug}_history.csv").open(newline="", encoding="utf-8") as stream:
        csv_records = list(csv.DictReader(stream))
    assert csv_records[0]["title"].startswith("'=")
    assert csv_records[1]["typed_count"] == "0"

    builder = TimelineBuilder(tmp_case_dir)
    builder.build_from_parsed()
    assert sum(event.event_type == "Browser visit" for event in builder.events) == 3
    assert len(builder.events) == 8  # visits + download endpoints + bookmark + extension + permission
    first_ids = {event.event_id for event in builder.events}
    assert len(first_ids) == len(builder.events)
    assert all(event.source_record_id and event.evidence_id and event.profile == "Profile #1" for event in builder.events)
    another = TimelineBuilder(tmp_case_dir)
    another.build_from_parsed()
    assert {event.event_id for event in another.events} == first_ids

    manager = ManifestManager(tmp_case_dir)
    manager.add_collection_result(result)
    manager.write_manifest()
    verification = manager.verify()
    assert len(verification["verified"]) == len(result.acquired_files)
    assert not verification["modified"] and not verification["unexpected"]
    from archive.zip_builder import ZipBuilder
    package, _ = ZipBuilder(tmp_case_dir).build_package()
    with zipfile.ZipFile(package) as archive:
        assert all(Path(item.acquired_path).relative_to(tmp_case_dir).as_posix() in archive.namelist() for item in result.acquired_files)


def test_firefox_bookmarks_downloads_permissions_extensions(tmp_case_dir, browser_environment):
    profile = browser_environment[1] / "Mozilla/Firefox/Profiles/fixture.default"
    profile.mkdir(parents=True)
    firefox_db(profile / "places.sqlite")
    with sqlite3.connect(profile / "permissions.sqlite") as connection:
        connection.execute("CREATE TABLE moz_perms (id INTEGER, origin TEXT, type TEXT, permission INTEGER, expireType INTEGER, expireTime INTEGER, modificationTime INTEGER)")
        connection.execute("INSERT INTO moz_perms VALUES (1, 'https://notify.test', 'desktop-notification', 1, 0, 0, ?)", (UNIX_US // 1000,))
    write_json(profile / "extensions.json", {"addons": [{"id": "fixture@test", "version": "1", "active": True, "installDate": UNIX_US // 1000, "defaultLocale": {"name": "Fixture"}, "secret": "excluded-value"}]})
    (profile / "prefs.js").write_text('user_pref("browser.startup.homepage", "https://home.test");\nuser_pref("secret", "excluded-value");')
    for name in ("cookies.sqlite", "key4.db", "logins.json", "formhistory.sqlite", "sessionstore.jsonlz4"):
        (profile / name).write_text("excluded-value")
    result = FirefoxCollector(tmp_case_dir).collect()
    assert result.status == CollectionStatus.SUCCESS, result.warnings + result.errors
    parsed = tmp_case_dir / "parsed/browsers/firefox"
    bookmarks = json.loads((parsed / "firefox_bookmarks.json").read_text())
    assert bookmarks[0]["folder"] == "Bookmarks Menu"
    downloads = json.loads((parsed / "firefox_downloads.json").read_text())
    assert downloads[0]["fileSize"] == 321
    assert downloads[0]["annotation_ids"] == [1, 2]
    assert downloads[0]["end_time"] == prtime_to_iso(UNIX_US + 2_000_000)
    assert json.loads((parsed / "firefox_permissions.json").read_text())[0]["permission"] == 1
    assert all("excluded-value" not in Path(item.acquired_path).read_text(encoding="utf-8", errors="ignore") for item in result.acquired_files)
    builder = TimelineBuilder(tmp_case_dir)
    builder.build_from_parsed()
    assert len(builder.events) == 8
    assert any(event.event_type == "Download annotation created" for event in builder.events)


def test_wal_capture_includes_committed_rows_and_is_immutable(tmp_case_dir, browser_environment):
    profile = browser_environment[0] / "Google/Chrome/User Data/Default"
    profile.mkdir(parents=True)
    connection = chromium_db(profile / "History")
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("INSERT INTO visits VALUES (4, 1, ?, 3, 0, 0)", (WEBKIT + 6_000_000,))
        connection.commit()
        assert (profile / "History-wal").exists()
        result = ChromeCollector(tmp_case_dir).collect()
        assert result.status == CollectionStatus.SUCCESS
        snapshot = next(item for item in result.acquired_files if item.filename == "History")
        snapshot_path = Path(snapshot.acquired_path)
        before = compute_sha256(snapshot_path)
        connection.execute("DELETE FROM visits")
        connection.commit()
        data = parse_history(snapshot_path, [])
        assert len(data["visits"]) == 4
        assert compute_sha256(snapshot_path) == before == snapshot.sha256
        assert snapshot.metadata["acquisition_method"] == "sqlite_backup"
        assert not snapshot_path.with_name("History-wal").exists()
    finally:
        connection.close()


@pytest.mark.parametrize("with_bookmarks", [False, True])
def test_capture_failure_never_parses_live_source(tmp_case_dir, browser_environment, monkeypatch, with_bookmarks):
    profile = browser_environment[0] / "Google/Chrome/User Data/Default"
    profile.mkdir(parents=True)
    chromium_db(profile / "History").close()
    if with_bookmarks:
        write_json(profile / "Bookmarks", {"roots": {}})
    collector = ChromeCollector(tmp_case_dir)

    def fail(*args):
        raise PermissionError("fixture access denied")

    monkeypatch.setattr(collector, "capture_database", fail)
    result = collector.collect()
    assert result.status == (CollectionStatus.PARTIAL if with_bookmarks else CollectionStatus.FAILED)
    assert not (tmp_case_dir / "parsed/browsers/chrome/chrome_visits.json").exists()
    inventory = json.loads((tmp_case_dir / "evidence/browsers/chrome/chrome_collection_inventory.json").read_text())
    assert inventory["artifacts"][0]["status"] == "failed"
    assert any("fixture access denied" in warning for warning in result.warnings)


def test_metadata_only_profiles_and_missing_browsers(tmp_case_dir, browser_environment):
    assert EdgeCollector(tmp_case_dir).collect().status == CollectionStatus.NOT_AVAILABLE
    for name in ("Default", "Profile 2"):
        write_json(browser_environment[0] / "Microsoft/Edge/User Data" / name / "Preferences", {"homepage": "https://fixture.test"})
    result = EdgeCollector(tmp_case_dir).collect()
    assert result.status == CollectionStatus.SUCCESS
    settings = json.loads((tmp_case_dir / "parsed/browsers/edge/edge_settings.json").read_text())
    assert {record["profile"] for record in settings} == {"Default", "Profile 2"}


@pytest.mark.parametrize("kind", ["corrupt", "timeout", "oversized_metadata", "malformed_metadata"])
def test_collection_gaps_and_atomic_cleanup(tmp_case_dir, browser_environment, monkeypatch, kind):
    profile = browser_environment[0] / "Google/Chrome/User Data/Default"
    profile.mkdir(parents=True)
    if kind == "corrupt":
        (profile / "History").write_text("not sqlite")
    elif kind == "timeout":
        chromium_db(profile / "History").close()
        monkeypatch.setattr("collectors.browsers.common.SNAPSHOT_TIMEOUT_SECONDS", -1)
    else:
        (profile / "Preferences").write_text("{" if kind == "malformed_metadata" else " " * (2 * 1024 * 1024 + 1))
    result = ChromeCollector(tmp_case_dir).collect()
    assert result.status in {CollectionStatus.FAILED, CollectionStatus.PARTIAL}
    assert result.warnings
    assert not list((tmp_case_dir / ".staging").glob("*.partial"))
    assert not (tmp_case_dir / "evidence/browsers/chrome/Default/History").exists()


def test_cancelled_snapshot_preserves_completed_files(tmp_case_dir, browser_environment):
    profile = browser_environment[0] / "Google/Chrome/User Data/Default"
    profile.mkdir(parents=True)
    chromium_db(profile / "History").close()
    token = CancellationToken()
    collector = ChromeCollector(tmp_case_dir)
    token.cancel()
    with processing_context(token), pytest.raises(AcquisitionCancelled):
        collector.collect()
    assert hasattr(collector, "partial_result")
    assert not list((tmp_case_dir / "evidence/browsers").rglob("History"))


def test_firefox_no_silent_50000_visit_limit(tmp_path):
    path = tmp_path / "places.sqlite"
    firefox_db(path)
    with sqlite3.connect(path) as connection:
        connection.executemany("INSERT INTO moz_historyvisits VALUES (?, 1, ?, 1, 0)", [(i, UNIX_US + i, ) for i in range(3, 50_004)])
    warnings = []
    assert len(parse_places(path, warnings)["visits"]) == 50_003
    assert not warnings


def test_legacy_firefox_download_database(tmp_case_dir, browser_environment):
    profile = browser_environment[1] / "Mozilla/Firefox/Profiles/legacy.default"
    profile.mkdir(parents=True)
    (profile / "prefs.js").write_text("")
    with sqlite3.connect(profile / "downloads.sqlite") as connection:
        connection.execute("CREATE TABLE moz_downloads (id INTEGER, source TEXT, target TEXT, startTime INTEGER, endTime INTEGER)")
        connection.execute("INSERT INTO moz_downloads VALUES (1, 'https://legacy.test', 'file:///C:/fixture', ?, ?)", (UNIX_US, UNIX_US + 1_000_000))
    result = FirefoxCollector(tmp_case_dir).collect()
    assert result.status == CollectionStatus.SUCCESS, result.warnings
    data = json.loads((tmp_case_dir / "parsed/browsers/firefox/firefox_downloads.json").read_text())
    assert data[0]["url"] == "https://legacy.test"


def test_browser_report_preview_redaction_preserves_raw(tmp_case_dir):
    path = tmp_case_dir / "parsed/browsers/chrome/chrome_visits.json"
    write_json(path, [{"url": "https://example.test/?token=fixture-secret", "title": "user@example.test"}])
    items = get_polaris_created_evidence_files(tmp_case_dir)
    preview = next(item for item in items if item["filename"] == path.name)
    assert "fixture-secret" not in json.dumps(preview["sample_records"])
    assert "user@example.test" not in preview["sample_text"]
    assert "fixture-secret" in path.read_text()


@pytest.mark.parametrize("converter", [webkit_to_iso, prtime_to_iso])
def test_browser_invalid_timestamps(converter):
    assert all(converter(value) == "" for value in (None, 0, -1, "invalid", 10**30))


def test_timeline_orders_timezone_offsets(tmp_case_dir):
    builder = TimelineBuilder(tmp_case_dir)
    builder.add_events([TimelineEvent(timestamp="2026-11-12T10:00:00+05:30"), TimelineEvent(timestamp="2026-11-12T05:00:00+00:00")])
    builder.sort_events()
    assert builder.events[0].timestamp.endswith("+05:30")


def test_unsupported_schema_retains_capture_and_reports_partial(tmp_case_dir, browser_environment):
    profile = browser_environment[0] / "Google/Chrome/User Data/Default"
    profile.mkdir(parents=True)
    with sqlite3.connect(profile / "History") as connection:
        connection.execute("CREATE TABLE urls (id INTEGER, url TEXT)")
        connection.execute("CREATE TABLE visits (id INTEGER, url INTEGER)")
    result = ChromeCollector(tmp_case_dir).collect()
    assert result.status == CollectionStatus.PARTIAL
    assert result.parser_status == "partial"
    assert any("visit_time" in warning for warning in result.warnings)
    assert any(evidence.filename == "History" for evidence in result.acquired_files)


def test_no_parse_still_captures_explicit_browser_scope(tmp_case_dir, browser_environment):
    profile = browser_environment[0] / "Microsoft/Edge/User Data/Default"
    profile.mkdir(parents=True)
    chromium_db(profile / "History").close()
    result = EdgeCollector(tmp_case_dir, parse=False).collect()
    assert result.status == CollectionStatus.SUCCESS
    assert result.parser_status is None
    assert not result.parsed_output_files
    assert any(evidence.filename == "History" for evidence in result.acquired_files)


def test_parsed_write_failure_changes_status(tmp_case_dir, browser_environment, monkeypatch):
    profile = browser_environment[0] / "Google/Chrome/User Data/Default"
    profile.mkdir(parents=True)
    chromium_db(profile / "History").close()
    collector = ChromeCollector(tmp_case_dir)
    original = collector.save_json

    def fail_visits(data, filename, *args, **kwargs):
        return None if filename == "chrome_visits.json" else original(data, filename, *args, **kwargs)

    monkeypatch.setattr(collector, "save_json", fail_visits)
    result = collector.collect()
    assert result.status == CollectionStatus.PARTIAL
    assert result.parser_status == "partial"
    assert any("chrome_visits.json" in warning for warning in result.warnings)


def test_cancel_during_backup_cleans_unpublished_snapshot(tmp_case_dir, browser_environment, monkeypatch):
    profile = browser_environment[0] / "Google/Chrome/User Data/Default"
    profile.mkdir(parents=True)
    chromium_db(profile / "History").close()
    collector = ChromeCollector(tmp_case_dir)
    calls = 0

    def cancel():
        nonlocal calls
        calls += 1
        raise AcquisitionCancelled("fixture cancellation during backup")

    monkeypatch.setattr("collectors.browsers.common.check_cancelled", cancel)
    with pytest.raises(AcquisitionCancelled):
        collector.capture_database(profile / "History", collector.evidence_dir / "captured", "fixture")
    assert calls > 0
    assert not (collector.evidence_dir / "captured").exists()
    assert not list((tmp_case_dir / ".staging").glob("*.partial"))
