"""Explicit browser artifact scope, consistent acquisition and derived exports."""
import csv
import json
import os
import re
import sqlite3
import time
from contextlib import closing
from io import StringIO
from pathlib import Path

from config.settings import CollectionStatus, get_iso_timestamp
from core.collector_base import CollectorBase, FileEvidence
from core.hash_manager import compute_sha256
from core.progress import check_cancelled, observe_operation
from parsers.browsers.chromium import parse_history, parse_bookmarks
from parsers.browsers.firefox import parse_places, parse_permissions
from parsers.browsers.sqlite_utils import timestamp_to_iso, convert_times

PARSER_VERSION = "2.0"
MAX_METADATA_BYTES = 2 * 1024 * 1024
SNAPSHOT_TIMEOUT_SECONDS = 10


def find_profiles(env_name, relative_root, markers):
    base = os.environ.get(env_name)
    if not base:
        return []
    root = Path(base) / relative_root
    try:
        return sorted((entry for entry in root.iterdir()
                       if entry.is_dir() and not entry.is_symlink()
                       and contained(entry, root)
                       and any((entry / marker).exists() for marker in markers)), key=lambda entry: entry.name.casefold())
    except OSError:
        return []


def contained(path, root):
    try:
        return path.resolve().is_relative_to(root.resolve())
    except OSError:
        return False


def read_metadata(path, profile):
    check_cancelled()
    if not contained(path, profile) or path.is_symlink():
        raise ValueError("Browser metadata path leaves its profile")
    if path.stat().st_size > MAX_METADATA_BYTES:
        raise ValueError("Browser metadata exceeds the 2 MiB read budget")
    return path.read_text(encoding="utf-8")


def selected(mapping, keys):
    if not isinstance(mapping, dict):
        return {}
    return {key: mapping[key] for key in keys if key in mapping}


def chromium_metadata(profile, warnings):
    """Project browser configuration; never copy whole Preferences or Local State."""
    data = {name: [] for name in ("settings", "extensions", "permissions")}
    extension_settings = {}
    for filename in ("Preferences", "Secure Preferences"):
        path = profile / filename
        if not path.exists():
            continue
        try:
            preferences = json.loads(read_metadata(path, profile))
            for section, keys in {
                "browser": ("show_home_button",),
                "download": ("default_directory", "prompt_for_download"),
                "session": ("restore_on_startup", "startup_urls"),
            }.items():
                for key, value in selected(preferences.get(section), keys).items():
                    data["settings"].append({"name": f"{section}.{key}", "value": value,
                                             "source_record_id": f"{filename}:{section}.{key}"})
            if "homepage" in preferences:
                data["settings"].append({"name": "homepage", "value": preferences["homepage"], "source_record_id": f"{filename}:homepage"})
            extensions = preferences.get("extensions", {}).get("settings", {})
            if isinstance(extensions, dict):
                for extension_id, item in extensions.items():
                    extension_settings.setdefault(extension_id, {}).update(selected(item, (
                        "state", "location", "from_webstore", "first_install_time", "last_update_time", "disable_reasons")))
            # Restrict site exceptions to permission fields, excluding arbitrary website storage.
            exceptions = preferences.get("profile", {}).get("content_settings", {}).get("exceptions", {})
            if isinstance(exceptions, dict):
                for permission_type in ("notifications", "geolocation", "media_stream_camera", "media_stream_mic", "popups", "automatic_downloads", "clipboard", "usb_guard", "serial_guard", "file_system_write_guard"):
                    entries = exceptions.get(permission_type, {})
                    if not isinstance(entries, dict):
                        continue
                    for origin, permission in entries.items():
                        if isinstance(permission, dict):
                            data["permissions"].append({"origin": origin, "permission_type": permission_type,
                                **selected(permission, ("setting", "last_modified", "expiration")),
                                "source_record_id": f"{filename}:permissions:{permission_type}:{origin}"})
        except (OSError, ValueError, TypeError, AttributeError) as error:
            warnings.append(f"Unable to read {filename} metadata: {error}")

    root = profile / "Extensions"
    if root.exists() and contained(root, profile):
        try:
            for extension_dir in sorted(root.iterdir()):
                check_cancelled()
                if not extension_dir.is_dir() or not contained(extension_dir, profile):
                    continue
                for version_dir in sorted(extension_dir.iterdir()):
                    path = version_dir / "manifest.json"
                    if not path.is_file():
                        continue
                    try:
                        manifest = json.loads(read_metadata(path, profile))
                        data["extensions"].append({"extension_id": extension_dir.name,
                            "installed_directory": str(version_dir),
                            **selected(manifest, ("name", "version", "description", "manifest_version", "permissions", "host_permissions", "optional_permissions", "update_url", "homepage_url")),
                            **extension_settings.get(extension_dir.name, {}),
                            "source_record_id": str(path.relative_to(profile)).replace("\\", "/")})
                    except (OSError, ValueError, TypeError) as error:
                        warnings.append(f"Unable to read extension manifest {extension_dir.name}/{version_dir.name}: {error}")
        except OSError as error:
            warnings.append(f"Unable to list browser extensions: {error}")
    manifest_ids = {row["extension_id"] for row in data["extensions"]}
    for extension_id, configuration in extension_settings.items():
        if extension_id not in manifest_ids:
            data["extensions"].append({"extension_id": extension_id, **configuration,
                                       "manifest_available": False, "source_record_id": f"extension_settings:{extension_id}"})
    return data


def firefox_metadata(profile, warnings):
    data = {name: [] for name in ("settings", "extensions", "permissions")}
    path = profile / "extensions.json"
    if path.exists():
        try:
            document = json.loads(read_metadata(path, profile))
            for addon in document.get("addons", []):
                check_cancelled()
                record = selected(addon, ("id", "version", "type", "active", "userDisabled", "appDisabled", "installDate", "updateDate", "signedState", "sourceURI", "userPermissions"))
                record.update(selected(addon.get("defaultLocale"), ("name", "description")))
                record["source_record_id"] = f"extensions.json:{addon.get('id', '')}"
                data["extensions"].append(record)
        except (OSError, ValueError, TypeError, AttributeError) as error:
            warnings.append(f"Unable to read Firefox extension metadata: {error}")
    path = profile / "prefs.js"
    if path.exists():
        try:
            text = read_metadata(path, profile)
            allowed = {"browser.startup.homepage", "browser.startup.page", "browser.download.dir", "browser.download.folderList", "browser.download.useDownloadDir", "extensions.lastAppVersion", "browser.search.region"}
            for match in re.finditer(r'user_pref\("([^"\\]+)",\s*(.*?)\);', text):
                name, value = match.groups()
                if name in allowed:
                    data["settings"].append({"name": name, "value": json.loads(value), "source_record_id": f"prefs.js:{name}"})
        except (OSError, ValueError, TypeError) as error:
            warnings.append(f"Unable to read selected Firefox preferences: {error}")
    return data


class BrowserCollector(CollectorBase):
    browser = ""
    slug = ""
    required_privileges = "user"

    def find_profiles(self):
        raise NotImplementedError

    def capture_database(self, source, destination, evidence_id):
        """Capture a logical SQLite snapshot including committed WAL records.

        The backup API reads one consistent database state. The snapshot is not
        a byte-for-byte disk image and omits deleted/uncommitted records.
        No fallback ever parses a live database after a failed acquisition.
        """
        observe_operation(f"Capturing {self.browser} database", str(source))
        started = get_iso_timestamp()
        deadline = time.monotonic() + SNAPSHOT_TIMEOUT_SECONDS
        tables = []

        def copy(temporary):
            def progress(status, remaining, total):
                check_cancelled()
                if time.monotonic() > deadline:
                    raise TimeoutError("SQLite snapshot exceeded its 10 second acquisition budget")
            with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.25)) as live:
                with closing(sqlite3.connect(str(temporary))) as captured:
                    live.backup(captured, pages=256, progress=progress, sleep=0.05)
                    if captured.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                        raise sqlite3.DatabaseError("Captured database failed quick_check")
                    tables.extend(row[0] for row in captured.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"))

        destination.parent.mkdir(parents=True, exist_ok=True)
        size = self._publish_file(destination, copy)
        return FileEvidence(evidence_id=evidence_id, original_path=str(source), acquired_path=str(destination),
            filename=destination.name, extension=destination.suffix, file_size=size, sha256=compute_sha256(destination),
            metadata={"browser": self.browser, "profile": source.parent.name, "sensitive": True,
                      "acquisition_method": "sqlite_backup", "wal_included": True,
                      "acquisition_start": started, "acquisition_end": get_iso_timestamp(),
                      "tables": tables,
                      "snapshot_scope": "committed logical database; excludes deleted and uncommitted records"})

    def _collect(self, result):
        profiles = self.find_profiles()
        if not profiles:
            result.status = CollectionStatus.NOT_AVAILABLE
            result.warnings.append(f"No {self.browser} profiles found for the current Windows account")
            return result
        inventory, datasets = [], {}
        capture_count, parsing_attempts = 0, 0
        parser_warnings = []
        user = os.environ.get("USERNAME", "")

        def ingest(data, evidence, profile_name):
            nonlocal parsing_attempts
            parsing_attempts += 1
            for dataset, records in data.items():
                target = datasets.setdefault(dataset, [])
                for record in records:
                    check_cancelled()
                    if dataset == "extensions":
                        if self.slug == "firefox":
                            convert_times(record, ["installDate", "updateDate"], lambda value: timestamp_to_iso(value, units=1000))
                        else:
                            convert_times(record, ["first_install_time", "last_update_time"], lambda value: timestamp_to_iso(value, epoch_year=1601))
                    elif dataset == "permissions" and self.slug != "firefox":
                        convert_times(record, ["last_modified", "expiration"], lambda value: timestamp_to_iso(value, epoch_year=1601))
                    record.update(browser=self.browser, profile=profile_name, user=user,
                                  evidence_id=evidence.evidence_id,
                                  source_evidence_path=str(Path(evidence.acquired_path).relative_to(self.case_dir)),
                                  parser_version=PARSER_VERSION, timezone="UTC")
                    target.append(record)

        for profile in profiles:
            check_cancelled()
            profile_name = profile.name
            destination = self.evidence_dir / self.slug / profile_name
            filenames = ["places.sqlite", "permissions.sqlite", "downloads.sqlite"] if self.slug == "firefox" else ["History", "Bookmarks"]
            for filename in filenames:
                check_cancelled()
                source = profile / filename
                item = {"profile": profile_name, "artifact": filename, "source_path": str(source), "status": "not_available"}
                inventory.append(item)
                if not source.exists():
                    continue
                evidence_id = f"{self.slug}_{profile_name}_{filename}"
                try:
                    if not contained(source, profile) or source.is_symlink():
                        raise ValueError("Browser artifact path leaves its profile")
                    if filename == "Bookmarks":
                        evidence = self.copy_file_raw(source, destination / filename, evidence_id)
                        if evidence is None:
                            raise OSError("File copy failed")
                        evidence.metadata.update(browser=self.browser, profile=profile_name, sensitive=True, acquisition_method="file_copy")
                        evidence.sha256 = compute_sha256(Path(evidence.acquired_path))
                    else:
                        evidence = self.capture_database(source, destination / filename, evidence_id)
                    result.acquired_files.append(evidence)
                    capture_count += 1
                    item.update(status="acquired", evidence_id=evidence.evidence_id,
                                acquisition_method=evidence.metadata["acquisition_method"], tables=evidence.metadata.get("tables", []))
                except (OSError, sqlite3.Error, ValueError, TimeoutError) as error:
                    item.update(status="failed", error=str(error))
                    result.warnings.append(f"Failed to acquire {self.browser} {profile_name}/{filename}: {error}")
                    continue
                if self.parse:
                    captured_path = Path(evidence.acquired_path)
                    if filename == "Bookmarks":
                        data = {"bookmarks": parse_bookmarks(captured_path, parser_warnings)}
                    elif filename == "History":
                        data = parse_history(captured_path, parser_warnings)
                    elif filename == "permissions.sqlite":
                        data = {"permissions": parse_permissions(captured_path, parser_warnings)}
                    else:
                        data = parse_places(captured_path, parser_warnings, downloads_only=filename == "downloads.sqlite")
                        if filename == "downloads.sqlite":
                            data = {"downloads": data["downloads"]}
                    ingest(data, evidence, profile_name)

            # Selected JSON fields form a preserved source snapshot for metadata parsing.
            metadata_warnings = []
            metadata = (firefox_metadata if self.slug == "firefox" else chromium_metadata)(profile, metadata_warnings)
            result.warnings.extend(metadata_warnings)
            sources_present = any((profile / name).exists() for name in
                (("extensions.json", "prefs.js") if self.slug == "firefox" else ("Preferences", "Secure Preferences", "Extensions")))
            if sources_present:
                item = {"profile": profile_name, "artifact": "selected_metadata.json", "status": "failed"}
                inventory.append(item)
                if metadata_warnings and not any(metadata.values()):
                    item["errors"] = metadata_warnings
                    continue
                evidence = self.save_json(metadata, "selected_metadata.json", destination, f"{self.slug}_{profile_name}_metadata")
                if evidence:
                    evidence.original_path = str(profile)
                    evidence.metadata.update(browser=self.browser, profile=profile_name, sensitive=True,
                                             acquisition_method="selected_metadata_snapshot", scope="settings, extensions and site permissions only")
                    evidence.sha256 = compute_sha256(Path(evidence.acquired_path))
                    result.acquired_files.append(evidence)
                    capture_count += 1
                    item.update(status="partial" if metadata_warnings else "acquired", evidence_id=evidence.evidence_id)
                    if self.parse:
                        # Re-read the published snapshot, never the live JSON source.
                        ingest(json.loads(Path(evidence.acquired_path).read_text(encoding="utf-8")), evidence, profile_name)
                else:
                    result.warnings.append(f"Failed to save {self.browser} metadata for {profile_name}")

        result.warnings.extend(parser_warnings)
        if self.parse:
            result.parser_name = f"polaris_{self.slug}_parser"
            result.parser_version = PARSER_VERSION
            result.parser_status = "partial" if parser_warnings else ("completed" if parsing_attempts else "not_available")
            warnings_before_exports = len(result.warnings)
            for dataset, records in datasets.items():
                self.write_dataset(result, dataset, records)
            if len(result.warnings) > warnings_before_exports:
                result.parser_status = "partial"

        summary = {"browser": self.browser, "account": user, "scope": "profiles of the current Windows account",
                   "profiles": [profile.name for profile in profiles], "artifacts": inventory,
                   "parsed_record_counts": {key: len(value) for key, value in datasets.items()},
                   "parser_status": result.parser_status, "warnings": result.warnings,
                   "exclusions": ["passwords", "cookies", "session tokens", "autofill", "form history", "website storage", "page cache", "session recovery"]}
        evidence = self.save_json(summary, f"{self.slug}_collection_inventory.json", self.evidence_dir / self.slug,
                                  f"{self.slug}_collection_inventory")
        if evidence:
            result.acquired_files.append(evidence)
        else:
            result.warnings.append("Failed to save browser collection inventory")
        result.status = (CollectionStatus.PARTIAL if result.warnings else CollectionStatus.SUCCESS) if capture_count else CollectionStatus.FAILED
        return result

    def write_dataset(self, result, dataset, records):
        directory = self.parsed_dir / self.slug
        filename = f"{self.slug}_{dataset}"
        evidence = self.save_json(records, filename + ".json", directory, filename + "_json")
        if evidence:
            evidence.metadata.update(browser=self.browser, sensitive=True, derived=True, parser_version=PARSER_VERSION)
            result.acquired_files.append(evidence)
            result.parsed_output_files.append(evidence.acquired_path)
        else:
            result.warnings.append(f"Failed to save {filename}.json")
        if not records:
            return
        buffer = StringIO()
        fields = list(dict.fromkeys(key for row in records for key in row))
        writer = csv.DictWriter(buffer, fieldnames=fields)
        writer.writeheader()
        for row in records:
            check_cancelled()
            safe_row = {}
            for key, value in row.items():
                text = json.dumps(value, ensure_ascii=True) if isinstance(value, (dict, list)) else ("" if value is None else str(value))
                safe_row[key] = "'" + text if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text
            writer.writerow(safe_row)
        evidence = self.save_text(buffer.getvalue(), filename + ".csv", directory, filename + "_csv")
        if evidence:
            evidence.metadata.update(browser=self.browser, sensitive=True, derived=True, formula_escaping=True)
            result.acquired_files.append(evidence)
            result.parsed_output_files.append(evidence.acquired_path)
        else:
            result.warnings.append(f"Failed to save {filename}.csv")
