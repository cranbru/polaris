"""Distinguish inapplicable logs/recovered hives from genuine acquisition gaps."""
from pathlib import Path

import pytest

from collectors.eventlogs import evtx_collector as evtx
from collectors.registry import hive_collector as hives
from config.settings import CollectionStatus


@pytest.mark.parametrize("unavailable,error,expected", [
    ("Microsoft-Windows-Sysmon/Operational", "The specified channel could not be found.", CollectionStatus.SUCCESS),
    ("Microsoft-Windows-Sysmon/Operational", "Error 0x3a9f", CollectionStatus.SUCCESS),
    ("Microsoft-Windows-Sysmon/Operational", "Access is denied.", CollectionStatus.PARTIAL),
    ("Security", "The specified channel could not be found.", CollectionStatus.PARTIAL),
])
def test_optional_absence_and_actual_export_failure(tmp_path, monkeypatch, unavailable, error, expected):
    monkeypatch.setattr(evtx, "TARGET_LOGS", ["Security", "System", "Microsoft-Windows-Sysmon/Operational"])
    queried = []

    def command(args, **kwargs):
        if args[1] == "qe":
            queried.append(args[2])
            return 0, "", ""
        if args[2] == unavailable:
            return 1, "", error
        Path(args[3]).write_bytes(b"EVTX fixture")
        return 0, "", ""

    monkeypatch.setattr(evtx, "run_command", command)
    result = evtx.EventLogCollector(tmp_path).collect()
    assert result.status == expected
    assert len(result.acquired_files) == 2
    assert result.warnings
    if expected == CollectionStatus.SUCCESS:
        assert unavailable not in queried


def test_no_exported_logs_remains_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(evtx, "run_command", lambda *a, **k: (1, "", "Access is denied"))
    result = evtx.EventLogCollector(tmp_path, parse=False).collect()
    assert result.status == CollectionStatus.FAILED
    assert result.errors


@pytest.mark.parametrize("failed_keys,empty_keys,expected,count", [
    (set(), set(), CollectionStatus.SUCCESS, 7),
    ({"HKCU"}, set(), CollectionStatus.PARTIAL, 6),
    (set(), {"HKCU"}, CollectionStatus.PARTIAL, 6),
    (set(hives.LIVE_HIVES.values()), set(), CollectionStatus.PARTIAL, 2),
    (set(hives.LIVE_HIVES.values()) | {"HKCU", r"HKCU\Software\Classes"}, set(), CollectionStatus.FAILED, 0),
])
def test_locked_user_hive_fallback_counts_only_unresolved_gaps(tmp_path, monkeypatch, failed_keys, empty_keys, expected, count):
    def save(key, destination, **kwargs):
        if key in failed_keys:
            return 1, "", "Access is denied"
        destination.write_bytes(b"" if key in empty_keys else b"Hive fixture")
        return 0, "", ""

    monkeypatch.setattr(hives, "_reg_save", save)
    monkeypatch.setattr(hives, "_get_user_hive_path", lambda filename, env: tmp_path / filename)
    monkeypatch.setattr(hives.RegistryHiveCollector, "copy_file", lambda *a, **k: None)
    result = hives.RegistryHiveCollector(tmp_path, parse=False).collect()
    assert result.status == expected
    assert result.artifact_count == count
    if expected == CollectionStatus.SUCCESS:
        assert len(result.warnings) == 2
        assert all("Acquired" in warning for warning in result.warnings)
        assert {item.metadata.get("requested_filename") for item in result.acquired_files[-2:]} == {"NTUSER.DAT", "UsrClass.dat"}
    else:
        assert result.errors or any("failed" in warning.lower() for warning in result.warnings)
