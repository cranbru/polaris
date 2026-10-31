from __future__ import annotations

import csv
import json
import logging
import os
import struct
from pathlib import Path
from typing import Optional

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp
from utils.filesystem import safe_glob

logger = logging.getLogger("polaris.jump_lists")


def _get_jumplist_dirs() -> tuple[Path | None, Path | None]:
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return None, None

    auto_dir = Path(appdata) / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations"
    custom_dir = Path(appdata) / "Microsoft" / "Windows" / "Recent" / "CustomDestinations"

    auto_result = auto_dir if auto_dir.exists() else None
    custom_result = custom_dir if custom_dir.exists() else None
    return auto_result, custom_result


def _parse_automatic_destinations(file_path: Path) -> list[dict[str, str]]:
    try:
        import olefile  # type: ignore[import-untyped]
    except ImportError:
        return []

    entries: list[dict[str, str]] = []
    try:
        if not olefile.isOleFile(str(file_path)):
            return []

        ole = olefile.OleFileIO(str(file_path))
        try:
            for stream_name in ole.listdir():
                stream_path = "/".join(stream_name)
                if stream_path.lower() == "destlist":
                    continue

                try:
                    data = ole.openstream(stream_name).read()
                    entry = _extract_lnk_info_from_stream(data, file_path.name, stream_path)
                    if entry:
                        entries.append(entry)
                except Exception:
                    continue
        finally:
            ole.close()
    except Exception as e:
        logger.debug(f"Failed to parse automatic destination {file_path}: {e}")

    return entries


def _extract_lnk_info_from_stream(
    data: bytes,
    jumplist_file: str,
    stream_name: str,
) -> Optional[dict[str, str]]:
    entry: dict[str, str] = {
        "jumplist_file": jumplist_file,
        "stream": stream_name,
        "target_path": "",
        "file_size": "",
        "creation_time": "",
        "modification_time": "",
        "access_time": "",
    }

    if len(data) < 76:
        return entry

    header_sig = data[:4]
    if header_sig != b"\x4c\x00\x00\x00":
        return entry

    try:
        creation_ft = struct.unpack_from("<Q", data, 28)[0]
        access_ft = struct.unpack_from("<Q", data, 36)[0]
        write_ft = struct.unpack_from("<Q", data, 44)[0]
        file_size_val = struct.unpack_from("<I", data, 52)[0]

        from utils.timestamps import filetime_to_iso
        entry["creation_time"] = filetime_to_iso(creation_ft)
        entry["access_time"] = filetime_to_iso(access_ft)
        entry["modification_time"] = filetime_to_iso(write_ft)
        entry["file_size"] = str(file_size_val)
    except (struct.error, Exception):
        pass

    try:
        offset = 76
        flags = struct.unpack_from("<I", data, 20)[0]

        has_link_target_idlist = bool(flags & 0x01)
        has_link_info = bool(flags & 0x02)

        if has_link_target_idlist and offset < len(data) - 2:
            idlist_size = struct.unpack_from("<H", data, offset)[0]
            offset += 2 + idlist_size

        if has_link_info and offset < len(data) - 4:
            link_info_size = struct.unpack_from("<I", data, offset)[0]
            link_info_end = offset + link_info_size

            if offset + 28 < len(data):
                local_base_path_offset = struct.unpack_from("<I", data, offset + 16)[0]
                abs_offset = offset + local_base_path_offset
                if abs_offset < link_info_end and abs_offset < len(data):
                    null_pos = data.find(b"\x00", abs_offset)
                    if null_pos != -1:
                        entry["target_path"] = data[abs_offset:null_pos].decode("ascii", errors="replace")
    except (struct.error, Exception):
        pass

    return entry


@register_collector("jump_lists")
class JumpListCollector(CollectorBase):
    module_id: str = "jump_lists"
    module_name: str = "Jump Lists"
    category: ArtifactCategory = ArtifactCategory.USER_ACTIVITY
    source_locations: list[str] = [
        r"%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations",
        r"%APPDATA%\Microsoft\Windows\Recent\CustomDestinations",
    ]
    required_privileges: str = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        auto_dir, custom_dir = _get_jumplist_dirs()
        collected_count: int = 0
        all_parsed: list[dict[str, str]] = []

        if auto_dir:
            count, parsed = self._collect_jumplist_dir(
                auto_dir,
                "*.automaticDestinations-ms",
                "automatic",
                result,
            )
            collected_count += count
            all_parsed.extend(parsed)

        if custom_dir:
            count, parsed = self._collect_jumplist_dir(
                custom_dir,
                "*.customDestinations-ms",
                "custom",
                result,
            )
            collected_count += count

        if self.parse and all_parsed:
            self._save_parsed_output(all_parsed, result)

        if collected_count == 0:
            if auto_dir is None and custom_dir is None:
                result.status = CollectionStatus.NOT_AVAILABLE
                result.warnings.append("Jump list directories not found")
            else:
                result.status = CollectionStatus.NOT_AVAILABLE
                result.warnings.append("No jump list files found")
        else:
            result.status = CollectionStatus.SUCCESS

        return result

    def _collect_jumplist_dir(
        self,
        source_dir: Path,
        pattern: str,
        subdir_name: str,
        result: CollectionResult,
    ) -> tuple[int, list[dict[str, str]]]:
        dest_dir = self.evidence_dir / "jump_lists" / subdir_name
        dest_dir.mkdir(parents=True, exist_ok=True)

        files = safe_glob(source_dir, pattern)
        collected: int = 0
        parsed_entries: list[dict[str, str]] = []

        for jl_file in files:
            if not jl_file.is_file():
                continue

            evidence = self.copy_file(
                jl_file,
                dest_dir,
                evidence_id=f"jumplist_{subdir_name}_{collected}",
            )
            if evidence:
                result.acquired_files.append(evidence)
                collected += 1

            if self.parse and subdir_name == "automatic":
                entries = _parse_automatic_destinations(jl_file)
                parsed_entries.extend(entries)

        return collected, parsed_entries

    def _save_parsed_output(
        self,
        entries: list[dict[str, str]],
        result: CollectionResult,
    ) -> None:
        json_evidence = self.save_json(
            entries,
            "jump_lists_parsed.json",
            self.parsed_dir,
            evidence_id="jumplists_parsed_json",
        )
        if json_evidence:
            result.acquired_files.append(json_evidence)
            result.parsed_output_files.append(json_evidence.acquired_path)

        csv_path = self.parsed_dir / "jump_lists_parsed.csv"
        try:
            fieldnames = [
                "jumplist_file", "stream", "target_path",
                "file_size", "creation_time", "modification_time", "access_time",
            ]
            with open(csv_path, "w", newline="", encoding="utf-8", errors="replace") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for entry in entries:
                    clean_entry = {k: str(v).encode("utf-8", errors="replace").decode("utf-8") for k, v in entry.items()}
                    writer.writerow(clean_entry)

            csv_evidence = FileEvidence(
                evidence_id="jumplists_parsed_csv",
                original_path="parsed_output",
                acquired_path=str(csv_path),
                filename=csv_path.name,
                extension=".csv",
                file_size=csv_path.stat().st_size,
                collection_timestamp=get_iso_timestamp(),
            )
            result.acquired_files.append(csv_evidence)
            result.parsed_output_files.append(str(csv_path))
        except OSError as e:
            result.warnings.append(f"Failed to save jump list parsed CSV: {e}")

        result.parser_name = "olefile_jumplist_parser"
        result.parser_version = "1.0"
        result.parser_status = "completed"
