from __future__ import annotations

import csv
import json
import logging
import os
from pathlib import Path
from typing import Optional

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp
from utils.filesystem import safe_glob

logger = logging.getLogger("polaris.lnk_collector")


def _get_lnk_search_dirs() -> list[Path]:
    user_profile = os.environ.get("USERPROFILE", "")
    appdata = os.environ.get("APPDATA", "")

    dirs: list[Path] = []
    if user_profile:
        dirs.append(Path(user_profile) / "Desktop")
        dirs.append(Path(user_profile) / "Downloads")
    if appdata:
        dirs.append(Path(appdata) / "Microsoft" / "Windows" / "Recent")
        dirs.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu")
        dirs.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs")

    return [d for d in dirs if d.exists()]


def _parse_lnk_file(lnk_path: Path) -> Optional[dict[str, str]]:
    try:
        import LnkParse3  # type: ignore[import-untyped]
    except ImportError:
        return None

    try:
        with open(lnk_path, "rb") as f:
            lnk = LnkParse3.lnk_file(f)

        info = lnk.get_json()
        lnk_data: dict[str, str] = {
            "lnk_file": str(lnk_path),
            "target_path": "",
            "arguments": "",
            "working_dir": "",
            "creation_time": "",
            "modification_time": "",
            "access_time": "",
            "description": "",
            "icon_location": "",
        }

        if isinstance(info, dict):
            header = info.get("header", {})
            data = info.get("data", {})
            link_info = info.get("link_info", {})
            extra = info.get("extra", {})

            if isinstance(header, dict):
                lnk_data["creation_time"] = str(header.get("creation_time", ""))
                lnk_data["modification_time"] = str(header.get("write_time", ""))
                lnk_data["access_time"] = str(header.get("access_time", ""))

            if isinstance(link_info, dict):
                local_path = link_info.get("local_base_path", "")
                common_path = link_info.get("common_path_suffix", "")
                lnk_data["target_path"] = str(local_path) + str(common_path)

            if isinstance(data, dict):
                lnk_data["arguments"] = str(data.get("command_line_arguments", ""))
                lnk_data["working_dir"] = str(data.get("working_directory", ""))
                lnk_data["description"] = str(data.get("description", ""))
                lnk_data["icon_location"] = str(data.get("icon_location", ""))

        return lnk_data
    except Exception as e:
        logger.debug(f"Failed to parse LNK {lnk_path}: {e}")
        return None


@register_collector("lnk_files")
class LnkCollector(CollectorBase):
    module_id: str = "lnk_files"
    module_name: str = "LNK Shortcut Files"
    category: ArtifactCategory = ArtifactCategory.USER_ACTIVITY
    source_locations: list[str] = [
        r"%USERPROFILE%\Desktop",
        r"%APPDATA%\Microsoft\Windows\Recent",
        r"%APPDATA%\Microsoft\Windows\Start Menu",
    ]
    required_privileges: str = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        search_dirs = _get_lnk_search_dirs()
        if not search_dirs:
            result.status = CollectionStatus.FAILED
            result.errors.append("No LNK search directories found")
            return result

        lnk_evidence_dir = self.evidence_dir / "lnk_files"
        lnk_evidence_dir.mkdir(parents=True, exist_ok=True)

        collected_count: int = 0
        parsed_records: list[dict[str, str]] = []
        parse_available: bool = True

        try:
            import LnkParse3  # type: ignore[import-untyped]
        except ImportError:
            parse_available = False
            if self.parse:
                result.warnings.append("LnkParse3 not installed; skipping LNK parsing")

        for search_dir in search_dirs:
            lnk_files = safe_glob(search_dir, "*.lnk")

            for sub_dir in [search_dir] + list(search_dir.iterdir() if search_dir.is_dir() else []):
                if sub_dir.is_dir() and sub_dir != search_dir:
                    lnk_files.extend(safe_glob(sub_dir, "*.lnk"))

            for lnk_path in lnk_files:
                if not lnk_path.is_file():
                    continue

                relative_source = lnk_path.parent.name
                dest_subdir = lnk_evidence_dir / relative_source
                evidence = self.copy_file(
                    lnk_path,
                    dest_subdir,
                    evidence_id=f"lnk_{collected_count}",
                )
                if evidence:
                    result.acquired_files.append(evidence)
                    collected_count += 1

                if self.parse and parse_available:
                    parsed = _parse_lnk_file(lnk_path)
                    if parsed:
                        parsed_records.append(parsed)

        if self.parse and parsed_records:
            self._save_parsed_output(parsed_records, result)

        if collected_count == 0:
            result.status = CollectionStatus.NOT_AVAILABLE
            result.warnings.append("No LNK files found in search directories")
        else:
            result.status = CollectionStatus.SUCCESS

        return result

    def _save_parsed_output(
        self,
        records: list[dict[str, str]],
        result: CollectionResult,
    ) -> None:
        json_evidence = self.save_json(
            records,
            "lnk_parsed.json",
            self.parsed_dir,
            evidence_id="lnk_parsed_json",
        )
        if json_evidence:
            result.acquired_files.append(json_evidence)
            result.parsed_output_files.append(json_evidence.acquired_path)

        csv_path = self.parsed_dir / "lnk_parsed.csv"
        try:
            fieldnames = [
                "lnk_file", "target_path", "arguments", "working_dir",
                "creation_time", "modification_time", "access_time",
                "description", "icon_location",
            ]
            with open(csv_path, "w", newline="", encoding="utf-8", errors="replace") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for record in records:
                    clean_rec = {k: str(v).encode("utf-8", errors="replace").decode("utf-8") for k, v in record.items()}
                    writer.writerow(clean_rec)

            csv_evidence = FileEvidence(
                evidence_id="lnk_parsed_csv",
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
            result.warnings.append(f"Failed to save LNK parsed CSV: {e}")

        result.parser_name = "LnkParse3"
        result.parser_version = "1.0"
        result.parser_status = "completed"
