from __future__ import annotations

import csv
import json
import logging
import struct
from pathlib import Path
from typing import Optional

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp
from utils.filesystem import safe_glob
from utils.timestamps import filetime_to_iso

logger = logging.getLogger("polaris.recycle_bin")

RECYCLE_BIN_ROOT = Path(r"C:\$Recycle.Bin")


def _parse_dollar_i_file(file_path: Path) -> Optional[dict[str, str]]:
    try:
        data = file_path.read_bytes()
    except (OSError, PermissionError):
        return None

    if len(data) < 28:
        return None

    entry: dict[str, str] = {
        "i_file": str(file_path),
        "sid_folder": file_path.parent.name,
        "header_version": "",
        "file_size": "",
        "deletion_time": "",
        "original_path": "",
    }

    try:
        header_version = struct.unpack_from("<Q", data, 0)[0]
        entry["header_version"] = str(header_version)

        if header_version == 1:
            if len(data) < 24:
                return entry
            file_size = struct.unpack_from("<Q", data, 8)[0]
            deletion_filetime = struct.unpack_from("<Q", data, 16)[0]
            entry["file_size"] = str(file_size)
            entry["deletion_time"] = filetime_to_iso(deletion_filetime)

            path_data = data[24:]
            try:
                original_path = path_data.decode("utf-16-le").rstrip("\x00")
                entry["original_path"] = original_path
            except (UnicodeDecodeError, ValueError):
                pass

        elif header_version == 2:
            if len(data) < 28:
                return entry
            file_size = struct.unpack_from("<Q", data, 8)[0]
            deletion_filetime = struct.unpack_from("<Q", data, 16)[0]
            path_length = struct.unpack_from("<I", data, 24)[0]
            entry["file_size"] = str(file_size)
            entry["deletion_time"] = filetime_to_iso(deletion_filetime)

            path_data = data[28:]
            try:
                original_path = path_data[:path_length * 2].decode("utf-16-le").rstrip("\x00")
                entry["original_path"] = original_path
            except (UnicodeDecodeError, ValueError):
                pass

        else:
            if len(data) >= 24:
                file_size = struct.unpack_from("<Q", data, 8)[0]
                deletion_filetime = struct.unpack_from("<Q", data, 16)[0]
                entry["file_size"] = str(file_size)
                entry["deletion_time"] = filetime_to_iso(deletion_filetime)

                path_data = data[24:]
                try:
                    original_path = path_data.decode("utf-16-le").rstrip("\x00")
                    entry["original_path"] = original_path
                except (UnicodeDecodeError, ValueError):
                    try:
                        original_path = path_data.decode("utf-8", errors="replace").rstrip("\x00")
                        entry["original_path"] = original_path
                    except Exception:
                        pass

    except struct.error as e:
        logger.debug(f"Failed to parse $I file {file_path}: {e}")

    return entry


@register_collector("recycle_bin")
class RecycleBinCollector(CollectorBase):
    module_id: str = "recycle_bin"
    module_name: str = "Recycle Bin"
    category: ArtifactCategory = ArtifactCategory.USER_ACTIVITY
    source_locations: list[str] = [r"C:\$Recycle.Bin"]
    required_privileges: str = "admin"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        if not RECYCLE_BIN_ROOT.exists():
            result.status = CollectionStatus.NOT_AVAILABLE
            result.warnings.append("Recycle Bin directory not found")
            return result

        recycle_evidence_dir = self.evidence_dir / "recycle_bin"
        recycle_evidence_dir.mkdir(parents=True, exist_ok=True)

        collected_count: int = 0
        parsed_records: list[dict[str, str]] = []
        sid_dirs_found: int = 0
        sid_dirs_failed: int = 0

        try:
            sid_folders = [d for d in RECYCLE_BIN_ROOT.iterdir() if d.is_dir()]
        except (OSError, PermissionError) as e:
            result.status = CollectionStatus.FAILED
            result.errors.append(f"Cannot access Recycle Bin: {e}")
            return result

        for sid_dir in sid_folders:
            sid_name = sid_dir.name
            if not sid_name.startswith("S-"):
                continue

            sid_evidence_dir = recycle_evidence_dir / sid_name
            sid_evidence_dir.mkdir(parents=True, exist_ok=True)
            sid_dirs_found += 1

            try:
                i_files = [f for f in sid_dir.iterdir() if f.is_file() and f.name.startswith("$I")]
            except (OSError, PermissionError) as e:
                sid_dirs_failed += 1
                result.warnings.append(f"Cannot access SID folder {sid_name}: {e}")
                continue

            for i_file in i_files:
                evidence = self.copy_file(
                    i_file,
                    sid_evidence_dir,
                    evidence_id=f"recycle_{sid_name}_{i_file.name}",
                )
                if evidence:
                    result.acquired_files.append(evidence)
                    collected_count += 1

                if self.parse:
                    parsed = _parse_dollar_i_file(i_file)
                    if parsed:
                        parsed_records.append(parsed)

        if self.parse and parsed_records:
            self._save_parsed_output(parsed_records, result)

        if collected_count == 0 and sid_dirs_found == 0:
            result.status = CollectionStatus.NOT_AVAILABLE
            result.warnings.append("No SID directories found in Recycle Bin")
        elif collected_count == 0:
            result.status = CollectionStatus.FAILED
            result.errors.append("Found SID directories but could not collect any $I files")
        elif sid_dirs_failed > 0:
            result.status = CollectionStatus.PARTIAL
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
            "recycle_bin_parsed.json",
            self.parsed_dir,
            evidence_id="recycle_bin_parsed_json",
        )
        if json_evidence:
            result.acquired_files.append(json_evidence)
            result.parsed_output_files.append(json_evidence.acquired_path)

        csv_path = self.parsed_dir / "recycle_bin_parsed.csv"
        try:
            fieldnames = [
                "i_file", "sid_folder", "header_version",
                "file_size", "deletion_time", "original_path",
            ]
            with open(csv_path, "w", newline="", encoding="utf-8", errors="replace") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for record in records:
                    clean_rec = {k: str(v).encode("utf-8", errors="replace").decode("utf-8") for k, v in record.items()}
                    writer.writerow(clean_rec)

            csv_evidence = FileEvidence(
                evidence_id="recycle_bin_parsed_csv",
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
            result.warnings.append(f"Failed to save recycle bin CSV: {e}")

        result.parser_name = "dollar_i_parser"
        result.parser_version = "1.0"
        result.parser_status = "completed"
