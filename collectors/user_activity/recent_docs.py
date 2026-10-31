from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp
from utils.subprocess_utils import run_command

logger = logging.getLogger("polaris.recent_docs")

REGISTRY_KEYS: dict[str, str] = {
    "RecentDocs": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    "OpenSavePidlMRU": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
}


def _reg_query_recursive(key_path: str, timeout: int = 60) -> tuple[int, str, str]:
    return run_command(
        ["reg", "query", key_path, "/s"],
        timeout=timeout,
    )


def _reg_export(key_path: str, output_file: Path, timeout: int = 60) -> tuple[int, str, str]:
    return run_command(
        ["reg", "export", key_path, str(output_file), "/y"],
        timeout=timeout,
    )


def _parse_reg_query_output(output: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current_key: str = ""

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("HKEY_"):
            current_key = stripped
            continue

        parts = stripped.split(maxsplit=2)
        if len(parts) >= 3:
            value_name = parts[0]
            value_type = parts[1]
            value_data = parts[2]

            if value_name.lower() == "(default)":
                continue

            records.append({
                "registry_key": current_key,
                "value_name": value_name,
                "value_type": value_type,
                "value_data": value_data,
            })

    return records


@register_collector("recent_docs")
class RecentDocsCollector(CollectorBase):
    module_id: str = "recent_docs"
    module_name: str = "Recent Documents (Registry)"
    category: ArtifactCategory = ArtifactCategory.USER_ACTIVITY
    source_locations: list[str] = list(REGISTRY_KEYS.values())
    required_privileges: str = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        export_dir = self.evidence_dir / "recent_docs"
        export_dir.mkdir(parents=True, exist_ok=True)

        keys_succeeded: int = 0
        keys_failed: int = 0
        all_records: list[dict[str, str]] = []

        for key_name, key_path in REGISTRY_KEYS.items():
            reg_file = export_dir / f"{key_name}.reg"
            returncode, stdout, stderr = _reg_export(key_path, reg_file)

            if returncode == 0 and reg_file.exists():
                evidence = FileEvidence(
                    evidence_id=f"recent_docs_{key_name}_reg",
                    original_path=key_path,
                    acquired_path=str(reg_file),
                    filename=reg_file.name,
                    extension=".reg",
                    file_size=reg_file.stat().st_size,
                    collection_timestamp=get_iso_timestamp(),
                )
                result.acquired_files.append(evidence)
                keys_succeeded += 1
            else:
                keys_failed += 1
                result.warnings.append(f"Failed to export {key_name}: {stderr.strip()}")

            if self.parse:
                query_rc, query_out, query_err = _reg_query_recursive(key_path)
                if query_rc == 0 and query_out.strip():
                    records = _parse_reg_query_output(query_out)
                    for record in records:
                        record["source_key"] = key_name
                    all_records.extend(records)

        if self.parse and all_records:
            json_evidence = self.save_json(
                all_records,
                "recent_docs_parsed.json",
                self.parsed_dir,
                evidence_id="recent_docs_parsed_json",
            )
            if json_evidence:
                result.acquired_files.append(json_evidence)
                result.parsed_output_files.append(json_evidence.acquired_path)

            result.parser_name = "reg_query_parser"
            result.parser_version = "1.0"
            result.parser_status = "completed"

        if keys_succeeded == 0:
            result.status = CollectionStatus.FAILED
            result.errors.append("Failed to export any recent documents registry keys")
        elif keys_failed > 0:
            result.status = CollectionStatus.PARTIAL
        else:
            result.status = CollectionStatus.SUCCESS

        return result
