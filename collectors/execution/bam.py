from __future__ import annotations

import re
from pathlib import Path

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory
from utils.subprocess_utils import run_command
from utils.timestamps import filetime_to_iso

BAM_REG_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
DAM_REG_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings"

FILETIME_HEX_RE = re.compile(
    r"^\s+(.+?)\s+REG_BINARY\s+([0-9A-Fa-f]+)\s*$", re.MULTILINE
)


def _parse_bam_dam_output(raw_output: str) -> list[dict]:
    """Parse reg query output, extracting executable paths and FILETIME timestamps."""
    entries: list[dict] = []
    current_sid = ""

    for line in raw_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("HKLM\\"):
            parts = stripped.rsplit("\\", 1)
            current_sid = parts[-1] if len(parts) == 2 else stripped

        match = FILETIME_HEX_RE.match(line)
        if match:
            value_name = match.group(1).strip()
            hex_data = match.group(2).strip()

            timestamp_iso = ""
            if len(hex_data) >= 16:
                try:
                    raw_bytes = bytes.fromhex(hex_data[:16])
                    filetime_val = int.from_bytes(raw_bytes, byteorder="little")
                    timestamp_iso = filetime_to_iso(filetime_val)
                except (ValueError, OverflowError):
                    pass

            entries.append({
                "sid": current_sid,
                "executable": value_name,
                "raw_hex": hex_data[:32],
                "last_execution_time": timestamp_iso,
            })

    return entries


class _BamDamBaseCollector(CollectorBase):
    """Shared implementation for BAM and DAM collectors."""

    _service_name: str = ""
    _reg_key: str = ""

    def _collect(self, result: CollectionResult) -> CollectionResult:
        dest_dir = self.evidence_dir / self._service_name
        collected = False

        returncode, stdout, stderr = run_command(
            ["reg", "query", self._reg_key, "/s"],
            timeout=60,
        )

        if returncode != 0:
            if "unable to find" in stderr.lower() or "error" in stderr.lower():
                result.status = CollectionStatus.NOT_AVAILABLE
                result.errors.append(
                    f"{self._service_name.upper()} registry key not found: {self._reg_key}"
                )
                return result
            result.status = CollectionStatus.FAILED
            result.errors.append(f"reg query failed (rc={returncode}): {stderr[:300]}")
            return result

        if not stdout.strip():
            result.status = CollectionStatus.NOT_AVAILABLE
            result.errors.append(f"No data returned from {self._service_name.upper()} registry key")
            return result

        raw_evidence = self.save_text(
            stdout,
            f"{self._service_name}_raw_export.txt",
            dest_dir,
            evidence_id=f"{self._service_name}_raw",
        )
        if raw_evidence:
            result.acquired_files.append(raw_evidence)
            collected = True
        else:
            result.errors.append(f"Failed to save {self._service_name} raw export")

        if self.parse:
            entries = _parse_bam_dam_output(stdout)
            if entries:
                parsed_evidence = self.save_json(
                    entries,
                    f"{self._service_name}_parsed.json",
                    self.parsed_dir / self._service_name,
                    evidence_id=f"{self._service_name}_parsed",
                )
                if parsed_evidence:
                    result.parsed_output_files.append(parsed_evidence.acquired_path)

        result.status = CollectionStatus.SUCCESS if collected else CollectionStatus.FAILED
        return result


@register_collector("bam")
class BamCollector(_BamDamBaseCollector):
    module_id: str = "bam"
    module_name: str = "Background Activity Moderator (BAM)"
    category: ArtifactCategory = ArtifactCategory.EXECUTION
    source_locations: list[str] = [BAM_REG_KEY]
    required_privileges: str = "admin"
    _service_name: str = "bam"
    _reg_key: str = BAM_REG_KEY


@register_collector("dam")
class DamCollector(_BamDamBaseCollector):
    module_id: str = "dam"
    module_name: str = "Desktop Activity Moderator (DAM)"
    category: ArtifactCategory = ArtifactCategory.EXECUTION
    source_locations: list[str] = [DAM_REG_KEY]
    required_privileges: str = "admin"
    _service_name: str = "dam"
    _reg_key: str = DAM_REG_KEY
