from __future__ import annotations

import codecs
import re
from pathlib import Path

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory
from utils.subprocess_utils import run_command

USERASSIST_BASE_KEY = (
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
)

USERASSIST_GUIDS = [
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",  # Executable File Execution
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}",  # Shortcut File Execution
]


def _rot13_decode(text: str) -> str:
    """Decode ROT13-encoded strings used by UserAssist."""
    return codecs.decode(text, "rot_13")


def _parse_userassist_output(raw_output: str) -> list[dict]:
    """Parse reg query output and decode ROT13 value names."""
    entries: list[dict] = []
    current_key = ""

    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("HK"):
            current_key = stripped
            continue

        match = re.match(r"^\s+(.+?)\s+REG_(BINARY|SZ|DWORD)\s+(.*)", line)
        if match:
            encoded_name = match.group(1).strip()
            reg_type = match.group(2).strip()
            raw_value = match.group(3).strip()

            decoded_name = _rot13_decode(encoded_name)

            entry: dict = {
                "registry_key": current_key,
                "encoded_name": encoded_name,
                "decoded_name": decoded_name,
                "value_type": f"REG_{reg_type}",
                "raw_data": raw_value[:64],
            }

            entries.append(entry)

    return entries


@register_collector("userassist")
class UserAssistCollector(CollectorBase):
    module_id: str = "userassist"
    module_name: str = "UserAssist Registry Keys"
    category: ArtifactCategory = ArtifactCategory.EXECUTION
    source_locations: list[str] = [USERASSIST_BASE_KEY]
    required_privileges: str = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        dest_dir = self.evidence_dir / "userassist"
        all_output_parts: list[str] = []
        any_success = False

        for guid in USERASSIST_GUIDS:
            count_key = f"{USERASSIST_BASE_KEY}\\{guid}\\Count"
            returncode, stdout, stderr = run_command(
                ["reg", "query", count_key, "/s"],
                timeout=60,
            )

            if returncode == 0 and stdout.strip():
                all_output_parts.append(f"--- {guid} ---\n{stdout}")
                any_success = True
            else:
                result.warnings.append(f"UserAssist GUID {guid}: not found or empty")

        if not any_success:
            returncode, stdout, stderr = run_command(
                ["reg", "query", USERASSIST_BASE_KEY, "/s"],
                timeout=60,
            )

            if returncode == 0 and stdout.strip():
                all_output_parts.append(stdout)
                any_success = True
            else:
                result.status = CollectionStatus.NOT_AVAILABLE
                result.errors.append("No UserAssist data found in registry")
                return result

        combined_output = "\n".join(all_output_parts)

        raw_evidence = self.save_text(
            combined_output,
            "userassist_raw_export.txt",
            dest_dir,
            evidence_id="userassist_raw",
        )
        if raw_evidence:
            result.acquired_files.append(raw_evidence)

        if self.parse:
            entries = _parse_userassist_output(combined_output)
            if entries:
                parsed_evidence = self.save_json(
                    entries,
                    "userassist_decoded.json",
                    self.parsed_dir / "userassist",
                    evidence_id="userassist_parsed",
                )
                if parsed_evidence:
                    result.parsed_output_files.append(parsed_evidence.acquired_path)

        result.status = CollectionStatus.SUCCESS if any_success else CollectionStatus.FAILED
        return result
