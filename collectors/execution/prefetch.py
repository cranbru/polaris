from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Optional

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp
from utils.filesystem import safe_glob
from utils.timestamps import format_timestamp, parse_unix_timestamp

PREFETCH_DIR = Path(r"C:\Windows\Prefetch")

PREFETCH_SIGNATURES: dict[int, str] = {
    0x11: "Windows XP / 2003",
    0x17: "Windows Vista / 7",
    0x1A: "Windows 8.1",
    0x1E: "Windows 10 / 11",
}

PREFETCH_MAM_SIGNATURE = 0x44414D  # "MAM" compressed header (Win10+)
SCCA_SIGNATURE = 0x41434353          # "SCCA"


def _extract_exe_name_from_filename(pf_name: str) -> str:
    """Extract executable name from prefetch filename (e.g., NOTEPAD.EXE-12345678.pf -> NOTEPAD.EXE)."""
    parts = pf_name.rsplit("-", 1)
    if len(parts) == 2:
        return parts[0]
    return pf_name.replace(".pf", "")


def _parse_prefetch_header(file_path: Path) -> dict:
    """Parse the first bytes of a prefetch file for signature and version info."""
    metadata: dict = {}
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
            if len(header) < 8:
                metadata["parse_error"] = "File too small for header"
                return metadata

            first_four = struct.unpack_from("<I", header, 0)[0]

            if (first_four & 0x00FFFFFF) == PREFETCH_MAM_SIGNATURE:
                metadata["compressed"] = True
                metadata["header_signature"] = f"MAM (0x{first_four:08X})"
                return metadata

            version = struct.unpack_from("<I", header, 0)[0]
            signature = struct.unpack_from("<I", header, 4)[0]

            if signature == SCCA_SIGNATURE:
                metadata["scca_signature_valid"] = True
                metadata["version"] = version
                metadata["windows_version"] = PREFETCH_SIGNATURES.get(version, f"Unknown (0x{version:02X})")
            else:
                metadata["scca_signature_valid"] = False
                metadata["raw_signature"] = f"0x{signature:08X}"

    except (OSError, struct.error) as e:
        metadata["parse_error"] = str(e)
    return metadata


@register_collector("prefetch")
class PrefetchCollector(CollectorBase):
    module_id: str = "prefetch"
    module_name: str = "Prefetch Files"
    category: ArtifactCategory = ArtifactCategory.EXECUTION
    source_locations: list[str] = [str(PREFETCH_DIR)]
    required_privileges: str = "admin"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        if not PREFETCH_DIR.exists():
            result.status = CollectionStatus.NOT_AVAILABLE
            result.errors.append(f"Prefetch directory not found: {PREFETCH_DIR}")
            return result

        pf_files = safe_glob(PREFETCH_DIR, "*.pf")
        if not pf_files:
            result.status = CollectionStatus.NOT_AVAILABLE
            result.errors.append("No .pf files found in Prefetch directory")
            return result

        dest_dir = self.evidence_dir / "prefetch"
        collected_count = 0
        parsed_entries: list[dict] = []

        for pf_path in pf_files:
            evidence = self.copy_file(pf_path, dest_dir, evidence_id=f"prefetch_{pf_path.name}")
            if evidence:
                exe_name = _extract_exe_name_from_filename(pf_path.name)
                evidence.metadata["executable_name"] = exe_name

                try:
                    stat_info = pf_path.stat()
                    evidence.metadata["source_modified"] = format_timestamp(
                        parse_unix_timestamp(stat_info.st_mtime)
                    )
                    evidence.metadata["source_created"] = format_timestamp(
                        parse_unix_timestamp(stat_info.st_ctime)
                    )
                except OSError:
                    pass

                if self.parse:
                    header_info = _parse_prefetch_header(pf_path)
                    evidence.metadata["header"] = header_info
                    parsed_entries.append({
                        "filename": pf_path.name,
                        "executable_name": exe_name,
                        "file_size": evidence.file_size,
                        "source_modified": evidence.metadata.get("source_modified", ""),
                        "source_created": evidence.metadata.get("source_created", ""),
                        "header": header_info,
                    })

                result.acquired_files.append(evidence)
                collected_count += 1
            else:
                result.errors.append(f"Failed to copy: {pf_path}")

        if self.parse and parsed_entries:
            self.save_json(parsed_entries, "prefetch_summary.json", self.parsed_dir / "prefetch")

        self._try_external_parser(result, dest_dir)

        if collected_count == 0:
            result.status = CollectionStatus.FAILED
            result.errors.append("Could not copy any prefetch files")
        elif collected_count < len(pf_files):
            result.status = CollectionStatus.PARTIAL
        else:
            result.status = CollectionStatus.SUCCESS

        return result

    def _try_external_parser(self, result: CollectionResult, pf_dir: Path) -> None:
        """Invoke PECmd.exe if configured via POLARIS_PECMD_PATH environment variable."""
        pecmd_path = os.environ.get("POLARIS_PECMD_PATH", "")
        if not pecmd_path or not Path(pecmd_path).is_file():
            return

        if not self.parse:
            return

        from utils.subprocess_utils import run_command

        output_dir = self.parsed_dir / "prefetch" / "pecmd_output"
        output_dir.mkdir(parents=True, exist_ok=True)
        csv_output = output_dir / "PECmd_Output.csv"

        returncode, stdout, stderr = run_command(
            [pecmd_path, "-d", str(pf_dir), "--csv", str(output_dir), "-q"],
            timeout=300,
        )

        if returncode == 0:
            result.parser_name = "PECmd"
            result.parser_status = "success"
            if csv_output.exists():
                result.parsed_output_files.append(str(csv_output))
        else:
            result.warnings.append(f"PECmd exited with code {returncode}: {stderr[:200]}")
            result.parser_status = "failed"
