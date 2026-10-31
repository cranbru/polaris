from __future__ import annotations

from pathlib import Path

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory

SRUM_DIR = Path(r"C:\Windows\System32\SRU")
SRUDB_FILE = SRUM_DIR / "SRUDB.dat"

SRUM_RELATED_PATTERNS = [
    "SRUDB.dat",
    "SRU*.log",
    "SRU*.chk",
]


@register_collector("srum")
class SrumCollector(CollectorBase):
    module_id: str = "srum"
    module_name: str = "System Resource Usage Monitor (SRUM)"
    category: ArtifactCategory = ArtifactCategory.EXECUTION
    source_locations: list[str] = [str(SRUM_DIR)]
    required_privileges: str = "admin"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        if not SRUM_DIR.exists():
            result.status = CollectionStatus.NOT_AVAILABLE
            result.errors.append(f"SRU directory not found: {SRUM_DIR}")
            return result

        if not SRUDB_FILE.exists():
            result.status = CollectionStatus.NOT_AVAILABLE
            result.errors.append(f"SRUDB.dat not found: {SRUDB_FILE}")
            return result

        dest_dir = self.evidence_dir / "srum"
        collected_count = 0
        total_found = 0

        for pattern in SRUM_RELATED_PATTERNS:
            matched_files = list(SRUM_DIR.glob(pattern))
            total_found += len(matched_files)

            for src_file in matched_files:
                if not src_file.is_file():
                    continue
                evidence = self.copy_file(src_file, dest_dir, evidence_id=f"srum_{src_file.name}")
                if evidence:
                    result.acquired_files.append(evidence)
                    collected_count += 1
                else:
                    result.errors.append(f"Failed to copy: {src_file}")

        if collected_count == 0:
            result.status = CollectionStatus.FAILED
            result.errors.append("Could not copy any SRUM files (database may be locked by service)")
            self._try_esentutl_copy(result, dest_dir)
        elif collected_count < total_found:
            result.status = CollectionStatus.PARTIAL
        else:
            result.status = CollectionStatus.SUCCESS

        if self.parse:
            srum_info = {
                "source_directory": str(SRUM_DIR),
                "files_collected": [f.filename for f in result.acquired_files],
                "primary_db_exists": SRUDB_FILE.exists(),
                "note": "SRUDB.dat is an ESE database. Use srum-dump or SrumECmd for full parsing.",
            }
            self.save_json(srum_info, "srum_info.json", self.parsed_dir / "srum")

        return result

    def _try_esentutl_copy(self, result: CollectionResult, dest_dir: Path) -> None:
        """Attempt to copy SRUDB.dat using esentutl if direct copy fails (locked file)."""
        from utils.subprocess_utils import run_command

        dest_file = dest_dir / "SRUDB.dat"
        dest_dir.mkdir(parents=True, exist_ok=True)

        returncode, stdout, stderr = run_command(
            ["esentutl.exe", "/y", str(SRUDB_FILE), "/vss", "/d", str(dest_file)],
            timeout=120,
        )

        if returncode == 0 and dest_file.exists():
            stat = dest_file.stat()
            evidence = FileEvidence(
                evidence_id="srum_srudb_esentutl",
                original_path=str(SRUDB_FILE),
                acquired_path=str(dest_file),
                filename=dest_file.name,
                extension=".dat",
                file_size=stat.st_size,
                metadata={"copy_method": "esentutl_vss"},
            )
            result.acquired_files.append(evidence)
            result.status = CollectionStatus.SUCCESS
            result.warnings.append("SRUDB.dat copied via esentutl /vss (direct copy failed)")
        else:
            result.errors.append(
                f"esentutl copy also failed (rc={returncode}): {stderr[:200]}"
            )
