from __future__ import annotations

from pathlib import Path

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory
from utils.subprocess_utils import run_command

SHIMCACHE_REG_KEY = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"


@register_collector("shimcache")
class ShimcacheCollector(CollectorBase):
    module_id: str = "shimcache"
    module_name: str = "Application Compatibility Cache (ShimCache)"
    category: ArtifactCategory = ArtifactCategory.EXECUTION
    source_locations: list[str] = [SHIMCACHE_REG_KEY]
    required_privileges: str = "admin"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        dest_dir = self.evidence_dir / "shimcache"
        collected = False

        reg_export_evidence = self._export_registry(result, dest_dir)
        if reg_export_evidence:
            result.acquired_files.append(reg_export_evidence)
            collected = True

        reg_query_evidence = self._query_registry(result, dest_dir)
        if reg_query_evidence:
            result.acquired_files.append(reg_query_evidence)
            collected = True

        if collected:
            result.status = CollectionStatus.SUCCESS
        else:
            result.status = CollectionStatus.FAILED

        return result

    def _export_registry(self, result: CollectionResult, dest_dir: Path) -> FileEvidence | None:
        export_file = dest_dir / "AppCompatCache_export.reg"
        export_file.parent.mkdir(parents=True, exist_ok=True)

        returncode, stdout, stderr = run_command(
            ["reg", "export", SHIMCACHE_REG_KEY, str(export_file), "/y"],
            timeout=60,
        )

        if returncode == 0 and export_file.exists():
            stat = export_file.stat()
            return FileEvidence(
                evidence_id="shimcache_reg_export",
                original_path=SHIMCACHE_REG_KEY,
                acquired_path=str(export_file),
                filename=export_file.name,
                extension=".reg",
                file_size=stat.st_size,
            )
        else:
            result.errors.append(f"reg export failed (rc={returncode}): {stderr[:300]}")
            return None

    def _query_registry(self, result: CollectionResult, dest_dir: Path) -> FileEvidence | None:
        returncode, stdout, stderr = run_command(
            ["reg", "query", SHIMCACHE_REG_KEY, "/v", "AppCompatCache"],
            timeout=60,
        )

        if returncode != 0:
            result.errors.append(f"reg query failed (rc={returncode}): {stderr[:300]}")
            return None

        evidence = self.save_text(
            stdout, "AppCompatCache_query.txt", dest_dir,
            evidence_id="shimcache_reg_query",
        )
        if not evidence:
            result.errors.append("Failed to save reg query output")
        return evidence
