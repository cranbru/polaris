from __future__ import annotations

from pathlib import Path

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory

AMCACHE_DIR = Path(r"C:\Windows\appcompat\Programs")
AMCACHE_HVE = AMCACHE_DIR / "Amcache.hve"

AMCACHE_RELATED_PATTERNS = [
    "Amcache.hve",
    "Amcache.hve.LOG*",
    "Amcache.hve.blf",
    "RecentFileCache.bcf",
]


@register_collector("amcache")
class AmcacheCollector(CollectorBase):
    module_id: str = "amcache"
    module_name: str = "Amcache Registry Hive"
    category: ArtifactCategory = ArtifactCategory.EXECUTION
    source_locations: list[str] = [str(AMCACHE_DIR)]
    required_privileges: str = "admin"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        if not AMCACHE_DIR.exists():
            result.status = CollectionStatus.NOT_AVAILABLE
            result.errors.append(f"Amcache directory not found: {AMCACHE_DIR}")
            return result

        dest_dir = self.evidence_dir / "amcache"
        collected_count = 0
        total_expected = 0

        for pattern in AMCACHE_RELATED_PATTERNS:
            matched_files = list(AMCACHE_DIR.glob(pattern))
            total_expected += len(matched_files)

            for src_file in matched_files:
                if not src_file.is_file():
                    continue
                evidence = self.copy_file(src_file, dest_dir, evidence_id=f"amcache_{src_file.name}")
                if evidence:
                    result.acquired_files.append(evidence)
                    collected_count += 1
                else:
                    result.errors.append(f"Failed to copy: {src_file}")

        if not AMCACHE_HVE.exists():
            result.status = CollectionStatus.NOT_AVAILABLE
            result.errors.append(f"Primary Amcache hive not found: {AMCACHE_HVE}")
            return result

        if collected_count == 0:
            result.status = CollectionStatus.FAILED
            result.errors.append("Could not copy any Amcache files")
        elif collected_count < total_expected:
            result.status = CollectionStatus.PARTIAL
        else:
            result.status = CollectionStatus.SUCCESS

        if self.parse:
            amcache_info = {
                "source_directory": str(AMCACHE_DIR),
                "files_collected": [f.filename for f in result.acquired_files],
                "primary_hive_exists": AMCACHE_HVE.exists(),
                "note": "Amcache.hve requires offline registry parsing (e.g., amcacheparser, RegRipper) for full analysis.",
            }
            self.save_json(amcache_info, "amcache_info.json", self.parsed_dir / "amcache")

        return result
