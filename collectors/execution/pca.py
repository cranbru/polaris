from __future__ import annotations

from pathlib import Path

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory
from utils.filesystem import safe_glob

PCA_DIR = Path(r"C:\Windows\appcompat\pca")

PCA_FILE_PATTERNS = [
    "PcaAppLaunchDic.txt",
    "PcaGeneralDb0.txt",
    "PcaGeneralDb1.txt",
    "*.xml",
    "*.txt",
    "*.db",
]


@register_collector("pca")
class PcaCollector(CollectorBase):
    module_id: str = "pca"
    module_name: str = "Program Compatibility Assistant (PCA)"
    category: ArtifactCategory = ArtifactCategory.EXECUTION
    source_locations: list[str] = [str(PCA_DIR)]
    required_privileges: str = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        if not PCA_DIR.exists():
            result.status = CollectionStatus.NOT_AVAILABLE
            result.errors.append(f"PCA directory not found: {PCA_DIR}")
            return result

        dest_dir = self.evidence_dir / "pca"
        collected_count = 0
        seen_files: set[str] = set()
        all_files: list[Path] = []

        for pattern in PCA_FILE_PATTERNS:
            for f in safe_glob(PCA_DIR, pattern):
                if f.name not in seen_files and f.is_file():
                    seen_files.add(f.name)
                    all_files.append(f)

        if not all_files:
            result.status = CollectionStatus.NOT_AVAILABLE
            result.errors.append("No PCA artifact files found")
            return result

        parsed_entries: list[dict] = []

        for src_file in all_files:
            evidence = self.copy_file(src_file, dest_dir, evidence_id=f"pca_{src_file.name}")
            if evidence:
                result.acquired_files.append(evidence)
                collected_count += 1

                if self.parse and src_file.suffix.lower() == ".txt":
                    entries = self._parse_pca_text(src_file)
                    if entries:
                        parsed_entries.extend(entries)
            else:
                result.errors.append(f"Failed to copy: {src_file}")

        if self.parse and parsed_entries:
            self.save_json(
                parsed_entries,
                "pca_parsed.json",
                self.parsed_dir / "pca",
                evidence_id="pca_parsed",
            )

        if collected_count == 0:
            result.status = CollectionStatus.FAILED
        elif collected_count < len(all_files):
            result.status = CollectionStatus.PARTIAL
        else:
            result.status = CollectionStatus.SUCCESS

        return result

    def _parse_pca_text(self, file_path: Path) -> list[dict]:
        """Best-effort parse of PCA text files (pipe/tab delimited)."""
        entries: list[dict] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            for line_num, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                if "|" in stripped:
                    parts = [p.strip() for p in stripped.split("|")]
                elif "\t" in stripped:
                    parts = [p.strip() for p in stripped.split("\t")]
                else:
                    parts = [stripped]

                entries.append({
                    "source_file": file_path.name,
                    "line_number": line_num,
                    "fields": parts,
                    "executable": parts[0] if parts else "",
                })
        except OSError:
            pass
        return entries
