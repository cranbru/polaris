import json
from pathlib import Path

from core.collector_base import CollectionResult, FileEvidence
from config.settings import CollectionStatus, get_iso_timestamp


class EvidenceManager:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.results: list[CollectionResult] = []

    def add_result(self, result: CollectionResult) -> None:
        self.results.append(result)

    def get_all_evidence_files(self) -> list[FileEvidence]:
        files = []
        for result in self.results:
            files.extend(result.acquired_files)
        return files

    def get_results_by_category(self, category: str) -> list[CollectionResult]:
        return [r for r in self.results if r.category.value == category]

    def get_results_by_status(self, status: CollectionStatus) -> list[CollectionResult]:
        return [r for r in self.results if r.status == status]

    def get_summary(self) -> dict:
        total = len(self.results)
        status_counts = {}
        for s in CollectionStatus:
            count = len([r for r in self.results if r.status == s])
            if count:
                status_counts[s.value] = count

        return {
            "total_modules": total,
            "total_files": sum(r.artifact_count for r in self.results),
            "status_counts": status_counts,
            "categories": list({r.category.value for r in self.results}),
            "errors": [
                {"module": r.module_id, "errors": r.errors}
                for r in self.results if r.errors
            ],
            "warnings": [
                {"module": r.module_id, "warnings": r.warnings}
                for r in self.results if r.warnings
            ],
        }

    def save_results(self) -> Path:
        meta_dir = self.case_dir / "metadata"
        meta_dir.mkdir(parents=True, exist_ok=True)
        path = meta_dir / "collection_results.json"
        data = [r.model_dump() for r in self.results]
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            json.dump(data, f, indent=2, default=lambda o: str(o).encode("utf-8", errors="replace").decode("utf-8"), ensure_ascii=False)
        return path

    def load_results(self) -> list[CollectionResult]:
        path = self.case_dir / "metadata" / "collection_results.json"
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.results = [CollectionResult(**d) for d in data]
        return self.results
