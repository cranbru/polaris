import csv
import json
from pathlib import Path
from datetime import datetime

from pydantic import BaseModel, Field

from config.settings import (
    MANIFEST_CSV,
    MANIFEST_JSON,
    get_iso_timestamp,
)
from core.collector_base import CollectionResult, FileEvidence
from core.hash_manager import compute_sha256


class ManifestEntry(BaseModel):
    evidence_id: str
    category: str
    original_path: str
    acquired_path: str
    filename: str
    extension: str
    file_size: int
    sha256: str
    collection_timestamp: str
    acquisition_status: str
    parser_status: str = "not_parsed"


def _sanitize_obj(obj):
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8")
    elif isinstance(obj, dict):
        return {k: _sanitize_obj(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitize_obj(item) for item in obj]
    return obj


class ManifestManager:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.manifest_dir = case_dir / "manifests"
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        self.entries: list[ManifestEntry] = []

    def add_collection_result(self, result: CollectionResult) -> None:
        for evidence in result.acquired_files:
            sha256 = ""
            acquired = Path(evidence.acquired_path)
            if acquired.exists():
                sha256 = compute_sha256(acquired)
                evidence.sha256 = sha256

            entry = ManifestEntry(
                evidence_id=evidence.evidence_id,
                category=result.category.value if hasattr(result.category, "value") else str(result.category),
                original_path=str(evidence.original_path),
                acquired_path=str(evidence.acquired_path),
                filename=str(evidence.filename),
                extension=str(evidence.extension),
                file_size=evidence.file_size,
                sha256=sha256,
                collection_timestamp=evidence.collection_timestamp,
                acquisition_status=result.status.value if hasattr(result.status, "value") else str(result.status),
                parser_status=result.parser_status or "not_parsed",
            )
            self.entries.append(entry)

    def write_manifest(self) -> tuple[Path, Path]:
        csv_path = self.manifest_dir / MANIFEST_CSV
        json_path = self.manifest_dir / MANIFEST_JSON

        fieldnames = list(ManifestEntry.model_fields.keys())
        with open(csv_path, "w", newline="", encoding="utf-8", errors="replace") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in self.entries:
                writer.writerow(_sanitize_obj(entry.model_dump()))

        with open(json_path, "w", encoding="utf-8", errors="replace") as f:
            json.dump(
                [_sanitize_obj(e.model_dump()) for e in self.entries],
                f,
                indent=2,
                ensure_ascii=False,
            )

        return csv_path, json_path

    def load_manifest(self, json_path: Path | None = None) -> list[ManifestEntry]:
        path = json_path or (self.manifest_dir / MANIFEST_JSON)
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.entries = [ManifestEntry(**d) for d in data]
        return self.entries

    def verify(self) -> dict:
        report = {
            "verification_timestamp": get_iso_timestamp(),
            "total_entries": len(self.entries),
            "verified": [],
            "modified": [],
            "missing": [],
            "unexpected": [],
            "errors": [],
        }

        acquired_paths = set()
        for entry in self.entries:
            acquired = Path(entry.acquired_path)
            acquired_paths.add(str(acquired))

            if not acquired.exists():
                report["missing"].append({
                    "evidence_id": entry.evidence_id,
                    "path": entry.acquired_path,
                    "original_sha256": entry.sha256,
                })
                continue

            try:
                current_hash = compute_sha256(acquired)
                if current_hash == entry.sha256:
                    report["verified"].append({
                        "evidence_id": entry.evidence_id,
                        "path": entry.acquired_path,
                        "sha256": current_hash,
                    })
                else:
                    report["modified"].append({
                        "evidence_id": entry.evidence_id,
                        "path": entry.acquired_path,
                        "original_sha256": entry.sha256,
                        "current_sha256": current_hash,
                    })
            except OSError as e:
                report["errors"].append({
                    "evidence_id": entry.evidence_id,
                    "path": entry.acquired_path,
                    "error": str(e),
                })

        evidence_root = self.case_dir / "evidence"
        if evidence_root.exists():
            for fpath in evidence_root.rglob("*"):
                if fpath.is_file() and str(fpath) not in acquired_paths:
                    report["unexpected"].append({
                        "path": str(fpath),
                        "sha256": compute_sha256(fpath),
                    })

        return report

    def write_verification_report(self, report: dict) -> Path:
        ver_dir = self.case_dir / "verification"
        ver_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = ver_dir / f"verification_{ts}.json"
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            json.dump(_sanitize_obj(report), f, indent=2, ensure_ascii=False)
        return path
