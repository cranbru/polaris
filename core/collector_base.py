from __future__ import annotations

import shutil
import os
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from config.settings import (
    CollectionStatus,
    ArtifactCategory,
    get_iso_timestamp,
)


class FileEvidence(BaseModel):
    evidence_id: str = ""
    original_path: str = ""
    acquired_path: str = ""
    filename: str = ""
    extension: str = ""
    file_size: int = 0
    sha256: str = ""
    collection_timestamp: str = Field(default_factory=get_iso_timestamp)
    metadata: dict = Field(default_factory=dict)


class CollectionResult(BaseModel):
    module_id: str
    module_name: str
    category: ArtifactCategory
    source_locations: list[str] = Field(default_factory=list)
    required_privileges: str = "user"
    status: CollectionStatus = CollectionStatus.SKIPPED
    acquired_files: list[FileEvidence] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    collection_start: str = ""
    collection_end: str = ""
    parser_name: Optional[str] = None
    parser_version: Optional[str] = None
    parser_status: Optional[str] = None
    parsed_output_files: list[str] = Field(default_factory=list)
    artifact_count: int = 0


class CollectorBase(ABC):
    module_id: str = ""
    module_name: str = ""
    category: ArtifactCategory = ArtifactCategory.SYSTEM
    source_locations: list[str] = []
    required_privileges: str = "user"

    def __init__(self, case_dir: Path, parse: bool = True):
        self.case_dir = case_dir
        self.parse = parse
        self.evidence_dir = case_dir / "evidence" / self.category.value
        self.parsed_dir = case_dir / "parsed" / self.category.value
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        if self.parse:
            self.parsed_dir.mkdir(parents=True, exist_ok=True)

    def collect(self) -> CollectionResult:
        result = CollectionResult(
            module_id=self.module_id,
            module_name=self.module_name,
            category=self.category,
            source_locations=self.source_locations,
            required_privileges=self.required_privileges,
            collection_start=get_iso_timestamp(),
        )
        try:
            result = self._collect(result)
        except Exception as e:
            result.status = CollectionStatus.FAILED
            result.errors.append(f"Unhandled error: {type(e).__name__}: {e}")
        finally:
            result.collection_end = get_iso_timestamp()
            result.artifact_count = len(result.acquired_files)
        return result

    @abstractmethod
    def _collect(self, result: CollectionResult) -> CollectionResult:
        ...

    def copy_file(self, src: Path, dest_dir: Path, evidence_id: str = "") -> FileEvidence | None:
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / src.name
            if dest.exists():
                stem = src.stem
                suffix = src.suffix
                dest = dest_dir / f"{stem}_{datetime.now().strftime('%H%M%S')}{suffix}"
            shutil.copy2(str(src), str(dest))
            stat = dest.stat()
            return FileEvidence(
                evidence_id=evidence_id or f"{self.module_id}_{src.name}",
                original_path=str(src),
                acquired_path=str(dest),
                filename=dest.name,
                extension=dest.suffix,
                file_size=stat.st_size,
                collection_timestamp=get_iso_timestamp(),
            )
        except PermissionError:
            return None
        except OSError:
            return None

    def copy_file_raw(self, src: Path, dest: Path, evidence_id: str = "") -> FileEvidence | None:
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dest))
            stat = dest.stat()
            return FileEvidence(
                evidence_id=evidence_id or f"{self.module_id}_{src.name}",
                original_path=str(src),
                acquired_path=str(dest),
                filename=dest.name,
                extension=dest.suffix,
                file_size=stat.st_size,
                collection_timestamp=get_iso_timestamp(),
            )
        except (PermissionError, OSError):
            return None

    def save_text(self, content: str, filename: str, dest_dir: Path, evidence_id: str = "") -> FileEvidence | None:
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / filename
            dest.write_text(content, encoding="utf-8", errors="replace")
            stat = dest.stat()
            return FileEvidence(
                evidence_id=evidence_id or f"{self.module_id}_{filename}",
                original_path="live_system_command",
                acquired_path=str(dest),
                filename=filename,
                extension=dest.suffix,
                file_size=stat.st_size,
                collection_timestamp=get_iso_timestamp(),
            )
        except OSError:
            return None

    def save_json(self, data: object, filename: str, dest_dir: Path, evidence_id: str = "") -> FileEvidence | None:
        import json
        try:
            content = json.dumps(data, indent=2, default=str, ensure_ascii=False)
            return self.save_text(content, filename, dest_dir, evidence_id)
        except (TypeError, ValueError):
            return None
