import json
from pathlib import Path
from datetime import datetime

from pydantic import BaseModel, Field

from config.settings import get_iso_timestamp, TOOL_NAME, TOOL_VERSION


class CaseMetadata(BaseModel):
    case_id: str
    created_at: str = Field(default_factory=get_iso_timestamp)
    tool_name: str = TOOL_NAME
    tool_version: str = TOOL_VERSION
    examiner: str = ""
    description: str = ""
    hostname: str = ""
    os_version: str = ""
    output_dir: str = ""
    profile: str = ""
    status: str = "created"
    collection_start: str = ""
    collection_end: str = ""
    total_artifacts: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    warnings: list[str] = Field(default_factory=list)


CASE_SUBDIRS = [
    "evidence/execution",
    "evidence/eventlogs",
    "evidence/registry",
    "evidence/user_activity",
    "evidence/browsers",
    "evidence/devices",
    "evidence/persistence",
    "evidence/network",
    "evidence/system",
    "parsed",
    "parsed/execution",
    "parsed/eventlogs",
    "parsed/registry",
    "parsed/user_activity",
    "parsed/browsers",
    "parsed/devices",
    "parsed/persistence",
    "parsed/network",
    "parsed/system",
    "timeline",
    "manifests",
    "logs",
    "metadata",
    "reports",
    "verification",
    "archive",
]


class CaseManager:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def create_case(self, case_id: str, profile: str = "", examiner: str = "", description: str = "") -> tuple[Path, CaseMetadata]:
        case_dir = self.base_dir / case_id
        if case_dir.exists():
            metadata = self.load_metadata(case_dir)
            if metadata:
                return case_dir, metadata

        for subdir in CASE_SUBDIRS:
            (case_dir / subdir).mkdir(parents=True, exist_ok=True)

        import platform
        metadata = CaseMetadata(
            case_id=case_id,
            hostname=platform.node(),
            os_version=platform.platform(),
            output_dir=str(case_dir),
            profile=profile,
            examiner=examiner,
            description=description,
        )
        self._save_metadata(case_dir, metadata)
        return case_dir, metadata

    def list_cases(self) -> list[str]:
        if not self.base_dir.exists():
            return []
        return [
            d.name for d in self.base_dir.iterdir()
            if d.is_dir() and (d / "metadata").exists()
        ]

    def load_metadata(self, case_dir: Path) -> CaseMetadata | None:
        meta_path = case_dir / "metadata" / "case_metadata.json"
        if not meta_path.exists():
            return None
        with open(meta_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return CaseMetadata(**data)

    def update_metadata(self, case_dir: Path, metadata: CaseMetadata) -> None:
        self._save_metadata(case_dir, metadata)

    def _save_metadata(self, case_dir: Path, metadata: CaseMetadata) -> None:
        meta_dir = case_dir / "metadata"
        meta_dir.mkdir(parents=True, exist_ok=True)
        meta_path = meta_dir / "case_metadata.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata.model_dump(), f, indent=2, ensure_ascii=False)
