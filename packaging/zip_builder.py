import os
import json
import zipfile
from datetime import datetime
from pathlib import Path

from config.settings import get_timestamp, get_iso_timestamp, TOOL_NAME, TOOL_VERSION
from core.hash_manager import compute_sha256


class ZipBuilder:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.archive_dir = case_dir / "archive"
        self.archive_dir.mkdir(parents=True, exist_ok=True)

    def build_package(self) -> tuple[Path, str]:
        case_id = self.case_dir.name
        ts = get_timestamp()
        zip_filename = f"POLARIS_CASE_{case_id}_{ts}.zip"
        zip_path = self.archive_dir / zip_filename

        include_dirs = [
            "evidence",
            "parsed",
            "timeline",
            "manifests",
            "logs",
            "metadata",
            "reports",
            "verification",
        ]

        # Files to strictly exclude for privacy, safety, and recursion prevention
        exclude_patterns = [
            ".env",
            ".polaris_config.json",
            ".git",
            "__pycache__",
            ".pyc",
            "archive",
            "token",
            "secret",
        ]

        file_count = 0
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for subdir_name in include_dirs:
                subdir_path = self.case_dir / subdir_name
                if not subdir_path.exists():
                    continue

                for root, _, files in os.walk(subdir_path):
                    root_path = Path(root)
                    if any(exc in root_path.parts for exc in exclude_patterns):
                        continue

                    for file in files:
                        if any(exc in file.lower() for exc in exclude_patterns):
                            continue

                        file_path = root_path / file
                        arcname = str(file_path.relative_to(self.case_dir)).encode("utf-8", errors="replace").decode("utf-8")
                        try:
                            zf.write(file_path, arcname=arcname)
                            file_count += 1
                        except Exception:
                            continue

        zip_sha256 = compute_sha256(zip_path)

        # Write text hash file
        hash_file = self.archive_dir / f"{zip_filename}.sha256"
        hash_file.write_text(f"{zip_sha256}  {zip_filename}\n", encoding="utf-8")

        # Write structured archive manifest
        manifest_meta = {
            "archive_filename": zip_filename,
            "case_id": case_id,
            "sha256": zip_sha256,
            "file_size_bytes": zip_path.stat().st_size,
            "total_archived_files": file_count,
            "timestamp": get_iso_timestamp(),
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "verification_status": "SEALED",
        }
        manifest_path = self.archive_dir / f"{zip_filename}_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_meta, f, indent=2)

        return zip_path, zip_sha256
