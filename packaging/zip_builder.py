import os
import zipfile
from datetime import datetime
from pathlib import Path

from config.settings import get_timestamp
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

        # Files to exclude for privacy and security
        exclude_patterns = [
            ".env",
            ".git",
            "__pycache__",
            ".pyc",
            "archive",
        ]

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
                        if any(exc in file for exc in exclude_patterns):
                            continue

                        file_path = root_path / file
                        arcname = str(file_path.relative_to(self.case_dir)).encode("utf-8", errors="replace").decode("utf-8")
                        try:
                            zf.write(file_path, arcname=arcname)
                        except Exception:
                            continue

        zip_sha256 = compute_sha256(zip_path)

        hash_file = self.archive_dir / f"{zip_filename}.sha256"
        hash_file.write_text(f"{zip_sha256}  {zip_filename}\n", encoding="utf-8")

        return zip_path, zip_sha256
