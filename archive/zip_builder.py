import os
import json
import zipfile
import hashlib
from datetime import datetime
from pathlib import Path

from config.settings import get_timestamp, get_iso_timestamp, TOOL_NAME, TOOL_VERSION
from core.hash_manager import compute_sha256


class ZipBuilder:
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.archive_dir = case_dir / "archive"
        self.archive_dir.mkdir(parents=True, exist_ok=True)

    def build_package(self, progress_callback=None) -> tuple[Path, str]:
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

        from core.progress import check_cancelled
        # These directories already contain case outputs, not application config.
        # Evidence names such as .env and secrets.txt must remain in the package.
        paths = []
        for name in include_dirs:
            directory = self.case_dir / name
            if directory.exists():
                paths.extend(p for p in directory.rglob("*") if p.is_file()
                             and not any(part in {".git", "__pycache__"} for part in p.relative_to(directory).parts))
        archive_names = {}
        filename_mapping = []
        occupied_names = {p.relative_to(self.case_dir).as_posix() for p in paths}
        for file_path in paths:
            original = file_path.relative_to(self.case_dir).as_posix()
            try:
                original.encode("utf-8")
                archive_names[file_path] = original
            except UnicodeEncodeError:
                # NTFS permits unpaired UTF-16 code units; ZIP UTF-8 does not.
                # Keep evidence unchanged and include a lossless source/name map.
                escaped = "".join(f"_u{ord(ch):04X}_" if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in original)
                digest = hashlib.sha256(original.encode("utf-16-le", errors="surrogatepass")).hexdigest()[:16]
                safe_path = Path(escaped)
                mapped = safe_path.with_name(f"{safe_path.stem}~{digest}{safe_path.suffix}").as_posix()
                suffix = 1
                while mapped in occupied_names:
                    mapped = safe_path.with_name(f"{safe_path.stem}~{digest}-{suffix}{safe_path.suffix}").as_posix()
                    suffix += 1
                occupied_names.add(mapped)
                archive_names[file_path] = mapped
                filename_mapping.append({"source_path": original, "archive_path": mapped,
                                         "reason": "NTFS filename is not representable in ZIP UTF-8"})
        total_bytes = sum(p.stat().st_size for p in paths)
        completed_bytes = 0
        file_count = 0
        partial = zip_path.with_suffix(".zip.partial")
        try:
            with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                for file_path in paths:
                    check_cancelled()
                    arcname = archive_names[file_path]
                    zf.write(file_path, arcname=arcname)
                    file_count += 1
                    completed_bytes += file_path.stat().st_size
                    if progress_callback:
                        progress_callback(min(completed_bytes, total_bytes), total_bytes, arcname)
                if filename_mapping:
                    zf.writestr("_POLARIS_ARCHIVE_FILENAME_MAP.json", json.dumps(filename_mapping, indent=2, ensure_ascii=True))
                    file_count += 1
            check_cancelled()
            os.replace(partial, zip_path)
        except Exception:
            partial.unlink(missing_ok=True)
            raise

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
            "filename_mapping_count": len(filename_mapping),
        }
        manifest_path = self.archive_dir / f"{zip_filename}_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_meta, f, indent=2)

        return zip_path, zip_sha256
