import shutil
from pathlib import Path
from typing import Generator


def safe_copy(src: Path, dest: Path) -> bool:
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src), str(dest))
        return True
    except (OSError, PermissionError):
        return False


def safe_glob(directory: Path, pattern: str) -> list[Path]:
    try:
        if directory.exists():
            return list(directory.glob(pattern))
    except (OSError, PermissionError):
        pass
    return []


def iter_files(directory: Path, extensions: list[str] | None = None) -> Generator[Path, None, None]:
    try:
        if not directory.exists():
            return
        for item in directory.rglob("*"):
            if item.is_file():
                if extensions is None or item.suffix.lower() in extensions:
                    yield item
    except (OSError, PermissionError):
        return


def get_size_str(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
