import platform
import os
import json
from pathlib import Path
from datetime import datetime

from config.settings import get_iso_timestamp, TOOL_NAME, TOOL_VERSION


def collect_system_info() -> dict:
    info = {
        "collection_timestamp": get_iso_timestamp(),
        "volatile_data": True,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "username": os.getlogin() if hasattr(os, "getlogin") else os.environ.get("USERNAME", "unknown"),
        "home_directory": str(Path.home()),
        "system_drive": os.environ.get("SystemDrive", "C:"),
        "windows_directory": os.environ.get("SystemRoot", r"C:\Windows"),
        "temp_directory": os.environ.get("TEMP", ""),
        "number_of_processors": os.environ.get("NUMBER_OF_PROCESSORS", ""),
        "domain": os.environ.get("USERDOMAIN", ""),
    }

    try:
        import locale
        info["locale"] = locale.getdefaultlocale()[0] or ""
    except Exception:
        info["locale"] = ""

    try:
        import time
        info["timezone"] = time.tzname[0] if time.tzname else ""
        info["utc_offset_seconds"] = time.timezone
    except Exception:
        pass

    return info


def save_system_info(case_dir: Path) -> Path:
    info = collect_system_info()
    dest = case_dir / "metadata" / "system_info.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)
    return dest
