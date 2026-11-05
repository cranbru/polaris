"""
POLARIS Standalone Executable Build Script
Compiles POLARIS into a single-file, portable Windows executable (polaris.exe)
configured for USB / pendrive triage with automatic UAC elevation.
"""

import sys
import shutil
import subprocess
from pathlib import Path


def build():
    print("[POLARIS] Building standalone executable...")
    root = Path(__file__).resolve().parent

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--name",
        "polaris",
        "--clean",
        "--collect-all",
        "pyfiglet",
        "--collect-all",
        "reportlab",
        "--hidden-import",
        "jinja2",
        "--hidden-import",
        "pydantic",
        "--hidden-import",
        "typer",
        "--hidden-import",
        "rich",
        "--hidden-import",
        "LnkParse3",
        "--hidden-import",
        "olefile",
        "--hidden-import",
        "Evtx",
        "--hidden-import",
        "Registry",
        "--add-data",
        f"{root / 'reports' / 'templates'};reports/templates",
        str(root / "main.py"),
    ]

    result = subprocess.run(cmd, cwd=str(root))
    if result.returncode != 0:
        print("[POLARIS] Build failed!")
        sys.exit(result.returncode)

    dist_exe = root / "dist" / "polaris.exe"
    target_exe = root / "polaris.exe"
    if dist_exe.exists():
        shutil.copy2(dist_exe, target_exe)
        sz_mb = target_exe.stat().st_size / (1024 * 1024)
        print(f"[POLARIS] Build successful! Output: {target_exe} ({sz_mb:.2f} MB)")
    else:
        print("[POLARIS] Warning: dist/polaris.exe not found.")


if __name__ == "__main__":
    build()
