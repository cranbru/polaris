"""
POLARIS Standalone Executable Build Script
Compiles POLARIS into a single-file, portable Windows executable (polaris.exe)
configured for desktop setup, optional elevation, and USB / pendrive triage.
"""

import sys
import shutil
import subprocess
from pathlib import Path


def ensure_icon():
    root = Path(__file__).resolve().parent
    png_path = root / "Polaris_logo.png"
    ico_path = root / "polaris_logo.ico"
    if png_path.exists():
        try:
            from PIL import Image
            img = Image.open(png_path)
            icon_sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
            img.save(ico_path, format="ICO", sizes=icon_sizes)
            print(f"[POLARIS] Generated application icon: {ico_path}")
        except Exception as e:
            print(f"[POLARIS] Warning: Could not generate icon: {e}")


def build():
    print("[POLARIS] Building standalone executable via polaris.spec...")
    root = Path(__file__).resolve().parent
    ensure_icon()

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        str(root / "polaris.spec"),
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
