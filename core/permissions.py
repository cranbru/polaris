import ctypes
import sys
import platform


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        return False


def is_windows() -> bool:
    return platform.system() == "Windows"


def require_windows() -> bool:
    if not is_windows():
        return False
    return True


def get_windows_version() -> str:
    try:
        ver = platform.version()
        release = platform.release()
        return f"Windows {release} (Build {ver})"
    except Exception:
        return "Unknown Windows Version"


def check_privilege(required: str) -> bool:
    if required == "user":
        return True
    if required == "admin":
        return is_admin()
    return True
