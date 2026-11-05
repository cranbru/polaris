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


def request_admin_elevation() -> bool:
    """Prompts Windows UAC to elevate the current process if not already running as administrator."""
    if not is_windows() or is_admin():
        return True
    try:
        if getattr(sys, "frozen", False):
            exe = sys.executable
            args = " ".join(f'"{arg}"' for arg in sys.argv[1:])
        else:
            exe = sys.executable
            args = f'"{sys.argv[0]}" ' + " ".join(f'"{arg}"' for arg in sys.argv[1:])

        # ShellExecuteW with 'runas' verb triggers the native Windows UAC dialog
        res = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            exe,
            args,
            None,
            1  # SW_SHOWNORMAL
        )
        if int(res) > 32:
            sys.exit(0)
    except Exception:
        pass
    return is_admin()
