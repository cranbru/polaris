import sys
import os
import warnings

# Suppress benign third-party library warnings (e.g., LnkParse3 unknown index, google SDK deprecation notices)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", module="LnkParse3.*")
warnings.filterwarnings("ignore", message=".*sort_index_value.*")

# Ensure UTF-8 output encoding for Windows terminals
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def should_request_admin() -> bool:
    """Check if the current invocation requires administrator privileges."""
    help_flags = {"--help", "-h", "help", "--version"}
    args_set = set(sys.argv[1:]) - {"--cli"}
    if args_set and args_set.issubset(help_flags):
        return False
    return True


def _prepare_streams(cli: bool):
    """Windowed executables have no Python streams; retain CLI pipes when supplied."""
    if cli and sys.platform == "win32" and getattr(sys, "frozen", False):
        import ctypes
        import msvcrt
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel.GetStdHandle.restype = wintypes.HANDLE
        kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                          ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                                          wintypes.BOOL, wintypes.DWORD]
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.AttachConsole(-1)
        for name, number, mode in (("stdin", -10, "r"), ("stdout", -11, "w"), ("stderr", -12, "w")):
            if getattr(sys, name) is not None:
                continue
            handle = kernel.GetStdHandle(number)
            if handle and handle != ctypes.c_void_p(-1).value:
                duplicate = wintypes.HANDLE()
                process = kernel.GetCurrentProcess()
                if kernel.DuplicateHandle(process, handle, process, ctypes.byref(duplicate), 0, False, 2):
                    fd = msvcrt.open_osfhandle(duplicate.value, os.O_RDONLY if mode == "r" else os.O_WRONLY)
                    setattr(sys, name, os.fdopen(fd, mode, encoding="utf-8", errors="replace", buffering=1))
        if sys.stdout is None:
            kernel.AllocConsole()
            for name, device, mode in (("stdin", "CONIN$", "r"), ("stdout", "CONOUT$", "w"), ("stderr", "CONOUT$", "w")):
                setattr(sys, name, open(device, mode, encoding="utf-8", errors="replace"))
    for name, mode in (("stdin", "r"), ("stdout", "w"), ("stderr", "w")):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, mode, encoding="utf-8"))


def run():
    args = sys.argv[1:]
    gui = not args or "--gui" in args
    if "--cli" in args:
        gui = False
    sys.argv = [sys.argv[0], *[arg for arg in args if arg not in {"--cli", "--gui"}]]
    _prepare_streams(cli=not gui)
    if gui:
        from desktop.application import run_desktop
        run_desktop()
        return
    if sys.platform == "win32" and "pytest" not in sys.modules:
        if should_request_admin():
            from core.permissions import is_admin, request_admin_elevation
            if not is_admin():
                request_admin_elevation()
    from cli.app import app
    app()


if __name__ == "__main__":
    run()
