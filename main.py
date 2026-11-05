import sys
import io
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

from cli.app import app


def should_request_admin() -> bool:
    """Check if the current invocation requires administrator privileges."""
    help_flags = {"--help", "-h", "help", "--version"}
    args_set = set(sys.argv[1:])
    if args_set and args_set.issubset(help_flags):
        return False
    return True


def run():
    if sys.platform == "win32" and "pytest" not in sys.modules:
        if should_request_admin():
            from core.permissions import is_admin, request_admin_elevation
            if not is_admin():
                request_admin_elevation()
    app()


if __name__ == "__main__":
    run()
