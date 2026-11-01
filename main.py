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


def run():
    app()


if __name__ == "__main__":
    run()
