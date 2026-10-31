import sys
import io

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
