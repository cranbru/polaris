"""Native desktop window using the installed Windows WebView2 renderer."""
from pathlib import Path
import sys
import threading


def resource_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "desktop" / "resources"
    return Path(__file__).resolve().parent / "resources"


def run_desktop():
    try:
        _open_desktop()
    except Exception:
        import os
        import traceback
        root = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Polaris" / "logs"
        diagnostic = root / "desktop_startup.log"
        try:
            root.mkdir(parents=True, exist_ok=True)
            diagnostic.write_text(traceback.format_exc(), encoding="utf-8")
        except OSError:
            diagnostic = None
        if sys.platform == "win32":
            import ctypes
            message = "POLARIS could not open its desktop window. Check that Microsoft Edge WebView2 Runtime is installed."
            if diagnostic:
                message += f"\n\nStartup diagnostics: {diagnostic}"
            ctypes.windll.user32.MessageBoxW(None, message, "POLARIS — Desktop startup", 0x10)
        else:
            raise


def _open_desktop():
    import webview
    from desktop.bridge import DesktopBridge

    bridge = DesktopBridge()
    window = webview.create_window("POLARIS — Digital Forensics", str(resource_dir() / "index.html"),
                                   js_api=bridge, width=1440, height=920, min_size=(900, 680),
                                   background_color="#030b15", text_select=True)
    bridge._attach(window)
    window.events.closing += bridge._closing

    def ready():
        threading.Thread(target=bridge._dispatch, daemon=True, name="polaris-ui-dispatch").start()

    window.events.loaded += ready
    webview.settings["ALLOW_DOWNLOADS"] = False
    webview.start(gui="edgechromium" if sys.platform == "win32" else None, http_server=True,
                  private_mode=True, debug=False)
