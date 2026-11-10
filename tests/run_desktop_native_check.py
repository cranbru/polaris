"""Opt-in native WebView2/bridge check using System Information only.

Runs the actual local page and API in a hidden QA window. No native screen
capture, computer-use interaction, external AI or broad artifact scan is used.
Run: python -m tests.run_desktop_native_check
"""
import json
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

import webview
from desktop.application import resource_dir
from desktop.bridge import DesktopBridge
from desktop.settings import SettingsStore
from desktop.secrets import SecretStore


class QABridge(DesktopBridge):
    def __init__(self, root):
        super().__init__(SettingsStore(root / "native-preferences.json"), SecretStore(root / "native-keys"))
        self._qa_root = root
        self._qa_data = None
        self._qa_done = threading.Event()
        self._qa_opened_outputs = []

    def report_qa(self, data):
        data["auto_opened_outputs"] = self._qa_opened_outputs
        self._qa_data = data
        self._qa_done.set()
        return True


def main():
    root = Path(tempfile.gettempdir()) / "polaris-ui-validation"
    root.mkdir(exist_ok=True)
    bridge = QABridge(root)
    window = webview.create_window("POLARIS Native QA", str(resource_dir() / "index.html"),
                                   js_api=bridge, width=1440, height=920, hidden=True)
    bridge._attach(window)

    def loaded():
        threading.Thread(target=bridge._dispatch, daemon=True).start()
        window.run_js("""
        (async function() {
          const waitFor = async predicate => {
            while (!predicate()) await new Promise(resolve => setTimeout(resolve, 50));
          };
          try {
            await waitFor(() => state.settings !== null);
            let loopCount = 0, lastVideoTime = 0;
            document.getElementById('background-video').addEventListener('timeupdate', event => {
              const current = event.target.currentTime;
              if (lastVideoTime > current + 1) loopCount++;
              lastVideoTime = current;
            });
            state.settings.modules = ['system_info'];
            state.settings.output_dir = OUTPUT_PATH;
            state.settings.ai_enabled = false;
            hydrateSettings();
            reviewAcquisition();
            await startAcquisition();
            const collapsedDuringRun = document.getElementById('processing-details').hidden;
            const cancelAvailable = !document.getElementById('cancel-acquisition').hidden;
            await waitFor(() => state.result !== null);
            await window.pywebview.api.report_qa({
              state: state.result.state,
              count: state.result.artifact_count,
              percentage: document.getElementById('progress-percentage').textContent,
              operation: document.getElementById('processing-title').textContent,
              bridge_available: !!window.pywebview.api.bootstrap,
              video_playing: !document.getElementById('background-video').paused,
              video_loop_count: loopCount,
              selected: state.settings.modules,
              collapsed_during_run: collapsedDuringRun,
              cancel_available: cancelAvailable,
              expanded_at_completion: !document.getElementById('processing-details').hidden,
              diagnostics_collapsed: document.getElementById('result-details').hidden && document.getElementById('operation-details').hidden,
              metrics_visible: document.getElementById('processed-modules').getBoundingClientRect().height > 0,
              output_buttons_visible: document.getElementById('open-report').getBoundingClientRect().height > 0,
              log_rows: document.getElementById('activity-log').children.length,
              error: state.result.error || null
            });
          } catch (error) { await window.pywebview.api.report_qa({error:error.message}); }
        })();
        """.replace("OUTPUT_PATH", json.dumps(str(root / "native-cases"))))

    def finish():
        if not bridge._qa_done.wait(180):
            bridge.cancel_acquisition()
            bridge._qa_data = {"error": "Native page/bridge check timed out"}
        (root / "native-check.json").write_text(json.dumps(bridge._qa_data, indent=2), encoding="utf-8")
        window.destroy()

    window.events.loaded += loaded
    # Verify the real bridge's shell requests without opening QA files on the
    # user's desktop. Production uses the ordinary Windows file associations.
    with patch("desktop.bridge.os.startfile", lambda path: bridge._qa_opened_outputs.append(path)):
        webview.start(finish, gui="edgechromium", http_server=True, private_mode=True)
    print(json.dumps(bridge._qa_data, indent=2))
    assert bridge._qa_data.get("state") == "COMPLETED", bridge._qa_data
    assert bridge._qa_data["percentage"] == "100%"
    assert bridge._qa_data["selected"] == ["system_info"]
    assert bridge._qa_data["bridge_available"]
    assert bridge._qa_data["video_playing"]
    assert bridge._qa_data["log_rows"] > 1
    assert bridge._qa_data["collapsed_during_run"]
    assert bridge._qa_data["cancel_available"]
    assert bridge._qa_data["expanded_at_completion"]
    assert bridge._qa_data["diagnostics_collapsed"]
    assert bridge._qa_data["metrics_visible"]
    assert bridge._qa_data["output_buttons_visible"]
    assert len(bridge._qa_data["auto_opened_outputs"]) == 2
    assert all(Path(path).exists() for path in bridge._qa_data["auto_opened_outputs"])


if __name__ == "__main__":
    main()
