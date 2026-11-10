"""Native-only API for the local desktop page. Long operations run off the UI thread."""
from __future__ import annotations

import json
import os
import platform
import queue
import sys
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

from config.ai_settings import AISettings, AIProviderType
from core.permissions import is_admin
from core.progress import CancellationToken
from core.mission import MissionOptions, run_mission
from desktop.settings import DesktopSettings, SettingsStore, collector_catalog, profile_modules
from desktop.secrets import SecretStore
from ai.factory import get_ai_provider


class DesktopBridge:
    def __init__(self, settings_store=None, secret_store=None):
        self._settings_store = settings_store or SettingsStore()
        self._secrets = secret_store or SecretStore()
        self._window = None
        self._queue = queue.Queue()
        self._worker = None
        self._token = None
        self._result = None
        self._consent = threading.Event()
        self._approved = False
        self._pending_consent = False
        self._close_after = False
        self._allow_close = False
        self._last_progress_time = 0
        self._last_progress_stage = ""
        self._lock = threading.Lock()

    def _attach(self, window):
        self._window = window

    def _dispatch(self):
        # Queue-driven native dispatch: no UI polling or timed progress loops.
        while True:
            event = self._queue.get()
            if event is None:
                return
            try:
                # run_js sends literal code; evaluate_js wraps it in eval, which
                # our page's Content-Security-Policy correctly forbids.
                self._window.run_js("window.Polaris.receive(" + json.dumps(event, ensure_ascii=True) + ")")
            except Exception:
                if self._window is None:
                    return

    def _send(self, kind, data):
        self._queue.put({"type": kind, "data": data})

    def _running(self):
        return self._worker is not None and self._worker.is_alive()

    def bootstrap(self):
        settings = self._settings_store.load()
        return {"settings": settings.model_dump(), "collectors": collector_catalog(),
                "presets": {"quick": profile_modules("quick"), "full": profile_modules("full")},
                "endpoint": {"hostname": platform.node(), "os": platform.system() + " " + platform.release(),
                             "admin": is_admin()},
                "credentials": {p: self._secrets.status(p) for p in ("openai", "gemini", "anthropic")},
                "persistent_secrets_supported": sys.platform == "win32"}

    def save_configuration(self, data, key="", remember=True):
        try:
            settings = DesktopSettings.model_validate(data)
            settings.validate_plan()
            if settings.ai_provider != "offline":
                if key.strip():
                    self._secrets.set(settings.ai_provider, key, persistent=bool(remember))
                elif remember and settings.ai_provider in self._secrets.session:
                    self._secrets.set(settings.ai_provider, self._secrets.get(settings.ai_provider), persistent=True)
                if not remember:
                    self._secrets.use_session_only(settings.ai_provider)
            self._settings_store.save(settings)
            return {"ok": True, "credential": self._secrets.status(settings.ai_provider)}
        except (ValueError, OSError, RuntimeError) as error:
            return {"ok": False, "error": str(error)}

    def clear_api_key(self, provider):
        if self._running():
            return {"ok": False, "error": "Wait for acquisition to finish before removing its credential."}
        try:
            self._secrets.clear(provider)
            return {"ok": True}
        except (ValueError, OSError) as error:
            return {"ok": False, "error": str(error)}

    def test_connection(self, provider, model, key=""):
        try:
            if provider == "offline":
                return {"ok": False, "error": "Offline analysis does not use an API connection."}
            if key.strip():
                self._secrets.set(provider, key, persistent=False)
            settings = AISettings(provider=AIProviderType(provider), model=model.strip(),
                                  session_api_key=self._secrets.get(provider))
            if not settings.model or not settings.has_valid_key():
                return {"ok": False, "error": "Enter a model identifier and API key first."}
            client = get_ai_provider(settings)
            client.request_timeout = 20
            response = client.generate_analysis(
                "This is a connectivity check. No forensic evidence is provided.",
                "Reply POLARIS_CONNECTION_OK.", temperature=0, max_tokens=24)
            if response.is_error:
                return {"ok": False, "error": self._safe_error(response.error_message, settings.session_api_key)}
            if not response.content.strip():
                return {"ok": False, "error": "The provider returned no content. Check the selected model."}
            return {"ok": True, "message": "Successfully connected to provider."}
        except Exception as error:
            return {"ok": False, "error": self._safe_error(str(error), key)}

    def list_models(self, provider, key=""):
        """Retrieve current model IDs from the configured provider, without case data."""
        try:
            if key.strip():
                self._secrets.set(provider, key, persistent=False)
            secret = self._secrets.get(provider)
            if not secret:
                return {"ok": False, "error": "Enter an API key to load available models."}
            endpoints = {"openai": "https://api.openai.com/v1/models",
                         "gemini": "https://generativelanguage.googleapis.com/v1beta/models",
                         "anthropic": "https://api.anthropic.com/v1/models"}
            headers = {"Accept": "application/json"}
            if provider == "openai":
                headers["Authorization"] = f"Bearer {secret}"
            elif provider == "gemini":
                headers["x-goog-api-key"] = secret
            elif provider == "anthropic":
                headers.update({"x-api-key": secret, "anthropic-version": "2023-06-01"})
            else:
                return {"ok": False, "error": "Choose a supported external provider."}
            with urllib.request.urlopen(urllib.request.Request(endpoints[provider], headers=headers), timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
            entries = payload.get("data", payload.get("models", []))
            models = sorted({item.get("id", item.get("name", "")).removeprefix("models/") for item in entries})
            return {"ok": True, "models": [m for m in models if m]}
        except urllib.error.HTTPError as error:
            messages = {401: "Invalid API credentials.", 403: "This key cannot list models.",
                        429: "Provider rate limit reached. Try again later."}
            return {"ok": False, "error": messages.get(error.code, f"Provider returned HTTP {error.code}.")}
        except Exception as error:
            return {"ok": False, "error": self._safe_error(str(error), key)}

    def _safe_error(self, message, key=""):
        for secret in [key, *self._secrets.session.values()]:
            if secret:
                message = message.replace(secret, "[REDACTED_KEY]")
        return message[:600]

    def choose_output_folder(self):
        import webview
        selected = self._window.create_file_dialog(webview.FileDialog.FOLDER)
        return str(selected[0]) if selected else None

    def start_acquisition(self, data, case_id="", key=""):
        with self._lock:
            if self._running():
                return {"ok": False, "error": "An acquisition is already running."}
            try:
                settings = DesktopSettings.model_validate(data)
                settings.validate_plan()
                if key.strip() and settings.ai_provider != "offline":
                    self._secrets.set(settings.ai_provider, key, persistent=False)
                self._settings_store.save(settings)
                ai = AISettings(enabled=settings.ai_enabled, provider=AIProviderType(settings.ai_provider),
                                model=settings.ai_model, session_api_key=self._secrets.get(settings.ai_provider),
                                consent_granted=False, redaction_enabled=True)
                options = MissionOptions(Path(settings.output_dir), settings.modules, settings.profile,
                                         settings.parse, case_id.strip(), settings.examiner, settings.description, ai)
                self._token = CancellationToken()
                self._result = None
                self._last_progress_time = 0
                self._last_progress_stage = ""
                self._worker = threading.Thread(target=self._run, args=(options,), daemon=True,
                                                name="polaris-acquisition")
                self._worker.start()
                return {"ok": True}
            except (ValueError, OSError) as error:
                return {"ok": False, "error": str(error)}

    def _progress(self, event):
        now = time.monotonic()
        terminal = event.state in {"COMPLETED", "FAILED", "CANCELLED"}
        if terminal or event.stage != self._last_progress_stage or now - self._last_progress_time >= .10:
            self._send("progress", event.to_dict())
            self._last_progress_time, self._last_progress_stage = now, event.stage

    def _request_consent(self, packet):
        self._approved = False
        self._pending_consent = True
        self._consent.clear()
        if self._token and self._token.event.is_set():
            self._pending_consent = False
            return False
        self._send("consent", packet)
        self._consent.wait()  # Examiner decision or cancellation wakes this wait.
        self._pending_consent = False
        return self._approved

    def respond_ai_consent(self, approved):
        if not self._pending_consent:
            return {"ok": False, "error": "No evidence submission is awaiting review."}
        self._approved = bool(approved)
        self._consent.set()
        return {"ok": True}

    def _run(self, options):
        try:
            self._result = run_mission(options, self._progress, self._token, self._request_consent)
            if self._result.get("workflow_completed") or self._result.get("state") == "COMPLETED":
                self._result["output_open_errors"] = self._open_completion_outputs()
            self._send("result", self._result)
        except Exception:
            self._result = {"state": "FAILED", "error": "The acquisition worker stopped unexpectedly. Review the case logs.",
                            "case_dir": "", "outputs": {}, "warnings": [], "modules": [],
                            "workflow_completed": False}
            self._send("result", self._result)
        finally:
            if self._close_after and self._window:
                self._window.destroy()

    def cancel_acquisition(self):
        if self._token and self._running():
            self._token.cancel()
            self._consent.set()
            return {"ok": True, "message": "Cancelling at the next safe checkpoint. The current system command may need to finish."}
        return {"ok": False, "error": "No acquisition is running."}

    def open_output(self, kind):
        if not self._result:
            return {"ok": False, "error": "No case output is available yet."}
        path = self._result.get("case_dir") if kind == "folder" else self._result.get("outputs", {}).get(kind)
        if not path or not Path(path).exists():
            return {"ok": False, "error": "This output was not generated. Open the case folder for diagnostics."}
        try:
            os.startfile(str(Path(path).resolve()))
        except OSError as error:
            return {"ok": False, "error": f"Could not open {kind}: {error}"}
        return {"ok": True}

    def _open_completion_outputs(self):
        # Each finished acquisition opens both outputs once. A shell launch
        # failure must not change the acquisition's recorded outcome.
        errors = []
        for kind in ("report", "folder"):
            response = self.open_output(kind)
            if not response["ok"]:
                errors.append(response["error"])
        return errors

    def toggle_fullscreen(self):
        self._window.toggle_fullscreen()
        return {"ok": True}

    def restart_elevated(self, data):
        if self._running():
            return {"ok": False, "error": "Stop acquisition before restarting elevated."}
        saved = self.save_configuration(data)
        if not saved["ok"]:
            return saved
        import ctypes
        import subprocess
        args = ["--gui"] if getattr(sys, "frozen", False) else [str(Path(__file__).resolve().parent.parent / "main.py"), "--gui"]
        status = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                                     subprocess.list2cmdline(args), str(Path.cwd()), 1)
        if status > 32:
            self._allow_close = True
            self._window.destroy()
            return {"ok": True}
        return {"ok": False, "error": "Administrator restart was declined or unavailable."}

    def request_close(self, cancel_running=False):
        if self._running():
            if cancel_running:
                self._close_after = True
                self.cancel_acquisition()
            else:
                self._send("close_requested", {})
            return False
        self._queue.put(None)
        self._allow_close = True
        if self._window:
            self._window.destroy()
        return True

    def _closing(self):
        if not self._allow_close and not self._close_after:
            self._send("close_requested", {})
            return False
        self._queue.put(None)
        return True
