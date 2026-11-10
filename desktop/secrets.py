"""Windows DPAPI secret storage. No keys in desktop preference files."""
from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from ctypes import wintypes


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _crypt(data: bytes, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise RuntimeError("Persistent key storage requires Windows DPAPI; keys can be used for this session only.")
    buffer = ctypes.create_string_buffer(data)
    source = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = DATA_BLOB()
    crypt32, kernel32 = ctypes.WinDLL("crypt32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    if protect:
        function = crypt32.CryptProtectData
        function.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR, ctypes.c_void_p,
                             ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
        ok = function(ctypes.byref(source), "POLARIS AI credential", None, None, None, 1, ctypes.byref(output))
    else:
        function = crypt32.CryptUnprotectData
        function.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
                             ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
        ok = function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output))
    if not ok:
        raise OSError(ctypes.get_last_error(), "Windows could not access the protected AI credential.")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)


class SecretStore:
    PROVIDERS = {"openai", "gemini", "anthropic"}

    def __init__(self, root: Path | None = None):
        self.root = root or Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Polaris" / "credentials"
        self.session: dict[str, str] = {}

    def _path(self, provider):
        if provider not in self.PROVIDERS:
            raise ValueError("Unsupported credential provider.")
        return self.root / f"{provider}.dpapi"

    def set(self, provider: str, key: str, persistent: bool = True):
        path = self._path(provider)
        if not key.strip():
            raise ValueError("Enter an API key.")
        self.session[provider] = key.strip()
        if persistent:
            encrypted = _crypt(key.strip().encode("utf-8"), True)
            self.root.mkdir(parents=True, exist_ok=True)
            temp = path.with_suffix(".tmp")
            temp.write_bytes(encrypted)
            os.replace(temp, path)

    def get(self, provider: str):
        if provider == "offline":
            return ""
        path = self._path(provider)
        if provider in self.session:
            return self.session[provider]
        if path.exists():
            try:
                return _crypt(path.read_bytes(), False).decode("utf-8")
            except (OSError, RuntimeError, UnicodeError):
                return ""
        return ""

    def clear(self, provider: str):
        self.session.pop(provider, None)
        self._path(provider).unlink(missing_ok=True)

    def use_session_only(self, provider: str):
        key = self.get(provider)
        self._path(provider).unlink(missing_ok=True)
        if key:
            self.session[provider] = key

    def status(self, provider: str):
        # Never return even a fragment of the stored key to the web UI.
        configured = bool(self.get(provider))
        persistent = False
        if configured and provider != "offline" and self._path(provider).exists():
            try:
                stored = _crypt(self._path(provider).read_bytes(), False).decode("utf-8")
                persistent = stored == self.get(provider)
            except (OSError, RuntimeError, UnicodeError):
                pass
        return {"configured": configured, "persistent": persistent}
