import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from desktop.settings import DesktopSettings, SettingsStore, supported_modules, profile_modules
from desktop.secrets import SecretStore
from desktop.bridge import DesktopBridge


def test_presets_and_custom_plan_persist_without_secrets(tmp_path):
    assert set(profile_modules("full")) == set(supported_modules()) - {"sensitive_files"}
    assert set(profile_modules("quick")) < set(profile_modules("full"))
    assert "sensitive_files" not in DesktopSettings().modules
    store = SettingsStore(tmp_path / "prefs.json")
    settings = DesktopSettings(modules=["system_info"], ai_provider="openai", ai_model="user-selected-model")
    store.save(settings)
    assert store.load().model_dump() == settings.model_dump()
    assert "api_key" not in json.loads(store.path.read_text())


def test_sensitive_files_explicit_opt_in_persists(tmp_path):
    store = SettingsStore(tmp_path / "prefs.json")
    settings = DesktopSettings(modules=["system_info", "sensitive_files"])
    store.save(settings)
    assert store.load().modules == settings.modules


@pytest.mark.parametrize("modules", [[], ["unsupported"]])
def test_invalid_selection_rejected(modules):
    with pytest.raises(ValueError):
        DesktopSettings(modules=modules).validate_plan()


def test_dependency_requires_explicit_enable(monkeypatch):
    from core.engine import get_registered_collectors
    collector = get_registered_collectors()["system_info"]
    monkeypatch.setattr(collector, "dependencies", ("network_info",), raising=False)
    with pytest.raises(ValueError, match="Enable it explicitly"):
        DesktopSettings(modules=["system_info"]).validate_plan()
    assert DesktopSettings(modules=["system_info", "network_info"]).validate_plan()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_dpapi_round_trip_session_only_and_bootstrap(tmp_path):
    key = "POLARIS-TEST-CREDENTIAL-DOES-NOT-AUTHENTICATE"
    secrets = SecretStore(tmp_path / "vault")
    settings = SettingsStore(tmp_path / "prefs.json")
    bridge = DesktopBridge(settings, secrets)
    assert bridge.save_configuration(DesktopSettings(ai_provider="openai").model_dump(), key, True)["ok"]
    protected = (secrets.root / "openai.dpapi").read_bytes()
    assert key.encode() not in protected
    assert SecretStore(secrets.root).get("openai") == key
    assert key not in settings.path.read_text()
    assert key not in json.dumps(bridge.bootstrap())
    assert secrets.status("openai") == {"configured": True, "persistent": True}
    assert bridge.save_configuration(DesktopSettings(ai_provider="openai").model_dump(), "", False)["ok"]
    assert secrets.get("openai") == key
    assert not SecretStore(secrets.root).get("openai")
    secrets.clear("openai")
    assert not secrets.get("openai")


def test_connection_validation_sends_no_evidence_and_handles_failure(tmp_path, monkeypatch):
    secrets = SecretStore(tmp_path / "vault")
    bridge = DesktopBridge(SettingsStore(tmp_path / "prefs.json"), secrets)
    client = Mock()
    client.generate_analysis.return_value = SimpleNamespace(is_error=False, content="POLARIS_CONNECTION_OK")
    factory = Mock(return_value=client)
    monkeypatch.setattr("desktop.bridge.get_ai_provider", factory)
    assert bridge.test_connection("openai", "chosen-model", "fake-test-key")["ok"]
    system_prompt, user_prompt = client.generate_analysis.call_args.args
    assert "No forensic evidence is provided" in system_prompt
    assert user_prompt == "Reply POLARIS_CONNECTION_OK."
    assert client.request_timeout == 20
    client.generate_analysis.return_value = SimpleNamespace(is_error=True, error_message="Invalid fake-test-key")
    failed = bridge.test_connection("openai", "chosen-model")
    assert not failed["ok"]
    assert "fake-test-key" not in failed["error"]


def test_cancel_before_consent_does_not_wait_forever(tmp_path):
    from core.progress import CancellationToken
    bridge = DesktopBridge(SettingsStore(tmp_path / "prefs.json"), SecretStore(tmp_path / "vault"))
    bridge._token = CancellationToken()
    bridge._token.cancel()
    assert bridge._request_consent({"prompt": "fixture"}) is False
