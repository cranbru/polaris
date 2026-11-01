import os
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from config.ai_settings import AISettings, AIProviderType
from cli.interactive import prompt_ai_configuration
from cli.app import app

runner = CliRunner()


def test_prompt_ai_configuration_decline_no_active_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with patch("builtins.input", side_effect=["n"]):
        settings = AISettings()
        res = prompt_ai_configuration(settings)
        assert res.provider == AIProviderType.OFFLINE
        assert res.consent_granted is True


def test_prompt_ai_configuration_select_gemini(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    with patch("builtins.input", side_effect=["y", "1", "AIzaSyTestKey123", "gemini-1.5-pro"]):
        settings = AISettings()
        res = prompt_ai_configuration(settings)
        assert res.provider == AIProviderType.GEMINI
        assert res.model == "gemini-1.5-pro"
        assert res.session_api_key == "AIzaSyTestKey123"
        assert res.consent_granted is True


def test_prompt_ai_configuration_select_openai(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with patch("builtins.input", side_effect=["y", "2", "sk-proj-testkey456", "gpt-4o"]):
        settings = AISettings()
        res = prompt_ai_configuration(settings)
        assert res.provider == AIProviderType.OPENAI
        assert res.model == "gpt-4o"
        assert res.session_api_key == "sk-proj-testkey456"
        assert res.consent_granted is True


def test_prompt_ai_configuration_manual_custom(monkeypatch):
    with patch("builtins.input", side_effect=["y", "4", "gemini", "gemini-2.5-flash", "AIzaSyCustom"]):
        settings = AISettings()
        res = prompt_ai_configuration(settings)
        assert res.provider == AIProviderType.GEMINI
        assert res.model == "gemini-2.5-flash"
        assert res.session_api_key == "AIzaSyCustom"
        assert res.consent_granted is True


def test_prompt_ai_configuration_offline_choice():
    with patch("builtins.input", side_effect=["y", "5"]):
        settings = AISettings()
        res = prompt_ai_configuration(settings)
        assert res.provider == AIProviderType.OFFLINE
        assert res.model == "offline-deterministic"
        assert res.consent_granted is True


def test_cli_default_invocation_calls_quick(monkeypatch):
    with patch("cli.app.execute_mission") as mock_exec:
        result = runner.invoke(app, ["--no-prompt", "--no-open"])
        assert result.exit_code == 0
        assert mock_exec.called
        kwargs = mock_exec.call_args[1]
        assert kwargs["profile"].value == "quick"


def test_cli_full_flag_invocation_calls_full(monkeypatch):
    with patch("cli.app.execute_mission") as mock_exec:
        result = runner.invoke(app, ["--full", "--no-prompt", "--no-open"])
        assert result.exit_code == 0
        assert mock_exec.called
        kwargs = mock_exec.call_args[1]
        assert kwargs["profile"].value == "full"
