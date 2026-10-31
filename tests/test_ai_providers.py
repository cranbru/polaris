import pytest
from unittest.mock import patch, MagicMock

from config.ai_settings import AISettings, AIProviderType
from ai.factory import get_ai_provider
from ai.providers.base import AIResponse
from ai.providers.openai_provider import OpenAIProvider
from ai.providers.anthropic_provider import AnthropicProvider
from ai.providers.gemini_provider import GeminiProvider
from ai.providers.offline_provider import OfflineDeterministicProvider


@pytest.mark.unit
def test_offline_provider_execution():
    provider = OfflineDeterministicProvider()
    res = provider.generate_analysis(system_prompt="system", user_prompt="user")

    assert not res.is_error
    assert res.provider == "offline"
    assert "OFFLINE FORENSIC INTELLIGENCE" in res.content


@pytest.mark.unit
def test_missing_api_keys_handling():
    # OpenAI with empty key
    op = OpenAIProvider(api_key="")
    res_op = op.generate_analysis("sys", "user")
    assert res_op.is_error
    assert "OPENAI_API_KEY" in res_op.error_message

    # Anthropic with empty key
    ap = AnthropicProvider(api_key="")
    res_ap = ap.generate_analysis("sys", "user")
    assert res_ap.is_error
    assert "ANTHROPIC_API_KEY" in res_ap.error_message

    # Gemini with empty key
    gp = GeminiProvider(api_key="")
    res_gp = gp.generate_analysis("sys", "user")
    assert res_gp.is_error
    assert "GOOGLE_API_KEY" in res_gp.error_message


@pytest.mark.unit
def test_ai_factory_instantiation():
    settings = AISettings(provider=AIProviderType.OFFLINE)
    provider = get_ai_provider(settings)
    assert isinstance(provider, OfflineDeterministicProvider)

    settings_op = AISettings(provider=AIProviderType.OPENAI, model="gpt-4o-mini")
    provider_op = get_ai_provider(settings_op)
    assert isinstance(provider_op, OpenAIProvider)
    assert provider_op.model == "gpt-4o-mini"


@pytest.mark.unit
def test_mocked_openai_success():
    provider = OpenAIProvider(api_key="sk-test-mock-key", model="gpt-4o")
    mock_payload = {
        "choices": [{"message": {"content": "Executive Summary: Incident analyzed cleanly."}}],
        "usage": {"total_tokens": 120},
    }

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = str(mock_payload).replace("'", '"').encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = provider.generate_analysis("sys", "user")
        assert not res.is_error
        assert "Incident analyzed cleanly" in res.content
        assert res.usage.get("total_tokens") == 120
