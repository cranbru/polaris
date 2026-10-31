from config.ai_settings import AISettings, AIProviderType
from ai.providers.base import BaseAIProvider
from ai.providers.openai_provider import OpenAIProvider
from ai.providers.anthropic_provider import AnthropicProvider
from ai.providers.gemini_provider import GeminiProvider
from ai.providers.offline_provider import OfflineDeterministicProvider


def get_ai_provider(settings: AISettings) -> BaseAIProvider:
    provider_type = settings.provider
    key = settings.get_api_key()
    model = settings.get_effective_model()

    if provider_type == AIProviderType.OPENAI:
        return OpenAIProvider(api_key=key, model=model)
    elif provider_type == AIProviderType.ANTHROPIC:
        return AnthropicProvider(api_key=key, model=model)
    elif provider_type == AIProviderType.GEMINI:
        return GeminiProvider(api_key=key, model=model)
    else:
        return OfflineDeterministicProvider(api_key="", model=model)
