import os
import json
from pathlib import Path
from enum import Enum
from pydantic import BaseModel, Field

CONFIG_FILE_PATH = Path(".polaris_config.json")


class AIProviderType(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OFFLINE = "offline"


DEFAULT_MODELS = {
    AIProviderType.OPENAI: "gpt-4o",
    AIProviderType.ANTHROPIC: "claude-3-5-sonnet-20241022",
    AIProviderType.GEMINI: "gemini-1.5-pro",
    AIProviderType.OFFLINE: "offline-deterministic",
}


class AISettings(BaseModel):
    enabled: bool = True
    provider: AIProviderType = AIProviderType.OFFLINE
    model: str = ""
    max_output_tokens: int = 4000
    temperature: float = 0.2
    consent_granted: bool = False
    redaction_enabled: bool = True

    def get_effective_model(self) -> str:
        if self.model:
            return self.model
        return DEFAULT_MODELS.get(self.provider, "default")

    def get_api_key(self) -> str:
        if self.provider == AIProviderType.OPENAI:
            return os.environ.get("OPENAI_API_KEY", "")
        elif self.provider == AIProviderType.ANTHROPIC:
            return os.environ.get("ANTHROPIC_API_KEY", "")
        elif self.provider == AIProviderType.GEMINI:
            return os.environ.get("GOOGLE_API_KEY", "") or os.environ.get("GEMINI_API_KEY", "")
        return ""

    def has_valid_key(self) -> bool:
        if self.provider == AIProviderType.OFFLINE:
            return True
        return bool(self.get_api_key().strip())

    def masked_api_key(self) -> str:
        key = self.get_api_key()
        if not key:
            return "[NOT CONFIGURED]"
        if len(key) <= 8:
            return "********"
        return f"{key[:4]}...{key[-4:]}"


def load_ai_settings() -> AISettings:
    # 1. Start with defaults
    settings = AISettings()

    # 2. Check local config file if present
    if CONFIG_FILE_PATH.exists():
        try:
            with open(CONFIG_FILE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                settings = AISettings(**data)
        except Exception:
            pass

    # 3. Environment variables override
    env_enabled = os.environ.get("AI_ENABLED")
    if env_enabled is not None:
        settings.enabled = env_enabled.lower() in ["true", "1", "yes"]

    env_provider = os.environ.get("AI_PROVIDER")
    if env_provider and env_provider.lower() in [p.value for p in AIProviderType]:
        settings.provider = AIProviderType(env_provider.lower())

    env_model = os.environ.get("AI_MODEL")
    if env_model:
        settings.model = env_model

    env_tokens = os.environ.get("AI_MAX_OUTPUT_TOKENS")
    if env_tokens and env_tokens.isdigit():
        settings.max_output_tokens = int(env_tokens)

    env_temp = os.environ.get("AI_TEMPERATURE")
    if env_temp:
        try:
            settings.temperature = float(env_temp)
        except ValueError:
            pass

    return settings


def save_ai_settings(settings: AISettings) -> None:
    # Save settings without any API keys
    data = settings.model_dump()
    with open(CONFIG_FILE_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
