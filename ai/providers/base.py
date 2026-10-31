from abc import ABC, abstractmethod
from typing import Optional
from pydantic import BaseModel, Field

from config.settings import get_iso_timestamp


class AIResponse(BaseModel):
    content: str = ""
    provider: str = ""
    model: str = ""
    is_error: bool = False
    error_message: str = ""
    usage: dict = Field(default_factory=dict)
    timestamp: str = Field(default_factory=get_iso_timestamp)


class BaseAIProvider(ABC):
    provider_name: str = "base"

    def __init__(self, api_key: str = "", model: str = ""):
        self.api_key = api_key
        self.model = model

    @abstractmethod
    def generate_analysis(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_tokens: int = 4000,
    ) -> AIResponse:
        pass
