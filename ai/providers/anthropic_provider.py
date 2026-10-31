import json
import logging
import urllib.request
import urllib.error
from ai.providers.base import BaseAIProvider, AIResponse

logger = logging.getLogger("polaris")


class AnthropicProvider(BaseAIProvider):
    provider_name: str = "anthropic"

    def __init__(self, api_key: str = "", model: str = ""):
        super().__init__(api_key=api_key, model=model or "claude-3-5-sonnet-20241022")

    def generate_analysis(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_tokens: int = 4000,
    ) -> AIResponse:
        if not self.api_key:
            return AIResponse(
                provider=self.provider_name,
                model=self.model,
                is_error=True,
                error_message="ANTHROPIC_API_KEY environment variable is not configured.",
            )

        endpoint = "https://api.anthropic.com/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": self.model,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            content = ""
            for block in data.get("content", []):
                if block.get("type") == "text":
                    content += block.get("text", "")

            usage = data.get("usage", {})
            return AIResponse(
                content=content,
                provider=self.provider_name,
                model=self.model,
                usage=usage,
            )

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            logger.error(f"Anthropic API HTTP Error {e.code}: {error_body}")
            return AIResponse(
                provider=self.provider_name,
                model=self.model,
                is_error=True,
                error_message=f"Anthropic API Error ({e.code}): {error_body[:300]}",
            )
        except Exception as e:
            logger.error(f"Anthropic request failed: {e}")
            return AIResponse(
                provider=self.provider_name,
                model=self.model,
                is_error=True,
                error_message=f"Anthropic connection error: {str(e)}",
            )
