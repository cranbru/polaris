import json
import logging
import urllib.request
import urllib.error
from ai.providers.base import BaseAIProvider, AIResponse

logger = logging.getLogger("polaris")


class GeminiProvider(BaseAIProvider):
    provider_name: str = "gemini"

    def __init__(self, api_key: str = "", model: str = ""):
        super().__init__(api_key=api_key, model=model or "gemini-1.5-pro")

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
                error_message="GOOGLE_API_KEY environment variable is not configured.",
            )

        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        headers = {
            "Content-Type": "application/json",
        }
        payload = {
            "system_instruction": {
                "parts": [{"text": system_prompt}]
            },
            "contents": [
                {
                    "parts": [{"text": user_prompt}]
                }
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }

        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.request_timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            candidates = data.get("candidates", [])
            content = ""
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                content = "".join(p.get("text", "") for p in parts)

            usage = data.get("usageMetadata", {})
            return AIResponse(
                content=content,
                provider=self.provider_name,
                model=self.model,
                usage=usage,
            )

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace").replace(self.api_key, "[REDACTED_KEY]")
            logger.error(f"Gemini API HTTP Error {e.code}: {error_body}")
            return AIResponse(
                provider=self.provider_name,
                model=self.model,
                is_error=True,
                error_message=f"Gemini API Error ({e.code}): {error_body[:300]}",
            )
        except Exception as e:
            e = str(e).replace(self.api_key, "[REDACTED_KEY]")
            logger.error(f"Gemini request failed: {e}")
            return AIResponse(
                provider=self.provider_name,
                model=self.model,
                is_error=True,
                error_message=f"Gemini connection error: {str(e)}",
            )
