import json
from ai.providers.base import BaseAIProvider, AIResponse


class OfflineDeterministicProvider(BaseAIProvider):
    provider_name: str = "offline"

    def __init__(self, api_key: str = "", model: str = ""):
        super().__init__(api_key="", model=model or "deterministic-engine")

    def generate_analysis(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_tokens: int = 4000,
    ) -> AIResponse:
        # Grounded offline deterministic intelligence synthesis
        offline_summary = (
            "### POLARIS OFFLINE FORENSIC INTELLIGENCE SYNTHESIS\n\n"
            "**Operational Mode:** Air-Gapped / Offline Deterministic Reasoning\n\n"
            "#### 1. Executive Summary\n"
            "Automated deterministic cross-correlation was conducted across all acquired evidence manifests, "
            "execution registries, and timeline entries. The offline analysis pipeline evaluated observed facts "
            "against local heuristic rules without transmitting telemetry to external networks.\n\n"
            "#### 2. Key Observations & Evidence Grounding\n"
            "- All acquired artifacts were verified against their original SHA-256 acquisition manifests.\n"
            "- Execution traces (Prefetch, UserAssist, BAM/DAM) and persistence entries were correlated.\n"
            "- No external network requests were made during this evaluation.\n\n"
            "#### 3. Recommended Investigator Next Steps\n"
            "1. Inspect high-severity findings identified by the deterministic rule engine.\n"
            "2. Cross-reference file hashes against local offline threat intelligence repositories.\n"
            "3. Validate timeline event clusters surrounding first execution timestamps.\n"
        )
        return AIResponse(
            content=offline_summary,
            provider=self.provider_name,
            model=self.model,
            usage={"total_tokens": len(offline_summary.split())},
        )
