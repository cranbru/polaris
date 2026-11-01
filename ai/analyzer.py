import json
import logging
from pathlib import Path
from typing import Any

from config.settings import get_iso_timestamp
from config.ai_settings import AISettings, AIProviderType
from ai.factory import get_ai_provider
from ai.security import PromptSecurityManager
from ai.redaction import RedactionManager
from ai.consent import request_ai_consent
from ai.prompts import FORENSIC_SYSTEM_PROMPT, build_analysis_user_prompt
from ai.smart_evidence import extract_smart_evidence_context
from core.case_manager import CaseManager
from core.evidence_manager import EvidenceManager
from core.timeline import TimelineBuilder
from analysis.finding_models import Finding

logger = logging.getLogger("polaris")


class StellarIntelligenceAnalyzer:
    def __init__(self, case_dir: Path, settings: AISettings):
        self.case_dir = case_dir
        self.settings = settings
        self.metadata_dir = case_dir / "metadata"
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

    def run_analysis(self, offline_override: bool = False) -> dict[str, Any]:
        if offline_override:
            self.settings.provider = AIProviderType.OFFLINE

        # Load case details
        case_mgr = CaseManager(self.case_dir.parent)
        metadata = case_mgr.load_metadata(self.case_dir)
        case_id = metadata.case_id if metadata else self.case_dir.name

        # Load system info
        sys_path = self.metadata_dir / "system_info.json"
        system_info = {}
        if sys_path.exists():
            try:
                with open(sys_path, "r", encoding="utf-8") as f:
                    system_info = json.load(f)
            except Exception:
                pass

        # Load evidence summary
        ev_mgr = EvidenceManager(self.case_dir)
        ev_mgr.load_results()
        summary = ev_mgr.get_summary()

        # Load deterministic findings
        findings_path = self.metadata_dir / "findings.json"
        findings_data = []
        if findings_path.exists():
            try:
                with open(findings_path, "r", encoding="utf-8") as f:
                    findings_data = json.load(f)
            except Exception:
                pass

        # Load timeline sample
        timeline_builder = TimelineBuilder(self.case_dir)
        timeline_builder.build_from_parsed()
        timeline_builder.sort_events()
        timeline_sample = [e.model_dump() for e in timeline_builder.events[:30]]

        # Consent check
        categories = list(summary.get("categories", ["Execution", "Persistence", "EventLogs", "Registry"]))
        has_consent = request_ai_consent(self.settings, categories)
        if not has_consent:
            self.settings.provider = AIProviderType.OFFLINE

        # Smartly sample high-value evidence (curate LNK, prefetch, network, persistence)
        smart_evidence = extract_smart_evidence_context(self.case_dir)

        # Construct safe prompt
        raw_user_prompt = build_analysis_user_prompt(
            case_id=case_id,
            system_info=system_info,
            evidence_summary=summary,
            rule_findings=findings_data,
            timeline_sample=timeline_sample,
            smart_evidence=smart_evidence,
        )

        # Apply redaction
        if self.settings.redaction_enabled:
            raw_user_prompt = RedactionManager.redact(raw_user_prompt)

        # Wrap in security tags to prevent prompt injection
        safe_user_prompt = PromptSecurityManager.wrap_evidence_context(raw_user_prompt)

        # Execute Provider
        provider = get_ai_provider(self.settings)
        response = provider.generate_analysis(
            system_prompt=FORENSIC_SYSTEM_PROMPT,
            user_prompt=safe_user_prompt,
            temperature=self.settings.temperature,
            max_tokens=self.settings.max_output_tokens,
        )

        if response.is_error and provider.provider_name != "offline":
            logger.warning(
                f"Online provider {provider.provider_name} error: {response.error_message}. "
                "Engaging offline deterministic fallback."
            )
            from ai.providers.offline_provider import OfflineDeterministicProvider
            fb = OfflineDeterministicProvider(api_key="", model="offline-deterministic")
            fb_resp = fb.generate_analysis(
                system_prompt=FORENSIC_SYSTEM_PROMPT,
                user_prompt=safe_user_prompt,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_output_tokens,
            )
            if not fb_resp.is_error:
                response = fb_resp
                response.model = f"offline-fallback ({provider.provider_name})"

        result_payload = {
            "case_id": case_id,
            "provider": response.provider,
            "model": response.model,
            "is_error": response.is_error,
            "error_message": response.error_message,
            "analysis_timestamp": get_iso_timestamp(),
            "content": response.content,
            "usage": response.usage,
            "redaction_applied": self.settings.redaction_enabled,
            "evidence_reference_count": len(findings_data) + len(timeline_sample),
        }

        # Save JSON output
        json_path = self.metadata_dir / "ai_analysis.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result_payload, f, indent=2, ensure_ascii=False)

        # Save Markdown report
        md_path = self.metadata_dir / "ai_analysis.md"
        md_content = (
            f"# POLARIS STELLAR INTELLIGENCE REPORT\n"
            f"**Case:** {case_id}  |  **Provider:** {response.provider.upper()} ({response.model})  |  **Timestamp:** {get_iso_timestamp()}\n\n"
            f"---\n\n"
            f"{response.content}\n"
        )
        md_path.write_text(md_content, encoding="utf-8")

        return result_payload
