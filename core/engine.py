import logging
from pathlib import Path
from typing import Callable, Optional

from config.settings import CollectionProfile, CollectionStatus, LIVE_ACQUISITION_WARNING, get_iso_timestamp
from config.profiles import get_modules_for_profile
from core.collector_base import CollectorBase, CollectionResult
from core.case_manager import CaseManager
from core.evidence_manager import EvidenceManager
from core.manifest import ManifestManager
from core.permissions import check_privilege, is_admin
from core.system_info import save_system_info
from core.progress import AcquisitionCancelled, check_cancelled
from utils.logging_config import setup_logging

logger = logging.getLogger("polaris")

COLLECTOR_REGISTRY: dict[str, type[CollectorBase]] = {}


def register_collector(module_id: str):
    def decorator(cls: type[CollectorBase]):
        COLLECTOR_REGISTRY[module_id] = cls
        return cls
    return decorator


def _import_all_collectors():
    """Statically imports all collectors so PyInstaller bundles them and registers them into COLLECTOR_REGISTRY."""
    try:
        import collectors.execution.prefetch
    except Exception as e:
        logger.debug(f"prefetch collector import error: {e}")
    try:
        import collectors.execution.amcache
    except Exception as e:
        logger.debug(f"amcache collector import error: {e}")
    try:
        import collectors.execution.shimcache
    except Exception as e:
        logger.debug(f"shimcache collector import error: {e}")
    try:
        import collectors.execution.bam
    except Exception as e:
        logger.debug(f"bam collector import error: {e}")
    try:
        import collectors.execution.srum
    except Exception as e:
        logger.debug(f"srum collector import error: {e}")
    try:
        import collectors.execution.userassist
    except Exception as e:
        logger.debug(f"userassist collector import error: {e}")
    try:
        import collectors.execution.pca
    except Exception as e:
        logger.debug(f"pca collector import error: {e}")
    try:
        import collectors.execution.powershell_artifacts
    except Exception as e:
        logger.debug(f"powershell_artifacts collector import error: {e}")
    try:
        import collectors.eventlogs.evtx_collector
    except Exception as e:
        logger.debug(f"evtx_collector import error: {e}")
    try:
        import collectors.user_activity.lnk_collector
    except Exception as e:
        logger.debug(f"lnk_collector import error: {e}")
    try:
        import collectors.user_activity.jump_lists
    except Exception as e:
        logger.debug(f"jump_lists collector import error: {e}")
    try:
        import collectors.user_activity.recent_docs
    except Exception as e:
        logger.debug(f"recent_docs collector import error: {e}")
    try:
        import collectors.user_activity.shellbags
    except Exception as e:
        logger.debug(f"shellbags collector import error: {e}")
    try:
        import collectors.user_activity.recycle_bin
    except Exception as e:
        logger.debug(f"recycle_bin collector import error: {e}")
    try:
        import collectors.registry.hive_collector
    except Exception as e:
        logger.debug(f"hive_collector import error: {e}")
    try:
        import collectors.registry.registry_artifacts
    except Exception as e:
        logger.debug(f"registry_artifacts collector import error: {e}")
    try:
        import collectors.browsers.chrome
    except Exception as e:
        logger.debug(f"chrome collector import error: {e}")
    try:
        import collectors.browsers.edge
    except Exception as e:
        logger.debug(f"edge collector import error: {e}")
    try:
        import collectors.browsers.firefox
    except Exception as e:
        logger.debug(f"firefox collector import error: {e}")
    try:
        import collectors.devices.usb_collector
    except Exception as e:
        logger.debug(f"usb_collector import error: {e}")
    try:
        import collectors.persistence.persistence_collector
    except Exception as e:
        logger.debug(f"persistence_collector import error: {e}")
    try:
        import collectors.network.network_collector
    except Exception as e:
        logger.debug(f"network_collector import error: {e}")
    try:
        import collectors.system.system_collector
    except Exception as e:
        logger.debug(f"system_collector import error: {e}")
    try:
        import collectors.sensitive_files.sensitive_file_collector
    except Exception as e:
        logger.debug(f"sensitive_file_collector import error: {e}")


def get_registered_collectors() -> dict[str, type[CollectorBase]]:
    _import_all_collectors()
    return dict(COLLECTOR_REGISTRY)


class AcquisitionEngine:
    def __init__(
        self,
        case_dir: Path,
        profile: CollectionProfile = CollectionProfile.FULL,
        parse: bool = True,
        selected_modules: list[str] | None = None,
    ):
        self.case_dir = case_dir
        self.profile = profile
        self.parse = parse
        self.selected_modules = selected_modules
        self.evidence_manager = EvidenceManager(case_dir)
        self.manifest_manager = ManifestManager(case_dir)
        self.logger = setup_logging(case_dir)

        _import_all_collectors()

    def get_target_modules(self) -> list[str]:
        if self.selected_modules is not None:
            return list(self.selected_modules)
        return get_modules_for_profile(self.profile)

    def run(
        self,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> EvidenceManager:
        logger.warning(LIVE_ACQUISITION_WARNING)
        save_system_info(self.case_dir)

        module_ids = self.get_target_modules()
        total_modules = len(module_ids)
        admin = is_admin()

        for idx, module_id in enumerate(module_ids):
            check_cancelled()
            collector_cls = COLLECTOR_REGISTRY.get(module_id)
            if not collector_cls:
                result = CollectionResult(
                    module_id=module_id,
                    module_name=module_id,
                    category="system",
                    status=CollectionStatus.NOT_AVAILABLE,
                    errors=[f"No collector registered for module: {module_id}"],
                    collection_start=get_iso_timestamp(),
                    collection_end=get_iso_timestamp(),
                )
                self.evidence_manager.add_result(result)
                logger.warning(f"No collector for {module_id}")
                if progress_callback:
                    progress_callback(module_id, idx + 1, total_modules)
                continue

            collector = collector_cls(self.case_dir, parse=self.parse)
            if progress_callback:
                progress_callback(collector.module_name, idx, total_modules)

            if not check_privilege(collector.required_privileges):
                result = CollectionResult(
                    module_id=collector.module_id,
                    module_name=collector.module_name,
                    category=collector.category,
                    required_privileges=collector.required_privileges,
                    status=CollectionStatus.SKIPPED,
                    errors=[
                        f"Insufficient privileges. Required: {collector.required_privileges}. "
                        f"Current user is {'admin' if admin else 'standard user'}."
                    ],
                    collection_start=get_iso_timestamp(),
                    collection_end=get_iso_timestamp(),
                )
                self.evidence_manager.add_result(result)
                logger.warning(f"Skipped {collector.module_name}: insufficient privileges")
                if progress_callback:
                    progress_callback(collector.module_name, idx + 1, total_modules)
                continue

            logger.info(f"Collecting: {collector.module_name}")
            try:
                result = collector.collect()
            except AcquisitionCancelled:
                partial = getattr(collector, "partial_result", None)
                if partial and partial.acquired_files:
                    partial.status = CollectionStatus.PARTIAL
                    partial.errors.append("Cancelled during acquisition; partial evidence preserved.")
                    self.evidence_manager.add_result(partial)
                    self.manifest_manager.add_collection_result(partial)
                self.manifest_manager.write_manifest()
                self.evidence_manager.save_results()
                raise
            self.evidence_manager.add_result(result)
            self.manifest_manager.add_collection_result(result)

            status_msg = f"{collector.module_name}: {result.status.value}"
            if result.errors:
                status_msg += f" (errors: {len(result.errors)})"
            logger.info(status_msg)

            if progress_callback:
                progress_callback(collector.module_name, idx + 1, total_modules)

        self.manifest_manager.write_manifest()
        self.evidence_manager.save_results()

        return self.evidence_manager
