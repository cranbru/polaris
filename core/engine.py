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
from utils.logging_config import setup_logging

logger = logging.getLogger("polaris")

COLLECTOR_REGISTRY: dict[str, type[CollectorBase]] = {}


def register_collector(module_id: str):
    def decorator(cls: type[CollectorBase]):
        COLLECTOR_REGISTRY[module_id] = cls
        return cls
    return decorator


def get_registered_collectors() -> dict[str, type[CollectorBase]]:
    return dict(COLLECTOR_REGISTRY)


def _import_all_collectors():
    import importlib
    modules = [
        "collectors.execution.prefetch",
        "collectors.execution.amcache",
        "collectors.execution.shimcache",
        "collectors.execution.bam",
        "collectors.execution.srum",
        "collectors.execution.userassist",
        "collectors.execution.pca",
        "collectors.execution.powershell_artifacts",
        "collectors.eventlogs.evtx_collector",
        "collectors.user_activity.lnk_collector",
        "collectors.user_activity.jump_lists",
        "collectors.user_activity.recent_docs",
        "collectors.user_activity.shellbags",
        "collectors.user_activity.recycle_bin",
        "collectors.registry.hive_collector",
        "collectors.registry.registry_artifacts",
        "collectors.browsers.chrome",
        "collectors.browsers.edge",
        "collectors.browsers.firefox",
        "collectors.devices.usb_collector",
        "collectors.persistence.persistence_collector",
        "collectors.network.network_collector",
        "collectors.system.system_collector",
    ]
    for mod in modules:
        try:
            importlib.import_module(mod)
        except ImportError as e:
            logger.debug(f"Could not import {mod}: {e}")


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
            result = collector.collect()
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
