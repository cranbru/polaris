from __future__ import annotations

import logging
import os
from pathlib import Path

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp
from utils.subprocess_utils import run_command

logger = logging.getLogger("polaris.shellbags")

SHELLBAG_KEYS: dict[str, str] = {
    "BagMRU_NTUSER": r"HKCU\Software\Microsoft\Windows\Shell\BagMRU",
    "Bags_NTUSER": r"HKCU\Software\Microsoft\Windows\Shell\Bags",
    "BagMRU_UsrClass": r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
    "Bags_UsrClass": r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
}


def _reg_export(key_path: str, output_file: Path, timeout: int = 120) -> tuple[int, str, str]:
    return run_command(
        ["reg", "export", key_path, str(output_file), "/y"],
        timeout=timeout,
    )


def _copy_user_hive_files(evidence_dir: Path) -> list[tuple[Path, str]]:
    user_profile = os.environ.get("USERPROFILE", "")
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    results: list[tuple[Path, str]] = []

    if user_profile:
        ntuser_path = Path(user_profile) / "NTUSER.DAT"
        if ntuser_path.exists():
            results.append((ntuser_path, "NTUSER.DAT"))

    if local_appdata:
        usrclass_path = Path(local_appdata) / "Microsoft" / "Windows" / "UsrClass.dat"
        if usrclass_path.exists():
            results.append((usrclass_path, "UsrClass.dat"))

    return results


@register_collector("shellbags")
class ShellBagsCollector(CollectorBase):
    module_id: str = "shellbags"
    module_name: str = "ShellBags"
    category: ArtifactCategory = ArtifactCategory.USER_ACTIVITY
    source_locations: list[str] = list(SHELLBAG_KEYS.values())
    required_privileges: str = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        export_dir = self.evidence_dir / "shellbags"
        export_dir.mkdir(parents=True, exist_ok=True)

        keys_succeeded: int = 0
        keys_failed: int = 0

        for key_name, key_path in SHELLBAG_KEYS.items():
            reg_file = export_dir / f"{key_name}.reg"

            returncode, stdout, stderr = _reg_export(key_path, reg_file)

            if returncode == 0 and reg_file.exists() and reg_file.stat().st_size > 0:
                evidence = FileEvidence(
                    evidence_id=f"shellbags_{key_name}",
                    original_path=key_path,
                    acquired_path=str(reg_file),
                    filename=reg_file.name,
                    extension=".reg",
                    file_size=reg_file.stat().st_size,
                    collection_timestamp=get_iso_timestamp(),
                )
                result.acquired_files.append(evidence)
                keys_succeeded += 1
            else:
                keys_failed += 1
                error_msg = stderr.strip() if stderr else "Unknown error"
                result.warnings.append(f"Failed to export {key_name}: {error_msg}")

        hive_files = _copy_user_hive_files(export_dir)
        for hive_path, hive_name in hive_files:
            evidence = self.copy_file(
                hive_path,
                export_dir,
                evidence_id=f"shellbags_hive_{hive_name}",
            )
            if evidence:
                result.acquired_files.append(evidence)
            else:
                result.warnings.append(
                    f"Could not copy {hive_name} (file may be locked by the OS)"
                )

        if keys_succeeded == 0:
            result.status = CollectionStatus.FAILED
            result.errors.append("Failed to export any ShellBags registry keys")
        elif keys_failed > 0:
            result.status = CollectionStatus.PARTIAL
        else:
            result.status = CollectionStatus.SUCCESS

        return result
