from __future__ import annotations

import logging
import os
from pathlib import Path

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp
from utils.subprocess_utils import run_command

logger = logging.getLogger("polaris.registry_hives")

LIVE_HIVES: dict[str, str] = {
    "SYSTEM": r"HKLM\SYSTEM",
    "SOFTWARE": r"HKLM\SOFTWARE",
    "DEFAULT": r"HKU\.DEFAULT",
    "SAM": r"HKLM\SAM",
    "SECURITY": r"HKLM\SECURITY",
}

USER_HIVE_FILES: list[tuple[str, str]] = [
    ("NTUSER.DAT", "USERPROFILE"),
    ("UsrClass.dat", "LOCALAPPDATA"),
]


def _reg_save(hive_key: str, output_path: Path, timeout: int = 120) -> tuple[int, str, str]:
    return run_command(
        ["reg", "save", hive_key, str(output_path), "/y"],
        timeout=timeout,
    )


def _get_user_hive_path(filename: str, env_var: str) -> Path | None:
    base = os.environ.get(env_var, "")
    if not base:
        return None

    if filename == "NTUSER.DAT":
        path = Path(base) / filename
    elif filename == "UsrClass.dat":
        path = Path(base) / "Microsoft" / "Windows" / filename
    else:
        return None

    return path if path.exists() else None


@register_collector("registry_hives")
class RegistryHiveCollector(CollectorBase):
    module_id: str = "registry_hives"
    module_name: str = "Registry Hive Files"
    category: ArtifactCategory = ArtifactCategory.REGISTRY
    source_locations: list[str] = [
        r"HKLM\SYSTEM",
        r"HKLM\SOFTWARE",
        r"HKU\.DEFAULT",
        r"%USERPROFILE%\NTUSER.DAT",
        r"%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat",
    ]
    required_privileges: str = "admin"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        hive_dir = self.evidence_dir / "hives"
        hive_dir.mkdir(parents=True, exist_ok=True)

        hives_succeeded: int = 0
        hives_failed: int = 0

        for hive_name, hive_key in LIVE_HIVES.items():
            dest_path = hive_dir / hive_name
            returncode, stdout, stderr = _reg_save(hive_key, dest_path)

            if returncode == 0 and dest_path.exists() and dest_path.stat().st_size > 0:
                evidence = FileEvidence(
                    evidence_id=f"hive_{hive_name}",
                    original_path=hive_key,
                    acquired_path=str(dest_path),
                    filename=hive_name,
                    extension="",
                    file_size=dest_path.stat().st_size,
                    collection_timestamp=get_iso_timestamp(),
                )
                result.acquired_files.append(evidence)
                hives_succeeded += 1
            else:
                hives_failed += 1
                error_msg = stderr.strip() if stderr else "Unknown error"
                result.warnings.append(f"Failed to save {hive_name} ({hive_key}): {error_msg}")

        for hive_filename, env_var in USER_HIVE_FILES:
            hive_path = _get_user_hive_path(hive_filename, env_var)
            if hive_path is None:
                result.warnings.append(
                    f"User hive file not found: {hive_filename}"
                )
                hives_failed += 1
                continue

            evidence = self.copy_file(
                hive_path,
                hive_dir,
                evidence_id=f"hive_user_{hive_filename}",
            )
            if evidence:
                result.acquired_files.append(evidence)
                hives_succeeded += 1
            else:
                if self._try_reg_save_user_hive(hive_filename, hive_dir, result):
                    hives_succeeded += 1
                else:
                    hives_failed += 1

        if hives_succeeded == 0:
            result.status = CollectionStatus.FAILED
            result.errors.append("Failed to acquire any registry hive files")
        elif hives_failed > 0:
            result.status = CollectionStatus.PARTIAL
        else:
            result.status = CollectionStatus.SUCCESS

        return result

    def _try_reg_save_user_hive(
        self,
        hive_filename: str,
        hive_dir: Path,
        result: CollectionResult,
    ) -> bool:
        if hive_filename == "NTUSER.DAT":
            hive_key = "HKCU"
            dest_name = "NTUSER_regsave"
        elif hive_filename == "UsrClass.dat":
            hive_key = r"HKCU\Software\Classes"
            dest_name = "UsrClass_regsave"
        else:
            return False

        dest_path = hive_dir / dest_name
        returncode, stdout, stderr = _reg_save(hive_key, dest_path)

        if returncode == 0 and dest_path.exists() and dest_path.stat().st_size > 0:
            evidence = FileEvidence(
                evidence_id=f"hive_user_{dest_name}",
                original_path=hive_key,
                acquired_path=str(dest_path),
                filename=dest_name,
                extension="",
                file_size=dest_path.stat().st_size,
                collection_timestamp=get_iso_timestamp(),
                metadata={"acquisition_method": "reg_save", "fallback": True,
                          "requested_filename": hive_filename},
            )
            result.acquired_files.append(evidence)
            result.warnings.append(
                f"Acquired {hive_filename} using 'reg save {hive_key}' after direct copy failed "
                "(live hive may be locked)."
            )
            return True

        error_msg = stderr.strip() if stderr else "No hive file was produced"
        result.warnings.append(
            f"Could not acquire {hive_filename}: direct copy and 'reg save {hive_key}' "
            f"fallback failed: {error_msg}. Volume shadow copy may be required."
        )
        return False
