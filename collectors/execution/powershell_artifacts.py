from __future__ import annotations

import os
from pathlib import Path

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import (
    CollectionStatus,
    ArtifactCategory,
    SENSITIVE_COLLECTION_WARNING,
)
from utils.subprocess_utils import run_command
from utils.filesystem import safe_glob

PS_OPERATIONAL_LOG = "Microsoft-Windows-PowerShell/Operational"
PS_SCRIPTBLOCK_LOG = "Microsoft-Windows-PowerShell/Operational"
PS_CLASSIC_LOG = "Windows PowerShell"

PSREADLINE_HISTORY_PATTERN = (
    r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
)


@register_collector("powershell")
class PowerShellCollector(CollectorBase):
    module_id: str = "powershell"
    module_name: str = "PowerShell Artifacts"
    category: ArtifactCategory = ArtifactCategory.EXECUTION
    source_locations: list[str] = [
        PS_OPERATIONAL_LOG,
        PS_CLASSIC_LOG,
        "PSReadLine History (opt-in)",
    ]
    required_privileges: str = "admin"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        dest_dir = self.evidence_dir / "powershell"
        any_success = False

        if self._collect_operational_log(result, dest_dir):
            any_success = True

        if self._collect_classic_log(result, dest_dir):
            any_success = True

        if self._collect_scriptblock_log(result, dest_dir):
            any_success = True

        if self._should_collect_psreadline():
            result.warnings.append(SENSITIVE_COLLECTION_WARNING)
            if self._collect_psreadline(result, dest_dir):
                any_success = True

        if any_success:
            result.status = CollectionStatus.SUCCESS
        elif result.errors:
            result.status = CollectionStatus.FAILED
        else:
            result.status = CollectionStatus.NOT_AVAILABLE

        return result

    def _collect_operational_log(self, result: CollectionResult, dest_dir: Path) -> bool:
        export_path = dest_dir / "PowerShell_Operational.evtx"
        export_path.parent.mkdir(parents=True, exist_ok=True)

        returncode, stdout, stderr = run_command(
            ["wevtutil", "epl", PS_OPERATIONAL_LOG, str(export_path)],
            timeout=120,
        )

        if returncode == 0 and export_path.exists() and export_path.stat().st_size > 0:
            stat = export_path.stat()
            evidence = FileEvidence(
                evidence_id="powershell_operational_evtx",
                original_path=PS_OPERATIONAL_LOG,
                acquired_path=str(export_path),
                filename=export_path.name,
                extension=".evtx",
                file_size=stat.st_size,
            )
            result.acquired_files.append(evidence)
            return True

        result.errors.append(
            f"Failed to export PowerShell Operational log (rc={returncode}): {stderr[:200]}"
        )
        return False

    def _collect_classic_log(self, result: CollectionResult, dest_dir: Path) -> bool:
        export_path = dest_dir / "WindowsPowerShell.evtx"
        export_path.parent.mkdir(parents=True, exist_ok=True)

        returncode, stdout, stderr = run_command(
            ["wevtutil", "epl", PS_CLASSIC_LOG, str(export_path)],
            timeout=120,
        )

        if returncode == 0 and export_path.exists() and export_path.stat().st_size > 0:
            stat = export_path.stat()
            evidence = FileEvidence(
                evidence_id="powershell_classic_evtx",
                original_path=PS_CLASSIC_LOG,
                acquired_path=str(export_path),
                filename=export_path.name,
                extension=".evtx",
                file_size=stat.st_size,
            )
            result.acquired_files.append(evidence)
            return True

        result.errors.append(
            f"Failed to export classic PowerShell log (rc={returncode}): {stderr[:200]}"
        )
        return False

    def _collect_scriptblock_log(self, result: CollectionResult, dest_dir: Path) -> bool:
        """Export script block logging events (Event ID 4104) as XML for parsed analysis."""
        if not self.parse:
            return False

        xml_path = dest_dir / "ScriptBlock_Events_4104.xml"
        xml_path.parent.mkdir(parents=True, exist_ok=True)

        query = '*[System[EventID=4104]]'
        returncode, stdout, stderr = run_command(
            [
                "wevtutil", "qe", PS_SCRIPTBLOCK_LOG,
                "/q:" + query,
                "/f:xml",
            ],
            timeout=180,
        )

        if returncode == 0 and stdout.strip():
            wrapped = f"<Events>\n{stdout}\n</Events>"
            evidence = self.save_text(
                wrapped, "ScriptBlock_Events_4104.xml", dest_dir,
                evidence_id="powershell_scriptblock_xml",
            )
            if evidence:
                result.acquired_files.append(evidence)
                return True

        result.warnings.append("No Script Block Logging events (4104) found or export failed")
        return False

    def _should_collect_psreadline(self) -> bool:
        env_val = os.environ.get("POLARIS_COLLECT_PSREADLINE", "").lower()
        return env_val in ("true", "1", "yes")

    def _collect_psreadline(self, result: CollectionResult, dest_dir: Path) -> bool:
        users_dir = Path(r"C:\Users")
        if not users_dir.exists():
            return False

        collected_any = False
        psreadline_dest = dest_dir / "psreadline"

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            if user_dir.name.lower() in ("public", "default", "default user", "all users"):
                continue

            history_path = user_dir / PSREADLINE_HISTORY_PATTERN
            if not history_path.exists() or not history_path.is_file():
                continue

            user_dest = psreadline_dest / user_dir.name
            evidence = self.copy_file(
                history_path, user_dest,
                evidence_id=f"psreadline_{user_dir.name}",
            )
            if evidence:
                evidence.metadata["username"] = user_dir.name
                evidence.metadata["sensitive"] = True
                result.acquired_files.append(evidence)
                collected_any = True
            else:
                result.errors.append(
                    f"Failed to copy PSReadLine history for user: {user_dir.name}"
                )

        return collected_any
