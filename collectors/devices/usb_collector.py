"""USB and device artifact collector."""

from __future__ import annotations

import json
import logging
import re
import csv
from io import StringIO
from pathlib import Path
from typing import Optional

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp
from utils.subprocess_utils import run_command, run_powershell

logger = logging.getLogger("polaris")


def _parse_usbstor_output(raw: str) -> list[dict]:
    """Parse 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR /s' output into structured entries."""
    devices: list[dict] = []
    current_key = ""
    current_device: dict = {}

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("HKEY_LOCAL_MACHINE"):
            if current_device and current_device.get("registry_key"):
                devices.append(current_device)

            current_key = line
            current_device = {"registry_key": current_key}

            key_parts = current_key.split("\\")
            usbstor_idx = -1
            for i, part in enumerate(key_parts):
                if part.upper() == "USBSTOR":
                    usbstor_idx = i
                    break

            if usbstor_idx >= 0 and len(key_parts) > usbstor_idx + 1:
                device_id = key_parts[usbstor_idx + 1]
                id_parts = device_id.split("&")
                if len(id_parts) >= 3:
                    current_device["device_type"] = id_parts[0].replace("Disk", "Disk").strip()
                    current_device["vendor"] = id_parts[1].replace("Ven_", "").strip()
                    current_device["product"] = id_parts[2].replace("Prod_", "").strip()
                    if len(id_parts) >= 4:
                        current_device["revision"] = id_parts[3].replace("Rev_", "").strip()

            if usbstor_idx >= 0 and len(key_parts) > usbstor_idx + 2:
                current_device["serial_number"] = key_parts[usbstor_idx + 2]

        elif "    " in line and "REG_" in line:
            parts = re.split(r"\s{2,}", line, maxsplit=2)
            if len(parts) >= 3:
                value_name = parts[0].strip()
                value_data = parts[2].strip()
                if value_name == "FriendlyName":
                    current_device["friendly_name"] = value_data
                elif value_name == "DeviceDesc":
                    current_device["device_description"] = value_data
                elif value_name == "Mfg":
                    current_device["manufacturer"] = value_data
                elif value_name == "Service":
                    current_device["service"] = value_data
                elif value_name == "ClassGUID":
                    current_device["class_guid"] = value_data
                elif value_name == "ContainerID":
                    current_device["container_id"] = value_data

    if current_device and current_device.get("registry_key"):
        devices.append(current_device)

    return devices


@register_collector("usb_devices")
class UsbDeviceCollector(CollectorBase):
    module_id = "usb_devices"
    module_name = "USB and Device Artifacts"
    category = ArtifactCategory.DEVICES
    source_locations = [
        "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
        "HKLM\\SYSTEM\\MountedDevices",
        "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB",
        "C:\\Windows\\INF\\setupapi.dev.log",
    ]
    required_privileges = "admin"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        collected_any = False

        collected_any |= self._collect_usbstor(result)
        collected_any |= self._collect_mounted_devices(result)
        collected_any |= self._collect_usb_enum(result)
        collected_any |= self._collect_setupapi_log(result)
        collected_any |= self._collect_pnp_events(result)

        if self.parse:
            self._parse_all(result)

        result.status = CollectionStatus.SUCCESS if collected_any else CollectionStatus.FAILED
        return result

    def _collect_usbstor(self, result: CollectionResult) -> bool:
        rc, stdout, stderr = run_command(
            ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR", "/s"],
            timeout=60,
        )
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, "usbstor_registry.txt", self.evidence_dir / "usb")
            if ev:
                ev.metadata = {"source": "USBSTOR registry", "volatile": False}
                result.acquired_files.append(ev)
                return True
        else:
            result.warnings.append(f"USBSTOR query failed: {stderr.strip()}")
        return False

    def _collect_mounted_devices(self, result: CollectionResult) -> bool:
        rc, stdout, stderr = run_command(
            ["reg", "query", r"HKLM\SYSTEM\MountedDevices"],
            timeout=60,
        )
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, "mounted_devices_registry.txt", self.evidence_dir / "usb")
            if ev:
                ev.metadata = {"source": "MountedDevices registry", "volatile": False}
                result.acquired_files.append(ev)
                return True
        else:
            result.warnings.append(f"MountedDevices query failed: {stderr.strip()}")
        return False

    def _collect_usb_enum(self, result: CollectionResult) -> bool:
        rc, stdout, stderr = run_command(
            ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Enum\USB", "/s"],
            timeout=60,
        )
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, "usb_enum_registry.txt", self.evidence_dir / "usb")
            if ev:
                ev.metadata = {"source": "USB enum registry", "volatile": False}
                result.acquired_files.append(ev)
                return True
        else:
            result.warnings.append(f"USB enum query failed: {stderr.strip()}")
        return False

    def _collect_setupapi_log(self, result: CollectionResult) -> bool:
        setupapi_path = Path(r"C:\Windows\INF\setupapi.dev.log")
        if setupapi_path.exists():
            ev = self.copy_file(setupapi_path, self.evidence_dir / "usb")
            if ev:
                ev.metadata = {"source": "setupapi.dev.log", "volatile": False}
                result.acquired_files.append(ev)
                return True
            else:
                result.warnings.append("Failed to copy setupapi.dev.log")
        else:
            result.warnings.append("setupapi.dev.log not found")
        return False

    def _collect_pnp_events(self, result: CollectionResult) -> bool:
        rc, stdout, stderr = run_command(
            [
                "wevtutil", "qe",
                "Microsoft-Windows-Kernel-PnP/Configuration",
                "/f:text",
                "/c:5000",
            ],
            timeout=120,
        )
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, "kernel_pnp_events.txt", self.evidence_dir / "usb")
            if ev:
                ev.metadata = {
                    "source": "Kernel-PnP event log",
                    "volatile": True,
                    "acquisition_timestamp": get_iso_timestamp(),
                }
                result.acquired_files.append(ev)
                return True
        else:
            result.warnings.append(f"PnP event log export failed: {stderr.strip()}")
        return False

    def _parse_all(self, result: CollectionResult) -> None:
        usbstor_file = self.evidence_dir / "usb" / "usbstor_registry.txt"
        if not usbstor_file.exists():
            return

        try:
            raw = usbstor_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        devices = _parse_usbstor_output(raw)
        if not devices:
            return

        parsed_dir = self.parsed_dir / "usb"
        parsed_dir.mkdir(parents=True, exist_ok=True)

        ev = self.save_json(devices, "usb_devices_parsed.json", parsed_dir)
        if ev:
            result.parsed_output_files.append(ev.acquired_path)
            result.acquired_files.append(ev)

        fieldnames = [
            "vendor", "product", "serial_number", "friendly_name",
            "device_description", "manufacturer", "service", "registry_key",
        ]
        buf = StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(devices)
        csv_ev = self.save_text(buf.getvalue(), "usb_devices_parsed.csv", parsed_dir)
        if csv_ev:
            result.parsed_output_files.append(csv_ev.acquired_path)
            result.acquired_files.append(csv_ev)

        result.parser_name = "polaris_usb_parser"
        result.parser_version = "1.0"
        result.parser_status = "completed"
