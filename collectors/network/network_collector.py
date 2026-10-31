"""Network information artifact collector."""

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
from utils.subprocess_utils import run_command

logger = logging.getLogger("polaris")

NETWORK_COMMANDS: list[tuple[str, list[str], str]] = [
    ("ipconfig_all", ["ipconfig", "/all"], "Network adapter configuration"),
    ("netstat_ano", ["netstat", "-ano"], "Active network connections"),
    ("route_print", ["route", "print"], "Routing table"),
    ("arp_cache", ["arp", "-a"], "ARP cache"),
    ("firewall_config", ["netsh", "advfirewall", "show", "allprofiles"], "Firewall configuration"),
]

DNS_COMMAND = ("dns_cache", ["ipconfig", "/displaydns"], "DNS resolver cache")
LISTENING_COMMAND = ("listening_ports", ["netstat", "-an"], "Listening ports")


def _parse_netstat_output(raw: str) -> list[dict]:
    """Parse netstat -ano output into structured records."""
    connections: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Active") or line.startswith("Proto"):
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        protocol = parts[0].upper()
        if protocol not in ("TCP", "UDP"):
            continue

        local_address = parts[1]
        local_addr, local_port = _split_address(local_address)

        if protocol == "TCP":
            remote_address = parts[2]
            remote_addr, remote_port = _split_address(remote_address)
            state = parts[3] if len(parts) > 3 else ""
            pid = parts[4] if len(parts) > 4 else ""
        else:
            remote_address = parts[2] if len(parts) > 2 else "*:*"
            remote_addr, remote_port = _split_address(remote_address)
            state = ""
            pid = parts[3] if len(parts) > 3 else ""

        connections.append({
            "protocol": protocol,
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "state": state,
            "pid": pid,
        })

    return connections


def _split_address(address: str) -> tuple[str, str]:
    """Split an address string like '192.168.1.1:443' or '[::1]:443' into (addr, port)."""
    if address.startswith("["):
        bracket_end = address.rfind("]")
        if bracket_end != -1 and bracket_end + 1 < len(address) and address[bracket_end + 1] == ":":
            return address[1:bracket_end], address[bracket_end + 2:]
        return address, ""
    last_colon = address.rfind(":")
    if last_colon != -1:
        return address[:last_colon], address[last_colon + 1:]
    return address, ""


def _filter_listening_lines(raw: str) -> str:
    """Filter netstat -an output for LISTENING lines only."""
    lines = [line for line in raw.splitlines() if "LISTENING" in line.upper()]
    return "\n".join(lines)


@register_collector("network_info")
class NetworkCollector(CollectorBase):
    module_id = "network_info"
    module_name = "Network Information"
    category = ArtifactCategory.NETWORK
    source_locations = ["Live system network state"]
    required_privileges = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        collected_any = False
        dest_dir = self.evidence_dir / "network"
        acquisition_ts = get_iso_timestamp()

        for cmd_id, cmd_args, description in NETWORK_COMMANDS:
            success = self._run_and_save(cmd_id, cmd_args, description, dest_dir, acquisition_ts, result)
            collected_any |= success

        dns_success = self._run_and_save(
            DNS_COMMAND[0], DNS_COMMAND[1], DNS_COMMAND[2], dest_dir, acquisition_ts, result
        )
        collected_any |= dns_success

        rc, stdout, stderr = run_command(LISTENING_COMMAND[1], timeout=60)
        if rc == 0 and stdout.strip():
            listening_text = _filter_listening_lines(stdout)
            if listening_text:
                ev = self.save_text(listening_text, "listening_ports.txt", dest_dir)
                if ev:
                    ev.metadata = {
                        "source": LISTENING_COMMAND[2],
                        "volatile": True,
                        "acquisition_timestamp": acquisition_ts,
                    }
                    result.acquired_files.append(ev)
                    collected_any = True

        if self.parse:
            self._parse_netstat(dest_dir, result)

        result.status = CollectionStatus.SUCCESS if collected_any else CollectionStatus.FAILED
        return result

    def _run_and_save(
        self,
        cmd_id: str,
        cmd_args: list[str],
        description: str,
        dest_dir: Path,
        acquisition_ts: str,
        result: CollectionResult,
    ) -> bool:
        rc, stdout, stderr = run_command(cmd_args, timeout=60)
        if rc == 0 and stdout.strip():
            ev = self.save_text(stdout, f"{cmd_id}.txt", dest_dir)
            if ev:
                ev.metadata = {
                    "source": description,
                    "command": " ".join(cmd_args),
                    "volatile": True,
                    "acquisition_timestamp": acquisition_ts,
                }
                result.acquired_files.append(ev)
                return True
        else:
            result.warnings.append(f"{description} failed: {stderr.strip()}")
        return False

    def _parse_netstat(self, evidence_dir: Path, result: CollectionResult) -> None:
        netstat_file = evidence_dir / "netstat_ano.txt"
        if not netstat_file.exists():
            return

        try:
            raw = netstat_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        connections = _parse_netstat_output(raw)
        if not connections:
            return

        parsed_dir = self.parsed_dir / "network"
        parsed_dir.mkdir(parents=True, exist_ok=True)

        j_ev = self.save_json(connections, "netstat_parsed.json", parsed_dir)
        if j_ev:
            result.parsed_output_files.append(j_ev.acquired_path)
            result.acquired_files.append(j_ev)

        fieldnames = ["protocol", "local_addr", "local_port", "remote_addr", "remote_port", "state", "pid"]
        buf = StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(connections)
        csv_ev = self.save_text(buf.getvalue(), "netstat_parsed.csv", parsed_dir)
        if csv_ev:
            result.parsed_output_files.append(csv_ev.acquired_path)
            result.acquired_files.append(csv_ev)

        result.parser_name = "polaris_network_parser"
        result.parser_version = "1.0"
        result.parser_status = "completed"
