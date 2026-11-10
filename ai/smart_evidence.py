import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("polaris")


def extract_smart_evidence_context(case_dir: Path) -> dict[str, Any]:
    """
    Intelligently samples and distills evidence files created by Polaris.
    Filters high-noise files (such as 1,500+ start menu LNK shortcuts) to isolate
    high-signal indicators: recent executions, unusual paths, command arguments,
    active network connections, and persistence mechanisms.
    """
    parsed_dir = case_dir / "parsed"
    smart_data: dict[str, Any] = {
        "shortcut_analysis": {
            "total_shortcuts_acquired": 0,
            "standard_os_shortcuts_count": 0,
            "suspicious_or_parameterized_count": 0,
            "suspicious_shortcuts_sample": [],
            "recently_modified_shortcuts_sample": [],
        },
        "execution_summary": {
            "total_prefetch_analyzed": 0,
            "recent_executions": [],
        },
        "persistence_mechanisms": [],
        "network_connections": [],
        "user_activity": [],
        "system_profile": {},
    }

    # 1. SMART LNK PROCESSING (Filter out OS start menu noise, isolate high-signal items)
    lnk_path = parsed_dir / "user_activity" / "lnk_parsed.json"
    if not lnk_path.exists():
        matches = list(parsed_dir.glob("**/lnk_parsed.json"))
        if matches:
            lnk_path = matches[0]

    if lnk_path.exists():
        try:
            with open(lnk_path, "r", encoding="utf-8", errors="replace") as f:
                all_lnks = json.load(f)

            if isinstance(all_lnks, list):
                total_lnks = len(all_lnks)
                suspicious_lnks = []
                recent_lnks = []
                standard_count = 0

                suspicious_target_kw = ["temp", "appdata", "downloads", "public", ".bat", ".ps1", ".vbs", ".cmd"]

                for item in all_lnks:
                    target = str(item.get("target_path", "")).lower()
                    args = str(item.get("arguments", "")).strip()
                    lnk_file = str(item.get("lnk_file", "")).lower()

                    is_suspicious = False
                    # Check for execution flags / command arguments
                    if args:
                        is_suspicious = True
                    # Check for suspicious target location (where shortcut points)
                    elif any(kw in target for kw in suspicious_target_kw):
                        is_suspicious = True
                    # Check for non-C drive targets (USB, external, network)
                    elif target and not target.startswith("c:"):
                        is_suspicious = True
                    # Check for suspicious shortcut location (e.g. dropped in Temp or Public)
                    elif any(kw in lnk_file for kw in ["\\temp\\", "\\public\\", "/temp/", "/public/"]):
                        is_suspicious = True

                    entry_summary = {
                        "shortcut": Path(item.get("lnk_file", "")).name,
                        "target": item.get("target_path", ""),
                        "arguments": item.get("arguments", ""),
                        "modified": item.get("modification_time", ""),
                        "accessed": item.get("access_time", ""),
                    }

                    if is_suspicious:
                        suspicious_lnks.append(entry_summary)
                    else:
                        standard_count += 1

                    if item.get("modification_time"):
                        recent_lnks.append(entry_summary)

                # Sort recent by modification time descending
                recent_lnks.sort(key=lambda x: str(x.get("modified", "")), reverse=True)

                smart_data["shortcut_analysis"] = {
                    "total_shortcuts_acquired": total_lnks,
                    "standard_os_shortcuts_count": standard_count,
                    "suspicious_or_parameterized_count": len(suspicious_lnks),
                    "suspicious_shortcuts_sample": suspicious_lnks[:15],
                    "recently_modified_shortcuts_sample": recent_lnks[:15],
                }
        except Exception as e:
            logger.debug(f"Error smartly parsing LNK evidence: {e}")

    # 2. SMART PREFETCH EXECUTION SUMMARY
    prefetch_path = parsed_dir / "execution" / "prefetch" / "prefetch_summary.json"
    if not prefetch_path.exists():
        matches = list(parsed_dir.glob("**/prefetch_summary.json")) or list(parsed_dir.glob("**/*prefetch*.json"))
        if matches:
            prefetch_path = matches[0]

    if prefetch_path.exists():
        try:
            with open(prefetch_path, "r", encoding="utf-8", errors="replace") as f:
                pf_data = json.load(f)

            if isinstance(pf_data, list):
                pf_data.sort(key=lambda x: str(x.get("last_run_time", "") or x.get("last_execution", "")), reverse=True)
                smart_data["execution_summary"]["total_prefetch_analyzed"] = len(pf_data)
                smart_data["execution_summary"]["recent_executions"] = [
                    {
                        "executable": item.get("executable") or item.get("executable_name") or item.get("file_name"),
                        "run_count": item.get("run_count"),
                        "last_run": item.get("last_run_time") or item.get("last_execution"),
                    }
                    for item in pf_data[:15]
                ]
            elif isinstance(pf_data, dict):
                smart_data["execution_summary"]["details"] = {k: pf_data[k] for k in list(pf_data.keys())[:10]}
        except Exception as e:
            logger.debug(f"Error parsing prefetch for AI: {e}")

    # 3. SMART PERSISTENCE (Run keys, services, tasks)
    run_keys_path = parsed_dir / "persistence" / "persistence" / "run_keys_parsed.json"
    if not run_keys_path.exists():
        matches = list(parsed_dir.glob("**/run_keys_parsed.json"))
        if matches:
            run_keys_path = matches[0]

    if run_keys_path.exists():
        try:
            with open(run_keys_path, "r", encoding="utf-8", errors="replace") as f:
                run_keys = json.load(f)
            if isinstance(run_keys, list):
                smart_data["persistence_mechanisms"] = run_keys[:12]
        except Exception as e:
            logger.debug(f"Error parsing run keys for AI: {e}")

    # 4. SMART NETWORK TELEMETRY
    netstat_path = parsed_dir / "network" / "network" / "netstat_parsed.json"
    if not netstat_path.exists():
        matches = list(parsed_dir.glob("**/netstat_parsed.json"))
        if matches:
            netstat_path = matches[0]

    if netstat_path.exists():
        try:
            with open(netstat_path, "r", encoding="utf-8", errors="replace") as f:
                net_data = json.load(f)

            if isinstance(net_data, list):
                # Filter for non-loopback established or listening connections
                interesting_conns = []
                for conn in net_data:
                    remote = str(conn.get("remote_addr", conn.get("remote_address", "")))
                    state = str(conn.get("state", "")).upper()
                    if remote and not remote.startswith("127.0.0.1") and not remote.startswith("0.0.0.0") and not remote.startswith("::1"):
                        interesting_conns.append(conn)
                    elif state in ["LISTEN", "LISTENING"]:
                        interesting_conns.append(conn)

                smart_data["network_connections"] = (interesting_conns or net_data)[:15]
        except Exception as e:
            logger.debug(f"Error parsing netstat for AI: {e}")

    # 5. USERASSIST EXECUTION HISTORY
    userassist_path = parsed_dir / "execution" / "userassist" / "userassist_decoded.json"
    if not userassist_path.exists():
        matches = list(parsed_dir.glob("**/userassist_decoded.json"))
        if matches:
            userassist_path = matches[0]

    if userassist_path.exists():
        try:
            with open(userassist_path, "r", encoding="utf-8", errors="replace") as f:
                ua_data = json.load(f)
            if isinstance(ua_data, list):
                smart_data["user_activity"] = ua_data[:12]
        except Exception as e:
            logger.debug(f"Error parsing userassist for AI: {e}")

    return smart_data
