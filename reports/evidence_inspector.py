import os
import json
import csv
from pathlib import Path
from typing import Any, Optional


def format_bytes(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def build_evidence_tree(case_dir: Path) -> dict[str, Any]:
    """Builds a structured hierarchy of the evidence and parsed directories."""
    evidence_dir = case_dir / "evidence"
    parsed_dir = case_dir / "parsed"

    def scan_dir(directory: Path, rel_prefix: str = "") -> dict[str, Any]:
        if not directory.exists():
            return {"name": directory.name, "type": "directory", "children": [], "file_count": 0, "total_size": 0}

        children = []
        file_count = 0
        total_size = 0

        # Subdirectories first
        try:
            subdirs = sorted([p for p in directory.iterdir() if p.is_dir()], key=lambda p: p.name.lower())
            files = sorted([p for p in directory.iterdir() if p.is_file()], key=lambda p: p.name.lower())
        except OSError:
            subdirs, files = [], []

        for sub in subdirs:
            sub_res = scan_dir(sub, f"{rel_prefix}/{sub.name}" if rel_prefix else sub.name)
            file_count += sub_res["file_count"]
            total_size += sub_res["total_size"]
            children.append(sub_res)

        # Truncate file listing per directory if excessive (e.g. thousands of LNK files)
        MAX_DISPLAY_FILES = 25
        displayed_files = files[:MAX_DISPLAY_FILES]

        for f in displayed_files:
            try:
                sz = f.stat().st_size
            except OSError:
                sz = 0
            file_count += 1
            total_size += sz
            rel_path = f"{rel_prefix}/{f.name}" if rel_prefix else f.name
            children.append({
                "name": f.name,
                "type": "file",
                "size_bytes": sz,
                "size_formatted": format_bytes(sz),
                "relative_path": rel_path,
            })

        remaining = len(files) - len(displayed_files)
        if remaining > 0:
            # Add overflow indicator
            remaining_size = sum(f.stat().st_size for f in files[MAX_DISPLAY_FILES:] if f.exists())
            file_count += remaining
            total_size += remaining_size
            children.append({
                "name": f"... and {remaining} additional files ({format_bytes(remaining_size)})",
                "type": "overflow",
                "count": remaining,
                "size_formatted": format_bytes(remaining_size),
            })

        return {
            "name": directory.name,
            "type": "directory",
            "children": children,
            "file_count": file_count,
            "total_size": total_size,
            "size_formatted": format_bytes(total_size),
            "relative_path": rel_prefix or directory.name,
        }

    tree_evidence = scan_dir(evidence_dir, "evidence")
    tree_parsed = scan_dir(parsed_dir, "parsed")

    return {
        "evidence": tree_evidence,
        "parsed": tree_parsed,
        "ascii_tree": generate_ascii_tree(tree_evidence),
    }


def generate_ascii_tree(node: dict[str, Any], prefix: str = "") -> list[str]:
    """Generates clean ASCII tree lines for terminal and PDF rendering."""
    lines = []
    if not node.get("children"):
        return lines

    children = node["children"]
    for idx, child in enumerate(children):
        is_last = (idx == len(children) - 1)
        connector = "\\-- " if is_last else "|-- "
        new_prefix = prefix + ("    " if is_last else "|   ")

        if child["type"] == "directory":
            lines.append(f"{prefix}{connector}{child['name']}/ ({child['file_count']} files, {child['size_formatted']})")
            lines.extend(generate_ascii_tree(child, new_prefix))
        elif child["type"] == "overflow":
            lines.append(f"{prefix}{connector}{child['name']}")
        else:
            lines.append(f"{prefix}{connector}{child['name']} ({child['size_formatted']})")

    return lines


def get_polaris_created_evidence_files(case_dir: Path) -> list[dict[str, Any]]:
    """Discovers every evidence and parsed report file created by Polaris and extracts sample snippets."""
    created_files: list[dict[str, Any]] = []
    target_dirs = [case_dir / "parsed", case_dir / "evidence"]

    # File extensions created by Polaris during extraction
    valid_exts = {".json", ".csv", ".txt"}

    for base_dir in target_dirs:
        if not base_dir.exists():
            continue

        for root, _, files in os.walk(base_dir):
            root_path = Path(root)
            for fname in sorted(files):
                file_path = root_path / fname
                ext = file_path.suffix.lower()
                if ext not in valid_exts:
                    continue

                try:
                    stat = file_path.stat()
                    file_size = stat.st_size
                except OSError:
                    continue

                # Categorize based on file naming and folder path
                rel_path = file_path.relative_to(case_dir)
                category = "General"
                parts = rel_path.parts
                fname_lower = fname.lower()
                if "lnk" in fname_lower or "jumplist" in fname_lower or "recent" in fname_lower or "shellbag" in fname_lower:
                    category = "User Activity"
                elif "prefetch" in fname_lower or "amcache" in fname_lower or "shimcache" in fname_lower or "bam" in fname_lower or "srum" in fname_lower:
                    category = "Execution"
                elif "netstat" in fname_lower or "network" in fname_lower or "dns" in fname_lower or "arp" in fname_lower or "route" in fname_lower:
                    category = "Network Telemetry"
                elif "service" in fname_lower or "task" in fname_lower or "persist" in fname_lower or "startup" in fname_lower:
                    category = "Persistence"
                elif "event" in fname_lower or "evtx" in fname_lower or "security" in fname_lower or "system" in fname_lower:
                    category = "Event Logs"
                elif len(parts) > 2:
                    category = parts[1].replace("_", " ").title()
                elif len(parts) > 1 and parts[0] != "parsed":
                    category = parts[0].replace("_", " ").title()

                item: dict[str, Any] = {
                    "filename": fname,
                    "relative_path": str(rel_path).replace("\\", "/"),
                    "category": category,
                    "size_bytes": file_size,
                    "size_formatted": format_bytes(file_size),
                    "extension": ext,
                    "record_count": 0,
                    "sample_records": [],
                    "sample_text": "",
                    "is_json": False,
                    "is_csv": False,
                }

                # Extract content snippet
                if ext == ".json":
                    item["is_json"] = True
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                            data = json.load(f)

                        if isinstance(data, list):
                            item["record_count"] = len(data)
                            item["sample_records"] = data[:6]
                            item["sample_text"] = json.dumps(data[:3], indent=2, ensure_ascii=False)
                        elif isinstance(data, dict):
                            item["record_count"] = len(data)
                            # Pick top keys
                            sample_dict = {k: data[k] for k in list(data.keys())[:8]}
                            item["sample_records"] = [sample_dict]
                            item["sample_text"] = json.dumps(sample_dict, indent=2, ensure_ascii=False)
                    except Exception as e:
                        item["sample_text"] = f"[Error reading JSON: {e}]"

                elif ext == ".csv":
                    item["is_csv"] = True
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                            reader = csv.DictReader(f)
                            rows = []
                            for idx, r in enumerate(reader):
                                if idx < 6:
                                    rows.append(dict(r))
                                item["record_count"] = idx + 1
                            item["sample_records"] = rows
                    except Exception as e:
                        item["sample_text"] = f"[Error reading CSV: {e}]"

                elif ext == ".txt":
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                            lines = [line.strip() for line in f.readlines() if line.strip()]
                        item["record_count"] = len(lines)
                        item["sample_text"] = "\n".join(lines[:12])
                    except Exception as e:
                        item["sample_text"] = f"[Error reading TXT: {e}]"

                created_files.append(item)

    # Sort files by category and filename
    created_files.sort(key=lambda x: (x["category"].lower(), x["filename"].lower()))
    return created_files
