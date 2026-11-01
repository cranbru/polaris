import json
import pytest
from pathlib import Path

from reports.evidence_inspector import build_evidence_tree, get_polaris_created_evidence_files


@pytest.mark.unit
def test_build_evidence_tree(tmp_path: Path):
    case_dir = tmp_path / "case_test"
    case_dir.mkdir(parents=True)
    evidence_dir = case_dir / "evidence" / "execution"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "calc.pf").write_text("dummy prefetch content", encoding="utf-8")

    parsed_dir = case_dir / "parsed"
    parsed_dir.mkdir(parents=True)
    (parsed_dir / "lnk_parsed.json").write_text('[{"lnk_file": "test.lnk"}]', encoding="utf-8")

    tree = build_evidence_tree(case_dir)
    assert tree is not None
    assert "evidence" in tree
    assert "parsed" in tree
    assert "ascii_tree" in tree

    ev_node = tree["evidence"]
    assert ev_node["name"] == "evidence"
    assert ev_node["file_count"] >= 1

    lines = tree["ascii_tree"]
    assert len(lines) > 0
    assert any("execution" in line for line in lines)


@pytest.mark.unit
def test_get_polaris_created_evidence_files(tmp_path: Path):
    case_dir = tmp_path / "case_test"
    case_dir.mkdir(parents=True)

    parsed_dir = case_dir / "parsed"
    parsed_dir.mkdir(parents=True)

    lnk_data = [
        {"lnk_file": "calc.lnk", "target_path": "C:\\Windows\\System32\\calc.exe", "arguments": ""},
        {"lnk_file": "cmd.lnk", "target_path": "C:\\Windows\\System32\\cmd.exe", "arguments": "/c whoami"},
    ]
    (parsed_dir / "lnk_parsed.json").write_text(json.dumps(lnk_data), encoding="utf-8")
    (parsed_dir / "netstat.txt").write_text("TCP 127.0.0.1:8080 LISTENING", encoding="utf-8")

    created = get_polaris_created_evidence_files(case_dir)
    assert len(created) >= 2

    json_item = next((item for item in created if item["filename"] == "lnk_parsed.json"), None)
    assert json_item is not None
    assert json_item["category"] == "User Activity"
    assert json_item["record_count"] == 2
    assert "sample_records" in json_item
