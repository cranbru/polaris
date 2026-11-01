import json
import pytest
from pathlib import Path

from ai.smart_evidence import extract_smart_evidence_context


@pytest.mark.unit
def test_extract_smart_evidence_context_with_mock_data(tmp_path: Path):
    case_dir = tmp_path / "case_test"
    parsed_dir = case_dir / "parsed"
    parsed_dir.mkdir(parents=True)

    # 1. Mock LNK shortcuts: benign vs suspicious
    lnk_records = [
        # Benign OS shortcut
        {
            "lnk_file": "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\Calculator.lnk",
            "target_path": "C:\\Windows\\System32\\calc.exe",
            "arguments": "",
            "modification_time": "2026-01-01 10:00:00",
        },
        # Suspicious shortcut with arguments
        {
            "lnk_file": "C:\\Users\\user\\Desktop\\Suspicious.lnk",
            "target_path": "powershell.exe",
            "arguments": "-enc SQBFAFgA",
            "modification_time": "2026-11-01 12:00:00",
        },
        # Non-standard target path (Temp)
        {
            "lnk_file": "C:\\Users\\user\\Downloads\\installer.lnk",
            "target_path": "C:\\Users\\user\\AppData\\Local\\Temp\\setup.exe",
            "arguments": "",
            "modification_time": "2026-11-01 12:05:00",
        },
    ]
    (parsed_dir / "lnk_parsed.json").write_text(json.dumps(lnk_records), encoding="utf-8")

    # 2. Mock Prefetch executions
    prefetch_records = [
        {"executable": "cmd.exe", "run_count": 5, "last_run_time": "2026-11-01 12:00:00"},
        {"executable": "powershell.exe", "run_count": 1, "last_run_time": "2026-11-01 12:01:00"},
    ]
    (parsed_dir / "prefetch_parsed.json").write_text(json.dumps(prefetch_records), encoding="utf-8")

    ctx = extract_smart_evidence_context(case_dir)

    assert "shortcut_analysis" in ctx
    shortcut_info = ctx["shortcut_analysis"]
    assert shortcut_info["total_shortcuts_acquired"] == 3
    assert shortcut_info["standard_os_shortcuts_count"] == 1
    assert shortcut_info["suspicious_or_parameterized_count"] == 2

    assert "execution_summary" in ctx
    exec_info = ctx["execution_summary"]
    assert exec_info["total_prefetch_analyzed"] == 2
    assert len(exec_info["recent_executions"]) == 2


@pytest.mark.unit
def test_extract_smart_evidence_context_empty(tmp_path: Path):
    case_dir = tmp_path / "empty_case"
    case_dir.mkdir(parents=True)

    ctx = extract_smart_evidence_context(case_dir)
    assert isinstance(ctx, dict)
    assert ctx["shortcut_analysis"]["total_shortcuts_acquired"] == 0
    assert ctx["execution_summary"]["total_prefetch_analyzed"] == 0
