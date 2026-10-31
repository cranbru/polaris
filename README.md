# POLARIS

```
                     .
                    / \
                   --*--
                    \ /
                     '
          .           |           .
           \          |          /
            \       +---+       /
             \      | * |      /
       -------+-----+---+-----+-------
             /      | * |      \
            /       +---+       \
           /          |          \
          '           |           '
                     .
                    / \
                   --*--
                    \ /
                     '
   ___  ____  __    ___    ____  _________
  / _ \/ __ \/ /   /   |  / __ \/  _/ ___/
 / ___/ /_/ / /   / /| | / /_/ // / \__ \ 
/_/   \____/____//_/ |_|/_/   _/___/____/ 
```

> "Your guide to Digital Forensics"
> Windows Digital Forensics, Artifact Acquisition & Intelligence Suite

POLARIS is a modular, forensically sound Windows artifact acquisition, timeline correlation, and explainable AI analysis engine. Inspired by the North Star, POLARIS guides incident responders and forensic examiners through live endpoint triage, cryptographic evidence sealing, deterministic heuristic detection, and evidence-grounded AI intelligence.

---

## Celestial Navigation Architecture

The application is structured around a 9-module celestial navigation matrix:

- [01] MISSION CONTROL: Central telemetry console and system environment monitoring.
- [02] CELESTIAL COLLECTOR: Multi-category live Windows forensic artifact acquisition.
- [03] OBSERVATORY: Artifact parsing, deterministic heuristic rules, and cross-correlation.
- [04] CONSTELLATION: Unified chronological forensic timeline synthesis.
- [05] STELLAR INTELLIGENCE: Evidence-grounded multi-provider AI analysis engine.
- [06] EVIDENCE VAULT: Dual-manifest tracking (CSV/JSON) and SHA-256 cryptographic verification.
- [07] NORTHSTAR REPORT: Publication-grade HTML and PDF forensic intelligence documentation.
- [08] MISSION ARCHIVE: Containerized ZIP evidence packaging with independent verification seal.
- [09] SETTINGS: Configuration of neural providers, inference budgets, and privacy controls.

---

## Key Capabilities

### 1. Forensic Integrity and Privacy Controls
- Strict read-only live acquisition.
- SHA-256 cryptographic hash calculated for every acquired artifact at point of capture.
- Dual manifest tracking: SHA256_MANIFEST.csv and SHA256_MANIFEST.json.
- Cryptographic verification engine detecting unmodified, modified, missing, and unexpected files.
- Zero collection of active browser sessions, cookies, login passwords, or credit card databases.
- System credential databases (SAM, SECURITY) and raw LSASS memory dumps are strictly excluded.
- Command history (PSReadLine) requires explicit investigator authorization.

### 2. Supported Windows Artifact Collectors (24 Modules)
- Execution:
  - Windows Prefetch (.pf with MAM and SCCA header parsing)
  - Amcache (Amcache.hve)
  - Shimcache / AppCompatCache
  - Background Activity Moderator (BAM)
  - Desktop Activity Moderator (DAM)
  - System Resource Usage Monitor (SRUM / SRUDB.dat)
  - UserAssist (with ROT13 application name decoding)
  - Program Compatibility Assistant (PCA)
  - PowerShell Operational & ScriptBlock event logs
- Windows Event Logs:
  - Security, System, Application
  - Windows Defender, PowerShell Operational, Task Scheduler
  - Remote Desktop (TerminalServices), Windows Firewall, Sysmon
- User Activity:
  - Windows Shortcut (LNK) files (parsed via LnkParse3)
  - AutomaticDestinations & CustomDestinations Jump Lists (parsed via olefile)
  - RecentDocs & OpenSavePidlMRU registry keys
  - ShellBags (BagMRU and Bags)
  - Recycle Bin ($I index records with deletion timestamps and original paths)
- Registry Hives:
  - Live hive exports: SYSTEM, SOFTWARE, DEFAULT, NTUSER.DAT, UsrClass.dat
  - Key extraction: Installed applications, Startup (Run/RunOnce), USB history, mounted devices
- Web Browsers:
  - Google Chrome, Microsoft Edge, Mozilla Firefox
  - History, Downloads, Bookmarks with SQLite WAL and SHM companion file handling
- USB and Device Artifacts:
  - USBSTOR, MountedDevices, USB enumeration, SetupAPI.dev.log, Kernel-PnP events
- Persistence Mechanisms:
  - Windows Services, Scheduled Tasks, Startup Folders, Run/RunOnce, Drivers, WMI Event Subscriptions
- Volatile Network and System Telemetry:
  - Netstat connections, listening ports, network adapters, ARP cache, DNS cache, routing table, firewall configuration
  - Systeminfo, running processes (tasklist), local user accounts

### 3. Hybrid Detection Engine
- Layer 1: Deterministic Rules (Suspicious execution directories, LOLBin invocations, Base64 PowerShell commands, non-standard services).
- Layer 2: Cross-Artifact Correlation (Runtime process execution correlated with persistence configurations; removable drive activity correlated with USB hardware records).
- Layer 3: Stellar Intelligence (Evidence-grounded AI synthesis using OpenAI, Anthropic, Gemini, or Offline deterministic engine).
- Layer 4: Investigator Validation (Human analyst annotations, review status tracking, and severity filtering).

### 4. Explainable AI and Evidence Grounding
Every finding is strictly grounded in acquired evidence and categorized by grounding tier:
- OBSERVED: Directly attested by an acquired evidence file.
- CORRELATED: Supported by cross-artifact convergence across multiple collectors.
- INFERRED: Analytical interpretation requiring additional validation.
- UNCONFIRMED: Plausible hypothesis requiring further evidence.

Each explainable finding records:
- Finding ID and Title
- Severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Confidence Level (HIGH, MODERATE, LOW)
- Grounding Tier
- Source Artifacts and Evidence IDs
- Observed Facts
- Analytical Interpretation
- Supporting Indicators and Alternative Benign Explanations
- Why the Finding Matters (DFIR Relevance)
- Recommended Validation Steps and Limitations

### 5. Multi-Provider AI Architecture
- OpenAI (e.g. gpt-4o, gpt-4o-mini)
- Anthropic (e.g. claude-3-5-sonnet-20241022)
- Google Gemini (e.g. gemini-1.5-pro, gemini-1.5-flash)
- Offline Deterministic Engine (no network access or API key required)

API keys are managed strictly via environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY) and are never logged, displayed, or written to reports or archive containers.

### 6. AI Security and Prompt Injection Defense
- Evidence is treated strictly as untrusted data, never as instructions.
- Text is sanitized and wrapped in protective structural boundaries to neutralize prompt injection payloads embedded in filenames or event logs.
- Automatic PII and credential redaction (emails, bearer tokens, API keys, password parameters).
- Explicit investigator consent prompt before transmitting telemetry to external cloud providers.

---

## Installation

### Prerequisites
- Windows 10 or Windows 11
- Python 3.11+
- Administrator privileges recommended for complete registry hive and security event log acquisition.

```powershell
pip install -r requirements.txt
```

---

## CLI Command Reference

```powershell
# 1. Mission Control: System telemetry and registered modules
python main.py dashboard

# 2. Celestial Collector: Artifact acquisition
python main.py collect --profile quick                          # High-value artifacts
python main.py collect --profile full --case-id CASE-001        # Full forensic collection
python main.py collect --profile custom                         # Interactive module picker
python main.py collect --profile full --no-parse                # Raw acquisition only

# 3. Observatory: Deterministic heuristic analysis & correlation
python main.py analyze --case CASE-001

# 4. Query explainable findings with validation steps
python main.py findings --case CASE-001
python main.py findings --case CASE-001 --severity high

# 5. Constellation: Unified chronological timeline synthesis
python main.py timeline --case CASE-001

# 6. Evidence Vault: Cryptographic SHA-256 evidence verification
python main.py verify --case CASE-001

# 7. Stellar Intelligence: Grounded AI analysis
python main.py ai --case CASE-001 --provider openai
python main.py ai --case CASE-001 --provider anthropic
python main.py ai --case CASE-001 --provider gemini
python main.py ai --case CASE-001 --offline

# 8. Northstar Report: HTML and PDF forensic documentation
python main.py report --case CASE-001                           # Default (includes AI if run)
python main.py report --case CASE-001 --without-ai              # Traditional forensic report only

# 9. Mission Archive: Sealed ZIP container creation
python main.py package --case CASE-001

# 10. Settings: View and configure providers and neural models
python main.py settings
python main.py settings --provider openai --model gpt-4o

# 11. End-to-end automated pipeline
python main.py all --profile full --case-id CASE-001
python main.py all --profile full --case-id CASE-001 --provider gemini
python main.py all --profile quick --case-id CASE-002 --offline
```

---

## Evidence Archive Structure

When a case is sealed with `polaris package`, a ZIP container named `POLARIS_CASE_<CASE-ID>_<TIMESTAMP>.zip` is produced with an accompanying `.sha256` checksum and manifest:

```
POLARIS_CASE_<CASE-ID>_<TIMESTAMP>.zip
├── evidence/            # Raw, bit-for-bit acquired artifacts (Prefetch, EVTX, Hives, etc.)
├── parsed/              # Extracted JSON and CSV files
├── timeline/            # TIMELINE.csv and TIMELINE.json
├── manifests/           # SHA256_MANIFEST.csv and SHA256_MANIFEST.json
├── logs/                # Execution debug logs
├── metadata/            # System info, findings.json, ai_analysis.json, ai_analysis.md
├── reports/             # report.html and report.pdf
└── verification/        # verification_<timestamp>.json
```

---

## Testing

POLARIS includes an automated offline unit test suite covering collector lifecycles, hashing, manifest verification, timeline building, report rendering, AI provider adapters, prompt security, redaction, and hybrid detection rules:

```powershell
pytest tests/ -v
```

---

## PyInstaller Executable Build

To compile POLARIS into a standalone Windows binary for field deployment on USB drives:

```powershell
pyinstaller --onefile --name polaris --clean `
  --hidden-import "jinja2" `
  --hidden-import "reportlab" `
  --hidden-import "pydantic" `
  --hidden-import "LnkParse3" `
  --hidden-import "olefile" `
  --hidden-import "Evtx" `
  --hidden-import "Registry" `
  --add-data "reports/templates;reports/templates" `
  main.py
```

---

## License

Distributed under the MIT License. See LICENSE for details.
