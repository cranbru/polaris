# POLARIS 🌟
> *"Your guide to Digital Forensics"*

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6.svg)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**POLARIS** is a modular, forensically sound Windows artifact acquisition and DFIR analysis engine. Engineered for offline and live investigations, it acquires system evidence, performs cryptographic SHA-256 integrity hashing, runs heuristic analysis rules, builds chronological timelines, and generates forensic reports.

---

## ⚡ Features

- **🛡️ Forensic Soundness & Integrity:**
  - Strict read-only live acquisition.
  - Automatic SHA-256 hash calculation for every acquired artifact.
  - Dual manifest tracking (`SHA256_MANIFEST.csv` and `SHA256_MANIFEST.json`).
  - Cryptographic verification engine detecting unmodified, modified, and missing evidence.
- **🔒 Privacy by Design:**
  - Zero collection of browser passwords, active sessions, or cookies.
  - Excludes system credential hives (`SAM`, `SECURITY`) and memory dumps.
  - Command histories (`PSReadLine`) require explicit authorization.
- **📦 24 Forensic Artifact Modules:**
  - **Execution:** Prefetch (.pf with MAM/SCCA parsing), Amcache, Shimcache, BAM, DAM, SRUM, UserAssist (ROT13 decode), PCA.
  - **Event Logs:** Security, System, Application, Defender, PowerShell Operational, Task Scheduler, Sysmon.
  - **User Activity:** LNK Shortcuts, Jump Lists (Automatic & Custom), RecentDocs, ShellBags, Recycle Bin ($I).
  - **Registry:** Live hive exports (`SYSTEM`, `SOFTWARE`, `DEFAULT`, `NTUSER.DAT`) & key extraction (Run/RunOnce, USB history, installed apps).
  - **Browsers:** Chrome, Edge, Firefox history, downloads, and bookmarks with SQLite WAL/SHM handling.
  - **Network & Volatile State:** Netstat, listening ports, network adapters, ARP cache, DNS cache, routing table.
  - **Persistence & Devices:** Services, scheduled tasks, startup entries, WMI persistence, USBSTOR devices.
- **🧠 Automated Analysis & Heuristics:**
  - Flags execution from volatile directories (`Temp`, `AppData`, `Downloads`).
  - Detects encoded PowerShell commands.
  - Cross-correlates runtime processes with persistence hooks.
- **⏱️ Unified Forensic Timeline:**
  - Synthesizes chronologically sorted events into `TIMELINE.csv` and `TIMELINE.json`.
- **📊 Reporting & Packaging:**
  - Functional HTML and PDF report generation.
  - Sealed ZIP evidence package (`POLARIS_CASE_<ID>_<TIMESTAMP>.zip`) with independent SHA-256 checksum.

---

## 🚀 Quick Start

### Prerequisites
- Windows 10 or Windows 11
- Python 3.11+
- Administrator privileges recommended for complete hive and event log acquisition.

### Installation
```powershell
# Clone the repository
git clone https://github.com/<your-username>/polaris.git
cd polaris

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 CLI Usage

```powershell
# 1. View system status and registered modules
python main.py dashboard

# 2. Collect artifacts
python main.py collect --profile quick                          # High-value artifacts
python main.py collect --profile full --case-id CASE-001        # Full forensic collection
python main.py collect --profile custom                         # Interactive module picker

# 3. Analyze case findings
python main.py analyze --case CASE-001

# 4. Generate forensic timeline
python main.py timeline --case CASE-001

# 5. Verify evidence integrity against SHA-256 manifest
python main.py verify --case CASE-001

# 6. Generate HTML and PDF reports
python main.py report --case CASE-001

# 7. Package evidence into a sealed ZIP container
python main.py package --case CASE-001

# 8. Run complete end-to-end pipeline in one step
python main.py all --profile full --case-id CASE-001
```

---

## 🧪 Testing

Run the offline unit test suite:

```powershell
pytest tests/ -v
```

---

## 🏗️ Architecture

```
POLARIS/
├── cli/          # Typer CLI application & Rich console renderers
├── core/         # Acquisition engine, manifest, timeline & case manager
├── collectors/   # 24 modular artifact acquisition collectors
├── parsers/      # Native parsers & external tool adapters (PECmd)
├── analysis/     # Forensic heuristic rules & artifact correlation
├── reports/      # HTML (Jinja2) and PDF (ReportLab) generators
├── packaging/    # Forensic ZIP packaging & cryptographic sealing
├── utils/        # Filesystem, timestamp, and process utilities
└── tests/        # Pytest unit & integration test suite
```

---

## ⚖️ License

Distributed under the MIT License. See `LICENSE` for details.
