# POLARIS - WINDOWS DIGITAL FORENSICS & INTELLIGENCE SUITE

```
   ___  ____  __    ___    ____  _________
  / _ \/ __ \/ /   /   |  / __ \/  _/ ___/
 / ___/ /_/ / /   / /| | / /_/ // / \__ \ 
/_/   \____/____//_/ |_|/_/   _/___/____/ 
```

> "Your guide to Digital Forensics"

POLARIS is an automated, forensically sound Windows artifact acquisition, timeline correlation, and explainable AI intelligence platform. Inspired by the North Star, POLARIS guides incident responders and digital forensic examiners through live endpoint triage, cryptographic evidence sealing, deterministic heuristic detection, and evidence-grounded AI assessment.

---

## Installation

```powershell
pip install -r requirements.txt
```

---

## Simple Commands

POLARIS is designed to run automatically with simple, single-line commands:

```powershell
# 1. Rapid Triage (Default): Runs Quick profile, interactive AI setup, reports, and evidence ZIP
py main.py

# 2. Comprehensive Investigation: Runs Full profile across all 24 forensic collectors
py main.py --full

# 3. Offline Mode: Runs without external API calls (deterministic heuristic analysis)
py main.py --offline

# 4. View Help and All Options
py main.py help
```

---

## How It Works

When you run `py main.py` or `py main.py --full`:

1. **Pre-Run AI Configuration**: POLARIS prompts if you want to configure an AI API key for explainable analysis.
   - Choose from Google Gemini (Recommended), OpenAI, Anthropic Claude, Manual entry, or Offline mode.
   - If you press Enter, it automatically uses your active shell environment key or defaults to offline mode.
2. **Celestial Collector**: Live artifact acquisition with a real-time visual progress bar.
3. **Observatory**: Heuristics, MITRE ATT&CK alignment, and cross-artifact correlation.
4. **Constellation**: Unified chronological timeline generation.
5. **Evidence Vault**: Real-time cryptographic SHA-256 integrity verification.
6. **Stellar Intelligence**: Grounded AI forensic synthesis positioned at the top of the findings.
7. **Northstar Reports**: Automatically generates HTML & PDF reports and opens the HTML report in your default browser.
8. **Mission Archive**: Packages all evidence and manifests into a sealed, SHA-256 hashed ZIP container.

---

## Supported Windows Artifacts (24 Collectors)

- **Execution**: Prefetch (.pf), Amcache, Shimcache, BAM, DAM, SRUM, UserAssist, PCA, PowerShell Logs.
- **Event Logs**: Security, System, Application, Defender, TerminalServices, Firewall, Sysmon.
- **User Activity**: Shortcut Files (LNK), Jump Lists, RecentDocs, ShellBags, Recycle Bin ($I).
- **Registry Hives**: SYSTEM, SOFTWARE, DEFAULT, NTUSER.DAT, UsrClass.dat, Startup Run/RunOnce.
- **Browsers**: Google Chrome, Microsoft Edge, Mozilla Firefox (History, Downloads, Bookmarks).
- **Hardware & Devices**: USBSTOR, MountedDevices, SetupAPI.dev.log, Kernel-PnP.
- **Persistence**: Windows Services, Scheduled Tasks, Startup Folders, Drivers, WMI Subscriptions.
- **Network & Volatile**: Netstat connections, open ports, ARP cache, DNS cache, active routing table.

---

## Output Structure

Each case is preserved in `cases/<CASE-ID>/`:

```
cases/<CASE-ID>/
|-- archive/              # Sealed POLARIS_CASE_<CASE-ID>_<TIMESTAMP>.zip
|-- reports/              # report.html (interactive) and report.pdf (executive)
|-- manifests/            # SHA256_MANIFEST.csv and SHA256_MANIFEST.json
|-- evidence/             # Raw bit-for-bit acquired forensic artifacts
|-- parsed/               # Extracted CSV and JSON parsed records
|-- timeline/             # Unified forensic chronological TIMELINE.csv and TIMELINE.json
|-- metadata/             # System information, findings.json, and ai_analysis.json
\-- logs/                 # Operational and debug logs
```

## License

Distributed under the MIT License. See LICENSE for details.
