<div align="center">

# 🛡️ CyberSentinel Pro
### High-Speed Windows Threat Hunting, Forensic Audit & Rapid Incident Response Engine

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/)
[![Language](https://img.shields.io/badge/Language-Python%203.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Stdlib)-brightgreen?style=for-the-badge)](https://github.com/)
[![Audit Time](https://img.shields.io/badge/Scan%20Time-%3C%2015%20Seconds-blueviolet?style=for-the-badge)](https://github.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

*An industrial-grade, lightweight incident response tool that audits 11 attack vectors in seconds, verifies Authenticode digital signatures, calculates threat scores, and provides immediate dual-action remediation.*

[Key Features](#-key-features) •
[Quick Start](#-quick-start) •
[11 Detection Vectors](#-11-forensic-detection-vectors) •
[MITRE ATT&CK Mapping](#-mitre-attck-matrix-mapping) •
[CLI Options](#-cli-reference--automation)

</div>

---

## ⚡ Why CyberSentinel?

Traditional antivirus disk scans take **30 to 60 minutes** reading every byte of inert files. Meanwhile, active malware, reverse shells, living-off-the-land (LOLBins) binaries, and stealth persistence operate **in memory, registries, scheduled tasks, and network sockets**.

**CyberSentinel Pro** audits the entire operational state of Windows in **under 15 seconds** using native OS telemetry, behavioral inspection, and Authenticode cryptographic verification—with **zero external third-party dependencies**.

```text
====================================================================================================
           CYBERSENTINEL PRO : ADVANCED WINDOWS THREAT AUDIT & INCIDENT RESPONSE
====================================================================================================
[*] Initializing deep multi-vector system audit (Authenticode + Forensic Hashing)...

  [1/11] Auditing Windows Defender (Engine & Real-Time Protection)...
  [2/11] Auditing Active Threats (Quarantine & Live Detections)...
  [3/11] Auditing Firewall Profiles (Domain, Private & Public Rules)...
  [4/11] Auditing Network Connections (Outbound C2 & Listening Backdoors)...
  [5/11] Auditing Suspicious Processes (LOLBins, Temp Binaries & Authenticode)...
  [6/11] Auditing Persistence / Startup (Registry Run/RunOnce & Startup Dir)...
  [7/11] Auditing Scheduled Tasks (Task Scheduler Persistence Auditing)...
  [8/11] Auditing Running Services (Windows Services Path Inspection)...
  [9/11] Auditing Hosts / DNS Integrity (Domain Redirection & Hijack Check)...
  [10/11] Auditing High-Risk Drop Dirs (Temp, Public & Downloads Scripts)...
  [11/11] Auditing Security Event Logs (Anti-Forensics & Wiped Log Checks)...

====================================================================================================
                                   SECURITY INSPECTION RESULTS
====================================================================================================
Check Category           Status             Details                                                
----------------------------------------------------------------------------------------------------
Windows Defender         Healthy & Active   Real-time protection, behavior monitor, and IOAV scanning active.
Active Threats           None Detected      0 active threats flagged by Defender. Threat history log is clean.
Firewall Profiles        Enabled            Domain, Private, and Public profiles are all active.   
Network Connections      Normal             All outbound connections verified (standard HTTPS 443 / verified apps).
Suspicious Processes     Clean              No rogue or temp processes running. Command lines verified.
Persistence / Startup    Clean              No suspicious autostart items found in Registry or Startup folders.
Scheduled Tasks          Clean              All active scheduled tasks verified against legitimate system templates.
Running Services         Clean              All running Windows services executing from standard protected system paths.
Hosts / DNS Integrity    Clean              Hosts file is intact. No DNS redirection or security site hijacking found.
High-Risk Drop Dirs      Clean              No unverified script payloads or disguised binaries found in Temp/Public/Downloads.
Security Event Logs      Clean              Security event logs intact. No anti-forensics log wiping detected.
====================================================================================================
[*] System Threat Risk Score : 0 / 100
[*] Deep Forensic Audit Time  : 7.68 seconds (Well within 5-minute target)
```

---

## 🌟 Key Features

* **Smart Authenticode Signature Verification**: Eliminates false positives by verifying binary certificates. Legitimate signed installers in `Temp` (like Ollama or Chrome) are recognized with vendor details, while unsigned binaries are flagged with high confidence.
* **Cryptographic SHA-256 Hashing**: Automatically hashes all suspicious binaries and generates direct VirusTotal lookup links.
* **Intelligent Threat Scoring (0–100 Risk Score)**: Aggregates indicators of compromise (IoCs) into an executive risk index.
* **Interactive Dual-Action Remediation**:
  * **`[1] Force Delete`**: Terminate process tree, unhook registry keys/scheduled tasks, strip locks, and permanently destroy file.
  * **`[2] Quarantine Vault`**: Safely moves file to an encrypted/isolated `.quarantine` vault with stripped execution permissions and a JSON audit manifest.
  * **`[3] Keep / Whitelist`**: Skip verified benign items.
* **SOC / SIEM Exporting**: Generate machine-readable JSON forensic exports and standalone dark-mode HTML executive reports.
* **Pure Standard Library**: No `pip install` required. Operates seamlessly on clean Windows environments.

---

## 🚀 Quick Start

### Option 1: One-Click GUI Execution
Double-click `run_scanner.bat`. It will run the audit, show live progress, prompt if any threats are detected, and produce an HTML audit report.

### Option 2: Command Line
```powershell
python cyber_sentinel.py
```

---

## 🔍 11 Forensic Detection Vectors

| Vector | Focus Area | What CyberSentinel Checks |
| :--- | :--- | :--- |
| **1. Windows Defender** | AV Engine State | Real-time protection, behavior monitor, IOAV filter, definitions freshness. |
| **2. Active Threats** | Malware Detections | Live infected resources, active threat logs, and quarantine state. |
| **3. Firewall Profiles** | Perimeter Rules | Domain, Private, and Public profile enforcement. |
| **4. Network C2 & Sockets** | Inbound/Outbound | Established sockets to known attack ports (`4444`, `1337`, `31337`, `6667`) and rogue listeners. |
| **5. Running Processes & LOLBins** | Living-off-the-Land | Obfuscated PowerShell (`-enc`, `-w hidden`, `IEX`, `DownloadString`), `certutil`, `bitsadmin`, `vssadmin` shadow copy deletion, masqueraded system binaries (`svchost.exe` outside System32), double-extensions (`.pdf.exe`). |
| **6. Persistence Mechanisms** | Autostart Hooks | `Run` & `RunOnce` registry keys (HKCU & HKLM), Startup folders (`shell:startup`). |
| **7. Scheduled Tasks** | Hidden Triggers | Non-system tasks executing out of user directories or with stealth command flags. |
| **8. Windows Services** | Privilege Escalation | Running services executing out of user profiles (`AppData\Local\Temp`, `Public`). |
| **9. DNS & Hosts File** | Redirection Hijacking | Tampering of `drivers\etc\hosts` redirecting search engines or security update servers. |
| **10. High-Risk Directories** | Staging / Drops | Rapid heuristic scan of `Temp`, `Users\Public`, and `Downloads` for scripts (`.vbs`, `.bat`, `.ps1`, `.scr`). |
| **11. Security Event Logs** | Anti-Forensics | Detection of cleared security event logs (Event ID 1102) and unauthorized service installation. |

---

## 🎯 MITRE ATT&CK Matrix Mapping

CyberSentinel Pro directly maps its heuristic and forensic checks to the MITRE ATT&CK framework:

| Tactic | Technique ID | Technique Name | CyberSentinel Detection |
| :--- | :--- | :--- | :--- |
| **Execution** | `T1059.001` | PowerShell | Detects encoded strings, hidden windows, memory downloads. |
| **Persistence** | `T1547.001` | Registry Run Keys / Startup Folder | Scans HKCU/HKLM Run keys and user Startup paths. |
| **Persistence** | `T1053.005` | Scheduled Task | Audits task execution triggers in user directories. |
| **Defense Evasion** | `T1036.005` | Masquerading | Identifies system binaries running in non-system directories. |
| **Defense Evasion** | `T1070.001` | Clear Windows Event Logs | Flags Event ID 1102 (Security audit log wiped). |
| **Defense Evasion** | `T1027` | Obfuscated Files or Information | Double extension detection (`.pdf.exe`, `.docx.exe`). |
| **Command and Control**| `T1095` | Non-Application Layer Protocol | Flags non-standard backdoor ports (`4444`, `1337`, `31337`). |
| **Impact** | `T1490` | Inhibit System Recovery | Detects `vssadmin delete shadows` ransomware behavior. |

---

## 🛠️ CLI Reference & Automation

CyberSentinel Pro includes a rich set of command-line flags for automation, CI/CD pipelines, and incident response automation:

```text
usage: cyber_sentinel.py [-h] [--scan-only] [--quarantine-all] [--force-delete-all]
                         [--json FILE] [--html FILE] [--no-color]

Options:
  -h, --help            Show this help message and exit
  --scan-only           Run forensic audit in read-only mode (no interactive prompt)
  --quarantine-all      Automatically move all detected threats into .quarantine vault
  --force-delete-all    Non-interactively terminate and destroy all flagged threats
  --json FILE           Export forensic findings to structured JSON file
  --html FILE           Export interactive standalone HTML dashboard report
  --no-color            Disable terminal ANSI color formatting (for logging/CI)
```

### Examples

**Export both JSON and HTML reports:**
```powershell
python cyber_sentinel.py --json audit.json --html audit.html
```

**Automated headless server scan & auto-quarantine:**
```powershell
python cyber_sentinel.py --quarantine-all --json /var/log/sentinel.json
```

---

## 📁 Repository Structure

```text
cyber-sentinel-scanner/
├── cyber_sentinel.py       # Core Multi-Vector Forensic & IR Engine
├── run_scanner.bat         # 1-Click Windows Batch Launcher
├── README.md               # Documentation & MITRE ATT&CK Matrix
├── LICENSE                 # MIT Open-Source License
├── .gitignore              # Git Ignore Configuration
└── .quarantine/            # (Auto-generated) Isolated Encrypted Quarantine Vault
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) - free for personal, commercial, and enterprise incident response use.
