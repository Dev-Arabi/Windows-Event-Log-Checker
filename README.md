# 🛡️ Windows Forensic Triage & Evidence Collection Toolkit

<p align="center">

<img src="https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white" />
<img src="https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows" />
<img src="https://img.shields.io/badge/DFIR-Incident%20Response-red?style=for-the-badge" />
<img src="https://img.shields.io/badge/Version-v1.4.0-success?style=for-the-badge" />

</p>

<p align="center">

A professional PowerShell toolkit for <b>Digital Forensics</b>, <b>Incident Response</b>, and <b>Security Auditing</b> on Windows.

</p>

---

# 📖 Overview

The **Windows Forensic Triage & Evidence Collection Toolkit** is a professional **PowerShell-based DFIR toolkit** designed to perform rapid, read-only forensic acquisition on Windows systems.

It automates the collection of volatile and non-volatile artifacts, generates investigation-ready evidence, and exports structured results for malware analysis, incident response, and digital forensic investigations.

## Designed For

* 🔍 Digital Forensics
* 🚨 Incident Response
* 🛡 Security Auditing
* 💻 Malware Analysis
* 🏢 Enterprise Security Teams
* 🎓 Students & Researchers
* 🧑‍💻 SOC Analysts
* 🔬 DFIR Professionals

---

# ✨ Highlights

* ✅ Read-only forensic acquisition
* ✅ Windows Event Log collection
* ✅ Process & service enumeration
* ✅ Network evidence collection
* ✅ Registry artifact collection
* ✅ NTFS metadata & MFT collection
* ✅ Alternate Data Stream (ADS) detection
* ✅ Timestomp detection
* ✅ Timeline generation
* ✅ SHA256 evidence hashing
* ✅ Structured forensic reports
* ✅ Chain-of-custody friendly output

---

# 🚀 Quick Start

## Clone the repository

```powershell
git clone https://github.com/YOUR_USERNAME/Windows-Forensic-Toolkit.git
```

## Navigate to the project

```powershell
cd Windows-Forensic-Toolkit
```

## Allow PowerShell execution (Current Session)

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

## Run the toolkit

```powershell
.\Windows-Forensic-Toolkit.ps1
```

The toolkit will automatically create a timestamped **Evidence** directory containing all collected artifacts.

---

# 📂 Output Structure

```
Evidence/
│
├── Browser/
├── Drivers/
├── EventLogs/
├── FileSystem/
├── Hashes/
├── Logs/
├── Network/
├── NTFS/
├── Processes/
├── Registry/
├── Report/
├── Services/
├── System/
├── Timeline/
└── Users/
```

---

# 🔥 Features

---

## 🖥️ System Information

Collects:

* Computer Information
* Windows Version
* Build Information
* Installation Date
* Boot Time
* Time Zone
* Hostname
* Logged-in Users
* Local Users
* Local Groups
* Environment Variables

---

## 📜 Windows Event Logs

Collects important forensic event logs including:

* Security
* System
* Application
* Windows Defender
* PowerShell
* Terminal Services
* WMI Activity
* Task Scheduler
* Firewall
* AppLocker
* Operational Logs

---

## ⚙️ Process Analysis

* Running Processes
* Parent / Child Processes
* Services
* Drivers
* Running Command Lines
* Loaded Modules
* Startup Programs
* Scheduled Tasks
* Autoruns

---

## 👤 User Activity

* Recent Files
* Recent Executables
* PowerShell History
* Downloads
* Desktop
* Documents
* Clipboard
* Jump Lists
* Prefetch Files

---

## 🗂 Registry Collection

Collects forensic registry artifacts including:

* Run Keys
* RunOnce
* Installed Software
* UserAssist
* USB Devices
* Mounted Devices
* Explorer Artifacts
* Network Profiles
* MRUs
* Services

---

## 🌐 Network Evidence

* Active TCP Connections
* Listening Ports
* ARP Cache
* DNS Cache
* Routing Table
* SMB Sessions
* Network Interfaces
* Shared Resources
* Wi-Fi Profiles

---

## 📁 File System Analysis

* Hidden Files
* Large Files
* Recently Modified Files
* Startup Folders
* Temporary Files
* Recycle Bin
* Alternate Data Streams (ADS)
* Suspicious Executables
* Timestomp Detection

---

## 💾 NTFS Collection

Current Version includes:

* NTFS Metadata
* Volume Information
* Master File Table (MFT) Enumeration
* File Reference Numbers
* Security Metadata
* File Timestamps

Supports collecting up to **1000 MFT records per volume**.

---

## 🪟 Windows Artifacts

Collects:

* Event Logs
* Registry Hives
* Prefetch
* LNK Files
* Browser Artifacts
* Scheduled Tasks
* Services
* Windows Defender Logs
* Hosts File
* DNS Cache

---

## 📅 Timeline Generation

Automatically generates a forensic timeline containing:

* File Activity
* Registry Activity
* Event Logs
* User Activity
* System Events

---

## 🔐 Evidence Integrity

Designed for forensic investigations.

Includes:

* SHA256 Hashing
* Read-only Collection
* Timestamp Preservation
* Structured Output
* Chain-of-Custody Friendly Evidence

---

# ⚡ Performance

Typical execution time:

| Storage | Estimated Time |
| ------- | -------------- |
| SSD     | 2–6 Minutes    |
| HDD     | 5–15 Minutes   |

Execution time depends on:

* Event Log Size
* Number of Files
* Installed Software
* Number of Users
* Disk Capacity

---

# 📸 Screenshots

> Screenshots will be added in future releases.

---

# 🛣️ Roadmap

Planned future improvements include:

* Full $MFT Parser
* USN Journal Parser
* $LogFile Parser
* Amcache Parser
* ShimCache Parser
* BAM/DAM Parser
* SRUM Database Parser
* Windows Timeline Parser
* Jump List Parser
* Browser SQLite Parser
* HTML Report Generator
* IOC Correlation
* Sigma Rule Detection
* MITRE ATT&CK Mapping
* YARA Scanning
* Optional Memory Acquisition

---

# 🤝 Contributing

Contributions are welcome.

If you discover a bug, have an improvement, or would like to add new forensic capabilities, feel free to open an Issue or submit a Pull Request.

---

# 📄 License

This project is licensed under the **MIT License**.

See the `LICENSE` file for details.

---

# ⚠️ Disclaimer

This project is intended **only for legitimate Digital Forensics, Incident Response, Security Auditing, Malware Analysis, and Defensive Security purposes.**

The author assumes **no responsibility or liability** for any misuse, damage, or illegal activities arising from the use of this software.

---

# 👨‍💻 Author

**MR. X Gaming**

Digital Forensics • Incident Response • Windows Internals • PowerShell

---

<p align="center">

### ⭐ If this project helps you, consider giving it a Star!

Made with ❤️ for the DFIR & Cybersecurity Community.

</p>
# 🛡️ Windows Forensic Triage & Evidence Collection Toolkit

<p align="center">

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows)
![DFIR](https://img.shields.io/badge/DFIR-Incident%20Response-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-v1.4.0-success?style=for-the-badge)


</p>

---

## Overview

**Windows Forensic Triage & Evidence Collection Toolkit** is a professional **PowerShell-based Digital Forensics & Incident Response (DFIR)** toolkit designed to perform **read-only forensic triage** on Windows systems.

The toolkit rapidly collects volatile and non-volatile artifacts, builds forensic timelines, preserves evidence integrity, and exports structured results for later investigation.

Designed for:

- 🔍 Digital Forensics
- 🚨 Incident Response
- 🛡️ Security Auditing
- 💻 Malware Investigations
- 🧑‍💻 SOC Analysts
- 🏢 Enterprise IR Teams
- 🎓 Learning Windows Internals

---

# Features

## System Information

- Computer Information
- Windows Version
- Installation Date
- Boot Time
- Time Zone
- Logged-in Users
- Local Users
- Groups
- Environment Variables

---

## Event Log Collection

Collects important Windows Event Logs including:

- Security
- System
- Application
- PowerShell
- Windows Defender
- Terminal Services
- WMI Activity
- Task Scheduler
- AppLocker
- Firewall
- Operational Logs

---

## Process Analysis

- Running Processes
- Parent/Child Relationships
- Services
- Drivers
- Loaded Modules
- Scheduled Tasks
- Startup Entries
- Autoruns
- Running Command Lines

---

## User Activity

- Recent Files
- Recent Executables
- Prefetch Files
- Jump Lists
- PowerShell History
- Clipboard
- Downloads
- Desktop
- Documents

---

## Registry Collection

Collects forensic registry artifacts including:

- Run Keys
- RunOnce
- Services
- USB Devices
- Mounted Devices
- Installed Software
- UserAssist
- Explorer Artifacts
- Network Profiles
- MRUs

---

## Network Evidence

- Active Connections
- Listening Ports
- ARP Cache
- DNS Cache
- Routing Table
- Network Interfaces
- Wi-Fi Profiles
- Shares
- SMB Sessions

---

## File System Analysis

- Hidden Files
- Suspicious Executables
- Alternate Data Streams (ADS)
- Timestomp Detection
- Recently Modified Files
- Large Files
- Temp Files
- Startup Folders
- Recycle Bin

---

## NTFS Collection

Current Version includes:

- NTFS Metadata
- Volume Information
- MFT Enumeration
- File Reference Data
- File Timestamps
- Security Information

Supports collecting up to **1000 MFT records per volume**.

---

## Windows Artifacts

- Prefetch
- Event Logs
- Registry Hives
- Browser Artifacts
- LNK Files
- Scheduled Tasks
- Services
- Windows Defender Logs
- Hosts File
- DNS Cache

---

## Timeline Generation

Automatically generates forensic timelines using collected evidence.

Timeline includes:

- File Activity
- Registry Activity
- Event Logs
- User Activity
- System Events

---

## Evidence Integrity

- SHA256 Hashes
- Read-only Collection
- Timestamp Preservation
- Structured Output
- Chain-of-Custody Friendly

---

# Output Structure

```
Evidence/
│
├── System/
├── EventLogs/
├── Registry/
├── Network/
├── Processes/
├── Services/
├── Drivers/
├── FileSystem/
├── Timeline/
├── NTFS/
├── Browser/
├── Users/
├── Logs/
├── Hashes/
└── Report/
```

---

# Screenshots

```
Coming Soon
```

---

# Requirements

- Windows 10
- Windows 11
- Windows Server
- PowerShell 5.1+
- Administrator Privileges (Recommended)

---

# Usage

Clone the repository

```powershell
git clone https://github.com/USERNAME/Windows-Forensic-Toolkit.git
```

Navigate to the folder

```powershell
cd Windows-Forensic-Toolkit
```

Allow execution (Current Session)

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

Run the toolkit

```powershell
.\Windows-Forensic-Toolkit.ps1
```

---

# Evidence Collection Philosophy

This toolkit is designed to perform **read-only forensic acquisition** wherever possible.

It **does not intentionally modify forensic artifacts**, making it suitable for triage and incident response investigations.

---

# Performance

Typical collection time:

| System | Approx Time |
|---------|-------------|
| SSD | 2–6 minutes |
| HDD | 5–15 minutes |

Depends on:

- Event Log Size
- Number of Files
- Number of Users
- Installed Software
- Disk Capacity

---

# Version

Current Release

```
v1.4.0
```

Highlights

- Increased MFT Collection
- ADS Detection
- Timestomp Detection
- Recent Executable Hunting
- Improved File Collection
- Performance Improvements
- Bug Fixes

---

# Roadmap

Future versions may include:

- Full $MFT Parser
- USN Journal Parser
- $LogFile Parser
- ShimCache Parser
- Amcache Parser
- BAM/DAM Parser
- SRUM Database Parser
- Jump List Parser
- Windows Timeline Parser
- Browser SQLite Parser
- HTML Report
- IOC Correlation
- Sigma Detection
- MITRE ATT&CK Mapping
- YARA Scanning
- Memory Acquisition Support

---

# Disclaimer

This project is intended **only for defensive security, digital forensics, incident response, and security auditing**.

The author is **not responsible** for misuse or illegal activities involving this software.

---

# Contributing

Contributions are welcome.

If you find bugs or have feature requests, feel free to open an Issue or submit a Pull Request.

---

# License

MIT License

---

# Author

**MR. X Gaming**

Digital Forensics • Incident Response • Windows Internals • PowerShell

---

<p align="center">

⭐ If you find this project useful, consider giving it a star!

</p>
