# 🛡️ Windows Forensic Triage & Evidence Collection Toolkit

<p align="center">

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows)
![DFIR](https://img.shields.io/badge/DFIR-Incident%20Response-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-v1.4.0-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

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
