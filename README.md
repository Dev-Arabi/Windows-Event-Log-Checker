# 🛡️ Windows Forensic Triage & Evidence Collection Toolkit

<div align="center">

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge\&logo=powershell\&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-blue?style=for-the-badge\&logo=windows)
![License](https://img.shields.io/badge/License-Forensic%20Use-success?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows-important?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen?style=for-the-badge)

### 🔍 Professional Digital Forensics • Incident Response • Security Auditing

*A professional single-file PowerShell toolkit designed for Windows forensic triage, evidence preservation, and incident response.*

---

</div>

> ⚠️ **Legal Notice**
>
> This toolkit is intended **ONLY** for systems that you own or are explicitly authorized to examine.
>
> The script operates in **read-only mode**, making **no modifications** to the target system other than creating its own output directory, log files, evidence package, and optional ZIP archive.

---

# ✨ Features

✅ Read-only forensic collection

✅ No third-party dependencies

✅ Windows built-in cmdlets only

✅ Portable single PowerShell script

✅ Administrator detection

✅ CSV Export

✅ JSON Export

✅ TXT Export

✅ Professional HTML Report

✅ SHA-256 Hash Verification

✅ Chain of Custody Manifest

✅ Timeline Generation

✅ Error-isolated collectors

✅ Offline Compatible

---

# 📦 What the Toolkit Collects

| Category              | Artifacts                                                                                 |
| --------------------- | ----------------------------------------------------------------------------------------- |
| 🖥 System Information | OS, BIOS, Hardware, CPU, Memory, Disk Information, BitLocker, Secure Boot, TPM, Time Zone |
| 👤 User Accounts      | Local Users, User Profiles                                                                |
| 📜 Event Logs         | Security, System, Application summaries, important Event IDs                              |
| 🛡 Security           | Windows Defender, Firewall Profiles                                                       |
| 📦 Installed Software | Registry-based uninstall inventory (64-bit, WOW6432Node, Per-user)                        |
| ⚙ Services            | Service configuration, executable path, service account, startup type                     |
| 🔄 Persistence        | Startup folders, Run Keys, RunOnce Keys, Scheduled Tasks                                  |
| 🔌 USB History        | USBSTOR devices, USB Enumeration                                                          |
| 🚗 Drivers            | Installed Signed Drivers with signer information                                          |
| 🌐 Network            | IP Configuration, DNS Cache, ARP Table, Routes, TCP Connections, Listening Ports          |
| 🩹 Windows Updates    | Installed Hotfixes and Updates                                                            |
| 👣 User Activity      | UserAssist (Decoded), RecentDocs                                                          |
| 📅 Timeline           | Unified chronological forensic timeline                                                   |

---

# 🧠 Why Use This Toolkit?

Unlike many forensic scripts that terminate after a single error,

**every collector is completely isolated.**

```text
Collector
     │
     ├── try
     │      Collect Evidence
     │
     └── catch
            Log Error
            Continue Next Collector
```

One failed artifact **never** stops the remainder of the acquisition.

---

# 📋 Requirements

* Windows PowerShell **5.1**
* Windows 10 / Windows 11
* Windows Server 2016+
* No Internet Required
* No External Modules
* Standard User Supported
* Administrator Recommended

---

# 🚀 Installation

No installation is required.

Simply download the script:

```text
Windows-Forensic-Toolkit.ps1
```

That's it.

---

# ▶ Usage

## Default Collection

```powershell
.\Windows-Forensic-Toolkit.ps1
```

Output is automatically created on the Desktop.

---

## Specify Output Folder

```powershell
.\Windows-Forensic-Toolkit.ps1 `
-OutputPath C:\Evidence\Case-2026-014
```

---

## Increase Event Collection

```powershell
.\Windows-Forensic-Toolkit.ps1 `
-MaxEventLogEntries 1000
```

---

## Disable ZIP Creation

```powershell
.\Windows-Forensic-Toolkit.ps1 `
-SkipZip
```

---

## Full Example

```powershell
.\Windows-Forensic-Toolkit.ps1 `
-OutputPath D:\Evidence `
-MaxEventLogEntries 1000 `
-SkipZip `
-Verbose
```

---

# 🔐 Execution Policy

If PowerShell blocks local scripts:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\Windows-Forensic-Toolkit.ps1
```

No permanent execution policy changes are made.

---

# ⚙ Parameters

| Parameter            | Default                                       | Description                            |
| -------------------- | --------------------------------------------- | -------------------------------------- |
| `OutputPath`         | Desktop\ForensicReport_<Computer>_<Timestamp> | Output folder                          |
| `MaxEventLogEntries` | 500                                           | Events collected per channel (10-5000) |
| `SkipZip`            | False                                         | Skip ZIP archive generation            |

---

# 📁 Output Structure

```text
ForensicReport_<Computer>_<Timestamp>
│
├── CSV
│     SystemInfo.csv
│     Services.csv
│     Software.csv
│     Timeline.csv
│     ...
│
├── JSON
│     ...
│
├── TXT
│     ...
│
├── HTML
│     ForensicReport.html
│
├── Hashes
│     file_hashes.csv
│     file_hashes.json
│
├── collection.log
│
└── manifest.json
```

If ZIP creation is enabled:

```text
ForensicReport_<Timestamp>.zip
```

is created automatically beside the evidence folder.

---

# 📊 Report Formats

Every collected artifact is exported into multiple formats.

| Format | Purpose                           |
| ------ | --------------------------------- |
| CSV    | Excel Analysis                    |
| JSON   | Automation / SIEM Import          |
| TXT    | Human-readable Raw Output         |
| HTML   | Professional Investigation Report |

---

# 🧾 HTML Report

The generated HTML report includes:

* Professional dashboard
* Evidence summary
* Host information
* Security status
* Installed software
* Services
* Persistence
* Network
* Timeline
* User Activity
* Driver Inventory
* USB History
* Event Logs
* Administrator Warning Banner

Open:

```text
HTML\
    ForensicReport.html
```

inside any modern browser.

---

# 📅 Timeline Generation

The toolkit automatically merges artifacts into a single chronological timeline.

Sources include:

* Security Events
* System Events
* Software Install Dates
* UserAssist Last Run
* Scheduled Task Last Run
* Windows Updates

Ideal for answering:

> **"What happened?"**

and

> **"When did it happen?"**

---

# 🔒 Evidence Integrity

Every generated file receives a SHA-256 hash.

```text
SHA-256

CSV Files
JSON Files
TXT Files
HTML Report
Manifest
Logs
```

Verification files:

```text
Hashes/
    file_hashes.csv
    file_hashes.json
```

---

# ⛓ Chain of Custody

The toolkit automatically generates

```text
manifest.json
```

including:

* Hostname
* Username
* Collection Time
* UTC Timestamp
* Tool Version
* File Inventory
* SHA-256 Hashes

allowing later verification that no evidence has been altered.

---

# 🛡 Read-Only Design

The toolkit **does not**:

❌ Modify Registry

❌ Delete Files

❌ Stop Services

❌ Change Event Logs

❌ Disable Security Features

❌ Install Software

The only created artifacts are:

* Output Folder
* Log File
* Report Files
* Optional ZIP Archive

---

# ⚠ Current Limitations

This is a **triage** toolkit.

It **does not** acquire:

* RAM Images
* Full Disk Images
* Browser Databases
* Deleted Files
* MFT Parsing
* Prefetch Parsing
* Registry Hive Extraction
* Volume Shadow Copies

For deeper investigations, combine this toolkit with:

* KAPE
* Memory acquisition tools
* Browser artifact parsers
* Disk imaging solutions

---

# 👨‍💻 Recommended Privileges

| Privilege     | Coverage                                                                   |
| ------------- | -------------------------------------------------------------------------- |
| Standard User | Most collectors                                                            |
| Administrator | Full artifact coverage including Security Log, BitLocker, TPM, Secure Boot |

If the toolkit is not elevated, the HTML report clearly displays a warning banner.

---

# 📈 Workflow

```text
Start

   │

Collect System

   │

Collect Users

   │

Collect Security

   │

Collect Services

   │

Collect Software

   │

Collect Persistence

   │

Collect Network

   │

Collect Drivers

   │

Collect Event Logs

   │

Build Timeline

   │

Export CSV

   │

Export JSON

   │

Export TXT

   │

Generate HTML

   │

Generate SHA-256 Hashes

   │

Generate Manifest

   │

ZIP Evidence

   │

Complete
```

---

# 🎯 Ideal Use Cases

* Incident Response
* Malware Investigation
* Security Audits
* Insider Threat Investigation
* Windows Triage
* SOC Operations
* Blue Team Operations
* DFIR Labs
* Penetration Test Evidence Collection
* Compliance Auditing

---

# 🤝 Contributing

Contributions, feature requests, bug reports, and improvements are welcome.

Feel free to fork the repository and submit a pull request.

---

# ⭐ Support

If this project helps your investigations,

please consider giving the repository a ⭐ on GitHub.

It helps others discover the project.

---

<div align="center">

## 🛡 Windows Forensic Triage & Evidence Collection Toolkit

**Professional • Portable • Read-Only • Offline • Evidence Focused**

Made with ❤️ for DFIR, SOC, Incident Response, and Windows Security Professionals.

</div>
