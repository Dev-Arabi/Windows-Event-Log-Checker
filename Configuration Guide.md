# ⚙️ Configuration Guide

The **Windows Forensic Triage & Evidence Collection Toolkit** provides several configurable parameters that allow investigators to control evidence collection, performance, and output.

These parameters are defined near the top of `Windows-Forensic-Toolkit.ps1` inside the `param()` block.

> [!IMPORTANT]
> If you do **not** specify a parameter when running the toolkit, the **default value** will be used automatically.

---

# 📍 Parameter Location

Open:

```text
Windows-Forensic-Toolkit.ps1
```

Locate the configuration block:

```powershell
param(
    ...
)
```

All settings below can either be modified directly in the script or supplied as command-line parameters when launching the toolkit.

---

# ⚙️ Parameter Reference

---

## 📂 OutputPath

```powershell
[string]$OutputPath
```

### Purpose

Specifies where the toolkit stores all collected forensic evidence.

### Default

Creates a timestamped folder on the current user's Desktop.

Example:

```text
Desktop
└── ForensicReport_WORKSTATION_20260702_214530
```

### If Changed

| Value | Result |
|--------|--------|
| Default | Saves evidence to Desktop |
| `D:\Evidence` | Saves evidence to D:\Evidence |
| `E:\Cases\Case01` | Saves into Case01 folder |

> [!TIP]
> Useful for external drives or dedicated evidence storage.

---

## 📜 MaxEventLogEntries

```powershell
[int]$MaxEventLogEntries = 500
```

### Purpose

Limits how many entries are collected from each Windows Event Log.

### If Increased

Example:

```powershell
-MaxEventLogEntries 5000
```

Result:

- Collects more events
- Better historical coverage
- Larger reports
- Longer execution time

### If Decreased

Example:

```powershell
-MaxEventLogEntries 100
```

Result:

- Faster collection
- Smaller reports
- Older events may not be collected

### Recommendation

| Investigation Type | Value |
|--------------------|------:|
| Quick triage | 500 |
| Malware investigation | 2000 |
| Enterprise IR | 5000 |

---

## 📦 SkipZip

```powershell
[switch]$SkipZip
```

### Purpose

Controls whether the toolkit compresses the evidence folder after collection.

### Default

ZIP archive is created.

### If Enabled

```powershell
-SkipZip
```

Result:

- No ZIP archive created
- Evidence remains as folders
- Slightly faster completion

Useful when evidence will immediately be analyzed locally.

---

## 🕒 SuspectedCompromiseTime

```powershell
[Nullable[datetime]]$SuspectedCompromiseTime
```

### Purpose

Allows the investigator to specify the estimated compromise time.

Example:

```powershell
-SuspectedCompromiseTime "2026-07-01 22:15"
```

### Effect

Timeline analysis can prioritize events occurring around the specified time.

---

## ⏰ CompromiseWindowMinutes

```powershell
[int]$CompromiseWindowMinutes = 120
```

### Purpose

Defines the investigation window around the suspected compromise time.

### Example

Compromise Time

```
22:00
```

Window

```
20:00 → 24:00
```

### If Increased

- More surrounding events collected
- Larger timelines

### If Decreased

- Narrower investigation window
- Faster review

---

## 📥 RecentDownloadDays

```powershell
[int]$RecentDownloadDays = 14
```

### Purpose

Collects downloaded files modified within the specified number of days.

### If Increased

Example:

```
60 days
```

Result:

- More downloads collected
- Larger evidence set

### If Decreased

Example:

```
7 days
```

Result:

- Focuses only on recent downloads
- Faster scanning

---

## 🚀 RecentExecutableDays

```powershell
[int]$RecentExecutableDays = 30
```

### Purpose

Searches for recently created or modified executable files.

Examples include:

- EXE
- DLL
- BAT
- CMD
- PS1
- SCR
- VBS

### If Increased

- Finds older executables
- Better historical visibility
- Longer scan

### If Decreased

- Focuses on recent malware activity
- Faster scan

---

## 🔐 MaxFileHashSizeMB

```powershell
[int]$MaxFileHashSizeMB = 100
```

### Purpose

Maximum file size eligible for SHA256 hashing.

### If Increased

Example:

```
500 MB
```

Result:

- More files hashed
- Longer execution time
- Increased CPU usage

### If Decreased

Example:

```
25 MB
```

Result:

- Faster hashing
- Large files skipped

---

## 💾 MftScanDays

```powershell
[int]$MftScanDays = 30
```

### Purpose

Limits `$MFT` analysis to files whose timestamps fall within the specified number of days (if your parser uses this filter).

### If Increased

- Older NTFS activity included
- Longer scan

### If Decreased

- Focuses on recent file activity
- Faster scan

---

## 📄 MftMaxRecordsPerVolume

```powershell
[int64]$MftMaxRecordsPerVolume = 1000
```

### Purpose

Maximum number of `$MFT` records parsed from each NTFS volume.

### Value = 0

Unlimited.

Every record is parsed.

Recommended for:

- Digital Forensics
- Incident Response
- Evidence Collection

### Positive Value

Example:

```powershell
50000
```

Result:

- Stops after first 50,000 records
- Faster execution
- Incomplete MFT collection

### Comparison

| Value | Result |
|-------:|--------|
| 0 | Complete MFT |
| 10000 | Partial |
| 50000 | Partial |
| 100000 | Large partial collection |

> [!IMPORTANT]
> For real forensic investigations, use **0** whenever possible.

---

## 📁 AdsScanMaxDepth

```powershell
[int]$AdsScanMaxDepth = 4
```

### Purpose

Maximum folder depth scanned for Alternate Data Streams (ADS).

### If Increased

- More folders inspected
- Better ADS coverage
- Longer scan

### If Decreased

- Faster execution
- Deep ADS may be missed

---

## 🕵️ TimestompScanDays

```powershell
[int]$TimestompScanDays = 30
```

### Purpose

Limits timestomp detection to files modified within the specified number of days.

### If Increased

- Older timestamp anomalies detected
- Longer scan

### If Decreased

- Focuses on recent activity
- Faster execution

---

# 🚀 Running with Custom Parameters

Example:

```powershell
.\Windows-Forensic-Toolkit.ps1 `
    -OutputPath "D:\Evidence" `
    -MaxEventLogEntries 5000 `
    -RecentExecutableDays 90 `
    -RecentDownloadDays 60 `
    -MaxFileHashSizeMB 250 `
    -MftMaxRecordsPerVolume 0 `
    -SkipZip
```

---

# 📊 Recommended Values

| Parameter | Recommended |
|------------|------------:|
| OutputPath | External Evidence Drive |
| MaxEventLogEntries | 2000–5000 |
| SkipZip | Disabled |
| RecentDownloadDays | 30 |
| RecentExecutableDays | 30 |
| MaxFileHashSizeMB | 100 |
| MftScanDays | 30 |
| MftMaxRecordsPerVolume | **0** |
| AdsScanMaxDepth | 4 |
| TimestompScanDays | 30 |

---

# ⚠️ Notes

- Increasing collection limits generally provides more complete forensic evidence but also increases execution time and output size.
- Decreasing limits improves performance but may omit valuable artifacts.
- Unless you have a specific reason to optimize for speed, the default values are intended to provide a balanced forensic collection.

> [!TIP]
> For **production DFIR investigations**, it is recommended to leave most parameters at their defaults, except for **`MftMaxRecordsPerVolume`**, which should be set to **`0`** to perform a complete `$MFT` acquisition.
