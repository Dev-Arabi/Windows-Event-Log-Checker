# 📄 MFT Record Collection Configuration

The **`MftMaxRecordsPerVolume`** setting controls **how many `$MFT` records are parsed per NTFS volume** before the toolkit stops processing that volume.

> [!IMPORTANT]
> This setting directly affects **collection time**, **report completeness**, and **overall forensic accuracy**.

---

# 📍 Configuration Location

Open **`Windows-Forensic-Toolkit.ps1`** and locate the following line near the beginning of the script:

```powershell
[int64]$MftMaxRecordsPerVolume = 0
```

---

# ⚙️ Configuration Modes

| Mode | Value | Recommended For |
|------|------:|----------------|
| 🚀 Full Scan | `0` | Real DFIR investigations |
| ⚡ Quick Test | Any positive value | Script testing & debugging |

---

# 🚀 Full Scan (Recommended)

```powershell
[int64]$MftMaxRecordsPerVolume = 0
```

> [!NOTE]
> `0` means **Unlimited** — the toolkit parses **every available `$MFT` record** on every NTFS volume.

### ✅ Advantages

- Complete forensic acquisition
- Full `MFTRecords.csv`
- Full `MFTRecords.json`
- Accurate `MFTSummary.txt`
- Complete parent-child directory reconstruction
- Best evidence quality
- Recommended for real investigations

### ⏱️ Trade-offs

- Longer execution time
- More disk I/O
- Larger output files

---

# ⚡ Quick Test Mode

```powershell
[int64]$MftMaxRecordsPerVolume = 50000
```

> [!TIP]
> Stops processing after the first **N successfully parsed `$MFT` records** on each volume.

Records are parsed in **raw `$MFT` order**, meaning:

- Lowest record numbers first
- **Not** newest files
- **Not** most important files
- **Not** sorted chronologically

### ✅ Ideal For

- Testing the toolkit
- Verifying parser functionality
- Checking CSV/JSON generation
- Development
- Debugging
- Performance benchmarking

### ⚠️ Limitations

- Incomplete evidence collection
- Partial statistics
- `MFTSummary.txt` reflects only the captured subset
- Some directory paths may appear as:

```text
[Unresolved-N]
```

This occurs when the parent directory record exists **outside the configured collection limit**.

---

# 📊 Comparison

| Feature | 🚀 Full Scan (`0`) | ⚡ Quick Test (`50000`) |
|---------|:------------------:|:-----------------------:|
| Complete MFT Collection | ✅ | ❌ |
| Accurate Statistics | ✅ | ❌ |
| Full Directory Paths | ✅ | Partial |
| CSV Output | Complete | Partial |
| JSON Output | Complete | Partial |
| Faster Execution | ❌ | ✅ |
| Recommended for DFIR | ✅ | ❌ |
| Recommended for Development | ⚠️ | ✅ |

---

# 🛠️ How to Change the Value

### 1️⃣ Open the Script

Open:

```text
Windows-Forensic-Toolkit.ps1
```

---

### 2️⃣ Locate the Configuration

Search for:

```powershell
[int64]$MftMaxRecordsPerVolume = 0
```

---

### 3️⃣ Choose Your Desired Value

| Value | Result |
|------:|--------|
| `0` | Unlimited (Full Scan) |
| `10000` | Parse first 10,000 records |
| `50000` | Parse first 50,000 records |
| `100000` | Parse first 100,000 records |
| Any positive integer | Parse the first **N** records |

---

### 4️⃣ Save & Run

Save the script and execute it again **with Administrator privileges**.

```powershell
Set-ExecutionPolicy Bypass -Scope Process

.\Windows-Forensic-Toolkit.ps1
```

---

# 💡 Recommendation

> [!IMPORTANT]
>
> **For production DFIR investigations**, leave the value set to:
>
> ```powershell
> [int64]$MftMaxRecordsPerVolume = 0
> ```
>
> This performs a **complete `$MFT` acquisition** and produces the most accurate forensic results.

---

# 📌 Summary

| Scenario | Recommended Value |
|----------|------------------:|
| Malware Investigation | `0` |
| Digital Forensics | `0` |
| Incident Response | `0` |
| Evidence Collection | `0` |
| Development | `50000` |
| Parser Testing | `10000` |
| Performance Testing | `50000` |

---

> [!TIP]
> **No additional code changes are required.**
>
> `MftMaxRecordsPerVolume` is the **single configuration value** that controls `$MFT` collection limits throughout the toolkit.
