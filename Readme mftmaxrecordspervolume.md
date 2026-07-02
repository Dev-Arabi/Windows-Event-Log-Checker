# `MftMaxRecordsPerVolume` — Quick Reference

Controls how many `$MFT` records the toolkit parses **per volume** before it stops early.

## Where it lives

Near the top of `Windows-Forensic-Toolkit.ps1`:

```powershell
[int64]$MftMaxRecordsPerVolume = 0
```

## Uncapped (full scan) — default

```powershell
[int64]$MftMaxRecordsPerVolume = 0
```

- `0` means **no limit**.
- Every record on every NTFS volume gets parsed.
- This is what you want for an actual investigation — complete `MFTRecords.csv`/`.json`
  and accurate totals in `MFTSummary.txt`.
- Takes the longest, but no missing data and no `[Unresolved-N]` parent paths
  caused by the cap itself.

## Capped (quick test run)

```powershell
[int64]$MftMaxRecordsPerVolume = 50000
```

- Stops each volume after the first **N** successfully parsed records
  (in raw `$MFT` order — i.e. lowest record numbers first, not most recent
  or most important).
- Good for: confirming the script runs end-to-end (opens the volume,
  reads the boot sector, writes valid CSV/JSON) before committing to a
  long full run.
- Not good for: real evidence collection. Stats in `MFTSummary.txt` will
  reflect only the captured subset, and files whose parent folder falls
  outside the cap will show up as `[Unresolved-N]` instead of a real path.

## How to change it

1. Open `Windows-Forensic-Toolkit.ps1` in a text editor.
2. Find the line near the top:
   ```powershell
   [int64]$MftMaxRecordsPerVolume = 0
   ```
3. Edit the number:
   - `0` → uncapped / full scan
   - Any positive number (e.g. `10000`, `50000`) → capped / quick test
4. Save the file and re-run the script (as Administrator).

No other code changes are needed — this single value controls the cap everywhere it's used.