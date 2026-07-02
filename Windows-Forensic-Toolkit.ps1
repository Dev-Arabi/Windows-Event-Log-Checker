#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path -Path ([Environment]::GetFolderPath('Desktop')) `
        -ChildPath ("ForensicReport_{0}_{1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))),

    [Parameter(Mandatory = $false)]
    [ValidateRange(10, 5000)]
    [int]$MaxEventLogEntries = 500,

    [Parameter(Mandatory = $false)]
    [switch]$SkipZip,

    [Parameter(Mandatory = $false)]
    [Nullable[datetime]]$SuspectedCompromiseTime = $null,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1440)]
    [int]$CompromiseWindowMinutes = 120,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$RecentDownloadDays = 14,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$RecentExecutableDays = 30,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10)]
    [int]$MaxFileHashSizeMB = 100,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$MftScanDays = 30,

    [Parameter(Mandatory = $false)]
    [int64]$MftMaxRecordsPerVolume = 1000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10)]
    [int]$AdsScanMaxDepth = 4,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$TimestompScanDays = 30
)

# ---------------------------------------------------------------------------
# Script-scope state
# ---------------------------------------------------------------------------
$Script:ToolVersion  = '1.4.0'
$Script:StartTime    = Get-Date
$Script:ComputerName = $env:COMPUTERNAME
$Script:LogFilePath  = $null
$Script:ReportFiles  = New-Object System.Collections.Generic.List[string]

$ErrorActionPreference = 'Continue'

#====================================================================
# Threat Assessment Indicator Lists
# NOTE: These are heuristic name/keyword matches for investigative
# triage only. A hit is a lead to verify, not proof of compromise.
# A miss is not proof of innocence. Always confirm with signature
# checks, hashes vs. threat intel, and full analyst review.
#====================================================================

# Legitimate remote-access / RMM tools. Presence isn't inherently malicious
# (many are used by IT), but attackers frequently abuse them for persistence
# and C2, so every hit here should be verified against known authorized use.
$Script:RemoteAccessToolNames = @(
    'anydesk', 'teamviewer', 'ultravnc', 'tightvnc', 'realvnc', 'vncserver',
    'screenconnect', 'connectwisecontrol', 'scconnect', 'rustdesk', 'splashtop',
    'logmein', 'gotoassist', 'gotomypc', 'atera', 'ninjarmm', 'ninjaone',
    'action1', 'meshagent', 'dwservice', 'radmin', 'chrome remote desktop',
    'chromoting', 'supremo', 'awesun', 'todesk', 'aeroadmin', 'showmypc',
    'quickassist', 'zoho assist', 'remotepc', 'iperius remote', 'netsupport'
)

# Keywords associated with credential/token/session stealing malware
# families and generic infostealer naming patterns.
$Script:TokenStealerKeywords = @(
    'redline', 'raccoon', 'vidar', 'lumma', 'lummac', 'mars stealer', 'stealc',
    'agenttesla', 'agent tesla', 'formbook', 'rhadamanthys', 'meduza',
    'whitesnake', 'azorult', 'pony stealer', 'kpot', 'arkei', 'oski',
    'aurora stealer', 'blackguard', 'eternity stealer', 'grabber', 'stealer',
    'discord token', 'tokengrabber', 'cookiegrabber'
)

# Keywords/patterns associated with common dual-use or outright malicious
# tooling and living-off-the-land abuse combinations.
$Script:MalwareIndicatorKeywords = @(
    'mimikatz', 'cobaltstrike', 'cobalt strike', 'beacon.dll', 'sliver',
    'metasploit', 'meterpreter', 'psexec', 'procdump', 'nanocore', 'njrat',
    'asyncrat', 'quasarrat', 'remcos', 'darkcomet', 'gh0strat', 'xworm',
    'venomrat', 'bladabindi', 'lsass.dmp', 'lsass_dump'
)

# Command-line fragments that frequently indicate obfuscated/malicious
# execution when seen on process creation or scheduled task actions.
$Script:SuspiciousCommandLinePatterns = @(
    '-enc ', '-encodedcommand', 'frombase64string', 'downloadstring',
    'downloadfile', 'iex(', 'iex (', 'invoke-expression', '-nop -w hidden',
    '-windowstyle hidden', 'bypass -c', 'certutil -decode', 'certutil -urlcache',
    'rundll32.exe javascript:', 'mshta http', 'regsvr32 /s /n /u /i:http'
)

# Dynamic DNS / free-tunnel providers and paste/webhook services commonly
# abused as low-cost, hard-to-block C2 or exfiltration channels.
$Script:SuspiciousDnsProviders = @(
    'duckdns.org', 'no-ip.com', 'no-ip.org', 'ngrok.io', 'ngrok-free.app',
    'dynu.com', 'dyndns.org', 'freedynamicdns.org', 'changeip.com',
    'hopto.org', 'zapto.org', 'sytes.net', 'ddns.net', 'serveo.net',
    'localtunnel.me', 'trycloudflare.com', 'pastebin.com', 'paste.ee',
    'transfer.sh', 'anonfiles.com', 'discord.com/api/webhooks',
    'discordapp.com/api/webhooks', 'telegram.org/bot'
)

# File extensions considered executable/scriptable for the "recently
# downloaded executables" collector.
$Script:ExecutableExtensions = @(
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse',
    '.wsf', '.hta', '.msi', '.msp', '.jar', '.lnk', '.cpl', '.reg'
)

# Focused extension set for the RecentExecutables.csv collector (broader
# location coverage than the download-provenance collector above, but a
# narrower/explicit extension list per that report's intended scope).
$Script:RecentExecutableTargetExtensions = @(
    '.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.msi'
)

# Named NTFS Alternate Data Stream names that are routinely created by
# Windows/Office/IE itself and are NOT, by themselves, evidence of anything.
# Anything outside this list is a *non-default* named stream a user or tool
# deliberately created, and is worth a second look - particularly if its
# name mimics an executable extension or its content starts with an MZ
# (PE executable) header, which are the classic "hide payload in an ADS"
# patterns (T1564.004 - Hide Artifacts: NTFS File Attributes).
$Script:KnownBenignAdsStreamNames = @(
    'Zone.Identifier', 'SummaryInformation', 'DocumentSummaryInformation',
    '{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}', 'encryptable', 'favicon'
)

#====================================================================
# Logging Functions
#====================================================================

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $line = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'WARNING' { Write-Host $line -ForegroundColor Yellow }
        'INFO'    { Write-Host $line -ForegroundColor Cyan }
        'DEBUG'   { Write-Verbose $line }
    }

    if ($Script:LogFilePath) {
        try {
            Add-Content -Path $Script:LogFilePath -Value $line -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-Host "[$timestamp] [ERROR] Unable to write to log file: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

#====================================================================
# Utility Functions
#====================================================================

function Test-IsAdministrator {
    [CmdletBinding()]
    param()
    try {
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Log -Level WARNING -Message "Unable to determine administrative context: $($_.Exception.Message)"
        return $false
    }
}

function Initialize-OutputDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        foreach ($sub in @('CSV', 'JSON', 'TXT', 'HTML', 'Hashes')) {
            $subPath = Join-Path -Path $Path -ChildPath $sub
            if (-not (Test-Path -LiteralPath $subPath)) {
                New-Item -Path $subPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
        }
        return $true
    } catch {
        Write-Host "FATAL: Failed to initialize output directory '$Path': $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function ConvertTo-Rot13 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$InputString
    )
    $chars = $InputString.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $c = $chars[$i]
        if ($c -ge 'a' -and $c -le 'z') {
            $chars[$i] = [char]((([int]$c - [int][char]'a' + 13) % 26) + [int][char]'a')
        } elseif ($c -ge 'A' -and $c -le 'Z') {
            $chars[$i] = [char]((([int]$c - [int][char]'A' + 13) % 26) + [int][char]'A')
        }
    }
    return -join $chars
}

function ConvertFrom-FileTimeBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )
    try {
        if ($Bytes.Length -lt 8) { return $null }
        $fileTime = [BitConverter]::ToInt64($Bytes, 0)
        if ($fileTime -le 0) { return $null }
        return [DateTime]::FromFileTime($fileTime)
    } catch {
        return $null
    }
}

function ConvertFrom-MruBinaryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RawValue
    )
    if ($null -eq $RawValue -or -not ($RawValue -is [byte[]])) { return $null }
    try {
        $nullIndex = -1
        for ($i = 0; $i -lt ($RawValue.Length - 1); $i += 2) {
            if ($RawValue[$i] -eq 0 -and $RawValue[$i + 1] -eq 0) { $nullIndex = $i; break }
        }
        if ($nullIndex -lt 0) { $nullIndex = $RawValue.Length - ($RawValue.Length % 2) }
        if ($nullIndex -le 0) { return $null }
        $text = [System.Text.Encoding]::Unicode.GetString($RawValue, 0, $nullIndex)
        return ($text -replace '[^\x20-\x7E]', '')
    } catch {
        return $null
    }
}

function Get-FileSha256Hash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    try {
        $hash = Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash
    } catch {
        # Files under WindowsApps (MSIX/UWP packages) are ACL-locked to
        # TrustedInstaller + the package SID. PowerShell surfaces this as a
        # plain IOException (not UnauthorizedAccessException), with messages
        # like "cannot be accessed by the system" or "Access to the path is
        # denied". This is expected OS behavior, not a tool failure, so log
        # it at INFO instead of WARNING. Anything else still logs as WARNING.
        $msg = $_.Exception.Message
        if ($msg -match 'cannot be accessed by the system' -or
            $msg -match 'Access to the path .* is denied' -or
            $FilePath -match '\\WindowsApps\\') {
            Write-Log -Level INFO -Message "Skipped protected package file (access restricted by OS ACL): '$FilePath'"
        } else {
            Write-Log -Level WARNING -Message "Unable to hash file '$FilePath': $msg"
        }
        return $null
    }
}

function ConvertTo-SafeFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern = "[{0}]" -f [System.Text.RegularExpressions.Regex]::Escape($invalid)
    return ($Name -replace $pattern, '_')
}

function Get-LocalUserProfilePaths {
    [CmdletBinding()]
    param()
    try {
        return Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
            Where-Object { -not $_.Special -and (Test-Path -LiteralPath $_.LocalPath -ErrorAction SilentlyContinue) } |
            Select-Object -ExpandProperty LocalPath
    } catch {
        Write-Log -Level WARNING -Message "Unable to enumerate user profiles, falling back to C:\Users: $($_.Exception.Message)"
        try {
            return Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction Stop |
                Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } |
                Select-Object -ExpandProperty FullName
        } catch {
            return @()
        }
    }
}

function Test-StringContainsAny {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string[]]$Keywords
    )
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $lowerText = $Text.ToLowerInvariant()
    foreach ($kw in $Keywords) {
        if ([string]::IsNullOrEmpty($kw)) { continue }
        if ($lowerText.Contains($kw.ToLowerInvariant())) { return $kw }
    }
    return $null
}

function Invoke-Collector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock
    )
    Write-Log -Level INFO -Message "Starting collector: $Name"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $ScriptBlock
        $sw.Stop()
        Write-Log -Level INFO -Message "Completed collector: $Name ($([math]::Round($sw.Elapsed.TotalSeconds, 2))s)"
        return $result
    } catch {
        $sw.Stop()
        Write-Log -Level ERROR -Message "Collector '$Name' failed: $($_.Exception.Message)"
        return $null
    }
}

#====================================================================
# System Information
#====================================================================

function Get-SystemInformation {
    [CmdletBinding()]
    param()

    $info = [ordered]@{
        OperatingSystem = $null
        BIOS            = $null
        ComputerSystem  = $null
        Processor       = $null
        MemoryModules   = $null
        Disks           = $null
        LogicalDisks    = $null
        BitLocker       = $null
        SecureBoot      = $null
        TPM             = $null
        TimeZone        = $null
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $info.OperatingSystem = [PSCustomObject]@{
            ComputerName          = $os.CSName
            Caption               = $os.Caption
            Version               = $os.Version
            BuildNumber           = $os.BuildNumber
            Architecture          = $os.OSArchitecture
            InstallDate           = $os.InstallDate
            LastBootUpTime        = $os.LastBootUpTime
            SystemDrive           = $os.SystemDrive
            WindowsDirectory      = $os.WindowsDirectory
            SerialNumber          = $os.SerialNumber
            RegisteredUser        = $os.RegisteredUser
            TotalVisibleMemoryMB  = [math]::Round($os.TotalVisibleMemorySize / 1KB, 2)
            FreePhysicalMemoryMB  = [math]::Round($os.FreePhysicalMemory / 1KB, 2)
        }
    } catch {
        Write-Log -Level WARNING -Message "OS info collection failed: $($_.Exception.Message)"
    }

    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $info.BIOS = [PSCustomObject]@{
            Manufacturer = $bios.Manufacturer
            Name         = $bios.Name
            SerialNumber = $bios.SerialNumber
            Version      = $bios.SMBIOSBIOSVersion
            ReleaseDate  = $bios.ReleaseDate
        }
    } catch {
        Write-Log -Level WARNING -Message "BIOS info collection failed: $($_.Exception.Message)"
    }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $info.ComputerSystem = [PSCustomObject]@{
            Manufacturer              = $cs.Manufacturer
            Model                     = $cs.Model
            SystemFamily              = $cs.SystemFamily
            Domain                    = $cs.Domain
            PartOfDomain              = $cs.PartOfDomain
            DomainRole                = $cs.DomainRole
            TotalPhysicalMemoryGB     = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            NumberOfProcessors        = $cs.NumberOfProcessors
            NumberOfLogicalProcessors = $cs.NumberOfLogicalProcessors
        }
    } catch {
        Write-Log -Level WARNING -Message "ComputerSystem info collection failed: $($_.Exception.Message)"
    }

    try {
        $info.Processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Name                      = $_.Name
                Manufacturer              = $_.Manufacturer
                NumberOfCores             = $_.NumberOfCores
                NumberOfLogicalProcessors = $_.NumberOfLogicalProcessors
                MaxClockSpeedMHz          = $_.MaxClockSpeed
                L2CacheSizeKB             = $_.L2CacheSize
                L3CacheSizeKB             = $_.L3CacheSize
                ProcessorId               = $_.ProcessorId
            }
        }
    } catch {
        Write-Log -Level WARNING -Message "Processor info collection failed: $($_.Exception.Message)"
    }

    try {
        $info.MemoryModules = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                BankLabel     = $_.BankLabel
                DeviceLocator = $_.DeviceLocator
                Manufacturer  = $_.Manufacturer
                CapacityGB    = [math]::Round($_.Capacity / 1GB, 2)
                SpeedMHz      = $_.Speed
                SerialNumber  = ($_.SerialNumber -as [string])
                PartNumber    = ($_.PartNumber -as [string])
            }
        }
    } catch {
        Write-Log -Level WARNING -Message "Memory module info collection failed: $($_.Exception.Message)"
    }

    try {
        $info.Disks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Model         = $_.Model
                InterfaceType = $_.InterfaceType
                MediaType     = $_.MediaType
                SizeGB        = [math]::Round($_.Size / 1GB, 2)
                SerialNumber  = ($_.SerialNumber -as [string])
                Partitions    = $_.Partitions
                Status        = $_.Status
            }
        }
    } catch {
        Write-Log -Level WARNING -Message "Disk info collection failed: $($_.Exception.Message)"
    }

    try {
        $info.LogicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                DeviceID    = $_.DeviceID
                VolumeName  = $_.VolumeName
                FileSystem  = $_.FileSystem
                SizeGB      = [math]::Round($_.Size / 1GB, 2)
                FreeSpaceGB = [math]::Round($_.FreeSpace / 1GB, 2)
            }
        }
    } catch {
        Write-Log -Level WARNING -Message "Logical disk info collection failed: $($_.Exception.Message)"
    }

    try {
        $blCommand = Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($blCommand) {
            $info.BitLocker = Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    MountPoint           = $_.MountPoint
                    VolumeStatus         = $_.VolumeStatus
                    ProtectionStatus     = $_.ProtectionStatus
                    EncryptionMethod     = $_.EncryptionMethod
                    EncryptionPercentage = $_.EncryptionPercentage
                }
            }
        } else {
            Write-Log -Level DEBUG -Message "BitLocker module not available on this system."
        }
    } catch {
        Write-Log -Level WARNING -Message "BitLocker status collection failed: $($_.Exception.Message)"
    }

    try {
        $sbCommand = Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($sbCommand) {
            $status = Confirm-SecureBootUEFI -ErrorAction Stop
            $info.SecureBoot = [PSCustomObject]@{ SecureBootEnabled = $status }
        } else {
            Write-Log -Level DEBUG -Message "Confirm-SecureBootUEFI not available on this system."
        }
    } catch {
        $info.SecureBoot = [PSCustomObject]@{ SecureBootEnabled = 'Unavailable (Legacy BIOS or access denied)' }
        Write-Log -Level WARNING -Message "Secure Boot status collection failed: $($_.Exception.Message)"
    }

    try {
        $tpmCommand = Get-Command -Name Get-Tpm -ErrorAction SilentlyContinue
        if ($tpmCommand) {
            $tpm = Get-Tpm -ErrorAction Stop
            $info.TPM = [PSCustomObject]@{
                TpmPresent          = $tpm.TpmPresent
                TpmReady             = $tpm.TpmReady
                TpmEnabled          = $tpm.TpmEnabled
                TpmActivated        = $tpm.TpmActivated
                ManufacturerVersion = $tpm.ManufacturerVersion
            }
        } else {
            Write-Log -Level DEBUG -Message "Get-Tpm cmdlet not available on this system."
        }
    } catch {
        Write-Log -Level WARNING -Message "TPM status collection failed: $($_.Exception.Message)"
    }

    try {
        $tz = Get-CimInstance -ClassName Win32_TimeZone -ErrorAction Stop
        $info.TimeZone = [PSCustomObject]@{
            Caption = $tz.Caption
            Bias    = $tz.Bias
        }
    } catch {
        Write-Log -Level WARNING -Message "Time zone collection failed: $($_.Exception.Message)"
    }

    return [PSCustomObject]$info
}

#====================================================================
# User Accounts
#====================================================================

function Get-UserInformation {
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        LocalUsers   = $null
        UserProfiles = $null
    }

    try {
        $cmd = Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue
        if ($cmd) {
            $result.LocalUsers = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, Description,
                LastLogon, PasswordRequired, PasswordExpires, SID, PrincipalSource
        } else {
            $adsiUsers = ([ADSI]"WinNT://$env:COMPUTERNAME").Children | Where-Object { $_.SchemaClassName -eq 'User' }
            $result.LocalUsers = $adsiUsers | ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Name.ToString()
                    Enabled     = -not [bool]([int]$_.UserFlags.Value -band 2)
                    Description = $_.Description.ToString()
                    SID         = (New-Object System.Security.Principal.SecurityIdentifier($_.objectSid.Value, 0)).Value
                }
            }
        }
    } catch {
        Write-Log -Level WARNING -Message "Local user enumeration failed: $($_.Exception.Message)"
    }

    try {
        $result.UserProfiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                LocalPath   = $_.LocalPath
                SID         = $_.SID
                Loaded      = $_.Loaded
                Special     = $_.Special
                LastUseTime = $_.LastUseTime
            }
        }
    } catch {
        Write-Log -Level WARNING -Message "User profile enumeration failed: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

#====================================================================
# Event Logs
#====================================================================

function Get-EventLogs {
    [CmdletBinding()]
    param(
        [int]$MaxEntries = 500
    )

    $result = [ordered]@{
        SecuritySummary        = $null
        SystemSummary           = $null
        ApplicationSummary      = $null
        NotableSecurityEvents   = $null
        NotableSystemEvents     = $null
    }

    foreach ($log in @('Security', 'System', 'Application')) {
        try {
            $events = Get-WinEvent -LogName $log -MaxEvents $MaxEntries -ErrorAction Stop | Select-Object TimeCreated, Id,
                LevelDisplayName, ProviderName,
                @{Name = 'Message'; Expression = {
                    $m = $_.Message
                    if ([string]::IsNullOrEmpty($m)) { '' } else { ($m -replace '\s+', ' ').Substring(0, [Math]::Min(300, $m.Length)) }
                }}
            switch ($log) {
                'Security'    { $result.SecuritySummary = $events }
                'System'      { $result.SystemSummary = $events }
                'Application' { $result.ApplicationSummary = $events }
            }
        } catch {
            Write-Log -Level WARNING -Message "Unable to read '$log' event log (may require elevation): $($_.Exception.Message)"
        }
    }

    try {
        $notableSecurityIds = 4624, 4625, 4634, 4648, 4672, 4688, 4720, 4722, 4724, 4728, 4732, 4756, 4776, 1102
        $result.NotableSecurityEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $notableSecurityIds } -MaxEvents $MaxEntries -ErrorAction Stop |
            Select-Object TimeCreated, Id,
                @{Name = 'EventType'; Expression = {
                    switch ($_.Id) {
                        4624 { 'Successful Logon' }
                        4625 { 'Failed Logon' }
                        4634 { 'Logoff' }
                        4648 { 'Explicit Credential Logon' }
                        4672 { 'Special Privileges Assigned' }
                        4688 { 'Process Creation' }
                        4720 { 'User Account Created' }
                        4722 { 'User Account Enabled' }
                        4724 { 'Password Reset Attempt' }
                        4728 { 'Member Added to Global Group' }
                        4732 { 'Member Added to Local Group' }
                        4756 { 'Member Added to Universal Group' }
                        4776 { 'Credential Validation' }
                        1102 { 'Audit Log Cleared' }
                        default { 'Other' }
                    }
                }},
                @{Name = 'Message'; Expression = {
                    $m = $_.Message
                    if ([string]::IsNullOrEmpty($m)) { '' } else { ($m -replace '\s+', ' ').Substring(0, [Math]::Min(300, $m.Length)) }
                }}
    } catch {
        Write-Log -Level WARNING -Message "Unable to filter notable Security events (may require elevated privileges): $($_.Exception.Message)"
    }

    try {
        $notableSystemIds = 7045, 7036, 1074, 6005, 6006, 6008, 104
        $result.NotableSystemEvents = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = $notableSystemIds } -MaxEvents $MaxEntries -ErrorAction Stop |
            Select-Object TimeCreated, Id,
                @{Name = 'EventType'; Expression = {
                    switch ($_.Id) {
                        7045 { 'Service Installed' }
                        7036 { 'Service State Change' }
                        1074 { 'System Shutdown/Restart Initiated' }
                        6005 { 'Event Log Service Started (Boot)' }
                        6006 { 'Event Log Service Stopped (Shutdown)' }
                        6008 { 'Unexpected Shutdown' }
                        104  { 'Event Log Cleared' }
                        default { 'Other' }
                    }
                }},
                ProviderName,
                @{Name = 'Message'; Expression = {
                    $m = $_.Message
                    if ([string]::IsNullOrEmpty($m)) { '' } else { ($m -replace '\s+', ' ').Substring(0, [Math]::Min(300, $m.Length)) }
                }}
    } catch {
        Write-Log -Level WARNING -Message "Unable to filter notable System events: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

#====================================================================
# Security Status (Windows Defender / Firewall)
#====================================================================

function Get-SecurityStatus {
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        Defender = $null
        Firewall = $null
    }

    try {
        $cmd = Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($cmd) {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $result.Defender = [PSCustomObject]@{
                AMServiceEnabled              = $mp.AMServiceEnabled
                AntispywareEnabled            = $mp.AntispywareEnabled
                AntivirusEnabled              = $mp.AntivirusEnabled
                RealTimeProtectionEnabled     = $mp.RealTimeProtectionEnabled
                BehaviorMonitorEnabled        = $mp.BehaviorMonitorEnabled
                AntivirusSignatureLastUpdated = $mp.AntivirusSignatureLastUpdated
                QuickScanAge                  = $mp.QuickScanAge
                FullScanAge                   = $mp.FullScanAge
                ComputerState                 = $mp.ComputerState
            }
        } else {
            Write-Log -Level DEBUG -Message "Get-MpComputerStatus not available (Defender module absent)."
        }
    } catch {
        Write-Log -Level WARNING -Message "Windows Defender status collection failed: $($_.Exception.Message)"
    }

    try {
        $cmd2 = Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue
        if ($cmd2) {
            $result.Firewall = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled,
                DefaultInboundAction, DefaultOutboundAction, LogFileName, LogAllowed, LogBlocked
        } else {
            Write-Log -Level DEBUG -Message "Get-NetFirewallProfile not available on this system."
        }
    } catch {
        Write-Log -Level WARNING -Message "Firewall status collection failed: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

#====================================================================
# Installed Software
#====================================================================

function Get-InstalledSoftware {
    [CmdletBinding()]
    param()

    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $software = New-Object System.Collections.Generic.List[object]

    foreach ($path in $paths) {
        try {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
                $software.Add([PSCustomObject]@{
                    DisplayName     = $_.DisplayName
                    DisplayVersion  = $_.DisplayVersion
                    Publisher       = $_.Publisher
                    InstallDate     = $_.InstallDate
                    InstallLocation = $_.InstallLocation
                    RegistryPath    = $_.PSPath
                })
            }
        } catch {
            Write-Log -Level WARNING -Message "Failed to read installed software from '$path': $($_.Exception.Message)"
        }
    }

    return ($software | Sort-Object DisplayName -Unique)
}

#====================================================================
# Services
#====================================================================

function Get-Services {
    [CmdletBinding()]
    param()
    try {
        return Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Select-Object Name, DisplayName,
            State, StartMode, StartName, PathName, ServiceType
    } catch {
        Write-Log -Level WARNING -Message "Service enumeration failed: $($_.Exception.Message)"
        return $null
    }
}

#====================================================================
# Startup Items / Registry Run Keys
#====================================================================

function Get-StartupItems {
    [CmdletBinding()]
    param()

    $items = New-Object System.Collections.Generic.List[object]

    try {
        $startupCmd = Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop
        foreach ($s in $startupCmd) {
            $items.Add([PSCustomObject]@{
                Name     = $s.Name
                Command  = $s.Command
                Location = $s.Location
                User     = $s.User
            })
        }
    } catch {
        Write-Log -Level WARNING -Message "Win32_StartupCommand enumeration failed: $($_.Exception.Message)"
    }

    return $items
}

function Get-RegistryRunKeys {
    [CmdletBinding()]
    param()

    $runKeyPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    $entries = New-Object System.Collections.Generic.List[object]

    foreach ($path in $runKeyPaths) {
        try {
            if (Test-Path -Path $path) {
                $props = Get-ItemProperty -Path $path -ErrorAction Stop
                $props.PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider)$' } |
                    ForEach-Object {
                        $entries.Add([PSCustomObject]@{
                            RegistryKey = $path
                            ValueName   = $_.Name
                            ValueData   = $_.Value
                        })
                    }
            }
        } catch {
            Write-Log -Level WARNING -Message "Failed to read run key '$path': $($_.Exception.Message)"
        }
    }

    return $entries
}

#====================================================================
# Scheduled Tasks
#====================================================================

function Get-ScheduledTasksInfo {
    [CmdletBinding()]
    param()
    try {
        return Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $taskInfo = $null
            try {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction Stop
            } catch {
                Write-Log -Level DEBUG -Message "Could not retrieve run-time info for task '$($_.TaskName)'."
            }
            [PSCustomObject]@{
                TaskName       = $_.TaskName
                TaskPath       = $_.TaskPath
                State          = $_.State
                Author         = $_.Author
                Description    = $_.Description
                LastRunTime    = $taskInfo.LastRunTime
                NextRunTime    = $taskInfo.NextRunTime
                LastTaskResult = $taskInfo.LastTaskResult
                Actions        = (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ')
            }
        }
    } catch {
        Write-Log -Level WARNING -Message "Scheduled task enumeration failed: $($_.Exception.Message)"
        return $null
    }
}

#====================================================================
# USB Device History
#====================================================================

function Get-USBHistory {
    [CmdletBinding()]
    param()

    $devices = New-Object System.Collections.Generic.List[object]

    try {
        $usbStorPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        if (Test-Path -Path $usbStorPath) {
            Get-ChildItem -Path $usbStorPath -ErrorAction Stop | ForEach-Object {
                $deviceClassKeyPath = $_.PSPath
                $deviceClassName    = $_.PSChildName
                Get-ChildItem -Path $deviceClassKeyPath -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $instanceProps = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
                        $devices.Add([PSCustomObject]@{
                            Source            = 'USBSTOR'
                            DeviceDescription = $instanceProps.FriendlyName
                            DeviceClass       = $deviceClassName
                            SerialNumber      = $_.PSChildName
                            Manufacturer      = $instanceProps.Mfg
                            HardwareID        = ($instanceProps.HardwareID -join '; ')
                        })
                    } catch {
                        Write-Log -Level DEBUG -Message "Skipping unreadable USBSTOR instance: $($_.Exception.Message)"
                    }
                }
            }
        }
    } catch {
        Write-Log -Level WARNING -Message "USB history (USBSTOR) enumeration failed: $($_.Exception.Message)"
    }

    try {
        $usbPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB'
        if (Test-Path -Path $usbPath) {
            Get-ChildItem -Path $usbPath -ErrorAction Stop | ForEach-Object {
                $vidPidKeyPath = $_.PSPath
                $vidPidName    = $_.PSChildName
                Get-ChildItem -Path $vidPidKeyPath -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $instanceProps = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
                        $description = if ($instanceProps.FriendlyName) { $instanceProps.FriendlyName } else { $instanceProps.DeviceDesc }
                        if ($description) {
                            $devices.Add([PSCustomObject]@{
                                Source            = 'USB'
                                DeviceDescription = $description
                                DeviceClass       = $vidPidName
                                SerialNumber      = $_.PSChildName
                                Manufacturer      = $instanceProps.Mfg
                                HardwareID        = ($instanceProps.HardwareID -join '; ')
                            })
                        }
                    } catch {
                        Write-Log -Level DEBUG -Message "Skipping unreadable USB instance: $($_.Exception.Message)"
                    }
                }
            }
        }
    } catch {
        Write-Log -Level WARNING -Message "USB history (USB) enumeration failed: $($_.Exception.Message)"
    }

    return ($devices | Sort-Object SerialNumber -Unique)
}

#====================================================================
# Drivers
#====================================================================

function Get-DriverInformation {
    [CmdletBinding()]
    param()
    try {
        return Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop | Select-Object DeviceName,
            DriverVersion, Manufacturer, DriverDate, IsSigned, Signer, InfName | Sort-Object DeviceName
    } catch {
        Write-Log -Level WARNING -Message "Driver enumeration failed: $($_.Exception.Message)"
        return $null
    }
}

#====================================================================
# Network Information
#====================================================================

function Get-NetworkInformation {
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        Adapters        = $null
        IPConfiguration = $null
        DnsCache        = $null
        ArpTable        = $null
        RoutingTable    = $null
        OpenConnections = $null
        ListeningPorts  = $null
    }

    try {
        $result.Adapters = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "PhysicalAdapter=True" -ErrorAction Stop |
            Select-Object Name, NetConnectionID, MACAddress, Speed, NetEnabled, AdapterType
    } catch {
        Write-Log -Level WARNING -Message "Network adapter enumeration failed: $($_.Exception.Message)"
    }

    try {
        $cmd = Get-Command -Name Get-NetIPConfiguration -ErrorAction SilentlyContinue
        if ($cmd) {
            $result.IPConfiguration = Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    InterfaceAlias     = $_.InterfaceAlias
                    IPv4Address        = ($_.IPv4Address.IPAddress -join ', ')
                    IPv6Address        = ($_.IPv6Address.IPAddress -join ', ')
                    DNSServer          = ($_.DNSServer.ServerAddresses -join ', ')
                    IPv4DefaultGateway = ($_.IPv4DefaultGateway.NextHop -join ', ')
                }
            }
        }
    } catch {
        Write-Log -Level WARNING -Message "IP configuration collection failed: $($_.Exception.Message)"
    }

    try {
        $cmd2 = Get-Command -Name Get-DnsClientCache -ErrorAction SilentlyContinue
        if ($cmd2) {
            $result.DnsCache = Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, Name, Data, Type, TimeToLive, Status
        }
    } catch {
        Write-Log -Level WARNING -Message "DNS cache collection failed: $($_.Exception.Message)"
    }

    try {
        $cmd3 = Get-Command -Name Get-NetNeighbor -ErrorAction SilentlyContinue
        if ($cmd3) {
            $result.ArpTable = Get-NetNeighbor -ErrorAction Stop | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias
        }
    } catch {
        Write-Log -Level WARNING -Message "ARP table collection failed: $($_.Exception.Message)"
    }

    try {
        $cmd4 = Get-Command -Name Get-NetRoute -ErrorAction SilentlyContinue
        if ($cmd4) {
            $result.RoutingTable = Get-NetRoute -ErrorAction Stop | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias, Protocol
        }
    } catch {
        Write-Log -Level WARNING -Message "Routing table collection failed: $($_.Exception.Message)"
    }

    try {
        $cmd5 = Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue
        if ($cmd5) {
            $connections = Get-NetTCPConnection -ErrorAction Stop
            $result.OpenConnections = $connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
                @{Name = 'ProcessName'; Expression = {
                    try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { 'Unknown' }
                }}
            $result.ListeningPorts = $connections | Where-Object { $_.State -eq 'Listen' } |
                Select-Object LocalAddress, LocalPort, OwningProcess
        }
    } catch {
        Write-Log -Level WARNING -Message "TCP connection enumeration failed: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

#====================================================================
# Installed Updates
#====================================================================

function Get-InstalledUpdates {
    [CmdletBinding()]
    param()
    try {
        return Get-HotFix -ErrorAction Stop | Select-Object HotFixID, Description, InstalledBy, InstalledOn |
            Sort-Object InstalledOn -Descending
    } catch {
        Write-Log -Level WARNING -Message "Installed update enumeration failed: $($_.Exception.Message)"
        return $null
    }
}

#====================================================================
# User Activity Artifacts (UserAssist / RecentDocs)
#====================================================================

function Get-UserAssistArtifacts {
    [CmdletBinding()]
    param()

    $entries  = New-Object System.Collections.Generic.List[object]
    $basePath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'

    try {
        if (Test-Path -Path $basePath) {
            Get-ChildItem -Path $basePath -ErrorAction Stop | ForEach-Object {
                $guidKeyPath = $_.PSPath
                $guidName    = $_.PSChildName
                $countPath   = Join-Path -Path $guidKeyPath -ChildPath 'Count'
                if (Test-Path -Path $countPath) {
                    try {
                        $key = Get-Item -Path $countPath -ErrorAction Stop
                        foreach ($valueName in $key.GetValueNames()) {
                            if ([string]::IsNullOrEmpty($valueName)) { continue }
                            $decodedName = ConvertTo-Rot13 -InputString $valueName
                            $rawData     = $key.GetValue($valueName)
                            $runCount    = $null
                            $lastRun     = $null
                            if ($rawData -is [byte[]] -and $rawData.Length -ge 68) {
                                try {
                                    $runCount = [BitConverter]::ToInt32($rawData, 4)
                                    $lastRun  = ConvertFrom-FileTimeBytes -Bytes $rawData[60..67]
                                } catch {
                                    Write-Log -Level DEBUG -Message "Could not parse UserAssist binary payload for '$decodedName'."
                                }
                            }
                            $entries.Add([PSCustomObject]@{
                                GUID         = $guidName
                                DecodedPath  = $decodedName
                                RunCount     = $runCount
                                LastExecuted = $lastRun
                            })
                        }
                    } catch {
                        Write-Log -Level DEBUG -Message "Skipping unreadable UserAssist subkey: $($_.Exception.Message)"
                    }
                }
            }
        } else {
            Write-Log -Level DEBUG -Message "UserAssist registry path not found for current user context."
        }
    } catch {
        Write-Log -Level WARNING -Message "UserAssist artifact collection failed: $($_.Exception.Message)"
    }

    return $entries
}

function Get-RecentDocsArtifacts {
    [CmdletBinding()]
    param()

    $entries  = New-Object System.Collections.Generic.List[object]
    $basePath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'

    try {
        if (Test-Path -Path $basePath) {
            try {
                $rootKey = Get-Item -Path $basePath -ErrorAction Stop
                foreach ($valueName in $rootKey.GetValueNames()) {
                    if ($valueName -eq 'MRUListEx' -or [string]::IsNullOrEmpty($valueName)) { continue }
                    $decoded = ConvertFrom-MruBinaryValue -RawValue $rootKey.GetValue($valueName)
                    if ($decoded) {
                        $entries.Add([PSCustomObject]@{
                            Category  = '(root)'
                            EntryName = $valueName
                            FileName  = $decoded
                        })
                    }
                }
            } catch {
                Write-Log -Level DEBUG -Message "Skipping unreadable RecentDocs root key: $($_.Exception.Message)"
            }

            Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue | ForEach-Object {
                $extKeyPath = $_.PSPath
                $extName    = $_.PSChildName
                try {
                    $props = Get-Item -Path $extKeyPath -ErrorAction Stop
                    foreach ($valueName in $props.GetValueNames()) {
                        if ($valueName -eq 'MRUListEx' -or [string]::IsNullOrEmpty($valueName)) { continue }
                        $decoded = ConvertFrom-MruBinaryValue -RawValue $props.GetValue($valueName)
                        if ($decoded) {
                            $entries.Add([PSCustomObject]@{
                                Category  = $extName
                                EntryName = $valueName
                                FileName  = $decoded
                            })
                        }
                    }
                } catch {
                    Write-Log -Level DEBUG -Message "Skipping unreadable RecentDocs subkey '$extName': $($_.Exception.Message)"
                }
            }
        } else {
            Write-Log -Level DEBUG -Message "RecentDocs registry path not found for current user context."
        }
    } catch {
        Write-Log -Level WARNING -Message "RecentDocs artifact collection failed: $($_.Exception.Message)"
    }

    return $entries
}

#====================================================================
# Browser Artifacts (Extensions / Saved-Password Indicators / Downloads)
#====================================================================

function Get-BrowserArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$DownloadLookbackDays = 14
    )

    $extensions   = New-Object System.Collections.Generic.List[object]
    $pwIndicators = New-Object System.Collections.Generic.List[object]
    $downloads    = New-Object System.Collections.Generic.List[object]

    # Chromium-family browsers keep a consistent "User Data\<Profile>" layout.
    $chromiumBrowsers = @(
        @{ Name = 'Chrome';    RelPath = 'AppData\Local\Google\Chrome\User Data' },
        @{ Name = 'Edge';      RelPath = 'AppData\Local\Microsoft\Edge\User Data' },
        @{ Name = 'Brave';     RelPath = 'AppData\Local\BraveSoftware\Brave-Browser\User Data' },
        @{ Name = 'Opera';     RelPath = 'AppData\Roaming\Opera Software\Opera Stable' },
        @{ Name = 'Vivaldi';   RelPath = 'AppData\Local\Vivaldi\User Data' }
    )

    $userProfiles = Get-LocalUserProfilePaths

    foreach ($profilePath in $userProfiles) {
        $userName = Split-Path -Path $profilePath -Leaf

        foreach ($browser in $chromiumBrowsers) {
            $userDataPath = Join-Path -Path $profilePath -ChildPath $browser.RelPath
            if (-not (Test-Path -LiteralPath $userDataPath)) { continue }

            $profileDirs = @('Default') + @(
                Get-ChildItem -Path $userDataPath -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^Profile \d+$' } | Select-Object -ExpandProperty Name
            )

            foreach ($profileDir in ($profileDirs | Select-Object -Unique)) {
                $profileFullPath = Join-Path -Path $userDataPath -ChildPath $profileDir
                if (-not (Test-Path -LiteralPath $profileFullPath)) { continue }

                # --- Extensions ---
                $extRoot = Join-Path -Path $profileFullPath -ChildPath 'Extensions'
                if (Test-Path -LiteralPath $extRoot) {
                    try {
                        Get-ChildItem -Path $extRoot -Directory -ErrorAction Stop | ForEach-Object {
                            $extId = $_.Name
                            $versionDir = Get-ChildItem -Path $_.FullName -Directory -ErrorAction SilentlyContinue |
                                Sort-Object LastWriteTime -Descending | Select-Object -First 1
                            if ($versionDir) {
                                $manifestPath = Join-Path -Path $versionDir.FullName -ChildPath 'manifest.json'
                                if (Test-Path -LiteralPath $manifestPath) {
                                    try {
                                        $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                                        $extName = $manifest.name
                                        if ($extName -match '^__MSG_') { $extName = "$extName (localized)" }
                                        $perms = @()
                                        if ($manifest.permissions) { $perms += $manifest.permissions }
                                        if ($manifest.host_permissions) { $perms += $manifest.host_permissions }
                                        $extensions.Add([PSCustomObject]@{
                                            User            = $userName
                                            Browser         = $browser.Name
                                            Profile         = $profileDir
                                            ExtensionId     = $extId
                                            Name            = $extName
                                            Version         = $manifest.version
                                            Permissions     = ($perms -join '; ')
                                            HighRiskPerms   = ((Test-StringContainsAny -Text ($perms -join ' ') -Keywords @('<all_urls>','webRequest','cookies','clipboardWrite','clipboardRead','debugger','proxy')) -ne $null)
                                            InstalledPath   = $versionDir.FullName
                                            LastModified    = $versionDir.LastWriteTime
                                        })
                                    } catch {
                                        Write-Log -Level DEBUG -Message "Could not parse extension manifest '$manifestPath': $($_.Exception.Message)"
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Log -Level DEBUG -Message "Extension enumeration failed for '$extRoot': $($_.Exception.Message)"
                    }
                }

                # --- Saved-password indicator (existence/metadata only; never decrypted) ---
                $loginDataPath = Join-Path -Path $profileFullPath -ChildPath 'Login Data'
                if (Test-Path -LiteralPath $loginDataPath) {
                    try {
                        $fi = Get-Item -LiteralPath $loginDataPath -ErrorAction Stop
                        $pwIndicators.Add([PSCustomObject]@{
                            User          = $userName
                            Browser       = $browser.Name
                            Profile       = $profileDir
                            ArtifactType  = 'Chromium Login Data (encrypted)'
                            FilePath      = $fi.FullName
                            SizeBytes     = $fi.Length
                            LastModified  = $fi.LastWriteTime
                            Note          = 'Presence + recent modification suggests saved credentials exist. Values are DPAPI-encrypted and are NOT extracted by this tool.'
                        })
                    } catch {
                        Write-Log -Level DEBUG -Message "Could not stat Login Data at '$loginDataPath': $($_.Exception.Message)"
                    }
                }

                # --- Download history (heuristic string extraction; no SQLite driver assumed) ---
                $historyPath = Join-Path -Path $profileFullPath -ChildPath 'History'
                if (Test-Path -LiteralPath $historyPath) {
                    try {
                        $tempCopy = Join-Path -Path $env:TEMP -ChildPath "wft_hist_$([guid]::NewGuid().ToString('N')).db"
                        Copy-Item -LiteralPath $historyPath -Destination $tempCopy -ErrorAction Stop
                        $bytes = [System.IO.File]::ReadAllBytes($tempCopy)
                        $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
                        $urlMatches = [regex]::Matches($text, 'https?://[^\s"''<>\x00-\x1f]{5,300}')
                        $seen = New-Object System.Collections.Generic.HashSet[string]
                        foreach ($m in $urlMatches) {
                            $u = $m.Value
                            if ($seen.Add($u)) {
                                $downloads.Add([PSCustomObject]@{
                                    User       = $userName
                                    Browser    = $browser.Name
                                    Profile    = $profileDir
                                    SourceFile = 'History (raw string scan)'
                                    Url        = $u
                                })
                            }
                        }
                        Remove-Item -LiteralPath $tempCopy -Force -ErrorAction SilentlyContinue
                    } catch {
                        Write-Log -Level DEBUG -Message "Could not extract URLs from '$historyPath' (likely locked): $($_.Exception.Message)"
                    }
                }
            }
        }

        # --- Firefox (different structure: profiles.ini + extensions.json + logins.json) ---
        $ffProfilesRoot = Join-Path -Path $profilePath -ChildPath 'AppData\Roaming\Mozilla\Firefox\Profiles'
        if (Test-Path -LiteralPath $ffProfilesRoot) {
            Get-ChildItem -Path $ffProfilesRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $ffProfile = $_.FullName
                $ffProfileName = $_.Name

                $extJsonPath = Join-Path -Path $ffProfile -ChildPath 'extensions.json'
                if (Test-Path -LiteralPath $extJsonPath) {
                    try {
                        $extJson = Get-Content -LiteralPath $extJsonPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                        foreach ($addon in $extJson.addons) {
                            if (-not $addon.id) { continue }
                            $extensions.Add([PSCustomObject]@{
                                User            = $userName
                                Browser         = 'Firefox'
                                Profile         = $ffProfileName
                                ExtensionId     = $addon.id
                                Name            = $addon.defaultLocale.name
                                Version         = $addon.version
                                Permissions     = (($addon.userPermissions.permissions) -join '; ')
                                HighRiskPerms   = ((Test-StringContainsAny -Text (($addon.userPermissions.permissions) -join ' ') -Keywords @('<all_urls>','webRequest','cookies','clipboardWrite')) -ne $null)
                                InstalledPath   = $ffProfile
                                LastModified    = $addon.updateDate
                            })
                        }
                    } catch {
                        Write-Log -Level DEBUG -Message "Could not parse Firefox extensions.json: $($_.Exception.Message)"
                    }
                }

                foreach ($credFile in @('logins.json', 'key4.db')) {
                    $credPath = Join-Path -Path $ffProfile -ChildPath $credFile
                    if (Test-Path -LiteralPath $credPath) {
                        try {
                            $fi = Get-Item -LiteralPath $credPath -ErrorAction Stop
                            $pwIndicators.Add([PSCustomObject]@{
                                User          = $userName
                                Browser       = 'Firefox'
                                Profile       = $ffProfileName
                                ArtifactType  = "Firefox $credFile (encrypted)"
                                FilePath      = $fi.FullName
                                SizeBytes     = $fi.Length
                                LastModified  = $fi.LastWriteTime
                                Note          = 'Presence suggests saved credentials exist. Values are NOT extracted by this tool.'
                            })
                        } catch {
                            Write-Log -Level DEBUG -Message "Could not stat '$credPath': $($_.Exception.Message)"
                        }
                    }
                }

                $ffPlacesPath = Join-Path -Path $ffProfile -ChildPath 'places.sqlite'
                if (Test-Path -LiteralPath $ffPlacesPath) {
                    try {
                        $tempCopy = Join-Path -Path $env:TEMP -ChildPath "wft_ffhist_$([guid]::NewGuid().ToString('N')).db"
                        Copy-Item -LiteralPath $ffPlacesPath -Destination $tempCopy -ErrorAction Stop
                        $bytes = [System.IO.File]::ReadAllBytes($tempCopy)
                        $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
                        $urlMatches = [regex]::Matches($text, 'https?://[^\s"''<>\x00-\x1f]{5,300}')
                        $seen = New-Object System.Collections.Generic.HashSet[string]
                        foreach ($m in $urlMatches) {
                            $u = $m.Value
                            if ($seen.Add($u)) {
                                $downloads.Add([PSCustomObject]@{
                                    User       = $userName
                                    Browser    = 'Firefox'
                                    Profile    = $ffProfileName
                                    SourceFile = 'places.sqlite (raw string scan)'
                                    Url        = $u
                                })
                            }
                        }
                        Remove-Item -LiteralPath $tempCopy -Force -ErrorAction SilentlyContinue
                    } catch {
                        Write-Log -Level DEBUG -Message "Could not extract URLs from '$ffPlacesPath': $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    return [PSCustomObject]@{
        Extensions              = $extensions
        SavedPasswordIndicators = $pwIndicators
        BrowserUrlHistorySample = $downloads
    }
}

#====================================================================
# Prefetch / Recently Executed Programs
#====================================================================

function Get-PrefetchArtifacts {
    [CmdletBinding()]
    param()

    $entries = New-Object System.Collections.Generic.List[object]
    $prefetchPath = Join-Path -Path $env:WINDIR -ChildPath 'Prefetch'

    try {
        if (-not (Test-Path -LiteralPath $prefetchPath)) {
            Write-Log -Level DEBUG -Message "Prefetch folder not found (may be disabled on SSD/server systems)."
            return $entries
        }
        Get-ChildItem -Path $prefetchPath -Filter '*.pf' -ErrorAction Stop | ForEach-Object {
            $baseName = $_.BaseName
            $exeName  = $baseName
            $hashPart = $null
            if ($baseName -match '^(?<exe>.+)-(?<hash>[0-9A-Fa-f]{8})$') {
                $exeName  = $Matches['exe']
                $hashPart = $Matches['hash']
            }
            $entries.Add([PSCustomObject]@{
                PrefetchFile  = $_.Name
                ExecutableName = $exeName
                HashSuffix    = $hashPart
                Created       = $_.CreationTime
                LastExecuted  = $_.LastWriteTime
                LastAccessed  = $_.LastAccessTime
                SizeBytes     = $_.Length
                Note          = 'LastExecuted reflects file LastWriteTime; precise embedded run-count/timestamps require a dedicated .pf parser.'
            })
        }
    } catch {
        Write-Log -Level WARNING -Message "Prefetch enumeration failed (often requires Administrator): $($_.Exception.Message)"
    }

    return ($entries | Sort-Object LastExecuted -Descending)
}

function Get-RecentlyExecutedPrograms {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [array]$UserAssistData,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [array]$PrefetchData
    )

    $combined = New-Object System.Collections.Generic.List[object]

    if ($UserAssistData) {
        foreach ($u in $UserAssistData) {
            $combined.Add([PSCustomObject]@{
                Source       = 'UserAssist (Registry)'
                Program      = $u.DecodedPath
                RunCount     = $u.RunCount
                LastExecuted = $u.LastExecuted
            })
        }
    }

    if ($PrefetchData) {
        foreach ($p in $PrefetchData) {
            $combined.Add([PSCustomObject]@{
                Source       = 'Prefetch'
                Program      = $p.ExecutableName
                RunCount     = $null
                LastExecuted = $p.LastExecuted
            })
        }
    }

    return ($combined | Where-Object { $_.LastExecuted } | Sort-Object LastExecuted -Descending)
}

#====================================================================
# DNS Query History
#====================================================================

function Get-DnsQueryHistory {
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        ResolverCache      = $null
        OperationalLogQueries = $null
    }

    try {
        $cmd = Get-Command -Name Get-DnsClientCache -ErrorAction SilentlyContinue
        if ($cmd) {
            $result.ResolverCache = Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, Name, Data, Type, TimeToLive, Status
        }
    } catch {
        Write-Log -Level WARNING -Message "DNS resolver cache collection failed: $($_.Exception.Message)"
    }

    try {
        # Requires the "Microsoft-Windows-DNS-Client/Operational" analytic log to be enabled.
        # (wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true, run as Administrator)
        $logCheck = Get-WinEvent -ListLog 'Microsoft-Windows-DNS-Client/Operational' -ErrorAction Stop
        if ($logCheck.IsEnabled -or $logCheck.RecordCount -gt 0) {
            $result.OperationalLogQueries = Get-WinEvent -LogName 'Microsoft-Windows-DNS-Client/Operational' -MaxEvents 2000 -ErrorAction Stop |
                Where-Object { $_.Id -eq 3008 } |
                Select-Object TimeCreated,
                    @{Name='QueryName'; Expression = { $_.Properties[1].Value }},
                    @{Name='QueryResults'; Expression = { ($_.Properties[3].Value -as [string]) }}
        } else {
            Write-Log -Level DEBUG -Message "DNS-Client Operational log exists but is not enabled; enable with: wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true"
        }
    } catch {
        Write-Log -Level DEBUG -Message "DNS-Client Operational log unavailable or not enabled: $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

#====================================================================
# Recently Downloaded Executables
#====================================================================

function Get-RecentDownloadedExecutables {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$LookbackDays = 14
    )

    $results = New-Object System.Collections.Generic.List[object]
    $cutoff  = (Get-Date).AddDays(-1 * $LookbackDays)
    $userProfiles = Get-LocalUserProfilePaths

    $scanFolders = New-Object System.Collections.Generic.List[string]
    foreach ($profilePath in $userProfiles) {
        foreach ($sub in @('Downloads', 'Desktop', 'AppData\Local\Temp', 'AppData\Roaming')) {
            $p = Join-Path -Path $profilePath -ChildPath $sub
            if (Test-Path -LiteralPath $p) { $scanFolders.Add($p) }
        }
    }

    foreach ($folder in $scanFolders) {
        try {
            Get-ChildItem -Path $folder -File -Recurse -Depth 2 -ErrorAction SilentlyContinue -Force |
                Where-Object { $Script:ExecutableExtensions -contains $_.Extension.ToLowerInvariant() -and $_.CreationTime -ge $cutoff } |
                ForEach-Object {
                    $signature = $null
                    try {
                        $sig = Get-AuthenticodeSignature -LiteralPath $_.FullName -ErrorAction Stop
                        $signature = $sig.Status
                    } catch { $signature = 'Unknown' }

                    $hash = $null
                    if ($_.Length -le ($MaxFileHashSizeMB * 1MB)) {
                        $hash = Get-FileSha256Hash -FilePath $_.FullName
                    }

                    $results.Add([PSCustomObject]@{
                        FileName          = $_.Name
                        FullPath          = $_.FullName
                        Extension         = $_.Extension
                        SizeBytes         = $_.Length
                        Created           = $_.CreationTime
                        LastModified      = $_.LastWriteTime
                        SignatureStatus   = $signature
                        SHA256            = $hash
                        ZoneIdentifier    = (Get-Content -LiteralPath "$($_.FullName):Zone.Identifier" -ErrorAction SilentlyContinue) -join ' | '
                    })
                }
        } catch {
            Write-Log -Level DEBUG -Message "Recent-executable scan failed for '$folder': $($_.Exception.Message)"
        }
    }

    return ($results | Sort-Object Created -Descending)
}

function Get-RecentExecutables {
    # Broader, extension-focused "recently created executable" inventory.
    # Unlike Get-RecentDownloadedExecutables above (scoped narrowly to
    # Downloads/Desktop/Temp/Roaming for download-provenance triage - Zone
    # Identifier, etc.), this collector casts a wider net: user-profile
    # locations (including Startup folders), common system drop folders
    # (Windows\Temp, ProgramData and its Startup folder), and a shallow pass
    # over the root of every fixed drive - to catch executables/scripts
    # dropped somewhere other than the usual download folders. Matches are
    # based on file extension (.exe, .dll, .ps1, .bat, .cmd, .vbs, .js, .msi)
    # and CreationTime/LastWriteTime falling inside the lookback window.
    # A hit here is a lead to verify, not proof of anything - legitimate
    # installers and updates create files here too.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$LookbackDays = 30
    )

    $results   = New-Object System.Collections.Generic.List[object]
    $seenPaths = New-Object System.Collections.Generic.HashSet[string]
    $cutoff    = (Get-Date).AddDays(-1 * $LookbackDays)

    $scanFolders = New-Object System.Collections.Generic.List[string]

    foreach ($profilePath in (Get-LocalUserProfilePaths)) {
        foreach ($sub in @(
            'Downloads', 'Desktop', 'Documents', 'AppData\Local\Temp',
            'AppData\Roaming', 'AppData\Local',
            'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        )) {
            $p = Join-Path -Path $profilePath -ChildPath $sub
            if (Test-Path -LiteralPath $p) { $scanFolders.Add($p) }
        }
    }

    $sysTemp        = Join-Path -Path $env:SystemRoot -ChildPath 'Temp'
    $programDataDir = $env:ProgramData
    $sysStartup     = if ($programDataDir) { Join-Path -Path $programDataDir -ChildPath 'Microsoft\Windows\Start Menu\Programs\StartUp' } else { $null }
    foreach ($sysFolder in @($sysTemp, $programDataDir, $sysStartup)) {
        if ($sysFolder -and (Test-Path -LiteralPath $sysFolder)) { $scanFolders.Add($sysFolder) }
    }

    # Shallow pass over the root of every fixed drive - catches executables
    # dropped directly at C:\, D:\, etc. rather than in a typical user/app folder.
    try {
        $fixedDrives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop
        foreach ($d in $fixedDrives) {
            if ($d.DeviceID) { $scanFolders.Add("$($d.DeviceID)\") }
        }
    } catch {
        Write-Log -Level DEBUG -Message "Unable to enumerate fixed drives for recent-executable root scan: $($_.Exception.Message)"
    }

    foreach ($folder in $scanFolders) {
        $isDriveRoot = ($folder -match '^[A-Za-z]:\\$')
        $depth = if ($isDriveRoot) { 1 } else { 3 }
        try {
            Get-ChildItem -Path $folder -File -Recurse -Depth $depth -ErrorAction SilentlyContinue -Force |
                Where-Object {
                    $Script:RecentExecutableTargetExtensions -contains $_.Extension.ToLowerInvariant() -and
                    ($_.CreationTime -ge $cutoff -or $_.LastWriteTime -ge $cutoff)
                } |
                ForEach-Object {
                    if (-not $seenPaths.Add($_.FullName.ToLowerInvariant())) { return }

                    $signature = 'Unknown'
                    try {
                        $sig = Get-AuthenticodeSignature -LiteralPath $_.FullName -ErrorAction Stop
                        $signature = $sig.Status
                    } catch { }

                    $hash = $null
                    if ($_.Length -le ($MaxFileHashSizeMB * 1MB)) {
                        $hash = Get-FileSha256Hash -FilePath $_.FullName
                    }

                    $zoneId = $null
                    try {
                        $zoneId = (Get-Content -LiteralPath "$($_.FullName):Zone.Identifier" -ErrorAction SilentlyContinue) -join ' | '
                    } catch { }

                    $results.Add([PSCustomObject]@{
                        FileName        = $_.Name
                        FullPath        = $_.FullName
                        Extension       = $_.Extension.ToLowerInvariant()
                        SizeBytes       = $_.Length
                        Created         = $_.CreationTime
                        LastModified    = $_.LastWriteTime
                        SignatureStatus = $signature
                        SHA256          = $hash
                        ZoneIdentifier  = $zoneId
                        SourceFolder    = $folder
                    })
                }
        } catch {
            Write-Log -Level DEBUG -Message "Recent-executable scan failed for '$folder': $($_.Exception.Message)"
        }
    }

    return ($results | Sort-Object Created -Descending)
}

function Get-SuspiciousPathExecutables {
    # Inventories executables/scripts sitting in locations that are commonly
    # abused for staging, persistence, or execution because they're
    # user-writable and rarely reviewed: per-user Temp, ProgramData, the
    # Downloads/Desktop folders, the Recycle Bin, the shared Public profile,
    # and Startup folders (user + all-users). A hit here is a lead to
    # verify, not proof of anything - installers and legitimate tools
    # routinely drop files in Temp/ProgramData too - but executables in
    # these spots deserve a second look, especially if unsigned or recently
    # created.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 4
    )

    $results   = New-Object System.Collections.Generic.List[object]
    $seenPaths = New-Object System.Collections.Generic.HashSet[string]

    # Category -> folder path. Order matters: if a file is reachable via more
    # than one entry (shouldn't normally happen given the specific folders
    # below, but is possible with unusual profile layouts), the first
    # category listed wins for the seenPaths de-dupe.
    $categoryFolders = New-Object System.Collections.Generic.List[object]

    foreach ($profilePath in (Get-LocalUserProfilePaths)) {
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Temp (AppData)';       Path = (Join-Path $profilePath 'AppData\Local\Temp') })
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Downloads';            Path = (Join-Path $profilePath 'Downloads') })
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Desktop';              Path = (Join-Path $profilePath 'Desktop') })
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Startup (User)';       Path = (Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') })
    }

    if ($env:SystemRoot) {
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Temp (System)'; Path = (Join-Path $env:SystemRoot 'Temp') })
    }
    if ($env:ProgramData) {
        $categoryFolders.Add([PSCustomObject]@{ Category = 'ProgramData';          Path = $env:ProgramData })
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Startup (All Users)';  Path = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp') })
    }
    if ($env:PUBLIC) {
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Public'; Path = $env:PUBLIC })
    }

    # Recycle Bin exists per-volume, not just on the system drive.
    try {
        $fixedDrives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop
        foreach ($d in $fixedDrives) {
            if ($d.DeviceID) {
                $categoryFolders.Add([PSCustomObject]@{ Category = 'Recycle Bin'; Path = (Join-Path "$($d.DeviceID)\" '$Recycle.Bin') })
            }
        }
    } catch {
        Write-Log -Level DEBUG -Message "Unable to enumerate fixed drives for Recycle Bin scan: $($_.Exception.Message)"
    }

    foreach ($entry in $categoryFolders) {
        $folder = $entry.Path
        if (-not $folder -or -not (Test-Path -LiteralPath $folder -ErrorAction SilentlyContinue)) { continue }

        try {
            Get-ChildItem -LiteralPath $folder -File -Recurse -Depth $MaxDepth -Force -ErrorAction SilentlyContinue |
                Where-Object { $Script:ExecutableExtensions -contains $_.Extension.ToLowerInvariant() } |
                ForEach-Object {
                    $key = $_.FullName.ToLowerInvariant()
                    if (-not $seenPaths.Add($key)) { return }

                    $signature = 'Unknown'
                    try {
                        $sig = Get-AuthenticodeSignature -LiteralPath $_.FullName -ErrorAction Stop
                        $signature = $sig.Status
                    } catch { }

                    $hash = $null
                    if ($_.Length -le ($MaxFileHashSizeMB * 1MB)) {
                        $hash = Get-FileSha256Hash -FilePath $_.FullName
                    }

                    $zoneId = $null
                    try {
                        $zoneId = (Get-Content -LiteralPath "$($_.FullName):Zone.Identifier" -ErrorAction SilentlyContinue) -join ' | '
                    } catch { }

                    $results.Add([PSCustomObject]@{
                        SuspiciousLocation = $entry.Category
                        FileName           = $_.Name
                        FullPath           = $_.FullName
                        Extension          = $_.Extension.ToLowerInvariant()
                        SizeBytes          = $_.Length
                        Created            = $_.CreationTime
                        LastModified       = $_.LastWriteTime
                        SignatureStatus    = $signature
                        SHA256             = $hash
                        ZoneIdentifier     = $zoneId
                    })
                }
        } catch {
            Write-Log -Level DEBUG -Message "Suspicious-path scan failed for '$folder' (category: $($entry.Category)): $($_.Exception.Message)"
        }
    }

    return ($results | Sort-Object SuspiciousLocation, Created -Descending)
}

#====================================================================
# NTFS Alternate Data Streams (ADS)
#
# NTFS lets any file carry additional named data streams beyond its
# default, unnamed ":$DATA" stream (e.g. "file.txt:secret.exe"). Explorer,
# `dir`, and most tools never show them, which makes ADS a long-standing
# technique for hiding payloads, staging tool output, or smuggling data
# past casual review. The most common LEGITIMATE stream is
# "Zone.Identifier" (Mark-of-the-Web, added by browsers/Outlook/Explorer
# when a file is downloaded). This collector enumerates every non-default
# stream on files under commonly-abused, user-writable locations, flags
# streams outside the known-benign set, and does a lightweight MZ
# (PE executable) header check plus a small text preview on each hit.
# A hit here is a lead to verify, not proof of concealment - some AV/
# indexing tools also write their own named streams.
#====================================================================

function Get-AlternateDataStreams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = $AdsScanMaxDepth,

        [Parameter(Mandatory = $false)]
        [int]$MaxPreviewBytes = 256
    )

    $results   = New-Object System.Collections.Generic.List[object]
    $seenPaths = New-Object System.Collections.Generic.HashSet[string]

    # Same "user-writable, rarely reviewed" scope used for the suspicious-path
    # executable inventory, but here we don't filter by extension - ADS can be
    # attached to a file of any type (.txt, .jpg, .docx, etc.), so restricting
    # to executable extensions would miss the technique entirely.
    $categoryFolders = New-Object System.Collections.Generic.List[object]

    foreach ($profilePath in (Get-LocalUserProfilePaths)) {
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Temp (AppData)';  Path = (Join-Path $profilePath 'AppData\Local\Temp') })
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Downloads';       Path = (Join-Path $profilePath 'Downloads') })
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Desktop';         Path = (Join-Path $profilePath 'Desktop') })
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Documents';       Path = (Join-Path $profilePath 'Documents') })
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Startup (User)';  Path = (Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') })
    }

    if ($env:SystemRoot) {
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Temp (System)'; Path = (Join-Path $env:SystemRoot 'Temp') })
    }
    if ($env:ProgramData) {
        $categoryFolders.Add([PSCustomObject]@{ Category = 'ProgramData';         Path = $env:ProgramData })
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Startup (All Users)'; Path = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp') })
    }
    if ($env:PUBLIC) {
        $categoryFolders.Add([PSCustomObject]@{ Category = 'Public'; Path = $env:PUBLIC })
    }

    # Recycle Bin exists per-volume, not just on the system drive, and is a
    # common place to find ADS-tagged files that were "deleted" but not purged.
    try {
        $fixedDrives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop
        foreach ($d in $fixedDrives) {
            if ($d.DeviceID) {
                $categoryFolders.Add([PSCustomObject]@{ Category = 'Recycle Bin'; Path = (Join-Path "$($d.DeviceID)\" '$Recycle.Bin') })
            }
        }
    } catch {
        Write-Log -Level DEBUG -Message "Unable to enumerate fixed drives for ADS Recycle Bin scan: $($_.Exception.Message)"
    }

    foreach ($entry in $categoryFolders) {
        $folder = $entry.Path
        if (-not $folder -or -not (Test-Path -LiteralPath $folder -ErrorAction SilentlyContinue)) { continue }

        try {
            Get-ChildItem -LiteralPath $folder -File -Recurse -Depth $MaxDepth -Force -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $file = $_
                    $key  = $file.FullName.ToLowerInvariant()
                    if (-not $seenPaths.Add($key)) { return }

                    $streams = $null
                    try {
                        $streams = Get-Item -LiteralPath $file.FullName -Stream * -ErrorAction Stop |
                            Where-Object { $_.Stream -ne ':$DATA' }
                    } catch {
                        return
                    }
                    if (-not $streams) { return }

                    foreach ($stream in $streams) {
                        $streamName  = $stream.Stream
                        $isKnownSafe = $Script:KnownBenignAdsStreamNames -contains $streamName
                        $adsPath     = "$($file.FullName):$streamName"

                        $looksExecutable = $false
                        try {
                            $headerBytes = Get-Content -LiteralPath $adsPath -Encoding Byte -TotalCount 2 -ErrorAction Stop
                            if ($headerBytes -and $headerBytes.Count -ge 2 -and $headerBytes[0] -eq 0x4D -and $headerBytes[1] -eq 0x5A) {
                                $looksExecutable = $true
                            }
                        } catch { }

                        $preview = $null
                        if (-not $looksExecutable -and $stream.Length -gt 0 -and $stream.Length -le $MaxPreviewBytes) {
                            try {
                                $raw = Get-Content -LiteralPath $adsPath -Raw -ErrorAction Stop
                                if ($raw) {
                                    $clean   = ($raw -replace '[\r\n\t]', ' ').Trim()
                                    $preview = if ($clean.Length -gt $MaxPreviewBytes) { $clean.Substring(0, $MaxPreviewBytes) + '...' } else { $clean }
                                }
                            } catch { }
                        }

                        $severity = 'Informational'
                        $reasons  = New-Object System.Collections.Generic.List[string]

                        if ($streamName -ieq 'Zone.Identifier') {
                            $reasons.Add('Mark-of-the-Web stream - expected on files downloaded via browser/email/Explorer')
                        } elseif ($isKnownSafe) {
                            $reasons.Add('Recognized system/Office metadata stream name')
                        } else {
                            $reasons.Add('Non-default, non-standard named stream')
                            $severity = 'Yellow'
                        }

                        if ($looksExecutable) {
                            $reasons.Add('Stream content begins with an MZ header (PE executable) - payload hidden in an ADS')
                            $severity = 'Red'
                        }

                        if (-not $isKnownSafe -and $Script:ExecutableExtensions -contains ".$($streamName.ToLowerInvariant())") {
                            $reasons.Add('Stream name mimics an executable file extension')
                            if ($severity -ne 'Red') { $severity = 'Yellow' }
                        }

                        $results.Add([PSCustomObject]@{
                            HostFileName    = $file.Name
                            HostFullPath    = $file.FullName
                            SourceCategory  = $entry.Category
                            StreamName      = $streamName
                            StreamSizeBytes = $stream.Length
                            IsKnownBenign   = $isKnownSafe
                            LooksExecutable = $looksExecutable
                            Severity        = $severity
                            Reasons         = ($reasons -join ' | ')
                            ContentPreview  = $preview
                            HostCreated     = $file.CreationTime
                            HostModified    = $file.LastWriteTime
                        })
                    }
                }
        } catch {
            Write-Log -Level DEBUG -Message "ADS scan failed for '$folder' (category: $($entry.Category)): $($_.Exception.Message)"
        }
    }

    return ($results | Sort-Object Severity, HostModified -Descending)
}

#====================================================================
# MFT / NTFS Metadata & Timestamp Anomaly Detection
#
# NOTE: This is a live-response, no-external-tools approach. It does NOT
# parse the raw $MFT file record attributes ($STANDARD_INFORMATION vs
# $FILE_NAME) - that requires a dedicated MFT parser (e.g. MFTECmd,
# analyzeMFT) run against a raw/forensic image or a copy of C:\$MFT
# pulled via raw disk access. What this DOES provide, using only
# built-in Windows tooling:
#   1. Per-volume $MFT metadata (size, record count, fragmentation) via
#      fsutil, useful for triage/sizing before a full MFT parse.
#   2. A heuristic scan of $STANDARD_INFORMATION timestamps (the ones
#      exposed by Get-Item/Get-ChildItem) for patterns commonly left by
#      timestomping tools and other anti-forensic timestamp tampering.
# A hit here is a lead to verify with a proper MFT parser, not proof of
# tampering - several of these patterns also occur during ordinary file
# copies, extractions, and installs.
#====================================================================

function Get-NtfsMftVolumeInfo {
    [CmdletBinding()]
    param()

    $results = New-Object System.Collections.Generic.List[object]

    try {
        $volumes = Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop |
            Where-Object { $_.FileSystem -eq 'NTFS' -and $_.DriveLetter }
    } catch {
        Write-Log -Level WARNING -Message "Unable to enumerate NTFS volumes for MFT info: $($_.Exception.Message)"
        return $results
    }

    foreach ($vol in $volumes) {
        $drive = $vol.DriveLetter
        try {
            $raw = & fsutil fsinfo ntfsinfo $drive 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Log -Level DEBUG -Message "fsutil fsinfo ntfsinfo failed for $drive (often requires Administrator): $($raw -join ' ')"
                continue
            }

            # fsutil emits simple "Label : Value" lines - parse into a flat object rather
            # than hard-coding field names, since exact wording/fields vary across OS builds.
            $info = [ordered]@{ Volume = $drive }
            foreach ($line in $raw) {
                if ($line -match '^\s*([^:]+?)\s*:\s*(.+)$') {
                    $key = ($Matches[1] -replace '[^A-Za-z0-9]', '')
                    if ($key) { $info[$key] = $Matches[2].Trim() }
                }
            }
            $results.Add([PSCustomObject]$info)
        } catch {
            Write-Log -Level WARNING -Message "MFT volume info collection failed for '$drive': $($_.Exception.Message)"
        }
    }

    return $results
}

function Get-MftTimestampAnomalies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$LookbackDays = 30
    )

    $results = New-Object System.Collections.Generic.List[object]
    $cutoff  = (Get-Date).AddDays(-1 * $LookbackDays)
    $now     = Get-Date

    $osInstallDate = $null
    try {
        $osInstallDate = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).InstallDate
    } catch {
        Write-Log -Level DEBUG -Message "Unable to determine OS install date for MFT anomaly baseline: $($_.Exception.Message)"
    }

    # Locations most commonly used for persistence/staging and therefore most
    # worth the scan cost. Mirrors the folder set used for recently-downloaded
    # executables, plus Startup folders and Scheduled Tasks storage.
    $scanFolders = New-Object System.Collections.Generic.List[string]
    foreach ($profilePath in (Get-LocalUserProfilePaths)) {
        foreach ($sub in @('Downloads', 'Desktop', 'AppData\Local\Temp', 'AppData\Roaming',
                            'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')) {
            $p = Join-Path -Path $profilePath -ChildPath $sub
            if (Test-Path -LiteralPath $p) { $scanFolders.Add($p) }
        }
    }
    foreach ($p in @(
        (Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path -Path $env:WINDIR -ChildPath 'Temp'),
        (Join-Path -Path $env:WINDIR -ChildPath 'System32\Tasks')
    )) {
        if (Test-Path -LiteralPath $p) { $scanFolders.Add($p) }
    }

    foreach ($folder in $scanFolders) {
        try {
            Get-ChildItem -Path $folder -File -Recurse -Depth 3 -ErrorAction SilentlyContinue -Force |
                Where-Object { $_.LastWriteTime -ge $cutoff -or $_.CreationTime -ge $cutoff } |
                ForEach-Object {
                    $reasons  = New-Object System.Collections.Generic.List[string]
                    $severity = 'Yellow'

                    # A future-dated timestamp cannot occur naturally and is a strong
                    # indicator of clock tampering or a forged FILETIME value.
                    if ($_.CreationTime -gt $now.AddMinutes(5) -or $_.LastWriteTime -gt $now.AddMinutes(5)) {
                        $reasons.Add('Creation or LastWrite timestamp is in the future relative to system clock')
                        $severity = 'Red'
                    }

                    # Common SetFileTime()-based timestomping tools write whole-second/whole-minute
                    # FILETIME values, whereas genuine NTFS-generated timestamps carry 100ns-resolution
                    # sub-second precision. Exact :00.000 on Creation is a soft signal, not proof.
                    if ($_.CreationTime.Second -eq 0 -and $_.CreationTime.Millisecond -eq 0) {
                        $reasons.Add('CreationTime is truncated to an exact minute boundary (0s/0ms) - a common SetFileTime/timestomping artifact')
                    }

                    # Creation newer than LastWrite is routinely normal for legitimately copied/installed
                    # files (Windows assigns a new CreationTime on copy but preserves the original
                    # LastWriteTime). Included as a low-weight, informational-only signal.
                    if ($_.CreationTime -gt $_.LastWriteTime.AddSeconds(1)) {
                        $reasons.Add('CreationTime is newer than LastWriteTime - normal for copied/installed files, but worth correlating with other signals')
                    }

                    if ($osInstallDate -and $_.CreationTime -lt $osInstallDate.AddDays(-1)) {
                        $reasons.Add('CreationTime predates the OS installation date on this machine')
                    }

                    if ($reasons.Count -gt 0) {
                        $isExecutable = $Script:ExecutableExtensions -contains $_.Extension.ToLowerInvariant()
                        if ($isExecutable -and $severity -ne 'Red') { $severity = 'Yellow' }
                        if (-not $isExecutable -and $severity -ne 'Red') { $severity = 'Informational' }

                        $results.Add([PSCustomObject]@{
                            FileName      = $_.Name
                            FullPath      = $_.FullName
                            Extension     = $_.Extension
                            IsExecutable  = $isExecutable
                            Created       = $_.CreationTime
                            LastModified  = $_.LastWriteTime
                            LastAccessed  = $_.LastAccessTime
                            Severity      = $severity
                            Anomalies     = ($reasons -join ' | ')
                            Note          = 'Heuristic $STANDARD_INFORMATION anomaly only. Confirm against $FILE_NAME attribute timestamps with a dedicated MFT parser (e.g. MFTECmd) before treating as confirmed timestomping.'
                        })
                    }
                }
        } catch {
            Write-Log -Level DEBUG -Message "MFT timestamp anomaly scan failed for '$folder': $($_.Exception.Message)"
        }
    }

    return ($results | Sort-Object Severity, Created -Descending)
}

#====================================================================
# Dedicated Timestomping Indicators (TimestompIndicators.csv)
#
# Purpose-built, three-category classifier layered on top of the same
# $STANDARD_INFORMATION timestamps exposed by Get-Item/Get-ChildItem
# (Created / LastModified / LastAccessed). Unlike Get-MftTimestampAnomalies
# above (a general heuristic sweep), this collector buckets every hit into
# exactly one of the categories an analyst asks for by name:
#   1. CreationAfterModification - CreationTime postdates LastWriteTime.
#      Normal for legitimately copied/installed files (Windows stamps a
#      fresh CreationTime on copy but preserves LastWriteTime), but also
#      the single most common side effect of timestomping tools that only
#      overwrite LastWriteTime/LastAccessTime and forget CreationTime -
#      so it's flagged for correlation rather than ignored.
#   2. ImpossibleTimestamp - timestamp values that cannot occur under
#      normal filesystem operation: any of the three timestamps in the
#      future relative to the system clock, LastAccessTime predating
#      CreationTime (accessed before it existed), or CreationTime
#      predating a sane filesystem-epoch floor (raw/corrupted FILETIME).
#   3. PotentialTimestomping - softer pattern-based signals consistent
#      with SetFileTime()-style anti-forensic tooling: all three
#      timestamps truncated to an exact whole-second/whole-minute
#      boundary, all three timestamps being byte-for-byte identical
#      (genuine files almost always drift by at least fractions of a
#      second across create/write/access), or CreationTime predating the
#      OS install date on this machine.
# A hit is a lead to verify against a proper MFT parser's $FILE_NAME
# attribute (e.g. MFTECmd) before treating as confirmed tampering - none
# of these signals is proof on its own.
#====================================================================

function Get-TimestompIndicators {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$LookbackDays = $TimestompScanDays
    )

    $results = New-Object System.Collections.Generic.List[object]
    $cutoff  = (Get-Date).AddDays(-1 * $LookbackDays)
    $now     = Get-Date
    # Small allowance for normal clock/timezone/NTP drift before a
    # "future" timestamp is treated as impossible rather than noise.
    $futureTolerance  = New-TimeSpan -Minutes 5
    $epochSanityFloor = Get-Date -Year 1990 -Month 1 -Day 1

    $osInstallDate = $null
    try {
        $osInstallDate = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).InstallDate
    } catch {
        Write-Log -Level DEBUG -Message "Unable to determine OS install date for timestomp baseline: $($_.Exception.Message)"
    }

    $scanFolders = New-Object System.Collections.Generic.List[string]
    foreach ($profilePath in (Get-LocalUserProfilePaths)) {
        foreach ($sub in @('Downloads', 'Desktop', 'Documents', 'AppData\Local\Temp', 'AppData\Roaming',
                            'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')) {
            $p = Join-Path -Path $profilePath -ChildPath $sub
            if (Test-Path -LiteralPath $p) { $scanFolders.Add($p) }
        }
    }
    foreach ($p in @(
        (Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path -Path $env:WINDIR -ChildPath 'Temp'),
        (Join-Path -Path $env:WINDIR -ChildPath 'System32\Tasks')
    )) {
        if (Test-Path -LiteralPath $p) { $scanFolders.Add($p) }
    }

    foreach ($folder in $scanFolders) {
        try {
            Get-ChildItem -Path $folder -File -Recurse -Depth 3 -ErrorAction SilentlyContinue -Force |
                Where-Object { $_.LastWriteTime -ge $cutoff -or $_.CreationTime -ge $cutoff } |
                ForEach-Object {
                    $created  = $_.CreationTime
                    $modified = $_.LastWriteTime
                    $accessed = $_.LastAccessTime

                    $indicatorTypes = New-Object System.Collections.Generic.List[string]
                    $details        = New-Object System.Collections.Generic.List[string]
                    $severity       = 'Informational'

                    # --- 1. Creation After Modification -----------------------------------
                    if ($created -gt $modified.AddSeconds(1)) {
                        $indicatorTypes.Add('CreationAfterModification')
                        $details.Add('CreationTime is newer than LastWriteTime - normal for copied/installed files, but also a common side effect of tools that only rewrite LastWriteTime')
                    }

                    # --- 2. Impossible Timestamp --------------------------------------------
                    if ($created -gt $now.Add($futureTolerance)) {
                        $indicatorTypes.Add('ImpossibleTimestamp')
                        $details.Add('CreationTime is in the future relative to the system clock')
                        $severity = 'Red'
                    }
                    if ($modified -gt $now.Add($futureTolerance)) {
                        $indicatorTypes.Add('ImpossibleTimestamp')
                        $details.Add('LastWriteTime is in the future relative to the system clock')
                        $severity = 'Red'
                    }
                    if ($accessed -gt $now.Add($futureTolerance)) {
                        $indicatorTypes.Add('ImpossibleTimestamp')
                        $details.Add('LastAccessTime is in the future relative to the system clock')
                        $severity = 'Red'
                    }
                    if ($accessed -lt $created.AddSeconds(-1)) {
                        $indicatorTypes.Add('ImpossibleTimestamp')
                        $details.Add('LastAccessTime predates CreationTime - the file was recorded as accessed before it existed')
                        $severity = 'Red'
                    }
                    if ($created -lt $epochSanityFloor) {
                        $indicatorTypes.Add('ImpossibleTimestamp')
                        $details.Add("CreationTime predates $($epochSanityFloor.ToString('yyyy-MM-dd')) - likely a corrupted or all-zero FILETIME value")
                        $severity = 'Red'
                    }

                    # --- 3. Potential Timestomping (pattern-based, softer signal) ----------
                    if ($created.Second -eq 0 -and $created.Millisecond -eq 0 -and
                        $modified.Second -eq 0 -and $modified.Millisecond -eq 0 -and
                        $accessed.Second -eq 0 -and $accessed.Millisecond -eq 0) {
                        $indicatorTypes.Add('PotentialTimestomping')
                        $details.Add('Created/Modified/Accessed are all truncated to an exact minute boundary (0s/0ms) - a common SetFileTime()/timestomping-tool artifact')
                        if ($severity -ne 'Red') { $severity = 'Yellow' }
                    } elseif ($created.Millisecond -eq 0 -and $modified.Millisecond -eq 0 -and $accessed.Millisecond -eq 0) {
                        $indicatorTypes.Add('PotentialTimestomping')
                        $details.Add('Created/Modified/Accessed all have zero sub-second precision - genuine NTFS timestamps are rarely all whole-second')
                        if ($severity -ne 'Red') { $severity = 'Yellow' }
                    }

                    if ($created -eq $modified -and $modified -eq $accessed) {
                        $indicatorTypes.Add('PotentialTimestomping')
                        $details.Add('Created, Modified, and Accessed timestamps are byte-for-byte identical - consistent with a single SetFileTime() call stamping all three fields at once')
                        if ($severity -ne 'Red') { $severity = 'Yellow' }
                    }

                    if ($osInstallDate -and $created -lt $osInstallDate.AddDays(-1)) {
                        $indicatorTypes.Add('PotentialTimestomping')
                        $details.Add('CreationTime predates the OS installation date on this machine')
                        if ($severity -ne 'Red') { $severity = 'Yellow' }
                    }

                    if ($indicatorTypes.Count -gt 0) {
                        $isExecutable = $Script:ExecutableExtensions -contains $_.Extension.ToLowerInvariant()
                        $uniqueTypes  = $indicatorTypes | Select-Object -Unique

                        $results.Add([PSCustomObject]@{
                            FileName       = $_.Name
                            FullPath       = $_.FullName
                            Extension      = $_.Extension
                            IsExecutable   = $isExecutable
                            Created        = $created
                            LastModified   = $modified
                            LastAccessed   = $accessed
                            IndicatorTypes = ($uniqueTypes -join ' | ')
                            Severity       = $severity
                            Details        = ($details -join ' | ')
                            Note           = 'Heuristic $STANDARD_INFORMATION indicator only. Confirm against $FILE_NAME attribute timestamps with a dedicated MFT parser (e.g. MFTECmd) before treating as confirmed timestomping.'
                        })
                    }
                }
        } catch {
            Write-Log -Level DEBUG -Message "Timestomp indicator scan failed for '$folder': $($_.Exception.Message)"
        }
    }

    return ($results | Sort-Object Severity, Created -Descending)
}

#====================================================================
# NTFS $MFT Raw Parser (Full Record-Level Collection)
#
# This section reads the $MFT directly from the raw volume (bypassing
# the filesystem driver's directory-enumeration API) using CreateFile/
# ReadFile against \\.\<Drive>: . This is the same general approach
# used by tools such as MFTECmd/analyzeMFT: parse the NTFS boot sector
# to locate the $MFT, read its own base record (#0) to learn the data
# runs that make up the full $MFT file, then walk every fixed-size
# file record in the table and parse the $STANDARD_INFORMATION,
# $FILE_NAME, and $DATA attributes out of each one.
#
# Requires Administrator privileges (raw volume handles are protected).
# Every raw read / per-volume parse is wrapped so that a failure on
# one volume (access denied, damaged boot sector, etc.) logs a warning
# and lets collection continue with the next volume.
#====================================================================

if (-not ([System.Management.Automation.PSTypeName]'Forensics.NativeDisk').Type) {
    Add-Type -Namespace Forensics -Name NativeDisk -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr CreateFile(
    string lpFileName,
    uint dwDesiredAccess,
    uint dwShareMode,
    IntPtr lpSecurityAttributes,
    uint dwCreationDisposition,
    uint dwFlagsAndAttributes,
    IntPtr hTemplateFile);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool ReadFile(
    IntPtr hFile,
    byte[] lpBuffer,
    uint nNumberOfBytesToRead,
    out uint lpNumberOfBytesRead,
    IntPtr lpOverlapped);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetFilePointerEx(
    IntPtr hFile,
    long liDistanceToMove,
    out long lpNewFilePointer,
    uint dwMoveMethod);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(IntPtr hObject);
'@
}

function Open-RawVolumeHandle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriveLetter
    )

    $path = "\\.\$($DriveLetter.TrimEnd(':')):"
    $GENERIC_READ     = [uint32]0x80000000L
    $FILE_SHARE_READ  = 0x1
    $FILE_SHARE_WRITE = 0x2
    $OPEN_EXISTING    = 3

    try {
        $handle = [Forensics.NativeDisk]::CreateFile(
            $path, $GENERIC_READ, ($FILE_SHARE_READ -bor $FILE_SHARE_WRITE),
            [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)

        if ($handle -eq [IntPtr]::Zero -or $handle.ToInt64() -eq -1) {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Log -Level WARNING -Message "Unable to open raw volume handle for '$DriveLetter' (Win32 error $err). This requires Administrator privileges and an unlocked volume."
            return $null
        }
        return $handle
    } catch {
        Write-Log -Level WARNING -Message "Exception opening raw volume '$DriveLetter': $($_.Exception.Message)"
        return $null
    }
}

function Read-RawVolumeBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [IntPtr]$Handle,

        [Parameter(Mandatory = $true)]
        [long]$Offset,

        [Parameter(Mandatory = $true)]
        [uint32]$Length
    )

    $newPos = 0L
    $moved = [Forensics.NativeDisk]::SetFilePointerEx($Handle, $Offset, [ref]$newPos, 0)
    if (-not $moved) {
        throw "SetFilePointerEx failed at offset $Offset (Win32 error $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    $buffer = New-Object byte[] $Length
    $bytesRead = 0
    $ok = [Forensics.NativeDisk]::ReadFile($Handle, $buffer, $Length, [ref]$bytesRead, [IntPtr]::Zero)
    if (-not $ok) {
        throw "ReadFile failed at offset $Offset (Win32 error $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }
    if ($bytesRead -ne $Length) {
        $trimmed = New-Object byte[] $Length
        [Array]::Copy($buffer, $trimmed, [int]$bytesRead)
        return $trimmed
    }
    return $buffer
}

function ConvertFrom-NtfsClusterCountByte {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte]$RawByte
    )
    if ($RawByte -gt 127) { return ($RawByte - 256) }
    return [int]$RawByte
}

function Get-NtfsBootSectorInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [IntPtr]$Handle
    )

    $boot = Read-RawVolumeBytes -Handle $Handle -Offset 0 -Length 512
    if ($boot.Length -lt 512) {
        throw "Boot sector read returned fewer than 512 bytes."
    }

    $oemId = [System.Text.Encoding]::ASCII.GetString($boot, 3, 8)
    if ($oemId.TrimEnd([char]0) -ne 'NTFS    ' -and -not $oemId.StartsWith('NTFS')) {
        throw "Not an NTFS boot sector (OEM ID: '$oemId')."
    }

    $bytesPerSector    = [BitConverter]::ToUInt16($boot, 11)
    $sectorsPerCluster = $boot[13]
    if ($bytesPerSector -eq 0 -or $sectorsPerCluster -eq 0) {
        throw "Invalid boot sector geometry (BytesPerSector=$bytesPerSector, SectorsPerCluster=$sectorsPerCluster)."
    }
    $clusterSize = [int64]$bytesPerSector * [int64]$sectorsPerCluster

    $totalSectors        = [BitConverter]::ToInt64($boot, 40)
    $mftStartCluster      = [BitConverter]::ToInt64($boot, 48)
    $mftMirrStartCluster  = [BitConverter]::ToInt64($boot, 56)

    $clustersPerRecordRaw = ConvertFrom-NtfsClusterCountByte -RawByte $boot[64]
    $fileRecordSize = if ($clustersPerRecordRaw -gt 0) {
        $clustersPerRecordRaw * $clusterSize
    } else {
        [int64][math]::Pow(2, [math]::Abs($clustersPerRecordRaw))
    }

    $clustersPerIndexRaw = ConvertFrom-NtfsClusterCountByte -RawByte $boot[68]
    $indexRecordSize = if ($clustersPerIndexRaw -gt 0) {
        $clustersPerIndexRaw * $clusterSize
    } else {
        [int64][math]::Pow(2, [math]::Abs($clustersPerIndexRaw))
    }

    return [PSCustomObject]@{
        BytesPerSector       = $bytesPerSector
        SectorsPerCluster    = $sectorsPerCluster
        ClusterSizeBytes     = $clusterSize
        TotalSectors         = $totalSectors
        VolumeSizeBytes      = $totalSectors * $bytesPerSector
        MftStartCluster      = $mftStartCluster
        MftMirrStartCluster  = $mftMirrStartCluster
        FileRecordSizeBytes  = [int]$fileRecordSize
        IndexRecordSizeBytes = [int]$indexRecordSize
    }
}

function Repair-MftRecordFixup {
    # Applies the NTFS "update sequence array" fixup in place. Every sector of a
    # raw file record has its last 2 bytes swapped out for a signature at write
    # time (torn-write protection); this restores the real trailing bytes.
    # Returns $false (record should be treated as unreliable) if the structure
    # looks inconsistent with the record buffer we actually read.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Record,

        [Parameter(Mandatory = $true)]
        [int]$BytesPerSector
    )

    $usaOffset = [BitConverter]::ToUInt16($Record, 4)
    $usaSize   = [BitConverter]::ToUInt16($Record, 6)
    if ($usaSize -lt 1 -or $usaOffset -eq 0 -or ($usaOffset + ($usaSize * 2)) -gt $Record.Length) {
        return $false
    }

    $usn = [BitConverter]::ToUInt16($Record, $usaOffset)
    $sectorCount = $usaSize - 1
    for ($i = 0; $i -lt $sectorCount; $i++) {
        $sectorEndOffset = (($i + 1) * $BytesPerSector) - 2
        if (($sectorEndOffset + 2) -gt $Record.Length) { break }
        $fixupValueOffset = $usaOffset + 2 + ($i * 2)
        if (($fixupValueOffset + 2) -gt $Record.Length) { break }
        $fixupBytes = $Record[$fixupValueOffset..($fixupValueOffset + 1)]
        $Record[$sectorEndOffset]     = $fixupBytes[0]
        $Record[$sectorEndOffset + 1] = $fixupBytes[1]
    }
    return $true
}

function ConvertFrom-MftDataRuns {
    # Parses an NTFS non-resident attribute's data-run byte stream into a list
    # of (LengthClusters, StartLcn, IsSparse) extents describing where on disk
    # the attribute's content actually lives.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Data,

        [Parameter(Mandatory = $true)]
        [int]$StartOffset,

        [Parameter(Mandatory = $true)]
        [int]$EndOffset
    )

    $runs = New-Object System.Collections.Generic.List[object]
    $offset = $StartOffset
    $currentLcn = 0L

    while ($offset -lt $EndOffset -and $offset -lt $Data.Length) {
        $header = $Data[$offset]
        if ($header -eq 0) { break }

        $lengthSize = $header -band 0x0F
        $offsetSize = ($header -shr 4) -band 0x0F
        $offset++
        if ($lengthSize -eq 0 -or ($offset + $lengthSize + $offsetSize) -gt $Data.Length) { break }

        $runLength = 0L
        for ($i = 0; $i -lt $lengthSize; $i++) {
            $runLength = $runLength -bor ([int64]$Data[$offset + $i] -shl (8 * $i))
        }
        $offset += $lengthSize

        $isSparse = ($offsetSize -eq 0)
        if (-not $isSparse) {
            $bytes = New-Object byte[] 8
            for ($i = 0; $i -lt $offsetSize; $i++) { $bytes[$i] = $Data[$offset + $i] }
            if ($Data[$offset + $offsetSize - 1] -band 0x80) {
                for ($i = $offsetSize; $i -lt 8; $i++) { $bytes[$i] = 0xFF }
            }
            $runOffset = [BitConverter]::ToInt64($bytes, 0)
            $currentLcn += $runOffset
            $offset += $offsetSize
        }

        $runs.Add([PSCustomObject]@{
            LengthClusters = $runLength
            StartLcn       = if ($isSparse) { -1L } else { $currentLcn }
            IsSparse       = $isSparse
        })
    }

    return $runs
}

function ConvertFrom-MftFileTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Buffer,

        [Parameter(Mandatory = $true)]
        [int]$Offset
    )
    try {
        if (($Offset + 8) -gt $Buffer.Length) { return $null }
        $ft = [BitConverter]::ToInt64($Buffer, $Offset)
        if ($ft -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc($ft)
    } catch {
        return $null
    }
}

function ConvertFrom-MftRecordBuffer {
    # Parses one fixed-size $MFT file record (already fixed up or about to be)
    # into its header fields plus the handful of attributes this toolkit cares
    # about: $STANDARD_INFORMATION (0x10), $FILE_NAME (0x30), $DATA (0x80).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Record,

        [Parameter(Mandatory = $true)]
        [int]$BytesPerSector,

        [Parameter(Mandatory = $true)]
        [int64]$FallbackRecordNumber
    )

    if ($Record.Length -lt 48) {
        return [PSCustomObject]@{ RecordNumber = $FallbackRecordNumber; Signature = ''; IsValid = $false }
    }

    $signature = [System.Text.Encoding]::ASCII.GetString($Record, 0, 4)
    if ($signature -ne 'FILE') {
        # 'BAAD' = NTFS itself flagged this record as fixup-inconsistent; all-zero
        # bytes mean the slot has never been allocated. Neither is parseable.
        return [PSCustomObject]@{ RecordNumber = $FallbackRecordNumber; Signature = $signature; IsValid = $false }
    }

    if (-not (Repair-MftRecordFixup -Record $Record -BytesPerSector $BytesPerSector)) {
        return [PSCustomObject]@{ RecordNumber = $FallbackRecordNumber; Signature = $signature; IsValid = $false }
    }

    $flags          = [BitConverter]::ToUInt16($Record, 22)
    $inUse          = (($flags -band 0x01) -ne 0)
    $isDirectory    = (($flags -band 0x02) -ne 0)
    $sequenceNumber = [BitConverter]::ToUInt16($Record, 16)
    $hardLinkCount  = [BitConverter]::ToUInt16($Record, 18)
    $firstAttrOff   = [BitConverter]::ToUInt16($Record, 20)
    $baseRecordRef  = [BitConverter]::ToUInt64($Record, 32)

    $recordNumber = $FallbackRecordNumber
    if ($Record.Length -ge 48) {
        try {
            $rn = [BitConverter]::ToUInt32($Record, 44)
            if ($rn -gt 0) { $recordNumber = [int64]$rn }
        } catch { }
    }

    $stdInfo   = $null
    $fileNames = New-Object System.Collections.Generic.List[object]
    $dataAttrs = New-Object System.Collections.Generic.List[object]

    $off = [int]$firstAttrOff
    $guard = 0
    while ($off -lt ($Record.Length - 8) -and $guard -lt 200) {
        $guard++
        $typeId = [BitConverter]::ToUInt32($Record, $off)
        if ($typeId -eq 0xFFFFFFFF -or $typeId -eq 0) { break }

        $attrLen = [BitConverter]::ToUInt32($Record, $off + 4)
        if ($attrLen -lt 8 -or ($off + $attrLen) -gt $Record.Length) { break }

        $nonResident = $Record[$off + 8]
        $nameLenChars = $Record[$off + 9]

        switch ($typeId) {
            0x10 {
                # $STANDARD_INFORMATION - always resident
                $contentOffset = [BitConverter]::ToUInt16($Record, $off + 20)
                $base = $off + $contentOffset
                if (($base + 36) -le $Record.Length) {
                    $stdInfo = [PSCustomObject]@{
                        Created        = ConvertFrom-MftFileTime -Buffer $Record -Offset $base
                        LastModified   = ConvertFrom-MftFileTime -Buffer $Record -Offset ($base + 8)
                        LastMftChange  = ConvertFrom-MftFileTime -Buffer $Record -Offset ($base + 16)
                        LastAccessed   = ConvertFrom-MftFileTime -Buffer $Record -Offset ($base + 24)
                        FileAttributes = [BitConverter]::ToUInt32($Record, $base + 32)
                    }
                }
            }
            0x30 {
                # $FILE_NAME - always resident
                $contentOffset = [BitConverter]::ToUInt16($Record, $off + 20)
                $base = $off + $contentOffset
                if (($base + 66) -le $Record.Length) {
                    $parentRef  = [BitConverter]::ToUInt64($Record, $base)
                    $nameLen    = $Record[$base + 64]
                    $namespaceT = $Record[$base + 65]
                    $nameBytes  = [int]$nameLen * 2
                    if ($nameLen -gt 0 -and ($base + 66 + $nameBytes) -le $Record.Length) {
                        $name = [System.Text.Encoding]::Unicode.GetString($Record, $base + 66, $nameBytes)
                        $fileNames.Add([PSCustomObject]@{
                            Name               = $name
                            Namespace          = $namespaceT
                            ParentRecordNumber = [int64]($parentRef -band [uint64]0xFFFFFFFFFFFF)
                            ParentSequence     = [int]((($parentRef -shr 48)) -band 0xFFFF)
                            AllocatedSize      = [BitConverter]::ToUInt64($Record, $base + 40)
                            RealSize           = [BitConverter]::ToUInt64($Record, $base + 48)
                            Flags              = [BitConverter]::ToUInt32($Record, $base + 56)
                        })
                    }
                }
            }
            0x80 {
                # $DATA
                $isNamedAttr = ($nameLenChars -gt 0)
                if ($nonResident -eq 0) {
                    if (($off + 20) -le $Record.Length) {
                        $contentLen = [BitConverter]::ToUInt32($Record, $off + 16)
                        $dataAttrs.Add([PSCustomObject]@{
                            Resident = $true; Size = [uint64]$contentLen; Named = $isNamedAttr; Runs = $null
                        })
                    }
                } else {
                    if (($off + 56) -le $Record.Length) {
                        $realSize   = [BitConverter]::ToUInt64($Record, $off + 48)
                        $runsOffset = [BitConverter]::ToUInt16($Record, $off + 32)
                        $runs = $null
                        if (-not $isNamedAttr -and $runsOffset -gt 0) {
                            try {
                                $runs = ConvertFrom-MftDataRuns -Data $Record -StartOffset ($off + $runsOffset) -EndOffset ($off + $attrLen)
                            } catch { $runs = $null }
                        }
                        $dataAttrs.Add([PSCustomObject]@{
                            Resident = $false; Size = $realSize; Named = $isNamedAttr; Runs = $runs
                        })
                    }
                }
            }
        }

        $off += [int]$attrLen
    }

    return [PSCustomObject]@{
        RecordNumber   = $recordNumber
        Signature      = $signature
        IsValid        = $true
        InUse          = $inUse
        IsDirectory    = $isDirectory
        SequenceNumber = $sequenceNumber
        HardLinkCount  = $hardLinkCount
        BaseRecordRef  = $baseRecordRef
        StandardInfo   = $stdInfo
        FileNames      = $fileNames
        DataAttributes = $dataAttrs
    }
}

function ConvertTo-CsvField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Value
    )
    if ($null -eq $Value) { return '""' }
    return '"' + $Value.Replace('"', '""') + '"'
}

function ConvertTo-MftJsonString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Value
    )
    if ($null -eq $Value) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '"') {
            [void]$sb.Append('\"')
        } elseif ($ch -eq '\') {
            [void]$sb.Append('\\')
        } elseif ($ch -eq "`n") {
            [void]$sb.Append('\n')
        } elseif ($ch -eq "`r") {
            [void]$sb.Append('\r')
        } elseif ($ch -eq "`t") {
            [void]$sb.Append('\t')
        } elseif ([int][char]$ch -lt 0x20) {
            [void]$sb.Append(('\u{0:x4}' -f [int][char]$ch))
        } else {
            [void]$sb.Append($ch)
        }
    }
    return $sb.ToString()
}

function Write-MftCsvRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.StreamWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [string]$Volume,

        [Parameter(Mandatory = $true)]
        [psobject]$Row
    )
    $createdText  = if ($Row.CreatedUtc)  { $Row.CreatedUtc.ToString('o') }  else { '' }
    $modifiedText = if ($Row.ModifiedUtc) { $Row.ModifiedUtc.ToString('o') } else { '' }

    $fields = @(
        $Volume, $Row.RecordNumber, $Row.FileName, $Row.FullPath, $Row.ParentDirectory,
        $Row.FileSizeBytes, $Row.EntryType, $Row.IsDeleted, $Row.InUse, $Row.SequenceNumber,
        $Row.Flags, $Row.ReferenceNumber, $createdText, $modifiedText
    )
    $csvParts = New-Object System.Collections.Generic.List[string]
    foreach ($f in $fields) { $csvParts.Add((ConvertTo-CsvField -Value ([string]$f))) }
    $Writer.WriteLine(($csvParts -join ','))
}

function Write-MftJsonRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.StreamWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [string]$Volume,

        [Parameter(Mandatory = $true)]
        [psobject]$Row,

        [Parameter(Mandatory = $true)]
        [ref]$IsFirst
    )
    if (-not $IsFirst.Value) { $Writer.Write(',') } else { $IsFirst.Value = $false }

    $createdText  = if ($Row.CreatedUtc)  { $Row.CreatedUtc.ToString('o') }  else { '' }
    $modifiedText = if ($Row.ModifiedUtc) { $Row.ModifiedUtc.ToString('o') } else { '' }

    $Writer.Write('{')
    $Writer.Write('"Volume":"' + (ConvertTo-MftJsonString $Volume) + '",')
    $Writer.Write('"RecordNumber":' + $Row.RecordNumber + ',')
    $Writer.Write('"FileName":"' + (ConvertTo-MftJsonString $Row.FileName) + '",')
    $Writer.Write('"FullPath":"' + (ConvertTo-MftJsonString $Row.FullPath) + '",')
    $Writer.Write('"ParentDirectory":"' + (ConvertTo-MftJsonString $Row.ParentDirectory) + '",')
    $Writer.Write('"FileSizeBytes":' + $Row.FileSizeBytes + ',')
    $Writer.Write('"EntryType":"' + $Row.EntryType + '",')
    $Writer.Write('"IsDeleted":' + $Row.IsDeleted.ToString().ToLowerInvariant() + ',')
    $Writer.Write('"InUse":' + $Row.InUse.ToString().ToLowerInvariant() + ',')
    $Writer.Write('"SequenceNumber":' + $Row.SequenceNumber + ',')
    $Writer.Write('"Flags":"' + (ConvertTo-MftJsonString $Row.Flags) + '",')
    $Writer.Write('"ReferenceNumber":"' + $Row.ReferenceNumber + '",')
    $Writer.Write('"CreatedUtc":"' + $createdText + '",')
    $Writer.Write('"ModifiedUtc":"' + $modifiedText + '"')
    $Writer.Write('}')
}

function Write-MftTimelineCsvRow {
    # Writes one row of MFTTimeline.csv - a lean, timeline-focused view of the
    # $STANDARD_INFORMATION timestamps (Created / Modified / MFT Modified /
    # Last Accessed) alongside the record number and resolved full path, so it
    # can be sorted/filtered/imported into a timeline tool without the extra
    # size/flags/attribute columns MFTRecords.csv carries.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.StreamWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [string]$Volume,

        [Parameter(Mandatory = $true)]
        [psobject]$Row
    )
    $createdText     = if ($Row.CreatedUtc)     { $Row.CreatedUtc.ToString('o') }     else { '' }
    $modifiedText    = if ($Row.ModifiedUtc)    { $Row.ModifiedUtc.ToString('o') }    else { '' }
    $mftModifiedText = if ($Row.MftModifiedUtc) { $Row.MftModifiedUtc.ToString('o') } else { '' }
    $accessedText    = if ($Row.AccessedUtc)    { $Row.AccessedUtc.ToString('o') }    else { '' }

    $fields = @(
        $createdText, $modifiedText, $mftModifiedText, $accessedText,
        $Row.RecordNumber, $Row.FullPath
    )
    $csvParts = New-Object System.Collections.Generic.List[string]
    foreach ($f in $fields) { $csvParts.Add((ConvertTo-CsvField -Value ([string]$f))) }
    $Writer.WriteLine(($csvParts -join ','))
}

function Resolve-MftDirectoryPath {
    # Memoized walk up the parent chain built during the record scan. Record #5
    # is always the volume root in NTFS. Cycle/unresolved-parent guards keep a
    # single bad reference from breaking path resolution for everything else.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int64]$RecordNumber,

        [Parameter(Mandatory = $true)]
        [hashtable]$Lookup,

        [Parameter(Mandatory = $true)]
        [hashtable]$Cache,

        [Parameter(Mandatory = $true)]
        [string]$DriveRoot
    )

    if ($RecordNumber -eq 5 -or $RecordNumber -eq 0) { return $DriveRoot }
    if ($Cache.ContainsKey($RecordNumber)) { return $Cache[$RecordNumber] }

    if (-not $Lookup.ContainsKey($RecordNumber)) {
        $result = "$DriveRoot\[UnresolvedParent-$RecordNumber]"
        $Cache[$RecordNumber] = $result
        return $result
    }

    $entry = $Lookup[$RecordNumber]
    if ($entry.Resolving) {
        return "$DriveRoot\[CyclicPath]"
    }

    $entry.Resolving = $true
    $parentPath = Resolve-MftDirectoryPath -RecordNumber $entry.Parent -Lookup $Lookup -Cache $Cache -DriveRoot $DriveRoot
    $entry.Resolving = $false

    $safeName = if ([string]::IsNullOrEmpty($entry.Name)) { "[Unnamed-$RecordNumber]" } else { $entry.Name }
    $full = if ($parentPath -eq $DriveRoot) { "$DriveRoot\$safeName" } else { "$parentPath\$safeName" }
    $Cache[$RecordNumber] = $full
    return $full
}

function Invoke-NtfsMftParse {
    # Parses the full raw $MFT for a single NTFS volume, streaming rows out to
    # the shared CSV/JSON writers (plus a filtered DeletedWriter for records
    # whose InUse flag is clear) and returning per-volume summary statistics.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriveLetter,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.IO.StreamWriter]$CsvWriter,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.IO.StreamWriter]$JsonWriter,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [ref]$IsFirstJsonRow,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.IO.StreamWriter]$TimelineWriter,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.IO.StreamWriter]$DeletedWriter,

        [Parameter(Mandatory = $false)]
        [int64]$MaxRecords = 0
    )

    $stats = [ordered]@{
        Volume                   = $DriveLetter
        Success                  = $false
        Error                    = $null
        TotalRecords             = 0
        ActiveRecords            = 0
        DeletedRecords           = 0
        FileCount                = 0
        DirectoryCount           = 0
        ResidentFiles            = 0
        NonResidentFiles         = 0
        CorruptOrUnparsedRecords = 0
        RecordSizeBytes          = 0
        MftSizeBytes             = 0
        ClusterSizeBytes         = 0
        BytesPerSector           = 0
        VolumeSizeBytes          = 0
    }

    $handle = Open-RawVolumeHandle -DriveLetter $DriveLetter
    if (-not $handle) {
        $stats.Error = 'Access denied or unable to open a raw volume handle (Administrator privileges are required).'
        return [PSCustomObject]$stats
    }

    $volumeRows = New-Object System.Collections.Generic.List[object]
    $parentLookup = @{}

    try {
        try {
            $boot = Get-NtfsBootSectorInfo -Handle $handle
        } catch {
            $stats.Error = "Unable to parse NTFS boot sector: $($_.Exception.Message)"
            return [PSCustomObject]$stats
        }

        $stats.ClusterSizeBytes = $boot.ClusterSizeBytes
        $stats.BytesPerSector   = $boot.BytesPerSector
        $stats.VolumeSizeBytes  = $boot.VolumeSizeBytes
        $stats.RecordSizeBytes  = $boot.FileRecordSizeBytes
        $recordSize = [int]$boot.FileRecordSizeBytes
        if ($recordSize -le 0) {
            $stats.Error = 'Invalid $MFT file record size read from boot sector.'
            return [PSCustomObject]$stats
        }

        # --- Read the $MFT's own base record (#0) to learn its data runs ---
        $mftRecordOffset = $boot.MftStartCluster * $boot.ClusterSizeBytes
        $rawRecord0 = $null
        try {
            $rawRecord0 = Read-RawVolumeBytes -Handle $handle -Offset $mftRecordOffset -Length $recordSize
        } catch {
            $stats.Error = "Unable to read base `$MFT record (record 0): $($_.Exception.Message)"
            return [PSCustomObject]$stats
        }

        $record0 = ConvertFrom-MftRecordBuffer -Record $rawRecord0 -BytesPerSector $boot.BytesPerSector -FallbackRecordNumber 0
        if (-not $record0.IsValid) {
            $stats.Error = 'Unable to parse base $MFT record (record 0) - signature/fixup invalid.'
            return [PSCustomObject]$stats
        }

        $mftDataAttr = $record0.DataAttributes | Where-Object { -not $_.Named -and -not $_.Resident } | Select-Object -First 1
        if (-not $mftDataAttr -or -not $mftDataAttr.Runs -or $mftDataAttr.Runs.Count -eq 0) {
            $stats.Error = 'Unable to locate $MFT $DATA attribute data runs.'
            return [PSCustomObject]$stats
        }

        $stats.MftSizeBytes = [int64]$mftDataAttr.Size

        $recordNum = 0L
        $stop = $false
        $chunkBytesTarget = 4MB
        $chunkClusters = [math]::Max(1, [int]([math]::Floor($chunkBytesTarget / $boot.ClusterSizeBytes)))

        foreach ($run in $mftDataAttr.Runs) {
            if ($stop) { break }

            if ($run.IsSparse) {
                $recordsInRun = [int64](($run.LengthClusters * $boot.ClusterSizeBytes) / $recordSize)
                $recordNum += $recordsInRun
                continue
            }

            $clustersRead = 0L
            while ($clustersRead -lt $run.LengthClusters) {
                if ($stop) { break }
                $thisChunk   = [math]::Min($chunkClusters, $run.LengthClusters - $clustersRead)
                $chunkOffset = ($run.StartLcn + $clustersRead) * $boot.ClusterSizeBytes
                $chunkLength = [uint32]($thisChunk * $boot.ClusterSizeBytes)

                $buffer = $null
                try {
                    $buffer = Read-RawVolumeBytes -Handle $handle -Offset $chunkOffset -Length $chunkLength
                } catch {
                    Write-Log -Level WARNING -Message "Raw `$MFT read failed for $($DriveLetter): at offset $chunkOffset - $($_.Exception.Message)"
                    $clustersRead += $thisChunk
                    $recordNum += [int64](($thisChunk * $boot.ClusterSizeBytes) / $recordSize)
                    continue
                }

                $recordsInChunk = [int]([math]::Floor($buffer.Length / $recordSize))
                for ($r = 0; $r -lt $recordsInChunk; $r++) {
                    if ($MaxRecords -gt 0 -and $stats.TotalRecords -ge $MaxRecords) { $stop = $true; break }

                    $recBytes = New-Object byte[] $recordSize
                    [Array]::Copy($buffer, $r * $recordSize, $recBytes, 0, $recordSize)

                    $parsed = $null
                    try {
                        $parsed = ConvertFrom-MftRecordBuffer -Record $recBytes -BytesPerSector $boot.BytesPerSector -FallbackRecordNumber $recordNum
                    } catch {
                        Write-Log -Level DEBUG -Message "Skipped unparsable `$MFT record $recordNum on $($DriveLetter): $($_.Exception.Message)"
                        $stats.CorruptOrUnparsedRecords++
                        $recordNum++
                        continue
                    }

                    if (-not $parsed -or -not $parsed.IsValid) {
                        if ($parsed -and $parsed.Signature -eq 'FILE') { $stats.CorruptOrUnparsedRecords++ }
                        $recordNum++
                        continue
                    }

                    $stats.TotalRecords++
                    if ($parsed.InUse) { $stats.ActiveRecords++ } else { $stats.DeletedRecords++ }

                    # Attribute-list extension records (BaseRecordRef points elsewhere) are
                    # continuations of another record's attributes, not standalone entries.
                    $isExtensionRecord = (($parsed.BaseRecordRef -band [uint64]0xFFFFFFFFFFFF) -ne 0)

                    if (-not $isExtensionRecord) {
                        if ($parsed.IsDirectory) { $stats.DirectoryCount++ } else { $stats.FileCount++ }

                        $primaryData = $null
                        foreach ($da in $parsed.DataAttributes) {
                            if (-not $da.Named) { $primaryData = $da; break }
                        }
                        if ($primaryData) {
                            if ($primaryData.Resident) { $stats.ResidentFiles++ } else { $stats.NonResidentFiles++ }
                        }

                        # Prefer Win32 (1) / Win32&DOS (3) names over DOS-only 8.3 (2) or POSIX (0)
                        $bestName = $null
                        $bestNameRank = [int]::MaxValue
                        foreach ($fn in $parsed.FileNames) {
                            $rank = switch ($fn.Namespace) { 1 { 0 }; 3 { 0 }; 0 { 1 }; 2 { 2 }; default { 3 } }
                            if ($rank -lt $bestNameRank) {
                                $bestNameRank = $rank
                                $bestName = $fn
                                if ($rank -eq 0) { break }
                            }
                        }

                        $fileSize = if ($primaryData) { [int64]$primaryData.Size } else { 0 }

                        $flagsList = New-Object System.Collections.Generic.List[string]
                        if (-not $parsed.InUse) { $flagsList.Add('Deleted') }
                        $flagsList.Add($(if ($parsed.IsDirectory) { 'Directory' } else { 'File' }))
                        if ($primaryData) { $flagsList.Add($(if ($primaryData.Resident) { 'Resident' } else { 'NonResident' })) }
                        if ($bestName -and ($bestName.Flags -band 0x2))  { $flagsList.Add('Hidden') }
                        if ($bestName -and ($bestName.Flags -band 0x4))  { $flagsList.Add('System') }
                        if ($bestName -and ($bestName.Flags -band 0x400)) { $flagsList.Add('ReparsePoint') }
                        if ($parsed.HardLinkCount -gt 1) { $flagsList.Add('HardLinked') }

                        $rowObj = [PSCustomObject]@{
                            RecordNumber    = $parsed.RecordNumber
                            FileName        = if ($bestName) { $bestName.Name } else { '' }
                            FullPath        = $null
                            ParentDirectory = if ($bestName) { $bestName.ParentRecordNumber } else { -1 }
                            FileSizeBytes   = $fileSize
                            EntryType       = if ($parsed.IsDirectory) { 'Directory' } else { 'File' }
                            IsDeleted       = (-not $parsed.InUse)
                            InUse           = $parsed.InUse
                            SequenceNumber  = $parsed.SequenceNumber
                            Flags           = ($flagsList -join '|')
                            ReferenceNumber = "$($parsed.RecordNumber)-$($parsed.SequenceNumber)"
                            CreatedUtc      = if ($parsed.StandardInfo) { $parsed.StandardInfo.Created } else { $null }
                            ModifiedUtc     = if ($parsed.StandardInfo) { $parsed.StandardInfo.LastModified } else { $null }
                            MftModifiedUtc  = if ($parsed.StandardInfo) { $parsed.StandardInfo.LastMftChange } else { $null }
                            AccessedUtc     = if ($parsed.StandardInfo) { $parsed.StandardInfo.LastAccessed } else { $null }
                        }

                        if (-not $parentLookup.ContainsKey([int64]$parsed.RecordNumber)) {
                            $parentLookup[[int64]$parsed.RecordNumber] = @{
                                Name      = $rowObj.FileName
                                Parent    = [int64]$rowObj.ParentDirectory
                                Resolving = $false
                            }
                        }

                        $volumeRows.Add($rowObj)
                    }

                    $recordNum++
                }
                $clustersRead += $thisChunk
            }
        }
    } finally {
        [void][Forensics.NativeDisk]::CloseHandle($handle)
    }

    # --- Second pass: resolve full paths now that the parent table is complete ---
    Write-Log -Level INFO -Message "Resolving full paths for $($volumeRows.Count) `$MFT records on $($DriveLetter):..."
    $driveRoot = "$($DriveLetter):"
    $pathCache = @{}
    $usedJsonWriter = ($null -ne $JsonWriter -and $null -ne $IsFirstJsonRow)

    foreach ($row in $volumeRows) {
        try {
            $parentDirPath = Resolve-MftDirectoryPath -RecordNumber ([int64]$row.ParentDirectory) -Lookup $parentLookup -Cache $pathCache -DriveRoot $driveRoot
            $leaf = if ([string]::IsNullOrEmpty($row.FileName)) { "[Unnamed-$($row.RecordNumber)]" } else { $row.FileName }
            $row.FullPath = if ($parentDirPath -eq $driveRoot) { "$driveRoot\$leaf" } else { "$parentDirPath\$leaf" }

            $parentName = if ($parentLookup.ContainsKey([int64]$row.ParentDirectory)) {
                $parentLookup[[int64]$row.ParentDirectory].Name
            } elseif ($row.ParentDirectory -eq 5) {
                '(volume root)'
            } else {
                "[Unresolved-$($row.ParentDirectory)]"
            }
            $row.ParentDirectory = $parentName

            if ($CsvWriter) { Write-MftCsvRow -Writer $CsvWriter -Volume "$($DriveLetter):" -Row $row }
            if ($usedJsonWriter) { Write-MftJsonRow -Writer $JsonWriter -Volume "$($DriveLetter):" -Row $row -IsFirst $IsFirstJsonRow }
            if ($TimelineWriter) { Write-MftTimelineCsvRow -Writer $TimelineWriter -Volume "$($DriveLetter):" -Row $row }
            if ($DeletedWriter -and $row.IsDeleted) { Write-MftCsvRow -Writer $DeletedWriter -Volume "$($DriveLetter):" -Row $row }
        } catch {
            Write-Log -Level DEBUG -Message "Skipped one `$MFT record during path resolution/write on $($DriveLetter): $($_.Exception.Message)"
        }
    }

    $stats.Success = $true
    return [PSCustomObject]$stats
}

function Get-MftGrowthDelta {
    # Tracks $MFT size/record-count across separate runs of this toolkit via a
    # small per-machine baseline file, so MFTSummary.txt can report real growth
    # instead of just a single point-in-time size. Entirely best-effort: any
    # failure to read/write the baseline is logged at DEBUG and simply means
    # growth cannot be reported for this run.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Volume,

        [Parameter(Mandatory = $true)]
        [int64]$CurrentMftSizeBytes,

        [Parameter(Mandatory = $true)]
        [int64]$CurrentRecordCount
    )

    $result = [ordered]@{
        PreviousSizeBytes   = $null
        PreviousRecordCount = $null
        PreviousCapturedUtc = $null
        GrowthBytes         = $null
        GrowthRecords       = $null
        Note                = 'No prior baseline found for this volume on this machine; growth will be measurable starting with the next run.'
    }

    $baselineDir  = Join-Path -Path $env:ProgramData -ChildPath 'WindowsForensicToolkit'
    $baselineFile = Join-Path -Path $baselineDir -ChildPath 'mft_baseline.json'

    try {
        $baseline = @{}
        if (Test-Path -LiteralPath $baselineFile) {
            $raw = Get-Content -LiteralPath $baselineFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            foreach ($p in $raw.PSObject.Properties) { $baseline[$p.Name] = $p.Value }
        }

        if ($baseline.ContainsKey($Volume)) {
            $prev = $baseline[$Volume]
            $result.PreviousSizeBytes   = [int64]$prev.MftSizeBytes
            $result.PreviousRecordCount = [int64]$prev.RecordCount
            $result.PreviousCapturedUtc = $prev.CapturedUtc
            $result.GrowthBytes         = $CurrentMftSizeBytes - [int64]$prev.MftSizeBytes
            $result.GrowthRecords       = $CurrentRecordCount - [int64]$prev.RecordCount
            $result.Note                = "Compared against baseline captured $($prev.CapturedUtc)."
        }

        $baseline[$Volume] = @{
            MftSizeBytes = $CurrentMftSizeBytes
            RecordCount  = $CurrentRecordCount
            CapturedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        }

        if (-not (Test-Path -LiteralPath $baselineDir)) {
            New-Item -Path $baselineDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        ($baseline | ConvertTo-Json -Depth 4 -ErrorAction Stop) | Out-File -FilePath $baselineFile -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Log -Level DEBUG -Message "MFT growth baseline unavailable for volume '$Volume': $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Write-MftSummaryReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$VolumeStats,

        [Parameter(Mandatory = $false)]
        [bool]$AdminRequired = $false
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('========================================================')
    [void]$sb.AppendLine(' NTFS $MFT (Master File Table) Summary')
    [void]$sb.AppendLine(" Computer:  $($Script:ComputerName)")
    [void]$sb.AppendLine(" Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine('========================================================')
    [void]$sb.AppendLine('')

    try {
        if ($AdminRequired) {
            [void]$sb.AppendLine('Raw $MFT parsing was skipped: reading $MFT file records directly requires opening')
            [void]$sb.AppendLine('a raw volume handle (\\.\<Drive>:), which requires Administrator privileges.')
            [void]$sb.AppendLine('Re-run this toolkit elevated (Run as Administrator) to collect MFTRecords.csv/json.')
            return
        }

        if (-not $VolumeStats -or $VolumeStats.Count -eq 0) {
            [void]$sb.AppendLine('No NTFS volumes were available to parse.')
            return
        }

        $agg = [ordered]@{
            TotalRecords = 0; ActiveRecords = 0; DeletedRecords = 0
            FileCount = 0; DirectoryCount = 0; ResidentFiles = 0; NonResidentFiles = 0
        }

        foreach ($s in $VolumeStats) {
            [void]$sb.AppendLine('--------------------------------------------------------')
            [void]$sb.AppendLine("Volume: $($s.Volume):")
            [void]$sb.AppendLine('--------------------------------------------------------')

            if (-not $s.Success) {
                [void]$sb.AppendLine("  STATUS: FAILED - $($s.Error)")
                [void]$sb.AppendLine('')
                continue
            }

            [void]$sb.AppendLine("  Total MFT Records:         $($s.TotalRecords)")
            [void]$sb.AppendLine("  Active Records:             $($s.ActiveRecords)")
            [void]$sb.AppendLine("  Deleted Records:            $($s.DeletedRecords)")
            [void]$sb.AppendLine("  File Count:                 $($s.FileCount)")
            [void]$sb.AppendLine("  Directory Count:            $($s.DirectoryCount)")
            [void]$sb.AppendLine("  Resident Files:             $($s.ResidentFiles)")
            [void]$sb.AppendLine("  Non-Resident Files:         $($s.NonResidentFiles)")
            [void]$sb.AppendLine("  Corrupt/Unparsed Records:   $($s.CorruptOrUnparsedRecords)")
            [void]$sb.AppendLine("  MFT Record Size (bytes):    $($s.RecordSizeBytes)")
            [void]$sb.AppendLine("  MFT Size (bytes):           $($s.MftSizeBytes) ($([math]::Round($s.MftSizeBytes / 1MB, 2)) MB)")
            [void]$sb.AppendLine("  Cluster Size (bytes):       $($s.ClusterSizeBytes)")
            [void]$sb.AppendLine("  Bytes Per Sector:           $($s.BytesPerSector)")
            [void]$sb.AppendLine("  Volume Size (bytes):        $($s.VolumeSizeBytes) ($([math]::Round($s.VolumeSizeBytes / 1GB, 2)) GB)")

            $growth = Get-MftGrowthDelta -Volume "$($s.Volume):" -CurrentMftSizeBytes $s.MftSizeBytes -CurrentRecordCount $s.TotalRecords
            [void]$sb.AppendLine('  MFT Growth Since Last Run On This Machine:')
            if ($null -ne $growth.GrowthBytes) {
                [void]$sb.AppendLine("    Size Delta:               $($growth.GrowthBytes) bytes")
                [void]$sb.AppendLine("    Record Count Delta:       $($growth.GrowthRecords) records")
            }
            [void]$sb.AppendLine("    $($growth.Note)")
            [void]$sb.AppendLine('')

            $agg.TotalRecords     += $s.TotalRecords
            $agg.ActiveRecords    += $s.ActiveRecords
            $agg.DeletedRecords   += $s.DeletedRecords
            $agg.FileCount        += $s.FileCount
            $agg.DirectoryCount   += $s.DirectoryCount
            $agg.ResidentFiles    += $s.ResidentFiles
            $agg.NonResidentFiles += $s.NonResidentFiles
        }

        [void]$sb.AppendLine('========================================================')
        [void]$sb.AppendLine(' Aggregate Totals (All NTFS Volumes)')
        [void]$sb.AppendLine('========================================================')
        [void]$sb.AppendLine("  Total MFT Records:   $($agg.TotalRecords)")
        [void]$sb.AppendLine("  Active Records:      $($agg.ActiveRecords)")
        [void]$sb.AppendLine("  Deleted Records:     $($agg.DeletedRecords)")
        [void]$sb.AppendLine("  File Count:          $($agg.FileCount)")
        [void]$sb.AppendLine("  Directory Count:     $($agg.DirectoryCount)")
        [void]$sb.AppendLine("  Resident Files:      $($agg.ResidentFiles)")
        [void]$sb.AppendLine("  Non-Resident Files:  $($agg.NonResidentFiles)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Note: a "Deleted" record is an $MFT slot marked not-in-use (the entry still')
        [void]$sb.AppendLine('exists in the table but the file/directory has been deleted; its clusters may')
        [void]$sb.AppendLine('be partially or fully overwritten). See MFTRecords.csv/json for full per-file')
        [void]$sb.AppendLine('detail, including deleted entries.')
    } finally {
        $sb.ToString() | Out-File -FilePath $Path -Encoding UTF8
    }
}

function Invoke-FullMftCollection {
    # Orchestrates raw $MFT collection across every NTFS volume with a drive
    # letter, writing one combined MFTRecords.csv/json (each row tagged with
    # its Volume), one MFTTimeline.csv (File Created / File Modified / MFT
    # Modified / Last Accessed / Record Number / Path - a lean timeline view
    # for import into timeline tooling), one DeletedFiles.csv (every parsed
    # record whose InUse flag is clear - i.e. the MFT slot has been marked
    # deleted but has not yet been reallocated/overwritten, so its record is
    # "still present" and recoverable metadata-wise), and one MFTSummary.txt
    # with per-volume and aggregate stats. A failure on any single volume is
    # logged and does not stop the others.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [int64]$MaxRecordsPerVolume = 0
    )

    $mftFolder   = Join-Path -Path $OutputPath -ChildPath 'MFT'
    if (-not (Test-Path -LiteralPath $mftFolder)) {
        New-Item -Path $mftFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    $csvPath      = Join-Path -Path $mftFolder -ChildPath 'MFTRecords.csv'
    $jsonPath     = Join-Path -Path $mftFolder -ChildPath 'MFTRecords.json'
    $timelinePath = Join-Path -Path $mftFolder -ChildPath 'MFTTimeline.csv'
    $deletedPath  = Join-Path -Path $mftFolder -ChildPath 'DeletedFiles.csv'
    $summaryPath  = Join-Path -Path $mftFolder -ChildPath 'MFTSummary.txt'

    if (-not (Test-IsAdministrator)) {
        Write-Log -Level WARNING -Message 'Full $MFT record parsing requires raw volume access (Administrator privileges). Writing MFTSummary.txt with this limitation noted; MFTRecords.csv/json/MFTTimeline.csv/DeletedFiles.csv will not be generated this run.'
        Write-MftSummaryReport -Path $summaryPath -VolumeStats @() -AdminRequired $true
        $Script:ReportFiles.Add($summaryPath)
        return
    }

    $volumeStatsList = New-Object System.Collections.Generic.List[object]
    $csvWriter      = $null
    $jsonWriter     = $null
    $timelineWriter = $null
    $deletedWriter  = $null

    try {
        $csvWriter = New-Object System.IO.StreamWriter($csvPath, $false, [System.Text.Encoding]::UTF8)
        $csvWriter.WriteLine('"Volume","RecordNumber","FileName","FullPath","ParentDirectory","FileSizeBytes","EntryType","IsDeleted","InUse","SequenceNumber","Flags","ReferenceNumber","CreatedUtc","ModifiedUtc"')
        $Script:ReportFiles.Add($csvPath)
    } catch {
        Write-Log -Level ERROR -Message "Unable to create MFTRecords.csv: $($_.Exception.Message)"
        $csvWriter = $null
    }

    try {
        $jsonWriter = New-Object System.IO.StreamWriter($jsonPath, $false, [System.Text.Encoding]::UTF8)
        $jsonWriter.Write('[')
        $Script:ReportFiles.Add($jsonPath)
    } catch {
        Write-Log -Level ERROR -Message "Unable to create MFTRecords.json: $($_.Exception.Message)"
        $jsonWriter = $null
    }

    try {
        $timelineWriter = New-Object System.IO.StreamWriter($timelinePath, $false, [System.Text.Encoding]::UTF8)
        $timelineWriter.WriteLine('"File Created","File Modified","MFT Modified","Last Accessed","Record Number","Path"')
        $Script:ReportFiles.Add($timelinePath)
    } catch {
        Write-Log -Level ERROR -Message "Unable to create MFTTimeline.csv: $($_.Exception.Message)"
        $timelineWriter = $null
    }

    try {
        $deletedWriter = New-Object System.IO.StreamWriter($deletedPath, $false, [System.Text.Encoding]::UTF8)
        $deletedWriter.WriteLine('"Volume","RecordNumber","FileName","FullPath","ParentDirectory","FileSizeBytes","EntryType","IsDeleted","InUse","SequenceNumber","Flags","ReferenceNumber","CreatedUtc","ModifiedUtc"')
        $Script:ReportFiles.Add($deletedPath)
    } catch {
        Write-Log -Level ERROR -Message "Unable to create DeletedFiles.csv: $($_.Exception.Message)"
        $deletedWriter = $null
    }

    $isFirstJsonRow = $true

    try {
        $volumes = @()
        try {
            $volumes = Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop |
                Where-Object { $_.FileSystem -eq 'NTFS' -and $_.DriveLetter }
        } catch {
            Write-Log -Level ERROR -Message "Unable to enumerate NTFS volumes: $($_.Exception.Message)"
        }

        if (-not $volumes -or @($volumes).Count -eq 0) {
            Write-Log -Level WARNING -Message 'No NTFS volumes with drive letters were found to parse.'
        }

        foreach ($vol in $volumes) {
            $drive = $vol.DriveLetter.TrimEnd(':')
            Write-Log -Level INFO -Message "Parsing raw `$MFT for volume $($drive):..."
            try {
                $stats = Invoke-NtfsMftParse -DriveLetter $drive -CsvWriter $csvWriter -JsonWriter $jsonWriter `
                    -IsFirstJsonRow ([ref]$isFirstJsonRow) -TimelineWriter $timelineWriter -DeletedWriter $deletedWriter `
                    -MaxRecords $MaxRecordsPerVolume
                $volumeStatsList.Add($stats)
                if ($stats.Success) {
                    Write-Log -Level INFO -Message "Completed `$MFT parse for $($drive): $($stats.TotalRecords) records ($($stats.ActiveRecords) active, $($stats.DeletedRecords) deleted)."
                } else {
                    Write-Log -Level WARNING -Message "`$MFT parse for $($drive): incomplete - $($stats.Error)"
                }
            } catch {
                Write-Log -Level ERROR -Message "`$MFT parse for volume $($drive) failed unexpectedly: $($_.Exception.Message)"
                $volumeStatsList.Add([PSCustomObject]@{ Volume = $drive; Success = $false; Error = $_.Exception.Message })
            }
        }
    } finally {
        if ($csvWriter)      { try { $csvWriter.Flush(); $csvWriter.Close() } catch { } }
        if ($jsonWriter)     { try { $jsonWriter.Write(']'); $jsonWriter.Flush(); $jsonWriter.Close() } catch { } }
        if ($timelineWriter) { try { $timelineWriter.Flush(); $timelineWriter.Close() } catch { } }
        if ($deletedWriter)  { try { $deletedWriter.Flush(); $deletedWriter.Close() } catch { } }
    }

    Write-MftSummaryReport -Path $summaryPath -VolumeStats $volumeStatsList -AdminRequired $false
    $Script:ReportFiles.Add($summaryPath)
}


#====================================================================
# Windows Defender Detections
#====================================================================

function Get-DefenderDetections {
    [CmdletBinding()]
    param()

    $result = [ordered]@{
        ThreatDetections    = $null
        OperationalEvents   = $null
    }

    try {
        $cmd = Get-Command -Name Get-MpThreatDetection -ErrorAction SilentlyContinue
        if ($cmd) {
            $result.ThreatDetections = Get-MpThreatDetection -ErrorAction Stop | Select-Object ThreatID, ProcessName,
                DetectionSourceTypeID, InitialDetectionTime, LastThreatStatusChangeTime, Resources,
                @{Name='ThreatName'; Expression = {
                    try { (Get-MpThreat -ThreatID $_.ThreatID -ErrorAction Stop).ThreatName } catch { $null }
                }}
        } else {
            Write-Log -Level DEBUG -Message "Get-MpThreatDetection not available (Defender module absent)."
        }
    } catch {
        Write-Log -Level WARNING -Message "Defender threat-detection collection failed: $($_.Exception.Message)"
    }

    try {
        $defenderIds = 1006, 1007, 1008, 1009, 1010, 1015, 1116, 1117, 1118, 1119, 5001, 5007
        $result.OperationalEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = $defenderIds
        } -MaxEvents 1000 -ErrorAction Stop | Select-Object TimeCreated, Id,
            @{Name='EventType'; Expression = {
                switch ($_.Id) {
                    1006 { 'Malware Detected' }
                    1007 { 'Action Taken on Malware' }
                    1008 { 'Action Failed' }
                    1009 { 'Item Restored from Quarantine' }
                    1010 { 'Quarantine Removal Failed' }
                    1015 { 'Suspicious Behavior Detected' }
                    1116 { 'Threat Detected' }
                    1117 { 'Action Taken on Threat' }
                    1118 { 'Action Failed on Threat' }
                    1119 { 'Critical Action Failed' }
                    5001 { 'Real-Time Protection Disabled' }
                    5007 { 'Defender Configuration Changed' }
                    default { 'Other' }
                }
            }},
            @{Name='Message'; Expression = {
                $m = $_.Message
                if ([string]::IsNullOrEmpty($m)) { '' } else { ($m -replace '\s+', ' ').Substring(0, [Math]::Min(400, $m.Length)) }
            }}
    } catch {
        Write-Log -Level WARNING -Message "Defender Operational log collection failed (log may be empty or inaccessible): $($_.Exception.Message)"
    }

    return [PSCustomObject]$result
}

function Export-DefenderEventLogEvtx {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        $destination = Join-Path -Path $OutputPath -ChildPath 'Defender.evtx'
        $logName = 'Microsoft-Windows-Windows Defender/Operational'
        $wevtutil = Get-Command -Name wevtutil.exe -ErrorAction Stop

        & $wevtutil.Source epl $logName $destination /ow:true 2>&1 | Out-Null

        if (Test-Path -LiteralPath $destination) {
            Write-Log -Level INFO -Message "Exported raw Defender Operational event log to: $destination"
            $Script:ReportFiles.Add($destination)
            return $destination
        } else {
            Write-Log -Level WARNING -Message "wevtutil did not produce Defender.evtx (log may require Administrator privileges or may not exist)."
            return $null
        }
    } catch {
        Write-Log -Level WARNING -Message "Failed to export Defender.evtx: $($_.Exception.Message)"
        return $null
    }
}

#====================================================================
# Running Processes (with optional compromise-window correlation)
#====================================================================

function Get-RunningProcessSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [Nullable[datetime]]$SuspectedCompromiseTime = $null,

        [Parameter(Mandatory = $false)]
        [int]$WindowMinutes = 120
    )

    $entries = New-Object System.Collections.Generic.List[object]

    try {
        $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
        foreach ($p in $procs) {
            $created = $null
            if ($p.CreationDate) {
                try { $created = $p.CreationDate.ToLocalTime() } catch { $created = $p.CreationDate }
            }

            $nearWindow = $false
            if ($SuspectedCompromiseTime -and $created) {
                $delta = [math]::Abs(($created - $SuspectedCompromiseTime).TotalMinutes)
                if ($delta -le $WindowMinutes) { $nearWindow = $true }
            }

            $signature = $null
            $hash = $null
            $exePath = $p.ExecutablePath
            if ($exePath -and (Test-Path -LiteralPath $exePath -ErrorAction SilentlyContinue)) {
                try { $signature = (Get-AuthenticodeSignature -LiteralPath $exePath -ErrorAction Stop).Status } catch { $signature = 'Unknown' }
                try {
                    $len = (Get-Item -LiteralPath $exePath -ErrorAction Stop).Length
                    if ($len -le ($MaxFileHashSizeMB * 1MB)) { $hash = Get-FileSha256Hash -FilePath $exePath }
                } catch { }
            }

            $owner = $null
            try { $owner = ($p | Invoke-CimMethod -MethodName GetOwner -ErrorAction Stop).User } catch { $owner = $null }

            $entries.Add([PSCustomObject]@{
                ProcessId         = $p.ProcessId
                ParentProcessId   = $p.ParentProcessId
                Name              = $p.Name
                ExecutablePath    = $exePath
                CommandLine       = $p.CommandLine
                CreationTime      = $created
                Owner             = $owner
                SignatureStatus   = $signature
                SHA256            = $hash
                NearCompromiseWindow = $nearWindow
            })
        }
    } catch {
        Write-Log -Level WARNING -Message "Running process snapshot failed: $($_.Exception.Message)"
    }

    return $entries
}

#====================================================================
# Threat Assessment / Classification
#====================================================================

function Get-ThreatAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$CollectedData
    )

    $malware     = New-Object System.Collections.Generic.List[object]
    $stealers    = New-Object System.Collections.Generic.List[object]
    $remoteAccess = New-Object System.Collections.Generic.List[object]
    $extensionsFlagged = New-Object System.Collections.Generic.List[object]
    $recentExeFlagged  = New-Object System.Collections.Generic.List[object]
    $suspiciousDns     = New-Object System.Collections.Generic.List[object]
    $timestompFlagged  = New-Object System.Collections.Generic.List[object]
    $clean       = New-Object System.Collections.Generic.List[object]

    function Add-Finding {
        param($List, $Severity, $Category, $Item, $Reason, $Location)
        if ($null -eq $List) {
            Write-Log -Level WARNING -Message "Add-Finding called with a null target list (Category: $Category, Item: $Item) - finding dropped."
            return
        }
        $List.Add([PSCustomObject]@{
            Severity = $Severity
            Category = $Category
            Item     = $Item
            Reason   = $Reason
            Location = $Location
        })
    }

    # --- Processes & services: malware / stealer / RAT keyword + heuristic matches ---
    $procSources = @()
    if ($CollectedData.RunningProcesses) { $procSources += $CollectedData.RunningProcesses }
    if ($CollectedData.Services) { $procSources += $CollectedData.Services }
    if ($CollectedData.StartupItems) { $procSources += $CollectedData.StartupItems }
    if ($CollectedData.RegistryRunKeys) { $procSources += $CollectedData.RegistryRunKeys }
    if ($CollectedData.ScheduledTasks) { $procSources += $CollectedData.ScheduledTasks }

    foreach ($item in $procSources) {
        if ($null -eq $item) { continue }
        try {
            $searchText = "$($item.Name) $($item.ExecutablePath) $($item.CommandLine) $($item.PathName) $($item.ValueData) $($item.Command) $($item.Actions) $($item.DisplayName)"
            if ([string]::IsNullOrWhiteSpace($searchText.Trim())) { continue }

            $malHit = Test-StringContainsAny -Text $searchText -Keywords $Script:MalwareIndicatorKeywords
            $cmdHit = Test-StringContainsAny -Text $searchText -Keywords $Script:SuspiciousCommandLinePatterns
            $stealHit = Test-StringContainsAny -Text $searchText -Keywords $Script:TokenStealerKeywords
            $ratHit = Test-StringContainsAny -Text $searchText -Keywords $Script:RemoteAccessToolNames

            $displayItem = if ($item.Name) { $item.Name } elseif ($item.DisplayName) { $item.DisplayName } else { $item.TaskName }
            $location = if ($item.ExecutablePath) { $item.ExecutablePath } elseif ($item.PathName) { $item.PathName } else { $item.ValueData }

            if ($malHit) {
                Add-Finding -List $malware -Severity 'Red' -Category 'Malware Indicator' -Item $displayItem -Reason "Matched known offensive-tooling keyword: '$malHit'" -Location $location
            }
            if ($cmdHit) {
                Add-Finding -List $malware -Severity 'Red' -Category 'Malware Indicator' -Item $displayItem -Reason "Obfuscated/suspicious command-line pattern: '$cmdHit'" -Location $item.CommandLine
            }
            if ($stealHit) {
                Add-Finding -List $stealers -Severity 'Red' -Category 'Token Stealer' -Item $displayItem -Reason "Matched known infostealer keyword: '$stealHit'" -Location $location
            }
            if ($ratHit) {
                Add-Finding -List $remoteAccess -Severity 'Red' -Category 'Remote Access Software' -Item $displayItem -Reason "Matched known remote-access tool name: '$ratHit' - verify this was authorized IT/user activity" -Location $location
            }

            # Unsigned/unknown-signature executable running from a user-writable temp/appdata path.
            if ($item.ExecutablePath -and $item.ExecutablePath -match '\\(AppData\\Local\\Temp|AppData\\Roaming|ProgramData)\\' -and $item.SignatureStatus -and $item.SignatureStatus -ne 'Valid') {
                Add-Finding -List $malware -Severity 'Red' -Category 'Malware Indicator' -Item $displayItem -Reason "Unsigned/invalid-signature executable running from a user-writable temp/appdata path" -Location $item.ExecutablePath
            }
        } catch {
            Write-Log -Level WARNING -Message "Threat assessment: skipped one process/service/task record due to an error: $($_.Exception.Message)"
        }
    }

    # --- Browser extensions ---
    if ($CollectedData.BrowserExtensions) {
        foreach ($ext in $CollectedData.BrowserExtensions) {
            if ($null -eq $ext) { continue }
            try {
                $sev = if ($ext.HighRiskPerms) { 'Yellow' } else { 'Yellow' }
                $reason = if ($ext.HighRiskPerms) { 'Installed extension requests broad/high-risk permissions (review manually)' } else { 'Installed extension - inventory only, verify legitimacy' }
                Add-Finding -List $extensionsFlagged -Severity $sev -Category 'Browser Extension' -Item "$($ext.Name) ($($ext.Browser))" -Reason $reason -Location $ext.InstalledPath
            } catch {
                Write-Log -Level WARNING -Message "Threat assessment: skipped one browser extension record due to an error: $($_.Exception.Message)"
            }
        }
    }

    # --- Recently downloaded executables ---
    if ($CollectedData.RecentDownloadedExecutables) {
        foreach ($f in $CollectedData.RecentDownloadedExecutables) {
            if ($null -eq $f) { continue }
            try {
                $sev = if ($f.SignatureStatus -and $f.SignatureStatus -ne 'Valid') { 'Red' } else { 'Yellow' }
                $reason = if ($f.SignatureStatus -and $f.SignatureStatus -ne 'Valid') { "Recently created executable with signature status '$($f.SignatureStatus)'" } else { 'Recently created/downloaded executable - review manually' }
                # NOTE: must use an explicit if/else statement (not an if/else *expression*) here.
                # `$cat = if (...) { $malware } else { $recentExeFlagged }` looks equivalent but is not:
                # when the block's last expression is a collection, PowerShell unrolls it onto the
                # output stream. If the list is empty at that moment, unrolling produces nothing, so
                # $cat silently becomes $null instead of a reference to the list - and every finding
                # in this branch gets silently dropped by Add-Finding's null-list guard.
                if ($sev -eq 'Red') { $cat = $malware } else { $cat = $recentExeFlagged }
                Add-Finding -List $cat -Severity $sev -Category 'Recently Downloaded Executable' -Item $f.FileName -Reason $reason -Location $f.FullPath
            } catch {
                Write-Log -Level WARNING -Message "Threat assessment: skipped one recently-downloaded-executable record due to an error: $($_.Exception.Message)"
            }
        }
    }

    # --- Executables in suspicious locations (Temp, ProgramData, Downloads,
    #     Desktop, Recycle Bin, Public, Startup folders) ---
    if ($CollectedData.SuspiciousPaths) {
        foreach ($f in $CollectedData.SuspiciousPaths) {
            if ($null -eq $f) { continue }
            try {
                $sev = if ($f.SignatureStatus -and $f.SignatureStatus -ne 'Valid') { 'Red' } else { 'Yellow' }
                $reason = if ($f.SignatureStatus -and $f.SignatureStatus -ne 'Valid') {
                    "Unsigned/invalid-signature executable found in suspicious location '$($f.SuspiciousLocation)'"
                } else {
                    "Signed executable found in suspicious location '$($f.SuspiciousLocation)' - review manually"
                }
                # See the note on the equivalent RecentDownloadedExecutables block above:
                # this must stay an explicit if/else statement, not an if/else expression.
                if ($sev -eq 'Red') { $cat = $malware } else { $cat = $recentExeFlagged }
                Add-Finding -List $cat -Severity $sev -Category 'Suspicious Path Executable' -Item $f.FileName -Reason $reason -Location $f.FullPath
            } catch {
                Write-Log -Level WARNING -Message "Threat assessment: skipped one suspicious-path executable record due to an error: $($_.Exception.Message)"
            }
        }
    }

    # --- DNS ---
    $dnsCandidates = New-Object System.Collections.Generic.List[string]
    try {
        if ($CollectedData.DnsHistory -and $CollectedData.DnsHistory.OperationalLogQueries) {
            foreach ($q in $CollectedData.DnsHistory.OperationalLogQueries) { if ($q -and $q.QueryName) { $dnsCandidates.Add($q.QueryName) } }
        }
        if ($CollectedData.DnsHistory -and $CollectedData.DnsHistory.ResolverCache) {
            foreach ($q in $CollectedData.DnsHistory.ResolverCache) { if ($q -and $q.Name) { $dnsCandidates.Add($q.Name) } }
        }
        if ($CollectedData.BrowserUrlHistorySample) {
            foreach ($u in $CollectedData.BrowserUrlHistorySample) { if ($u -and $u.Url) { $dnsCandidates.Add($u.Url) } }
        }
    } catch {
        Write-Log -Level WARNING -Message "Threat assessment: DNS/URL candidate collection encountered an error: $($_.Exception.Message)"
    }
    foreach ($candidate in ($dnsCandidates | Select-Object -Unique)) {
        try {
            $hit = Test-StringContainsAny -Text $candidate -Keywords $Script:SuspiciousDnsProviders
            if ($hit) {
                Add-Finding -List $suspiciousDns -Severity 'Yellow' -Category 'Suspicious DNS/URL' -Item $candidate -Reason "Matched dynamic-DNS/paste/webhook provider commonly abused for C2 or exfiltration: '$hit'" -Location $null
            }
        } catch {
            Write-Log -Level WARNING -Message "Threat assessment: skipped one DNS/URL candidate due to an error: $($_.Exception.Message)"
        }
    }

    # --- MFT / NTFS timestamp anomalies (potential timestomping) ---
    if ($CollectedData.MftTimestampAnomalies) {
        foreach ($m in $CollectedData.MftTimestampAnomalies) {
            if ($null -eq $m) { continue }
            try {
                $sev = if ($m.Severity) { $m.Severity } else { 'Yellow' }
                # Add-Finding's Severity field expects Red/Yellow/Green; map the scanner's
                # informational tier down to Yellow here so it still surfaces for review.
                if ($sev -eq 'Informational') { $sev = 'Yellow' }
                Add-Finding -List $timestompFlagged -Severity $sev -Category 'MFT Timestamp Anomaly' -Item $m.FileName -Reason $m.Anomalies -Location $m.FullPath
            } catch {
                Write-Log -Level WARNING -Message "Threat assessment: skipped one MFT timestamp anomaly record due to an error: $($_.Exception.Message)"
            }
        }
    }

    # --- Defender detections escalate straight to Red ---
    if ($CollectedData.DefenderDetections -and $CollectedData.DefenderDetections.ThreatDetections) {
        foreach ($t in $CollectedData.DefenderDetections.ThreatDetections) {
            if ($null -eq $t) { continue }
            try {
                Add-Finding -List $malware -Severity 'Red' -Category 'Malware Indicator' -Item ($t.ThreatName -as [string]) -Reason 'Confirmed by Windows Defender detection' -Location ($t.Resources -join '; ')
            } catch {
                Write-Log -Level WARNING -Message "Threat assessment: skipped one Defender detection record due to an error: $($_.Exception.Message)"
            }
        }
    }

    # --- Clean summary (representative, not exhaustive - avoids dumping the whole system as "clean") ---
    if ($CollectedData.RunningProcesses) {
        try {
            $cleanProcs = $CollectedData.RunningProcesses | Where-Object {
                $_ -and $_.SignatureStatus -eq 'Valid' -and $_.ExecutablePath -match '^(C:\\Windows\\|C:\\Program Files)'
            } | Select-Object -ExpandProperty Name -Unique
            foreach ($cp in ($cleanProcs | Select-Object -First 50)) {
                Add-Finding -List $clean -Severity 'Green' -Category 'Clean Item' -Item $cp -Reason 'Validly signed executable running from a standard system/program-files path' -Location $null
            }
        } catch {
            Write-Log -Level WARNING -Message "Threat assessment: clean-item summary encountered an error: $($_.Exception.Message)"
        }
    }

    return [PSCustomObject]@{
        MalwareIndicators          = $malware
        TokenStealers              = $stealers
        RemoteAccessSoftware       = $remoteAccess
        BrowserExtensionsFlagged   = $extensionsFlagged
        RecentlyDownloadedFlagged  = $recentExeFlagged
        SuspiciousDnsRequests      = $suspiciousDns
        TimestampAnomalies         = $timestompFlagged
        CleanItemsSample           = $clean
        SummaryCounts              = [PSCustomObject]@{
            Red    = ($malware.Count + $stealers.Count + $remoteAccess.Count + @($timestompFlagged | Where-Object { $_.Severity -eq 'Red' }).Count)
            Yellow = ($extensionsFlagged.Count + $recentExeFlagged.Count + $suspiciousDns.Count + @($timestompFlagged | Where-Object { $_.Severity -eq 'Yellow' }).Count)
            Green  = $clean.Count
        }
    }
}

#====================================================================
# Timeline Generation
#====================================================================

function New-ForensicTimeline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CollectedData
    )

    $timeline = New-Object System.Collections.Generic.List[object]

    try {
        if ($CollectedData.EventLogs -and $CollectedData.EventLogs.NotableSecurityEvents) {
            foreach ($e in $CollectedData.EventLogs.NotableSecurityEvents) {
                $timeline.Add([PSCustomObject]@{
                    Timestamp = $e.TimeCreated
                    Source    = 'Security Event Log'
                    EventType = $e.EventType
                    Detail    = "EventID $($e.Id)"
                })
            }
        }

        if ($CollectedData.EventLogs -and $CollectedData.EventLogs.NotableSystemEvents) {
            foreach ($e in $CollectedData.EventLogs.NotableSystemEvents) {
                $timeline.Add([PSCustomObject]@{
                    Timestamp = $e.TimeCreated
                    Source    = 'System Event Log'
                    EventType = $e.EventType
                    Detail    = "EventID $($e.Id) ($($e.ProviderName))"
                })
            }
        }

        if ($CollectedData.InstalledSoftware) {
            foreach ($s in ($CollectedData.InstalledSoftware | Where-Object { $_.InstallDate })) {
                $parsedDate = $null
                if ($s.InstallDate -match '^\d{8}$') {
                    try { $parsedDate = [DateTime]::ParseExact($s.InstallDate, 'yyyyMMdd', $null) } catch { $parsedDate = $null }
                }
                if ($parsedDate) {
                    $timeline.Add([PSCustomObject]@{
                        Timestamp = $parsedDate
                        Source    = 'Installed Software'
                        EventType = 'Software Installed'
                        Detail    = $s.DisplayName
                    })
                }
            }
        }

        if ($CollectedData.UserAssist) {
            foreach ($u in ($CollectedData.UserAssist | Where-Object { $_.LastExecuted })) {
                $timeline.Add([PSCustomObject]@{
                    Timestamp = $u.LastExecuted
                    Source    = 'UserAssist'
                    EventType = 'Program Execution'
                    Detail    = $u.DecodedPath
                })
            }
        }

        if ($CollectedData.ScheduledTasks) {
            foreach ($t in ($CollectedData.ScheduledTasks | Where-Object { $_.LastRunTime })) {
                $timeline.Add([PSCustomObject]@{
                    Timestamp = $t.LastRunTime
                    Source    = 'Scheduled Tasks'
                    EventType = 'Task Executed'
                    Detail    = $t.TaskName
                })
            }
        }

        if ($CollectedData.PrefetchArtifacts) {
            foreach ($p in ($CollectedData.PrefetchArtifacts | Where-Object { $_.LastExecuted })) {
                $timeline.Add([PSCustomObject]@{
                    Timestamp = $p.LastExecuted
                    Source    = 'Prefetch'
                    EventType = 'Program Execution'
                    Detail    = $p.ExecutableName
                })
            }
        }

        if ($CollectedData.DefenderDetections -and $CollectedData.DefenderDetections.ThreatDetections) {
            foreach ($d in ($CollectedData.DefenderDetections.ThreatDetections | Where-Object { $_.InitialDetectionTime })) {
                $timeline.Add([PSCustomObject]@{
                    Timestamp = $d.InitialDetectionTime
                    Source    = 'Windows Defender'
                    EventType = 'Malware Detected'
                    Detail    = "$($d.ThreatName) ($($d.ProcessName))"
                })
            }
        }

        if ($CollectedData.DefenderDetections -and $CollectedData.DefenderDetections.OperationalEvents) {
            foreach ($e in ($CollectedData.DefenderDetections.OperationalEvents | Where-Object { $_.TimeCreated })) {
                $timeline.Add([PSCustomObject]@{
                    Timestamp = $e.TimeCreated
                    Source    = 'Windows Defender Operational Log'
                    EventType = $e.EventType
                    Detail    = "EventID $($e.Id)"
                })
            }
        }

        if ($CollectedData.RecentDownloadedExecutables) {
            foreach ($f in ($CollectedData.RecentDownloadedExecutables | Where-Object { $_.Created })) {
                $timeline.Add([PSCustomObject]@{
                    Timestamp = $f.Created
                    Source    = 'Recently Downloaded Executable'
                    EventType = 'File Created'
                    Detail    = $f.FullPath
                })
            }
        }

        if ($CollectedData.MftTimestampAnomalies) {
            foreach ($m in ($CollectedData.MftTimestampAnomalies | Where-Object { $_.Created })) {
                $timeline.Add([PSCustomObject]@{
                    Timestamp = $m.Created
                    Source    = 'MFT Timestamp Anomaly'
                    EventType = "Timestamp Anomaly ($($m.Severity))"
                    Detail    = "$($m.FullPath) - $($m.Anomalies)"
                })
            }
        }
    } catch {
        Write-Log -Level WARNING -Message "Timeline generation encountered an error: $($_.Exception.Message)"
    }

    return ($timeline | Where-Object { $_.Timestamp } | Sort-Object Timestamp)
}

#====================================================================
# Report Export
#====================================================================

function Get-FlattenedReportSections {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$CollectedData
    )

    $sections = New-Object System.Collections.Generic.List[object]

    foreach ($key in $CollectedData.Keys) {
        $data = $CollectedData[$key]
        if ($null -eq $data) {
            $sections.Add([PSCustomObject]@{ Title = $key; Data = $null })
            continue
        }

        if ($data -is [System.Collections.IDictionary]) {
            foreach ($dictKey in $data.Keys) {
                $sections.Add([PSCustomObject]@{ Title = "$key-$dictKey"; Data = $data[$dictKey] })
            }
            continue
        }

        $isContainer = ($data -is [PSCustomObject]) -and (-not ($data -is [System.Collections.ICollection]))
        if ($isContainer) {
            foreach ($prop in $data.PSObject.Properties) {
                $sections.Add([PSCustomObject]@{ Title = "$key-$($prop.Name)"; Data = $prop.Value })
            }
        } else {
            $sections.Add([PSCustomObject]@{ Title = $key; Data = $data })
        }
    }

    return $sections
}

function Export-DataToFormats {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    if ($null -eq $Data) {
        Write-Log -Level DEBUG -Message "No data to export for section '$Name'."
        return
    }

    $safeName = ConvertTo-SafeFileName -Name $Name

    try {
        $csvPath = Join-Path -Path (Join-Path $OutputPath 'CSV') -ChildPath "$safeName.csv"
        $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        $Script:ReportFiles.Add($csvPath)
    } catch {
        Write-Log -Level WARNING -Message "CSV export failed for '$Name': $($_.Exception.Message)"
    }

    try {
        $jsonPath = Join-Path -Path (Join-Path $OutputPath 'JSON') -ChildPath "$safeName.json"
        $Data | ConvertTo-Json -Depth 6 -ErrorAction Stop | Out-File -FilePath $jsonPath -Encoding UTF8 -ErrorAction Stop
        $Script:ReportFiles.Add($jsonPath)
    } catch {
        Write-Log -Level WARNING -Message "JSON export failed for '$Name': $($_.Exception.Message)"
    }

    try {
        $txtPath = Join-Path -Path (Join-Path $OutputPath 'TXT') -ChildPath "$safeName.txt"
        $Data | Format-List * | Out-File -FilePath $txtPath -Encoding UTF8 -ErrorAction Stop
        $Script:ReportFiles.Add($txtPath)
    } catch {
        Write-Log -Level WARNING -Message "TXT export failed for '$Name': $($_.Exception.Message)"
    }
}

function ConvertTo-HtmlTableFragment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Data
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("<h2>$([System.Net.WebUtility]::HtmlEncode([string]$Title))</h2>")

    # Build $rows with an explicit foreach instead of `@($Data) | Where-Object {...}`.
    # Several sections pass a strongly-typed System.Collections.Generic.List[object]
    # (e.g. the ThreatAssessment finding lists, browser extension/history lists) as
    # $Data. Piping a generic List through Where-Object for filtering can trip up
    # PowerShell's pipeline parameter binding for that type ("Argument types do not
    # match"), whereas a plain foreach enumerates any IEnumerable uniformly and safely.
    $rows = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Data) {
        foreach ($item in $Data) {
            if ($null -ne $item) { $rows.Add($item) }
        }
    }

    if ($rows.Count -eq 0) {
        [void]$sb.AppendLine("<p class='empty'>No data collected or artifact not present on this system.</p>")
        return $sb.ToString()
    }

    # Simple/primitive rows (strings, numbers, dictionaries, etc.) don't have
    # meaningful PSObject properties to tabulate - render as a single-column list instead.
    $allSimple = $true
    foreach ($r in $rows) {
        if (($r -is [PSCustomObject]) -or ($r -is [System.Management.Automation.PSObject] -and $r.PSObject.Properties.Count -gt 0 -and -not ($r -is [string]))) {
            if (-not ($r -is [string]) -and -not ($r -is [System.Collections.IDictionary]) -and $r.PSObject.Properties.Name.Count -gt 0) {
                $allSimple = $false
            }
        }
    }

    if ($allSimple) {
        [void]$sb.AppendLine('<table><thead><tr><th>Value</th></tr></thead><tbody>')
        foreach ($row in $rows) {
            $text = ''
            try { $text = [string]$row } catch { $text = '(unable to render value)' }
            [void]$sb.AppendLine("<tr><td>$([System.Net.WebUtility]::HtmlEncode($text))</td></tr>")
        }
        [void]$sb.AppendLine('</tbody></table>')
        return $sb.ToString()
    }

    # Union property names across all rows so heterogeneous record shapes don't
    # silently drop columns (or crash when row[0] isn't representative).
    $propertySet = New-Object System.Collections.Generic.List[string]
    foreach ($row in $rows) {
        try {
            foreach ($p in $row.PSObject.Properties.Name) {
                if (-not $propertySet.Contains($p)) { [void]$propertySet.Add($p) }
            }
        } catch { }
    }
    $properties = $propertySet

    [void]$sb.AppendLine("<table><thead><tr>")
    foreach ($p in $properties) {
        [void]$sb.AppendLine("<th>$([System.Net.WebUtility]::HtmlEncode($p))</th>")
    }
    [void]$sb.AppendLine("</tr></thead><tbody>")

    foreach ($row in $rows) {
        [void]$sb.AppendLine("<tr>")
        foreach ($p in $properties) {
            $text = ''
            try {
                $value = $row.$p
                $text = if ($null -eq $value) { '' } else { [string]$value }
            } catch {
                $text = '(unable to render value)'
            }
            [void]$sb.AppendLine("<td>$([System.Net.WebUtility]::HtmlEncode($text))</td>")
        }
        [void]$sb.AppendLine("</tr>")
    }
    [void]$sb.AppendLine("</tbody></table>")

    return $sb.ToString()
}

function Export-HtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$Sections,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [bool]$RanAsAdministrator
    )

    try {
        $htmlPath = Join-Path -Path (Join-Path $OutputPath 'HTML') -ChildPath 'ForensicReport.html'
        $sb = New-Object System.Text.StringBuilder

        [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="UTF-8">')
        [void]$sb.AppendLine("<title>Windows Forensic Report - $([System.Net.WebUtility]::HtmlEncode($Script:ComputerName))</title>")
        [void]$sb.AppendLine('<style>
body { font-family: "Segoe UI", Arial, sans-serif; margin: 20px; color: #1a1a1a; background: #f7f8fa; }
h1 { color: #14213d; border-bottom: 3px solid #14213d; padding-bottom: 8px; }
h2 { color: #1d3557; margin-top: 32px; border-left: 4px solid #457b9d; padding-left: 8px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 16px; background: #fff; }
th, td { border: 1px solid #d3d6db; padding: 6px 10px; text-align: left; font-size: 12px; word-break: break-word; }
th { background: #1d3557; color: #fff; }
tr:nth-child(even) { background: #f0f2f5; }
.meta { background: #fff; border: 1px solid #d3d6db; padding: 12px; margin-bottom: 20px; }
.empty { color: #888; font-style: italic; }
.banner { background: #fff3cd; border: 1px solid #ffe69c; padding: 10px; margin-bottom: 16px; font-size: 13px; }
</style>')
        [void]$sb.AppendLine('</head><body>')
        [void]$sb.AppendLine('<h1>Windows Forensic Report</h1>')
        [void]$sb.AppendLine("<div class='meta'>")
        [void]$sb.AppendLine("<strong>Computer Name:</strong> $([System.Net.WebUtility]::HtmlEncode($Script:ComputerName))<br/>")
        [void]$sb.AppendLine("<strong>Collection Start:</strong> $($Script:StartTime)<br/>")
        [void]$sb.AppendLine("<strong>Report Generated:</strong> $(Get-Date)<br/>")
        [void]$sb.AppendLine("<strong>Toolkit Version:</strong> $($Script:ToolVersion)<br/>")
        [void]$sb.AppendLine("<strong>Collected By:</strong> $([System.Net.WebUtility]::HtmlEncode("$env:USERDOMAIN\$env:USERNAME"))<br/>")
        [void]$sb.AppendLine("<strong>Ran As Administrator:</strong> $RanAsAdministrator<br/>")
        [void]$sb.AppendLine('</div>')

        if (-not $RanAsAdministrator) {
            [void]$sb.AppendLine("<div class='banner'>This collection was run WITHOUT Administrator privileges. Some artifacts (Security event log, BitLocker, other-user registry hives) may be incomplete or missing.</div>")
        }

        foreach ($section in $Sections) {
            try {
                [void]$sb.AppendLine((ConvertTo-HtmlTableFragment -Title $section.Title -Data $section.Data))
            } catch {
                Write-Log -Level WARNING -Message "HTML report: skipped section '$($section.Title)' due to an error: $($_.Exception.Message)"
                [void]$sb.AppendLine("<h2>$([System.Net.WebUtility]::HtmlEncode([string]$section.Title))</h2><p class='empty'>This section could not be rendered.</p>")
            }
        }

        [void]$sb.AppendLine('</body></html>')
        $sb.ToString() | Out-File -FilePath $htmlPath -Encoding UTF8 -ErrorAction Stop
        $Script:ReportFiles.Add($htmlPath)
        Write-Log -Level INFO -Message "HTML report generated: $htmlPath"
    } catch {
        Write-Log -Level ERROR -Message "HTML report generation failed: $($_.Exception.Message)"
    }
}

function Export-Reports {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$CollectedData,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [bool]$RanAsAdministrator
    )

    Write-Log -Level INFO -Message "Exporting collected artifacts to CSV/JSON/TXT..."
    $sections = Get-FlattenedReportSections -CollectedData $CollectedData
    foreach ($section in $sections) {
        Export-DataToFormats -Name $section.Title -Data $section.Data -OutputPath $OutputPath
    }

    Write-Log -Level INFO -Message "Building consolidated HTML report..."
    Export-HtmlReport -Sections $sections -OutputPath $OutputPath -RanAsAdministrator $RanAsAdministrator
}

#====================================================================
# Evidence Integrity (Hashing / Manifest / Archive)
#====================================================================

function Get-ReportHashManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $hashList = New-Object System.Collections.Generic.List[object]

    foreach ($file in $Script:ReportFiles) {
        try {
            if (Test-Path -LiteralPath $file) {
                $hash     = Get-FileSha256Hash -FilePath $file
                $fileInfo = Get-Item -LiteralPath $file
                $relative = $fileInfo.FullName
                if ($relative.StartsWith($OutputPath)) {
                    $relative = $relative.Substring($OutputPath.Length).TrimStart('\', '/')
                }
                $hashList.Add([PSCustomObject]@{
                    FileName     = $fileInfo.Name
                    RelativePath = $relative
                    SizeBytes    = $fileInfo.Length
                    SHA256       = $hash
                })
            }
        } catch {
            Write-Log -Level WARNING -Message "Hashing failed for '$file': $($_.Exception.Message)"
        }
    }

    try {
        $hashesCsv = Join-Path -Path (Join-Path $OutputPath 'Hashes') -ChildPath 'file_hashes.csv'
        $hashList | Export-Csv -Path $hashesCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

        $hashesJson = Join-Path -Path (Join-Path $OutputPath 'Hashes') -ChildPath 'file_hashes.json'
        $hashList | ConvertTo-Json -Depth 4 -ErrorAction Stop | Out-File -FilePath $hashesJson -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Log -Level WARNING -Message "Failed to write hash manifest files: $($_.Exception.Message)"
    }

    return $hashList
}

function New-CaseManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [array]$HashList,

        [Parameter(Mandatory = $true)]
        [bool]$RanAsAdministrator
    )

    try {
        $manifest = [ordered]@{
            ToolName            = 'Windows Forensic Toolkit'
            ToolVersion         = $Script:ToolVersion
            ComputerName        = $Script:ComputerName
            CollectedBy         = "$env:USERDOMAIN\$env:USERNAME"
            RanAsAdministrator  = $RanAsAdministrator
            CollectionStartUtc  = $Script:StartTime.ToUniversalTime().ToString('o')
            CollectionEndUtc    = (Get-Date).ToUniversalTime().ToString('o')
            PowerShellVersion   = $PSVersionTable.PSVersion.ToString()
            OSVersion           = [System.Environment]::OSVersion.VersionString
            OutputPath          = $OutputPath
            TotalFilesCollected = @($HashList).Count
            Files               = $HashList
        }

        $manifestPath = Join-Path -Path $OutputPath -ChildPath 'manifest.json'
        $manifest | ConvertTo-Json -Depth 6 -ErrorAction Stop | Out-File -FilePath $manifestPath -Encoding UTF8 -ErrorAction Stop
        Write-Log -Level INFO -Message "Manifest written: $manifestPath"
        return $manifestPath
    } catch {
        Write-Log -Level ERROR -Message "Manifest generation failed: $($_.Exception.Message)"
        return $null
    }
}

function Compress-ReportArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        $parent  = Split-Path -Path $OutputPath -Parent
        $leaf    = Split-Path -Path $OutputPath -Leaf
        $zipPath = Join-Path -Path $parent -ChildPath "$leaf.zip"

        if (Test-Path -LiteralPath $zipPath) {
            Remove-Item -LiteralPath $zipPath -Force -ErrorAction Stop
        }

        Compress-Archive -Path (Join-Path $OutputPath '*') -DestinationPath $zipPath -CompressionLevel Optimal -ErrorAction Stop
        Write-Log -Level INFO -Message "Evidence archive created: $zipPath"
        return $zipPath
    } catch {
        Write-Log -Level ERROR -Message "Archive compression failed: $($_.Exception.Message)"
        return $null
    }
}

#====================================================================
# Main
#====================================================================

function Main {
    [CmdletBinding()]
    param()

    if (-not (Initialize-OutputDirectory -Path $OutputPath)) {
        return
    }

    $Script:LogFilePath = Join-Path -Path $OutputPath -ChildPath 'collection.log'

    Write-Log -Level INFO -Message '========================================================'
    Write-Log -Level INFO -Message " Windows Forensic Toolkit v$($Script:ToolVersion)"
    Write-Log -Level INFO -Message " Computer: $($Script:ComputerName) | User: $env:USERDOMAIN\$env:USERNAME"
    Write-Log -Level INFO -Message " Output:   $OutputPath"
    Write-Log -Level INFO -Message '========================================================'

    $isAdmin = Test-IsAdministrator
    if (-not $isAdmin) {
        Write-Log -Level WARNING -Message 'Script is NOT running with Administrator privileges. Some artifacts (Security event log, BitLocker, other-user registry hives) may be incomplete.'
    } else {
        Write-Log -Level INFO -Message 'Running with Administrator privileges.'
    }

    $collected = [ordered]@{}

    $collected['SystemInformation']  = Invoke-Collector -Name 'System Information'   -ScriptBlock { Get-SystemInformation }
    $collected['UserAccounts']       = Invoke-Collector -Name 'User Accounts'        -ScriptBlock { Get-UserInformation }
    $collected['EventLogs']          = Invoke-Collector -Name 'Event Logs'           -ScriptBlock { Get-EventLogs -MaxEntries $MaxEventLogEntries }
    $collected['SecurityStatus']     = Invoke-Collector -Name 'Security Status'      -ScriptBlock { Get-SecurityStatus }
    $collected['InstalledSoftware']  = Invoke-Collector -Name 'Installed Software'   -ScriptBlock { Get-InstalledSoftware }
    $collected['Services']           = Invoke-Collector -Name 'Services'             -ScriptBlock { Get-Services }
    $collected['StartupItems']       = Invoke-Collector -Name 'Startup Items'        -ScriptBlock { Get-StartupItems }
    $collected['RegistryRunKeys']    = Invoke-Collector -Name 'Registry Run Keys'    -ScriptBlock { Get-RegistryRunKeys }
    $collected['ScheduledTasks']     = Invoke-Collector -Name 'Scheduled Tasks'      -ScriptBlock { Get-ScheduledTasksInfo }
    $collected['USBHistory']         = Invoke-Collector -Name 'USB History'          -ScriptBlock { Get-USBHistory }
    $collected['Drivers']            = Invoke-Collector -Name 'Drivers'              -ScriptBlock { Get-DriverInformation }
    $collected['NetworkInformation'] = Invoke-Collector -Name 'Network Information'  -ScriptBlock { Get-NetworkInformation }
    $collected['InstalledUpdates']   = Invoke-Collector -Name 'Installed Updates'    -ScriptBlock { Get-InstalledUpdates }
    $collected['UserAssist']         = Invoke-Collector -Name 'UserAssist Artifacts' -ScriptBlock { Get-UserAssistArtifacts }
    $collected['RecentDocs']         = Invoke-Collector -Name 'Recent Documents'     -ScriptBlock { Get-RecentDocsArtifacts }

    $browserData = Invoke-Collector -Name 'Browser Artifacts' -ScriptBlock { Get-BrowserArtifacts -DownloadLookbackDays $RecentDownloadDays }
    $collected['BrowserExtensions']         = $browserData.Extensions
    $collected['BrowserSavedPasswordIndicators'] = $browserData.SavedPasswordIndicators
    $collected['BrowserUrlHistorySample']   = $browserData.BrowserUrlHistorySample

    $collected['PrefetchArtifacts']  = Invoke-Collector -Name 'Prefetch Artifacts'    -ScriptBlock { Get-PrefetchArtifacts }
    $collected['RecentlyExecutedPrograms'] = Invoke-Collector -Name 'Recently Executed Programs' -ScriptBlock {
        Get-RecentlyExecutedPrograms -UserAssistData $collected['UserAssist'] -PrefetchData $collected['PrefetchArtifacts']
    }

    $collected['DnsHistory']         = Invoke-Collector -Name 'DNS Query History'     -ScriptBlock { Get-DnsQueryHistory }
    $collected['RecentDownloadedExecutables'] = Invoke-Collector -Name 'Recently Downloaded Executables' -ScriptBlock {
        Get-RecentDownloadedExecutables -LookbackDays $RecentDownloadDays
    }
    $collected['RecentExecutables']  = Invoke-Collector -Name 'Recent Executables' -ScriptBlock {
        Get-RecentExecutables -LookbackDays $RecentExecutableDays
    }
    $collected['SuspiciousPaths']    = Invoke-Collector -Name 'Suspicious Path Executables' -ScriptBlock {
        Get-SuspiciousPathExecutables
    }
    $collected['ADS']                = Invoke-Collector -Name 'Alternate Data Streams' -ScriptBlock {
        Get-AlternateDataStreams -MaxDepth $AdsScanMaxDepth
    }
    $collected['MftVolumeInfo']         = Invoke-Collector -Name 'MFT Volume Information' -ScriptBlock { Get-NtfsMftVolumeInfo }
    $collected['MftTimestampAnomalies'] = Invoke-Collector -Name 'MFT Timestamp Anomalies' -ScriptBlock {
        Get-MftTimestampAnomalies -LookbackDays $MftScanDays
    }
    $collected['TimestompIndicators']   = Invoke-Collector -Name 'Timestomping Indicators' -ScriptBlock {
        Get-TimestompIndicators -LookbackDays $TimestompScanDays
    }

    Write-Log -Level INFO -Message 'Starting collector: Full $MFT Record Collection (raw volume parse; can take a while on large volumes)'
    try {
        Invoke-FullMftCollection -OutputPath $OutputPath -MaxRecordsPerVolume $MftMaxRecordsPerVolume
        Write-Log -Level INFO -Message 'Completed collector: Full $MFT Record Collection'
    } catch {
        Write-Log -Level ERROR -Message "Collector 'Full `$MFT Record Collection' failed: $($_.Exception.Message)"
    }
    $collected['DefenderDetections'] = Invoke-Collector -Name 'Windows Defender Detections' -ScriptBlock { Get-DefenderDetections }
    $collected['RunningProcesses']   = Invoke-Collector -Name 'Running Processes' -ScriptBlock {
        Get-RunningProcessSnapshot -SuspectedCompromiseTime $SuspectedCompromiseTime -WindowMinutes $CompromiseWindowMinutes
    }

    Write-Log -Level INFO -Message 'Starting collector: Threat Assessment'
    try {
        $collected['ThreatAssessment'] = Get-ThreatAssessment -CollectedData $collected
        Write-Log -Level INFO -Message 'Completed collector: Threat Assessment'
    } catch {
        Write-Log -Level ERROR -Message "Collector 'Threat Assessment' failed: $($_.Exception.Message)"
        $collected['ThreatAssessment'] = $null
    }

    Write-Log -Level INFO -Message 'Starting collector: Forensic Timeline'
    try {
        $collected['Timeline'] = New-ForensicTimeline -CollectedData $collected
        Write-Log -Level INFO -Message 'Completed collector: Forensic Timeline'
    } catch {
        Write-Log -Level ERROR -Message "Collector 'Forensic Timeline' failed: $($_.Exception.Message)"
        $collected['Timeline'] = $null
    }

    Export-Reports -CollectedData $collected -OutputPath $OutputPath -RanAsAdministrator $isAdmin

    Write-Log -Level INFO -Message 'Exporting raw Windows Defender Operational event log (Defender.evtx)...'
    Export-DefenderEventLogEvtx -OutputPath $OutputPath | Out-Null

    Write-Log -Level INFO -Message 'Computing SHA-256 hashes for all report files...'
    $hashList = Get-ReportHashManifest -OutputPath $OutputPath

    Write-Log -Level INFO -Message 'Writing case manifest...'
    New-CaseManifest -OutputPath $OutputPath -HashList $hashList -RanAsAdministrator $isAdmin | Out-Null

    if (-not $SkipZip) {
        Write-Log -Level INFO -Message 'Compressing evidence package...'
        Compress-ReportArchive -OutputPath $OutputPath | Out-Null
    } else {
        Write-Log -Level INFO -Message 'Skipping ZIP compression (per -SkipZip).'
    }

    $duration = (Get-Date) - $Script:StartTime
    Write-Log -Level INFO -Message '========================================================'
    Write-Log -Level INFO -Message " Collection complete. Duration: $($duration.ToString('hh\:mm\:ss'))"
    Write-Log -Level INFO -Message " Total report files: $($Script:ReportFiles.Count)"
    Write-Log -Level INFO -Message " Output folder: $OutputPath"
    Write-Log -Level INFO -Message '========================================================'

    Write-Host ''
    Write-Host 'Forensic collection finished.' -ForegroundColor Green
    Write-Host "Evidence folder: $OutputPath" -ForegroundColor Green
}

# Entry point
Main
