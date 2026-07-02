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
    [ValidateRange(1, 10)]
    [int]$MaxFileHashSizeMB = 100
)

# ---------------------------------------------------------------------------
# Script-scope state
# ---------------------------------------------------------------------------
$Script:ToolVersion  = '1.1.0'
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
        Write-Log -Level WARNING -Message "Unable to hash file '$FilePath': $($_.Exception.Message)"
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
        CleanItemsSample           = $clean
        SummaryCounts              = [PSCustomObject]@{
            Red    = ($malware.Count + $stealers.Count + $remoteAccess.Count)
            Yellow = ($extensionsFlagged.Count + $recentExeFlagged.Count + $suspiciousDns.Count)
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
