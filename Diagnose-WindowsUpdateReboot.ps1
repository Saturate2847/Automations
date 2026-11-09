[CmdletBinding()]
param(
    [string]$OutputPath = 'C:\Temp\WindowsUpdate-Reboot-Diagnostic.txt',
    [int]$EventHours = 72,
    [switch]$IncludeFullEventDetails
)

# Read-only diagnostic. It does not install updates, restart the computer, or change configuration.
$ErrorActionPreference = 'SilentlyContinue'
$script:Lines = [System.Collections.Generic.List[string]]::new()
$script:Findings = [System.Collections.Generic.List[object]]::new()

function Write-Line([string]$Text = '') { $script:Lines.Add($Text) }
function Add-Finding([string]$Severity, [string]$Reason, [string]$Evidence, [string]$HowDetermined) {
    $script:Findings.Add([pscustomobject]@{ Severity=$Severity; Reason=$Reason; Evidence=$Evidence; HowDetermined=$HowDetermined })
}
function Get-Value($Expression, $Default = 'Unavailable') {
    try { $v = & $Expression; if ($null -eq $v -or "$v" -eq '') { $Default } else { $v } } catch { $Default }
}
function Section([string]$Name) { Write-Line ''; Write-Line ('=' * 78); Write-Line $Name; Write-Line ('=' * 78) }

New-Item -ItemType Directory -Path (Split-Path $OutputPath -Parent) -Force | Out-Null
$started = Get-Date

Write-Line 'Windows Update and Reboot Diagnostic (read-only)'
Write-Line "Started: $started"
Write-Line "Computer: $env:COMPUTERNAME | User: $env:USERNAME | PowerShell: $($PSVersionTable.PSVersion)"
Write-Line "Scope: Last $EventHours hours; no remediation actions are performed."

Section '1. Executive findings'

$os = Get-CimInstance Win32_OperatingSystem
$lastBoot = $os.LastBootUpTime
$uptime = if ($lastBoot) { ((Get-Date) - $lastBoot) } else { $null }
$pending = @()
$pendingReg = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
  'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
)
foreach ($path in $pendingReg) {
    if (Test-Path $path) {
        if ($path -like '*Session Manager') { $v = (Get-ItemProperty $path).PendingFileRenameOperations; if ($v) { $pending += 'PendingFileRenameOperations' } }
        else { $pending += (Split-Path $path -Leaf) }
    }
}

$events = @()
$logs = @('System','Application','Microsoft-Windows-WindowsUpdateClient/Operational','Microsoft-Windows-Servicing/Operational')
$since = (Get-Date).AddHours(-[math]::Abs($EventHours))
foreach ($log in $logs) {
    try { $events += Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$since} -ErrorAction Stop } catch {}
}
$wuEvents = @($events | Where-Object { $_.LogName -like '*WindowsUpdate*' })
$rebootEvents = @($events | Where-Object { $_.Id -in 41,1001,1074,1076,6005,6006,6008,6009 })
$failureEvents = @($events | Where-Object { $_.Id -in 20,25,31,34,35,36,38,40,43,44 -and $_.LogName -like '*WindowsUpdate*' })

if ($pending.Count) { Add-Finding 'HIGH' 'Windows is waiting for a reboot to complete servicing.' ($pending -join ', ') 'Checked documented Windows pending-reboot registry indicators.' }
if ($failureEvents.Count) { Add-Finding 'HIGH' 'Windows Update reported update installation or applicability failures.' ("{0} Windows Update failure events; IDs: {1}" -f $failureEvents.Count,(($failureEvents.Id | Sort-Object -Unique) -join ', ')) 'Queried WindowsUpdateClient/Operational events in the selected time window and matched failure event IDs.' }
if ($rebootEvents | Where-Object Id -in 41,6008) { Add-Finding 'HIGH' 'The last period includes an unexpected shutdown or possible reboot failure.' ((($rebootEvents | Where-Object Id -in 41,6008 | Select-Object -First 5 | ForEach-Object { "$($_.TimeCreated) ID $($_.Id)" }) -join '; ')) 'Queried System event log for Kernel-Power 41 and EventLog 6008.' }
if ($uptime -and $uptime.TotalDays -gt 7) { Add-Finding 'MEDIUM' 'The computer has not completed a normal reboot recently.' ("Last boot: $lastBoot; uptime: $($uptime.ToString())") 'Read Win32_OperatingSystem.LastBootUpTime and calculated uptime.' }

if (-not $script:Findings.Count) { Add-Finding 'INFO' 'No high-confidence failure pattern was found in the selected window.' 'No pending-reboot indicators, matching Windows Update failure events, or unexpected-shutdown events were observed.' 'Correlated registry indicators, Windows Update events, and System events.' }
foreach ($f in $script:Findings) {
    Write-Line ("[{0}] {1}" -f $f.Severity,$f.Reason)
    Write-Line "  Evidence: $($f.Evidence)"
    Write-Line "  Determined by: $($f.HowDetermined)"
}

Section '2. Reboot state and shutdown evidence'
Write-Line "Last boot: $lastBoot"
Write-Line "Uptime: $($uptime)"
Write-Line "Pending reboot indicators: $(if($pending){$pending -join ', '}else{'None found'})"
Write-Line 'Recent reboot/shutdown events:'
foreach ($e in ($rebootEvents | Sort-Object TimeCreated -Descending | Select-Object -First 30)) { Write-Line ("{0} | {1} | ID {2} | {3}" -f $e.TimeCreated,$e.LogName,$e.Id,($e.Message -replace '\s+',' ')) }

Section '3. Windows Update state and history'
foreach ($svcName in 'wuauserv','bits','cryptsvc','trustedinstaller') {
    $svc = Get-Service -Name $svcName
    if ($svc) { Write-Line "${svcName}: Status=$($svc.Status); StartType=$($svc.StartType)" }
}
Write-Line 'Installed hotfixes (most recent 20):'
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 | ForEach-Object { Write-Line ("{0} | {1} | {2}" -f $_.InstalledOn,$_.HotFixID,$_.Description) }
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $count = $searcher.GetTotalHistoryCount()
    $history = if ($count -gt 0) { $searcher.QueryHistory(0,[math]::Min($count,50)) } else { @() }
    Write-Line 'Windows Update Agent history (most recent 50):'
    foreach ($h in $history) { Write-Line ("{0} | Result={1} | HResult=0x{2:X8} | {3}" -f $h.Date,$h.ResultCode,$h.HResult,$h.Title) }
} catch { Write-Line "Windows Update Agent history unavailable: $($_.Exception.Message)" }
Write-Line 'Windows Update failure events:'
foreach ($e in ($failureEvents | Sort-Object TimeCreated -Descending | Select-Object -First 50)) { Write-Line ("{0} | ID {1} | {2}" -f $e.TimeCreated,$e.Id,($e.Message -replace '\s+',' ')) }

Section '4. Servicing and update log evidence'
Write-Line 'Modern Windows Update diagnostics are ETW-based; WindowsUpdate.log may not exist until ETL data is converted.'
$etwRoots = @('C:\ProgramData\USOShared\Logs','C:\Windows\Logs\WindowsUpdate','C:\Windows\Logs\waasmedic')
foreach ($root in $etwRoots) {
    if (Test-Path $root) {
        Write-Line "ETW log root: $root"
        Get-ChildItem -LiteralPath $root -Filter '*.etl' -File -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 50 | ForEach-Object {
            Write-Line ("  {0} | {1} KB | LastWrite={2}" -f $_.FullName,[math]::Round($_.Length/1KB,1),$_.LastWriteTime)
        }
    }
}
if (Get-Command Get-WindowsUpdateLog -ErrorAction SilentlyContinue) {
    $convertedLog = Join-Path (Split-Path $OutputPath -Parent) 'WindowsUpdate-ETW-converted.log'
    try {
        Get-WindowsUpdateLog -LogPath $convertedLog -ErrorAction Stop | Out-Null
        if (Test-Path $convertedLog) {
            Write-Line "ETW conversion output: $convertedLog (last 200 lines)"
            Get-Content $convertedLog -Tail 200 | ForEach-Object { Write-Line $_ }
        }
    } catch { Write-Line "ETW conversion unavailable: $($_.Exception.Message)" }
} else { Write-Line 'Get-WindowsUpdateLog is unavailable on this system; ETL inventory was still collected.' }
foreach ($file in 'C:\Windows\Logs\CBS\CBS.log','C:\Windows\WindowsUpdate.log') {
    if (Test-Path $file) {
        Write-Line "File: $file (last 80 lines)"
        Get-Content $file -Tail 80 | ForEach-Object { Write-Line $_ }
    } else { Write-Line "File not present: $file" }
}

Section '5. Resource and configuration checks'
$drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
Write-Line "C: free space: $([math]::Round($drive.FreeSpace/1GB,2)) GB of $([math]::Round($drive.Size/1GB,2)) GB"
if ($drive.FreeSpace -lt 10GB) { Add-Finding 'MEDIUM' 'Low free space may prevent update extraction or servicing.' ("C: has $([math]::Round($drive.FreeSpace/1GB,2)) GB free") 'Read Win32_LogicalDisk for the system volume and compared free space with a 10 GB diagnostic threshold.' }
Write-Line "System architecture: $($os.OSArchitecture); Version: $($os.Version); Build: $($os.BuildNumber)"
$wuPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
if ($wuPolicy) { Write-Line 'Windows Update policy values:'; $wuPolicy.PSObject.Properties | Where-Object Name -notmatch '^PS' | ForEach-Object { Write-Line "  $($_.Name)=$($_.Value)" } }

Section '6. ConnectWise RMM clues (read-only)'
$cwServices = Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'connectwise|automate|labtech|screenconnect' -or $_.DisplayName -match 'connectwise|automate|labtech|screenconnect' }
if ($cwServices) { foreach ($s in $cwServices) { Write-Line "Service: $($s.Name) | $($s.DisplayName) | State=$($s.State) | StartMode=$($s.StartMode) | Path=$($s.PathName)" } }
else { Write-Line 'No service whose name/display name contains ConnectWise, Automate, LabTech, or ScreenConnect was found.' }
$cwPaths = @('C:\Program Files\ConnectWise','C:\Program Files (x86)\ConnectWise','C:\Windows\LTSvc','C:\Program Files\LabTech','C:\Program Files (x86)\LabTech')
foreach ($p in $cwPaths) { if (Test-Path $p) { Write-Line "Present path: $p" } }
Write-Line 'Interpretation: RMM may schedule, defer, or report patches, but Windows Update/CBS/System evidence is used to identify the local failure. RMM-specific attribution requires matching the RMM job history with these timestamps.'

Section '7. Event detail appendix'
if ($IncludeFullEventDetails) {
    foreach ($e in ($events | Sort-Object TimeCreated -Descending | Select-Object -First 250)) { Write-Line ("{0} | {1} | ID {2}`r`n{3}" -f $e.TimeCreated,$e.LogName,$e.Id,$e.Message) }
} else { Write-Line 'Omitted by default. Re-run with -IncludeFullEventDetails for up to 250 full event messages.' }

Section '8. Method and limitations'
Write-Line 'This report is evidence-based and read-only. It checks registry pending-reboot flags, Windows Update Agent history, hotfix inventory, WindowsUpdateClient and Servicing events, System reboot events, CBS/Windows Update logs, service state, disk space, policy values, and common ConnectWise service/path clues.'
Write-Line 'A missing event or log does not prove that no failure occurred: retention, log size, RMM scheduling, WSUS policy, and update metadata can affect what is visible.'
Write-Line "Completed: $(Get-Date)"

# Re-print findings discovered after the executive section (for example low disk space).
[System.IO.File]::WriteAllLines($OutputPath,$script:Lines)

# Ensure findings added later are included in a final summary block without modifying the system.
Add-Content -LiteralPath $OutputPath -Value @('',('='.PadRight(78,'=')),'FINAL FINDINGS (INCLUDING LATE CHECKS)',('='.PadRight(78,'=')))
foreach ($f in $script:Findings) { Add-Content -LiteralPath $OutputPath -Value ("[{0}] {1}`r`n  Evidence: {2}`r`n  Determined by: {3}" -f $f.Severity,$f.Reason,$f.Evidence,$f.HowDetermined) }
Write-Output "Diagnostic written to $OutputPath"

