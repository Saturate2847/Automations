[CmdletBinding()]
param(
    [string]$OutputPath = 'C:\Temp\SystemDrive-Corruption-Diagnostic.txt',
    [switch]$SkipScans
)

# Read-only diagnostic. It never runs repair commands, changes files, or restarts the computer.
$ErrorActionPreference = 'SilentlyContinue'
$lines = [System.Collections.Generic.List[string]]::new()
$findings = [System.Collections.Generic.List[object]]::new()

function Write-Line([string]$Text = '') { $lines.Add($Text) }
function Add-Finding([string]$Severity, [string]$Reason, [string]$Evidence, [string]$HowDetermined) {
    $findings.Add([pscustomobject]@{ Severity=$Severity; Reason=$Reason; Evidence=$Evidence; HowDetermined=$HowDetermined })
}
function Section([string]$Name) { Write-Line ''; Write-Line ('=' * 78); Write-Line $Name; Write-Line ('=' * 78) }
function Invoke-ReadOnlyCommand([string]$FilePath, [string[]]$ArgumentList) {
    try {
        $output = & $FilePath @ArgumentList 2>&1 | Out-String
        return [pscustomobject]@{ ExitCode=$LASTEXITCODE; Output=$output }
    } catch { return [pscustomobject]@{ ExitCode=-1; Output=$_.Exception.Message } }
}

New-Item -ItemType Directory -Path (Split-Path $OutputPath -Parent) -Force | Out-Null
Write-Line 'System Drive Corruption Diagnostic (read-only)'
Write-Line "Started: $(Get-Date)"
Write-Line "Computer: $env:COMPUTERNAME | User: $env:USERNAME | PowerShell: $($PSVersionTable.PSVersion)"
Write-Line 'Repair operations are intentionally excluded. SFC, DISM, and CHKDSK are run in verification/scan modes only.'

Section '1. Executive findings'
if (-not $SkipScans) {
    $sfc = Invoke-ReadOnlyCommand "$env:SystemRoot\System32\sfc.exe" @('/verifyonly')
    $dism = Invoke-ReadOnlyCommand "$env:SystemRoot\System32\Dism.exe" @('/Online','/Cleanup-Image','/ScanHealth')
    $chkdsk = Invoke-ReadOnlyCommand "$env:SystemRoot\System32\chkdsk.exe" @('C:','/scan')
} else {
    $sfc = [pscustomobject]@{ ExitCode=$null; Output='Skipped by -SkipScans' }
    $dism = [pscustomobject]@{ ExitCode=$null; Output='Skipped by -SkipScans' }
    $chkdsk = [pscustomobject]@{ ExitCode=$null; Output='Skipped by -SkipScans' }
}

if ($sfc.Output -match 'found corrupt files|cannot repair|could not perform|corruption') {
    Add-Finding 'HIGH' 'System File Checker reported Windows file corruption or could not complete verification.' ("ExitCode=$($sfc.ExitCode); $($sfc.Output -replace '\s+',' ')") 'Ran sfc.exe /verifyonly and matched its reported corruption/verification status.'
} elseif ($sfc.ExitCode -eq 0) { Add-Finding 'INFO' 'SFC did not report protected system file corruption.' "ExitCode=$($sfc.ExitCode)" 'Ran sfc.exe /verifyonly and observed a successful result.' }

if ($dism.Output -match 'corruption (is|has been) detected|repairable|non-repairable|error' -and $dism.Output -notmatch 'No component store corruption detected') {
    $severity = if ($dism.Output -match 'non-repairable') { 'HIGH' } else { 'MEDIUM' }
    Add-Finding $severity 'DISM reported component store corruption or a servicing scan error.' ("ExitCode=$($dism.ExitCode); $($dism.Output -replace '\s+',' ')") 'Ran DISM /Online /Cleanup-Image /ScanHealth and matched its component-store status.'
} elseif ($dism.ExitCode -eq 0) { Add-Finding 'INFO' 'DISM did not report component store corruption.' "ExitCode=$($dism.ExitCode)" 'Ran DISM /Online /Cleanup-Image /ScanHealth and observed a successful result.' }

if ($chkdsk.Output -match 'Windows has found problems|corrupt|bad sectors|unable to|errors found') {
    Add-Finding 'HIGH' 'CHKDSK reported file-system errors, corruption, or possible bad sectors on C:.' ("ExitCode=$($chkdsk.ExitCode); $($chkdsk.Output -replace '\s+',' ')") 'Ran chkdsk C: /scan and matched its file-system and volume-health output.'
} elseif ($chkdsk.ExitCode -eq 0) { Add-Finding 'INFO' 'CHKDSK did not report file-system corruption during the online scan.' "ExitCode=$($chkdsk.ExitCode)" 'Ran chkdsk C: /scan and observed a successful result.' }

foreach ($f in $findings) { Write-Line ("[{0}] {1}`r`n  Evidence: {2}`r`n  Determined by: {3}" -f $f.Severity,$f.Reason,$f.Evidence,$f.HowDetermined) }

Section '2. SFC verification output'
Write-Line "Exit code: $($sfc.ExitCode)"
Write-Line $sfc.Output

Section '3. DISM component-store scan output'
Write-Line "Exit code: $($dism.ExitCode)"
Write-Line $dism.Output

Section '4. CHKDSK online scan output'
Write-Line "Exit code: $($chkdsk.ExitCode)"
Write-Line $chkdsk.Output

Section '5. Disk and volume health'
$volume = Get-Volume -DriveLetter C
if ($volume) { Write-Line "C: FileSystem=$($volume.FileSystem); Health=$($volume.HealthStatus); Size=$([math]::Round($volume.Size/1GB,2)) GB; Free=$([math]::Round($volume.SizeRemaining/1GB,2)) GB" }
$physical = Get-PhysicalDisk
if ($physical) { foreach ($disk in $physical) { Write-Line "PhysicalDisk: $($disk.FriendlyName) | Health=$($disk.HealthStatus) | Operational=$($disk.OperationalStatus) | Size=$([math]::Round($disk.Size/1GB,2)) GB" } }
$diskEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7,9,11,15,51,55,57,98,129,153,157; StartTime=(Get-Date).AddDays(-30)}
if ($diskEvents) {
    Add-Finding 'HIGH' 'The System log contains recent storage or file-system error events.' ((($diskEvents | Select-Object -First 10 | ForEach-Object { "$($_.TimeCreated) ID $($_.Id): $($_.Message -replace '\s+',' ')" }) -join '; ')) 'Queried System events commonly associated with disk, NTFS, and storage path failures over the last 30 days.'
    Write-Line 'Recent storage-related System events:'
    foreach ($e in ($diskEvents | Sort-Object TimeCreated -Descending | Select-Object -First 50)) { Write-Line ("{0} | ID {1} | {2}" -f $e.TimeCreated,$e.Id,($e.Message -replace '\s+',' ')) }
} else { Write-Line 'No matching storage-related System events found in the last 30 days.' }

Section '6. Method and limitations'
Write-Line 'This report runs SFC verification, DISM component-store ScanHealth, and CHKDSK online scan without repair switches. It also reads volume/physical-disk health and recent System storage events.'
Write-Line 'A clean scan does not guarantee healthy hardware. Firmware, controller, intermittent I/O, RAID/SAN layers, and errors outside the selected event retention window may require vendor-specific diagnostics.'
Write-Line "Completed: $(Get-Date)"

[System.IO.File]::WriteAllLines($OutputPath,$lines)
Add-Content -LiteralPath $OutputPath -Value @('',('='.PadRight(78,'=')),'FINAL FINDINGS',('='.PadRight(78,'=')))
foreach ($f in $findings) { Add-Content -LiteralPath $OutputPath -Value ("[{0}] {1}`r`n  Evidence: {2}`r`n  Determined by: {3}" -f $f.Severity,$f.Reason,$f.Evidence,$f.HowDetermined) }
Write-Output "Diagnostic written to $OutputPath"

