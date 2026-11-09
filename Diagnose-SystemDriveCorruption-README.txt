System Drive Corruption Diagnostic

Run from an elevated PowerShell context:

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Diagnose-SystemDriveCorruption.ps1

The default report is written to:

  C:\Temp\SystemDrive-Corruption-Diagnostic.txt

The script runs only verification/scan operations:

* `sfc.exe /verifyonly`
* `DISM.exe /Online /Cleanup-Image /ScanHealth`
* `chkdsk.exe C: /scan`

It also checks volume and physical-disk health plus recent System events associated with disk, NTFS, and storage-path errors. It does not run SFC `/scannow`, DISM `/RestoreHealth`, `chkdsk /f`, `chkdsk /r`, or any other repair operation.

Use `-SkipScans` when collecting only the non-invasive health and event inventory. Scan output is still recorded in the report when scans are run.

