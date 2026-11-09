Windows Update / Reboot Diagnostic

Run from an elevated PowerShell context:

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Diagnose-WindowsUpdateReboot.ps1

The default report is written to:

  C:\Temp\WindowsUpdate-Reboot-Diagnostic.txt

Optional parameters:

  -EventHours 168
      Inspect the last 7 days instead of the default 72 hours.

  -IncludeFullEventDetails
      Append up to 250 full event messages to the report.

  -OutputPath C:\Temp\custom-report.txt
      Change the report location.

ConnectWise RMM guidance:

* Run as Local System or an administrator so event logs, CBS.log, services, and registry indicators are readable.
* Capture the script's standard output and collect C:\Temp\WindowsUpdate-Reboot-Diagnostic.txt as the resulting artifact.
* Keep the job action read-only. The script does not install updates, restart the computer, start/stop services, clear caches, or change policy.
* Compare the report timestamps with the ConnectWise patch policy/job history. The script can identify local Windows evidence, but only the RMM job history can prove whether a patch was deferred, interrupted, or never dispatched.

