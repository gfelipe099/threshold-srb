# threshold-srb

## What is this?
System Readiness for Business is an automated privacy-focused configuration tool which debloats and tweaks Windows 10 Enterprise N LTSC to improve it's performance and reduce the user's footprint.

## Modifications
* OS version validator before script's execution
* Script simplified
* Server tweaks removed
* Privacy settings hardened
* Security parameters hardened
* And maybe more in the future

## Getting started
Get started by opening PowerShell as administrator, then copy and right-click on the PowerShell window, this command:
> `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('https://git.io/JJVqP')"`

Or, if you prefer, allow the execution of untrusted scripts on PowerShell by using `Set-ExecutionPolicy untrusted`. Afterwards, click [here](https://raw.githubusercontent.com/gfelipe099/threshold-srb/master/threshold-srb.ps1) to download the script and execute it yourself using `.\threshold-srb.ps1`.
