#
# Created by Liam Powell (gfelipe099)
# A fork from ChrisTitusTech's https://github.com/ChrisTitusTech/win10script
# threshold-srb.sh file
# System Readiness for Business
# For Microsoft Windows 10 Enterprise N LTSC 2019 x64
#
Clear-Host
###### MAIN FUNCTIONS ######

### Check system version and edition ###
if (!${validatedOsVersion}) {
    New-Variable -Name validatedOsVersion -Value "10.0.17763" | Out-Null
}

if (!${validatedOsEdition}) {
	New-Variable -Name validatedOsEdition -Value "Microsoft Windows 10 Enterprise N LTSC" | Out-Null
}

if (!${OsVersion}) {
    New-Variable -Name OsVersion -Value (gwmi win32_operatingsystem).version | Out-Null
}

if (!${OsEdition}) {
	New-Variable -Name OsEdition -Value (gwmi win32_operatingsystem).caption | Out-Null
}

Function CheckOs {
    if (${OsEdition} -ne "${validatedOsEdition}") {
        Write-Output ""
        Write-Output "Sorry, the script won't execute."
        Write-Output ""
        Write-Output "The script was only made for: ${validatedOsEdition},"
        Write-Output "and you are using: ${OsEdition}."
        Write-Output ""
        Write-Output "Closing script..."
        Start-Sleep 20
        exit
        if (${OsVersion} -ne "${validatedOsVersion}") {
            Write-Output ""
            Write-Output "Sorry, the script won't continue."
            Write-Output ""
            Write-Output "The version you currently use is: v${OsVersion}, which is not supported yet."
            Write-Output "Only the version v${validatedOsVersion} is compatible."
            Write-Output ""
            Write-Output "Closing script..."
            Start-Sleep 20
            exit
        }
    }
    Startup
}

Function Startup {
	Write-Output ""
	Write-Output "System Readiness for Business"
	Write-Output ""
	Write-Output ""
	Write-Output "Starting script..."
	Start-Sleep 5
	RequireAdmin
}

## Presets ##
${Full} = @(
	"ProgramsSetup",
	"PrivacySettings",
	"SecuritySettings",
	"ServicesSettings",
	"UISettings",
	"WindowsExplorerSettings",
	"ApplicationsSettings",
	"Reboot"
    )

Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"${PSCommandPath}`" $${PSCommandArgs}" -WorkingDirectory ${pwd} -Verb RunAs
		Exit
	}
}

Function Reboot {
	Write-Output "System Readiness for Business has finished! Press any key to reboot your computer..."
	[Console]::ReadKey(${true}) | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Type String -Value "Restricted"
	Start-Sleep 5
    Restart-Computer
}

###### MAIN FUNCTIONS ######

### Programs settings ###
Function ProgramsSetup {
	Write-Output "Installing and configuring programs... "
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) | Out-Null
	choco install chocolatey-core.extension -y | Out-Null
	Import-Module BitsTransfer | Out-Null
	Start-BitsTransfer -Source "https://raw.githubusercontent.com/gfelipe099/threshold-readiness/master/ooshutup10.cfg" -Destination ooshutup10.cfg | Out-Null
	Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe | Out-Null
	./OOSU10.exe ooshutup10.cfg /quiet
	Remove-Module BitsTransfer
	choco install 7zip.install -y | Out-Null
	choco install steam -y | Out-Null
	choco install origin -y --ignore-checksums | Out-Null
	choco install firefoxesr -y | Out-Null
	choco install reddit-wallpaper-changer -y | Out-Null
	# Get-AppxPackage -allusers | Remove-AppxPackage | Out-Null
}

### Privacy settings ###
Function PrivacySettings {
	Write-Output "Configuring privacy settings..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 1 -ErrorAction SilentlyContinue
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 1 -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
		Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
		Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue | Out-Null
	Set-Service "DiagTrack" -StartupType Disabled | Out-Null
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue | Out-Null
	Set-Service "dmwappushservice" -StartupType Disabled | Out-Null
}

### Security settings ###
Function SecuritySettings {
	Write-Output "Setting up security parameters..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 2
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Type DWord -Value 2
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
	Set-NetConnectionProfile -NetworkCategory Public
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
	Set-MpPreference -EnableControlledFolderAccess Disabled
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
	bcdedit /set `{current`} bootmenupolicy Standard | Out-Null
	bcdedit /set `{current`} nx AlwaysOn | Out-Null
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" -Name "Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

### Services settings ###
Function ServicesSettings{
	Write-Output "Configuring services..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
	Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
	Set-Service "HomeGroupListener" -StartupType Disabled
	Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
	Set-Service "HomeGroupProvider" -StartupType Disabled
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
	Disable-NetFirewallRule -Name "RemoteDesktop*"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "08" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "32" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "StoragePoliciesNotified" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 0
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
	powercfg -h off | Out-Null
}

### UI settings ###
Function UISettings {
	Write-Output "Setting up UI parameters..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}

### Windows Explorer settings ###
Function WindowsExplorerSettings {
	Write-Output "Configuring Windows explorer settings..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
}

### Application settings ###
Function ApplicationsSettings {
	Write-Output "Setting up applications parameters..."
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
	Write-Output "Configuring Windows optional features..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "SearchEngine-Client-Package" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "MSRDC-Infrastructure" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "TFTP" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "TIFFIFilter" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Enable-WindowsOptionalFeature -Online -FeatureName "LegacyComponents" -All -NoRestart -WarningAction SilentlyContinue | Out-Null
	Enable-WindowsOptionalFeature -Online -FeatureName "DirectPlay" -All -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-InternetPrinting-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-LPDPrintService" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-LPRPortMonitor" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "SimpleTCP" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Enable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -All -NoRestart -WarningAction SilentlyContinue | Out-Null
	Enable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -All -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Windows-Identity-Foundation" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Client-ProjFS" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -All -NoRestart -WarningAction SilentlyContinue | Out-Null
	Enable-WindowsOptionalFeature -Online -FeatureName "NetFx4-Advsrvs" -All -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WCF-HTTP-Activation" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WCF-NonHTTP-Activation" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServer" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-CommonHttpFeatures" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpErrors" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpRedirect" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ApplicationDevelopment" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-NetFxExtensibility" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-NetFxExtensibility45" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HealthAndDiagnostics" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpLogging" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-LoggingLibraries" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-RequestMonitor" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpTracing" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-Security" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-URLAuthorization" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-RequestFiltering" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-IPSecurity" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-Performance" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpCompressionDynamic" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerManagementTools" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ManagementScriptingTools" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-IIS6ManagementCompatibility" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-Metabase" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WAS-WindowsActivationService" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WAS-ProcessModel" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WAS-NetFxEnvironment" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WAS-ConfigurationAPI" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HostableWebCore" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Enable-WindowsOptionalFeature -Online -FeatureName "WCF-Services45" -All -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WCF-HTTP-Activation45" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WCF-TCP-Activation45" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WCF-Pipe-Activation45" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WCF-MSMQ-Activation45" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Enable-WindowsOptionalFeature -Online -FeatureName "WCF-TCP-PortSharing45" -All -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-StaticContent" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-DefaultDocument" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "-DirectoryBrowsing" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebDAV" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebSockets" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ApplicationInit" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ASPNET" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ASPNET45" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "-ASP" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-CGI" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ISAPIExtensions" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ISAPIFilter" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ServerSideIncludes" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-CustomLogging" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-BasicAuthentication" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpCompressionStatic" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ManagementConsole" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ManagementService" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WMICompatibility" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-LegacyScripts" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-LegacySnapIn" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPServer" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPSvc" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPExtensibility" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "MSMQ-Container" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "MSMQ-DCOMProxy" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "MSMQ-Server" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "-ADIntegration" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "MSMQ-HTTP" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "MSMQ-Multicast" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Triggers" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-CertProvider" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WindowsAuthentication" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-DigestAuthentication" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ClientCertificateMappingAuthentication" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-IISCertificateMappingAuthentication" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ODBCLogging" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "NetFx4-AdvSrvs" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "NetFx4Extended-ASPNET45" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Deprecation" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "DataCenterBridging" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "ServicesForNFS-ClientOnly" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "ClientForNFS-Infrastructure" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "NFS-Administration" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "SmbDirect" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "HostGuardian" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "MultiPoint-Connector" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "MultiPoint-Connector-Services" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "MultiPoint-Tools" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Enable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-Default-Definitions" -All -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "HypervisorPlatform" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "VirtualMachinePlatform" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-Tools-All" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-Management-PowerShell" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-Hypervisor" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-Services" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-Management-Clients" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Client-DeviceLockdown" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Client-EmbeddedShellLauncher" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Client-EmbeddedBootExp" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Client-EmbeddedLogon" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Client-KeyboardFilter" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Client-UnifiedWriteFilter" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "DirectoryServices-ADAM-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Containers" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart -WarningAction SilentlyContinue | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Accessibility.Braille~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Analog.Holographic.Desktop~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:App.Support.QuickAssist~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Hello.Face.17658~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Hello.Face.Migration.17658~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~af-ZA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ar-SA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~as-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~az-LATN-AZ~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ba-RU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~be-BY~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~bg-BG~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~bn-BD~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~bn-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~bs-LATN-BA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ca-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~cs-CZ~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~cy-GB~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~da-DK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~de-DE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~el-GR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~en-GB~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~es-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~es-MX~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~et-EE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~eu-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~fa-IR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~fi-FI~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~fil-PH~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~fr-CA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~fr-FR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ga-IE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~gd-GB~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~gl-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~gu-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ha-LATN-NG~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~haw-US~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~he-IL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~hi-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~hr-HR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~hu-HU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~hy-AM~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~id-ID~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ig-NG~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~is-IS~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~it-IT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ja-JP~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ka-GE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~kk-KZ~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~kl-GL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~kn-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ko-KR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~kok-DEVA-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ky-KG~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~lb-LU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~lt-LT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~lv-LV~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~mi-NZ~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~mk-MK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ml-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~mn-MN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~mr-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ms-BN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ms-MY~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~mt-MT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~nb-NO~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ne-NP~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~nl-NL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~nn-NO~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~nso-ZA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~or-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~pa-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~pl-PL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ps-AF~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~pt-BR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~pt-PT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~rm-CH~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ro-RO~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ru-RU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~rw-RW~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~sah-RU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~si-LK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~sk-SK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~sl-SI~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~sq-AL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~sr-CYRL-RS~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~sr-LATN-RS~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~sv-SE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~sw-KE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ta-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~te-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~tg-CYRL-TJ~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~th-TH~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~tk-TM~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~tn-ZA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~tr-TR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~tt-RU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ug-CN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~uk-UA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~ur-PK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~uz-LATN-UZ~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~vi-VN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~wo-SN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~xh-ZA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~yo-NG~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~zh-CN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~zh-HK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~zh-TW~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Basic~~~zu-ZA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Arab~~~und-ARAB~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Beng~~~und-BENG~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Cans~~~und-CANS~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Cher~~~und-CHER~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Deva~~~und-DEVA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Ethi~~~und-ETHI~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Gujr~~~und-GUJR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Guru~~~und-GURU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Hans~~~und-HANS~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Hant~~~und-HANT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Hebr~~~und-HEBR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Jpan~~~und-JPAN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Khmr~~~und-KHMR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Knda~~~und-KNDA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Kore~~~und-KORE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Laoo~~~und-LAOO~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Mlym~~~und-MLYM~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Orya~~~und-ORYA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.PanEuropeanSupplementalFonts~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Sinh~~~und-SINH~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Syrc~~~und-SYRC~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Taml~~~und-TAML~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Telu~~~und-TELU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Fonts.Thai~~~und-THAI~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~af-ZA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~bs-LATN-BA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ca-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~cs-CZ~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~cy-GB~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~da-DK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~de-DE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~el-GR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~en-GB~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~es-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~es-MX~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~eu-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~fi-FI~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~fr-FR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ga-IE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~gd-GB~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~gl-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~hi-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~hr-HR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~id-ID~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~it-IT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ja-JP~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ko-KR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~lb-LU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~mi-NZ~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ms-BN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ms-MY~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~nb-NO~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~nl-NL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~nn-NO~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~nso-ZA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~pl-PL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~pt-BR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~pt-PT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~rm-CH~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ro-RO~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~ru-RU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~rw-RW~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sk-SK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sl-SI~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sq-AL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sr-CYRL-RS~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sr-LATN-RS~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sv-SE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~sw-KE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~tn-ZA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~tr-TR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~wo-SN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~xh-ZA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~zh-CN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~zh-HK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~zh-TW~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Handwriting~~~zu-ZA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~ar-SA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~bg-BG~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~bs-LATN-BA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~cs-CZ~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~da-DK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~de-DE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~el-GR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~en-GB~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~es-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~es-MX~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~fi-FI~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~fr-CA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~fr-FR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~hr-HR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~hu-HU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~it-IT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~ja-JP~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~ko-KR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~nb-NO~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~nl-NL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~pl-PL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~pt-BR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~pt-PT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~ro-RO~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~ru-RU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~sk-SK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~sl-SI~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~sr-CYRL-RS~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~sr-LATN-RS~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~sv-SE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~tr-TR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~zh-CN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~zh-HK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.OCR~~~zh-TW~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~de-DE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~en-AU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~en-CA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~en-GB~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~en-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~es-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~es-MX~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~fr-CA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~fr-FR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~it-IT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~ja-JP~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~pt-BR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~zh-CN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~zh-HK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.Speech~~~zh-TW~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ar-EG~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ar-SA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~bg-BG~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ca-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~cs-CZ~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~da-DK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~de-AT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~de-CH~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~de-DE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~el-GR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-AU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-CA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-GB~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-IE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~es-ES~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~es-MX~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~fi-FI~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~fr-CA~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~fr-CH~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~fr-FR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~he-IL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~hi-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~hr-HR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~hu-HU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~id-ID~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~it-IT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ja-JP~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ko-KR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ms-MY~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~nb-NO~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~nl-BE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~nl-NL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~pl-PL~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~pt-BR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~pt-PT~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ro-RO~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ru-RU~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~sk-SK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~sl-SI~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~sv-SE~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~ta-IN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~th-TH~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~tr-TR~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~vi-VN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~zh-CN~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~zh-HK~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~zh-TW~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:MathRecognizer~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Media.WindowsMediaPlayer~~~~0.0.12.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Microsoft.Onecore.StorageManagement~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Microsoft.WebDriver~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Microsoft.Windows.StorageManagement~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Msix.PackagingTool.Driver~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Add-Capability /CapabilityName:NetFX3~~~~ /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:OneCoreUAP.OneSync~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:OpenSSH.Client~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:RasCMAK.Client~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:RIP.Listener~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.BitLocker.Recovery.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.CertificateServices.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.DHCP.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.Dns.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.FileServices.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.IPAM.Client.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.LLDP.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.NetworkController.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.NetworkLoadBalancing.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.RemoteAccess.Management.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.RemoteDesktop.Services.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.ServerManager.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.Shielded.VM.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.StorageMigrationService.Management.Tools~~~~0.0.1 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.StorageReplica.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.SystemInsights.Management.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.VolumeActivation.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Rsat.WSUS.Tools~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:SNMP.Client~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Tools.DeveloperMode.Core~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Tools.DTrace.Platform~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:Tools.Graphics.DirectX~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:WMI-SNMP-Provider.Client~~~~0.0.1.0 /NoRestart | Out-Null
	DISM /Online /Remove-Capability /CapabilityName:XPS.Viewer~~~~0.0.1.0 /NoRestart | Out-Null
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue | Out-Null
}

### Parse parameters and apply preset ###
${preset} = ""
${PSCommandArgs} = ${args}
If (${args} -And ${args}[0].ToLower() -eq "-preset") {
	${preset} = Resolve-Path $(${args} | Select-Object -Skip 1)
	${PSCommandArgs} = "-preset `"${preset}`""
}

If (${args}) {
	${Full} = ${args}
	If (${preset}) {
		${Full} = Get-Content ${preset} -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
	}
}

### Start ###
CheckOs
${Full}| ForEach { Invoke-Expression $_ }
