#
# Created by Liam Powell (gfelipe099)
# A fork from ChrisTitusTech's https://github.com/ChrisTitusTech/win10script
# threshold-srb.sh file
# System Readiness for Business
# For Microsoft Windows 10 64-bit
#
cls
### Check for OS version ###
if (!$validatedOsVersion) {
    New-Variable -Name validatedOsVersion -Value "10.0.19041"
}

if (!$systemOsVersion) {
    New-Variable -Name systemOsVersion -Value (gwmi win32_operatingsystem).version
}

Function CheckOSVersion {
    if ( (gwmi win32_operatingsystem).version -ne "${validatedOsVersion}" ) {
        Write-Output "The version v${systemOsVersion} is not supported yet."
        Write-Host "Only the version v${validatedOsVersion} is compatible."
        exit
    }
}

# Default preset
${tweaks} = @(
	"RequireAdmin",
	"ProgramsSetup",
	"PrivacySettings",
	"SecuritySettings",
	"ServicesSettings",
	"UISettings",
	"WindowsExplorerSettings",
	"ApplicationsSettings",
	"PressAnyKeyToReboot"
)

### Startup ###
Function Startup {
    Write-Output "System Readiness for Business (Windows 10 v2004 or higher)"
    Write-Output ""
    Write-Output ""
    Write-Output "PRESS ANY KEY TO EXECUTE THE SCRIPT..."
	[Console]::ReadKey(${true}) | Out-Null
    Write-Output ""
    Write-Output ""
}

### Programs settings ###
Function ProgramsSetup {
	Write-Output "Installing Chocolatey... "
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	choco install chocolatey-core.extension -y
	
	Write-Output ""
	
	Write-Output "Running O&O ShutUp10 with privacy-hardened settings..."
	Import-Module BitsTransfer
	Start-BitsTransfer -Source "https://raw.githubusercontent.com/gfelipe099/threshold-readiness/master/ooshutup10.cfg" -Destination ooshutup10.cfg
	Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe
	./OOSU10.exe ooshutup10.cfg /quiet
	
	Write-Output ""
	
	Write-Output "Installing 7-Zip, Steam, Origin and Microsoft Edge... "
	choco install 7zip.install -y
	choco install steam -y
	choco install origin -y
	choco install microsoft-edge -y

	Write-Output ""

	Write-Output "Uninstalling all Windows UWP application. Please wait, will take a while..."
    Start-Sleep 5
	Get-AppxPackage -allusers | Remove-AppxPackage | Out-Null
}

### Privacy settings ###
Function PrivacySettings {
	Write-Output "Disabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	
	Write-Output ""

	Write-Output "Disabling Wi-Fi Sense..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type Dword -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type Dword -Value 0
	
	Write-Output ""
	
	Write-Output "Enabling SmartScreen Filter..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue
	
	Write-Output ""
	
	Write-Output "Disabling Bing Search in Start Menu..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Disabling Application suggestions..."
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

	Write-Output ""

	Write-Output "Disabling activity history..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Disabling background application access..."
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
		Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
		Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
	}

	Write-Output ""

	Write-Output "Disabling location tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Disabling automatic Maps updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Disabling Feedback..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

	Write-Output ""

	Write-Output "Disabling tailored experiences..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Disabling advertising ID..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Disabling Cortana..."
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

	Write-Output ""

	Write-Output "Disabling error reporting ... "
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

	Write-Output ""

	Write-Output "Restricting Windows Update P2P only to local network ... "
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Stopping and disabling Diagnostics Tracking Service..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled

	Write-Output ""

	Write-Output "Stopping and disabling WAP Push Service..."
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled
}

### Security settings ###
Function SecuritySettings {
	Write-Output "Raising UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Disabling sharing mapped drives between users..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue

	Write-Output ""

	Write-Output "Disabling implicit administrative shares..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Disabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

	Write-Output ""

	Write-Output "Disabling SMB Server..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force

	Write-Output ""

	Write-Output "Disabling Link-Local Multicast Name Resolution (LLMNR) protocol..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Setting current network profile to public..."
	Set-NetConnectionProfile -NetworkCategory Public

	Write-Output ""

	Write-Output "Setting unknown networks profile to public..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue

	Write-Output ""

	Write-Output "Disabling automatic installation of network devices..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Disabling Controlled Folder Access..."
	Set-MpPreference -EnableControlledFolderAccess Disabled

	Write-Output ""

	Write-Output "Enabling Firewall..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue

	Write-Output ""

	Write-Output "Enabling Windows Defender..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
	}

	Write-Output ""

	Write-Output "Disabling Windows Defender Cloud ... "
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2

	Write-Output ""

	Write-Output "Disabling F8 legacy boot menu options ... "
	bcdedit /set `{current`} bootmenupolicy Standard | Out-Null

	Write-Output ""

	Write-Output "Setting Data Execution Prevention (DEP) policy to OptIn ..."
	bcdedit /set `{current`} nx OptIn | Out-Null
	bcdedit /set `{current`} nx AlwaysOn | Out-Null

	Write-Output ""

	Write-Output "Enabling Core Isolation Memory Integrity..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Disabling Windows Script Host..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0

	Write-Output ""

	Write-output "Enabling .NET strong cryptography..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Enabling Meltdown (CVE-2017-5754) compatibility flag..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

### Services settings ###
Function ServicesConfiguration {
	Write-Output "Enabling Malicious Software Removal Tool offering..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue

	Write-Output ""

	Write-Output "Disabling automatic driver installation through Windows Update..."
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

	Write-Output ""

	Write-Output "Disabling Windows Update automatic restart..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Stopping and disabling Home Groups services..."
	Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
	Set-Service "HomeGroupListener" -StartupType Disabled
	Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
	Set-Service "HomeGroupProvider" -StartupType Disabled

	Write-Output ""

	Write-Output "Disabling Shared Experiences..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Disabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Disabling Remote Desktop..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
	Disable-NetFirewallRule -Name "RemoteDesktop*"

	Write-Output ""

	Write-Output "Enabling Autoplay..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Enabling Autorun for all drives..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue

	Write-Output ""

	Write-Output "Enabling Storage Sense..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "08" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "32" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "StoragePoliciesNotified" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Disabling scheduled defragmentation..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null

	Write-Output ""

	Write-Output "Stopping and disabling Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled

	Write-Output ""
	
	Write-Output "Stopping and disabling Windows Search indexing service..."
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled

	Write-Output ""

	Write-Output "Setting BIOS time to local time..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue

	Write-Output ""

	Write-Output "Disabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

	Write-Output ""

	Write-Output "Disabling Sleep start menu and keyboard button..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type Dword -Value 0
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0

	Write-Output ""

	Write-Output "Disabling display and sleep mode timeouts..."
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 0
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0

	Write-Output ""

	Write-Output "Disabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

### UI settings ###
Function UISettings {
	Write-Output "Hiding network options from Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Hiding shutdown options from Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Disabling Sticky keys prompt..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"

	Write-Output ""
	
	Write-Output "Showing file operations details..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Enabling file delete confirmation dialog..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Hiding Taskbar Search icon / box..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Hiding Task View button..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Hiding Cortana button..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Hiding People icon..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Showing all tray icons..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Disabling search for app in store for unknown extensions..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Setting Control Panel view to categories..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -ErrorAction SilentlyContinue

	Write-Output ""

	Write-Output "Adjusting visual effects for performance..."
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
	Write-Output "Showing known file extensions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Disabling thumbnails..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1

	Write-Output ""

	Write-Output "Disabling thumbails cache..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
}

### Application settings ###
Function ApplicationsSettings {
	Write-Output "Disabling Xbox features..."
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Disabling built-in Adobe Flash in IE and Edge..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0

	Write-Output ""

	Write-Output "Configuring Windows optional features..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features"
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
	Disable-WindowsOptionalFeature -Online -FeatureName "-Triggers" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-CertProvider" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WindowsAuthentication" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-DigestAuthentication" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ClientCertificateMappingAuthentication" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-IISCertificateMappingAuthentication" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ODBCLogging" -NoRestart -WarningAction SilentlyContinue | Out-Null
	Disable-WindowsOptionalFeature -Online -FeatureName "NetFx4-AdvSrvs" -All -NoRestart -WarningAction SilentlyContinue | Out-Null
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
	Enable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-Default-Definitions" -All
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
	
	Write-Output ""

	Write-Output "Removing 'Fax' from default printers..."
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}

### Auxiliary Functions ###
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"${PSCommandPath}`" $${PSCommandArgs}" -WorkingDirectory ${pwd} -Verb RunAs
		Exit
	}
}

Function PressAnyKeyToReboot {
	Write-Output "System Readiness for Business has finished! Press any key to reboot your computer..."
	[Console]::ReadKey(${true}) | Out-Null
    Restart-Computer
}

### Parse parameters and apply tweaks ###
${preset} = ""
${PSCommandArgs} = ${args}
If (${args} -And ${args}[0].ToLower() -eq "-preset") {
	${preset} = Resolve-Path $(${args} | Select-Object -Skip 1)
	${PSCommandArgs} = "-preset `"${preset}`""
}

If (${args}) {
	${tweaks} = ${args}
	If (${preset}) {
		${tweaks} = Get-Content ${preset} -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
	}
}

# Call the desired tweak functions
Startup
CheckOSVersion
${tweaks} | ForEach { Invoke-Expression $_ }
