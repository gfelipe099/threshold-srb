#
# Created by Liam Powell (gfelipe099)
# A fork from ChrisTitusTech's https://github.com/ChrisTitusTech/win10script
# threshold-srb.ps1 file
# System Readiness for Business
# For Microsoft Windows 10 Enterprise N LTSC 2019 x64
#
Clear-Host

### Check system version and edition ###
if (!${validatedOsVersion}) {
    New-Variable -Name validatedOsVersion -Value "10.0.17763" | Out-Null
}

if (!${validatedOsEdition}) {
    New-Variable -Name validatedOsEdition -Value "Microsoft Windows 10 Enterprise N LTSC" | Out-Null
}

if (!${OsVersion}) {
    New-Variable -Name osVersion -Value (gwmi win32_operatingsystem).version | Out-Null
}

if (!${OsEdition}) {
    New-Variable -Name osEdition -Value (gwmi win32_operatingsystem).caption | Out-Null
}

${WShell} = New-Object -ComObject Wscript.Shell
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
        Switch ([System.Windows.MessageBox]::Show("This script needs Administrator privileges to run. Do you want to give permissions to this script?", "Insufficient permissions", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)) {
        Yes {
            Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
            Exit
        }
        No {
            Switch ([System.Windows.MessageBox]::Show("This script cannot be executed without Administrator privileges.", "threshold-srb", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)) {
            OK {
                Exit
            }
            }
        }
    }
}

${threshold-srb}                                                = New-Object System.Windows.Forms.Form
${threshold-srb}.ClientSize                                     = New-Object System.Drawing.Point(1050,700)
${threshold-srb}.Text                                           = "System Readiness for Business"
${threshold-srb}.TopMost                                        = $false

${ProgramsContainer}                                            = New-Object System.Windows.Forms.Panel
${ProgramsContainer}.AutoSize                                   = $true

${ProgramsSetup}                                                = New-Object System.Windows.Forms.Label
${ProgramsSetup}.Text                                           = "Programs Setup"
${ProgramsSetup}.AutoSize                                       = $true
${ProgramsSetup}.Location                                       = New-Object System.Drawing.Point(10,15)
${ProgramsSetup}.Font                                           = New-Object System.Drawing.Font('Microsoft Sans Serif',30)

${ProgramsSetup_Install_Chocolatey}                             = New-Object System.Windows.Forms.Button
${ProgramsSetup_Install_Chocolatey}.Text                        = "Install Chocolatey"
${ProgramsSetup_Install_Chocolatey}.AutoSize                    = $true
${ProgramsSetup_Install_Chocolatey}.Location                    = New-Object System.Drawing.Point(30,80)
${ProgramsSetup_Install_Chocolatey}.Font                        = New-Object System.Drawing.Font('Microsoft Sans Serif',20)

${ProgramsSetup_Install_7zip}                                   = New-Object System.Windows.Forms.Button
${ProgramsSetup_Install_7zip}.Text                              = "Install 7-Zip"
${ProgramsSetup_Install_7zip}.AutoSize                          = $true
${ProgramsSetup_Install_7zip}.Location                          = New-Object System.Drawing.Point(30,135)
${ProgramsSetup_Install_7zip}.Font                              = New-Object System.Drawing.Font('Microsoft Sans Serif',20)

${ProgramsSetup_Install_Steam}                                  = New-Object System.Windows.Forms.Button
${ProgramsSetup_Install_Steam}.Text                             = "Install Steam"
${ProgramsSetup_Install_Steam}.AutoSize                         = $true
${ProgramsSetup_Install_Steam}.Location                         = New-Object System.Drawing.Point(30,190)
${ProgramsSetup_Install_Steam}.Font                             = New-Object System.Drawing.Font('Microsoft Sans Serif',20)

${ProgramsSetup_Install_Rwc}                                    = New-Object System.Windows.Forms.Button
${ProgramsSetup_Install_Rwc}.Text                               = "Install Reddit Wallpaper Changer"
${ProgramsSetup_Install_Rwc}.AutoSize                           = $true
${ProgramsSetup_Install_Rwc}.Location                           = New-Object System.Drawing.Point(30,245)
${ProgramsSetup_Install_Rwc}.Font                               = New-Object System.Drawing.Font('Microsoft Sans Serif',20)

${ProgramsSetup_Install_Egl}                                    = New-Object System.Windows.Forms.Button
${ProgramsSetup_Install_Egl}.Text                               = "Install Epic Games Launcher"
${ProgramsSetup_Install_Egl}.AutoSize                           = $true
${ProgramsSetup_Install_Egl}.Location                           = New-Object System.Drawing.Point(30,300)
${ProgramsSetup_Install_Egl}.Font                               = New-Object System.Drawing.Font('Microsoft Sans Serif',20)

${ProgramsSetup_Install_Spotify}                                = New-Object System.Windows.Forms.Button
${ProgramsSetup_Install_Spotify}.Text                           = "Install Spotify"
${ProgramsSetup_Install_Spotify}.AutoSize                       = $true
${ProgramsSetup_Install_Spotify}.Location                       = New-Object System.Drawing.Point(30,355)
${ProgramsSetup_Install_Spotify}.Font                           = New-Object System.Drawing.Font('Microsoft Sans Serif',20)

${ProgramsSetup_Install_Discord}                                = New-Object System.Windows.Forms.Button
${ProgramsSetup_Install_Discord}.Text                           = "Install Discord"
${ProgramsSetup_Install_Discord}.AutoSize                       = $true
${ProgramsSetup_Install_Discord}.Location                       = New-Object System.Drawing.Point(30,410)
${ProgramsSetup_Install_Discord}.Font                           = New-Object System.Drawing.Font('Microsoft Sans Serif',20)

${ProgramsSetup_Install_Bleachbit}                              = New-Object System.Windows.Forms.Button
${ProgramsSetup_Install_Bleachbit}.Text                         = "Install BleachBit"
${ProgramsSetup_Install_Bleachbit}.AutoSize                     = $true
${ProgramsSetup_Install_Bleachbit}.Location                     = New-Object System.Drawing.Point(30,465)
${ProgramsSetup_Install_Bleachbit}.Font                         = New-Object System.Drawing.Font('Microsoft Sans Serif',20)

${SystemAdministration}                                         = New-Object System.Windows.Forms.Panel
${SystemAdministration}.AutoSize                                = $true

${SystemReadiness}                                              = New-Object System.Windows.Forms.Label
${SystemReadiness}.Text                                         = "System Administration"
${SystemReadiness}.AutoSize                                     = $true
${SystemReadiness}.Location                                     = New-Object System.Drawing.Point(550,15)
${SystemReadiness}.Font                                         = New-Object System.Drawing.Font('Microsoft Sans Serif',30)

${SystemReadiness_Apply}                                        = New-Object System.Windows.Forms.Button
${SystemReadiness_Apply}.Text                                   = "Apply System Readiness"
${SystemReadiness_Apply}.AutoSize                               = $true
${SystemReadiness_Apply}.Location                               = New-Object System.Drawing.Point(580,80)
${SystemReadiness_Apply}.Font                                   = New-Object System.Drawing.Font('Microsoft Sans Serif',20)

${ProgramsSetup_Install_Chocolatey}.Add_Click({
    Write-Host "Installing Chocolatey package manager for Windows... "
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) | Out-Null
    choco install chocolatey-core.extension -y
    ${WShell}.Popup("Operation completed",0,"$(${ProgramsSetup_Install_Chocolatey}.Text)",0x0)
})

${ProgramsSetup_Install_7Zip}.Add_Click({
    Write-Host "Installing 7-Zip... "
    choco install 7zip.install -y
    ${WShell}.Popup("Operation completed",0,"$(${ProgramsSetup_Install_7Zip}.Text)",0x0)
})

${ProgramsSetup_Install_Steam}.Add_Click({
   Write-Host "Installing Steam... "
    choco install steam -y
    ${WShell}.Popup("Operation completed",0,"$(${ProgramsSetup_Install_Steam}.Text)",0x0)
})

${ProgramsSetup_Install_Rwc}.Add_Click({
   Write-Host "Installing Reddit Wallpaper Changer... "
    choco install reddit-wallpaper-changer -y
    ${WShell}.Popup("Operation completed",0,"$(${ProgramsSetup_Install_Rwc}.Text)",0x0)
})

${ProgramsSetup_Install_Egl}.Add_Click({
   Write-Host "Installing Epic Games Launcher... "
    choco install reddit-wallpaper-changer -y
    ${WShell}.Popup("Operation completed",0,"$(${ProgramsSetup_Install_Egl}.Text)",0x0)
})

${ProgramsSetup_Install_Spotify}.Add_Click({
   Write-Host "Installing Spotify... "
    choco install spotify -y
    ${WShell}.Popup("Operation completed",0,"$(${ProgramsSetup_Install_Spotify}.Text)",0x0)
})

${ProgramsSetup_Install_Discord}.Add_Click({
   Write-Host "Installing Discord... "
    choco install discord -y
    ${WShell}.Popup("Operation completed",0,"$(${ProgramsSetup_Install_Discord}.Text)",0x0)
})

${ProgramsSetup_Install_Bleachbit}.Add_Click({
   Write-Host "Installing BleachBit... "
    choco install bleachbit -y
    ${WShell}.Popup("Operation completed",0,"$(${ProgramsSetup_Install_Bleachbit}.Text)",0x0)
})

${SystemReadiness_Apply}.Add_Click({
    # Privacy settings
   Write-Host "Applying privacy settings..."
    Import-Module BitsTransfer | Out-Null
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/gfelipe099/threshold-srb/master/ooshutup10.cfg" -Destination ooshutup10.cfg | Out-Null
    Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe | Out-Null
    ./OOSU10.exe ooshutup10.cfg /quiet
    Remove-Module BitsTransfer

    # Performance settings
   Write-Host "Applying performance settings..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "IconsOnly" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0

    # Interface settings
   Write-Host "Applying interface settings..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HiddenFileExt" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "ShowTaskBarButton" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "ShowCortanaButton" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0

    # Windows optional features
   Write-Host "Configuring Windows optional features..."
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
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebDAV" -NoRestart -WarningAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebSockets" -NoRestart -WarningAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ApplicationInit" -NoRestart -WarningAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ASPNET" -NoRestart -WarningAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ASPNET45" -NoRestart -WarningAction SilentlyContinue | Out-Null
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
    Disable-WindowsOptionalFeature -Online -FeatureName "MSMQ-HTTP" -NoRestart -WarningAction SilentlyContinue | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "MSMQ-Multicast" -NoRestart -WarningAction SilentlyContinue | Out-Null
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
   Write-Host "Please wait, still disabling some features..."
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
})

${threshold-srb}.Controls.AddRange(@(${ProgramsContainer},${SystemAdministration}))
${ProgramsContainer}.Controls.AddRange(@(${ProgramsSetup},${ProgramsSetup_Install_Chocolatey},${ProgramsSetup_Install_7zip},${ProgramsSetup_Install_Steam},${ProgramsSetup_Install_Origin},${ProgramsSetup_Install_Rwc},${ProgramsSetup_Install_Egl},${ProgramsSetup_Install_Spotify},${ProgramsSetup_Install_Discord},${ProgramsSetup_Install_Bleachbit},${SystemReadiness_Apply}))
${SystemAdministration}.Controls.AddRange(@(${SystemReadiness},${SystemReadiness_Apply}))

if (${OsEdition} -ne "${validatedOsEdition}") {
    ${WShell}.Popup("The OS edition you are using is not validated to use with this script. You need to use ${validatedOsEdition}, and you are using: ${OsEdition}.",0,"$(${threshold-srb}.Text)",0x0)
    Exit
}

if (${OsVersion} -ne "${validatedOsVersion}") {
    ${WShell}.Popup("Your version of Windows is not validated on this script. You need to use ${validatedOsVersion}, and you are using ${OsVersion}.",0,"$(${threshold-srb}.Text)",0x0)
    Exit
}

[void]${threshold-srb}.ShowDialog()
