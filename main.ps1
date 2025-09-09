<#
.DESCRIPTION
   Silly script that makes your life kawaii

.AUTHOR
    Thahmid

.VERSION
    2.0
#>


# Ensure the script is running as Administrator
Write-Host "Checking for administrative privileges!!" -ForegroundColor Yellow
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator privileges are required to run this script." -ForegroundColor Red
    Write-Host "Please re-run this script as an Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit!!"
    exit
}
Write-Host "Successfully running with administrative privileges." -ForegroundColor Green

# i will beat ur ass
Clear-Host
Write-Host "=====================================================================" -ForegroundColor Red
Write-Host "                          D I S C L A I M E R" -ForegroundColor White
Write-Host "=====================================================================" -ForegroundColor Red
Write-Host ""
Write-Host "This script will make significant changes to your system settings." -ForegroundColor Yellow
Write-Host "I AM NOT responsible for any damage or data loss that may occur." -ForegroundColor Yellow
Write-Host ""
Write-Host "It is STRONGLY RECOMMENDED that you create a System Restore Point" -ForegroundColor Cyan
Write-Host "before proceeding with these optimizations." -ForegroundColor Cyan
Write-Host ""
Write-Host "LETS TAKE THEM TO THE WASTELAND"-ForegroundColor Red
Write-Host ""
$UserInput = Read-Host "Press ENTER to continue, or 'N' to exit"

if ($UserInput -eq 'n' -or $UserInput -eq 'N') {
    Write-Host "Script execution cancelled by user." -ForegroundColor Red
    Read-Host "Press Enter to close this window!!"
    exit
}

function Disable-Telemetry {
    Write-Host "Disabling Telemetry and Data Collection!!" -ForegroundColor Cyan
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $RegistryPath -Name "AllowTelemetry" -Value 0 -Type DWord -Force
    Write-Host "Disabling telemetry services!!" -ForegroundColor Cyan
    sc.exe config DiagTrack start= disabled
    sc.exe stop DiagTrack
    sc.exe config dmwappushservice start= disabled
    sc.exe stop dmwappushservice
    Write-Host "Telemetry has been disabled." -ForegroundColor Green
}

function Disable-SysMain {
    Write-Host "Disabling SysMain (Superfetch)!!" -ForegroundColor Cyan
    sc.exe config SysMain start= disabled
    sc.exe stop SysMain
    Write-Host "SysMain has been disabled." -ForegroundColor Green
}

function Set-EdgePrivacy {
    Write-Host "Configuring Microsoft Edge privacy settings!!" -ForegroundColor Cyan
    $EdgeRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $EdgeRegistryPath)) { New-Item -Path $EdgeRegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $EdgeRegistryPath -Name "TrackingPrevention" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path $EdgeRegistryPath -Name "EdgeShoppingAssistantEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $EdgeRegistryPath -Name "AdvertisingIdEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $EdgeRegistryPath -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
    Write-Host "Microsoft Edge privacy settings have been configured." -ForegroundColor Green
}

function Optimize-Win32Priority {
    Write-Host "Optimizing CPU scheduling for foreground apps!!" -ForegroundColor Cyan
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
    Set-ItemProperty -Path $RegistryPath -Name "Win32PrioritySeparation" -Value 0x26 -Type DWord -Force
    Write-Host "CPU scheduling has been optimized." -ForegroundColor Green
}

function Disable-Geolocation {
    Write-Host "Disabling Geolocation Service!!" -ForegroundColor Cyan
    sc.exe config lfsvc start= disabled
    sc.exe stop lfsvc
    Write-Host "Geolocation Service has been disabled." -ForegroundColor Green
}

function Disable-MouseAcceleration {
    Write-Host "Disabling Mouse Acceleration!!" -ForegroundColor Cyan
    $MouseRegistryPath = "HKCU:\Control Panel\Mouse"
    Set-ItemProperty -Path $MouseRegistryPath -Name "MouseSpeed" -Value "0" -Type String -Force
    Set-ItemProperty -Path $MouseRegistryPath -Name "MouseThreshold1" -Value "0" -Type String -Force
    Set-ItemProperty -Path $MouseRegistryPath -Name "MouseThreshold2" -Value "0" -Type String -Force
    Write-Host "Mouse Acceleration has been disabled." -ForegroundColor Green
}

function Apply-RegistryTweaks {
    Write-Host "Applying various performance and UI tweaks!!" -ForegroundColor Cyan
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Value 0 -Type DWord -Force
    powercfg -h off
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0 -Type DWord -Force
    $StartupDelayPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize"
    if (-not (Test-Path $StartupDelayPath)) { New-Item -Path $StartupDelayPath -Force | Out-Null }
    Set-ItemProperty -Path $StartupDelayPath -Name "StartupDelayInMSec" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Value "10" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "0" -Type String -Force
    Write-Host "Miscellaneous registry tweaks have been applied." -ForegroundColor Green
}

function Set-NetworkTweaks {
    Write-Host "Applying network tweaks!!" -ForegroundColor Cyan
    $adapters = Get-NetAdapter -Physical -OperationalStatus Up
    if ($adapters) {
        foreach ($adapter in $adapters) {
            Write-Host "Setting DNS for adapter: $($adapter.Name)" -ForegroundColor White
            try {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("1.1.1.1", "1.0.0.1") -ErrorAction Stop
                Write-Host "Successfully set Cloudflare DNS for $($adapter.Name)." -ForegroundColor Green
            }
            catch { Write-Host "Failed to set DNS for $($adapter.Name). Error: $_" -ForegroundColor Red }
        }
    }
    else { Write-Host "No active network adapters found." -ForegroundColor Yellow }
    Write-Host "Network tweaks have been applied." -ForegroundColor Green
}

function Set-UltimatePerformance {
    Write-Host "Setting Power Plan to Ultimate Performance!!" -ForegroundColor Cyan
    $UltimatePerformanceGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
    powercfg /duplicatescheme $UltimatePerformanceGuid | Out-Null
    powercfg /setactive $UltimatePerformanceGuid
    Write-Host "Power Plan has been set to Ultimate Performance." -ForegroundColor Green
}

function Disable-BackgroundApps {
    Write-Host "Disabling background apps!!" -ForegroundColor Cyan
    $RegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
    if (-not (Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $RegistryPath -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force
    Write-Host "Background apps have been disabled." -ForegroundColor Green
}

function Cleanup-FileExplorer {
    Write-Host "Cleaning up File Explorer!!" -ForegroundColor Cyan
    $RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $RegistryPath -Name "Hidden" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $RegistryPath -Name "HideFileExt" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $RegistryPath -Name "LaunchTo" -Value 1 -Type DWord -Force
    $ExplorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    Set-ItemProperty -Path $ExplorerPath -Name "ShowFrequent" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $ExplorerPath -Name "ShowRecent" -Value 0 -Type DWord -Force
    Write-Host "Clearing File Explorer history!!" -ForegroundColor White
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force -ErrorAction SilentlyContinue
    Write-Host "File Explorer has been cleaned up." -ForegroundColor Green
}

function Restore-OldContextMenu {
    Write-Host "Restoring the classic context menu!!" -ForegroundColor Cyan
    $RegistryPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    if (-not (Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $RegistryPath -Name "(Default)" -Value "" -Type String -Force
    Write-Host "Classic context menu has been restored. You may need to restart explorer.exe or reboot." -ForegroundColor Green
}

function Disable-Cortana {
    Write-Host "Disabling Cortana!!" -ForegroundColor Cyan
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    if (-not (Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $RegistryPath -Name "AllowCortana" -Value 0 -Type DWord -Force
    Write-Host "Cortana has been disabled." -ForegroundColor Green
}

function Remove-Bloatware {
    Write-Host "Removing bloatware apps!" -ForegroundColor Cyan
    $BloatwareList = @(
        "Microsoft.Microsoft3DViewer", "Microsoft.People", "Microsoft.MixedReality.Portal",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.Getstarted",
        "Microsoft.YourPhone", "Microsoft.WindowsMaps", "Microsoft.WindowsFeedbackHub",
        "SpotifyAB.SpotifyMusic", "Netflix.Netflix",
        "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.BingFinance",
        "microsoft.windowscommunicationsapps", "Microsoft.SkypeApp", "5A894077.McAfeeSecurity_2.1.27.0_x64__wafk5atnkzcwy", "5A894077.McAfeeSecurity", "RealtimeboardInc.RealtimeBoard",
        "MirametrixInc.GlancebyMirametrix", "Microsoft.Teams", "Microsoft.Print3D", "Disney.37853FC22B2CE", "C27EB4BA.DropboxOEM*",
        "*CandyCrush*", "*BubbleWitch3Saga*", "MSTeams", "*Microsoft.MicrosoftStickyNotes*", "Microsoft.Copilot", "Microsft.BingSearch", "Microsoft.PowerAutomateDesktop",
        "Microsoft.Todos", 
    )
    foreach ($AppName in $BloatwareList) {
        Write-Host "Attempting to remove: $AppName" -ForegroundColor White
        try {
            Get-AppxPackage -AllUsers -Name $AppName | Remove-AppxPackage -AllUsers -ErrorAction Stop
            Write-Host "Successfully removed $AppName." -ForegroundColor Green
        }
        catch { Write-Host "Could not remove $AppName. It might not be installed. GULPPPP" -ForegroundColor Yellow }
    }
    Write-Host "Bloatware removal process finished." -ForegroundColor Green
}

function Clear-TemporaryFiles {
    Write-Host "Cleaning up temporary files and prefetch!!" -ForegroundColor Cyan
    $TempFolders = @( "$env:TEMP", "C:\Windows\Temp", "C:\Windows\Prefetch" )
    foreach ($Folder in $TempFolders) {
        Write-Host "Cleaning folder: $Folder" -ForegroundColor White
        try {
            Get-ChildItem -Path "$Folder\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully cleaned $Folder." -ForegroundColor Green
        }
        catch { Write-Host "Could not clean $Folder completely. Some files may be in use. Now go plant the spike bro" -ForegroundColor Yellow }
    }
    Write-Host "Temporary file cleanup finished." -ForegroundColor Green
}

function Set-ManualServices {
    Write-Host "Setting non-essential services to Manual startup!!" -ForegroundColor Cyan
    $ServicesToSetManual = @(
        "Fax",                  
        "StiSvc",               
        "TabletInputService",
        "DoSvc",
    )
    foreach ($ServiceName in $ServicesToSetManual) {
        Write-Host "Setting $ServiceName to Manual." -ForegroundColor White
        try {
            Set-Service -Name $ServiceName -StartupType Manual -ErrorAction Stop
            Write-Host "$ServiceName set to Manual." -ForegroundColor Green
        }
        catch { Write-Host "Could not set $ServiceName. It might not exist on this system." -ForegroundColor Yellow }
    }
    Write-Host "Service startup types have been configured." -ForegroundColor Green
}

function Disable-ScheduledTasks {
    Write-Host "Disabling non-essential scheduled tasks!!" -ForegroundColor Cyan
    $TasksToDisable = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    )
    foreach ($TaskPath in $TasksToDisable) {
        try {
            Get-ScheduledTask -TaskPath $TaskPath | Disable-ScheduledTask -ErrorAction Stop
            Write-Host "Disabled task: $TaskPath" -ForegroundColor Green
        }
        catch {
            Write-Host "Could not disable task: $TaskPath (It may not exist)." -ForegroundColor Yellow
        }
    }
    Write-Host "Scheduled tasks have been configured." -ForegroundColor Green
}

function Clear-SystemCache {
    Write-Host "Clearing system caches!!" -ForegroundColor Cyan
    
    Write-Host "Flushing DNS cache!!" -ForegroundColor White
    ipconfig /flushdns
    
    Write-Host "System caches have been cleared." -ForegroundColor Green
}

function Tweak-ContextMenu {
    Write-Host "Cleaning up the context menu!!" -ForegroundColor Cyan
    $ContextMenuPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
    )
    $ItemsToBlock = @(
        "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}", # Share
        "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}", # 3D Print
        "{F86FA3AB-70D2-4FC7-9C99-FCBF0596D6AF}"  # Cast to Device
    )
    foreach ($path in $ContextMenuPaths) {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        foreach ($item in $ItemsToBlock) {
            Set-ItemProperty -Path $path -Name $item -Value "" -Type String -Force
        }
    }
    Write-Host "Context menu has been tweaked. Restart explorer.exe to see changes." -ForegroundColor Green
}

function Disable-CpuParking {
    Write-Host "Disabling CPU Core Parking!!" -ForegroundColor Cyan
    $SubGroup = "54533251-82be-4824-96c1-47b60b740d00"
    $Setting = "0cc5b647-c1df-4637-891a-dec35c318583"
    powercfg /setacvalueindex SCHEME_CURRENT $SubGroup $Setting 100
    powercfg /setdcvalueindex SCHEME_CURRENT $SubGroup $Setting 100
    powercfg /setactive SCHEME_CURRENT
    Write-Host "CPU Core Parking has been disabled." -ForegroundColor Green
}

function Configure-EaseOfAccess {
    Write-Host "Configuring Ease of Access settings (disabling hotkeys)!!" -ForegroundColor Cyan
    $StickyKeysPath = "HKCU:\Control Panel\Accessibility\StickyKeys"
    Set-ItemProperty -Path $StickyKeysPath -Name "Flags" -Value "58" -Type String -Force
    $KeyboardResponsePath = "HKCU:\Control Panel\Accessibility\Keyboard Response"
    Set-ItemProperty -Path $KeyboardResponsePath -Name "Flags" -Value "122" -Type String -Force
    $ToggleKeysPath = "HKCU:\Control Panel\Accessibility\ToggleKeys"
    Set-ItemProperty -Path $ToggleKeysPath -Name "Flags" -Value "58" -Type String -Force
    Write-Host "Sticky Keys, Toggle Keys, and Filter Keys hotkeys have been disabled." -ForegroundColor Green
}

function Remove-OneDrive {
    Write-Host "Attempting to completely remove OneDrive!!" -ForegroundColor Cyan
    Write-Host "Terminating OneDrive process..." -ForegroundColor White
    taskkill.exe /f /im OneDrive.exe > $null 2>&1
    Write-Host "Running OneDrive uninstaller..." -ForegroundColor White
    $OneDriveSetupPath_64 = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    $OneDriveSetupPath_32 = "$env:SystemRoot\System32\OneDriveSetup.exe"
    
    if (Test-Path $OneDriveSetupPath_64) {
        Start-Process $OneDriveSetupPath_64 "/uninstall" -Wait
    }
    elseif (Test-Path $OneDriveSetupPath_32) {
        Start-Process $OneDriveSetupPath_32 "/uninstall" -Wait
    }
    else {
        Write-Host "OneDrive installer not found." -ForegroundColor Yellow
    }
    Write-Host "Removing OneDrive from File Explorer sidebar..." -ForegroundColor White
    $RegistryPath = "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    if (Test-Path $RegistryPath) {
        Set-ItemProperty -Path $RegistryPath -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue
    }

    Write-Host "OneDrive has been removed. A restart may be required to fully remove the sidebar icon." -ForegroundColor Green
}

function Add-TakeOwnership {
    Write-Host "Adding 'Take Ownership' to the context menu!!" -ForegroundColor Cyan
    $RegPath = "HKCR:\*\shell\runas"
    if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
    Set-ItemProperty -Path $RegPath -Name "(Default)" -Value "Take Ownership" -Force
    Set-ItemProperty -Path $RegPath -Name "NoWorkingDirectory" -Value "" -Force
    $CmdPath = "HKCR:\*\shell\runas\command"
    if (-not (Test-Path $CmdPath)) { New-Item -Path $CmdPath -Force | Out-Null }
    Set-ItemProperty -Path $CmdPath -Name "(Default)" -Value 'cmd.exe /c takeown /f "%1" && icacls "%1" /grant administrators:F' -Force
    Write-Host "'Take Ownership' has been added. Be careful with this power!" -ForegroundColor Green
}

function Disable-NetworkThrottling {
    Write-Host "Disabling network throttling!!" -ForegroundColor Cyan
    $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    Set-ItemProperty -Path $RegistryPath -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Type DWord -Force
    Write-Host "Network throttling has been disabled." -ForegroundColor Green
}

function TCP-Opti {
    Write-Host "Optimizing TCP/IP for lower latency!!" -ForegroundColor Cyan
    $InterfacesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    $InterfaceGuids = Get-ChildItem -Path $InterfacesPath | ForEach-Object { $_.PSChildName }

    foreach ($Guid in $InterfaceGuids) {
        $InterfacePath = "$InterfacesPath\$Guid"
        Set-ItemProperty -Path $InterfacePath -Name "TcpAckFrequency" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $InterfacePath -Name "TCPNoDelay" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    }
    Write-Host "TCP/IP settings have been optimized for gaming." -ForegroundColor Green
}

function Enable-AdvancedAdapterProperties {
    Write-Host "Enabling advanced network adapter properties!!" -ForegroundColor Cyan
    $adapters = Get-NetAdapter -Physical -OperationalStatus Up
    if ($adapters) {
        foreach ($adapter in $adapters) {
            Write-Host "Optimizing adapter: $($adapter.Name)" -ForegroundColor White
            try {
                Enable-NetAdapterRss -Name $adapter.Name -ErrorAction Stop
                Write-Host "  - Enabled RSS for $($adapter.Name)." -ForegroundColor Green
            }
            catch { Write-Host "  - Failed to enable RSS for $($adapter.Name) or already enabled." -ForegroundColor Yellow }
            try {
                Set-NetAdapterChecksumOffload -Name $adapter.Name -IpIPv4Enabled -TcpIPv4Enabled -TcpIPv6Enabled -UdpIPv4Enabled -UdpIPv6Enabled
                 Write-Host "  - Enabled Checksum Offloads for $($adapter.Name)." -ForegroundColor Green
            }
            catch { Write-Host "  - Failed to enable Checksum Offloads for $($adapter.Name)." -ForegroundColor Yellow }
        }
    }
    else { Write-Host "No active physical network adapters found to optimize." -ForegroundColor Yellow }
    Write-Host "Advanced adapter properties have been configured." -ForegroundColor Green
}

function Disable-AdapterPowerSaving {
    Write-Host "Disabling network adapter power saving!!" -ForegroundColor Cyan
    $adapters = Get-NetAdapter -Physical -OperationalStatus Up
    if ($adapters) {
        foreach ($adapter in $adapters) {
            try {
                Set-NetAdapterPowerManagement -Name $adapter.Name -ArpOffload -D0PacketCoalescing -NSOffload -RsnRekeyOffload -WakeOnMagicPacket -WakeOnPattern -DeviceSleepOnDisconnect -ErrorAction Stop
                Write-Host "Disabled power saving for $($adapter.Name)." -ForegroundColor Green
            }
            catch { Write-Host "Could not modify power settings for $($adapter.Name). May not be supported." -ForegroundColor Yellow }
        }
    }
     else { Write-Host "No active physical network adapters found." -ForegroundColor Yellow }
     Write-Host "Adapter power saving has been disabled where supported." -ForegroundColor Green
}

function Configure-StartAndSuggestions {
    Write-Host "Configuring Start Menu and disabling unwanted suggestions!!" -ForegroundColor Cyan
    Write-Host "Applying Start Menu layout: More pins, minimal recommendations..." -ForegroundColor White
    $AdvExplorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $AdvExplorerPath -Name "Start_Layout" -Value 0 -Type DWord -Force # More pins
    Set-ItemProperty -Path $AdvExplorerPath -Name "Start_ShowRecentlyAdded" -Value 1 -Type DWord -Force # On
    Set-ItemProperty -Path $AdvExplorerPath -Name "Start_ShowMostUsed" -Value 0 -Type DWord -Force # Off
    Set-ItemProperty -Path $AdvExplorerPath -Name "Start_ShowRecommended" -Value 0 -Type DWord -Force # Off
    Set-ItemProperty -Path $AdvExplorerPath -Name "Start_ShowUser" -Value 1 -Type DWord -Force # On
    Write-Host "Disabling suggestions, tips, and welcome experience popups..." -ForegroundColor White
    $ContentManagerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    if (-not (Test-Path $ContentManagerPath)) { New-Item -Path $ContentManagerPath -Force | Out-Null }
    Set-ItemProperty -Path $ContentManagerPath -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $ContentManagerPath -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $ContentManagerPath -Name "SubscribedContent-310093Enabled" -Value 0 -Type DWord -Force
    $EngagementPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement"
    if (-not (Test-Path $EngagementPath)) { New-Item -Path $EngagementPath -Force | Out-Null }
    Set-ItemProperty -Path $EngagementPath -Name "ScoobeSystemSettingEnabled" -Value 0 -Type DWord -Force

    Write-Host "Start Menu and suggestions have been configured." -ForegroundColor Green
}

Write-Host "Starting Windows 11 Optimization!!" -ForegroundColor Magenta
Write-Host "LETS TAKE THEM TO THE WASTELANDDD!" -ForegroundColor Red

Disable-Telemetry
Disable-SysMain
Set-EdgePrivacy
Optimize-Win32Priority
Disable-CpuParking
Configure-EaseOfAccess
Disable-Geolocation
Disable-MouseAcceleration
Apply-RegistryTweaks
Set-NetworkTweaks
Disable-NetworkThrottling
TCP-Opti
Enable-AdvancedAdapterProperties
Disable-AdapterPowerSaving
Set-UltimatePerformance
Disable-BackgroundApps
Configure-StartAndSuggestions
Cleanup-FileExplorer
Restore-OldContextMenu
Disable-Cortana
Remove-OneDrive
Remove-Bloatware
Clear-TemporaryFiles
Set-ManualServices
Disable-ScheduledTasks
Tweak-ContextMenu
Add-TakeOwnership
Clear-SystemCache


Write-Host "All tweaks have been applied, Restart or ill do kawaii things to u!" -ForegroundColor Pink
Write-Host "FACE YOUR FEARSSS" -ForegroundColor Red
Start-Process "https://t8xh.cc"

Read-Host "Press Enter to close"



