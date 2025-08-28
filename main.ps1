<#
.DESCRIPTION
   Silly script that makes your life kawaii

.AUTHOR
    Thahmid

.VERSION
    1.2
#>


# Ensure the script is running as Administrator
Write-Host "Checking for administrative privileges..." -ForegroundColor Yellow
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator privileges are required to run this script." -ForegroundColor Red
    Write-Host "Please re-run this script as an Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit..."
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
Write-Host "What on mars are you doing!"
Write-Host ""
$UserInput = Read-Host "Press ENTER to continue, or 'N' to exit"

if ($UserInput -eq 'n' -or $UserInput -eq 'N') {
    Write-Host "Script execution cancelled by user." -ForegroundColor Red
    Read-Host "Press Enter to close this window..."
    exit
}




function Disable-Telemetry {
    Write-Host "Disabling Telemetry and Data Collection..." -ForegroundColor Cyan
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $RegistryPath -Name "AllowTelemetry" -Value 0 -Type DWord -Force
    Write-Host "Disabling telemetry services..." -ForegroundColor Cyan
    sc.exe config DiagTrack start= disabled
    sc.exe stop DiagTrack
    sc.exe config dmwappushservice start= disabled
    sc.exe stop dmwappushservice
    Write-Host "Telemetry has been disabled." -ForegroundColor Green
}

function Disable-SysMain {
    Write-Host "Disabling SysMain (Superfetch)..." -ForegroundColor Cyan
    sc.exe config SysMain start= disabled
    sc.exe stop SysMain
    Write-Host "SysMain has been disabled." -ForegroundColor Green
}

function Set-EdgePrivacy {
    Write-Host "Configuring Microsoft Edge privacy settings..." -ForegroundColor Cyan
    $EdgeRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $EdgeRegistryPath)) { New-Item -Path $EdgeRegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $EdgeRegistryPath -Name "TrackingPrevention" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path $EdgeRegistryPath -Name "EdgeShoppingAssistantEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $EdgeRegistryPath -Name "AdvertisingIdEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $EdgeRegistryPath -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
    Write-Host "Microsoft Edge privacy settings have been configured." -ForegroundColor Green
}

function Optimize-Win32Priority {
    Write-Host "Optimizing CPU scheduling for foreground apps..." -ForegroundColor Cyan
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
    Set-ItemProperty -Path $RegistryPath -Name "Win32PrioritySeparation" -Value 0x26 -Type DWord -Force
    Write-Host "CPU scheduling has been optimized." -ForegroundColor Green
}

function Disable-Geolocation {
    Write-Host "Disabling Geolocation Service..." -ForegroundColor Cyan
    sc.exe config lfsvc start= disabled
    sc.exe stop lfsvc
    Write-Host "Geolocation Service has been disabled." -ForegroundColor Green
}

function Disable-MouseAcceleration {
    Write-Host "Disabling Mouse Acceleration..." -ForegroundColor Cyan
    $MouseRegistryPath = "HKCU:\Control Panel\Mouse"
    Set-ItemProperty -Path $MouseRegistryPath -Name "MouseSpeed" -Value "0" -Type String -Force
    Set-ItemProperty -Path $MouseRegistryPath -Name "MouseThreshold1" -Value "0" -Type String -Force
    Set-ItemProperty -Path $MouseRegistryPath -Name "MouseThreshold2" -Value "0" -Type String -Force
    Write-Host "Mouse Acceleration has been disabled." -ForegroundColor Green
}

function Apply-RegistryTweaks {
    Write-Host "Applying various performance and UI tweaks..." -ForegroundColor Cyan
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
    Write-Host "Applying network tweaks..." -ForegroundColor Cyan
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
    Write-Host "Setting Power Plan to Ultimate Performance..." -ForegroundColor Cyan
    $UltimatePerformanceGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
    powercfg /duplicatescheme $UltimatePerformanceGuid | Out-Null
    powercfg /setactive $UltimatePerformanceGuid
    Write-Host "Power Plan has been set to Ultimate Performance." -ForegroundColor Green
}

function Disable-BackgroundApps {
    Write-Host "Disabling background apps..." -ForegroundColor Cyan
    $RegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
    if (-not (Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $RegistryPath -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force
    Write-Host "Background apps have been disabled." -ForegroundColor Green
}

function Cleanup-FileExplorer {
    Write-Host "Cleaning up File Explorer..." -ForegroundColor Cyan
    $RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $RegistryPath -Name "Hidden" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $RegistryPath -Name "HideFileExt" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $RegistryPath -Name "LaunchTo" -Value 1 -Type DWord -Force
    $ExplorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    Set-ItemProperty -Path $ExplorerPath -Name "ShowFrequent" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $ExplorerPath -Name "ShowRecent" -Value 0 -Type DWord -Force
    Write-Host "Clearing File Explorer history..." -ForegroundColor White
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force -ErrorAction SilentlyContinue
    Write-Host "File Explorer has been cleaned up." -ForegroundColor Green
}

function Restore-OldContextMenu {
    Write-Host "Restoring the classic context menu..." -ForegroundColor Cyan
    $RegistryPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    if (-not (Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $RegistryPath -Name "(Default)" -Value "" -Type String -Force
    Write-Host "Classic context menu has been restored. You may need to restart explorer.exe or reboot." -ForegroundColor Green
}

function Disable-Cortana {
    Write-Host "Disabling Cortana..." -ForegroundColor Cyan
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    if (-not (Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $RegistryPath -Name "AllowCortana" -Value 0 -Type DWord -Force
    Write-Host "Cortana has been disabled." -ForegroundColor Green
}

function Remove-Bloatware {
    Write-Host "Removing bloatware apps..." -ForegroundColor Cyan
    $BloatwareList = @(
        "Microsoft.Microsoft3DViewer", "Microsoft.People", "Microsoft.MixedReality.Portal",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.Getstarted",
        "Microsoft.YourPhone", "Microsoft.WindowsMaps", "Microsoft.WindowsFeedbackHub",
        "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "SpotifyAB.SpotifyMusic", "Netflix.Netflix",
        "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.BingFinance",
        "microsoft.windowscommunicationsapps", "Microsoft.SkypeApp"
    )
    foreach ($AppName in $BloatwareList) {
        Write-Host "Attempting to remove: $AppName" -ForegroundColor White
        try {
            Get-AppxPackage -AllUsers -Name $AppName | Remove-AppxPackage -AllUsers -ErrorAction Stop
            Write-Host "Successfully removed $AppName." -ForegroundColor Green
        }
        catch { Write-Host "Could not remove $AppName. It might not be installed." -ForegroundColor Yellow }
    }
    Write-Host "Bloatware removal process finished." -ForegroundColor Green
}

function Clear-TemporaryFiles {
    Write-Host "Cleaning up temporary files and prefetch..." -ForegroundColor Cyan
    $TempFolders = @( "$env:TEMP", "C:\Windows\Temp", "C:\Windows\Prefetch" )
    foreach ($Folder in $TempFolders) {
        Write-Host "Cleaning folder: $Folder" -ForegroundColor White
        try {
            Get-ChildItem -Path "$Folder\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction Stop
            Write-Host "Successfully cleaned $Folder." -ForegroundColor Green
        }
        catch { Write-Host "Could not clean $Folder completely. Some files may be in use." -ForegroundColor Yellow }
    }
    Write-Host "Temporary file cleanup finished." -ForegroundColor Green
}

function Set-ManualServices {
    Write-Host "Setting non-essential services to Manual startup..." -ForegroundColor Cyan
    $ServicesToSetManual = @(
        "Fax",                  
        "StiSvc",               
        "TabletInputService"    
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


Write-Host "Starting Windows 11 Optimization..." -ForegroundColor Magenta

Disable-Telemetry
Disable-SysMain
Set-EdgePrivacy
Optimize-Win32Priority
Disable-Geolocation
Disable-MouseAcceleration
Apply-RegistryTweaks
Set-NetworkTweaks
Set-UltimatePerformance
Disable-BackgroundApps
Cleanup-FileExplorer
Restore-OldContextMenu
Disable-Cortana
Remove-Bloatware
Clear-TemporaryFiles
Set-ManualServices

Write-Host "All tweaks have been applied, Restart or I will brimstone ult u" -ForegroundColor Magenta
Start-Process "https://t8xh.cc"
Read-Host "Press Enter to close"
