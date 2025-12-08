<#
.DESCRIPTION
   best script no cap >_<

.AUTHOR
   Thahmid

.VERSION
   3.4A
#>

# --- PRE-FLIGHT CHECKS ---
Write-Host "Checking for administrative privileges!!" -ForegroundColor Yellow
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator privileges are required to run this script." -ForegroundColor Red
    Write-Host "Please re-run this script as an Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit!!"
    exit
}
Write-Host "Successfully running with administrative privileges." -ForegroundColor Green

Clear-Host
Write-Host "=====================================================================" -ForegroundColor Red
Write-Host "                          D I S C L A I M E R" -ForegroundColor White
Write-Host "=====================================================================" -ForegroundColor Red
Write-Host ""
Write-Host "This script will make significant changes to your system settings." -ForegroundColor Yellow
Write-Host "I AM NOT responsible for any damage or data loss that may occur." -ForegroundColor Yellow
Write-Host ""
Write-Host "It is STRONGLY RECOMMENDED that you create a System Restore Point" -ForegroundColor Cyan
Write-Host "before proceeding." -ForegroundColor Cyan
Write-Host ""
Write-Host "KIRA KIRA BEAMMM" -ForegroundColor Magenta
Write-Host ""
$UserInput = Read-Host "Press ENTER to continue, or 'N' to exit"

if ($UserInput -eq 'n' -or $UserInput -eq 'N') {
    exit
}

# --- 1. SYSTEM SAFETY ---
function Create-Restore-Point {
    Write-Host "Ensuring System Restore is enabled..." -ForegroundColor Cyan
    try {
        Set-Service -Name "sr" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name "sr" -ErrorAction SilentlyContinue
        Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
        Write-Host "Creating a System Restore Point..." -ForegroundColor Cyan
        Checkpoint-Computer -Description "Kawaii Optimization Final" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Host "System Restore Point created successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "WARNING: Could not create a System Restore Point." -ForegroundColor Red
        Write-Host "Reason: Your System Restore service might be fully broken or blocked." -ForegroundColor Yellow
        Write-Host "Continuing with script in 3 seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds 3
    }
}

# --- 2. PRIVACY & TELEMETRY ---
function Disable-Telemetry-Complete {
    Write-Host "Nuking Telemetry and Data Collection!!" -ForegroundColor Cyan
    
    # Registry Tweaks (Merged from Main & Privacy Tweaks)
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $RegistryPath -Name "AllowTelemetry" -Value 0 -Type DWord -Force
    
    # Advertising ID (From Privacy Tweaks)
    $AdPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    if (-not (Test-Path $AdPath)) { New-Item -Path $AdPath -Force | Out-Null }
    Set-ItemProperty -Path $AdPath -Name "Enabled" -Value 0 -Type DWord -Force

    # Services
    Write-Host "Stopping tracking services..." -ForegroundColor White
    $Services = "DiagTrack", "dmwappushservice", "lfsvc" # lfsvc is Geolocation
    foreach ($service in $Services) {
        sc.exe config $service start= disabled
        sc.exe stop $service
    }
    Write-Host "Telemetry services disabled." -ForegroundColor Green
}

function Set-EdgePrivacy {
    Write-Host "Configuring Edge Privacy Policies..." -ForegroundColor Cyan
    $EdgeRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $EdgeRegistryPath)) { New-Item -Path $EdgeRegistryPath -Force | Out-Null }
    Set-ItemProperty -Path $EdgeRegistryPath -Name "TrackingPrevention" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path $EdgeRegistryPath -Name "EdgeShoppingAssistantEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $EdgeRegistryPath -Name "AdvertisingIdEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $EdgeRegistryPath -Name "MetricsReportingEnabled" -Value 0 -Type DWord -Force
    Write-Host "Edge policies set." -ForegroundColor Green
}

# --- 3. BLOATWARE REMOVAL ---
function ForceRemoveEdge {
    Write-Host "> Forcefully uninstalling Microsoft Edge..." -ForegroundColor Magenta
    # (Code from Remove MS Edge.ps1)
    $regView = [Microsoft.Win32.RegistryView]::Registry32
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $regView)
    $hklm.CreateSubKey('SOFTWARE\Microsoft\EdgeUpdateDev').SetValue('AllowUninstall', '')

    $edgeStub = "$env:SystemRoot\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"
    New-Item $edgeStub -ItemType Directory -Force | Out-Null
    New-Item "$edgeStub\MicrosoftEdge.exe" -Force | Out-Null

    $uninstallRegKey = $hklm.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge')
    if ($null -ne $uninstallRegKey) {
        $uninstallString = $uninstallRegKey.GetValue('UninstallString') + ' --force-uninstall'
        Start-Process cmd.exe "/c $uninstallString" -WindowStyle Hidden -Wait

        # Cleanup Lnk files
        $edgePaths = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
            "$env:PUBLIC\Desktop\Microsoft Edge.lnk",
            "$env:USERPROFILE\Desktop\Microsoft Edge.lnk",
            "$edgeStub"
        )
        foreach ($path in $edgePaths) {
             if (Test-Path $path) { Remove-Item -Path $path -Force -Recurse -ErrorAction SilentlyContinue }
        }
        Write-Host "Edge has been forcefully removed." -ForegroundColor Green
    }
}

function Remove-Bloatware-Apps {
    Write-Host "Removing Extended Bloatware List..." -ForegroundColor Cyan
    
    $BloatwareList = @(
        # --- Microsoft Basic Bloat ---
        "Microsoft.Microsoft3DViewer", 
        "Microsoft.MixedReality.Portal",
        "Microsoft.MicrosoftOfficeHub", 
        "Microsoft.MicrosoftSolitaireCollection", 
        "Microsoft.Getstarted", # Tips
        "Microsoft.YourPhone", 
        "Microsoft.WindowsMaps", 
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.BingNews", 
        "Microsoft.BingWeather", 
        "Microsoft.BingFinance",
        "Microsoft.BingFoodAndDrink",
        "Microsoft.People",
        "microsoft.windowscommunicationsapps", # Mail & Calendar (Old)
        "Microsoft.SkypeApp", 
        "Microsoft.Teams", 
        "MSTeams", # New Teams
        "Microsoft.Print3D",
        "Microsoft.3DBuilder",
        "Microsoft.MicrosoftStickyNotes",
        "Microsoft.Copilot", 
        "Microsft.BingSearch", 
        "Microsoft.PowerAutomateDesktop",
        "Microsoft.Todos",
        "Microsoft.Office.OneNote", 
        "Microsoft.Office.Sway",
        "Microsoft.OneConnect", # Mobile plans
        "MicrosoftCorporationII.MicrosoftFamily",
        "Microsoft.Windows.DevHome",
        "Microsoft.549981C3F5F10", # Cortana
        "Microsoft.ZuneMusic", # Legacy Media Player
        "Microsoft.ZuneVideo", # Legacy Movies & TV
        
        # --- Third Party / Pre-installed Junk ---
        "Netflix.Netflix",
        "Disney.37853FC22B2CE",
        "DisneyMagicKingdoms",
        "Amazon.com.Amazon",
        "AmazonVideo.PrimeVideo",
        "PandoraMediaInc",
        "Plex",
        "Clipchamp.Clipchamp",
        "Tik-Tok",
        "Instagram",
        "Facebook",
        "Twitter",
        "WhatsApp",
        "AdobeSystemsIncorporated.AdobePhotoshopExpress",
        "AutodeskSketchBook",
        "Duolingo-LearnLanguagesforFree",
        "Flipboard.Flipboard",
        "TuneInRadio",
        "*CandyCrush*", 
        "*BubbleWitch3Saga*",
        "King.com.CandyCrushSaga",
        "King.com.CandyCrushSodaSaga",
        "MarchoEmpires",
        "Asphalt8Airborne",
        "CaesarsSlotsFreeCasino",
        "COOKINGFEVER",
        "FarmVille2CountryEscape",
        "HiddenCityMysteryofShadows",
        "ROBLOXCORPORATION.ROBLOX",
        
        # --- OEM / Security Bloat (McAfee, etc.) ---
        "5A894077.McAfeeSecurity*",
        "RealtimeboardInc.RealtimeBoard",
        "MirametrixInc.GlancebyMirametrix",
        "C27EB4BA.DropboxOEM*"
    )

    foreach ($AppName in $BloatwareList) {
        Get-AppxPackage -Name $AppName -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "Removing $($_.Name)..." -ForegroundColor DarkGray
            $_ | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        }
    }
    Write-Host "Bloatware removal complete." -ForegroundColor Green
}

function Remove-Vendor-Bloatware {
    Write-Host "Detecting PC Manufacturer..." -ForegroundColor Cyan
    $Vendor = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
    Write-Host "Vendor Detected: $Vendor" -ForegroundColor Magenta
    $UniversalBloat = @(
        "McAfee", 
        "Norton", 
        "Avast", 
        "Dropbox", 
        "Evernote", 
        "WPSOffice",
        "LinkedIn",
        "TikTok",
        "Disney",
        "Spotify",
        "Pandora"
    )

    # Vendor-Specific Lists
    $VendorLists = @{
        "HP" = @(
            "HP Audio Switch", "HP Connection Optimizer", "HP Documentation", 
            "HP JumpStart", "HP Sure Click", "HP Wolf Security", "HP Support Assistant", 
            "AD2F1837.*"
        )
        "Dell" = @(
            "Dell Digital Delivery", "Dell Help & Support", "Dell Update", 
            "SupportAssist", "Dell Power Manager", "Dell Optimizer", 
            "DellInc.DellSupportAssistforPCs"
        )
        "Lenovo" = @(
            "Lenovo Vantage", "Lenovo Utility", "Lenovo Welcome", 
            "LenovoServiceBridge", "Lenovo.Vantage", "E046963F.LenovoCompanion"
        )
        "ASUS" = @(
            "MyASUS", "ASUS GiftBox", "ASUS Live Update", 
            "B9ECED6F.ASUSPCAssistant"
        )
        "Acer" = @(
            "Acer Care Center", "Acer Collection", "Acer Jumpstart", 
            "Acer Portal", "AcerIncorporated.AcerCareCenter"
        )
        "MSI" = @(
            "Dragon Center", "MSI Center", "MSI App Player", 
            "Micro-StarInternationalCoLtd.DragonCenter"
        )
    }
    $KillList = $UniversalBloat + @()
    foreach ($Key in $VendorLists.Keys) {
        if ($Vendor -match $Key) {
            Write-Host "Loading removal list for $Key..." -ForegroundColor Green
            $KillList += $VendorLists[$Key]
        }
    }
    Write-Host "Scanning Store Apps..." -ForegroundColor Cyan
    foreach ($App in $KillList) {
        Get-AppxPackage -Name "*$App*" -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "Removing Appx: $($_.Name)..." -ForegroundColor DarkGray
            $_ | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        }
    }

    Write-Host "Scanning Installed Programs..." -ForegroundColor Cyan
    foreach ($App in $KillList) {
        Get-Package -Name "*$App*" -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "Uninstalling Program: $($_.Name)..." -ForegroundColor Magenta
            Uninstall-Package -InputObject $_ -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host "Vendor Bloatware scrubbed!" -ForegroundColor Green
}

function Remove-OneDrive {
    Write-Host "Removing OneDrive..." -ForegroundColor Cyan
    taskkill.exe /f /im OneDrive.exe > $null 2>&1
    $OneDriveSetupPath_64 = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    if (Test-Path $OneDriveSetupPath_64) { Start-Process $OneDriveSetupPath_64 "/uninstall" -Wait }
    $RegistryPath = "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    if (Test-Path $RegistryPath) { Set-ItemProperty -Path $RegistryPath -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue }
    Write-Host "OneDrive removed." -ForegroundColor Green
}

# --- 4. PERFORMANCE & POWER ---
function Set-Power-Ultimate {
    Write-Host "Setting Power Plan to Ultimate Performance!!" -ForegroundColor Cyan
    $UltimatePerformanceGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
    powercfg /duplicatescheme $UltimatePerformanceGuid | Out-Null
    powercfg /setactive $UltimatePerformanceGuid
    Write-Host "Ultimate Performance Mode: ON" -ForegroundColor Green
}

function Optimize-CPU-Memory {
    Write-Host "Optimizing CPU & Memory..." -ForegroundColor Cyan
    # CPU Priority (Win32PrioritySeparation)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 0x26 -Type DWord -Force
    
    # Memory Management (From Performance Tweaks.ps1)
    $MemoryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Set-ItemProperty -Path $MemoryPath -Name "LargeSystemCache" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $MemoryPath -Name "IoPageLockLimit" -Value 983040 -Type DWord -Force
    Set-ItemProperty -Path $MemoryPath -Name "DisablePagingExecutive" -Value 1 -Type DWord -Force
    
    # Disable SysMain
    sc.exe config SysMain start= disabled
    sc.exe stop SysMain
    
    # Disable CPU Parking
    $SubGroup = "54533251-82be-4824-96c1-47b60b740d00"
    $Setting = "0cc5b647-c1df-4637-891a-dec35c318583"
    powercfg /setacvalueindex SCHEME_CURRENT $SubGroup $Setting 100
    powercfg /setdcvalueindex SCHEME_CURRENT $SubGroup $Setting 100
    powercfg /setactive SCHEME_CURRENT
    
    Write-Host "CPU & Memory optimized." -ForegroundColor Green
}

function Set-VisualEffects {
    Write-Host "Setting Balanced Visual Effects..." -ForegroundColor Cyan
    $VisualEffectsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    Set-ItemProperty -Path $VisualEffectsPath -Name "VisualFXSetting" -Value 3 -Type DWord -Force
    $BalancedMask = [byte[]](0x90, 0x32, 0x07, 0x80, 0x10, 0x00, 0x00, 0x00)
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value $BalancedMask -Type Binary -Force    
    Write-Host "Visual effects balanced." -ForegroundColor Green
}

# --- 5. NETWORK OPTIMIZATION ---
function Optimize-Network-Stack {
    Write-Host "Optimizing Network Stack (Registry & Netsh)..." -ForegroundColor Cyan
    $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    Set-ItemProperty -Path $RegistryPath -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Type DWord -Force
    
    $InterfacesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    Get-ChildItem -Path $InterfacesPath | ForEach-Object {
        $InterfacePath = $_.PSPath
        Set-ItemProperty -Path $InterfacePath -Name "TcpAckFrequency" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $InterfacePath -Name "TCPNoDelay" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    }
    try {
        netsh int tcp set global ecncapability=disabled
        netsh int tcp set global autotuninglevel=normal
    } catch {}
    try {
        Set-NetTCPSetting -SettingName "InternetCustom" -CongestionProvider CTCP -InitialRto 2000 -MinRto 300 -ErrorAction SilentlyContinue
    } catch {}

    # 4. QoS
    $QoSPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Psched\Parameters"
    if (-not (Test-Path $QoSPath)) { New-Item $QoSPath -Force | Out-Null }
    Set-ItemProperty -Path $QoSPath -Name "NonBestEffortLimit" -Value 0 -Type DWord -Force

    Write-Host "Network stack optimized." -ForegroundColor Green
}

function Optimize-Adapters {
    Write-Host "Optimizing Physical Adapters..." -ForegroundColor Cyan
    $adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }
    
    if ($adapters) {
        # Set Cloudflare DNS
        foreach ($adapter in $adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("1.1.1.1", "1.0.0.1") -ErrorAction SilentlyContinue
            
            # Advanced Properties (RSS, Checksum)
            try { Enable-NetAdapterRss -Name $adapter.Name -ErrorAction SilentlyContinue } catch {}
            try { Set-NetAdapterChecksumOffload -Name $adapter.Name -IpIPv4Enabled -TcpIPv4Enabled -TcpIPv6Enabled -UdpIPv4Enabled -UdpIPv6Enabled -ErrorAction SilentlyContinue } catch {}
            
            # Power Saving
            try { Set-NetAdapterPowerManagement -Name $adapter.Name -ArpOffload -D0PacketCoalescing -NSOffload -RsnRekeyOffload -WakeOnMagicPacket -WakeOnPattern -DeviceSleepOnDisconnect -ErrorAction SilentlyContinue } catch {}
        }
    }
    Write-Host "Adapters configured." -ForegroundColor Green
}
# --- 6. CLEANUP & TASKS ---
function Disable-Tasks-Merged {
    Write-Host "Disabling Unwanted Scheduled Tasks..." -ForegroundColor Cyan
    $TasksToDisable = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    )
    foreach ($TaskPath in $TasksToDisable) {
        Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue
    }
    Write-Host "Tasks disabled." -ForegroundColor Green
}

function Tweaks-And-Cleanup {
    Write-Host "Applying Final UI/UX Tweaks..." -ForegroundColor Cyan
    
    # Disable Mouse Accel
    $MouseRegistryPath = "HKCU:\Control Panel\Mouse"
    Set-ItemProperty -Path $MouseRegistryPath -Name "MouseSpeed" -Value "0" -Type String -Force
    
    # Context Menu (Classic & Ownership)
    $RegPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
    Set-ItemProperty -Path $RegPath -Name "(Default)" -Value "" -Type String -Force
    
    # Disable Web Search in Start
    $PolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    if (-not (Test-Path $PolicyPath)) { New-Item -Path $PolicyPath -Force | Out-Null }
    Set-ItemProperty -Path $PolicyPath -Name "DisableSearchBoxSuggestions" -Value 1 -Type DWord -Force

    # Disable Background Apps
    $BgPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
    if (-not (Test-Path $BgPath)) { New-Item -Path $BgPath -Force | Out-Null }
    Set-ItemProperty -Path $BgPath -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force

    # Flush DNS
    ipconfig /flushdns | Out-Null
    
    Write-Host "UI & System Cleaned." -ForegroundColor Green
}

# --- EXECUTION ---
Create-Restore-Point
Disable-Telemetry-Complete
Set-EdgePrivacy
ForceRemoveEdge
Remove-Bloatware-Apps
Remove-OneDrive
Set-Power-Ultimate
Optimize-CPU-Memory
Set-VisualEffects
Optimize-Network-Stack
Optimize-Adapters
Disable-Tasks-Merged
Tweaks-And-Cleanup

Write-Host "==========================================================" -ForegroundColor Magenta
Write-Host "   OPTIMIZATION COMPLETE! PLEASE RESTART YOUR PC NOW!     " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Magenta
Write-Host "FACE YOUR FEARSSS" -ForegroundColor Red
Start-Process "https://t8xh.cc"

Read-Host "Press Enter to exit..."



