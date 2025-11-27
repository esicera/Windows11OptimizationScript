# 🛠️ Windows 11 Optimization Script (v3.0)

A powerful, all-in-one PowerShell script designed to streamline, debloat, and optimize Windows 11 for maximum performance, privacy. Now integrated with advanced network and privacy modules.
CHECK MY SHOWCASE! 
---
https://youtu.be/3eIEDpaehE8?feature=shared
---

![meow](https://github.com/esicera/Windows11OptimizationScript/blob/main/kira%20kira%20beam.gif)

## ⚡ Features (v3.0 Updated)

**🔥 Privacy & Extreme Debloating:** - **Telemetry Nuke:** Completely disables system telemetry, DiagTrack, and data collection services.
- **Edge Remover:** **NEW!** Includes a "Force Removal" module to completely uninstall Microsoft Edge and its leftovers.
- **Bloatware Banished:** Removes an extensive list of pre-installed apps (Candy Crush, Teams, Cortana, etc.) and completely uninstalls OneDrive.
- **Advertising ID:** Now disables the user Advertising ID for extra privacy.

**🚀 Ultimate Performance & Gaming:** - **Power Unleashed:** Automatically enforces the **Ultimate Performance** power plan.
- **CPU & Memory:** Optimizes `Win32PrioritySeparation` for foreground apps, disables CPU Core Parking, and tweaks memory management (LargeSystemCache, IoPageLockLimit).
- **Visuals:** Applies a balanced visual effects mask—keeping fonts smooth while disabling laggy animations.

**🌐 Advanced Network Optimization:** - **Aggressive Tuning:** **NEW!** Implements aggressive TCP/IP settings (CTCP Congestion Provider, InitialRto 2000) for lower latency.
- **Throttling Disabled:** Removes network throttling limits and disables QoS `NonBestEffortLimit`.
- **Adapter Tweaks:** Enables RSS (Receive Side Scaling) and Checksum Offloading, while disabling power-saving features on network adapters.
- **DNS:** Sets Cloudflare DNS (1.1.1.1) for faster lookup speeds.

**✨ UI & Quality of Life:** - **Classic Vibes:** Restores the classic Windows 10 right-click context menu and adds a "Take Ownership" button.
- **Mouse Fix:** Disables mouse acceleration for consistent aim/movement.
- **Start Menu:** Configures a cleaner Start Menu layout with fewer suggestions and ads.

---

## 🚀 Quick Start

> **Warning:** Use at your own risk. This script makes system-level changes (Registry, Services, Uninstallation). Always back up important data first. **CREATE A RESTORE POINT!!**
To run the latest version directly:
```powershell
PowerShell -ExecutionPolicy Bypass -Command "iex (irm '[https://raw.githubusercontent.com/esicera/Windows11OptimizationScript/main/main.ps1](https://raw.githubusercontent.com/esicera/Windows11OptimizationScript/main/main.ps1)')"
