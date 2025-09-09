# 🛠️ Windows 11 Optimization Script

A lightweight, modular PowerShell script designed to streamline, debloat, and optimize Windows 11 for improved performance, privacy, and usability. Ideal for fresh installs, gaming rigs, and power users.

---

![meow](https://github.com/esicera/Windows11OptimizationScript/blob/main/kira%20kira%20beam.gif)

## ⚡ Features

Privacy & Debloating: Disables system telemetry, location tracking, and Cortana. It removes a long list of pre-installed bloatware apps and completely uninstalls OneDrive. It also tightens Microsoft Edge's privacy settings to reduce tracking.

Performance & Gaming: Disables non-essential services like SysMain (Superfetch), sets the power plan to Ultimate Performance, and optimizes CPU scheduling for foreground apps. Includes advanced network optimizations to disable throttling, lower gaming latency by optimizing TCP/IP (disabling Nagle's Algorithm), and configure advanced adapter properties for maximum throughput.

UI & Customization: Restores the classic Windows 10 right-click menu, disables mouse acceleration, and speeds up UI animations. It also adds a powerful "Take Ownership" command to the context menu for easy file permission changes and cleans up File Explorer for a minimalist look.

System & Cleanup: Clears all temp files, prefetch data, and flushes DNS cache to resolve potential issues. It also switches your DNS to CLoudflare for improved browsing speed (goat)

---

## 🚀 Quick Start

> **Warning:** Use at your own risk. This script makes system-level changes. Always back up important data first. **CREATE A RESTORE POINT!!**

To run the latest version directly:
```powershell
PowerShell -ExecutionPolicy Bypass -Command "iex (irm "https://raw.githubusercontent.com/esicera/Windows11OptimizationScript/main/main.ps1")"
