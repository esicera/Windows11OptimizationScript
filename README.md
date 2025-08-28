# 🛠️ Windows 11 Optimization Script

A lightweight, modular PowerShell script designed to streamline, debloat, and optimize Windows 11 for improved performance, privacy, and usability. Ideal for fresh installs, gaming rigs, and power users.

---

## ⚡ Features (Planned or Included)

Privacy: It disables system telemetry, location tracking, Cortana, and background apps. It also changes Microsoft Edge's privacy settings.

Performance: It disables non-essential services (SysMain, Prefetch), sets the power plan to "Ultimate Performance," prioritizes CPU resources for active applications, disables mouse acceleration, and speeds up UI animations.

Debloating & UI: It removes a curated list of pre-installed bloatware apps, restores the classic Windows 10 right-click menu, and cleans up File Explorer by hiding recent files and showing hidden items/extensions.

Cleanup & Network: It permanently deletes temporary files and prefetch data. It also switches your DNS to Cloudflare's faster servers for better browsing speed.

---

## 🚀 Quick Start

> **Warning:** Use at your own risk. This script makes system-level changes. Always back up important data first. **CREATE A RESTORE POINT!!**

To run the latest version directly:
```powershell
PowerShell -ExecutionPolicy Bypass -Command "iex (irm "https://raw.githubusercontent.com/esicera/Windows11OptimizationScript/main/main.ps1")"
