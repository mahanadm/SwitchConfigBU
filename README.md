# Switch Config Backup Tool

A PowerShell WinForms GUI application for managing network switches — primarily Hirschmann and Cisco devices.

## Features

- **Scan & Discover** — CIDR subnet scanning with automatic device identification (Hirschmann/Cisco)
- **Credentials** — Encrypted credential management using Windows DPAPI
- **Backup** — Download running configurations from switches via SSH (plink)
- **Audit** — Run batches of show commands across multiple switches and save results
- **Discovery** — HiDiscovery v2 protocol support for Hirschmann switch discovery, IP assignment, and management

## Requirements

- Windows with PowerShell 5.1+
- [PuTTY/plink.exe](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) (for SSH connections)

## Quick Start

1. Run `SwitchConfigBackup.bat` (or run `SwitchConfigBackup.ps1` directly with `-ExecutionPolicy Bypass`)
2. Add credentials on the **Credentials** tab
3. Enter a subnet on the **Scan & Discover** tab and click **Scan**
4. Use **Backup** or **Audit** tabs to pull configs or run commands on discovered devices

## Files

| File | Purpose |
|------|---------|
| `SwitchConfigBackup.ps1` | Main application script |
| `SwitchConfigBackup.bat` | Launcher with ExecutionPolicy bypass |
| `audit_cisco_commands.json` | Default Cisco show commands for audit |
| `audit_hirschmann_commands.json` | Default Hirschmann show commands for audit |
