"""
NetSentinel - Windows Defender Firewall Active Defense (IPS)
Automates creation, deletion, and synchronization of real Windows Firewall inbound BLOCK rules.
"""

import os
import sys
import subprocess
from typing import List, Dict, Any, Optional

FIREWALL_RULE_PREFIX = "NetSentinel-Block-"
SCRIPT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
FIREWALL_BAT_PATH = os.path.join(SCRIPT_DIR, "apply_firewall_rules.bat")
FIREWALL_PS1_PATH = os.path.join(SCRIPT_DIR, "apply_firewall_rules.ps1")


class WindowsFirewallManager:
    def __init__(self):
        os.makedirs(SCRIPT_DIR, exist_ok=True)
        self.is_admin = self._check_admin()
        self.quarantined_ips: Dict[str, Dict[str, str]] = {}

    def _check_admin(self) -> bool:
        """Check if current process has elevated Administrator privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def block_ip(self, ip: str, reason: str = "Hostile Traffic Detected") -> Dict[str, Any]:
        """Create inbound firewall rule blocking the specified IP."""
        clean_ip = ip.strip()
        rule_name = f"{FIREWALL_RULE_PREFIX}{clean_ip}"
        applied_live = False

        if self.is_admin:
            try:
                # Execute native netsh advfirewall command
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={clean_ip}",
                    f"description=Blocked by NetSentinel IPS: {reason}"
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0 or "Ok." in res.stdout:
                    applied_live = True
            except Exception as e:
                print(f"[!] Direct firewall rule failed: {e}")

        # Store in state
        record = {
            "ip": clean_ip,
            "rule_name": rule_name,
            "reason": reason,
            "status": "LIVE_ENFORCED" if applied_live else "QUEUED_ELEVATED_SYNC",
            "enforced": applied_live
        }
        self.quarantined_ips[clean_ip] = record

        # Automatically export/update the Windows elevated batch script
        self.export_firewall_scripts()

        return record

    def unblock_ip(self, ip: str) -> bool:
        """Remove firewall rule for the specified IP."""
        clean_ip = ip.strip()
        rule_name = f"{FIREWALL_RULE_PREFIX}{clean_ip}"

        if self.is_admin:
            try:
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            except Exception:
                pass

        if clean_ip in self.quarantined_ips:
            del self.quarantined_ips[clean_ip]

        self.export_firewall_scripts()
        return True

    def export_firewall_scripts(self):
        """Generates ready-to-run elevated batch and powershell scripts for Windows."""
        try:
            # 1. Batch Script
            bat_lines = [
                "@echo off",
                ":: NetSentinel Windows Defender Firewall Sync Script",
                ":: Run as Administrator to apply all active quarantine rules",
                "echo ======================================================================",
                "echo   NetSentinel Active Defense - Synchronizing Windows Defender Firewall",
                "echo ======================================================================",
                "net session >nul 2>&1",
                "if %ERRORLEVEL% NEQ 0 (",
                "    echo [ERROR] This script requires Administrator privileges.",
                "    echo Right-click this file and select 'Run as administrator'.",
                "    pause",
                "    exit /b 1",
                ")",
                "echo [INFO] Applying active block rules...",
                ""
            ]

            for ip, data in self.quarantined_ips.items():
                rule = data["rule_name"]
                reason = data["reason"].replace('"', '')
                # Delete existing rule first to prevent duplicate entries
                bat_lines.append(f'netsh advfirewall firewall delete rule name="{rule}" >nul 2>&1')
                bat_lines.append(f'netsh advfirewall firewall add rule name="{rule}" dir=in action=block remoteip={ip} description="NetSentinel IPS: {reason}"')

            bat_lines.extend([
                "",
                "echo ======================================================================",
                "echo   [SUCCESS] Windows Defender Firewall rules synchronized successfully!",
                "echo ======================================================================",
                "pause"
            ])

            with open(FIREWALL_BAT_PATH, "w", encoding="utf-8") as f:
                f.write("\n".join(bat_lines))

            # 2. PowerShell Script
            ps_lines = [
                "# NetSentinel Windows Defender Firewall Sync Script (PowerShell)",
                "# Requires elevated privileges",
                "Write-Host '======================================================================' -ForegroundColor Cyan",
                "Write-Host '  NetSentinel - Synchronizing Windows Firewall via NetSecurity' -ForegroundColor Cyan",
                "Write-Host '======================================================================' -ForegroundColor Cyan",
                ""
            ]

            for ip, data in self.quarantined_ips.items():
                rule = data["rule_name"]
                ps_lines.append(f'Remove-NetFirewallRule -DisplayName "{rule}" -ErrorAction SilentlyContinue')
                ps_lines.append(f'New-NetFirewallRule -DisplayName "{rule}" -Direction Inbound -Action Block -RemoteAddress "{ip}" -Description "NetSentinel IPS Block" | Out-Null')
                ps_lines.append(f'Write-Host "  [+] Blocked Remote IP: {ip}" -ForegroundColor Red')

            ps_lines.extend([
                "",
                "Write-Host '`n[SUCCESS] Windows Firewall rules applied successfully!' -ForegroundColor Green"
            ])

            with open(FIREWALL_PS1_PATH, "w", encoding="utf-8") as f:
                f.write("\n".join(ps_lines))

        except Exception as e:
            print(f"[!] Failed to export firewall scripts: {e}")

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_admin": self.is_admin,
            "mode": "ACTIVE_OS_ENFORCED" if self.is_admin else "ACTIVE_SYNC_SCRIPT_READY",
            "active_rules_count": len(self.quarantined_ips),
            "script_bat_path": FIREWALL_BAT_PATH,
            "script_ps1_path": FIREWALL_PS1_PATH
        }


global_firewall = WindowsFirewallManager()
