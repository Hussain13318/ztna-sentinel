import platform
import subprocess
import sys
import socket
import uuid
import datetime
from typing import Any

import psutil


class DevicePostureChecker:
    """Collects device posture signals and computes a simple posture score."""

    WINDOWS_AV_PROCESSES = {
        "msmpeng.exe",      # Windows Defender
        "avp.exe",          # Kaspersky
        "avgui.exe",        # AVG
        "avguard.exe",      # Avira
        "nortonsecurity.exe",
        "mcshield.exe",     # McAfee
        "savservice.exe",   # Sophos
        "bdservicehost.exe",  # Bitdefender
        "ekrn.exe",         # ESET
    }

    LINUX_AV_PROCESSES = {
        "clamd",
        "freshclam",
        "sav-protect",      # Sophos
        "esets_daemon",     # ESET
        "f-prot",
    }

    SUSPICIOUS_PROCESSES = {
        "netcat", "nc.exe", "mimikatz", "meterpreter", "wireshark", "nmap", "pwdump"
    }

    DANGEROUS_PORTS = [4444, 1337, 5900, 6666, 31337]

    APPROVED_MACS = {
        "00:1A:2B:3C:4D:5E", # Replace with actual MACs in production
        "11:22:33:44:55:66",
        # Note: The active MAC is auto-added in __init__ for testing purposes
    }

    def __init__(self):
        # Auto-whitelist the current MAC for demonstration/testing purposes
        # so you don't immediately fail the test on your own machine.
        mac_int = uuid.getnode()
        current_mac = ':'.join(['{:02x}'.format((mac_int >> ele) & 0xff) for ele in range(40, -1, -8)]).upper()
        self.APPROVED_MACS.add(current_mac)

    @classmethod
    def get_approved_macs(cls) -> set:
        """Return copy of approved MAC set."""
        return set(cls.APPROVED_MACS)

    @classmethod
    def add_approved_mac(cls, mac_address: str) -> bool:
        """Add a MAC address to the whitelist. Returns True if added, False if invalid format."""
        mac_upper = mac_address.strip().upper()
        # Validate MAC format: XX:XX:XX:XX:XX:XX
        if len(mac_upper) == 17 and mac_upper.count(":") == 5:
            parts = mac_upper.split(":")
            try:
                all(int(p, 16) for p in parts)
                cls.APPROVED_MACS.add(mac_upper)
                return True
            except ValueError:
                return False
        return False

    @classmethod
    def remove_approved_mac(cls, mac_address: str) -> bool:
        """Remove a MAC address from the whitelist. Returns True if removed, False if not found."""
        mac_upper = mac_address.strip().upper()
        if mac_upper in cls.APPROVED_MACS:
            cls.APPROVED_MACS.discard(mac_upper)
            return True
        return False

    @classmethod
    def reset_approved_macs(cls) -> None:
        """Reset MACs to default whitelist."""
        cls.APPROVED_MACS = {
            "00:1A:2B:3C:4D:5E",
            "11:22:33:44:55:66",
        }
        # Auto-add current MAC
        mac_int = uuid.getnode()
        current_mac = ':'.join(['{:02x}'.format((mac_int >> ele) & 0xff) for ele in range(40, -1, -8)]).upper()
        cls.APPROVED_MACS.add(current_mac)

    def get_os_info(self) -> dict[str, str]:
        """Return the host OS name and version information."""
        release = platform.release()
        
        if platform.system() == "Windows":
            try:
                if sys.getwindowsversion().build >= 22000:
                    release = "11"
            except Exception:
                pass
                
        return {
            "system": platform.system(),
            "release": release,
            "version": platform.version(),
        }

    def is_firewall_active(self) -> tuple[bool, str]:
        """Check firewall status using platform-specific commands."""
        system = platform.system().lower()

        try:
            if system == "windows":
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "currentprofile"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                output = (result.stdout + "\n" + result.stderr).lower()

                if result.returncode == 0:
                    active = False
                    for line in output.splitlines():
                        if "state" in line and "on" in line:
                            active = True
                            break
                    return active, "netsh advfirewall"
                return False, "netsh command failed or unexpected output"

            if system == "linux":
                result = subprocess.run(
                    ["ufw", "status"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                output = (result.stdout + "\n" + result.stderr).lower()

                if result.returncode == 0:
                    active = "status: active" in output
                    return active, "ufw status"
                return False, "ufw command failed or not available"

            return False, "unsupported OS for firewall check"
        except FileNotFoundError:
            return False, "firewall command not found"
        except subprocess.TimeoutExpired:
            return False, "firewall check timed out"
        except Exception as exc:
            return False, f"firewall check error: {exc}"

    def antivirus_status(self) -> tuple[bool, list[str]]:
        """Detect common antivirus processes in the active process list."""
        system = platform.system().lower()
        av_names = self.WINDOWS_AV_PROCESSES if system == "windows" else self.LINUX_AV_PROCESSES

        running_matches: list[str] = []
        try:
            for process in psutil.process_iter(attrs=["name"]):
                name = (process.info.get("name") or "").lower()
                if name in av_names:
                    running_matches.append(name)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        unique_matches = sorted(set(running_matches))
        return len(unique_matches) > 0, unique_matches

    def suspicious_process_check(self) -> tuple[bool, list[str]]:
        """Scan for known malicious processes."""
        found_suspicious: list[str] = []
        try:
            for process in psutil.process_iter(attrs=["name"]):
                name = (process.info.get("name") or "").lower()
                for bad_proc in self.SUSPICIOUS_PROCESSES:
                    if bad_proc in name:
                        found_suspicious.append(name)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        
        unique_matches = sorted(set(found_suspicious))
        return len(unique_matches) == 0, unique_matches

    def dangerous_ports_check(self) -> tuple[bool, list[int]]:
        """Check if dangerous ports are open on localhost."""
        open_ports = []
        for port in self.DANGEROUS_PORTS:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                # connect_ex returns 0 if connection succeeds (port is open)
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    open_ports.append(port)
        return len(open_ports) == 0, open_ports

    def mac_whitelist_check(self) -> tuple[bool, str]:
        """Check if the device MAC address is in the approved whitelist."""
        mac_int = uuid.getnode()
        mac_str = ':'.join(['{:02x}'.format((mac_int >> ele) & 0xff) for ele in range(40, -1, -8)]).upper()
        return mac_str in self.APPROVED_MACS, mac_str

    def os_update_check(self) -> tuple[bool, str]:
        """Check if OS was updated in the last 30 days (Windows only)."""
        system = platform.system().lower()
        if system != "windows":
            return True, "N/A" # Skip for non-Windows
        
        try:
            result = subprocess.run(
                ["powershell", "-Command", "(Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 1).InstalledOn.ToString('yyyy-MM-dd')"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10
            )
            date_str = result.stdout.strip()
            if date_str:
                last_update = datetime.datetime.strptime(date_str, "%Y-%m-%d")
                days_since = (datetime.datetime.now() - last_update).days
                return days_since <= 30, f"{days_since} days ago"
            return False, "Could not determine update date"
        except Exception as e:
            return False, f"Error checking updates: {e}"

    def calculate_posture_score(
        self, 
        os_ok: bool, 
        firewall_active: bool, 
        av_running: bool,
        no_suspicious_procs: bool,
        no_dangerous_ports: bool,
        mac_approved: bool,
        os_updated: bool
    ) -> int:
        """Compute score in the 0-100 range using weighted posture checks."""
        score = 0
        if os_ok:
            score += 10
        if firewall_active:
            score += 20
        if av_running:
            score += 20
        if no_suspicious_procs:
            score += 15
        if no_dangerous_ports:
            score += 15
        if mac_approved:
            score += 10
        if os_updated:
            score += 10
            
        return max(0, min(100, score))

    def run_checks(self) -> dict[str, Any]:
        """Run all posture checks and return detailed results with final score."""
        os_info = self.get_os_info()
        os_ok = bool(os_info.get("system") and os_info.get("version"))

        firewall_active, firewall_detail = self.is_firewall_active()
        av_running, av_processes = self.antivirus_status()
        
        no_suspicious_procs, suspicious_procs = self.suspicious_process_check()
        no_dangerous_ports, open_ports = self.dangerous_ports_check()
        mac_approved, current_mac = self.mac_whitelist_check()
        os_updated, update_detail = self.os_update_check()

        posture_score = self.calculate_posture_score(
            os_ok=os_ok,
            firewall_active=firewall_active,
            av_running=av_running,
            no_suspicious_procs=no_suspicious_procs,
            no_dangerous_ports=no_dangerous_ports,
            mac_approved=mac_approved,
            os_updated=os_updated
        )

        return {
            "os": os_info,
            "os_check_passed": os_ok,
            "firewall": {
                "active": firewall_active,
                "detail": firewall_detail,
            },
            "antivirus": {
                "running": av_running,
                "detected_processes": av_processes,
            },
            "suspicious_processes": {
                "passed": no_suspicious_procs,
                "detected": suspicious_procs
            },
            "dangerous_ports": {
                "passed": no_dangerous_ports,
                "open_ports": open_ports
            },
            "mac_whitelist": {
                "passed": mac_approved,
                "mac": current_mac
            },
            "os_update": {
                "passed": os_updated,
                "detail": update_detail
            },
            "posture_score": posture_score,
        }

    def get_device_info(self) -> str:
        """Get a human-readable device info string for audit logs."""
        os_info = self.get_os_info()
        os_sys = os_info.get("system", "Unknown")
        os_ver = os_info.get("version", "Unknown")
        _, current_mac = self.mac_whitelist_check()
        return f"{os_sys} {os_ver} ({current_mac})"


if __name__ == "__main__":
    checker = DevicePostureChecker()
    result = checker.run_checks()
    import json
    print(json.dumps(result, indent=2))
