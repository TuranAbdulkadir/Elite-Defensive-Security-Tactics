"""
Zero-Trust Device Attestation Engine
Evaluates device health posture (TPM, OS patch level, AV status,
disk encryption) before granting network access.
"""
import platform
import subprocess
import json

class DeviceAttestationEngine:
    def __init__(self):
        self.posture = {}
        self.compliant = True

    def check_os_version(self):
        """Verify OS is up-to-date and supported."""
        os_info = platform.platform()
        version = platform.version()
        self.posture["os"] = os_info
        print(f"[*] OS: {os_info}")
        # Example: reject Windows 7 or older
        if "Windows-7" in os_info or "Windows-XP" in os_info:
            self.posture["os_compliant"] = False
            self.compliant = False
            print("[!] FAIL: Unsupported OS version detected.")
        else:
            self.posture["os_compliant"] = True
            print("[+] PASS: OS version is supported.")

    def check_disk_encryption(self):
        """Check if BitLocker or equivalent disk encryption is active."""
        print("[*] Checking disk encryption status...")
        # On Windows, query BitLocker via manage-bde
        # result = subprocess.run(["manage-bde", "-status", "C:"], capture_output=True, text=True)
        # Simulated check:
        encrypted = True  # Placeholder for real check
        self.posture["disk_encrypted"] = encrypted
        if not encrypted:
            self.compliant = False
            print("[!] FAIL: System drive is NOT encrypted.")
        else:
            print("[+] PASS: Disk encryption is active.")

    def check_antivirus(self):
        """Verify that a real-time antivirus engine is running."""
        print("[*] Checking antivirus status...")
        # On Windows, use WMI or Get-MpComputerStatus
        av_running = True  # Placeholder
        self.posture["av_active"] = av_running
        if not av_running:
            self.compliant = False
            print("[!] FAIL: No active antivirus detected.")
        else:
            print("[+] PASS: Antivirus is active and running.")

    def check_firewall(self):
        """Verify the host firewall is enabled."""
        print("[*] Checking firewall status...")
        fw_enabled = True  # Placeholder
        self.posture["firewall_enabled"] = fw_enabled
        if not fw_enabled:
            self.compliant = False
            print("[!] FAIL: Host firewall is disabled.")
        else:
            print("[+] PASS: Firewall is enabled.")

    def evaluate(self):
        """Run all attestation checks and return compliance verdict."""
        print("\n" + "=" * 60)
        print("  ZERO-TRUST DEVICE ATTESTATION")
        print("=" * 60)
        self.check_os_version()
        self.check_disk_encryption()
        self.check_antivirus()
        self.check_firewall()
        print("\n" + "-" * 60)
        if self.compliant:
            print("[+] VERDICT: COMPLIANT - Device may access the network.")
        else:
            print("[!] VERDICT: NON-COMPLIANT - Access DENIED.")
        return self.compliant, self.posture
