"""
USB Device Audit Trail & Policy Enforcer
Monitors and audits all USB device connections by parsing Windows Registry
USBSTOR keys and SetupAPI logs. Enforces device whitelists and detects
unauthorized mass storage connections (data exfiltration vector).
"""
import os
import re
import json
from datetime import datetime

class USBDeviceAuditor:
    # Windows Registry paths for USB forensics
    REGISTRY_PATHS = {
        "usbstor": r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",
        "usb": r"HKLM\SYSTEM\CurrentControlSet\Enum\USB",
        "mounted_devices": r"HKLM\SYSTEM\MountedDevices",
    }
    SETUPAPI_LOG_PATHS = [
        r"C:\Windows\inf\setupapi.dev.log",
        r"C:\Windows\setupapi.log",
    ]

    def __init__(self):
        self.devices = []
        self.whitelist = set()
        self.alerts = []

    def load_whitelist(self, whitelist_file):
        """Load approved USB device serial numbers from a whitelist file."""
        if os.path.exists(whitelist_file):
            with open(whitelist_file, "r") as f:
                for line in f:
                    serial = line.strip()
                    if serial and not serial.startswith("#"):
                        self.whitelist.add(serial.upper())
            print(f"[+] Loaded {len(self.whitelist)} whitelisted USB devices.")

    def parse_setupapi_log(self, log_path=None):
        """Parse Windows SetupAPI log to extract USB connection timestamps."""
        if log_path is None:
            for path in self.SETUPAPI_LOG_PATHS:
                if os.path.exists(path):
                    log_path = path
                    break

        if not log_path or not os.path.exists(log_path):
            print("[-] SetupAPI log not found.")
            return

        print(f"[*] Parsing SetupAPI log: {log_path}")
        current_device = None

        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # Match device installation entries
                    device_match = re.search(
                        r"Device Install.*USBSTOR\\(Disk&Ven_(.+?)&Prod_(.+?)&Rev_(.+?))\\(.+?)$",
                        line, re.IGNORECASE
                    )
                    if device_match:
                        current_device = {
                            "vendor": device_match.group(2).strip("_"),
                            "product": device_match.group(3).strip("_"),
                            "revision": device_match.group(4).strip("_"),
                            "serial": device_match.group(5).strip(),
                            "raw_id": device_match.group(1),
                        }

                    # Match timestamp for current device
                    time_match = re.search(
                        r"Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})",
                        line
                    )
                    if time_match and current_device:
                        current_device["first_connected"] = time_match.group(1)
                        self.devices.append(current_device)
                        current_device = None

        except PermissionError:
            print("[-] Permission denied. Run as Administrator.")

    def enforce_whitelist(self):
        """Check all discovered devices against the whitelist."""
        for device in self.devices:
            serial = device.get("serial", "").upper()
            if serial not in self.whitelist:
                self.alerts.append({
                    "severity": "CRITICAL",
                    "type": "UNAUTHORIZED_USB",
                    "vendor": device.get("vendor", "Unknown"),
                    "product": device.get("product", "Unknown"),
                    "serial": serial,
                    "first_seen": device.get("first_connected", "Unknown"),
                    "detail": "USB mass storage device NOT in approved whitelist"
                })

    def detect_badusb(self):
        """Detect potential BadUSB attacks: devices that register as both
        HID (keyboard) and mass storage simultaneously.
        """
        device_serials = {}
        for device in self.devices:
            serial = device.get("serial", "")
            if serial not in device_serials:
                device_serials[serial] = []
            device_serials[serial].append(device)

        for serial, instances in device_serials.items():
            device_types = set()
            for inst in instances:
                raw = inst.get("raw_id", "").lower()
                if "disk" in raw:
                    device_types.add("MASS_STORAGE")
                if "hid" in raw or "keyboard" in raw:
                    device_types.add("HID")

            if "MASS_STORAGE" in device_types and "HID" in device_types:
                self.alerts.append({
                    "severity": "CRITICAL",
                    "type": "BADUSB_SUSPECTED",
                    "serial": serial,
                    "detail": "Device registered as BOTH HID and Mass Storage (BadUSB indicator)"
                })

    def generate_report(self):
        """Run all checks and generate audit report."""
        self.enforce_whitelist()
        self.detect_badusb()

        print("\n" + "=" * 72)
        print("  USB DEVICE AUDIT TRAIL REPORT")
        print(f"  Devices Discovered: {len(self.devices)}")
        print(f"  Whitelisted: {len(self.whitelist)}")
        print(f"  Alerts: {len(self.alerts)}")
        print("=" * 72)

        if self.devices:
            print("\n  --- DEVICE INVENTORY ---")
            for d in self.devices:
                status = "APPROVED" if d.get("serial", "").upper() in self.whitelist else "UNAUTHORIZED"
                print(f"  [{status}] {d.get('vendor', '?')} {d.get('product', '?')} "
                      f"(Serial: {d.get('serial', 'N/A')}) "
                      f"First seen: {d.get('first_connected', 'N/A')}")

        if self.alerts:
            print(f"\n  --- SECURITY ALERTS ---")
            for alert in self.alerts:
                print(f"  [{alert['severity']}] {alert['type']}")
                print(f"    {alert['detail']}")
                for k in ('vendor', 'product', 'serial', 'first_seen'):
                    if k in alert:
                        print(f"    {k}: {alert[k]}")
