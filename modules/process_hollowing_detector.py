"""
Process Hollowing Detector
Detects process hollowing (RunPE) by comparing the on-disk image
of a process with its in-memory representation.
"""
import os
import hashlib

class ProcessHollowingDetector:
    SYSTEM_PROCESSES = {
        "svchost.exe": r"C:\Windows\System32\svchost.exe",
        "lsass.exe": r"C:\Windows\System32\lsass.exe",
        "csrss.exe": r"C:\Windows\System32\csrss.exe",
        "smss.exe": r"C:\Windows\System32\smss.exe",
        "wininit.exe": r"C:\Windows\System32\wininit.exe",
        "services.exe": r"C:\Windows\System32\services.exe",
        "explorer.exe": r"C:\Windows\explorer.exe",
    }

    def __init__(self):
        self.alerts = []

    def _hash_file(self, filepath):
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except FileNotFoundError:
            return None

    def compare_disk_vs_memory(self, process_name, memory_hash):
        """Compare the on-disk hash of a system binary with its in-memory hash."""
        expected_path = self.SYSTEM_PROCESSES.get(process_name.lower())
        if not expected_path:
            return  # Not a monitored system process

        disk_hash = self._hash_file(expected_path)
        if disk_hash is None:
            self.alerts.append({
                "severity": "HIGH",
                "type": "MISSING_BINARY",
                "process": process_name,
                "detail": f"Expected binary not found at {expected_path}"
            })
            return

        if disk_hash != memory_hash:
            self.alerts.append({
                "severity": "CRITICAL",
                "type": "PROCESS_HOLLOWING",
                "process": process_name,
                "disk_hash": disk_hash,
                "memory_hash": memory_hash,
                "detail": "In-memory image does NOT match on-disk binary. Possible code replacement."
            })
        else:
            print(f"  [OK] {process_name}: disk and memory hashes match.")

    def scan_all(self, running_processes):
        """Scan all running processes for hollowing indicators."""
        print("[*] Scanning for Process Hollowing (RunPE) indicators...")
        for proc in running_processes:
            self.compare_disk_vs_memory(proc["name"], proc.get("memory_hash", ""))
        print(f"[+] Scan complete. {len(self.alerts)} alerts.")
        return self.alerts
