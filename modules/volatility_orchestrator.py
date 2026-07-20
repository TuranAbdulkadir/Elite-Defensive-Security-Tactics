"""
Volatility Memory Forensics Orchestrator
Automates a full memory forensics triage pipeline using
the Volatility3 framework API patterns.
"""
import os
import json
from datetime import datetime

class VolatilityOrchestrator:
    SUSPICIOUS_PROCESS_NAMES = [
        "mimikatz", "procdump", "psexec", "cobalt", "beacon",
        "meterpreter", "powershell_ise", "certutil", "bitsadmin",
        "rundll32", "regsvr32", "mshta", "wscript", "cscript"
    ]

    def __init__(self, memory_image_path):
        self.image_path = memory_image_path
        self.findings = []

    def enumerate_processes(self, process_list):
        """Analyze a list of running processes from a memory dump."""
        print(f"[*] Analyzing {len(process_list)} processes from memory image...")
        for proc in process_list:
            name = proc.get("name", "").lower()
            pid = proc.get("pid", 0)
            ppid = proc.get("ppid", 0)
            cmdline = proc.get("cmdline", "")

            # Check for known malicious process names
            for suspicious in self.SUSPICIOUS_PROCESS_NAMES:
                if suspicious in name:
                    self.findings.append({
                        "type": "SUSPICIOUS_PROCESS",
                        "severity": "CRITICAL",
                        "name": name,
                        "pid": pid,
                        "ppid": ppid,
                        "cmdline": cmdline
                    })

            # Detect process name masquerading (e.g., svchost.exe not spawned by services.exe)
            if name == "svchost.exe" and ppid != 684:  # 684 is typical services.exe PID
                self.findings.append({
                    "type": "PROCESS_MASQUERADING",
                    "severity": "HIGH",
                    "detail": f"svchost.exe (PID {pid}) has unexpected parent PID {ppid}",
                })

    def detect_code_injection(self, vad_list):
        """Check Virtual Address Descriptors for injected executable memory regions."""
        print("[*] Scanning VAD tree for injected code regions...")
        for vad in vad_list:
            protection = vad.get("protection", "")
            tag = vad.get("tag", "")
            # PAGE_EXECUTE_READWRITE is highly suspicious for non-image VADs
            if "EXECUTE_READWRITE" in protection and tag != "Vad ":
                self.findings.append({
                    "type": "CODE_INJECTION",
                    "severity": "CRITICAL",
                    "vad_start": vad.get("start"),
                    "vad_end": vad.get("end"),
                    "protection": protection
                })

    def detect_hidden_modules(self, loaded_modules, peb_modules):
        """Cross-reference PEB module list with VAD to find unlinked DLLs."""
        print("[*] Cross-referencing PEB module list with VAD entries...")
        peb_set = set(m.lower() for m in peb_modules)
        loaded_set = set(m.lower() for m in loaded_modules)
        hidden = loaded_set - peb_set
        for mod in hidden:
            self.findings.append({
                "type": "HIDDEN_MODULE",
                "severity": "CRITICAL",
                "module": mod,
                "detail": "Module found in VAD but unlinked from PEB (rootkit behavior)"
            })

    def generate_report(self, output_path=None):
        print(f"\n{'=' * 70}")
        print("  MEMORY FORENSICS TRIAGE REPORT")
        print(f"  Image: {self.image_path}")
        print(f"  Findings: {len(self.findings)}")
        print(f"{'=' * 70}")
        for f in self.findings:
            print(f"  [{f['severity']}] {f['type']}")
            for k, v in f.items():
                if k not in ('severity', 'type'):
                    print(f"    {k}: {v}")
            print(f"  {'-' * 66}")

        if output_path:
            with open(output_path, "w", encoding="utf-8") as out:
                json.dump(self.findings, out, indent=2)
            print(f"\n[+] Report saved to {output_path}")
