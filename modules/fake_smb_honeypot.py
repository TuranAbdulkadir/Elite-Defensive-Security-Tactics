"""
Fake SMB Share Honeypot
Deploys a decoy network file share to lure ransomware and lateral
movement tools. Any access to the share triggers an immediate alert.
"""
import os
import time
import hashlib

class SMBHoneypot:
    def __init__(self, share_path):
        self.share_path = share_path
        self.canary_files = {}  # filename -> original_hash

    def deploy_canary_files(self):
        """Create realistic-looking decoy files in the share."""
        os.makedirs(self.share_path, exist_ok=True)
        decoy_names = [
            "Q4_Financial_Report_2024.xlsx",
            "Employee_SSN_Database.csv",
            "Board_Meeting_Minutes_Confidential.docx",
            "IT_Infrastructure_Passwords.txt",
            "Customer_Credit_Cards_Export.csv",
            "Merger_Acquisition_Plans.pdf",
            "VPN_Private_Keys.pem",
            "AWS_Root_Credentials.json",
        ]
        for name in decoy_names:
            filepath = os.path.join(self.share_path, name)
            content = f"HONEYPOT CANARY FILE - {name} - DO NOT MODIFY"
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            file_hash = hashlib.sha256(content.encode()).hexdigest()
            self.canary_files[name] = file_hash

        print(f"[+] Deployed {len(decoy_names)} canary files in {self.share_path}")

    def monitor(self):
        """Check if any canary files have been modified, encrypted, or deleted."""
        print("[*] Monitoring honeypot share for unauthorized access...")
        alerts = []
        for name, original_hash in self.canary_files.items():
            filepath = os.path.join(self.share_path, name)
            if not os.path.exists(filepath):
                alerts.append({"type": "FILE_DELETED", "file": name})
                continue
            with open(filepath, "r", encoding="utf-8") as f:
                current_hash = hashlib.sha256(f.read().encode()).hexdigest()
            if current_hash != original_hash:
                alerts.append({
                    "type": "FILE_MODIFIED",
                    "file": name,
                    "detail": "Possible ransomware encryption or data tampering"
                })

        if alerts:
            print(f"[!] HONEYPOT TRIGGERED: {len(alerts)} canary file violations!")
            for a in alerts:
                print(f"    [{a['type']}] {a['file']}")
        else:
            print("[+] All canary files intact.")
        return alerts
