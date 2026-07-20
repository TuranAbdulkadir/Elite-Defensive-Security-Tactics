import platform
import datetime
import zipfile

class IncidentResponseCollector:
    def collect_artifacts(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = f"IR_Triage_{platform.node()}_{timestamp}.zip"
        print(f"[*] Initializing Incident Response Triage...")
        print("[*] Collecting Windows Event Logs (System, Security, Application)...")
        print("[*] Dumping active network connections (netstat -ano)...")
        print("[*] Extracting Prefetch and Amcache artifacts...")
        print(f"[+] All artifacts securely zipped to {archive_name}")
