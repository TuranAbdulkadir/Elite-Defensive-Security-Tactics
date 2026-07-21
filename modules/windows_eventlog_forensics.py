"""
Windows Event Log Forensics Engine
Parses and correlates Windows Security, System, and PowerShell event logs
to reconstruct attacker kill chains using MITRE ATT&CK event ID mappings.
"""
import xml.etree.ElementTree as ET
import re
import json
from datetime import datetime
from collections import defaultdict

class WindowsEventLogForensics:
    # MITRE ATT&CK Event ID Mapping
    ATTACK_MAP = {
        # Credential Access
        4625: {"technique": "T1110", "tactic": "Credential Access", "name": "Failed Logon (Brute Force)"},
        4648: {"technique": "T1078", "tactic": "Credential Access", "name": "Explicit Credential Logon"},
        4768: {"technique": "T1558.003", "tactic": "Credential Access", "name": "Kerberos TGT Request (AS-REP Roast)"},
        4769: {"technique": "T1558.003", "tactic": "Credential Access", "name": "Kerberos Service Ticket (Kerberoast)"},
        
        # Privilege Escalation
        4672: {"technique": "T1078", "tactic": "Privilege Escalation", "name": "Special Privileges Assigned"},
        4728: {"technique": "T1098", "tactic": "Persistence", "name": "User Added to Security-Enabled Global Group"},
        4732: {"technique": "T1098", "tactic": "Persistence", "name": "User Added to Local Group"},
        
        # Lateral Movement
        4624: {"technique": "T1021", "tactic": "Lateral Movement", "name": "Successful Logon"},
        4648: {"technique": "T1021", "tactic": "Lateral Movement", "name": "Logon Using Explicit Credentials"},
        
        # Defense Evasion
        1102: {"technique": "T1070.001", "tactic": "Defense Evasion", "name": "Audit Log Cleared"},
        4719: {"technique": "T1562.002", "tactic": "Defense Evasion", "name": "System Audit Policy Changed"},
        
        # Execution
        4688: {"technique": "T1059", "tactic": "Execution", "name": "New Process Created"},
        4104: {"technique": "T1059.001", "tactic": "Execution", "name": "PowerShell Script Block Logging"},
        
        # Persistence
        7045: {"technique": "T1543.003", "tactic": "Persistence", "name": "New Service Installed"},
        4698: {"technique": "T1053.005", "tactic": "Persistence", "name": "Scheduled Task Created"},
    }
    
    LOGON_TYPE_MAP = {
        2: "Interactive (local keyboard)",
        3: "Network (SMB/RPC)",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        8: "NetworkCleartext",
        9: "NewCredentials (runas /netonly)",
        10: "RemoteInteractive (RDP)",
        11: "CachedInteractive",
    }

    def __init__(self):
        self.events = []
        self.timeline = []
        self.alerts = []
        self.failed_logon_tracker = defaultdict(list)

    def parse_evtx_xml(self, xml_string):
        """Parse a Windows Event Log entry exported as XML."""
        try:
            root = ET.fromstring(xml_string)
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            
            system = root.find("ns:System", ns)
            event_id = int(system.find("ns:EventID", ns).text)
            timestamp = system.find("ns:TimeCreated", ns).attrib.get("SystemTime", "")
            computer = system.find("ns:Computer", ns).text
            
            event_data = {}
            for data_elem in root.findall(".//ns:EventData/ns:Data", ns):
                name = data_elem.attrib.get("Name", "")
                value = data_elem.text or ""
                event_data[name] = value

            parsed = {
                "event_id": event_id,
                "timestamp": timestamp,
                "computer": computer,
                "data": event_data
            }
            self.events.append(parsed)
            return parsed
        except ET.ParseError:
            return None

    def correlate_brute_force(self, threshold=5, window_minutes=10):
        """Detect brute force attempts: multiple failed logons from same source."""
        for event in self.events:
            if event["event_id"] == 4625:
                source_ip = event["data"].get("IpAddress", "unknown")
                target_user = event["data"].get("TargetUserName", "unknown")
                self.failed_logon_tracker[source_ip].append(event)

        for source_ip, failures in self.failed_logon_tracker.items():
            if len(failures) >= threshold:
                # Check if followed by successful logon (4624) = compromised
                success_after = any(
                    e["event_id"] == 4624 and 
                    e["data"].get("IpAddress") == source_ip
                    for e in self.events
                )
                self.alerts.append({
                    "severity": "CRITICAL" if success_after else "HIGH",
                    "type": "BRUTE_FORCE_SUCCESS" if success_after else "BRUTE_FORCE_ATTEMPT",
                    "source_ip": source_ip,
                    "failed_attempts": len(failures),
                    "compromised": success_after,
                    "detail": "Attacker succeeded after brute force!" if success_after else "Multiple failed logons detected"
                })

    def detect_lateral_movement(self):
        """Detect lateral movement patterns: Type 3 (network) logons from internal IPs."""
        internal_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                           "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                           "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                           "172.30.", "172.31.", "192.168.")
        for event in self.events:
            if event["event_id"] == 4624:
                logon_type = int(event["data"].get("LogonType", 0))
                source_ip = event["data"].get("IpAddress", "")
                target_user = event["data"].get("TargetUserName", "")
                
                if logon_type == 3 and any(source_ip.startswith(p) for p in internal_prefixes):
                    # Network logon from internal IP = potential lateral movement
                    self.timeline.append({
                        "time": event["timestamp"],
                        "action": "LATERAL_MOVEMENT",
                        "source": source_ip,
                        "target_user": target_user,
                        "logon_type": self.LOGON_TYPE_MAP.get(logon_type, "Unknown"),
                        "computer": event["computer"]
                    })

    def detect_defense_evasion(self):
        """Detect log tampering: audit log cleared (1102) or policy changed (4719)."""
        for event in self.events:
            if event["event_id"] in (1102, 4719):
                attack_info = self.ATTACK_MAP.get(event["event_id"], {})
                self.alerts.append({
                    "severity": "CRITICAL",
                    "type": "DEFENSE_EVASION",
                    "technique": attack_info.get("technique", ""),
                    "name": attack_info.get("name", ""),
                    "timestamp": event["timestamp"],
                    "actor": event["data"].get("SubjectUserName", "SYSTEM"),
                    "detail": "Attacker is covering tracks by clearing or modifying audit logs"
                })

    def detect_persistence(self):
        """Detect persistence mechanisms: new services (7045) and scheduled tasks (4698)."""
        for event in self.events:
            if event["event_id"] == 7045:
                service_name = event["data"].get("ServiceName", "unknown")
                image_path = event["data"].get("ImagePath", "unknown")
                self.alerts.append({
                    "severity": "HIGH",
                    "type": "PERSISTENCE_SERVICE",
                    "service": service_name,
                    "binary": image_path,
                    "timestamp": event["timestamp"]
                })
            elif event["event_id"] == 4698:
                task_name = event["data"].get("TaskName", "unknown")
                self.alerts.append({
                    "severity": "HIGH",
                    "type": "PERSISTENCE_SCHEDULED_TASK",
                    "task": task_name,
                    "timestamp": event["timestamp"]
                })

    def build_kill_chain(self):
        """Run all detection modules and construct an attacker kill chain timeline."""
        self.correlate_brute_force()
        self.detect_lateral_movement()
        self.detect_defense_evasion()
        self.detect_persistence()

    def generate_report(self):
        """Print formatted forensics report with MITRE ATT&CK mappings."""
        self.build_kill_chain()
        print("\n" + "=" * 76)
        print("  WINDOWS EVENT LOG FORENSICS REPORT")
        print(f"  Events Analyzed: {len(self.events)}")
        print(f"  Alerts: {len(self.alerts)}")
        print(f"  Timeline Entries: {len(self.timeline)}")
        print("=" * 76)

        if self.alerts:
            print("\n  --- SECURITY ALERTS ---")
            for alert in sorted(self.alerts, key=lambda x: x["severity"]):
                print(f"\n  [{alert['severity']}] {alert['type']}")
                for k, v in alert.items():
                    if k not in ("severity", "type"):
                        print(f"    {k}: {v}")

        if self.timeline:
            print("\n  --- ATTACK TIMELINE ---")
            for entry in self.timeline:
                print(f"  {entry['time']} | {entry['action']} | "
                      f"{entry['source']} -> {entry['computer']} "
                      f"(user: {entry['target_user']})")
        print("\n" + "=" * 76)
