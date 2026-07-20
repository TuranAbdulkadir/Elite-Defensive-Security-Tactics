"""
AWS CloudTrail Threat Hunter
Parses CloudTrail JSON logs to detect unauthorized API calls,
privilege escalation attempts, and data exfiltration patterns.
"""
import json
import os
from datetime import datetime, timedelta

class CloudTrailHunter:
    CRITICAL_EVENTS = [
        "CreateAccessKey", "AttachUserPolicy", "PutBucketPolicy",
        "AuthorizeSecurityGroupIngress", "RunInstances", "CreateLoginProfile",
        "UpdateAssumeRolePolicy", "PutRolePolicy", "DisableCloudTrail",
        "StopLogging", "DeleteTrail", "CreateNetworkAclEntry"
    ]

    EXFILTRATION_EVENTS = [
        "GetObject", "CopyObject", "CreateSnapshot", "ModifySnapshotAttribute",
        "SharedSnapshotVolumeCreated", "PutBucketAcl"
    ]

    def __init__(self):
        self.alerts = []

    def parse_log_file(self, filepath):
        """Parse a single CloudTrail JSON log file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        for record in data.get("Records", []):
            event_name = record.get("eventName", "")
            source_ip = record.get("sourceIPAddress", "unknown")
            user_arn = record.get("userIdentity", {}).get("arn", "unknown")
            event_time = record.get("eventTime", "")
            error_code = record.get("errorCode", None)

            # Detect privilege escalation
            if event_name in self.CRITICAL_EVENTS:
                self.alerts.append({
                    "severity": "CRITICAL",
                    "type": "PRIVILEGE_ESCALATION",
                    "event": event_name,
                    "actor": user_arn,
                    "source_ip": source_ip,
                    "time": event_time
                })

            # Detect data exfiltration patterns
            if event_name in self.EXFILTRATION_EVENTS:
                self.alerts.append({
                    "severity": "HIGH",
                    "type": "DATA_EXFILTRATION",
                    "event": event_name,
                    "actor": user_arn,
                    "source_ip": source_ip,
                    "time": event_time
                })

            # Detect access denied floods (credential stuffing / recon)
            if error_code == "AccessDenied":
                self.alerts.append({
                    "severity": "MEDIUM",
                    "type": "RECON_ACCESS_DENIED",
                    "event": event_name,
                    "actor": user_arn,
                    "source_ip": source_ip,
                    "time": event_time
                })

    def scan_directory(self, log_dir):
        """Recursively scan a directory of CloudTrail logs."""
        print(f"[*] Scanning CloudTrail logs in {log_dir}")
        for root, dirs, files in os.walk(log_dir):
            for fname in files:
                if fname.endswith(".json"):
                    self.parse_log_file(os.path.join(root, fname))
        print(f"[+] Scan complete. {len(self.alerts)} alerts generated.")
        return self.alerts

    def generate_report(self):
        """Print a formatted threat report."""
        print("\n" + "=" * 70)
        print("  AWS CLOUDTRAIL THREAT HUNTING REPORT")
        print("=" * 70)
        for alert in self.alerts:
            print(f"  [{alert['severity']}] {alert['type']}")
            print(f"    Event:  {alert['event']}")
            print(f"    Actor:  {alert['actor']}")
            print(f"    Source: {alert['source_ip']}")
            print(f"    Time:   {alert['time']}")
            print("-" * 70)
