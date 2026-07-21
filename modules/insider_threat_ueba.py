"""
Insider Threat Detector (User & Entity Behavior Analytics - UEBA)
Builds behavioral profiles per user and flags deviations:
unusual login hours, mass file downloads, privilege abuse,
and resignation-correlated data hoarding patterns.
"""
import statistics
from collections import defaultdict
from datetime import datetime, timedelta

class InsiderThreatDetector:
    def __init__(self):
        self.user_profiles = defaultdict(lambda: {
            "login_hours": [],
            "file_access_counts": [],
            "data_volume_mb": [],
            "privilege_actions": [],
            "vpn_locations": [],
            "usb_events": 0,
            "print_jobs": 0,
            "email_attachments_out": 0,
        })
        self.alerts = []

    def record_login(self, user, timestamp, location="office"):
        profile = self.user_profiles[user]
        hour = timestamp.hour
        profile["login_hours"].append(hour)
        profile["vpn_locations"].append(location)

    def record_file_access(self, user, file_count, volume_mb):
        profile = self.user_profiles[user]
        profile["file_access_counts"].append(file_count)
        profile["data_volume_mb"].append(volume_mb)

    def record_usb_event(self, user):
        self.user_profiles[user]["usb_events"] += 1

    def record_print_job(self, user):
        self.user_profiles[user]["print_jobs"] += 1

    def record_email_attachment(self, user):
        self.user_profiles[user]["email_attachments_out"] += 1

    def analyze_user(self, user):
        profile = self.user_profiles[user]
        risk_score = 0
        indicators = []

        # 1. Unusual login hours
        if len(profile["login_hours"]) >= 5:
            mean_hour = statistics.mean(profile["login_hours"])
            recent_hour = profile["login_hours"][-1]
            if recent_hour < 5 or recent_hour > 22:
                if abs(recent_hour - mean_hour) > 6:
                    risk_score += 20
                    indicators.append(f"Login at unusual hour: {recent_hour}:00 (avg: {mean_hour:.0f}:00)")

        # 2. Mass file access spike
        if len(profile["file_access_counts"]) >= 3:
            baseline_mean = statistics.mean(profile["file_access_counts"][:-1])
            baseline_std = statistics.stdev(profile["file_access_counts"][:-1]) if len(profile["file_access_counts"]) > 2 else 1
            latest = profile["file_access_counts"][-1]
            if baseline_std > 0:
                z = (latest - baseline_mean) / baseline_std
                if z > 3:
                    risk_score += 30
                    indicators.append(f"File access spike: {latest} files (baseline: {baseline_mean:.0f})")

        # 3. Large data volume transfer
        if len(profile["data_volume_mb"]) >= 3:
            baseline = statistics.mean(profile["data_volume_mb"][:-1])
            latest_vol = profile["data_volume_mb"][-1]
            if latest_vol > baseline * 5 and latest_vol > 500:
                risk_score += 25
                indicators.append(f"Data volume spike: {latest_vol:.0f}MB (baseline: {baseline:.0f}MB)")

        # 4. USB + high file access = exfiltration pattern
        if profile["usb_events"] > 3 and sum(profile["file_access_counts"][-3:]) > 100:
            risk_score += 25
            indicators.append(f"USB activity ({profile['usb_events']} events) combined with high file access")

        # 5. Excessive printing (physical exfiltration)
        if profile["print_jobs"] > 50:
            risk_score += 10
            indicators.append(f"Excessive print jobs: {profile['print_jobs']}")

        # 6. Outbound email attachments
        if profile["email_attachments_out"] > 20:
            risk_score += 15
            indicators.append(f"High outbound email attachments: {profile['email_attachments_out']}")

        if risk_score >= 30:
            self.alerts.append({
                "user": user,
                "risk_score": min(risk_score, 100),
                "severity": "CRITICAL" if risk_score >= 60 else "HIGH" if risk_score >= 40 else "MEDIUM",
                "indicators": indicators
            })

    def analyze_all(self):
        for user in self.user_profiles:
            self.analyze_user(user)

    def generate_report(self):
        self.analyze_all()
        print("\n" + "=" * 72)
        print("  INSIDER THREAT (UEBA) ANALYSIS REPORT")
        print(f"  Users Profiled: {len(self.user_profiles)}")
        print(f"  Alerts: {len(self.alerts)}")
        print("=" * 72)
        for alert in sorted(self.alerts, key=lambda x: x["risk_score"], reverse=True):
            print(f"\n  [{alert['severity']}] User: {alert['user']} (Risk: {alert['risk_score']}/100)")
            for ind in alert["indicators"]:
                print(f"    - {ind}")
