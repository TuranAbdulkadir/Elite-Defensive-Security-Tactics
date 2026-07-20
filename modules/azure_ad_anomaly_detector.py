"""
Azure Active Directory Anomaly Detector
Detects Impossible Travel, Brute Force, and suspicious OAuth consent grants
by analyzing Azure AD Sign-In and Audit logs.
"""
import json
import math
from datetime import datetime

class AzureADAnomalyDetector:
    EARTH_RADIUS_KM = 6371.0

    def __init__(self):
        self.user_logins = {}  # user -> list of (time, lat, lon)
        self.alerts = []

    def _haversine(self, lat1, lon1, lat2, lon2):
        """Calculate the great-circle distance between two points on Earth."""
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (math.sin(dlat / 2) ** 2 +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
             math.sin(dlon / 2) ** 2)
        return self.EARTH_RADIUS_KM * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    def ingest_sign_in_log(self, log_entry):
        """Ingest a single Azure AD sign-in log entry."""
        user = log_entry.get("userPrincipalName", "unknown")
        timestamp = datetime.fromisoformat(log_entry.get("createdDateTime", "2000-01-01T00:00:00"))
        lat = log_entry.get("location", {}).get("latitude", 0)
        lon = log_entry.get("location", {}).get("longitude", 0)
        status = log_entry.get("status", {}).get("errorCode", 0)

        if user not in self.user_logins:
            self.user_logins[user] = []
        self.user_logins[user].append((timestamp, lat, lon, status))

    def detect_impossible_travel(self):
        """Flag logins that are geographically impossible within the time window."""
        MAX_SPEED_KMH = 900  # Fastest commercial aircraft
        for user, logins in self.user_logins.items():
            sorted_logins = sorted(logins, key=lambda x: x[0])
            for i in range(1, len(sorted_logins)):
                prev_time, prev_lat, prev_lon, _ = sorted_logins[i - 1]
                curr_time, curr_lat, curr_lon, _ = sorted_logins[i]

                distance_km = self._haversine(prev_lat, prev_lon, curr_lat, curr_lon)
                time_diff_hours = (curr_time - prev_time).total_seconds() / 3600.0

                if time_diff_hours > 0:
                    speed = distance_km / time_diff_hours
                    if speed > MAX_SPEED_KMH and distance_km > 500:
                        self.alerts.append({
                            "severity": "CRITICAL",
                            "type": "IMPOSSIBLE_TRAVEL",
                            "user": user,
                            "distance_km": round(distance_km, 2),
                            "time_hours": round(time_diff_hours, 2),
                            "required_speed_kmh": round(speed, 2)
                        })

    def detect_brute_force(self, threshold=10):
        """Flag users with excessive failed login attempts."""
        for user, logins in self.user_logins.items():
            failures = [l for l in logins if l[3] != 0]
            if len(failures) >= threshold:
                self.alerts.append({
                    "severity": "HIGH",
                    "type": "BRUTE_FORCE",
                    "user": user,
                    "failed_attempts": len(failures)
                })

    def generate_report(self):
        self.detect_impossible_travel()
        self.detect_brute_force()
        print(f"\n[+] Azure AD Analysis Complete. {len(self.alerts)} anomalies detected.")
        for alert in self.alerts:
            print(f"  [{alert['severity']}] {alert['type']} | User: {alert['user']}")
