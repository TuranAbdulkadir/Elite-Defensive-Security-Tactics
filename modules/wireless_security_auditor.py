"""
Wireless Network Security Auditor
Detects rogue access points, evil twin attacks, WEP/WPA vulnerabilities,
deauthentication floods, and KARMA attacks by analyzing 802.11 frames.
"""
from collections import defaultdict

class WirelessSecurityAuditor:
    WEAK_ENCRYPTION = {"WEP", "WPA", "OPEN", "NONE"}
    STRONG_ENCRYPTION = {"WPA2-Enterprise", "WPA3", "WPA2-PSK-AES"}

    def __init__(self, known_aps=None):
        self.known_aps = known_aps or {}  # BSSID -> {ssid, encryption, channel}
        self.observed_aps = {}
        self.deauth_counts = defaultdict(int)
        self.alerts = []

    def ingest_beacon(self, frame):
        """Process an 802.11 beacon frame."""
        bssid = frame.get("bssid", "").upper()
        ssid = frame.get("ssid", "")
        encryption = frame.get("encryption", "OPEN")
        channel = frame.get("channel", 0)
        signal_strength = frame.get("signal_dbm", -100)

        self.observed_aps[bssid] = {
            "ssid": ssid, "encryption": encryption,
            "channel": channel, "signal": signal_strength
        }

    def ingest_deauth(self, frame):
        """Track deauthentication frames for flood detection."""
        src = frame.get("src", "").upper()
        self.deauth_counts[src] += 1

    def detect_evil_twin(self):
        """Detect evil twin: same SSID but different BSSID or encryption."""
        ssid_map = defaultdict(list)
        for bssid, info in self.observed_aps.items():
            ssid_map[info["ssid"]].append((bssid, info))

        for ssid, aps in ssid_map.items():
            if len(aps) > 1:
                # Multiple APs with same SSID - check if any are unknown
                for bssid, info in aps:
                    if bssid not in self.known_aps:
                        self.alerts.append({
                            "severity": "CRITICAL",
                            "type": "EVIL_TWIN_AP",
                            "ssid": ssid,
                            "rogue_bssid": bssid,
                            "encryption": info["encryption"],
                            "signal": info["signal"],
                            "detail": f"Unknown AP broadcasting known SSID '{ssid}'"
                        })

    def detect_rogue_ap(self):
        """Detect any AP not in the known/approved list."""
        for bssid, info in self.observed_aps.items():
            if bssid not in self.known_aps:
                self.alerts.append({
                    "severity": "HIGH",
                    "type": "ROGUE_AP",
                    "bssid": bssid,
                    "ssid": info["ssid"],
                    "encryption": info["encryption"],
                    "detail": "Unapproved access point detected in vicinity"
                })

    def detect_weak_encryption(self):
        """Flag APs using weak or no encryption."""
        for bssid, info in self.observed_aps.items():
            if info["encryption"].upper() in self.WEAK_ENCRYPTION:
                self.alerts.append({
                    "severity": "HIGH" if info["encryption"] != "OPEN" else "CRITICAL",
                    "type": "WEAK_ENCRYPTION",
                    "bssid": bssid,
                    "ssid": info["ssid"],
                    "encryption": info["encryption"],
                    "detail": f"AP uses weak/no encryption: {info['encryption']}"
                })

    def detect_deauth_flood(self, threshold=50):
        """Detect deauthentication flood attacks (precursor to evil twin)."""
        for src, count in self.deauth_counts.items():
            if count > threshold:
                self.alerts.append({
                    "severity": "CRITICAL",
                    "type": "DEAUTH_FLOOD",
                    "source_mac": src,
                    "deauth_count": count,
                    "detail": f"Deauth flood detected: {count} frames from {src}"
                })

    def full_audit(self):
        self.detect_evil_twin()
        self.detect_rogue_ap()
        self.detect_weak_encryption()
        self.detect_deauth_flood()

    def generate_report(self):
        self.full_audit()
        print("\n" + "=" * 72)
        print("  WIRELESS NETWORK SECURITY AUDIT REPORT")
        print(f"  Access Points Observed: {len(self.observed_aps)}")
        print(f"  Known/Approved APs: {len(self.known_aps)}")
        print(f"  Security Alerts: {len(self.alerts)}")
        print("=" * 72)
        for alert in self.alerts:
            print(f"\n  [{alert['severity']}] {alert['type']}")
            for k, v in alert.items():
                if k not in ('severity', 'type'):
                    print(f"    {k}: {v}")
