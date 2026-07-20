"""
Behavioral Biometrics Session Monitor
Analyzes keystroke dynamics (dwell time, flight time) and mouse
movement patterns to detect session hijacking in real-time.
"""
import time
import statistics

class KeystrokeDynamicsAnalyzer:
    def __init__(self):
        self.baseline_dwell_times = []
        self.baseline_flight_times = []
        self.threshold_std_devs = 2.5

    def record_baseline(self, keystroke_events):
        """Build a behavioral baseline from a series of keystroke events.
        Each event is a dict: {key, press_time, release_time}
        """
        for i, event in enumerate(keystroke_events):
            dwell = event["release_time"] - event["press_time"]
            self.baseline_dwell_times.append(dwell)
            if i > 0:
                flight = event["press_time"] - keystroke_events[i - 1]["release_time"]
                self.baseline_flight_times.append(flight)

        print(f"[*] Baseline recorded: {len(keystroke_events)} keystrokes")
        print(f"    Avg dwell: {statistics.mean(self.baseline_dwell_times):.4f}s")
        if self.baseline_flight_times:
            print(f"    Avg flight: {statistics.mean(self.baseline_flight_times):.4f}s")

    def analyze_session(self, live_events):
        """Compare live keystrokes against the baseline to detect anomalies."""
        if len(self.baseline_dwell_times) < 5:
            print("[-] Insufficient baseline data.")
            return False

        baseline_mean = statistics.mean(self.baseline_dwell_times)
        baseline_std = statistics.stdev(self.baseline_dwell_times) if len(self.baseline_dwell_times) > 1 else 0.01

        anomalies = 0
        for event in live_events:
            dwell = event["release_time"] - event["press_time"]
            z_score = abs(dwell - baseline_mean) / baseline_std if baseline_std > 0 else 0
            if z_score > self.threshold_std_devs:
                anomalies += 1

        anomaly_rate = anomalies / len(live_events) if live_events else 0
        if anomaly_rate > 0.3:
            print(f"[!] SESSION HIJACK ALERT: {anomaly_rate:.0%} of keystrokes deviate from baseline.")
            return True
        else:
            print(f"[+] Session appears legitimate. Anomaly rate: {anomaly_rate:.0%}")
            return False
