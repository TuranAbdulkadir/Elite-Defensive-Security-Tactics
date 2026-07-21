"""
Network Traffic Baseline Anomaly Detector
Builds a statistical baseline of normal network traffic patterns (bytes/sec,
connections/min, protocol distribution) and flags deviations using
Z-score analysis and Exponentially Weighted Moving Average (EWMA).
"""
import math
import statistics
from collections import defaultdict
from datetime import datetime, timedelta

class NetworkBaselineAnalyzer:
    def __init__(self, z_threshold=3.0, ewma_alpha=0.3):
        self.z_threshold = z_threshold
        self.ewma_alpha = ewma_alpha
        self.baseline = {}
        self.current_metrics = {}
        self.anomalies = []

    def build_baseline(self, historical_data):
        """Build baseline from historical network metrics.
        historical_data: list of {timestamp, bytes_in, bytes_out, 
                                   connections, protocol_counts}
        """
        metrics = defaultdict(list)
        for entry in historical_data:
            metrics["bytes_in"].append(entry.get("bytes_in", 0))
            metrics["bytes_out"].append(entry.get("bytes_out", 0))
            metrics["connections"].append(entry.get("connections", 0))
            metrics["unique_destinations"].append(
                len(entry.get("destinations", [])))

            for proto, count in entry.get("protocol_counts", {}).items():
                metrics[f"proto_{proto}"].append(count)

        for metric_name, values in metrics.items():
            if len(values) >= 2:
                self.baseline[metric_name] = {
                    "mean": statistics.mean(values),
                    "stdev": statistics.stdev(values),
                    "median": statistics.median(values),
                    "min": min(values),
                    "max": max(values),
                    "p95": sorted(values)[int(len(values) * 0.95)],
                    "ewma": values[-1]
                }

        print(f"[+] Baseline built from {len(historical_data)} samples "
              f"across {len(self.baseline)} metrics.")

    def _update_ewma(self, metric_name, new_value):
        """Update the Exponentially Weighted Moving Average for a metric."""
        if metric_name in self.baseline:
            old_ewma = self.baseline[metric_name]["ewma"]
            new_ewma = self.ewma_alpha * new_value + (1 - self.ewma_alpha) * old_ewma
            self.baseline[metric_name]["ewma"] = new_ewma
            return new_ewma
        return new_value

    def analyze_window(self, current_data):
        """Analyze a current time window against the baseline."""
        timestamp = current_data.get("timestamp", datetime.utcnow().isoformat())

        checks = {
            "bytes_in": current_data.get("bytes_in", 0),
            "bytes_out": current_data.get("bytes_out", 0),
            "connections": current_data.get("connections", 0),
            "unique_destinations": len(current_data.get("destinations", [])),
        }
        for proto, count in current_data.get("protocol_counts", {}).items():
            checks[f"proto_{proto}"] = count

        for metric_name, current_value in checks.items():
            if metric_name not in self.baseline:
                continue

            bl = self.baseline[metric_name]
            stdev = bl["stdev"] if bl["stdev"] > 0 else 1.0
            z_score = (current_value - bl["mean"]) / stdev

            self._update_ewma(metric_name, current_value)

            if abs(z_score) > self.z_threshold:
                direction = "SPIKE" if z_score > 0 else "DROP"
                self.anomalies.append({
                    "timestamp": timestamp,
                    "metric": metric_name,
                    "direction": direction,
                    "current_value": current_value,
                    "baseline_mean": round(bl["mean"], 2),
                    "baseline_stdev": round(bl["stdev"], 2),
                    "z_score": round(z_score, 2),
                    "severity": "CRITICAL" if abs(z_score) > 5 else "HIGH"
                })

    def generate_report(self):
        print("\n" + "=" * 72)
        print("  NETWORK BASELINE ANOMALY DETECTION REPORT")
        print(f"  Baseline Metrics: {len(self.baseline)}")
        print(f"  Anomalies Detected: {len(self.anomalies)}")
        print(f"  Z-Score Threshold: {self.z_threshold}")
        print("=" * 72)

        if self.baseline:
            print("\n  --- BASELINE SUMMARY ---")
            for name, bl in self.baseline.items():
                print(f"  {name:25s} mean={bl['mean']:.1f}  stdev={bl['stdev']:.1f}  "
                      f"p95={bl['p95']:.1f}  ewma={bl['ewma']:.1f}")

        if self.anomalies:
            print("\n  --- ANOMALIES ---")
            for a in self.anomalies:
                print(f"  [{a['severity']}] {a['direction']} in {a['metric']}")
                print(f"    Current: {a['current_value']}  "
                      f"Baseline: {a['baseline_mean']} +/- {a['baseline_stdev']}  "
                      f"Z-Score: {a['z_score']}")
