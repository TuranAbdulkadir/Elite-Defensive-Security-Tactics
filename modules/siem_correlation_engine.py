"""
SIEM-Lite: Log Correlation & Alert Engine
A lightweight Security Information and Event Management (SIEM) engine
that ingests logs from multiple sources and correlates them using
rule-based pattern matching to detect complex multi-stage attacks.
"""
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict

class CorrelationRule:
    """Defines a correlation rule that triggers when conditions are met."""
    def __init__(self, name, severity, conditions, window_seconds=300, threshold=1):
        self.name = name
        self.severity = severity
        self.conditions = conditions  # list of {field: regex_pattern}
        self.window_seconds = window_seconds
        self.threshold = threshold

class SIEMCorrelationEngine:
    def __init__(self):
        self.events = []
        self.rules = []
        self.alerts = []
        self._load_default_rules()

    def _load_default_rules(self):
        """Load built-in correlation rules for common attack patterns."""
        self.rules = [
            CorrelationRule(
                name="Brute Force -> Successful Login",
                severity="CRITICAL",
                conditions=[
                    {"event_type": "auth_failure"},
                    {"event_type": "auth_success"}
                ],
                window_seconds=600,
                threshold=5
            ),
            CorrelationRule(
                name="Port Scan -> Service Exploitation",
                severity="HIGH",
                conditions=[
                    {"event_type": "connection_attempt"},
                    {"event_type": "exploit_detected"}
                ],
                window_seconds=300,
                threshold=20
            ),
            CorrelationRule(
                name="Privilege Escalation Chain",
                severity="CRITICAL",
                conditions=[
                    {"event_type": "auth_success"},
                    {"event_type": "privilege_change"},
                    {"event_type": "sensitive_file_access"}
                ],
                window_seconds=900,
                threshold=1
            ),
            CorrelationRule(
                name="Data Exfiltration Pattern",
                severity="CRITICAL",
                conditions=[
                    {"event_type": "large_upload"},
                ],
                window_seconds=60,
                threshold=3
            ),
        ]

    def ingest_event(self, event):
        """Ingest a normalized log event.
        Expected format: {timestamp, source_ip, event_type, details, raw_log}
        """
        if isinstance(event.get("timestamp"), str):
            try:
                event["timestamp"] = datetime.fromisoformat(event["timestamp"])
            except ValueError:
                event["timestamp"] = datetime.utcnow()
        self.events.append(event)

    def correlate(self):
        """Run all correlation rules against ingested events."""
        sorted_events = sorted(self.events, key=lambda e: e["timestamp"])

        for rule in self.rules:
            # Group events by source_ip
            by_source = defaultdict(list)
            for event in sorted_events:
                by_source[event.get("source_ip", "unknown")].append(event)

            for source_ip, source_events in by_source.items():
                # Check if all conditions are met within the time window
                condition_matches = [[] for _ in rule.conditions]

                for event in source_events:
                    for idx, condition in enumerate(rule.conditions):
                        match = all(
                            re.search(pattern, str(event.get(field, "")))
                            for field, pattern in condition.items()
                        )
                        if match:
                            condition_matches[idx].append(event)

                # Verify all conditions have matches
                if all(len(matches) >= (rule.threshold if i == 0 else 1)
                       for i, matches in enumerate(condition_matches)):
                    # Verify time window
                    first_event = condition_matches[0][0]
                    last_condition = condition_matches[-1]
                    if last_condition:
                        last_event = last_condition[-1]
                        time_diff = (last_event["timestamp"] - first_event["timestamp"]).total_seconds()
                        if time_diff <= rule.window_seconds:
                            self.alerts.append({
                                "rule": rule.name,
                                "severity": rule.severity,
                                "source_ip": source_ip,
                                "time_span_seconds": round(time_diff),
                                "matched_events": sum(len(m) for m in condition_matches),
                                "first_seen": first_event["timestamp"].isoformat(),
                                "last_seen": last_event["timestamp"].isoformat()
                            })

    def generate_report(self):
        self.correlate()
        print("\n" + "=" * 72)
        print("  SIEM-LITE CORRELATION ENGINE REPORT")
        print(f"  Total Events Ingested: {len(self.events)}")
        print(f"  Correlation Rules: {len(self.rules)}")
        print(f"  Alerts Triggered: {len(self.alerts)}")
        print("=" * 72)
        for alert in self.alerts:
            print(f"\n  [{alert['severity']}] {alert['rule']}")
            print(f"    Source IP:     {alert['source_ip']}")
            print(f"    Time Span:    {alert['time_span_seconds']}s")
            print(f"    Events:       {alert['matched_events']}")
            print(f"    First Seen:   {alert['first_seen']}")
            print(f"    Last Seen:    {alert['last_seen']}")
