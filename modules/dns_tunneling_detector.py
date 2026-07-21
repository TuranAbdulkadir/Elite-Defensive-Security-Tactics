"""
DNS Tunneling Detector
Detects data exfiltration and C2 communication hidden inside DNS queries.
Analyzes query length, subdomain entropy, query frequency, TXT record
abuse, and NXDOMAIN ratios to identify covert DNS channels.
"""
import math
import statistics
from collections import defaultdict, Counter
from datetime import datetime

class DNSTunnelingDetector:
    def __init__(self):
        self.queries = []
        self.domain_stats = defaultdict(lambda: {
            "query_count": 0, "total_query_length": 0, "nxdomain_count": 0,
            "txt_count": 0, "unique_subdomains": set(), "timestamps": []
        })
        self.alerts = []

    def _shannon_entropy(self, text):
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def ingest_query(self, query):
        """Ingest a DNS query log entry.
        query: {timestamp, qname, qtype, rcode, src_ip}
        """
        self.queries.append(query)
        qname = query.get("qname", "").lower()
        parts = qname.split(".")
        
        # Extract base domain (last 2 parts)
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else qname
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

        stats = self.domain_stats[base_domain]
        stats["query_count"] += 1
        stats["total_query_length"] += len(qname)
        stats["unique_subdomains"].add(subdomain)
        stats["timestamps"].append(query.get("timestamp", datetime.utcnow()))

        if query.get("rcode") == "NXDOMAIN":
            stats["nxdomain_count"] += 1
        if query.get("qtype") == "TXT":
            stats["txt_count"] += 1

    def analyze(self):
        """Run tunneling detection across all ingested queries."""
        for domain, stats in self.domain_stats.items():
            indicators = []
            score = 0

            # Indicator 1: High volume of queries to single domain
            if stats["query_count"] > 100:
                indicators.append(f"High query volume: {stats['query_count']}")
                score += 20

            # Indicator 2: Long average query length (encoded data in subdomain)
            avg_length = stats["total_query_length"] / max(stats["query_count"], 1)
            if avg_length > 50:
                indicators.append(f"Long avg query length: {avg_length:.0f} chars")
                score += 25

            # Indicator 3: High subdomain entropy (random-looking subdomains)
            unique_subs = list(stats["unique_subdomains"])
            if unique_subs:
                entropies = [self._shannon_entropy(s) for s in unique_subs if s]
                if entropies:
                    avg_entropy = statistics.mean(entropies)
                    if avg_entropy > 3.5:
                        indicators.append(f"High subdomain entropy: {avg_entropy:.2f}")
                        score += 30

            # Indicator 4: Many unique subdomains (data encoded per query)
            unique_count = len(stats["unique_subdomains"])
            if unique_count > 50:
                indicators.append(f"Excessive unique subdomains: {unique_count}")
                score += 20

            # Indicator 5: High NXDOMAIN ratio
            if stats["query_count"] > 10:
                nxdomain_ratio = stats["nxdomain_count"] / stats["query_count"]
                if nxdomain_ratio > 0.5:
                    indicators.append(f"High NXDOMAIN ratio: {nxdomain_ratio:.0%}")
                    score += 15

            # Indicator 6: TXT record abuse
            if stats["txt_count"] > 20:
                indicators.append(f"Excessive TXT queries: {stats['txt_count']}")
                score += 20

            # Indicator 7: Query frequency (rapid-fire = data transfer)
            if len(stats["timestamps"]) >= 2:
                sorted_ts = sorted(stats["timestamps"])
                intervals = []
                for i in range(1, len(sorted_ts)):
                    diff = (sorted_ts[i] - sorted_ts[i-1]).total_seconds()
                    if diff >= 0:
                        intervals.append(diff)
                if intervals:
                    avg_interval = statistics.mean(intervals)
                    if avg_interval < 0.5:  # More than 2 queries per second
                        indicators.append(f"Rapid query rate: avg {avg_interval:.2f}s between queries")
                        score += 25

            if score >= 40:
                self.alerts.append({
                    "severity": "CRITICAL" if score >= 70 else "HIGH",
                    "type": "DNS_TUNNELING",
                    "domain": domain,
                    "score": min(score, 100),
                    "indicators": indicators,
                    "query_count": stats["query_count"],
                    "unique_subdomains": unique_count
                })

    def generate_report(self):
        self.analyze()
        print("\n" + "=" * 72)
        print("  DNS TUNNELING DETECTION REPORT")
        print(f"  Queries Analyzed: {len(self.queries)}")
        print(f"  Domains Monitored: {len(self.domain_stats)}")
        print(f"  Tunneling Alerts: {len(self.alerts)}")
        print("=" * 72)
        for alert in sorted(self.alerts, key=lambda x: x["score"], reverse=True):
            print(f"\n  [{alert['severity']}] {alert['domain']} (score: {alert['score']}/100)")
            print(f"    Queries: {alert['query_count']} | Unique Subdomains: {alert['unique_subdomains']}")
            for ind in alert["indicators"]:
                print(f"    - {ind}")
