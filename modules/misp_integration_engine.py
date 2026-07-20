"""
MISP Threat Intelligence Integration Engine
Pulls Indicators of Compromise (IoCs) from a MISP instance and
cross-references them against local network telemetry.
"""
import json

class MISPIntegrationEngine:
    def __init__(self, misp_url, api_key):
        self.misp_url = misp_url
        self.api_key = api_key
        self.ioc_database = {"ip": set(), "domain": set(), "hash": set()}

    def pull_threat_feed(self, feed_data):
        """Ingest IoCs from a MISP JSON event export."""
        for event in feed_data.get("response", []):
            for attribute in event.get("Event", {}).get("Attribute", []):
                ioc_type = attribute.get("type", "")
                value = attribute.get("value", "")
                if "ip" in ioc_type:
                    self.ioc_database["ip"].add(value)
                elif "domain" in ioc_type:
                    self.ioc_database["domain"].add(value)
                elif "md5" in ioc_type or "sha" in ioc_type:
                    self.ioc_database["hash"].add(value)

        total = sum(len(v) for v in self.ioc_database.values())
        print(f"[+] Ingested {total} IoCs from MISP feed.")

    def match_against_logs(self, network_connections):
        """Match local network connections against known malicious IoCs."""
        hits = []
        for conn in network_connections:
            dest_ip = conn.get("dest_ip", "")
            dest_domain = conn.get("dest_domain", "")
            if dest_ip in self.ioc_database["ip"]:
                hits.append({"type": "IP_MATCH", "value": dest_ip, "connection": conn})
            if dest_domain in self.ioc_database["domain"]:
                hits.append({"type": "DOMAIN_MATCH", "value": dest_domain, "connection": conn})

        if hits:
            print(f"[!] THREAT INTEL MATCH: {len(hits)} connections to known malicious infrastructure!")
        else:
            print("[+] No matches against known threat intelligence.")
        return hits
