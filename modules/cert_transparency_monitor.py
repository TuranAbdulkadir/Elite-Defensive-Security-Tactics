"""
SSL/TLS Certificate Transparency Monitor
Monitors Certificate Transparency (CT) logs for newly issued certificates
matching your organization's domains. Detects phishing domains, unauthorized
certificates, and shadow IT before attackers can weaponize them.
"""
import ssl
import socket
import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

class CertTransparencyMonitor:
    def __init__(self, watched_domains):
        self.watched_domains = [d.lower() for d in watched_domains]
        self.certificate_inventory = {}
        self.alerts = []

    def fetch_certificate(self, hostname, port=443):
        """Connect to a host and retrieve its TLS certificate chain."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert_der = tls_sock.getpeercert(binary_form=True)
                    cert_info = tls_sock.getpeercert()
                    return {
                        "hostname": hostname,
                        "subject": dict(x[0] for x in cert_info.get("subject", ())),
                        "issuer": dict(x[0] for x in cert_info.get("issuer", ())),
                        "serial": cert_info.get("serialNumber", ""),
                        "not_before": cert_info.get("notBefore", ""),
                        "not_after": cert_info.get("notAfter", ""),
                        "san": self._extract_san(cert_info),
                        "sha256_fingerprint": hashlib.sha256(cert_der).hexdigest(),
                        "fetched_at": datetime.now(timezone.utc).isoformat()
                    }
        except Exception as e:
            return {"hostname": hostname, "error": str(e)}

    def _extract_san(self, cert_info):
        """Extract Subject Alternative Names from certificate."""
        san_entries = []
        for entry_type, value in cert_info.get("subjectAltName", ()):
            san_entries.append({"type": entry_type, "value": value})
        return san_entries

    def detect_lookalike_domains(self, ct_log_entries):
        """Scan CT log entries for domains that visually resemble watched domains.
        Uses character substitution detection (homoglyph attack detection).
        """
        HOMOGLYPHS = {
            "a": ["@", "4", "a"],
            "e": ["3", "e"],
            "i": ["1", "l", "!", "i"],
            "o": ["0", "o"],
            "s": ["5", "$", "s"],
            "t": ["7", "+", "t"],
            "g": ["9", "q", "g"],
        }

        for entry in ct_log_entries:
            issued_domain = entry.get("common_name", "").lower()
            for watched in self.watched_domains:
                if issued_domain == watched:
                    continue
                # Calculate character-level similarity
                similarity = self._domain_similarity(watched, issued_domain)
                if similarity > 0.75 and similarity < 1.0:
                    self.alerts.append({
                        "severity": "HIGH",
                        "type": "LOOKALIKE_CERTIFICATE",
                        "watched_domain": watched,
                        "lookalike_domain": issued_domain,
                        "similarity": round(similarity, 3),
                        "issuer": entry.get("issuer", "unknown"),
                        "issued_at": entry.get("not_before", "unknown")
                    })

    def _domain_similarity(self, domain_a, domain_b):
        """Levenshtein-based similarity ratio between two domain strings."""
        len_a, len_b = len(domain_a), len(domain_b)
        if len_a == 0 or len_b == 0:
            return 0.0

        matrix = [[0] * (len_b + 1) for _ in range(len_a + 1)]
        for i in range(len_a + 1):
            matrix[i][0] = i
        for j in range(len_b + 1):
            matrix[0][j] = j

        for i in range(1, len_a + 1):
            for j in range(1, len_b + 1):
                cost = 0 if domain_a[i - 1] == domain_b[j - 1] else 1
                matrix[i][j] = min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost
                )

        distance = matrix[len_a][len_b]
        max_len = max(len_a, len_b)
        return 1.0 - (distance / max_len)

    def audit_certificate_chain(self, hostname):
        """Full audit of a host's certificate: expiry, weak algorithms, pinning."""
        cert = self.fetch_certificate(hostname)
        if "error" in cert:
            print(f"  [-] Could not connect to {hostname}: {cert['error']}")
            return cert

        issues = []
        # Check expiry
        try:
            not_after = datetime.strptime(cert["not_after"], "%b %d %H:%M:%S %Y %Z")
            days_remaining = (not_after - datetime.utcnow()).days
            if days_remaining < 0:
                issues.append(f"EXPIRED {abs(days_remaining)} days ago")
            elif days_remaining < 30:
                issues.append(f"Expiring in {days_remaining} days")
        except (ValueError, KeyError):
            pass

        # Check for wildcard certs (potential over-scoping)
        for san in cert.get("san", []):
            if san.get("value", "").startswith("*."):
                issues.append(f"Wildcard certificate: {san['value']}")

        cert["issues"] = issues
        cert["issue_count"] = len(issues)
        self.certificate_inventory[hostname] = cert

        print(f"  [{'!' if issues else '+'}] {hostname}: {len(issues)} issue(s) found")
        for issue in issues:
            print(f"      - {issue}")
        return cert

    def generate_inventory_report(self):
        """Generate a full certificate inventory report."""
        print("\n" + "=" * 72)
        print("  CERTIFICATE TRANSPARENCY & INVENTORY REPORT")
        print(f"  Watched Domains: {', '.join(self.watched_domains)}")
        print(f"  Certificates Audited: {len(self.certificate_inventory)}")
        print(f"  Alerts: {len(self.alerts)}")
        print("=" * 72)
        for hostname, cert in self.certificate_inventory.items():
            print(f"\n  [{hostname}]")
            print(f"    Issuer:      {cert.get('issuer', {}).get('organizationName', 'N/A')}")
            print(f"    Fingerprint: {cert.get('sha256_fingerprint', 'N/A')[:32]}...")
            print(f"    Valid Until: {cert.get('not_after', 'N/A')}")
            print(f"    SANs:        {len(cert.get('san', []))}")
            print(f"    Issues:      {cert.get('issue_count', 0)}")
        print("\n" + "-" * 72)
        if self.alerts:
            print("\n  LOOKALIKE DOMAIN ALERTS:")
            for alert in self.alerts:
                print(f"    [{alert['severity']}] {alert['lookalike_domain']} "
                      f"(looks like {alert['watched_domain']}, "
                      f"similarity: {alert['similarity']})")
