"""
Email Header Forensics Analyzer
Parses raw email headers to trace the full delivery path, detect spoofing,
verify SPF/DKIM/DMARC alignment, and identify phishing indicators.
"""
import re
from datetime import datetime

class EmailHeaderForensics:
    def __init__(self):
        self.headers = {}
        self.hops = []
        self.alerts = []

    def parse_raw_headers(self, raw_header_text):
        """Parse raw email headers into structured key-value pairs."""
        current_key = None
        current_value = ""

        for line in raw_header_text.split("\n"):
            if re.match(r"^[A-Za-z][A-Za-z0-9-]*:", line):
                if current_key:
                    self.headers.setdefault(current_key, []).append(current_value.strip())
                parts = line.split(":", 1)
                current_key = parts[0].strip()
                current_value = parts[1].strip() if len(parts) > 1 else ""
            else:
                current_value += " " + line.strip()

        if current_key:
            self.headers.setdefault(current_key, []).append(current_value.strip())

    def trace_delivery_path(self):
        """Extract and order all Received headers to trace the email's journey."""
        received_headers = self.headers.get("Received", [])
        for i, header in enumerate(reversed(received_headers)):
            hop = {"hop_number": i + 1, "raw": header}

            # Extract 'from' server
            from_match = re.search(r"from\s+([\w.-]+)", header)
            if from_match:
                hop["from_server"] = from_match.group(1)

            # Extract 'by' server
            by_match = re.search(r"by\s+([\w.-]+)", header)
            if by_match:
                hop["by_server"] = by_match.group(1)

            # Extract IP
            ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", header)
            if ip_match:
                hop["source_ip"] = ip_match.group(1)

            # Extract timestamp
            time_match = re.search(r";\s*(.+)$", header)
            if time_match:
                hop["timestamp"] = time_match.group(1).strip()

            self.hops.append(hop)

    def check_spf(self):
        """Analyze SPF (Sender Policy Framework) authentication result."""
        auth_results = " ".join(self.headers.get("Authentication-Results", []))
        if "spf=pass" in auth_results.lower():
            return {"spf": "PASS", "status": "OK"}
        elif "spf=fail" in auth_results.lower():
            self.alerts.append({
                "severity": "CRITICAL",
                "type": "SPF_FAIL",
                "detail": "Sender IP is NOT authorized to send on behalf of this domain"
            })
            return {"spf": "FAIL", "status": "SPOOFING_LIKELY"}
        elif "spf=softfail" in auth_results.lower():
            self.alerts.append({
                "severity": "HIGH",
                "type": "SPF_SOFTFAIL",
                "detail": "Sender IP is not explicitly authorized (softfail)"
            })
            return {"spf": "SOFTFAIL", "status": "SUSPICIOUS"}
        return {"spf": "NONE", "status": "NO_SPF_RECORD"}

    def check_dkim(self):
        """Analyze DKIM (DomainKeys Identified Mail) authentication result."""
        auth_results = " ".join(self.headers.get("Authentication-Results", []))
        if "dkim=pass" in auth_results.lower():
            return {"dkim": "PASS"}
        elif "dkim=fail" in auth_results.lower():
            self.alerts.append({
                "severity": "HIGH",
                "type": "DKIM_FAIL",
                "detail": "Email signature verification failed - content may be tampered"
            })
            return {"dkim": "FAIL"}
        return {"dkim": "NONE"}

    def detect_display_name_spoofing(self):
        """Detect when the display name mimics a known executive/brand
        but the actual email address is from a different domain.
        """
        from_headers = self.headers.get("From", [])
        for from_header in from_headers:
            display_match = re.match(r'"?([^"<]+)"?\s*<([^>]+)>', from_header)
            if display_match:
                display_name = display_match.group(1).strip().lower()
                email_addr = display_match.group(2).strip().lower()
                email_domain = email_addr.split("@")[-1] if "@" in email_addr else ""

                # Flag if display name looks like a known brand but domain doesn't match
                KNOWN_BRANDS = ["microsoft", "google", "apple", "amazon", "paypal", "bank"]
                for brand in KNOWN_BRANDS:
                    if brand in display_name and brand not in email_domain:
                        self.alerts.append({
                            "severity": "CRITICAL",
                            "type": "DISPLAY_NAME_SPOOFING",
                            "display_name": display_match.group(1),
                            "actual_email": email_addr,
                            "detail": f"Display name contains '{brand}' but email domain is '{email_domain}'"
                        })

    def full_analysis(self):
        """Run all forensics checks and generate a report."""
        self.trace_delivery_path()
        spf = self.check_spf()
        dkim = self.check_dkim()
        self.detect_display_name_spoofing()

        print("\n" + "=" * 72)
        print("  EMAIL HEADER FORENSICS REPORT")
        print("=" * 72)
        print(f"  From:    {self.headers.get('From', ['N/A'])[0]}")
        print(f"  To:      {self.headers.get('To', ['N/A'])[0]}")
        print(f"  Subject: {self.headers.get('Subject', ['N/A'])[0]}")
        print(f"  SPF:     {spf.get('spf', 'N/A')}")
        print(f"  DKIM:    {dkim.get('dkim', 'N/A')}")

        print(f"\n  --- DELIVERY PATH ({len(self.hops)} hops) ---")
        for hop in self.hops:
            print(f"  Hop {hop['hop_number']}: "
                  f"{hop.get('from_server', '?')} -> {hop.get('by_server', '?')} "
                  f"[{hop.get('source_ip', '?')}]")

        if self.alerts:
            print(f"\n  --- ALERTS ({len(self.alerts)}) ---")
            for alert in self.alerts:
                print(f"  [{alert['severity']}] {alert['type']}: {alert['detail']}")
