"""
Data Loss Prevention (DLP) Engine
Scans files, emails, and network streams for sensitive data patterns
(credit cards, SSNs, API keys, medical records) using regex and Luhn
algorithm validation. Enforces data classification policies.
"""
import re
import os
import hashlib

class DLPEngine:
    PATTERNS = {
        "CREDIT_CARD_VISA": {
            "regex": r"\b4[0-9]{12}(?:[0-9]{3})?\b",
            "severity": "CRITICAL",
            "validator": "luhn"
        },
        "CREDIT_CARD_MASTERCARD": {
            "regex": r"\b5[1-5][0-9]{14}\b",
            "severity": "CRITICAL",
            "validator": "luhn"
        },
        "SSN_US": {
            "regex": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
            "severity": "CRITICAL",
            "validator": None
        },
        "EMAIL_ADDRESS": {
            "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "severity": "MEDIUM",
            "validator": None
        },
        "AWS_ACCESS_KEY": {
            "regex": r"\bAKIA[0-9A-Z]{16}\b",
            "severity": "CRITICAL",
            "validator": None
        },
        "AWS_SECRET_KEY": {
            "regex": r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
            "severity": "CRITICAL",
            "validator": None
        },
        "PRIVATE_KEY_PEM": {
            "regex": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
            "severity": "CRITICAL",
            "validator": None
        },
        "IBAN": {
            "regex": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
            "severity": "HIGH",
            "validator": None
        },
        "PHONE_INTERNATIONAL": {
            "regex": r"\+\d{1,3}[\s-]?\d{3,14}",
            "severity": "LOW",
            "validator": None
        },
        "GITHUB_TOKEN": {
            "regex": r"\bghp_[A-Za-z0-9]{36}\b",
            "severity": "CRITICAL",
            "validator": None
        },
        "JWT_TOKEN": {
            "regex": r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            "severity": "HIGH",
            "validator": None
        },
        "IP_ADDRESS_PRIVATE": {
            "regex": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            "severity": "MEDIUM",
            "validator": None
        },
    }

    def __init__(self):
        self.findings = []
        self.compiled_patterns = {}
        for name, config in self.PATTERNS.items():
            self.compiled_patterns[name] = re.compile(config["regex"])

    def _luhn_check(self, number_str):
        """Validate a number using the Luhn algorithm (credit card checksum)."""
        digits = [int(d) for d in number_str if d.isdigit()]
        if len(digits) < 13:
            return False
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0

    def scan_text(self, text, source="unknown"):
        """Scan a block of text for all sensitive data patterns."""
        results = []
        for name, pattern in self.compiled_patterns.items():
            config = self.PATTERNS[name]
            matches = pattern.findall(text)
            for match in matches:
                # Apply validator if specified
                if config["validator"] == "luhn":
                    if not self._luhn_check(match):
                        continue  # Failed Luhn = not a real card number
                
                masked = self._mask_sensitive(match)
                finding = {
                    "pattern": name,
                    "severity": config["severity"],
                    "matched_value": masked,
                    "source": source,
                    "raw_length": len(match)
                }
                results.append(finding)
                self.findings.append(finding)
        return results

    def scan_file(self, filepath):
        """Scan a file for sensitive data leaks."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_text(content, source=filepath)
        except (PermissionError, FileNotFoundError) as e:
            return [{"error": str(e), "source": filepath}]

    def scan_directory(self, directory, extensions=None):
        """Recursively scan a directory for sensitive data."""
        if extensions is None:
            extensions = {".txt", ".csv", ".json", ".xml", ".yaml", ".yml",
                         ".env", ".cfg", ".conf", ".ini", ".log", ".py",
                         ".js", ".java", ".go", ".rb", ".php", ".sql"}

        print(f"[*] DLP scanning directory: {directory}")
        total_files = 0
        for root, dirs, files in os.walk(directory):
            # Skip common non-useful directories
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv"}]
            for fname in files:
                if any(fname.endswith(ext) for ext in extensions):
                    filepath = os.path.join(root, fname)
                    self.scan_file(filepath)
                    total_files += 1

        print(f"[+] Scanned {total_files} files. Found {len(self.findings)} sensitive data matches.")

    def _mask_sensitive(self, value):
        """Mask sensitive data for safe logging (show first/last 4 chars only)."""
        if len(value) <= 8:
            return value[:2] + "*" * (len(value) - 2)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]

    def generate_report(self):
        print("\n" + "=" * 72)
        print("  DATA LOSS PREVENTION (DLP) SCAN REPORT")
        print(f"  Total Findings: {len(self.findings)}")
        print("=" * 72)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x.get("severity", "LOW"), 99))
        for f in sorted_findings:
            print(f"  [{f['severity']}] {f['pattern']}")
            print(f"    Value:  {f['matched_value']}")
            print(f"    Source: {f['source']}")
