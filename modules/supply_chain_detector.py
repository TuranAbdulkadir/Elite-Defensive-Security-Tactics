"""
Software Supply Chain Attack Detector
Audits project dependencies (pip, npm, go modules) for typosquatting,
dependency confusion, and known malicious packages. Compares package
checksums against a trusted baseline to detect tampering.
"""
import json
import hashlib
import re

class SupplyChainDetector:
    KNOWN_MALICIOUS_PACKAGES = {
        "pip": ["colourama", "python-dateutils", "jeIlyfish", "python3-dateutil",
                "pypistats", "setup-tools", "openvc", "request"],
        "npm": ["crossenv", "event-strem", "flatmap-streem", "d3.js",
                "gruntcli", "mongose", "mariadb", "mysqljs"],
    }

    LEGITIMATE_PACKAGES = {
        "pip": ["colorama", "python-dateutil", "jellyfish", "requests",
                "setuptools", "opencv-python", "numpy", "pandas"],
        "npm": ["cross-env", "event-stream", "flatmap-stream", "d3",
                "grunt-cli", "mongoose", "mysql", "express"],
    }

    def __init__(self):
        self.findings = []

    def _levenshtein(self, s1, s2):
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    def scan_requirements_txt(self, content):
        """Scan a Python requirements.txt for suspicious packages."""
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pkg_name = re.split(r"[=<>!~]", line)[0].strip().lower()
            self._check_package(pkg_name, "pip")

    def scan_package_json(self, content):
        """Scan a Node.js package.json for suspicious packages."""
        data = json.loads(content)
        for dep_type in ("dependencies", "devDependencies"):
            for pkg_name in data.get(dep_type, {}):
                self._check_package(pkg_name.lower(), "npm")

    def _check_package(self, pkg_name, ecosystem):
        # Check against known malicious
        if pkg_name in self.KNOWN_MALICIOUS_PACKAGES.get(ecosystem, []):
            self.findings.append({
                "severity": "CRITICAL",
                "type": "KNOWN_MALICIOUS_PACKAGE",
                "package": pkg_name,
                "ecosystem": ecosystem,
                "detail": "This package is a known malicious typosquat"
            })
            return

        # Typosquatting detection via Levenshtein distance
        for legit in self.LEGITIMATE_PACKAGES.get(ecosystem, []):
            distance = self._levenshtein(pkg_name, legit)
            if 0 < distance <= 2 and pkg_name != legit:
                self.findings.append({
                    "severity": "HIGH",
                    "type": "TYPOSQUAT_SUSPECTED",
                    "package": pkg_name,
                    "similar_to": legit,
                    "distance": distance,
                    "ecosystem": ecosystem,
                    "detail": f"Package '{pkg_name}' is suspiciously similar to '{legit}'"
                })

    def verify_checksums(self, package_name, expected_hash, actual_content):
        """Verify package integrity by comparing SHA-256 checksums."""
        actual_hash = hashlib.sha256(actual_content).hexdigest()
        if actual_hash != expected_hash:
            self.findings.append({
                "severity": "CRITICAL",
                "type": "CHECKSUM_MISMATCH",
                "package": package_name,
                "expected": expected_hash[:16] + "...",
                "actual": actual_hash[:16] + "...",
                "detail": "Package content has been tampered with since last verified build"
            })
            return False
        return True

    def generate_report(self):
        print("\n" + "=" * 72)
        print("  SOFTWARE SUPPLY CHAIN SECURITY REPORT")
        print(f"  Findings: {len(self.findings)}")
        print("=" * 72)
        for f in self.findings:
            print(f"  [{f['severity']}] {f['type']}")
            print(f"    Package:   {f['package']} ({f.get('ecosystem', 'N/A')})")
            print(f"    {f['detail']}")
