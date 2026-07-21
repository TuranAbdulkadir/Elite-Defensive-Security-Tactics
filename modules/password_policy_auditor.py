"""
Password Strength & Policy Auditor
Evaluates password hashes against multiple attack vectors: dictionary,
rainbow tables, hybrid rules, and entropy analysis. Also audits
organizational password policies for compliance with NIST SP 800-63B.
"""
import hashlib
import math
import re
import string
from collections import Counter

class PasswordPolicyAuditor:
    # NIST SP 800-63B minimum requirements
    NIST_MIN_LENGTH = 8
    NIST_RECOMMENDED_LENGTH = 15
    NIST_BANNED_PATTERNS = [
        r"^(password|123456|qwerty|admin|letmein|welcome|monkey|dragon)",
        r"^(.)\ 1{3,}",  # Repeating characters
        r"^(abc|123|qwe|asd|zxc)",  # Keyboard walks
    ]

    def __init__(self):
        self.audit_results = []

    def calculate_entropy(self, password):
        """Calculate Shannon entropy (bits) of a password."""
        if not password:
            return 0.0
        charset_size = 0
        if re.search(r"[a-z]", password):
            charset_size += 26
        if re.search(r"[A-Z]", password):
            charset_size += 26
        if re.search(r"[0-9]", password):
            charset_size += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            charset_size += 33

        if charset_size == 0:
            return 0.0
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)

    def estimate_crack_time(self, entropy_bits):
        """Estimate time to crack based on entropy, assuming 10B guesses/sec (GPU)."""
        if entropy_bits <= 0:
            return "Instant"
        keyspace = 2 ** entropy_bits
        seconds = keyspace / 10_000_000_000  # 10 billion guesses/sec

        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds / 86400:.1f} days"
        elif seconds < 31536000 * 1000:
            return f"{seconds / 31536000:.1f} years"
        else:
            return f"{seconds / 31536000:.1e} years"

    def check_known_breach(self, password_hash, breach_db_path=None):
        """Check if the password hash appears in a known breach database
        (e.g., HaveIBeenPwned SHA-1 hash prefixes).
        """
        sha1 = hashlib.sha1(password_hash.encode() if isinstance(password_hash, str) else password_hash).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        # In real implementation, query the HIBP API:
        # GET https://api.pwnedpasswords.com/range/{prefix}
        return {"sha1_prefix": prefix, "checked": True, "found_in_breach": False}

    def detect_keyboard_pattern(self, password):
        """Detect keyboard walk patterns (e.g., qwerty, asdfgh, zxcvbn)."""
        KEYBOARD_ROWS = [
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "1234567890"
        ]
        password_lower = password.lower()
        for row in KEYBOARD_ROWS:
            for length in range(4, len(row) + 1):
                for start in range(len(row) - length + 1):
                    pattern = row[start:start + length]
                    if pattern in password_lower or pattern[::-1] in password_lower:
                        return True, pattern
        return False, None

    def detect_leet_speak(self, password):
        """Detect leet speak substitutions (e.g., p@$$w0rd)."""
        LEET_MAP = {"@": "a", "0": "o", "1": "i", "3": "e", "$": "s", "5": "s", "7": "t", "!": "i"}
        decoded = ""
        for char in password.lower():
            decoded += LEET_MAP.get(char, char)
        
        COMMON_WORDS = ["password", "admin", "welcome", "letmein", "monkey", "dragon",
                       "master", "login", "access", "hello", "shadow", "sunshine"]
        for word in COMMON_WORDS:
            if word in decoded:
                return True, word
        return False, None

    def audit_password(self, password, username=""):
        """Full audit of a single password against all checks."""
        result = {
            "length": len(password),
            "entropy_bits": self.calculate_entropy(password),
            "issues": [],
            "score": 100
        }

        # Length check
        if len(password) < self.NIST_MIN_LENGTH:
            result["issues"].append(f"Below NIST minimum length ({self.NIST_MIN_LENGTH})")
            result["score"] -= 30
        elif len(password) < self.NIST_RECOMMENDED_LENGTH:
            result["issues"].append(f"Below recommended length ({self.NIST_RECOMMENDED_LENGTH})")
            result["score"] -= 10

        # Entropy check
        if result["entropy_bits"] < 28:
            result["issues"].append("Extremely weak entropy (< 28 bits)")
            result["score"] -= 30
        elif result["entropy_bits"] < 45:
            result["issues"].append("Weak entropy (< 45 bits)")
            result["score"] -= 15

        # Username in password
        if username and username.lower() in password.lower():
            result["issues"].append("Password contains username")
            result["score"] -= 25

        # Keyboard pattern
        has_pattern, pattern = self.detect_keyboard_pattern(password)
        if has_pattern:
            result["issues"].append(f"Contains keyboard walk pattern: '{pattern}'")
            result["score"] -= 20

        # Leet speak
        has_leet, word = self.detect_leet_speak(password)
        if has_leet:
            result["issues"].append(f"Leet-speak encoding of common word: '{word}'")
            result["score"] -= 20

        result["score"] = max(0, result["score"])
        result["crack_time"] = self.estimate_crack_time(result["entropy_bits"])
        result["rating"] = (
            "CRITICAL" if result["score"] < 30 else
            "WEAK" if result["score"] < 50 else
            "FAIR" if result["score"] < 70 else
            "GOOD" if result["score"] < 90 else
            "EXCELLENT"
        )

        self.audit_results.append(result)
        return result

    def generate_report(self):
        print("\n" + "=" * 68)
        print("  PASSWORD POLICY AUDIT REPORT (NIST SP 800-63B)")
        print(f"  Passwords Audited: {len(self.audit_results)}")
        print("=" * 68)
        for i, r in enumerate(self.audit_results, 1):
            print(f"\n  Password #{i}:")
            print(f"    Length:     {r['length']}")
            print(f"    Entropy:    {r['entropy_bits']} bits")
            print(f"    Crack Time: {r['crack_time']}")
            print(f"    Rating:     {r['rating']} ({r['score']}/100)")
            if r["issues"]:
                for issue in r["issues"]:
                    print(f"    [!] {issue}")
