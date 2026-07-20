"""
Domain Generation Algorithm (DGA) Detector
Uses Shannon entropy and n-gram frequency analysis to distinguish
algorithmically generated domains from legitimate ones.
"""
import math
import re
from collections import Counter

class DGADetector:
    # Common English bigrams for reference
    COMMON_BIGRAMS = {"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
                      "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar"}

    def __init__(self, entropy_threshold=3.5, bigram_threshold=0.15):
        self.entropy_threshold = entropy_threshold
        self.bigram_threshold = bigram_threshold

    def _shannon_entropy(self, text):
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0
        freq = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _bigram_score(self, domain):
        """Calculate the ratio of common English bigrams in the domain."""
        domain_clean = re.sub(r"[^a-z]", "", domain.lower())
        if len(domain_clean) < 2:
            return 0
        bigrams = [domain_clean[i:i + 2] for i in range(len(domain_clean) - 1)]
        common_count = sum(1 for b in bigrams if b in self.COMMON_BIGRAMS)
        return common_count / len(bigrams)

    def classify(self, domain):
        """Classify a domain as legitimate or DGA-generated."""
        # Strip TLD for analysis
        parts = domain.split(".")
        sld = parts[0] if parts else domain

        entropy = self._shannon_entropy(sld)
        bigram_score = self._bigram_score(sld)
        length = len(sld)

        is_dga = (entropy > self.entropy_threshold and
                  bigram_score < self.bigram_threshold and
                  length > 10)

        return {
            "domain": domain,
            "entropy": round(entropy, 3),
            "bigram_score": round(bigram_score, 3),
            "length": length,
            "verdict": "DGA" if is_dga else "LEGITIMATE"
        }

    def scan_dns_log(self, domains):
        """Bulk scan a list of queried domains."""
        print(f"[*] Analyzing {len(domains)} DNS queries for DGA patterns...")
        results = [self.classify(d) for d in domains]
        dga_count = sum(1 for r in results if r["verdict"] == "DGA")
        print(f"[+] Analysis complete. {dga_count}/{len(domains)} domains flagged as DGA.")
        return results
