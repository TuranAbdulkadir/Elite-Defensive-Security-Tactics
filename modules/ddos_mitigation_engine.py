"""
DDoS Mitigation Engine
Real-time Distributed Denial of Service attack detection and mitigation.
Implements token bucket rate limiting, SYN flood detection via half-open
connection tracking, slowloris detection, and automatic IP blacklisting.
"""
import time
import threading
from collections import defaultdict
from datetime import datetime, timedelta

class TokenBucket:
    """Token bucket algorithm for precise rate limiting."""
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, tokens=1):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

class DDoSMitigationEngine:
    def __init__(self, requests_per_second=100, syn_threshold=500, slowloris_timeout=10):
        self.rps_limit = requests_per_second
        self.syn_threshold = syn_threshold
        self.slowloris_timeout = slowloris_timeout
        self.ip_buckets = {}
        self.half_open_connections = defaultdict(int)
        self.slow_connections = defaultdict(list)
        self.blacklist = set()
        self.whitelist = set()
        self.attack_log = []

    def _get_bucket(self, ip):
        if ip not in self.ip_buckets:
            self.ip_buckets[ip] = TokenBucket(
                capacity=self.rps_limit * 2,
                refill_rate=self.rps_limit
            )
        return self.ip_buckets[ip]

    def process_request(self, ip, request_type="HTTP", payload_size=0):
        """Process an incoming request through the mitigation pipeline."""
        if ip in self.whitelist:
            return {"action": "ALLOW", "reason": "whitelisted"}
        if ip in self.blacklist:
            return {"action": "DROP", "reason": "blacklisted"}

        bucket = self._get_bucket(ip)
        if not bucket.consume():
            self._log_attack(ip, "RATE_LIMIT_EXCEEDED", f"{request_type} flood detected")
            self.blacklist.add(ip)
            return {"action": "DROP", "reason": "rate_limit_exceeded"}

        return {"action": "ALLOW", "reason": "within_limits"}

    def track_syn(self, ip):
        """Track SYN packets to detect SYN flood attacks."""
        self.half_open_connections[ip] += 1
        if self.half_open_connections[ip] > self.syn_threshold:
            self._log_attack(ip, "SYN_FLOOD", 
                f"{self.half_open_connections[ip]} half-open connections")
            self.blacklist.add(ip)
            return True
        return False

    def track_syn_ack(self, ip):
        """Track completed handshakes to reduce half-open count."""
        if ip in self.half_open_connections:
            self.half_open_connections[ip] = max(0, self.half_open_connections[ip] - 1)

    def track_slow_connection(self, ip, connection_start_time, bytes_received):
        """Detect Slowloris attacks: connections that send data very slowly."""
        elapsed = time.time() - connection_start_time
        if elapsed > self.slowloris_timeout and bytes_received < 100:
            self._log_attack(ip, "SLOWLORIS",
                f"Connection open {elapsed:.0f}s with only {bytes_received} bytes")
            self.blacklist.add(ip)
            return True
        return False

    def detect_amplification(self, ip, request_size, response_size):
        """Detect DNS/NTP amplification: tiny request triggers huge response."""
        if request_size > 0:
            ratio = response_size / request_size
            if ratio > 50:
                self._log_attack(ip, "AMPLIFICATION",
                    f"Amplification ratio: {ratio:.0f}x (req={request_size}, resp={response_size})")
                return True
        return False

    def _log_attack(self, ip, attack_type, detail):
        self.attack_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": ip,
            "attack_type": attack_type,
            "detail": detail,
            "action_taken": "BLACKLISTED"
        })

    def generate_report(self):
        print("\n" + "=" * 72)
        print("  DDoS MITIGATION ENGINE REPORT")
        print(f"  Active Rate Limiters: {len(self.ip_buckets)}")
        print(f"  Blacklisted IPs: {len(self.blacklist)}")
        print(f"  Attacks Detected: {len(self.attack_log)}")
        print("=" * 72)
        for attack in self.attack_log:
            print(f"  [{attack['attack_type']}] {attack['source_ip']}")
            print(f"    {attack['detail']}")
            print(f"    Time: {attack['timestamp']}")
        if self.blacklist:
            print(f"\n  Blacklisted IPs: {', '.join(sorted(self.blacklist))}")
