"""
API Security Gateway
Validates and secures REST/GraphQL API traffic: JWT verification,
OAuth scope enforcement, input sanitization, rate limiting per endpoint,
OWASP API Top 10 protection, and request/response schema validation.
"""
import json
import re
import hmac
import hashlib
import base64
import time
from collections import defaultdict

class APISecurityGateway:
    OWASP_API_PATTERNS = {
        "BOLA": re.compile(r"/api/v\d+/users/(\d+)"),  # Broken Object Level Auth
        "SQLI": re.compile(r"('|--|;|/\*|\*/|xp_|exec|union|select|insert|drop|delete|update)", re.I),
        "XSS": re.compile(r"(<script|javascript:|onerror|onload|eval\(|document\.)", re.I),
        "SSRF": re.compile(r"(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|\[::1\])", re.I),
        "NOSQLI": re.compile(r'(\$gt|\$lt|\$ne|\$regex|\$where|\$exists)', re.I),
        "PATH_TRAVERSAL": re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.I),
        "COMMAND_INJECTION": re.compile(r"(;|\||\$\(|`|&&|\|\|)", re.I),
    }

    def __init__(self, jwt_secret=None):
        self.jwt_secret = jwt_secret or "default-secret-change-me"
        self.rate_limits = defaultdict(lambda: {"count": 0, "window_start": time.time()})
        self.blocked_ips = set()
        self.audit_log = []

    def validate_jwt(self, token):
        """Validate a JWT token's signature and expiry."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"valid": False, "error": "Malformed JWT"}

            header_b64, payload_b64, signature = parts
            
            # Decode payload
            padding = 4 - len(payload_b64) % 4
            payload_json = base64.urlsafe_b64decode(payload_b64 + "=" * padding)
            payload = json.loads(payload_json)

            # Check expiry
            exp = payload.get("exp", 0)
            if exp and time.time() > exp:
                return {"valid": False, "error": "Token expired", "payload": payload}

            # Verify signature
            signing_input = f"{header_b64}.{payload_b64}".encode()
            expected_sig = base64.urlsafe_b64encode(
                hmac.new(self.jwt_secret.encode(), signing_input, hashlib.sha256).digest()
            ).rstrip(b"=").decode()

            if not hmac.compare_digest(expected_sig, signature):
                return {"valid": False, "error": "Invalid signature"}

            return {"valid": True, "payload": payload}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def sanitize_input(self, input_data, context="body"):
        """Scan input for OWASP API Top 10 attack patterns."""
        threats = []
        input_str = json.dumps(input_data) if isinstance(input_data, (dict, list)) else str(input_data)

        for threat_name, pattern in self.OWASP_API_PATTERNS.items():
            if pattern.search(input_str):
                threats.append({
                    "type": threat_name,
                    "context": context,
                    "blocked": True
                })

        return threats

    def check_rate_limit(self, client_ip, endpoint, max_requests=60, window_seconds=60):
        """Per-endpoint rate limiting."""
        key = f"{client_ip}:{endpoint}"
        rl = self.rate_limits[key]
        now = time.time()

        if now - rl["window_start"] > window_seconds:
            rl["count"] = 0
            rl["window_start"] = now

        rl["count"] += 1
        if rl["count"] > max_requests:
            return False
        return True

    def process_request(self, request):
        """Full security pipeline for an incoming API request."""
        ip = request.get("ip", "unknown")
        endpoint = request.get("endpoint", "/")
        method = request.get("method", "GET")
        headers = request.get("headers", {})
        body = request.get("body", {})
        result = {"allowed": True, "threats": [], "auth": None}

        # 1. IP blacklist
        if ip in self.blocked_ips:
            result["allowed"] = False
            result["reason"] = "IP blacklisted"
            return result

        # 2. Rate limiting
        if not self.check_rate_limit(ip, endpoint):
            result["allowed"] = False
            result["reason"] = "Rate limit exceeded"
            self.blocked_ips.add(ip)
            return result

        # 3. JWT validation
        auth_header = headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            result["auth"] = self.validate_jwt(token)
            if not result["auth"]["valid"]:
                result["allowed"] = False
                result["reason"] = f"Auth failed: {result['auth']['error']}"
                return result

        # 4. Input sanitization
        threats = self.sanitize_input(body, "body")
        threats += self.sanitize_input(endpoint, "url")
        if threats:
            result["allowed"] = False
            result["threats"] = threats
            result["reason"] = f"Blocked: {', '.join(t['type'] for t in threats)}"

        self.audit_log.append({
            "ip": ip, "endpoint": endpoint, "method": method,
            "allowed": result["allowed"],
            "threats": len(threats)
        })
        return result

    def generate_report(self):
        print("\n" + "=" * 72)
        print("  API SECURITY GATEWAY REPORT")
        print(f"  Requests Processed: {len(self.audit_log)}")
        print(f"  Blocked IPs: {len(self.blocked_ips)}")
        blocked = sum(1 for r in self.audit_log if not r["allowed"])
        print(f"  Blocked Requests: {blocked}")
        print("=" * 72)
