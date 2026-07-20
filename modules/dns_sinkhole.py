import socket

class DNSSinkhole:
    def __init__(self, blocklist_file):
        self.blocklist = ["malicious-c2.com", "crypto-miner.net"]
        self.sinkhole_ip = "127.0.0.1"
        
    def handle_request(self, domain):
        if domain in self.blocklist:
            print(f"[!] Blocked malicious DNS query: {domain} -> Redirecting to {self.sinkhole_ip}")
            return self.sinkhole_ip
        return "8.8.8.8" # Allow benign
