import uuid
import json

class HoneyTokenGenerator:
    def generate_aws_keys(self):
        access_key = "AKIA" + str(uuid.uuid4()).replace("-", "")[:16].upper()
        secret_key = str(uuid.uuid4()).replace("-", "") + str(uuid.uuid4()).replace("-", "")
        print(f"[*] Generated Honey Token AWS Access Key: {access_key}")
        
        # Save to simulated .aws/credentials
        print("[+] Token injected into system. Monitoring CloudTrail for unauthorized usage...")
        return access_key, secret_key
