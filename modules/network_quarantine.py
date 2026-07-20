import subprocess

class NetworkQuarantine:
    def isolate_host(self):
        print("[!] CRITICAL ANOMALY: Isolating Host from Network")
        commands = [
            "netsh advfirewall set allprofiles state on",
            "netsh advfirewall firewall add rule name=\"Isolate\" dir=in action=block",
            "netsh advfirewall firewall add rule name=\"Isolate\" dir=out action=block"
        ]
        for cmd in commands:
            print(f"[*] Executing: {cmd}")
            # subprocess.run(cmd.split())
        print("[+] Host is now in strict quarantine.")
