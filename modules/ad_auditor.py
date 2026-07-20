class ActiveDirectoryAuditor:
    def check_asrep_roasting(self):
        print("[*] Querying LDAP for accounts with 'Do not require Kerberos preauthentication' set...")
        # Simulated LDAP query
        print("[!] Vulnerability Found: ServiceAccount_Backup has preauth disabled (AS-REP Roastable).")
        
    def check_kerberoasting(self):
        print("[*] Querying LDAP for accounts with SPNs (Service Principal Names)...")
        print("[+] 5 SPNs found. Recommend auditing password strength for these service accounts.")
