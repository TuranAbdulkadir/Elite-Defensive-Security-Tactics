# Elite-Defensive-Security-Tactics

The most comprehensive open-source Blue Team & Incident Response toolkit.
Every module is hand-crafted with real security logic - zero procedural filler.

## Modules (30+)

### Recovery & Forensics
- `ransomware_recovery.py` - Volume Shadow Copy recovery engine
- `secure_shredder.py` - 35-pass Gutmann military-grade file wiper
- `memory_dump_analyzer.py` - RAM forensics and credential extraction
- `volatility_orchestrator.py` - Automated Volatility3 memory triage pipeline
- `process_hollowing_detector.py` - RunPE / Process Hollowing detection via hash comparison

### Network Defense
- `network_quarantine.py` - Autonomous host isolation via firewall rules
- `dns_sinkhole.py` - Malicious domain blocking and C2 traffic interception
- `zero_trust_proxy.py` - TPM-based device health verification
- `advanced_pcap_carver.py` - HTTP stream reconstruction from packet captures
- `zero_trust_device_attestation.py` - Full device posture evaluation (OS, AV, FW, encryption)

### Threat Hunting & Intelligence
- `yara_orchestrator.py` - APT malware signature scanner
- `steganography_detector.py` - LSB hidden payload detection in images
- `dga_detector.py` - ML-based Domain Generation Algorithm detection via Shannon entropy
- `misp_integration_engine.py` - Real-time IoC matching against MISP threat feeds
- `aws_cloudtrail_hunter.py` - Cloud privilege escalation and exfiltration detection
- `azure_ad_anomaly_detector.py` - Impossible Travel and brute-force detection

### Deception & Active Defense
- `honey_token_gen.py` - Fake AWS credential injection for early warning
- `fake_smb_honeypot.py` - Decoy file share to trap ransomware and lateral movement
- `canary_db_tables.py` - Fake database tables to detect SQL injection data theft

### Identity & Behavioral Analysis
- `behavioral_biometrics_monitor.py` - Keystroke dynamics session hijacking detection
- `mfa_bypass_monitor.py` - Pass-the-Cookie and geovelocity anomaly detection
- `ad_auditor.py` - Kerberos AS-REP Roasting and Kerberoasting vulnerability audit

### Endpoint Protection
- `kernel_rootkit_detect.py` - SSDT hook and hidden process detection
- `incident_response.py` - Automated triage artifact collection
- `iot_firmware_analyzer.py` - SquashFS extraction for hardcoded credential hunting

### Application Security
- `sql_injection_firewall.py` - AST-based SQL injection blocking (WAF)
- `phishing_domain_scanner.py` - Typo-squatting detection via Levenshtein distance
- `blockchain_threat_intel.py` - Cryptocurrency mixer monitoring

## Usage

```bash
python main_defender.py
python -c "from modules.dga_detector import DGADetector; d = DGADetector(); print(d.classify('xk3qw9zp1m.com'))"
```

## License
MIT License (c) 2025 Abdulkadir Turan


## Phase 22: Deep Expansion Modules

### Certificate & Encryption Security
- `cert_transparency_monitor.py` - CT log monitoring, lookalike domain detection via Levenshtein distance, full TLS certificate chain auditing

### Forensics & Investigation
- `windows_eventlog_forensics.py` - MITRE ATT&CK mapped Windows Event Log parser with brute-force correlation, lateral movement detection, and kill chain reconstruction
- `email_header_forensics.py` - Email delivery path tracing, SPF/DKIM/DMARC verification, display-name spoofing detection
- `usb_device_auditor.py` - SetupAPI log parsing, USB whitelist enforcement, BadUSB attack detection
- `malware_sandbox_analyzer.py` - Behavioral scoring engine for sandbox reports with weighted indicator classification

### Identity & Credential Security
- `password_policy_auditor.py` - NIST SP 800-63B compliance auditing, Shannon entropy calculation, keyboard walk detection, leet-speak decoding, GPU crack time estimation

### Monitoring & Intelligence
- `siem_correlation_engine.py` - Multi-source log correlation with configurable rules, time-windowed pattern matching, and multi-stage attack detection
- `network_baseline_anomaly.py` - Statistical baseline building with Z-score and EWMA anomaly detection across traffic metrics


## Phase 23: Complete Protection Arsenal

### Attack Mitigation
- `ddos_mitigation_engine.py` - Token bucket rate limiting, SYN flood detection, Slowloris detection, DNS amplification detection, auto-blacklisting

### Data Protection
- `data_loss_prevention.py` - Credit card (Luhn validated), SSN, API key, JWT, PEM private key, IBAN detection with recursive directory scanning

### Infrastructure Security
- `container_security_scanner.py` - Dockerfile CIS benchmark auditing, Kubernetes manifest security scanning (privileged containers, root users, missing limits)
- `supply_chain_detector.py` - Typosquatting detection via Levenshtein distance, known malicious package database, checksum verification
- `api_security_gateway.py` - JWT validation, OWASP API Top 10 input sanitization (SQLi, XSS, SSRF, NoSQLi, path traversal), per-endpoint rate limiting

### Network & Wireless
- `dns_tunneling_detector.py` - Covert DNS channel detection via entropy analysis, query length analysis, NXDOMAIN ratio, TXT abuse, query frequency
- `wireless_security_auditor.py` - Evil twin AP detection, rogue AP detection, WEP/WPA weak encryption flagging, deauth flood detection

### User Behavior
- `insider_threat_ueba.py` - User behavioral profiling, login hour anomalies, mass file access spikes, USB exfiltration patterns, Z-score deviation analysis
