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
