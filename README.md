# Elite Defensive Security Tactics

> The most comprehensive open-source Blue Team, Incident Response & Defensive Security toolkit ever assembled. **46+ hand-crafted modules** covering every major protection domain in cybersecurity.

![Python](https://img.shields.io/badge/Language-Python%203.10+-blue)
![Modules](https://img.shields.io/badge/Modules-46+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)

---

## Quick Start

```bash
git clone https://github.com/TuranAbdulkadir/Elite-Defensive-Security-Tactics.git
cd Elite-Defensive-Security-Tactics
pip install -r requirements.txt
python main_defender.py
```

---

## Module Categories

### 1. DDoS & Network Attack Mitigation
| Module | Description |
|--------|-------------|
| `ddos_mitigation_engine.py` | Token bucket rate limiting, SYN flood detection, Slowloris detection, DNS amplification analysis, automatic IP blacklisting |
| `network_quarantine.py` | Autonomous host isolation via Windows Firewall / iptables rules upon anomaly detection |
| `dns_sinkhole.py` | Malicious C2 domain blocking by redirecting DNS queries to localhost |

### 2. Data Protection & Privacy
| Module | Description |
|--------|-------------|
| `data_loss_prevention.py` | Detects credit cards (Luhn validated), SSNs, AWS keys, JWTs, PEM keys, IBANs across files and directories |
| `secure_shredder.py` | 35-pass Gutmann military-grade file destruction with random byte overwriting |

### 3. Cryptography & Encryption
| Module | Description |
|--------|-------------|
| `aes_vault.py` | AES-256-CBC file encryption/decryption vault using the `cryptography` library |
| `hash_analyzer.py` | Multi-algorithm file hashing (MD5, SHA-1, SHA-256) for integrity verification |

### 4. Network Analysis & Monitoring
| Module | Description |
|--------|-------------|
| `scanner.py` | Multi-threaded TCP port scanner using `concurrent.futures` with common port detection |
| `pcap_analyzer.py` | PCAP network capture file parser for traffic analysis |
| `network_baseline_anomaly.py` | Statistical baseline builder with Z-score and EWMA anomaly detection across traffic metrics |
| `dns_tunneling_detector.py` | Covert DNS channel detection via Shannon entropy, query length, NXDOMAIN ratio, and TXT abuse |
| `wireless_security_auditor.py` | Evil twin AP detection, rogue AP scanning, WEP/WPA weakness flagging, deauth flood detection |

### 5. Threat Hunting & Intelligence
| Module | Description |
|--------|-------------|
| `yara_orchestrator.py` | YARA rule-based APT malware signature scanner |
| `dga_detector.py` | Domain Generation Algorithm detection using Shannon entropy and bigram frequency analysis |
| `misp_integration_engine.py` | Real-time IoC matching against MISP threat intelligence feeds |
| `steganography_detector.py` | LSB (Least Significant Bit) hidden payload detection in image files |
| `blockchain_threat_intel.py` | Cryptocurrency mixer and illicit fund transfer monitoring |

### 6. Deception & Active Defense
| Module | Description |
|--------|-------------|
| `honey_token_gen.py` | Fake AWS credential injection for early intrusion warning |
| `fake_smb_honeypot.py` | Decoy SMB file share with canary files to trap ransomware and lateral movement |
| `canary_db_tables.py` | Fake database tables with realistic credit card data to detect SQL injection theft |

### 7. Memory & Disk Forensics
| Module | Description |
|--------|-------------|
| `memory_dump_analyzer.py` | RAM forensics for shellcode signatures and credential extraction |
| `volatility_orchestrator.py` | Automated Volatility3 memory triage: process analysis, VAD code injection, hidden module detection |
| `process_hollowing_detector.py` | RunPE/Process Hollowing detection by comparing disk vs. memory SHA-256 hashes |

### 8. Cloud Security
| Module | Description |
|--------|-------------|
| `aws_cloudtrail_hunter.py` | AWS CloudTrail log analysis for privilege escalation, data exfiltration, and recon detection |
| `azure_ad_anomaly_detector.py` | Impossible Travel detection (Haversine formula), brute-force flagging in Azure AD sign-in logs |
| `aws_iam_policy_auditor.py` | IAM JSON policy auditing for overly permissive roles |

### 9. Endpoint Protection
| Module | Description |
|--------|-------------|
| `kernel_rootkit_detect.py` | SSDT hook scanning and hidden process detection via EPROCESS cross-referencing |
| `ransomware_recovery.py` | Volume Shadow Copy (VSS) enumeration and encrypted file restoration |
| `usb_device_auditor.py` | SetupAPI log parsing, USB whitelist enforcement, BadUSB attack detection |

### 10. Identity & Access Security
| Module | Description |
|--------|-------------|
| `ad_auditor.py` | Active Directory Kerberos AS-REP Roasting and Kerberoasting vulnerability audit |
| `behavioral_biometrics_monitor.py` | Keystroke dynamics session hijacking detection using Z-score analysis |
| `mfa_bypass_monitor.py` | Pass-the-Cookie and geovelocity anomaly detection for MFA bypass attacks |
| `zero_trust_device_attestation.py` | Full device posture evaluation (OS version, AV, firewall, disk encryption) |
| `password_policy_auditor.py` | NIST SP 800-63B compliance, Shannon entropy, keyboard walk detection, leet-speak decoding, GPU crack time estimation |

### 11. Incident Response
| Module | Description |
|--------|-------------|
| `incident_response.py` | Automated triage artifact collector (Event Logs, Prefetch, Amcache, netstat) |
| `windows_eventlog_forensics.py` | MITRE ATT&CK mapped Event Log parser with kill chain reconstruction |
| `email_header_forensics.py` | Email delivery path tracing, SPF/DKIM/DMARC verification, display-name spoofing detection |
| `siem_correlation_engine.py` | Multi-source log correlation with configurable rules and time-windowed pattern matching |

### 12. Application & API Security
| Module | Description |
|--------|-------------|
| `api_security_gateway.py` | JWT validation, OWASP API Top 10 input sanitization, per-endpoint rate limiting |
| `sql_injection_firewall.py` | AST-based SQL injection blocking (WAF) |
| `phishing_domain_scanner.py` | Typo-squatting detection via Levenshtein distance |
| `cert_transparency_monitor.py` | CT log monitoring, lookalike domain detection, TLS certificate chain auditing |

### 13. Infrastructure Security
| Module | Description |
|--------|-------------|
| `container_security_scanner.py` | Dockerfile CIS benchmark audit, Kubernetes manifest security scanning |
| `supply_chain_detector.py` | pip/npm typosquatting detection, known malicious package database, checksum verification |
| `iot_firmware_analyzer.py` | SquashFS extraction for hardcoded credential hunting in IoT firmware |

### 14. Behavioral Analytics
| Module | Description |
|--------|-------------|
| `insider_threat_ueba.py` | User behavioral profiling, login hour anomalies, mass file access spikes, USB exfiltration patterns |
| `malware_sandbox_analyzer.py` | Weighted behavioral scoring engine for sandbox reports with automatic classification |

### 15. OSINT
| Module | Description |
|--------|-------------|
| `dns_enum.py` | DNS subdomain bruteforce enumeration |

---

## Architecture

```
Elite-Defensive-Security-Tactics/
|-- main_defender.py              # Main orchestrator CLI
|-- requirements.txt              # Python dependencies
|-- modules/
|   |-- aes_vault.py              # Cryptography
|   |-- ad_auditor.py             # Active Directory
|   |-- api_security_gateway.py   # API Security
|   |-- aws_cloudtrail_hunter.py  # Cloud Security
|   |-- azure_ad_anomaly_detector.py
|   |-- behavioral_biometrics_monitor.py
|   |-- canary_db_tables.py       # Deception
|   |-- cert_transparency_monitor.py
|   |-- container_security_scanner.py
|   |-- data_loss_prevention.py   # DLP
|   |-- ddos_mitigation_engine.py
|   |-- dga_detector.py           # Threat Intel
|   |-- dns_enum.py               # OSINT
|   |-- dns_sinkhole.py
|   |-- dns_tunneling_detector.py
|   |-- email_header_forensics.py
|   |-- fake_smb_honeypot.py
|   |-- hash_analyzer.py
|   |-- honey_token_gen.py
|   |-- incident_response.py
|   |-- insider_threat_ueba.py    # UEBA
|   |-- kernel_rootkit_detect.py
|   |-- malware_sandbox_analyzer.py
|   |-- memory_dump_analyzer.py
|   |-- misp_integration_engine.py
|   |-- network_baseline_anomaly.py
|   |-- network_quarantine.py
|   |-- password_policy_auditor.py
|   |-- pcap_analyzer.py
|   |-- process_hollowing_detector.py
|   |-- ransomware_recovery.py
|   |-- scanner.py
|   |-- secure_shredder.py
|   |-- siem_correlation_engine.py
|   |-- sql_injection_firewall.py
|   |-- steganography_detector.py
|   |-- supply_chain_detector.py
|   |-- usb_device_auditor.py
|   |-- volatility_orchestrator.py
|   |-- windows_eventlog_forensics.py
|   |-- wireless_security_auditor.py
|   |-- yara_orchestrator.py
|   |-- zero_trust_device_attestation.py
|   +-- ... (and more)
```

---

## Requirements

```
cryptography
scapy
Pillow
requests
```

---

## License

MIT License (c) 2025 Abdulkadir Turan

---

## Disclaimer

This toolkit is designed for **authorized security testing, education, and defensive operations only**. Always obtain proper authorization before scanning or testing systems you do not own.
