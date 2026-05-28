## Scenario 01 — Encoded PowerShell Execution
### Overview
Simulates suspicious PowerShell execution using encoded commands on a Windows Server
Domain Controller and analyzes the resulting telemetry in Wazuh and Sysmon.
### Environment
- Attacker/Victim: Windows Server 2019 Domain Controller
- SIEM: Wazuh Manager + Agent
- Logging: Sysmon + PowerShell Script Block Logging
### Attack Chain
| Stage | Technique | MITRE ID | Command |
|---|---|---|---|
| 1 | Encoded PowerShell | T1059.001 | `powershell.exe -ExecutionPolicy Bypass -enc <base64>` |
| 2 | File Drop | T1105 | Sysmon Event ID 11 |
### Detections
| Rule ID | Description | Severity |
|---|---|---|
| 92213 | Executable file dropped in folder commonly used by malware | 12 (High) |
| 100100 | Encoded PowerShell execution detected | 12 (High) |
### Evidence
- `logs/scenario01_powershell.json` — Event ID 1
- `logs/scenario01_filedrop.json` — Event ID 11
- `detections/scenario01_rules.xml` — Wazuh detection rules
- `screenshots/` — Dashboard evidence per stage

---

## Scenario 02 — Domain Admin Enumeration
### Overview
Simulates Active Directory reconnaissance by querying the Domain Admins group
using native Windows tools and analyzes detection capability in Wazuh and Sysmon.
### Environment
- Attacker/Victim: Windows Server 2019 Domain Controller
- SIEM: Wazuh Manager + Agent
- Logging: Sysmon + PowerShell Script Block Logging
### Attack Chain
| Stage | Technique | MITRE ID | Command |
|---|---|---|---|
| 1 | Domain Admin Enumeration via net.exe | T1069.002 | `net group "Domain Admins" /domain` |
| 2 | Domain Admin Enumeration via PowerShell | T1069.002 | `Get-ADGroupMember "Domain Admins"` |
### Detections
| Rule ID | Description | Severity |
|---|---|---|
| 100201 | Domain Admin group enumeration detected | 10 (Medium) |
### Evidence
- `logs/scenario02_netgroup.json` — net.exe enumeration
- `logs/scenario02_domain_enum.json` — Get-ADGroupMember telemetry
- `detections/scenario02_rules.xml` — Wazuh detection rules
- `screenshots/scenario02_domain_admins.png` — Dashboard evidence

---

## Scenario 03 — Multi-Stage Attack (PowerShell + Enumeration + Persistence)

### Overview
Simulates a multi-stage attack chain on a Windows Server Domain Controller using
encoded PowerShell, domain enumeration, registry persistence, and file drop.

### Environment
- Attacker/Victim: Windows Server 2019 Domain Controller
- SIEM: Wazuh Manager + Agent
- Logging: Sysmon + PowerShell Script Block Logging

### Attack Chain

| Stage | Technique | MITRE ID | Command |
|---|---|---|---|
| 1 | Encoded PowerShell | T1059.001 | `powershell.exe -enc <base64>` |
| 2 | Domain Admin Enumeration | T1069.002 | `net group "Domain Admins" /domain` |
| 3 | Registry Persistence | T1547.001 | `reg add HKCU\...\Run /v Updater` |
| 4 | File Drop | T1105 | Sysmon Event ID 11 |

### Detections

| Rule ID | Description | Severity |
|---|---|---|
| 100301 | Encoded PowerShell execution | 12 (High) |
| 100302 | Domain Admin group enumeration | 10 (Medium) |
| 100303 | Registry Run key persistence | 13 (Critical) |
| 100304 | Suspicious file in temp directory | 10 (Medium) |

### Evidence
- `logs/scenario03_powershell.json` — Event ID 4104
- `logs/scenario03_domain_enum.json` — Event ID 1
- `logs/scenario03_registry_persistence.json` — Event ID 13
- `logs/scenario03_filedrop.json` — Event ID 11
- `detections/scenario03_rules.xml` — Wazuh detection rules
- `screenshots/` — Dashboard evidence per stage

---

## Scenario 04 — Linux SSH Brute Force + Persistence
### Overview
Simulates a multi-stage Linux attack chain involving SSH brute force, successful
authentication, cron job persistence, and log tampering on an Ubuntu Server.
### Environment
- Attacker: Kali Linux (Live USB)
- Victim: Ubuntu Server + Wazuh Agent
- SIEM: Wazuh Manager + Agent
- Logging: auth.log + Wazuh FIM
### Attack Chain
| Stage | Technique | MITRE ID | Command |
|---|---|---|---|
| 1 | SSH Brute Force | T1110.001 | `hydra -l ubuntu -P passwords.txt ssh://<ip>` |
| 2 | Successful SSH Login | T1078 | `ssh ubuntu@<ip>` |
| 3 | Cron Persistence | T1053.003 | `crontab -e` |
| 4 | Log Tampering | T1070.003 | `cat /dev/null > /var/log/auth.log` |
### Detections
| Rule ID | Description | Severity |
|---|---|---|
| 100401 | SSH brute force detected | 10 (Medium) |
| 100402 | Successful login after failures | 12 (High) |
| 100403 | Crontab modification detected | 12 (High) |
| 100404 | auth.log tampering detected | 13 (Critical) |
### Evidence
- `logs/scenario04_bruteforce.json` — Failed SSH attempts
- `logs/scenario04_ssh_login.json` — Successful login
- `logs/scenario04_persistence.json` — Crontab FIM alert
- `logs/scenario04_logtamper.json` — auth.log FIM alert
- `detections/scenario04_rules.xml` — Wazuh detection rules
- `screenshots/` — Dashboard evidence per stage

---

## Scenario 05 — Phishing Malicious Document Analysis (Passive)
### Overview
Passive static analysis of a real malicious Word document from MalwareBazaar.
Identifies CVE-2017-11882 exploit technique, extracts IOCs, and documents
findings as a SOC analyst triage report.
### Environment
- Analysis Machine: Ubuntu Server (isolated VM)
- Tools: oletools, oleid, olevba, VirusTotal
### Sample
- SHA256: f26336dfb7477c2be6c38f459bed7c8351f8548acd344d5f291de17a9c9843cc
- Type: DOCX with embedded RTF
- Threat: CVE-2017-11882 Equation Editor RCE
- VT Detection: 40/66
### MITRE ATT&CK
| Technique | ID |
|---|---|
| Phishing: Spearphishing Attachment | T1566.001 |
| Exploit Public-Facing Application | T1203 |
| Obfuscated Files or Information | T1027 |
### Key Findings
| IOC | Risk |
|---|---|
| aFChunk loading embedded RTF | High |
| CVE-2017-11882 exploit | Critical |
| Fake Microsoft author metadata | Medium |
| 40/66 VT detections | Critical |
### Evidence
- `logs/scenario05_oleid_output.txt` — oleid analysis
- `screenshots/scenario05_virustotal.png` — VT detections
- `screenshots/scenario05_vt_details.png` — VT details
- `screenshots/scenario05_vt_behaviour.png` — VT behaviour

---

## Scenario 06 — Mimikatz Credential Dumping
### Overview
Executes Mimikatz on a Windows Server Domain Controller to simulate credential
dumping via LSASS memory access. Detects and compares alerts across Wazuh/Sysmon
and Microsoft Defender for Endpoint.
### Environment
- Target: Windows Server 2022 Domain Controller
- Tool: Mimikatz v2.2.0
- SIEM: Wazuh + Sysmon
- EDR: Microsoft Defender for Endpoint P2
### Attack Chain
| Stage | Technique | MITRE ID | Command |
|---|---|---|---|
| 1 | Disable Defender | T1562.001 | `Set-MpPreference -DisableRealtimeMonitoring $true` |
| 2 | Request debug privilege | T1134 | `privilege::debug` |
| 3 | Dump LSASS credentials | T1003.001 | `sekurlsa::logonpasswords` |
| 4 | Dump LSA secrets | T1003.004 | `lsadump::lsa /patch` |
### Key Findings
- krbtgt hash obtained — Golden Ticket attack possible
- All domain account NTLM hashes dumped
- MDE generated Priority 100 incident with automatic account containment
### Detections
| Tool | Detection | Severity |
|---|---|---|
| Wazuh Rule 92900 | LSASS process access by mimikatz.exe | 12 (High) |
| MDE | Mimikatz credential theft tool | High |
| MDE | Hands-on keyboard attack | High — Priority 100 |
| MDE | LSASS process memory modified | High |
### Evidence
- `logs/scenario06_wazuh_event10.json` — Wazuh Event ID 10
- `logs/scenario06_mde_incidents.csv` — MDE incidents
- `screenshots/` — Wazuh and MDE evidence

---

## Scenario 07 — Microsoft Defender for Endpoint (EDR Detection)
### Overview
Deploys Microsoft Defender for Endpoint P2 on a Windows Server Domain Controller,
executes a multi-stage attack chain, and validates detection using device timeline,
Advanced Hunting KQL queries, and custom detection rules.
### Environment
- EDR: Microsoft Defender for Endpoint P2
- Endpoint: Windows Server 2019 Domain Controller
- Portal: security.microsoft.com
### Attack Chain
| Stage | Technique | MITRE ID | Command |
|---|---|---|---|
| 1 | Encoded PowerShell | T1059.001 | `powershell.exe -enc <base64>` |
| 2 | Domain Admin Enumeration | T1069.002 | `net group "Domain Admins" /domain` |
| 3 | Registry Persistence | T1547.001 | `reg add HKCU\...\Run /v Updater` |
### Detections
| Method | Description | Severity |
|---|---|---|
| Device Timeline | MITRE ATT&CK auto-tagged events | Automatic |
| Advanced Hunting | KQL query across all 3 stages | Manual |
| Custom Detection Rule | Real-time High alert on process execution | High |
### Evidence
- `logs/scenario07_advanced_hunting.json` — KQL export
- `detections/scenario07_rules.md` — KQL rule documentation
- `screenshots/scenario07_timeline.png` — Device timeline
- `screenshots/scenario07_advanced_hunting.png` — KQL results
- `screenshots/scenario07_detection_rule.png` — Custom rule
- `screenshots/scenario07_alert.png` — Triggered alert

---
