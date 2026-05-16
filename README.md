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
