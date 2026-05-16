# Scenario 03 — Multi-Stage Attack Chain

## Objective

Simulate a multi-stage intrusion workflow involving PowerShell execution, file staging, Active Directory reconnaissance, and persistence-related behavior.

The objective is to analyze how multiple telemetry sources and detections can be correlated during a SOC investigation.

---

# Attack Stages

| Stage | Activity |
|---|---|
| 1 | Encoded PowerShell execution |
| 2 | Temporary PowerShell file creation |
| 3 | Domain Admins enumeration |
| 4 | Persistence simulation |

---

# Environment

| Component | Description |
|---|---|
| SIEM | Wazuh |
| Endpoint Monitoring | Sysmon |
| Environment | Active Directory Lab |

---

# MITRE ATT&CK Coverage

| Technique | ID |
|---|---|
| PowerShell | T1059.001 |
| Ingress Tool Transfer | T1105 |
| Domain Groups Discovery | T1069.002 |
| Registry Run Keys / Startup Folder | T1547.001 |

---

# Investigation Goals

1. Identify initial execution activity
2. Correlate process creation events
3. Track suspicious file creation
4. Detect Active Directory reconnaissance
5. Identify persistence-related activity
6. Build attack timeline from telemetry

---

## Commands
| Stage | Command |
|---|---|
| 1 | `powershell.exe -ExecutionPolicy Bypass -enc UwB0AGEAcgB0...` |
| 2 | `Sysmon auto-captured via Stage 1` |
| 3 | `net group "Domain Admins" /domain` |
| 4 | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\temp\updater.exe"` |

---

## Detection Evidence
| Stage | Log File | Event ID | Wazuh Rule |
|---|---|---|---|
| 1 | scenario03_powershell.json | 4104 | 100301 |
| 2 | scenario03_filedrop.json | 11 | 100304 |
| 3 | scenario03_domain_enum.json | 1 | 100302 |
| 4 | scenario03_registry_persistence.json | 13 | 100303 |

---

## Attack Timeline
| Time | Stage | Activity | Detected |
|---|---|---|---|
| T+0 | 1 | Encoded PowerShell executed | ✅ |
| T+1 | 2 | File dropped in temp | ✅ |
| T+2 | 3 | Domain Admins enumerated | ✅ |
| T+3 | 4 | Registry Run key written | ✅ |

---

## References
- [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [T1105](https://attack.mitre.org/techniques/T1105/)
- [T1069.002](https://attack.mitre.org/techniques/T1069/002/)
- [T1547.001](https://attack.mitre.org/techniques/T1547/001/)

---
