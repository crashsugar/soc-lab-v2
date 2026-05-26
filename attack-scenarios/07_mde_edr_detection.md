# Scenario 07 — Microsoft Defender for Endpoint (EDR Detection)

## Objective
Deploy Microsoft Defender for Endpoint (MDE) on a Windows Server Domain Controller,
execute a multi-stage attack chain, and validate detection capability using the MDE
portal, Advanced Hunting (KQL), and custom detection rules.

---

## Attack Stages
| Stage | Activity |
|---|---|
| 1 | Encoded PowerShell execution |
| 2 | Domain Admin enumeration via net.exe |
| 3 | Registry persistence via reg.exe |

---

## Environment
| Component | Description |
|---|---|
| EDR | Microsoft Defender for Endpoint P2 |
| Endpoint | Windows Server 2019 Domain Controller |
| Portal | security.microsoft.com |
| Detection | Custom KQL detection rule + built-in MDE telemetry |

---

## MITRE ATT&CK Coverage
| Technique | ID |
|---|---|
| PowerShell | T1059.001 |
| Domain Groups Discovery | T1069.002 |
| Registry Run Keys Persistence | T1547.001 |

---

## Commands
| Stage | Command |
|---|---|
| 1 | `powershell.exe -ExecutionPolicy Bypass -enc UwB0AGEAcgB0...` |
| 2 | `net group "Domain Admins" /domain` |
| 3 | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\temp\updater.exe"` |

---

## Detection Method 1 — Device Timeline

MDE automatically tagged events with MITRE ATT&CK technique IDs in the device timeline:

| Event | MITRE Tag |
|---|---|
| dns.exe ran LDAP query | T1087.002 — Domain Account |
| Network communication flagged | T1095 — Non-Application Layer Protocol |
| Named pipe activity | T1559 — Inter-Process Communication |

---

## Detection Method 2 — Advanced Hunting (KQL)

Query used to detect all 3 attack stages:

```kusto
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in ("powershell.exe", "net.exe", "reg.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

Results returned:
- `reg.exe add HKCU\Software\...` — Registry persistence
- `net.exe group "Domain Admins"` — Domain enumeration
- `powershell.exe -ExecutionPolicy Bypass -enc` — Encoded PowerShell

---

## Detection Method 3 — Custom Detection Rule

Rule created from Advanced Hunting query:

| Field | Value |
|---|---|
| Rule name | Suspicious Process Execution - PowerShell/Net/Reg |
| Severity | High |
| Category | Exploit |
| Detection source | Custom detection |
| Service source | Microsoft Defender XDR |
| Run frequency | Continuous (NRT) |

Alert generated: **Suspicious Attack Chain - PowerShell/Net/Reg Execution**

---

## Attack Timeline
| Time | Stage | Activity | Detected |
|---|---|---|---|
| T+0 | 1 | Encoded PowerShell executed | ✅ |
| T+1 | 2 | net.exe queried Domain Admins | ✅ |
| T+2 | 3 | reg.exe wrote to Run key | ✅ |
| T+3 | — | Custom rule fired High alert | ✅ |

---

## Investigation Goals
1. Onboard Windows DC to enterprise EDR
2. Detect attack chain via device timeline
3. Query telemetry using KQL in Advanced Hunting
4. Build and validate custom detection rule
5. Analyse alert details and process chain

---

## Outcome
The attack successfully generated:
- Automatic MITRE ATT&CK tagged events in device timeline
- Full process chain visibility in MDE portal
- KQL query results showing all 3 attack stages
- High severity custom detection alert fired in real time

This validates:
- MDE onboarding and telemetry collection
- Advanced Hunting KQL query capability
- Custom detection rule engineering in enterprise EDR
- Process chain analysis for SOC investigation

---

## Evidence
- `logs/scenario07_advanced_hunting.json` — KQL query export
- `screenshots/scenario07_timeline.png` — Device timeline with MITRE tags
- `screenshots/scenario07_advanced_hunting.png` — KQL results
- `screenshots/scenario07_detection_rule.png` — Custom rule details
- `screenshots/scenario07_alert.png` — Triggered alert details

---

## References
- [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [T1069.002](https://attack.mitre.org/techniques/T1069/002/)
- [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
