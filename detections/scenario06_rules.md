# Scenario 06 — Detection Rules Documentation

## Overview
Detection coverage for Mimikatz credential dumping via LSASS memory access.
Covers both Wazuh/Sysmon and Microsoft Defender for Endpoint detections.

---

## Wazuh — Built-in Rule 92900

### Rule Details
| Field | Value |
|---|---|
| Rule ID | 92900 |
| Level | 12 (High) |
| Group | sysmon, sysmon_eid10_detections, windows |
| MITRE | T1003.001 — LSASS Memory |
| Tactic | Credential Access |

### Trigger Condition
Sysmon Event ID 10 where targetImage is lsass.exe

### Sysmon Config Required
```xml
<ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
</ProcessAccess>
```

### Key Fields in Alert
| Field | Value |
|---|---|
| sourceImage | mimikatz.exe path |
| targetImage | C:\Windows\system32\lsass.exe |
| grantedAccess | 0x1010 — Read process memory |
| sourceUser | LAB\Administrator |
| targetUser | NT AUTHORITY\SYSTEM |

---

## MDE — Advanced Hunting KQL

### Mimikatz Process Detection
```kusto
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName == "mimikatz.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### LSASS Access Detection
```kusto
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType == "LsassProcessAccess"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Credential Dumping Broad Detection
```kusto
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName == "mimikatz.exe"
    or ProcessCommandLine has "sekurlsa"
    or ProcessCommandLine has "lsadump"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## MDE — Built-in Alerts Triggered

| Alert | Severity | Category |
|---|---|---|
| Mimikatz credential theft tool | High | Credential access |
| Malicious credential theft tool execution detected | High | Credential access |
| LSASS process memory modified | High | Credential access |
| Suspicious access to LSASS service | High | Credential access |
| Hands-on keyboard attack from compromised account | High | Lateral Movement |
| Potential human-operated malicious activity | High | Suspicious activity |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detected By |
|---|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 | Wazuh Rule 92900, MDE |
| Access Token Manipulation | T1134 | MDE |
| Security Support Provider | T1547.005 | MDE |
| Disable or Modify Tools | T1562.001 | MDE |

---

## Wazuh vs MDE Comparison

| Feature | Wazuh | MDE |
|---|---|---|
| LSASS access detection | ✅ Rule 92900 | ✅ Automatic |
| Mimikatz named detection | ✅ via sourceImage | ✅ Named alert |
| MITRE auto-tagging | ✅ T1003.001 | ✅ Multiple |
| Automated response | ❌ | ✅ Account containment |
| Incident correlation | ❌ Manual | ✅ Automatic |
| Priority scoring | ❌ | ✅ Score 100 |
| Query language | Wazuh DSL | KQL |
