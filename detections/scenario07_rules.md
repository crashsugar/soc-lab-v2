# Scenario 07 — MDE Detection Documentation

## Overview
Detection engineered in Microsoft Defender for Endpoint using
Advanced Hunting (KQL) and custom detection rules.

---

## KQL Detection Query

```kusto
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in ("powershell.exe", "net.exe", "reg.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## Custom Detection Rule

| Field | Value |
|---|---|
| Rule name | Suspicious Process Execution - PowerShell/Net/Reg |
| Severity | High |
| Category | Exploit |
| Frequency | Continuous (NRT) |
| Detection source | Custom detection |
| Service | Microsoft Defender XDR |

---

## MITRE ATT&CK Mapping

| Technique | ID | Detected Via |
|---|---|---|
| PowerShell | T1059.001 | ProcessCommandLine contains -enc |
| Domain Groups Discovery | T1069.002 | net.exe with Domain Admins argument |
| Registry Run Keys | T1547.001 | reg.exe writing to CurrentVersion\Run |

---

## Key Differences vs Wazuh

| Feature | Wazuh | MDE |
|---|---|---|
| Detection rules | XML based | KQL based |
| Process chain visibility | Limited | Full parent/child chain |
| MITRE auto-tagging | Manual | Automatic |
| Alert correlation | Manual | Automatic (XDR) |
| Query language | Wazuh DSL | KQL |
