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
