# Scenario 02 — Domain Admins Enumeration

## Objective

Simulate Active Directory reconnaissance activity by enumerating the Domain Admins group and analyze resulting telemetry in Wazuh and Sysmon.

---

# Attack Simulation

## Commands Executed

```powershell
net group "Domain Admins" /domain
```

```powershell
Get-ADGroupMember "Domain Admins"
```

---

# Environment

| Component | Description |
|---|---|
| SIEM | Wazuh |
| Endpoint Monitoring | Sysmon |
| OS | Windows Server |
| Environment | Active Directory Lab |

---

# Attack Goals

The objective of this activity is to simulate attacker reconnaissance focused on identifying privileged Active Directory accounts.

Enumeration of Domain Admins is commonly observed during:

- privilege escalation
- lateral movement preparation
- Active Directory discovery
- post-exploitation reconnaissance

---

# Planned Telemetry

| Source | Event Type |
|---|---|
| Sysmon | Process Creation |
| PowerShell | Command Execution |
| Windows Security Logs | Account Enumeration |
| Wazuh | Detection Alerts |

---

# MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Domain Groups Discovery | T1069.002 |

---

# Investigation Goals

1. Identify suspicious domain enumeration activity
2. Review PowerShell command execution
3. Identify user performing reconnaissance
4. Determine whether activity is expected administrative behavior
5. Correlate with additional suspicious activity
