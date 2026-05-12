# Scenario 01 — Encoded PowerShell Execution

## Objective

Simulate suspicious PowerShell execution using encoded commands and analyze the resulting telemetry in Wazuh and Sysmon.

---

# Attack Simulation

## Command Executed

```powershell
powershell.exe -ExecutionPolicy Bypass -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAYQBsAGMALgBlAHgAZQA=
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

# Telemetry Generated

## Sysmon Event ID 1 — Process Creation

### Key Indicators

- powershell.exe
- encoded command execution
- ExecutionPolicy Bypass
- suspicious command-line arguments

### Example Query

```text
data.win.system.eventID:1
```

---

## Sysmon Event ID 11 — File Creation

### Key Indicators

- Temp PowerShell script creation
- __PSScriptPolicyTest file activity
- suspicious temporary PS1 files

### Example Query

```text
data.win.system.eventID:11
```

---

# Detection Opportunities

## Suspicious Indicators

| Indicator | Description |
|---|---|
| -enc | Encoded PowerShell command |
| ExecutionPolicy Bypass | PowerShell policy bypass |
| Temp PS1 creation | Suspicious staging behavior |

---

# Existing Wazuh Detection

## Rule Triggered

| Rule ID | Description |
|---|---|
| 92213 | Executable file dropped in folder commonly used by malware |

---

# MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| PowerShell | T1059.001 |
| Ingress Tool Transfer | T1105 |

---

# Investigation Workflow

1. Identify suspicious PowerShell execution
2. Review command-line arguments
3. Identify parent process
4. Review Sysmon Event ID 11 activity
5. Correlate temporary file creation
6. Determine whether payload execution occurred

---

# Outcome

The attack successfully generated:

- PowerShell process creation telemetry
- Encoded command visibility
- Suspicious file creation activity
- Wazuh detection alerts

This validates:

- Sysmon telemetry collection
- Wazuh ingestion pipeline
- Detection capability
- Threat hunting workflow
