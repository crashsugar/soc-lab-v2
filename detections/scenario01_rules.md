# Encoded PowerShell Detection

## Objective

Detect suspicious PowerShell execution using encoded command-line arguments.

---

# Detection Logic

The detection monitors Sysmon process creation events and searches for the `-enc` argument inside PowerShell command-line activity.

---

# Detection Rule

```xml
<group name="windows,powershell,">

  <rule id="100100" level="12">

    <if_sid>91852</if_sid>

    <field name="data.win.eventdata.commandLine">(?i)-enc</field>

    <description>Encoded PowerShell execution detected</description>

    <mitre>
      <id>T1059</id>
      <id>T1059.001</id>
    </mitre>

  </rule>

</group>
```

---

# Telemetry Source

| Source | Description |
|---|---|
| Sysmon Event ID 1 | Process creation telemetry |

---

# Detection Coverage

## Detects

- Encoded PowerShell execution
- Suspicious PowerShell command-line arguments
- Potential payload staging activity

---

# MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| PowerShell | T1059.001 |

---

# Limitations

## Potential Evasion

Attackers may avoid detection by:

- using alternative PowerShell flags
- obfuscating command-line arguments
- using indirect execution methods

---

# Tuning Considerations

Potential improvements:

- monitor `ExecutionPolicy Bypass`
- detect suspicious child processes
- detect PowerShell spawned from Office applications
- correlate with Event ID 11 file creation activity

---

# Validation

The rule was tested successfully inside the SOC Lab v2 Active Directory environment using encoded PowerShell execution.

