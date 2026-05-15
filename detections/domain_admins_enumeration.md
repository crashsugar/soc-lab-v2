# Domain Admins Enumeration Detection

## Objective

Detect Active Directory reconnaissance activity involving enumeration of privileged domain groups.

---

# Detection Logic

The rule monitors Sysmon process creation events and searches for command-line activity referencing the `Domain Admins` group.

This behavior may indicate:

- Active Directory discovery
- privilege reconnaissance
- attacker enumeration activity
- post-exploitation situational awareness

---

# Detection Rule

```xml
<group name="windows,active_directory,reconnaissance,">

  <rule id="100200" level="10">

    <if_sid>91852</if_sid>

    <field name="data.win.eventdata.commandLine">(?i)Domain Admins</field>

    <description>Possible Domain Admins enumeration detected</description>

    <mitre>
      <id>T1069</id>
      <id>T1069.002</id>
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

# Observed Commands

```powershell
net group "Domain Admins" /domain
```

---

# Detection Opportunities

## Indicators

| Indicator | Description |
|---|---|
| `net.exe` | Native Windows enumeration utility |
| `Domain Admins` | Privileged AD group |
| `/domain` | Domain-wide enumeration |

---

# MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Domain Groups Discovery | T1069.002 |

---

# Potential False Positives

Legitimate administrators may execute similar commands during:

- account audits
- AD administration
- troubleshooting
- privilege reviews

---

# Tuning Considerations

Possible improvements:

- alert only for non-administrative users
- correlate with suspicious PowerShell activity
- monitor frequency of reconnaissance commands
- correlate with lateral movement indicators

---

# Analyst Investigation Workflow

1. Identify user executing enumeration
2. Review command-line activity
3. Determine execution context
4. Correlate with additional reconnaissance activity
5. Investigate follow-on authentication attempts

---

# Validation

The rule was validated successfully in the SOC Lab v2 Active Directory environment using Domain Admins enumeration commands.
