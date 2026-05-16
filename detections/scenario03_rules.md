# Scenario 03 — Detection Rules Documentation

## Overview
Custom Wazuh rules for detecting the multi-stage attack chain.
Rule file: `scenario03_rules.xml`

---

## Rule 100301 — Encoded PowerShell
- **Event Source:** PowerShell Operational Log
- **Event ID:** 4104 (Script Block Logging)
- **Severity:** 12 (High)
- **MITRE:** T1059.001 — Command and Scripting Interpreter: PowerShell
- **Detects:** PowerShell executed with `-enc` or `-encodedcommand` flag
- **Why it matters:** Attackers encode commands to evade basic string detection

---

## Rule 100302 — Domain Admin Enumeration
- **Event Source:** Sysmon
- **Event ID:** 1 (Process Creation)
- **Severity:** 10 (Medium)
- **MITRE:** T1069.002 — Permission Groups Discovery: Domain Groups
- **Detects:** `net.exe` querying Domain Admins group
- **Why it matters:** Common recon step before privilege escalation

---

## Rule 100303 — Registry Persistence
- **Event Source:** Sysmon
- **Event ID:** 13 (Registry Value Set)
- **Severity:** 13 (Critical)
- **MITRE:** T1547.001 — Boot or Logon Autostart: Registry Run Keys
- **Detects:** New value written to `CurrentVersion\Run`
- **Why it matters:** Classic persistence mechanism surviving reboots

---

## Rule 100304 — Suspicious File Drop
- **Event Source:** Sysmon
- **Event ID:** 11 (File Creation)
- **Severity:** 10 (Medium)
- **MITRE:** T1105 — Ingress Tool Transfer
- **Detects:** Executable or script created in temp directory
- **Why it matters:** Common staging location for malware droppers
