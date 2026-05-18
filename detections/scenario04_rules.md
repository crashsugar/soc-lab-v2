# Scenario 04 — Detection Rules Documentation

## Overview
Custom Wazuh rules for detecting Linux SSH brute force and persistence chain.
Rule file: `scenario04_rules.xml`

---

## Rule 100401 — SSH Brute Force
- **Event Source:** /var/log/auth.log
- **Severity:** 10 (Medium)
- **MITRE:** T1110.001 — Brute Force: Password Guessing
- **Detects:** Multiple failed SSH authentication attempts from same source IP
- **Why it matters:** Common initial access technique against exposed SSH services

---

## Rule 100402 — Successful Login After Failures
- **Event Source:** /var/log/auth.log
- **Severity:** 12 (High)
- **MITRE:** T1078 — Valid Accounts
- **Detects:** Successful SSH login following authentication failures
- **Why it matters:** Indicates possible successful brute force or credential stuffing

---

## Rule 100403 — Cron Persistence
- **Event Source:** Wazuh FIM
- **Severity:** 12 (High)
- **MITRE:** T1053.003 — Scheduled Task/Job: Cron
- **Detects:** Modification to crontab files in /var/spool/cron
- **Why it matters:** Attackers use cron jobs for persistent backdoor execution

---

## Rule 100404 — Log Tampering
- **Event Source:** Wazuh FIM
- **Severity:** 13 (Critical)
- **MITRE:** T1070.003 — Indicator Removal: Clear Linux Logs
- **Detects:** Modification or clearing of /var/log/auth.log
- **Why it matters:** Attackers clear logs to remove evidence of intrusion
