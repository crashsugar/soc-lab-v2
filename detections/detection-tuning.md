# Detection Tuning and False Positive Analysis

## Objective

Document false positives, noisy detections, and tuning considerations identified during SOC Lab v2 testing.

---

# Case Study — Sysmon Event ID 1 False Positive

## Detection Triggered

| Rule ID | Description |
|---|---|
| 92052 | Windows command prompt started by an abnormal process |

---

# Observed Process

```text
dsregcmd.exe
```

---

# Observed Behavior

The detection triggered on execution of `dsregcmd.exe`, a legitimate Microsoft Windows component associated with device registration and scheduled system activity.

The process was launched by:

```text
svchost.exe -k netsvcs -p -s Schedule
```

and executed under:

```text
NT AUTHORITY\SYSTEM
```

---

# Investigation Findings

## Indicators Supporting Benign Classification

| Indicator | Observation |
|---|---|
| Binary Signature | Microsoft signed |
| Parent Process | svchost.exe |
| Execution Context | SYSTEM |
| Execution Path | System32 |
| Known Windows Utility | Yes |

---

# Analyst Assessment

The alert appears to represent legitimate scheduled Windows activity rather than malicious execution.

This demonstrates the importance of:

- contextual analysis
- process lineage review
- parent-child relationship validation
- distinguishing benign from malicious behavior

---

# Potential Tuning Strategies

## Reduce Noise

Possible approaches:

- whitelist known Microsoft binaries
- suppress trusted parent-child combinations
- lower severity for SYSTEM scheduled tasks
- create exception logic for known benign behavior

---

# Tuning Risks

Excessive suppression may reduce visibility into:

- LOLBins
- attacker abuse of legitimate Windows binaries
- scheduled task persistence
- masquerading attacks

---

# SOC Engineering Lessons

This case highlights a key challenge in detection engineering:

High detection sensitivity may improve visibility but can also increase analyst fatigue through false positives.

Effective SOC operations require balancing:

- visibility
- fidelity
- alert volume
- analyst workload

---

# Outcome

The lab successfully demonstrated:

- alert triage workflow
- false positive analysis
- process investigation
- detection tuning considerations
- SOC investigation methodology

