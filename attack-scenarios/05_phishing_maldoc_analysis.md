# Scenario 05 — Phishing Malicious Document Analysis (Passive)

## Objective
Perform passive static analysis of a malicious Word document (.docx) obtained from
MalwareBazaar. Identify attack techniques, extract IOCs, and document findings as
a SOC analyst triage report without executing the sample.

---

## Sample Information
| Field | Value |
|---|---|
| Filename | f26336dfb7477c2be6c38f459bed7c8351f8548acd344d5f291de17a9c9843cc.docx |
| SHA256 | f26336dfb7477c2be6c38f459bed7c8351f8548acd344d5f291de17a9c9843cc |
| File size | 560.58 KB |
| File type | DOCX (OpenXML) with embedded RTF |
| Source | MalwareBazaar |

---

## Environment
| Component | Description |
|---|---|
| Analysis Machine | Ubuntu Server (isolated VM) |
| Tools | oletools, oleid, olevba, unzip, strings |
| Network | Isolated — no execution performed |

---

## MITRE ATT&CK Coverage
| Technique | ID |
|---|---|
| Phishing: Spearphishing Attachment | T1566.001 |
| Exploit Public-Facing Application | T1203 |
| Command and Scripting Interpreter | T1059 |
| Obfuscated Files or Information | T1027 |

---

## Vulnerability
**CVE-2017-11882 — Microsoft Office Equation Editor RCE**
- Allows remote code execution on document open
- No macro interaction required
- Affects Microsoft Office 2007-2016
- One of the most exploited Office vulnerabilities

---

## Analysis Methodology

### Step 1 — File Identification
```bash
file sample.docx
```
Result: Zip archive data — confirmed DOCX format

### Step 2 — Macro Analysis
```bash
olevba sample.docx
oleid sample.docx
```
Result: No VBA or XLM macros found — exploitation via CVE not macros

### Step 3 — Relationship Analysis
```bash
unzip -p sample.docx word/_rels/document.xml.rels
```
Suspicious finding:
```xml
<Relationship Type="aFChunk" Target="/word/urse.xml" Id="PDj5"/>
```
- aFChunk loads external content at document open
- Points to embedded RTF file urse.xml

### Step 4 — Document Body Analysis
```bash
unzip -p sample.docx word/document.xml
```
Finding:
```xml
<w:altChunk r:id="PDj5"/>
```
Confirms automatic loading of malicious RTF chunk on open

### Step 5 — Metadata Extraction
```bash
unzip -p sample.docx docProps/core.xml
```

### Step 6 — VirusTotal Analysis
SHA256 submitted to VirusTotal for reputation check

---

## IOCs (Indicators of Compromise)

### File IOCs
| IOC | Value |
|---|---|
| SHA256 | f26336dfb7477c2be6c38f459bed7c8351f8548acd344d5f291de17a9c9843cc |
| File type | DOCX with embedded RTF |
| File size | 560.58 KB |

### Document Metadata IOCs
| Field | Value | Suspicious |
|---|---|---|
| Creator | Microsoft | ⚠️ Fake author name |
| Last modified by | John | ⚠️ Generic name |
| Created | 2020-01-30 | noted |
| Last modified | 2026-01-10 | ⚠️ Modified 6 years after creation |
| Revision count | 10 | ⚠️ Multiple edits suggest tampering |

### Structural IOCs
| IOC | Description |
|---|---|
| aFChunk relationship | Loads malicious RTF at document open |
| urse.xml | Embedded RTF with hex encoded payload |
| ZIP magic bytes in RTF | Polyglot file technique |
| altChunk element | Triggers automatic content loading |

---

## VirusTotal Results
| Field | Value |
|---|---|
| Detection ratio | 40/66 engines |
| Threat label | trojan.obfsobjdat/rtfmalform |
| Threat categories | Trojan, Dropper |
| Family labels | obfsobjdat, rtfmalform, rtfobfustream |
| Tags | docx, malware, calls-wmi, exploit, CVE-2017-11882 |

---

## Analyst Assessment

### What This Document Does
This document exploits CVE-2017-11882 (Microsoft Office Equation Editor RCE).
When opened on a vulnerable system it automatically loads an embedded RTF chunk
containing hex-encoded shellcode. No user interaction beyond opening the file
is required. The document masquerades as a legitimate file using fake Microsoft
authorship metadata.

---

### Attack Chain

Victim receives phishing email with .docx attachment
↓
Victim opens document
↓
altChunk loads urse.xml (malicious RTF)
↓
CVE-2017-11882 triggers Equation Editor exploit
↓
Shellcode executes → dropper downloads payload
↓
Trojan installed on victim machine

---

### Suspicious Indicators Summary
| Indicator | Risk |
|---|---|
| Fake "Microsoft" author metadata | Medium |
| aFChunk loading embedded RTF | High |
| CVE-2017-11882 exploit technique | Critical |
| Hex encoded payload in RTF | High |
| 40/66 VT detections | Critical |
| Trojan/Dropper classification | Critical |

---

## Detection Recommendations
| Recommendation | Priority |
|---|---|
| Block documents with aFChunk relationships at email gateway | High |
| Patch CVE-2017-11882 on all Office installations | Critical |
| Enable Attack Surface Reduction rules for Office | High |
| Scan attachments with sandbox before delivery | High |
| Block Equation Editor (eqnedt32.exe) via AppLocker | High |

---

## Outcome
Passive analysis successfully identified:
- Exploit technique without executing the sample
- CVE-2017-11882 as the attack vector
- Multiple IOCs for detection and blocking
- Full attack chain reconstruction from static analysis alone

This validates:
- Static malware analysis workflow
- oletools usage for document analysis
- IOC extraction and documentation
- SOC triage report writing

---

## Evidence
- `logs/scenario05_oleid_output.txt` — oleid analysis results
- `screenshots/scenario05_virustotal.png` — VT detection results
- `screenshots/scenario05_vt_details.png` — VT file details
- `screenshots/scenario05_vt_behaviour.png` — VT behaviour tab

---

## References
- [CVE-2017-11882](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11882)
- [T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [T1203](https://attack.mitre.org/techniques/T1203/)
- [T1027](https://attack.mitre.org/techniques/T1027/)
- [MalwareBazaar Sample](https://bazaar.abuse.ch/sample/f26336dfb7477c2be6c38f459bed7c8351f8548acd344d5f291de17a9c9843cc/)
