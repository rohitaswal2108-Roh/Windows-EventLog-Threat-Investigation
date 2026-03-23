 # Windows Event Log Threat Investigation

![Splunk](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-orange)
![Sysmon](https://img.shields.io/badge/Sysmon-v15.15-blue)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![Events](https://img.shields.io/badge/Events%20Analysed-44%2C553-blueviolet)

A hands-on Windows event log baseline investigation performed using **Splunk Enterprise** and **Sysmon v15.15**. This project demonstrates practical SOC analyst skills including log ingestion, SPL query development, process chain analysis, anomaly investigation, and structured incident documentation.

---

## Investigation Summary

| Field | Detail |
|---|---|
| Host | DEADHACK (Windows 10/11) |
| Analyst | Rohit Aswal |
| Investigation Period | 22–23 March 2026 (24 hours) |
| Total Events Analysed | 44,553 |
| Log Sources | Security, Sysmon/Operational, Application, System |
| Malicious Activity | None confirmed |
| Outcome | Baseline established, 6 detection queries developed |

---

## Skills Demonstrated

- Windows Security event log analysis
- Sysmon configuration and deployment (SwiftOnSecurity config)
- SPL query development and field extraction
- Process creation chain investigation (parent-child analysis)
- Authentication baseline and anomaly triage
- Account enumeration investigation (EventCode 4798)
- Network connection analysis and C2 detection patterns
- MITRE ATT&CK technique mapping
- SOC-style investigation documentation

---

## Tools & Technologies

| Tool | Purpose |
|---|---|
| Splunk Enterprise | SIEM — log ingestion, SPL queries, correlation |
| Sysmon v15.15 | Endpoint telemetry (SwiftOnSecurity config) |
| Windows Event Viewer | Raw log verification |
| MITRE ATT&CK Navigator | Technique mapping |

---

## Key Findings

### Finding 1 — Authentication Analysis (4624 / 4625)
- 227 successful logon events recorded — all Logon Type 2 (interactive) by `DEADHACK\Rohit`
- **Zero failed logon attempts** — no brute force activity detected
- Established logon type baseline for future anomaly detection

### Finding 2 — Account Enumeration Investigation (4798) ⚠️
- 41,966 group membership enumeration events — initially flagged as suspicious
- Used `transpose` SPL command for field schema discovery
- Traced to Windows background audit process systematically enumerating all local accounts
- Uniform count of 10,480 across built-in accounts confirmed automated behaviour — **not threat actor enumeration**
- **Verdict: Benign** — false positive triage documented

### Finding 3 — Process Creation Analysis (Sysmon ID 1)
- 19,681 process creation events analysed
- Mapped complete parent-child process tree for host
- Identified one **orphaned cmd.exe** instance (no parent captured) — attributed to Epic Games launcher via command line content
- Flagged as low-confidence T1055 (Process Injection) — monitor pattern documented

### Finding 4 — Network Connection Analysis (Sysmon ID 3)
- 2,765 outbound connections — all attributed to `chrome.exe` under `DEADHACK\Rohit`
- External IPs on port 443: `142.251.152.119`, `34.8.7.18` (Google LLC / Google Cloud)
- Local gateway: `10.222.192.1`
- **Verdict: Benign** — normal browser traffic, no C2 beaconing detected

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Observed In | Verdict |
|---|---|---|---|
| T1059.003 | Windows Command Shell | cmd.exe chains — Splunk, ADB, McAfee | Benign |
| T1078 | Valid Accounts | DEADHACK\Rohit logon activity | Benign |
| T1087.001 | Local Account Discovery | EventCode 4798 enumeration | Benign — false positive |
| T1071.001 | Web Protocols | Chrome HTTPS outbound traffic | Benign |
| T1055 | Process Injection (potential) | Orphaned cmd.exe — no parent | Low confidence — monitor |

---

## SPL Detection Queries

### 1. Failed logon detection (brute force)
```spl
index=main source="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, host
| sort -count
```

### 2. Interactive logon analysis
```spl
index=main source="WinEventLog:Security" EventCode=4624
| where Logon_Type=2 OR Logon_Type=10 OR Logon_Type=11
| table _time, Account_Name, Logon_Type, Workstation_Name
| sort -_time
```

### 3. Account enumeration investigation
```spl
index=main source="WinEventLog:Security" EventCode=4798
| stats count by Account_Name, ComputerName
| sort -count
```

### 4. Suspicious cmd.exe / PowerShell process chains
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where (Image LIKE "%powershell.exe" OR Image LIKE "%cmd.exe")
AND NOT (ParentImage LIKE "%splunk%")
AND NOT (ParentImage LIKE "%Windows%")
| table _time, ParentImage, Image, CommandLine, User
| sort -_time
```

### 5. Outbound network connections — C2 detection pattern
```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| table _time, Image, DestinationIp, DestinationPort, User
| where DestinationIp!="127.0.0.1"
| sort -_time
```

### 6. Field schema discovery — transpose technique
```spl
index=main source="WinEventLog:Security" EventCode=4798
| head 1
| transpose
```

---

## Critical Event IDs Referenced

| Event ID | Source | Description | SOC Relevance |
|---|---|---|---|
| 4624 | Security | Successful logon | Baseline — check Logon Type |
| 4625 | Security | Failed logon | Brute force detection |
| 4648 | Security | Explicit credential use | Lateral movement signal |
| 4798 | Security | Local group enumeration | Potential reconnaissance |
| 4688 | Security | Process creation | Execution detection |
| Sysmon 1 | Sysmon | Process creation (rich) | Parent-child chain analysis |
| Sysmon 3 | Sysmon | Network connection | C2 / exfiltration detection |
| Sysmon 11 | Sysmon | File created | Dropper / payload detection |
| Sysmon 12/13 | Sysmon | Registry modification | Persistence detection |

---

## Repository Structure
```
Windows-EventLog-Threat-Investigation/
│
├── README.md
│
├── report/
│   └── Windows_EventLog_Investigation_Report.docx
│
├── screenshots/
│   ├── SS1_log_sources.png
│   ├── SS2_eventid_breakdown.png
│   ├── SS3_logon_analysis.png
│   ├── SS4_transpose_fields.png
│   ├── SS5_4798_account_breakdown.png
│   ├── SS6_process_tree.png
│   ├── SS7_suspicious_cmd_chains.png
│   ├── SS8_network_connections.png
│   └── SS9_splunk_query_live.png
│
└── queries/
    └── detection_queries.spl
```

---

## Lab Environment Setup

**Requirements:**
- Windows 10 / 11
- [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html) (free — 500MB/day)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) + [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config)

**Log ingestion — inputs.conf:**
```
[WinEventLog://Security]
index = main
disabled = false

[WinEventLog://System]
index = main
disabled = false

[WinEventLog://Application]
index = main
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = main
disabled = false
renderXml = false
```

---

## Key Takeaways

**Analyst techniques practised:**
- Used `transpose` command to extract field schema from unknown event types — real-world field discovery method
- Applied `stats count by` grouping to triage high-volume events efficiently
- Distinguished machine account (`DEADHACK$`) from user account activity
- Identified orphaned process pattern and documented attribution methodology

**Detection engineering outputs:**
- 6 validated SPL detection queries ready to deploy as Splunk saved searches
- Documented false positive patterns for EventCode 4798 to reduce alert fatigue
- Established host baseline for future anomaly comparison

---

## Author

**Rohit Aswal**
MSc Cybersecurity, Threat Intelligence & Digital Forensics — University of Salford
CEH Practical Certified | SOC Analyst | Threat Hunting | Digital Forensics

[LinkedIn](https://www.linkedin.com/in/rohit-aswal08) | [GitHub](https://github.com/rohitaswal2108-Roh)

---

> All investigations performed on a personal lab machine. No real organisational data involved. Screenshots contain only lab environment data.
```

---

## FILE 2 — `queries/detection_queries.spl`

---
```
# Windows Event Log Detection Queries
# Analyst: Rohit Aswal | Host: DEADHACK | Date: 23 March 2026
# All queries validated against live Splunk instance with Sysmon v15.15

# ─────────────────────────────────────────────
# AUTHENTICATION QUERIES
# ─────────────────────────────────────────────

# Query 1 — Failed logon detection (brute force pattern)
index=main source="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, host
| sort -count

# Query 2 — Interactive logon analysis
index=main source="WinEventLog:Security" EventCode=4624
| where Logon_Type=2 OR Logon_Type=10 OR Logon_Type=11
| table _time, Account_Name, Logon_Type, Workstation_Name
| sort -_time

# Query 3 — Explicit credential use (lateral movement signal)
index=main source="WinEventLog:Security" EventCode=4648
| table _time, Account_Name, Target_Server_Name, Process_Name
| sort -_time

# ─────────────────────────────────────────────
# ACCOUNT ENUMERATION QUERIES
# ─────────────────────────────────────────────

# Query 4 — Account enumeration volume investigation
index=main source="WinEventLog:Security" EventCode=4798
| stats count by Account_Name, ComputerName
| sort -count

# Query 5 — Field schema discovery (transpose technique)
index=main source="WinEventLog:Security" EventCode=4798
| head 1
| transpose

# ─────────────────────────────────────────────
# PROCESS CREATION QUERIES
# ─────────────────────────────────────────────

# Query 6 — Parent-child process tree baseline
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| stats count by ParentImage, Image
| sort -count
| head 20

# Query 7 — Suspicious cmd.exe / PowerShell chains
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where (Image LIKE "%powershell.exe" OR Image LIKE "%cmd.exe")
AND NOT (ParentImage LIKE "%splunk%")
AND NOT (ParentImage LIKE "%Windows%")
| table _time, ParentImage, Image, CommandLine, User
| sort -_time

# Query 8 — Orphaned process detection (no parent captured)
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where ParentImage="-" OR isnull(ParentImage)
| table _time, Image, CommandLine, User
| sort -_time

# ─────────────────────────────────────────────
# NETWORK CONNECTION QUERIES
# ─────────────────────────────────────────────

# Query 9 — Outbound network connections (C2 detection pattern)
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| table _time, Image, DestinationIp, DestinationPort, User
| where DestinationIp!="127.0.0.1"
| sort -_time

# Query 10 — Outbound connections by process — summary view
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| where DestinationIp!="127.0.0.1"
| stats count by Image, DestinationPort
| sort -count
```


