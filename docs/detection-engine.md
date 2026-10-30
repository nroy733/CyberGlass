# 🚨 Detection and Correlation Engine

The CyberGlass Detection Engine (`cg-detect`) provides real-time rule evaluation, sliding-window threshold correlation, Sigma YAML import, and built-in MITRE ATT&CK matrix mapping.

---

## 1. Rule Types

CyberGlass supports five detection archetypes:

| Rule Type | Description | Use Case |
|---|---|---|
| **Simple** | Evaluated per-event against parsed key-value tokens | Immediate threat detection (e.g., `action=sudo` or `malware=detected`) |
| **Threshold** | Evaluates event count within a sliding time window grouped by an entity | Brute force attacks, port scans, password spraying |
| **Correlation** | Multi-event sequence matching across distinct event sources | Phishing click followed by PowerShell execution and outbound C2 |
| **Anomaly** | Statistical baseline deviation tracking | Data exfiltration volume spikes, unusual logon hours |
| **Chain** | Attack path verification linking multiple MITRE ATT&CK tactics | Initial Access $\rightarrow$ Privilege Escalation $\rightarrow$ Lateral Movement |

---

## 2. Sliding-Window Threshold Correlation

Threshold rules trigger when an event condition matches at least $N$ times within a configurable lookback window $T$, grouped by an entity attribute (e.g. `src_ip`, `user`, or `host`).

**Example: Brute Force Detection**
```rust
DetectionRule {
    id: "rule-brute-force".into(),
    name: "Brute Force Authentication Attempt".into(),
    query: "action=failure".into(),
    severity: RuleSeverity::High,
    rule_type: RuleType::Threshold,
    threshold: Some(RuleThreshold {
        count: 5,
        time_window_seconds: 60,
        group_by_field: Some("src_ip".into()),
    }),
    mitre_techniques: vec!["T1110".into()],
    ...
}
```

When 5 failed authentication attempts occur from IP `192.168.1.100` within 60 seconds:
1. The alert is generated with `event_ids` containing all 5 triggering events as forensic evidence.
2. An automatic suppression window is activated to prevent alert fatigue.

---

## 3. Sigma Rule Import

CyberGlass includes a native Sigma compiler (`SigmaConverter`) that converts standard Sigma YAML rules into CyberGlass detection rules and CyberQL queries.

### Sigma Example
```yaml
title: Suspicious PowerShell Download
status: experimental
description: Detects suspicious PowerShell cradle executing WebClient
level: high
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: powershell.exe
        CommandLine:
            - Net.WebClient
            - DownloadFile
    condition: selection
```

### Generated CyberGlass Rule
- **Name**: `Suspicious PowerShell Download`
- **Severity**: `RuleSeverity::High`
- **MITRE ATT&CK**: `["T1059"]` (Command and Scripting Interpreter)
- **Compiled Query**: `product="windows" Image="powershell.exe" (CommandLine="Net.WebClient" OR CommandLine="DownloadFile")`

---

## 4. Built-in MITRE ATT&CK Mapping

CyberGlass embeds offline metadata for MITRE ATT&CK techniques:

| Technique ID | Name | Tactic | Description |
|---|---|---|---|
| **T1110** | Brute Force | Credential Access | Password guessing, credential stuffing, password spraying |
| **T1078** | Valid Accounts | Defense Evasion | Abuse of legitimate credentials |
| **T1059** | Command & Scripting Interpreter | Execution | PowerShell, Bash, Python, AppleScript execution |
| **T1068** | Exploitation for Privilege Escalation | Privilege Escalation | Elevating permissions via software flaws |
| **T1053** | Scheduled Task/Job | Persistence | Task scheduler and cron persistence |
| **T1003** | OS Credential Dumping | Credential Access | LSASS memory dump, SAM database extraction |
| **T1021** | Remote Services | Lateral Movement | RDP, SSH, SMB lateral movement |
| **T1041** | Exfiltration Over C2 Channel | Exfiltration | Transferring stolen data over command channels |
| **T1071** | Application Layer Protocol | Command and Control | C2 over HTTP, HTTPS, DNS |
| **T1566** | Phishing | Initial Access | Malicious email attachments and credential harvesting links |
| **T1486** | Data Encrypted for Impact | Impact | Ransomware encryption of organizational assets |
