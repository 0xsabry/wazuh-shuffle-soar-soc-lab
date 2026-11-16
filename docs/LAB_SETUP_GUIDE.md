# Step-by-Step SOC & SOAR Lab Setup Guide

A complete, reproducible guide to building the distributed Wazuh SIEM + Shuffle SOAR + Tailscale Mesh security operations environment.

---

## 1. Prerequisites

- **Host Virtualization**: VirtualBox 7.0+ or VMware Workstation 17+
- **Wazuh Manager**: Official all-in-one Wazuh OVA (v4.14+)
- **Operating Systems**:
  - Ubuntu Server 24.04 LTS (2 vCPU, 4 GB RAM)
  - Windows 11 Enterprise (2 vCPU, 4 GB RAM)
  - Windows Server 2022 Standard (2 vCPU, 4 GB RAM)
- **Networking & VPN**: Tailscale Free Plan (Owner-approved mesh tailnet)
- **Automation**: Docker & Docker Compose (for Shuffle SOAR)

---

## 2. Wazuh SIEM Manager Deployment

1. **Import the Official OVA**:
   - Download the Wazuh all-in-one virtual appliance.
   - Import into VirtualBox with **Bridged Adapter** or **NAT Network** with Tailscale enabled.
2. **Rotate Default Credentials**:
   ```bash
   tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
   /var/ossec/bin/wazuh-control restart
   ```
3. **Join Tailscale Mesh**:
   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up --accept-routes
   ```
   Note the assigned `100.x.x.10` address.

---

## 3. Tailscale Mesh Network Configuration

1. Log in to the [Tailscale Admin Console](https://login.tailscale.com/admin).
2. Generate an **Invite Link** or Auth Key for team members.
3. Verify all 5 node endpoints appear in the tailnet:
   - `wazuh-manager` (`100.64.0.10`)
   - `ubuntu-victim` (`100.64.0.11`)
   - `win11-victim` (`100.64.0.12`)
   - `win2022-srv` (`100.64.0.13`)
   - `shuffle-soar` (`100.64.0.14`)
4. Keep key-expiry policy appropriate to each device. Disabling expiry can reduce security; only consider it for a trusted, unattended lab server when uptime requires it, and document the trade-off. Leave expiry enabled for human-operated devices. See [Tailscale key expiry](https://tailscale.com/docs/features/access-control/key-expiry).

---

## 4. Wazuh Agent Enrollment

### Linux (Ubuntu Server)
```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.4-1_amd64.deb
sudo WAZUH_MANAGER='100.64.0.10' WAZUH_AGENT_NAME='mohamedmassoud' dpkg -i wazuh-agent_4.14.4-1_amd64.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### Windows (11 & Server 2022)
Open an elevated PowerShell prompt:
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.4-1.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='100.64.0.10' WAZUH_AGENT_NAME='karim' WAZUH_REGISTRATION_SERVER='100.64.0.10'
NET START Wazuh
```

---

## 5. Shuffle SOAR Deployment (Docker)

1. Clone the Shuffle repository and launch with Docker Compose:
   ```bash
   git clone https://github.com/Shuffle/Shuffle.git
   cd Shuffle
   docker compose up -d
   ```
2. Access Shuffle at `http://100.64.0.14:3001`.
3. Create an admin account and import [`configs/shuffle/soc_automated_response_workflow.json`](../configs/shuffle/soc_automated_response_workflow.json).
4. Configure environment variables in Shuffle:
   - `VIRUSTOTAL_API_KEY`: Your VirusTotal API Key.
   - `WAZUH_API_CREDENTIALS`: `wazuh-wui:password` (Base64 encoded).

Store real values only in Shuffle's local secret/configuration mechanism. The example above is a placeholder; never commit credentials, tokens, generated webhook URLs, or screenshots containing them.

---

## 6. Configuring the Wazuh-to-Shuffle Webhook

Edit `/var/ossec/etc/ossec.conf` on the Wazuh Manager:

```xml
<integration>
  <name>custom-shuffle</name>
  <hook_url>http://100.64.0.14:3001/api/v1/hooks/webhook_wazuh_alerts</hook_url>
  <level>6</level>
  <rule_id>5763,91837,92650,67027</rule_id>
  <alert_format>json</alert_format>
</integration>
```

Restart the Wazuh Manager daemon:
```bash
sudo systemctl restart wazuh-manager
```

Verify webhook transmission by monitoring `/var/ossec/logs/ossec.log`:
```bash
tail -f /var/ossec/logs/ossec.log | grep -i custom-shuffle
```
