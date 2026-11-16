# Distributed SOC & SOAR Lab Architecture

A comprehensive technical overview of the distributed, multi-cloud, multi-OS security operations and automated response architecture.

---

## 1. Executive Summary

This security operations lab implements an enterprise-grade, open-source **SIEM + SOAR + Zero-Trust Mesh** detection and response pipeline across 5 physically separated network environments. By utilizing **Tailscale** as an encrypted WireGuard mesh VPN, endpoints across different geographical locations communicate over a flat `100.x` private subnet without requiring port-forwarding or exposing services to the public internet.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               TAILSCALE ZERO-TRUST TAILNET (100.x)                     │
├───────────────────┬───────────────────┬───────────────────┬────────────────────────────┤
│  Ubuntu 24.04     │  Windows 11       │  Win Server 2022  │  Wazuh Manager (OVA 4.14)  │
│  (M. Massoud)     │  (Karim)          │  (M. Bushnak)     │  (Mohamed Sabry)           │
│  Agent: 100.64.0.11│ Agent: 100.64.0.12│ Agent: 100.64.0.13│  Manager: 100.64.0.10      │
└─────────┬─────────┴─────────┬─────────┴─────────┬─────────┴──────────────┬─────────────┘
          │                   │                   │                        │
          └───────────────────┴───────────────────┴───────────────┐        │ Webhook Alerts
                                                                  │        ▼
                                                       ┌───────────────────────────────┐
                                                       │  Shuffle SOAR Engine (Docker) │
                                                       │  (Omar Khaled)                │
                                                       │  Host: 100.64.0.14            │
                                                       └───────────────┬───────────────┘
                                                                       │
                                                       ┌───────────────┴───────────────┐
                                                       │                               │
                                                       ▼                               ▼
                                            ┌────────────────────┐          ┌────────────────────┐
                                            │ VirusTotal API v3  │          │ Wazuh JWT Callback │
                                            │ Threat Intel       │          │ Active Response    │
                                            └────────────────────┘          └────────────────────┘
```

---

## 2. Distributed Node & Role Breakdown

| Node ID | Hostname / OS | Lab Role | Contributor | IP Address (Tailnet) | Primary Workload |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Node 01** | `wazuh-manager` / Linux | **SIEM Manager** | **Mohamed Sabry** ([@0xsabry](https://github.com/0xsabry)) | `100.64.0.10` | Log correlation, rule decoders, API daemon, active-response orchestrator |
| **Node 02** | `shuffle-soar` / Linux (Docker) | **SOAR Engine** | **Omar Khaled** | `100.64.0.14` | Webhook ingestion, decision trees, VT enrichment, authenticated callbacks |
| **Node 03** | `ubuntu-victim` / Ubuntu 24.04 | **SSH Target** | **Mohamed Massoud** | `100.64.0.11` | Wazuh Linux agent, auditd, sshd brute-force detection & iptables containment |
| **Node 04** | `win11-victim` / Windows 11 | **PowerShell Target** | **Karim** | `100.64.0.12` | Wazuh Windows agent, Sysmon, PowerShell script block logs, netsh isolation |
| **Node 05** | `win2022-srv` / Server 2022 | **C2 Target** | **Mohamed Bushnak** | `100.64.0.13` | Wazuh Windows agent, Service Manager events, PsExec remote execution target |

---

## 3. Network Isolation & Security Model

1. **Zero-Exposure Ingress**: All victim endpoints and SIEM/SOAR nodes are isolated from direct WAN traffic. Inbound communication only occurs via peer-to-peer authenticated WireGuard tunnels managed by Tailscale.
2. **Attacker Machine Isolation**: Attacker machines (Kali Linux and simulated external attacker scripts) operate strictly on local subnets outside the Tailscale mesh to replicate authentic external breach attempts.
3. **Strict Device Authorization**: Every node attempting to join the tailnet requires manual owner approval from the Tailscale Admin Console before routing permissions are granted.

---

## 4. SIEM & SOAR Integration Architecture

The interaction between Wazuh SIEM and Shuffle SOAR operates in a closed loop:

1. **Ingestion & Correlation**: Agents ship encrypted OSSEC events to the Wazuh Manager on port `1514/TCP`.
2. **Rule Escalation**: When event thresholds exceed defined severity levels (e.g. repeated SSH auth failures or suspicious PowerShell execution), Wazuh triggers an alert.
3. **Webhook Dispatch**: The `ossec-integratord` daemon constructs a JSON payload containing full alert context (Rule ID, Source IP, Agent ID, Full Command Line) and posts it over HTTP/HTTPS to Shuffle's webhook URL (`http://100.64.0.14:3001/api/v1/hooks/...`).
4. **SOAR Orchestration**:
   - Parses JSON fields.
   - Evaluates branch conditions (Rule 100003 vs Rule 100004 vs Rule 100006).
   - Queries VirusTotal API v3 for IOC reputation.
   - Obtains a short-lived JWT token from Wazuh REST API (`/security/user/authenticate`).
   - Executes Active Response via `/active-response` endpoint.
5. **Host Containment**: The Wazuh agent receives the containment instruction and executes native firewall rules (`iptables` on Linux, `netsh` on Windows) within milliseconds.
