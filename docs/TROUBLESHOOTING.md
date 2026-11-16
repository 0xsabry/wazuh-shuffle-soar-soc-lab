# Troubleshooting the Wazuh-to-Shuffle Lab

Use this runbook to isolate failures one boundary at a time. It covers the documented lab flow; it does not assert that a fresh checkout has live infrastructure or that offline repository checks validate integrations.

## Before investigating

- Record the Wazuh/agent versions, affected node, approximate timestamp, and the last stage that worked.
- Use a sanitized event and redact usernames, public IPs, tokens, webhook URLs, and other organization-specific data before sharing logs.
- Run attack simulations and active-response checks only on endpoints you own or are explicitly authorized to test. Start with an isolated test endpoint and have a recovery path before testing containment.

## Follow the event path

| Symptom | Check | What the result tells you |
| --- | --- | --- |
| A node cannot reach the manager | On both nodes, inspect `tailscale status`; from the endpoint run `tailscale ping <manager-tailnet-IP>`. | If the peer is absent or unreachable, check device approval, the tailnet access policy, and whether both nodes are online before investigating Wazuh. Do not expose manager ports to the public Internet to work around a tailnet issue. |
| The endpoint is not connected to Wazuh | On Linux, run `sudo systemctl status wazuh-agent`. On Windows PowerShell, run `Get-Service Wazuh`. On the manager, run `sudo /var/ossec/bin/agent_control -l`. | A service can be running while the agent is disconnected. Check the manager address and registration settings from the setup guide, then inspect the agent's `ossec.log` for connection or enrollment errors. |
| The agent is active, but the expected event is missing | Confirm the relevant log source or Windows Event Channel is enabled in the agent configuration. Check the agent and manager logs around the recorded timestamp. | This separates collection and forwarding problems from decoder or rule problems. An active agent does not prove that every requested log source is configured. |
| The event arrives, but the expected rule does not match | On the manager, run `/var/ossec/bin/wazuh-logtest` and paste a sanitized raw event. Inspect Phase 1, Phase 2, and Phase 3. | Phase 2 shows the decoded field names and values; Phase 3 shows the matching rule. If a rule depends on fields, confirm those fields are present exactly as expected. For correlation, feed the relevant events in order in the same logtest session. |
| The rule matches, but Shuffle receives nothing | Check the `<integration>` stanza in the manager's `ossec.conf` (`name`, `hook_url`, `level`, `rule_id`, and `alert_format`) and inspect `/var/ossec/logs/ossec.log` for `custom-shuffle` errors. | The configured level and rule filter determine which alerts are sent. Fix a dispatch error before changing the playbook. Keep the real hook URL private. |
| Shuffle starts, but later nodes fail | Open that execution in Shuffle and inspect the input and output at each node, starting with the webhook trigger and JSON parser. Compare the parsed keys with the sample payload in [SOAR Playbooks](SOAR_PLAYBOOKS.md). | This identifies whether the problem is the incoming event shape, branch condition, enrichment, API authentication, or response request. Do not share raw alerts or credential-bearing node output publicly. |
| VirusTotal enrichment fails | Confirm the workflow receives the expected indicator, then inspect the action's sanitized status/error and service quota. Verify the API key is configured locally in Shuffle. | A missing indicator, rejected credential, network failure, or rate limit are different failure classes. Never paste the key into a workflow committed to this repository or into logs/issues. |
| Active response fails or containment is unsafe | Inspect the failed workflow node and the Wazuh API response. Confirm the selected agent and response command in the lab configuration. | Test only on an isolated, disposable endpoint. Containment can interrupt the route you need for recovery; do not test it against production or your only management path. |

## Keep the investigation reproducible

For a useful bug report, include the versions, the failing stage, a sanitized event or config excerpt, the relevant error, and what you expected versus observed. Do not include API keys, passwords, JWTs, live webhook URLs, or unredacted endpoint data. See the [safe lab contribution guidance](../CONTRIBUTING.md) before sharing attack-simulation details.

The repository's `scripts/validate_lab_assets.py` and unit tests check committed XML/JSON/SVG structure offline. They do not connect to Tailscale, Wazuh, Shuffle, VirusTotal, or an endpoint, and they cannot verify detection or containment behavior.

## Related guides

- [Lab setup](LAB_SETUP_GUIDE.md)
- [Detection engineering](DETECTION_ENGINEERING.md)
- [Attack scenarios](ATTACK_SCENARIOS.md)
- [SOAR playbooks and payload shape](SOAR_PLAYBOOKS.md)
- [Architecture](ARCHITECTURE.md)

## References

- [Wazuh agent connection](https://documentation.wazuh.com/4.14/user-manual/agent/agent-management/agent-connection.html)
- [Testing Wazuh decoders and rules](https://documentation.wazuh.com/4.14/user-manual/ruleset/testing.html)
- [Tailscale key expiry](https://tailscale.com/docs/features/access-control/key-expiry)
