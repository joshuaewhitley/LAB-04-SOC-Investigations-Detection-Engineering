# LAB-04 — SIEM Collection and Verification

## Collection pipeline

`WL-WIN11-01` (Windows events) → **Wazuh Windows Agent 001** → `WL-SIEM01` (manager/rules) → **Wazuh Threat Hunting**.

The monitored endpoint was running Wazuh Agent `4.14.9`. The agent connected to `10.10.10.20:1514/tcp` and its `ossec.log` confirmed that each required Windows event channel was initialized. We later observed corresponding alerts in Threat Hunting.

## Windows agent configuration

The relevant agent settings are in `C:\Program Files (x86)\ossec-agent\ossec.conf` on `WL-WIN11-01`. The following represents the **event-channel collection blocks**, not a complete `ossec.conf` or the full Wazuh platform configuration:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

The Security channel was already present as part of the agent setup. Sysmon and Defender channels were confirmed in the agent configuration during the lab. These example blocks omit the other agent settings and any environment-specific secrets.

## Validation method

1. Verified Windows 11 network connectivity to Wazuh TCP ports `1514` and `1515` prior to enrollment.
2. Confirmed Agent `001`, `WL-WIN11-01`, appeared **Active** in the Wazuh dashboard.
3. Checked Windows agent `ossec.log` for `Analyzing event log` entries for the Security, Sysmon and Microsoft Defender channels.
4. Validated real matching event evidence, rather than relying solely on a successful agent connection:
   - **Security 4624/4625:** Wazuh and local Windows events matched for records `23313` and `23498`.
   - **Sysmon Event 1:** custom Rule `100201` and source Record `1536` matched after a controlled Notepad launch.
   - **Defender Events 1116/1117:** Wazuh Rules `62123` / `62124` matched source records `376` / `378` during an EICAR test.

## Operational troubleshooting lessons

- **DNS matters for domain access:** verify the endpoint uses the domain controller as DNS before diagnosing domain-join failures.
- **Collected telemetry versus alerting:** a log can be collected but not appear in Threat Hunting if it doesn't meet an alerting rule (or the underlying alert isn't indexed for that query).
- **Rule syntax isn't enough:** `wazuh-analysisd -t` passing is helpful, but a rule should also be tested against controlled source events.
- **Time interpretation matters:** Wazuh records contain UTC timestamps while Windows tools may render the same events in local Pacific time.

## Security boundaries

The documentation intentionally excludes live passwords, agent enrollment keys, API tokens, or complete secret-bearing configuration. Microsoft Defender integration here is **Defender Antivirus event collection**, not evidence of licensed Defender for Endpoint EDR.

[Return to project README](../README.md) · [Original custom rule](../04-Detection-Engineering/lab04_notepad_rules.xml)
