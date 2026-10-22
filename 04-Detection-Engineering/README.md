# LAB-04 — Detection Engineering: Wazuh Rule 100201

## Objective

Create an intentionally low-severity alert for a **controlled, benign Notepad process creation** so that the entire Sysmon → Windows agent → Wazuh manager → Threat Hunting pipeline can be tested.

## Original deployed rule

[**lab04_notepad_rules.xml — authentic exported rule**](lab04_notepad_rules.xml)

The XML file in this repository was copied from the active Wazuh manager at `/var/ossec/etc/rules/lab04_notepad_rules.xml` to the Ubuntu `socadmin` home directory, transferred to the host with SCP, and checked in Windows PowerShell (`Test-Path` and `Get-Content`). The transfer was confirmed before the first Git commit.

| Field | Implementation |
| --- | --- |
| Parent rule | `61603` — built-in Sysmon Event ID 1 process creation (level 0) |
| Child custom rule | `100201` — level 3 |
| Match field | `win.eventdata.image` |
| Match expression | `(?i)\\notepad\.exe$` (PCRE2, case insensitive, path ending in `\notepad.exe`) |
| Wazuh rule group | `lab04_process_test` |
| Test execution | `Start-Process notepad.exe` on `WL-WIN11-01` |
| Wazuh output | Exactly one matching custom-rule alert was observed in the validation search |
| Source corroboration | Sysmon Event `1`, Record `1536`; user `WL-WIN11-01\labadmin`; parent `powershell.exe` |

## Validation performed

1. Authored the child XML rule and checked parsing with `sudo /var/ossec/bin/wazuh-analysisd -t` (exit code 0).
2. Confirmed `wazuh-manager` was active after loading the updated rule.
3. Ran the benign test process on `WL-WIN11-01`.
4. Searched Threat Hunting for `rule.id: "100201"` and inspected the resulting alert.
5. Queried the original Windows Sysmon event by `EventRecordID=1536` and correlated image, parent, account, PID and timestamp.

[Custom-rule alert screenshot](../05-Evidence/SOC-003/Wazuh-rule-100201-alert.png) · [Original Sysmon record](../05-Evidence/SOC-003/Windows-Sysmon-event-1536-PowerShell.png) · [Investigation report](../03-SOC-Investigations/SOC-003-Process-Detection/investigation-report.md)

## Detection quality limitation

This deliberately broad, benign rule tests **collection and rule firing**. It is not a high-fidelity production security detection, and Notepad execution is not itself malicious. Production detections require stronger behavioral context, alert tuning, and severity evaluation. This repository demonstrates rule creation and validation rather than production-scale tuning metrics.

[Return to project README](../README.md)
