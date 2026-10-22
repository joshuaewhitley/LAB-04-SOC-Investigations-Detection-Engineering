# SOC-003 — Sysmon Process Detection & Custom Rule Validation

**LAB-04 · Case status:** Closed — custom detection validated  
**Endpoint:** `WL-WIN11-01.corp.whitleylab.test`  
**Event date:** October 21, 2026  
**Sources:** Sysmon Operational log → Wazuh Agent 001 → Wazuh detection rules

## Executive summary
A custom Wazuh rule detected a **benign, operator-initiated Notepad process** launched from PowerShell. The custom rule extended Wazuh's built-in Level 0 Sysmon process-creation rule and generated a Level 3 alert. The alert's original **Sysmon Event ID 1, Record ID 1536** was independently retrieved from the endpoint and matched by record identifier, timestamp, path, user and parent-child process details. **Disposition: authorized detection-engineering test; rule functioning as designed.**

## Rule design and validation
| Item | Value |
| --- | --- |
| Built-in parent rule | **61603**, Sysmon Event 1, Level 0 |
| Custom Wazuh rule | **100201**, Level 3 |
| Source field | `win.eventdata.image` |
| Condition | Case-insensitive executable path ending in `\notepad.exe` |
| Test command | `Start-Process notepad.exe` |
| Configuration test | `sudo /var/ossec/bin/wazuh-analysisd -t` — exit code `0` |
| Live test | Wazuh Threat Hunting returned **one** alert for `rule.id: "100201"` |

> **Source artifact:** The actual deployed rule was exported from `/var/ossec/etc/rules/lab04_notepad_rules.xml` on `WL-SIEM01`, copied to the Windows host and verified with `Get-Content` before Git publication. [View the exported rule](../../04-Detection-Engineering/lab04_notepad_rules.xml).

## Correlated process evidence
| Field | Verified value |
| --- | --- |
| Sysmon Event ID / Record ID | **1 / 1536** |
| Event time | **October 21, 2026, 8:06:59 AM PDT** (`15:06:59.854Z`) |
| Process | `Notepad.exe` in the WindowsApps package path |
| Process ID | **11436** |
| Parent executable | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Parent PID | **11828** |
| User | `WL-WIN11-01\labadmin` |
| Integrity | **High** (expected for elevated lab shell) |
| Detection | Wazuh custom Rule **100201**, Level 3 |

### Endpoint verification
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' `
    -FilterXPath '*[System[EventRecordID=1536]]' |
    Format-List TimeCreated, Id, RecordId, Message
```

## Analyst assessment
Sysmon documented a PowerShell parent process starting Notepad; Wazuh recognized that event using the operator-authored rule. Notepad is **not** classified as malware. This intentionally noisy, low-level rule was created as a verifiable lab sensor and is not a high-fidelity production detection. A production design would add context, suppression, and appropriate severity assignments.

## Additional triage: Wazuh level 12 `sdbinst.exe` alert
During SOC-003, Wazuh Rule **92058** flagged application-compatibility database installation activity. The original **Sysmon Event 1 / Record 567**, at **October 20, 2026, 5:59:15 PM PDT**, showed `C:\Windows\System32\sdbinst.exe` with command line `sdbinst.exe -m -bg`, parent `svchost.exe` associated with **PcaSvc**, and execution as `NT AUTHORITY\SYSTEM`.

The on-disk executable's Authenticode signature was **Valid — Microsoft Corporation**, and its SHA-256 matched the value recorded in Sysmon:

`1E19973DD638EFE37EA66554C3A8EEDFCF01F8136A29CDCB0C73AE162768180`

**Disposition:** Likely legitimate Windows compatibility activity, not confirmed malicious activity. The signature and hash corroborate identity of the inspected file at the time of review but do **not** alone establish intent or rule out abuse. Broader host timeline and compatibility-database artifact inspection were not performed. This is documented as a separate triage finding rather than relabeling the controlled Notepad test.

## Supporting screenshots
- [Custom rule detection in Wazuh](../../05-Evidence/SOC-003/Wazuh-rule-100201-alert.png)
- [Wazuh event 1536 fields](../../05-Evidence/SOC-003/Wazuh-Sysmon-event-1536-details.png)
- [Original Windows Sysmon record 1536](../../05-Evidence/SOC-003/Windows-Sysmon-event-1536-PowerShell.png)
- [Custom rule shown in Nano](../../05-Evidence/SOC-003/Wazuh-custom-rule-Nano.png)
- [sdbinst Wazuh fields](../../05-Evidence/SOC-003/Wazuh-rule-92058-process-details-a.png)
- [sdbinst original Sysmon record](../../05-Evidence/SOC-003/Windows-sdbinst-event-567-PowerShell.png)
- [Microsoft signature verification](../../05-Evidence/SOC-003/Windows-sdbinst-signature.png)
- [SHA-256 comparison](../../05-Evidence/SOC-003/Windows-sdbinst-SHA256.png)

## Closure
**SOC-003 custom detection validation complete.** Record IDs and process lineage were independently confirmed. The separate Level 12 compatibility alert is assessed as likely benign with stated limitations.
