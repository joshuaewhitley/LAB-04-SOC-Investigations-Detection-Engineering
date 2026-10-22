# SOC-001 — Remote Interactive Logon Investigation

**LAB-04 · Case status:** Closed — expected administrative activity  
**Endpoint:** `WL-WIN11-01.corp.whitleylab.test`  
**Event date:** October 20, 2026 (Pacific Daylight Time)  
**Monitoring sources:** Windows Security log; Wazuh Agent 001 (`10.10.10.30`)

## Executive summary
Wazuh reported a successful remote-interactive logon involving the lab's local `labadmin` account. The alert was traced to its original Windows Security event. The workstation was being accessed through Hyper-V's Enhanced Session Mode, which was confirmed enabled, and the lab operator confirmed being connected to the VM around the event's timestamp. **Disposition: expected, authorized lab administration.** This evidence does not establish any external intrusion.

## Trigger and investigation question
- **Wazuh rule:** `92653`, severity level **3**.
- **Rule description:** Remote Desktop Connection (RDP)-related logon.
- **Investigation question:** Was the remote-interactive authentication expected administration or an unauthorized session?
- **Initial limitation:** The recorded source IP was `0.0.0.0`, not a usable origin indicator.

## Source evidence
| Field | Observed value |
| --- | --- |
| Windows provider/channel | Microsoft-Windows-Security-Auditing / Security |
| Event ID / record | **4624 / 23313** |
| Event time | **October 20, 2026, 11:31:37 AM PDT** |
| Target identity | `WL-WIN11-01\labadmin` |
| Logon type | **10 — RemoteInteractive** |
| Source IP / port | `0.0.0.0` / `0` |
| Logon process | `User32` |
| Authentication package | `Negotiate` |
| Caller process | `C:\Windows\System32\svchost.exe` |

## Investigation workflow
1. Identified the Wazuh Rule 92653 alert under Threat Hunting for Agent 001.
2. Inspected the event payload rather than inferring account/source from the rule description.
3. Retrieved Windows Security **EventRecordID 23313** locally with `Get-WinEvent` and compared logon type, account, process and event time.
4. Checked Hyper-V Virtual Machine Connection: **Enhanced Session Mode was checked**.
5. Asked the operator to correlate the timestamp with their activity. The operator confirmed being connected to the Windows VM at that time.

### Read-only verification command
```powershell
Get-WinEvent -LogName Security -FilterXPath '*[System[EventRecordID=23313]]' |
    Format-List TimeCreated, Id, RecordId, Message
```

## Analyst assessment
Windows Event 4624 indicates a **successful** authentication; Logon Type 10 is remote-interactive. The user account, known lab activity, Enhanced Session setting, and operator confirmation support an authorized administrative explanation. This is a **benign-positive alert** in the context of the exercise; no containment was justified by the evidence reviewed.

**Limitations:** The source address `0.0.0.0` cannot identify the originating host, and enabling Enhanced Session Mode alone is not independent proof of session provenance. The conclusion relies partly on operator confirmation. This was not a formal forensic attribution or a review of all potential access paths.

## Supporting screenshots
- [Wazuh rule context](../../05-Evidence/SOC-001/Wazuh-rule-92653-details.png)
- [Wazuh event fields](../../05-Evidence/SOC-001/Wazuh-event-4624-fields.png)
- [Original Windows record 23313](../../05-Evidence/SOC-001/Windows-event-23313-PowerShell.png)

## Closure
**Case closed as authorized administration.** Preserve the lab screenshots; no account lockout, remote-session termination, or system isolation was indicated by this single corroborated event.
