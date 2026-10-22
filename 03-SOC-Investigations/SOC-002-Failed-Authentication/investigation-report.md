# SOC-002 — Failed Authentication Investigation

**LAB-04 · Case status:** Closed — controlled authentication failure  
**Endpoint:** `WL-WIN11-01.corp.whitleylab.test`  
**Event date:** October 20, 2026 (Pacific Daylight Time)  
**Monitoring sources:** Windows Security log; Wazuh Agent 001

## Executive summary
A failed interactive logon involving the local `labadmin` account was examined during an authorized training exercise. Windows recorded Event ID 4625, and Wazuh generated a matching failed-logon alert. The original event record was retrieved on the endpoint and correlated to the SIEM payload by **EventRecordID 23498**, time, account and failure codes. **Disposition: expected failed authentication during the controlled exercise; no compromise demonstrated.**

## Detection and Windows evidence
| Field | Observed value |
| --- | --- |
| Windows Event ID / Record ID | **4625 / 23498** |
| Time | **October 20, 2026, 1:44:24 PM PDT** |
| Target identity | `WL-WIN11-01\labadmin` |
| Logon type | **2 — Interactive** |
| Status | `0xC000006D` — unsuccessful logon |
| Substatus | `0xC000006A` — incorrect password |
| Source address / port | `127.0.0.1` / `0` |
| Process | `C:\Windows\System32\svchost.exe` |
| Wazuh rule description | `Logon Failure - Unknown user or bad password` |
| Wazuh severity | **Level 5** |
| Wazuh event UTC time | `2026-10-20T20:44:24.902Z` |

## Investigation sequence
1. Verified `auditpol /get /subcategory:"Logon"` reported **Success and Failure**.
2. Attempted controlled `runas` authentication; earlier attempts returned **“Unable to acquire user password”**, not proof of an incorrect-password authentication. Those attempts were not treated as successful test evidence.
3. During the subsequent controlled sign-in exercise, Event Viewer showed a failed interactive logon for `labadmin`.
4. Opened the Wazuh failure alert and inspected decoded event fields, including `eventRecordID`, account, status and substatus.
5. Independently queried the original Windows Security log for record **23498**. The record, timestamp and authentication fields matched the indexed Wazuh event.

### Read-only verification command
```powershell
Get-WinEvent -LogName Security -FilterXPath '*[System[EventRecordID=23498]]' |
    Format-List TimeCreated, Id, RecordId, Message
```

## Findings and disposition
Substatus `0xC000006A` supports a **bad password**, not an unknown username. Logon Type 2 indicates an interactive local logon context. The `127.0.0.1` source address is loopback and does not support an external network-origin claim. Windows and Wazuh independently recorded the same failed authentication.

**Conclusion:** Expected lab test behavior. A single unsuccessful login does not, by itself, establish password spraying, brute force, or account compromise. No containment action was necessary.

**Limitations:** The precise user-interface interaction that produced Record 23498 was not separately recorded on video. This was not a full correlation against domain-controller Kerberos logs. The supplied event and timeline support the test interpretation without proving a larger attack pattern.

## Supporting screenshots
- [Event Viewer 4625 properties](../../05-Evidence/SOC-002/Windows-event-4625-properties.png)
- [Wazuh failure event fields — part A](../../05-Evidence/SOC-002/Wazuh-event-4625-details-a.png)
- [Wazuh failure event fields — part B](../../05-Evidence/SOC-002/Wazuh-event-4625-details-b.png)
- [Original Windows record 23498](../../05-Evidence/SOC-002/Windows-event-23498-PowerShell.png)

## Closure
**Case closed — expected failed sign-in.** Maintain the lab alert and event artifacts as proof of endpoint logging and SIEM correlation.
