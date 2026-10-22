# SOC-004 — Microsoft Defender Antivirus Detection and Response

**LAB-04 · Case status:** Closed — authorized antivirus-control validation  
**Endpoint:** `WL-WIN11-01.corp.whitleylab.test`  
**Test date:** October 21, 2026 (Pacific Daylight Time)  
**Monitoring path:** Defender Antivirus Operational log → Wazuh agent 001 → Threat Hunting

## Executive summary
An **EICAR harmless antivirus-test pattern** was written into `C:\Temp\lab04-eicar.com.txt` on an isolated Windows 11 VM. Microsoft Defender Antivirus detected it under real-time protection and reported a successful **Quarantine** protection action with error code `0x00000000` and no further action required. Wazuh generated a Level 12 detection alert and a Level 3 protection-action alert, both correlated with their source endpoint records. **Disposition: successful authorized security-control test, not a real infection.**

## Detection and response timeline
| Local timestamp (PDT) | Endpoint evidence | Wazuh evidence | Observation |
| --- | --- | --- | --- |
| **1:03:57 PM** | Defender **Event 1116**, **Record 376** | Rule **62123**, Level **12** | EICAR test pattern detected |
| **1:04:16 PM** | Defender **Event 1117**, **Record 378** | Rule **62124**, Level **3** | Quarantine reported successful |

The timestamps represent **recorded log events**, not a measured end-to-end response latency. The 1116 event's UTC time `2026-10-21T20:03:57.854Z` maps to the local detection time; Event 1117 has UTC time `2026-10-21T20:04:16.179Z`.

## Detailed event fields
| Field | Verified value |
| --- | --- |
| Detection | `Virus:DOS/EICAR_Test_File` |
| Defender threat identifier | `2147519003` |
| File | `C:\Temp\lab04-eicar.com.txt` |
| Source | Real-Time Protection |
| Defender severity | `Severe` (product category for test pattern) |
| Initiating process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Detection user | `WL-WIN11-01\labadmin` |
| Remediation user | `NT AUTHORITY\SYSTEM` |
| Protection action | **Quarantine** |
| Error code | `0x00000000` — operation completed successfully |
| Action result | No additional actions required |

## Analyst workflow
1. Confirmed Defender Antivirus service and real-time protection were enabled; Defender Operational log contained preexisting events.
2. Added `Microsoft-Windows-Windows Defender/Operational` as a Wazuh `eventchannel` source and verified agent startup logs showed channel initialization.
3. Validated Defender alerts were already being generated in Wazuh before the test.
4. Created the standard EICAR harmless file **without disabling antivirus**.
5. Retrieved and reviewed local Defender Events **1116** and **1117**, capturing detection details and the reported quarantine action.
6. Located the corresponding Wazuh alerts using Defender event-channel and Event ID filters; matched the detection and response record IDs, timestamps, threat ID/name, and action fields.
7. Re-ran `Get-WinEvent` queries for original endpoint **Record IDs 376 and 378** to independently verify the alert evidence.

### Read-only endpoint verification
```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' `
    -FilterXPath '*[System[EventRecordID=376]]' |
    Format-List TimeCreated, Id, RecordId, Message

Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' `
    -FilterXPath '*[System[EventRecordID=378]]' |
    Format-List TimeCreated, Id, RecordId, Message
```

## Findings and disposition
Defender's own Event 1117 reported that quarantine succeeded, and Wazuh preserved this action in its alert payload. This validates **endpoint detection, automated protection, event forwarding, centralized alerting, and evidence correlation** for the tested artifact.

**Limitations:** EICAR is a benign industry test string, not malware. No real persistence, lateral movement, recovery procedure, or manual containment was tested. No Microsoft Defender for Endpoint license, advanced EDR incident queue, or enterprise-wide policy was involved. “Severe” is Defender's classification of the test signature, not proof of operational impact.

## Supporting screenshots
- [Local Defender 1116/1117 events](../../05-Evidence/SOC-004/Defender-events-1116-1117-local.png)
- [Wazuh alerts 62123 and 62124](../../05-Evidence/SOC-004/Wazuh-Defender-alerts-62123-62124.png)
- [Wazuh Defender event 1116 / record 376](../../05-Evidence/SOC-004/Wazuh-1116-record-376-a.png)
- [Original Windows 1116 / record 376](../../05-Evidence/SOC-004/Windows-1116-record-376.png)
- [Wazuh 1117 protection action](../../05-Evidence/SOC-004/Wazuh-1117-record-378-a.png)
- [Wazuh 1117 record identifier](../../05-Evidence/SOC-004/Wazuh-1117-record-378-c.png)
- [Original Windows 1117 / record 378](../../05-Evidence/SOC-004/Windows-1117-record-378.png)

## Closure
**SOC-004 closed — successful authorized Defender antivirus-control test.** No actual malware infection or incident remediation claim is made.
