# LAB-04 — Custom Wazuh Rule 100201

## Purpose
Create a **Level 3, intentionally benign** alert when Sysmon records a Notepad process start, so the Windows endpoint → Wazuh ingestion → manager detection → Threat Hunting pipeline can be validated.

- Parent Wazuh rule: `61603` (Sysmon Event 1, Level 0)
- Child rule: `100201` (Level 3)
- Target: `win.eventdata.image` ending in `\notepad.exe` (PCRE2, case insensitive)
- Saved on SIEM at `/var/ossec/etc/rules/lab04_notepad_rules.xml`
- Local rule validation: `/var/ossec/bin/wazuh-analysisd -t` returned exit code `0`
- Live validation: `Start-Process notepad.exe` generated an alert for Rule 100201
- Correlated source: Sysmon Event ID 1, Record ID 1536, October 21, 2026, 8:06:59 AM PDT

**Publishing note:** The example XML in this folder is reconstructed from the screenshot of the Nano editor, *not independently copied from the current SIEM configuration*. Export and review the live `/var/ossec/etc/rules/lab04_notepad_rules.xml` before publishing it as the actual deployed rule.

## Export the authentic rule from Windows host
```powershell
scp socadmin@10.10.10.20:/var/ossec/etc/rules/lab04_notepad_rules.xml "C:\CyberLab\LAB-04-Portfolio\04-Detection-Engineering\lab04_notepad_rules.xml"
```
If permissions block the read, use SSH with `sudo cat` and securely copy the output through an appropriate method. Keep passwords and credentials out of GitHub.

## Test again if needed
```powershell
Start-Process notepad.exe
```
Search Wazuh Threat Hunting with `rule.id: "100201"`. Inspect the matching alert and correlate `data.win.system.eventRecordID` to local Sysmon Event ID 1.

**Scope:** This rule is test instrumentation, not proof Notepad is suspicious. It would be noisy in production without additional tuning.
