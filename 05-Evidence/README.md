# LAB-04 — Evidence Index

These are **25 screenshots** captured during four authorized SOC lab investigations, grouped by case. The images record Windows and Wazuh alert details, local validation commands and the evidence correlation process.

| Case | Count | Primary evidence |
| --- | ---: | --- |
| [SOC-001](../03-SOC-Investigations/SOC-001-Remote-Logon/investigation-report.md) | 3 | Wazuh 92653; Security 4624 and record 23313 |
| [SOC-002](../03-SOC-Investigations/SOC-002-Failed-Authentication/investigation-report.md) | 4 | Security 4625 and record 23498; failed password fields |
| [SOC-003](../03-SOC-Investigations/SOC-003-Process-Detection/investigation-report.md) | 9 | Rule 100201; Sysmon record 1536; `sdbinst.exe` triage |
| [SOC-004](../03-SOC-Investigations/SOC-004-Defender-Response/investigation-report.md) | 9 | Defender 1116/1117; Wazuh 62123/62124; quarantine |

## Evidence interpretation and handling

- Every screenshot was visually reviewed before initial publication for visibly exposed credentials, password-manager popups, personal data and production-system context.
- Screenshots show fictional lab hostnames, local usernames and RFC 1918 private IP addresses to preserve the technical event context.
- The images are copies of material captured during the exercises; no formal digital-forensic chain of custody or cryptographic evidence integrity manifest is claimed.
- The case reports distinguish directly observed fields from analyst assessments and explicit limitations. A single screenshot may illustrate only part of an event; consult the linked report and related images.
- The harmless EICAR test file itself is **not** included. Do not publish live API keys, agent enrollment secrets, passwords or antivirus test samples as artifacts.

[Return to project README](../README.md)
