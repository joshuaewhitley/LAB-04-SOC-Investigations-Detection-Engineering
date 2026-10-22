# Evidence index and pre-publication review

These PNG files are **copies of screenshots supplied during the LAB-04 session**, organized by case. File names have been made descriptive; their image contents were not altered.

| Case | Evidence emphasis |
| --- | --- |
| SOC-001 | Wazuh RDP-related alert + original Windows Event 4624, Record 23313 |
| SOC-002 | Wazuh authentication-failure alert + original Event 4625, Record 23498 |
| SOC-003 | Rule 100201 custom alert + original Sysmon Record 1536; additional level-12 `sdbinst.exe` triage |
| SOC-004 | Defender detection/quarantine events 1116/1117 and Wazuh rules 62123/62124 |

## Before putting this repository on GitHub
1. **Personally open every screenshot**. Confirm no password-manager popups, email addresses, passwords, recovery keys, enrollment secrets or access tokens are visible. Blur or omit any image that contains them.
2. The screenshots expose lab hostnames, usernames and private IP addresses. These are not public IPs, but consider whether you wish to disclose your lab topology.
3. The screenshot collection is an informal lab evidence archive: **no formal chain-of-custody procedures or cryptographic evidence-manifest hashes are claimed**.
4. Screenshots were captured across multiple windows and not all views prove every field; match each report to its corresponding source record before publication.
5. Publishing this package does not publish or restore a Defender-quarantined EICAR artifact. **Do not upload antivirus test strings or executable test files.**
