# Alert: New local account created and added to Administrators

**Rules:** 92040 (level 12), 60109 (level 8), 60110 (level 8), 60170 (level 5), 60160 (level 5), 60154 (level 12)
**Time:** 31 Oct 2026, 20:28:43–20:28:47 AEDT (09:28:43–09:28:47 UTC)
**Host:** DESKTOP-LFHITGA (Wazuh agent WIN11-LAB, 10.0.50.7)
**User:** labadmin (SID ending -1001), logon ID `0x4a525`
**MITRE ATT&CK:** T1136.001 Create Account: Local Account, T1098.007 Account Manipulation: Additional Local or Domain Groups

## What fired

Within four seconds, a process created a new local account called `T1136.001_Admin` and added it to the built-in Administrators group. Two of the alerts were level 12, and Wazuh raised six alerts in total across Sysmon and the Windows Security log.

## Investigation

**Process evidence (Sysmon event 1, rule 92040)**

| Field | Value |
| --- | --- |
| Command line | `net1 user /add "T1136.001_Admin" "T1136_pass"` |
| Image | `C:\Windows\System32\net1.exe` |
| Parent | `net.exe`, launched by `cmd.exe` (rule 92036) |
| Integrity level | High (running with admin rights) |
| Working directory | `C:\Users\labadmin\AppData\Local\Temp\` |
| SHA256 | `8489DB35375D890314EB8F7CD9E0CBD3866475F4E252865F00F649B0A02FD757` (legitimate Microsoft `net1.exe`) |

**Account evidence (Windows Security log)**

| Event | Rule | What it shows |
| --- | --- | --- |
| 4720 / 4722 | 60109 | New account created and enabled |
| 4738 | 60110 | Account properties changed |
| 4732 | 60154 | Account (SID ending -1002) added to Administrators (S-1-5-32-544), record 20897 |

**Correlation**

- The Sysmon process event and the Security log group change share logon ID `0x4a525`, so both actions came from the same logon session.
- The same session later created a scheduled task named `spawn` (`schtasks /Create /SC ONCE /TN spawn /TR cmd.exe`) at 20:43 AEDT. That's a second persistence mechanism.
- The command ran from a Temp folder, which is unusual for legitimate admin work.
- The new account's password, `T1136_pass`, is visible in plain text in the command line.

**Context checked**

- [ ] Change ticket or approved request for a new admin account: none (lab)
- [ ] Is `T1136.001_Admin` a naming convention used by IT? No
- [ ] Logons by the new account since creation: [check event 4624 for SID -1002]

## Verdict

**True positive.** The deciding evidence is a new account added straight to Administrators from a Temp-folder command line, followed in the same session by a scheduled task. Together these are a persistence pattern, not routine administration.

## Action

**Escalated.** See `escalation/escalation-note.md`.

## Lessons

- Correlating the logon ID across Sysmon and the Security log turned two separate alerts into one story.
- Command-line logging captured a cleartext password. Logs like this hold credentials and need access controls.

## Evidence

- `screenshots/01-alert-list.png`: the alert sequence in Threat Hunting
- `screenshots/01-92040-details.png`: process details
- `screenshots/01-60154-details.png`: group membership change
