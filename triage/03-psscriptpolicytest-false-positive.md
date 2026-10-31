# Alert: PowerShell created an executable file in a Windows root folder

**Rule:** 92205 (level 9), fired twice
**Time:** 31 Oct 2026, 20:41:11 and 20:41:17 AEDT (09:41 UTC)
**Host:** DESKTOP-LFHITGA (Wazuh agent WIN11-LAB, 10.0.50.7)
**User:** NT AUTHORITY\SYSTEM
**MITRE ATT&CK:** Mapped by the rule to file-based execution; not applicable after investigation

## What fired

Sysmon logged PowerShell writing a `.ps1` script file inside `C:\Windows`. Wazuh treats that as a dropped executable and alerts at level 9.

## Investigation

**File evidence (Sysmon event 11)**

| Field | Value |
| --- | --- |
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Process ID | 5916 |
| User | NT AUTHORITY\SYSTEM |
| Target file | `C:\Windows\SystemTemp\__PSScriptPolicyTest_12msnxiq.i0c.ps1` |
| Created (UTC) | 2026-10-31 09:41:16.499 |

**Analysis**

- PowerShell creates `__PSScriptPolicyTest_<random>.ps1` files itself when it starts, to test whether script policies such as AppLocker allow scripts to run. It then deletes them.
- The file is in a temp folder, not the Windows root itself, and it's owned by a SYSTEM PowerShell process.
- No network connections, child processes or persistence followed from this process.

## Verdict

**False positive.** This is normal PowerShell startup behaviour. The deciding evidence is the `__PSScriptPolicyTest_` filename pattern, created and owned by a SYSTEM PowerShell process.

## Action

**Tuning proposed.** This is a child rule for `/var/ossec/etc/rules/local_rules.xml` that drops the alert to level 0 only for this exact pattern:

```xml
<group name="local,sysmon,">
  <rule id="100100" level="0">
    <if_sid>92205</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
    <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\(SystemTemp|Temp)\\__PSScriptPolicyTest_[a-z0-9]+\.[a-z0-9]+\.ps1$</field>
    <description>Suppress benign PowerShell __PSScriptPolicyTest file creation</description>
  </rule>
</group>
```

Apply it with `sudo systemctl restart wazuh-manager`, then confirm the alert stops while other 92205 alerts still fire.

**Residual risk:** an attacker could name a malicious file to match this pattern. The rule limits that risk by requiring the creating process to be `powershell.exe`, the file to be in a temp folder, and the exact random-name format.

## Lessons

- A rule that looks only at the folder and file type, with no other context, generates noise from normal Windows behaviour.
- Tuning should be as narrow as possible: suppress the known-benign pattern, not the whole rule.

## Evidence

- `screenshots/03-92205-details.png`
