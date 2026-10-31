# Lab Setup

## Network

| Item | Value |
| --- | --- |
| Hypervisor | VirtualBox 7 |
| Network | NAT Network `SOCLab`, `10.0.50.0/24`, gateway `10.0.50.1` |
| wazuh-server | `10.0.50.5` (static) |
| WIN11-LAB | `10.0.50.7` (DHCP), hostname DESKTOP-LFHITGA |
| Dashboard | `https://127.0.0.1:8443`, port-forwarded to `10.0.50.5:443` |

## Wazuh server

- Ubuntu Server 26.04 LTS, 6 GB RAM, 2 vCPU, 50 GB disk (no LVM)
- Wazuh 4.14.9 all-in-one, installed with the official installation assistant (`wazuh-install.sh -a`)
- Static IP set with netplan: see [configs/netplan-static-ip.yaml](configs/netplan-static-ip.yaml)

## Windows endpoint

- Windows 11 Enterprise evaluation, 4 GB RAM, 2 vCPU, 64 GB disk, EFI + TPM 2.0
- Sysmon with the SwiftOnSecurity config
- Group Policy: PowerShell Script Block Logging and Module Logging (`*`) enabled
- Wazuh agent 4.14.9, with Sysmon and PowerShell channels added: see [configs/ossec-localfile-snippet.xml](configs/ossec-localfile-snippet.xml)

## Attack simulation

Invoke-AtomicRedTeam, installed to `C:\AtomicRedTeam`.

| Technique | Test | Time run (AEDT) |
| --- | --- | --- |
| T1087.001 Account Discovery | 8: Enumerate all accounts on Windows | 30 Oct 2026, 11:59 |
| T1136.001 Create Local Account | 8: Create a new Windows admin user | 31 Oct 2026, 20:28 |
| T1053.005 Scheduled Task | 2: Scheduled task Local | 31 Oct 2026, 20:43 |

## Problems I hit and how I fixed them

| Problem | Cause | Fix |
| --- | --- | --- |
| Wazuh installer refused to run | VM had 3.3 GB usable RAM, under the 4 GB minimum | Raised the VM to 6 GB |
| Kernel "soft lockup" and "RCU stall" messages | VM starved of CPU by the host | Ran fewer VMs at once and closed host apps |
| Both VMs lost their IP addresses | VirtualBox's NAT Network service (`VBoxNetNAT.exe`) had crashed | Restarted the VirtualBox services |
| Dashboard unreachable after reboot | Server's DHCP lease failed | Set a static IP with netplan |
| Atomic Red Team installer blocked | Defender's AMSI flagged the in-memory install script | Temporarily disabled real-time protection in the lab VM |
| Agent service error 1067 on first start | Agent started before the MSI finished installing | Waited and started it again |
