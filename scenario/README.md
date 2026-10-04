# Investigation Scenario

## Overview

This project documents a controlled SOC investigation performed in a home lab using Splunk Enterprise, Sysmon and Windows Security telemetry.

The scenario was designed to simulate a suspicious sequence of activity on a Windows 11 endpoint. The objective was not simply to generate alerts, but to investigate them as a SOC analyst would: validate the initial detection, scope the activity, correlate multiple telemetry sources, reconstruct the sequence of events, assess the incident and perform remediation.

All activity was generated deliberately within an isolated lab environment. No malware or destructive payloads were used.

## Scenario

A Windows 11 endpoint generated multiple security alerts associated with suspicious PowerShell activity and local account creation.

The investigation began with an alert for PowerShell using an encoded command. Subsequent analysis identified additional activity on the same endpoint, including:

- PowerShell execution using `-EncodedCommand`
- An outbound TCP connection from PowerShell to another lab system
- Creation of a PowerShell script in the user's temporary directory
- Execution of the staged script using `ExecutionPolicy Bypass`
- Creation of a new local Windows account

The analyst was required to determine whether the alerts represented isolated events or formed part of a related sequence of activity.

## Lab Systems

| System | Role | IP Address |
|---|---|---|
| WIN11-DFIR | Windows endpoint under investigation | 192.168.134.129 |
| Ubuntu-Splunk | Splunk Enterprise SIEM | 192.168.134.10 |
| Kali Linux | Controlled test infrastructure | 192.168.134.128 |

All systems were hosted in VMware Workstation using an isolated lab network.

## Investigation Objectives

The investigation aimed to:

1. Validate the initial PowerShell detection.
2. Identify related endpoint activity within the incident timeframe.
3. Correlate process, network, file and Windows Security telemetry.
4. Reconstruct the incident timeline.
5. Map observed behaviour to relevant MITRE ATT&CK techniques.
6. Determine an appropriate incident severity and disposition.
7. Identify appropriate containment and remediation actions.
8. Verify that remediation was successful.
