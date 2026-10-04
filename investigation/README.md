# Investigation

## 1. Initial Alert Triage

The investigation began after Splunk generated multiple alerts on `WIN11-DFIR`, including:

- Encoded PowerShell Command Execution — High
- Local User Account Created — High
- PowerShell Process Execution — Medium

The encoded PowerShell alert was selected as the initial investigation point.

Sysmon Event ID 1 showed `powershell.exe` executing with the `-EncodedCommand` parameter under the `WIN11-DFIR\dfiruser` account.

The Base64-encoded argument was decoded as:

```powershell
Write-Output "SOC-INV-2026-001 initial execution"
```

Although the decoded command was benign in this controlled simulation, the use of encoded PowerShell warranted further investigation.

## 2. Scoping the Activity

Sysmon telemetry was reviewed for the period immediately following the initial alert.

The investigation identified:

- 22 process creation events — Sysmon Event ID 1
- 1 network connection event — Sysmon Event ID 3
- 3 file creation events — Sysmon Event ID 11

The single network connection was prioritised for further analysis because it occurred shortly after the encoded PowerShell execution.

## 3. Network Analysis

At `21:52:20`, PowerShell process ID `7868` established a TCP connection:

```text
192.168.134.129:64093 → 192.168.134.128:8080
```

The connection originated from `WIN11-DFIR` and was made by:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This established that PowerShell had communicated with another system in the lab shortly after the initial alert.

## 4. File Creation Analysis

Sysmon Event ID 11 showed that the same PowerShell process, PID `7868`, created:

```text
C:\Users\dfiruser\AppData\Local\Temp\SOC-INV-2026-001.ps1
```

The matching process ID and ProcessGuid allowed the file creation event to be correlated with the previously identified network connection.

Two additional PowerShell-generated `__PSScriptPolicyTest` files were present in the same timeframe. These were treated as background PowerShell activity rather than evidence of the staged artifact.

## 5. Script Execution

Sysmon Event ID 1 subsequently recorded a new PowerShell process executing the staged file:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\dfiruser\AppData\Local\Temp\SOC-INV-2026-001.ps1
```

The new process, PID `10736`, had PowerShell PID `7868` as its parent.

This linked the network and file activity to subsequent execution of the downloaded script.

## 6. Local Account Creation

A high-severity Splunk alert subsequently identified creation of the local account:

```text
SOC-TestUser
```

Windows Security Event ID `4720` confirmed the account creation.

Sysmon process telemetry showed the associated process chain:

```text
powershell.exe
    ↓
net.exe
    ↓
net1.exe
```

The command-line telemetry showed `net.exe` being used to create the account. The lab password was redacted from public-facing evidence while the underlying telemetry remained unchanged.

## 7. Incident Reconstruction

Correlation of Sysmon and Windows Security telemetry produced the following sequence:

| Time | Event | Activity |
|---|---:|---|
| 21:51:26 | Sysmon 1 | Encoded PowerShell execution |
| 21:52:18 | Sysmon 11 | Staged PowerShell artifact created |
| 21:52:20 | Sysmon 3 | Outbound connection to controlled test infrastructure |
| 21:53:13 | Sysmon 1 | Staged PowerShell script executed |
| 21:53:48 | Sysmon 1 | Local account creation command |
| 21:53:48 | Sysmon 1 | Account creation child process |
| 21:53:48 | Security 4720 | Local user account created |

The correlated events demonstrated that the alerts were not isolated. They formed a related sequence of activity on the same endpoint.

## 8. Analyst Assessment

**Severity:** High  
**Confidence:** High  
**Disposition:** True Positive — Suspicious/Malicious Activity (Controlled Simulation)

The assessment was based on the combined behaviour rather than any individual event: encoded PowerShell execution, network communication, creation and execution of a PowerShell script from the user's temporary directory, and subsequent creation of a local account.

The available evidence did not demonstrate malware execution, credential theft, lateral movement or compromise of additional systems. Those activities were therefore not attributed to the incident.
