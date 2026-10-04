# Incident Report — SOC-INV-2026-001

## Executive Summary

A high-severity security investigation was initiated following detection of encoded PowerShell execution on the Windows endpoint `WIN11-DFIR`.

Analysis of Sysmon and Windows Security telemetry identified a sequence of related activity involving PowerShell execution, network communication with another system, creation and execution of a PowerShell script from the user's temporary directory, and creation of a new local Windows account.

Correlation of process, network, file and account telemetry established that the alerts represented a related sequence rather than isolated events.

The incident was assessed as a **High-severity True Positive** with **High confidence** within the controlled lab scenario.

The endpoint state was preserved before remediation. The newly created account and staged PowerShell artifact were subsequently removed and their removal was verified.

---

## Incident Details

| Field | Value |
|---|---|
| Incident ID | SOC-INV-2026-001 |
| Endpoint | WIN11-DFIR |
| Endpoint IP | 192.168.134.129 |
| Initial Detection | Encoded PowerShell Command Execution |
| Severity | High |
| Confidence | High |
| Disposition | True Positive — Controlled Simulation |
| Primary Telemetry | Sysmon and Windows Security |
| SIEM | Splunk Enterprise |

---

## Initial Detection

Splunk generated a high-severity alert after Sysmon Event ID 1 recorded `powershell.exe` executing with the `-EncodedCommand` parameter.

The encoded argument was decoded during triage as:

```powershell
Write-Output "SOC-INV-2026-001 initial execution"
```

The decoded command itself was benign. However, the use of encoded PowerShell provided sufficient reason to investigate surrounding endpoint activity.

---

## Key Findings

### 1. PowerShell Network Activity

PowerShell PID `7868` established a TCP connection from the Windows endpoint to:

```text
192.168.134.128:8080
```

The destination was controlled infrastructure within the lab environment.

### 2. Staged Artifact Created

Sysmon Event ID 11 showed PowerShell PID `7868` creating:

```text
C:\Users\dfiruser\AppData\Local\Temp\SOC-INV-2026-001.ps1
```

The matching process identity correlated the file creation with the observed network activity.

### 3. Staged Script Executed

A new PowerShell process subsequently executed the staged file using:

```text
-NoProfile -ExecutionPolicy Bypass -File C:\Users\dfiruser\AppData\Local\Temp\SOC-INV-2026-001.ps1
```

The executing process was a child of PowerShell PID `7868`.

### 4. Local Account Created

Sysmon telemetry recorded the following process chain:

```text
powershell.exe
    ↓
net.exe
    ↓
net1.exe
```

The command created the local account:

```text
SOC-TestUser
```

Windows Security Event ID `4720` independently confirmed successful account creation.

---

## Timeline

**Incident date:** 4 October 2026  
**Timezone:** Europe/Dublin

| Time | Event | Finding |
|---|---:|---|
| 21:51:26 | Sysmon 1 | Encoded PowerShell executed |
| 21:52:18 | Sysmon 11 | PowerShell script created in `%TEMP%` |
| 21:52:20 | Sysmon 3 | PowerShell connected to `192.168.134.128:8080` |
| 21:53:13 | Sysmon 1 | Staged script executed with `ExecutionPolicy Bypass` |
| 21:53:48 | Sysmon 1 | `net.exe` launched account creation command |
| 21:53:48 | Sysmon 1 | `net1.exe` executed as child process |
| 21:53:48 | Security 4720 | `SOC-TestUser` created |

---

## MITRE ATT&CK

The observed activity was mapped to:

| Technique | Description |
|---|---|
| T1059.001 | PowerShell |
| T1105 | Ingress Tool Transfer |
| T1136.001 | Create Account: Local Account |

Only techniques directly supported by collected telemetry were assigned.

---

## Assessment

The activity was classified as a **True Positive** because multiple telemetry sources established a coherent sequence of suspicious behaviour.

The assessment was based on the combination of:

- Encoded PowerShell execution
- PowerShell network communication
- Creation of a PowerShell script in the user's temporary directory
- Execution using `ExecutionPolicy Bypass`
- Local account creation
- Independent confirmation through Windows Security telemetry

No single event was treated as proof of compromise in isolation.

The investigation did **not** establish evidence of:

- Credential theft
- Lateral movement
- Malware execution
- Data exfiltration
- Compromise of additional endpoints

These activities were therefore not attributed to the incident.

---

## Containment and Remediation

Before remediation, a VMware snapshot was taken to preserve the endpoint's post-incident state.

The following actions were then performed:

1. Verified that `SOC-TestUser` existed and was active.
2. Confirmed that the account had no recorded logon.
3. Deleted `SOC-TestUser`.
4. Verified that the account no longer existed.
5. Verified that `SOC-INV-2026-001.ps1` remained in the user's temporary directory.
6. Removed the staged PowerShell artifact.
7. Verified that the artifact was no longer present.

Windows Security Event ID `4726` subsequently confirmed deletion of the local account.

---

## Recommended Actions in a Production Environment

If equivalent activity were observed on a production endpoint, recommended actions would include:

1. Isolate the affected endpoint where appropriate.
2. Disable or remove the unauthorized account.
3. Preserve relevant endpoint and SIEM evidence.
4. Investigate the source and destination infrastructure associated with the network activity.
5. Search other endpoints for matching indicators and behavioural patterns.
6. Review the initiating user and process context.
7. Determine whether additional persistence mechanisms were established.
8. Review authentication activity for use of the newly created account.
9. Remove confirmed malicious or unauthorized artifacts.
10. Continue monitoring after remediation for recurrence.

---

## Detection Improvement Opportunities

The investigation highlighted several opportunities for stronger detection engineering:

- Correlate encoded PowerShell execution with subsequent network connections.
- Correlate PowerShell network activity with file creation in user-writable directories.
- Detect PowerShell launching scripts from `%TEMP%` or similar locations.
- Increase confidence when `ExecutionPolicy Bypass` occurs alongside other suspicious PowerShell behaviour.
- Correlate account creation events with preceding PowerShell, `net.exe` or `net1.exe` activity.
- Use process GUIDs and parent-child relationships to improve event correlation.
- Baseline legitimate PowerShell activity to reduce false positives from broad process-execution detections.

---

## Conclusion

The investigation demonstrated how multiple low-level telemetry sources can be combined to reconstruct a security incident.

Rather than relying solely on individual alerts, Sysmon process, network and file telemetry was correlated with Windows Security events to establish the sequence of activity, assess its significance and support remediation decisions.

The exercise also demonstrated the importance of distinguishing suspicious behaviour from confirmed impact and limiting conclusions to what the available evidence supports.
