# Detection Logic

Three Splunk detections provided the initial alert context for this investigation.

The detections were developed and tested previously in the home SOC lab and were reused here to demonstrate how individual alerts can be correlated during an incident investigation.

## 1. Encoded PowerShell Command Execution

**Severity:** High  
**Telemetry:** Sysmon Event ID 1 — Process Creation

### Detection Objective

Identify PowerShell processes launched with command-line parameters commonly used to execute Base64-encoded commands.

### Behaviour

The detection looks for PowerShell process creation containing:

```text
-enc
-EncodedCommand
```

During `SOC-INV-2026-001`, this detection identified the initial suspicious event and became the starting point for the investigation.

### Investigation Value

The alert provided:

- Process image
- Command line
- User context
- Process ID
- Parent process information
- Timestamp

The encoded argument was subsequently decoded during triage to determine what had been executed.

---

## 2. PowerShell Process Execution

**Severity:** Medium  
**Telemetry:** Sysmon Event ID 1 — Process Creation

### Detection Objective

Provide visibility into PowerShell execution on the monitored endpoint.

This is intentionally a broad detection and may generate legitimate activity. It is therefore more useful as supporting telemetry than as a high-confidence alert on its own.

### Investigation Value

During the incident, PowerShell process telemetry helped identify and correlate:

- The initial encoded PowerShell process
- Network activity associated with PowerShell
- Execution of the staged `.ps1` file
- Parent-child process relationships

This demonstrated the difference between a broad behavioural detection and a more specific high-severity detection.

---

## 3. Local User Account Created

**Severity:** High  
**Telemetry:** Windows Security Event ID 4720

### Detection Objective

Identify creation of a new local Windows user account.

During the investigation, the detection identified creation of:

```text
SOC-TestUser
```

The Security event was correlated with Sysmon process telemetry showing:

```text
powershell.exe
    ↓
net.exe
    ↓
net1.exe
```

This provided both Windows Security confirmation that the account was created and process-level evidence showing how the action occurred.

---

## Detection Considerations

No individual alert was treated as proof of compromise.

The investigation relied on correlation between multiple events and telemetry sources. The encoded PowerShell alert provided the initial investigation point, while Sysmon process, network and file telemetry and Windows Security events established the broader sequence of activity.

The broad PowerShell detection is expected to produce more noise than the encoded-command or account-creation detections. In a production environment, additional tuning and environmental baselining would be required to reduce false positives.
