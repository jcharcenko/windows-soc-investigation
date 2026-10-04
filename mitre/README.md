# MITRE ATT&CK Mapping

The activity observed during `SOC-INV-2026-001` was mapped to MITRE ATT&CK based on evidence collected during the investigation.

Only techniques directly supported by the available telemetry were included.

## Technique Summary

| Technique | Name | Tactic | Supporting Evidence |
|---|---|---|---|
| T1059.001 | PowerShell | Execution | PowerShell executed an encoded command and subsequently launched a staged `.ps1` file using `ExecutionPolicy Bypass`. |
| T1105 | Ingress Tool Transfer | Command and Control | PowerShell established a network connection to controlled test infrastructure and transferred a `.ps1` file to the Windows endpoint. |
| T1136.001 | Create Account: Local Account | Persistence | `net.exe` and `net1.exe` were used to create `SOC-TestUser`, confirmed by Windows Security Event ID 4720. |

## T1059.001 — PowerShell

### Evidence

Sysmon Event ID 1 recorded PowerShell executing with:

```text
-EncodedCommand
```

Later telemetry showed another PowerShell process executing:

```text
-NoProfile -ExecutionPolicy Bypass -File C:\Users\dfiruser\AppData\Local\Temp\SOC-INV-2026-001.ps1
```

### Assessment

The observed activity directly demonstrated PowerShell being used for command and script execution.

---

## T1105 — Ingress Tool Transfer

### Evidence

PowerShell PID `7868` established a TCP connection from:

```text
192.168.134.129 → 192.168.134.128:8080
```

Sysmon Event ID 11 showed the same PowerShell process creating:

```text
C:\Users\dfiruser\AppData\Local\Temp\SOC-INV-2026-001.ps1
```

### Assessment

Correlation of the network connection and file creation demonstrated transfer of the staged PowerShell artifact from controlled test infrastructure to the Windows endpoint.

---

## T1136.001 — Create Account: Local Account

### Evidence

Sysmon process telemetry recorded:

```text
powershell.exe
    ↓
net.exe
    ↓
net1.exe
```

The associated command created the local account:

```text
SOC-TestUser
```

Windows Security Event ID `4720` independently confirmed that the account was successfully created.

### Assessment

The observed activity directly demonstrated creation of a local Windows account.

---

## Mapping Approach

ATT&CK techniques were assigned only where the collected evidence demonstrated the associated behaviour.

For example, the use of Base64 encoding was treated as a suspicious characteristic of the PowerShell execution but was not independently mapped to an additional ATT&CK technique. The available evidence also did not support claims of credential theft, lateral movement, malware execution or compromise of additional systems.

This conservative approach avoids overstating what the telemetry demonstrates.
