# Threat Hunt Report (Part 2) — Azuki Import/Export Trading Co.

> **TLP: RED — Confidential (Training Use Only). Do not distribute outside the IR team.**
>
> This document is **Part 2** and builds on the initial IR write-up (Part 1) for **AZ-2025-001 / IR-2025-001**.

---

## Report Metadata

| Field | Value |
|---|---|
| **Organization** | Azuki Import/Export Trading Co. |
| **Threat Hunt Title** | AZ-2025-001 — Post-Exploitation + Exfiltration + Lateral Movement Hunt |
| **Part** | 2 of 2 |
| **Date of Report** | 2026-04-10 |
| **Incident Date** | 2025-11-19 |
| **Severity** | CRITICAL |
| **Primary Endpoint** | AZUKI-SL (IT Admin Workstation) |
| **Primary Compromised Account** | `kenji.sato` |
| **Analyst** | Ramzy Aboughlia |
| **Status** | Contained |

---

## Executive Summary (Part 2 Focus)

Part 2 of the threat hunt confirms **post-compromise tradecraft** following initial access to **AZUKI-SL** using the **`kenji.sato`** account. Evidence indicates the attacker:

- Automated actions via a staged **PowerShell script (`wupdate.ps1`)** retrieved from a C2 host.
- Performed **defense evasion** by adding Microsoft Defender exclusions for key file extensions and staging directories.
- Conducted **credential dumping** via a renamed **Mimikatz** binary (`mm.exe`) against LSASS.
- Packaged data into **`export-data.zip`** and **exfiltrated** it to a **Discord webhook** over HTTPS.
- Established **persistence** via both a **local admin backdoor account** (`support`) and a **scheduled task** (`Windows Update Check`) executing a masqueraded payload.
- **Cleared Windows event logs** using `wevtutil.exe` to degrade forensic visibility.
- Executed **lateral movement** to **`10.1.0.188`** (internal file server) using `cmdkey` + `mstsc`.

> **Context (Part 1):** Part 1 documents attribution to **Scattered Spider / UNC3944 / Octo Tempest**, initial access to AZUKI-SL, payload staging with `certutil.exe`, persistence via scheduled task, Defender exclusions, and a critical defensive gap: **Conditional Access not applied** to the successful sign-in from the attacker IP.

---

## Objectives of This Hunt (Part 2)

1. Validate and scope **post-exploitation activity** on AZUKI-SL.
2. Confirm **credential access** and identify potential credential exposure.
3. Confirm **data staging + exfiltration** and identify likely egress paths.
4. Confirm **persistence mechanisms** and identify artifacts for eradication.
5. Confirm **lateral movement** beyond the initial endpoint and identify next-scope targets.

---

## Scope

### In-Scope Assets

| Asset | Description |
|---|---|
| **Endpoint** | `AZUKI-SL` (IT Admin Workstation) |
| **Accounts** | `kenji.sato`, attacker-created `support`, laterally used `fileadmin` |
| **Lateral Target** | `10.1.0.188` (internal file server) |

### Out-of-Scope / Pending Validation

- Additional endpoints not explicitly confirmed via logs after event-log clearing
- Full file inventory of `10.1.0.188` pending dedicated file server triage

---

## Key Findings (Part 2)

### 1. Execution — Scripted Attack Chain

`wupdate.ps1` was downloaded from `78.141.196.6:8080` and executed to automate the attack chain.

### 2. Defense Evasion — Microsoft Defender Exclusions

Exclusions added for **`.bat`**, **`.ps1`**, **`.exe`** and the following staging directories:
- `C:\ProgramData\WindowsCache`
- `C:\Users\...\AppData\Local\Temp`

### 3. Credential Access — LSASS Dumping via Renamed Mimikatz

Renamed credential tool **`mm.exe`** executed with `sekurlsa::logonpasswords` against LSASS.

### 4. Collection + Exfiltration — Archive + Discord Webhook

- Data staged and compressed to **`export-data.zip`**
- Exfiltrated using **`curl.exe`** to a Discord webhook endpoint (`discord.com/api/webhooks/...`) over HTTPS/443.

### 5. Persistence — Local Backdoor + Scheduled Task

- Local account **`support`** created and elevated to **Administrators**
- Scheduled task **`Windows Update Check`** configured to run a staged `svchost.exe` payload daily at **02:00** as **SYSTEM**

### 6. Defense Evasion — Event Log Clearing

Security, System, and Application logs cleared via `wevtutil.exe`, reducing certainty for full activity reconstruction.

### 7. Lateral Movement — RDP to Internal File Server

`cmdkey` used to stage credentials; `mstsc /v:10.1.0.188` used to pivot via RDP to the file server using the `fileadmin` account.

---

## Attack Chain Narrative (Part 2)

```
[1] Initial foothold confirmed (Part 1) → AZUKI-SL / kenji.sato
[2] Scripted execution via wupdate.ps1 from C2 (78.141.196.6:8080)
[3] AV weakening — Defender exclusions added (extensions + paths)
[4] Tool transfer — mm.exe (Mimikatz), staged svchost.exe (LOLBin delivery)
[5] Credential dumping — LSASS via mm.exe
[6] Data staging — export-data.zip
[7] Exfiltration — Discord webhook over port 443 via curl.exe
[8] Persistence — support local admin + Windows Update Check scheduled task
[9] Log clearing — wevtutil cleared Security/System/Application logs
[10] Lateral movement → 10.1.0.188 via RDP (fileadmin)
```

---

## Timeline (UTC) — Part 2 Highlights

| Time (UTC) | Activity | Evidence Source |
|---|---|---|
| ~18:00 | `wupdate.ps1` downloaded from `78.141.196.6:8080` | DeviceNetworkEvents / DeviceFileEvents |
| 18:49:27–29 | Defender exclusions added (extensions + paths) | DeviceRegistryEvents |
| ~19:10 | `mm.exe` executes `sekurlsa::logonpasswords` | DeviceProcessEvents |
| ~19:15 | `export-data.zip` created | DeviceFileEvents |
| ~19:20 | Exfil to Discord webhook via `curl.exe` | DeviceNetworkEvents |
| ~19:25 | Scheduled task created (daily 02:00 SYSTEM) | DeviceProcessEvents |
| ~19:28–30 | Event logs cleared (`wevtutil`) | DeviceProcessEvents |
| 19:10:41 | Lateral RDP to `10.1.0.188` | DeviceNetworkEvents / DeviceLogonEvents |

---

## Indicators of Compromise (IOCs)

### Network

| Type | Indicator | Notes |
|---|---|---|
| External IP | `88.97.178.12` | Initial access source |
| External IP | `115.247.157.74` | Secondary brute-force attempts |
| Internal Pivot | `10.0.8.9` (`vm00000b`) | Internal pivot / remote device |
| C2 | `78.141.196.6:8080` | Payload / script hosting |
| Exfil Endpoint | `discord.com/api/webhooks/...` | Data exfiltration endpoint |
| Lateral Target | `10.1.0.188` | Internal file server |

### Host Artifacts

| Type | Artifact | Path |
|---|---|---|
| Staging Directory | `WindowsCache` | `C:\ProgramData\WindowsCache\` |
| Credential Dumper | Renamed Mimikatz | `C:\ProgramData\WindowsCache\mm.exe` |
| Masqueraded Payload | Fake `svchost.exe` | `C:\ProgramData\WindowsCache\svchost.exe` |
| Attack Script | `wupdate.ps1` | `C:\Users\...\AppData\Local\Temp\wupdate.ps1` |
| Archive | Exfil package | `C:\ProgramData\WindowsCache\export-data.zip` |
| Persistence Task | Scheduled task | `Windows Update Check` |
| Backdoor Account | Local admin | `support` |

---

## MITRE ATT&CK Mapping (Part 2)

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Execution | PowerShell | T1059.001 | `wupdate.ps1` execution |
| Defense Evasion | Impair Defenses | T1562.001 | Defender exclusions added |
| Credential Access | OS Credential Dumping: LSASS | T1003.001 | `mm.exe` + `sekurlsa::logonpasswords` |
| Collection | Archive Collected Data | T1560.001 | `export-data.zip` |
| Exfiltration | Exfiltration Over Web Service | T1567 | Discord webhook + `curl.exe` |
| Persistence | Create Account | T1136.001 | `support` local admin |
| Persistence | Scheduled Task/Job | T1053.005 | `Windows Update Check` as SYSTEM |
| Defense Evasion | Clear Windows Event Logs | T1070.001 | `wevtutil` log clearing |
| Lateral Movement | Remote Desktop Protocol | T1021.001 | `mstsc /v:10.1.0.188` |

---

## Detection Opportunities

### High-Signal Behaviors to Alert On

| Behavior | Tool/Command |
|---|---|
| Event log clearing | `wevtutil.exe cl *` |
| Defender exclusion modification | Registry writes to Defender exclusion keys |
| LOLBin file downloads | `certutil.exe -urlcache -f http*` from raw IPs / non-standard ports |
| Data archiving in staging dirs | `Compress-Archive` writing ZIPs to `WindowsCache` or `Temp` |
| Exfil to Discord | `curl.exe` / scripting engines POSTing to `discord.com/api/webhooks` |
| Credential staging + RDP pivot | `cmdkey.exe` followed by `mstsc.exe` targeting internal hosts |

---

## Remediation & Containment

### Immediate (0–24 Hours)

- [ ] Delete scheduled task **`Windows Update Check`**
- [ ] Disable/delete local account **`support`**
- [ ] Remove Defender exclusions (extensions + paths) and validate Tamper Protection is enabled
- [ ] Isolate AZUKI-SL for forensic image capture before additional cleanup
- [ ] Block at perimeter/firewall:
  - `78.141.196.6:8080`
  - `88.97.178.12`
  - `115.247.157.74`
- [ ] Rotate credentials for:
  - `kenji.sato`
  - `fileadmin`
  - All accounts authenticated to AZUKI-SL during the compromise window

### Short-Term (1–7 Days)

- [ ] Add egress controls to restrict outbound traffic to:
  - Raw IP destinations
  - Non-standard ports (e.g., 8080)
  - Discord webhooks (or enforce explicit allowlists)
- [ ] Enable and validate advanced audit policy coverage (account logon failures, credential validation failures)
- [ ] Deploy detections for LOLBin usage, scheduled task creation, and Defender exclusion registry writes

### Long-Term

- [ ] Implement PAW (Privileged Access Workstations) for IT admins
- [ ] Enable LSASS protections — **Credential Guard** and/or **RunAsPPL**
- [ ] Close Conditional Access "notApplied" gaps for all privileged access (critical failure identified in Part 1)

---

## Appendix — Hunt Queries (KQL)

### 1. Initial Access / Logon Events

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| sort by Timestamp asc
| project AccountName, ActionType, LogonType, RemoteIP, RemoteDeviceName,
          RemotePort, RemoteIPType, IsLocalAdmin
```

---

*Report prepared by Ramzy Aboughlia — Training use only (TLP: RED)*
