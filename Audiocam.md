# AudioCam.py

Read-only Windows 10/11 auditor for **microphones**, **cameras**, and the **apps and sites that were allowed to use them**.

**Version 1.1.0**

It enumerates three independent views:

1. **Access traces** — Windows Capability Access Manager last-use records (`ConsentStore`, plus the Windows 11 `CapabilityAccessManager.db` when readable)
2. **Connected devices** — Plug and Play cameras and capture endpoints present now
3. **Site permissions** — default-profile Chromium and Firefox microphone and camera origin grants

It does **not** record audio, open devices, change the registry, capture packets, or dump cookies, history, or extensions.

```text
python AudioCam.py
```

---

## Requirements

| Item | Notes |
| --- | --- |
| OS | Windows 10 or Windows 11 |
| Runtime | Python 3.10+ on `PATH` |
| Privileges | Unelevated is enough for HKCU and the current user's browser profiles. HKLM, other users' `HKU` hives, and `CapabilityAccessManager.db` are incomplete or unreadable without Administrator. |
| Dependencies | Standard library. Optional: `pyfiglet` (banner), `pywin32` (WMI fallback if PowerShell PnP is empty). |

```powershell
pip install pyfiglet
```

The script still runs if those packages are missing.

The test suite runs on any platform, including Linux CI, because the `winreg` import is guarded and every parsing, scoring and classification function is platform-independent:

```bash
python -m unittest discover -s tests -v
```

---

## Commands

Run from PowerShell or CMD in the directory that contains `AudioCam.py`.

```powershell
python AudioCam.py
python AudioCam.py --json
python AudioCam.py --csv
python AudioCam.py --inventory
python AudioCam.py --csv --inventory
python AudioCam.py --version
python AudioCam.py -h
```

| Command | Effect |
| --- | --- |
| `python AudioCam.py` | Human-readable report: consent summary, source status, Table 1, Table 2, Table 3. |
| `python AudioCam.py --json` | Same data as JSON on stdout. |
| `python AudioCam.py --csv` | Writes `audiocam_historical.csv`, `audiocam_active.csv`, and `audiocam_site_permissions.csv` in the current directory. |
| `python AudioCam.py --inventory` | Also prints **Table 1b**: Enum / MMDevices hardware nodes that have **no** `LastUsedTimeStart`. Device inventory, not access traces. |
| `python AudioCam.py --version` | Print the version and exit. Works on any platform. |
| `python AudioCam.py -h` | Flag help. |

Exit codes: `0` success (including partial source failures), `2` not Windows or a structural setup error.

The process is **read-only**. Printed `Disable-PnpDevice` text next to Stereo Mix is informational and is not executed. The only files written are the three CSVs when you ask for them, and short-lived private copies of locked SQLite databases in a temp directory, which are deleted before exit.

### JSON keys

`generated_at`, `generated_at_iso`, `host`, `elevated`, `consent_summary`, `historical`, `access_traces`, `hardware_inventory`, `active`, `site_permissions`, `source_status`.

`historical` is `access_traces` plus `hardware_inventory` when `--inventory` was passed, and equal to `access_traces` otherwise.

### Row schemas

Access traces and hardware inventory (`HIST_COLS`):

```text
RecordKind, Source, Capability, Hive, AppType, Application, Developer,
DeveloperSource, SignatureStatus, VidPidObserved, VidPidCorrelated,
VidPidSource, Consent, LastStart, LastStop, LastStartISO, LastStopISO,
Duration, Notes
```

Active devices (`ACTIVE_COLS`):

```text
Type, Name, Make, Model, VidPidObserved, VidPidSource, InstanceId,
Status, Present, Backend, Virtual, Notes
```

Site permissions (`SITE_COLS`):

```text
Browser, Profile, Origin, Capability, Setting, LastModified,
LastModifiedISO, Expires, ExtraProfiles
```

`RecordKind` is `access-trace` or `hardware-inventory`. `LastStart` and `LastStop` are local display strings; the `*ISO` fields carry a UTC offset and are what you should use for correlation with other logs.

---

## Source status

Every source records whether it could be read. This block prints before the tables.

| State | Meaning | Shown on console |
| --- | --- | --- |
| `ok` | Read successfully | Yes |
| `fail` | The artifact exists but could not be read | Yes |
| `absent` | The artifact does not exist on this host | No — recorded in `--json` only |

The distinction is the point. An empty Table 1 because ConsentStore held nothing and an empty Table 1 because the hive was denied are different claims, and the tool must not make the second look like the first.

Sources that report: ConsentStore, MMDevices Capture, MMDevices Render, Enum hardware nodes, `CapabilityAccessManager.db`, live PnP enumeration, the Authenticode publisher lookup, the process list used for LIVE attach, and each browser database.

Each source is individually fault-isolated. One unreadable artifact produces a `fail` line and costs you that source only; the rest of the report still prints.

---

## Features

| Area | Behavior |
| --- | --- |
| ConsentStore | Walks `microphone` and `webcam` under HKLM, HKCU, and loaded HKU SIDs. HKCU and its matching `HKU\<SID>` are the same hive, so the current user's SID is resolved and excluded to avoid reporting every trace twice. Packaged apps and `NonPackaged` paths (`#` → `\`). FILETIME → local and ISO-8601 timestamps, duration, `Allow`/`Deny`/`Prompt`. |
| LIVE sessions | Start time present and stop time missing (or stop < start): header becomes `LIVE` and matching running PIDs are attached. NonPackaged rows only — a Package Family Name is not an image name and can never match a process, so packaged rows say so rather than claiming the process is not running. |
| Developer | Authenticode signer CN **with its `Status`**, then `VersionInfo.CompanyName` read natively through `version.dll`, then directory-anchored path heuristics. Every tier below a valid signature says so in the string itself. |
| VID/PID | `VidPidObserved` is read from a device's own instance ID. `VidPidCorrelated` is inference across the host, attached to access-trace rows which store no hardware ID at all. `VidPidSource` says which. Correlated values never seed the catalog that produces them. |
| Live PnP | `Get-PnpDevice`, then `Win32_PnPEntity`, then `pnputil`, then optional `win32com`. All four report only `Status`; `Present` is derived from it in one place, so the column means the same thing whichever backend answered. `Backend` records which one did. |
| Site permissions | Default profile only: Chromium `Preferences` `media_stream_mic` / `media_stream_camera`; Firefox `permissions.sqlite`. The Firefox default comes from the `[Install<hash>]` section, not the legacy `Default=1` flag. Expired grants are omitted; session-scoped grants are labelled. Extra profiles are **named**, not expanded, and are flagged when they hold stored permissions. |
| CAM.db | Best-effort read of `%ProgramData%\Microsoft\Windows\CapabilityAccessManager\CapabilityAccessManager.db`. The file is normally held by `camsvc`, so a locked database is read from a private snapshot rather than reported as empty. |
| Output | Figlet banner when `pyfiglet` is installed; capability-root `Allow` printed in red. Deterministic across runs. |

---

## What each function can and cannot detect

These tables are the product boundary. A hit is an **artifact**, not proof that audio or video left the machine.

### 1. Privacy consent summary (capability-root `Value`)

Reads the root `Value` on ConsentStore `\microphone` and `\webcam` per hive.

| Detects | Does not detect |
| --- | --- |
| Machine- or user-wide "let desktop apps access microphone/camera" set to Allow, Deny, Prompt, or missing | Which app or site used the device |
| That a hive is readable vs missing vs denied | Group Policy / MDM overlay that Settings UI shows but this key does not |
| | Per-app toggles (those live on child keys, Table 1) |

### 2. Table 1 — historical access traces + LIVE

Source of truth: `LastUsedTimeStart` on ConsentStore, and CAM.db when readable. Hardware-only Enum/MMDevices rows are omitted unless `--inventory`.

| Detects | Does not detect |
| --- | --- |
| An application **opened the Windows microphone or webcam capability**, with last start/stop and duration | A full timeline — stock ConsentStore keeps the **last session per app**, not every session |
| Packaged identity (PFN) vs NonPackaged filesystem path | Which physical device that app bound. `VidPidCorrelated` is host-wide inference, not stored on the app key |
| Publisher **and signature validity** when the file is present | A binary whose Authenticode and `CompanyName` are both absent — reported as `Unknown`, never as a guessed vendor |
| A deleted binary: the registry key outlives the file, reported as `Unknown (binary no longer present)` | The content of what was captured |
| `LIVE`: last session has no stop time, plus running PIDs for that image | That a LIVE row is a call, a hung tab, or a silent `getUserMedia` hold |
| Same-second opens (`0s` duration) as a real invoke | Audio payload, codec, or whether samples were uploaded |
| Unexpected NonPackaged EXEs that went through the capability broker | Anything that never calls that broker |
| | Kernel streaming, raw USB isochronous reads, or a driver that bypasses Capability Access Manager |
| | Injection into a process that **already** holds the device — still attributed to the host EXE |
| | Capture performed in a `LocalSystem`, `LocalService` or `NetworkService` context: those hives (`S-1-5-18/19/20`) are skipped by design |

### 3. VID/PID correlation

| Detects | Does not detect |
| --- | --- |
| USB `VID_xxxx&PID_xxxx` and some HDAUDIO `VEN_&DEV_` on endpoints and Enum nodes (`VidPidObserved`) | Proof that a given ConsentStore app used that exact adapter |
| Up to two plausible **capture** devices per capability (`VidPidCorrelated`), USB preferred | Anything when no plausible capture hardware exists — the tool reports that rather than offering a keyboard |
| Virtual software device nodes (`SWD\`, `ROOT\`) | A complete USB history after the node is deleted from Enum |

### 4. Table 2 — active / currently connected devices

| Detects | Does not detect |
| --- | --- |
| Cameras and capture-like endpoints Windows reports now (name, manufacturer, instance ID, status, derived presence, enumerator) | That any app is **using** the device right now (that is Table 1 LIVE) |
| Virtual cameras/mics and Stereo Mix / loopback enabled in PnP | Analog taps, DSP firmware on a headset, or a camera that never enumerates |
| Ghost and disabled nodes PnP still returns, labelled `Present=False` | Nodes PnP no longer returns at all (use `--inventory`) |
| Capture-class endpoints whose name says neither input nor output, surfaced as `Audio (unclassified)` rather than dropped | Which direction such an endpoint actually runs in |

### 5. `--inventory` hardware remnants (Table 1b)

| Detects | Does not detect |
| --- | --- |
| Enum/MMDevices nodes that look like cameras or mics **without** an access timestamp | That the remnant was ever opened by software |
| Unplugged USB cameras that still have an Enum key | Devices whose keys were cleaned by Windows or a third-party tool |

### 6. Table 3 — browser site permissions

Default profile of Brave, Chrome, Edge, Chromium, Vivaldi, Opera, and Firefox. Mic and camera keys only.

| Detects | Does not detect |
| --- | --- |
| Origins with **Allow** or **Block** for `getUserMedia` in the **default** profile | Permissions stored only in other profiles (those are **named**, and flagged when they hold stored permissions) |
| Session-scoped grants, labelled `Allow (session)` | Which origin held the live stream during a Table 1 browser session |
| Grant expiry, with already-expired grants omitted | Cookies, passwords, history, downloads, or extension IDs (intentionally out of scope) |
| Last-modified time when the browser wrote one | A one-shot prompt denied and never written, or an in-memory permission never flushed |
| | Opera GX, Chrome Canary, or Edge Beta/Dev channels |

### 7. LIVE process attach

| Detects | Does not detect |
| --- | --- |
| ConsentStore open session plus running PIDs for that image | Which tab, renderer, or extension inside a multi-process browser owns the `MediaStream` |
| Stale open-session keys when the image is **not** running | Network egress while the session is live |

---

## Worked scenario: could malware turn the microphone on remotely, and would this tool see it?

Assume no anti-forensics: the operator did not delete the ConsentStore key, did not clear CAM.db, and did not tamper with the registry after the fact.

The short answer is that **it depends entirely on which layer of the audio stack the implant used**, and the tool is explicit about which layers it covers.

### Case A — the implant uses the normal Windows audio APIs

An implant that calls WASAPI (`IAudioClient`), WinRT `MediaCapture`, or DirectShow is brokered by the Capability Access Manager service, the same as any other application. That is true whether or not a consent prompt appeared: if "Allow desktop apps to access your microphone" is already **Allow**, the capture happens silently, but the usage is **still recorded**. Consent and logging are separate mechanisms, and the tool prints the consent root precisely so you can tell that no prompt was involved.

Suppose an implant at `C:\Users\alice\AppData\Local\Temp\svchost.exe` held the microphone from 02:14 for four hours. Table 1 would show:

```text
#1   Microphone   svchost.exe   4h 12m 8s
  App           C:\Users\alice\AppData\Local\Temp\svchost.exe
  Developer     Unknown
  VID/PID       VID_0B0E&PID_0300 [Headset Microphone]  (correlated, not measured)
  Consent       Allow
  Window        2026-08-30 02:14:52  →  2026-08-30 06:27:00
  Notes         Correlated, not measured: top 2 capture VID/PIDs on this host
```

Four separate signals make that row worth investigating, and none of them is the tool asserting that malware exists:

- **An unsigned binary.** `Developer` is `Unknown` and `SignatureStatus` is `NotSigned`. The tool will not guess a vendor from the directory name, so a file in `Temp` or in `C:\Windows\Temp` gets no publisher at all rather than an inherited one.
- **A name that does not match its location.** `svchost.exe` belongs in `System32`. The tool does not flag this for you; you read it off the `App` line.
- **Duration and time of day.** Four hours starting at 02:14 is not a video call.
- **`Consent = Allow`.** No prompt was shown, so the user has no memory of approving it.

If the implant deleted itself afterwards, the ConsentStore key survives the binary and the row reads `Unknown (binary no longer present)` — which is itself a finding, because a legitimate application that opened your microphone is normally still installed.

**Verdict: yes, recorded, with a strong signal.**

### Case B — the implant injects into a process that already has the microphone

If the code injects into Teams, Zoom, or a browser that already holds an open capture stream, the ConsentStore record is attributed to the **host image**. Table 1 will say `teams.exe`, correctly and uselessly.

What you might still notice is the shape of the session: an implausibly long duration, or a `LIVE` row for an application you are not currently using. That is a weak signal and easily lost in normal behaviour.

**Verdict: the capture is recorded, the attribution is wrong.** The tool tells you the microphone was open and who nominally held it, not who was actually reading the samples.

### Case C — the implant works below the capability broker

A kernel-mode driver, a filter driver on the audio stack, or raw USB isochronous reads never touch the Capability Access Manager. Nothing is written to ConsentStore, so nothing appears in Table 1.

Table 2 may still be interesting — a rogue virtual audio device or an unexpected capture endpoint would enumerate — but a driver that reads the existing device leaves no trace this tool can see.

**Verdict: not recorded. This is the tool's principal blind spot, and no amount of registry auditing closes it.**

### Case D — the implant runs as a service under `LocalSystem`

Capture performed in a `LocalSystem`, `LocalService` or `NetworkService` context records under `HKU\S-1-5-18`, `S-1-5-19` or `S-1-5-20`. AudioCam skips those hives by design, because they are dominated by platform noise.

**Verdict: not shown in the default output**, even though the artifact exists. This is a known gap rather than a technical limit; see Known gaps below.

### Case E — the payload is a web page

A page the user once granted `getUserMedia` to can re-open the microphone silently on every later visit. Table 3 shows the origin with `Allow`; Table 1 shows the browser executable. The tool does **not** connect the two, and cannot tell you which tab held the stream. Read them together: a browser row with a long duration plus an unexpected origin in Table 3 is the pattern.

**Verdict: both halves recorded, the link between them is yours to make.**

### What "recorded" does not mean

Even in Case A, a Table 1 row establishes only that **the microphone capability was opened by that image for that window**. It does not establish that audio was encoded, retained, or sent anywhere. AudioCam performs no network capture and reads no network artifacts, so it cannot distinguish local recording from live exfiltration. Pair it with network telemetry, EDR data, or event logs before drawing a conclusion.

### Retention, which limits all of the above

ConsentStore keeps **the last session per application**, not a history. An implant that captured nightly for three weeks leaves one row, showing the most recent night. CAM.db retains roughly thirty days when it is readable at all. Neither is an audit log, and neither was designed to survive an adversary who knows they exist.

### Practical reading order

1. Check **source status** first. A `fail` line means a table below is incomplete, not empty.
2. Read the **consent summary**. If the capability root is `Allow`, silent activation was possible for every desktop application.
3. Scan **Table 1** for unsigned binaries, unfamiliar paths, long durations, odd hours, and `LIVE` rows.
4. Check **Table 2** for virtual capture devices and enabled loopback.
5. Cross-reference **Table 3** if a browser appears in Table 1.
6. Run elevated for a second pass, which adds HKLM and other users' hives.

---

## Artifacts touched (read-only)

```text
HKLM|HKCU|HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone
HKLM|HKCU|HKU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render     (loopback names only)
HKLM\SYSTEM\CurrentControlSet\Enum\{USB,USBVIDEO,SWD,HDAUDIO,BTHENUM,HID}
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList             (SID resolution fallback)

%ProgramData%\Microsoft\Windows\CapabilityAccessManager\CapabilityAccessManager.db

%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\
%LOCALAPPDATA%\Google\Chrome\User Data\
%LOCALAPPDATA%\Microsoft\Edge\User Data\
%LOCALAPPDATA%\Chromium\User Data\
%LOCALAPPDATA%\Vivaldi\User Data\
%APPDATA%\Opera Software\Opera Stable\
%APPDATA%\Mozilla\Firefox\profiles.ini + Profiles\*\permissions.sqlite
```

External commands: `powershell` (device enumeration, Authenticode), `pnputil` and `tasklist` (fallback and process list). All read-only queries.

---

## Interpretation notes

- A 21-hour `brave.exe` microphone row means the **browser process** held the capability for that last recorded window. It is compatible with a meeting, a tab that never called `track.stop()`, or a site that already had sticky Allow.
- `Developer = Brave Software, Inc. (Authenticode: Valid)` means the image is signed by Brave and the signature verifies. It does not mean the session was benign.
- `Developer = X [signature: HashMismatch]` means a signed binary was modified after signing. Treat that as a finding.
- `Developer = X (path heuristic, unverified)` means the vendor was guessed from a directory name and nothing verified it.
- `VidPidCorrelated` is inference. Nothing on a ConsentStore app key records which adapter an app bound.
- `Present=False` in Table 2 means PnP still holds the node but it is not started — a ghost or disabled device.
- `LIVE` is the closest this module gets to "happening now." It is still not a wiretap record.

---

## Known gaps

Documented rather than hidden. These are limitations of the current version, not bugs:

- Service-context captures (`S-1-5-18/19/20`) are skipped.
- `CapabilityAccessManager.db` sits in a directory restricted to SYSTEM on some builds. An elevated shell may help; if it does not, the source-status block will say `fail` rather than pretend the file is absent.
- Opera GX, Chrome Canary and Edge Beta/Dev are not enumerated.
- `--csv` writes to the current directory and overwrites without asking.
- `pnputil` output is parsed by English field names; on a localised host that fallback yields nothing.
- Timestamps outside 2000–2100 are discarded rather than flagged.

---

## Safety

AudioCam does not enable capture, persist implants, or send data off-host. Use it on systems you are authorized to audit. Output can include workplace or personal URLs and full filesystem paths; treat reports as sensitive.

CSV output escapes values that begin with `=`, `+`, `-`, `@`, tab or carriage return, because a USB device supplies its own name and a site supplies its own origin, and spreadsheets execute those cells on open.
