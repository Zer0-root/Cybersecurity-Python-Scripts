# Bluejack.py

Read-only Bluetooth posture audit for a single Windows host.

Bluejack answers one question from one machine: **what is this host's Bluetooth
posture right now, and what should I fix first?** It enumerates adapters, bonded
Classic and BLE devices, offered profiles, discoverability, authentication,
encryption-key-length policy, and stale pairings, then maps what it finds to stable
MITRE ATT&CK techniques.

It does not change anything. It does not talk to the radio. It does not emit link
keys. It does not touch the network.

```
python Bluejack.py                       # human report
python Bluejack.py --json                # machine-readable
python Bluejack.py --stale-days 180 --role conference
python Bluejack.py --require-admin       # refuse to report if the scan was blind
```

Standard library only. Two files, no install step.

---

## Who this is for

One person auditing machines they own or are authorised to inspect — their own
laptop, a handful of workstations, a lab, a client engagement. It is a hand-run
tool that prints a report you read.

It is deliberately **not** an enterprise product. There is no agent, no server, no
dashboard, no scheduler. If you need fleet-wide Bluetooth posture management, buy
something built for that. What Bluejack gives you is a complete, honest picture of
one host in a few seconds, in a form you can read or hand to someone else.

---

## Requirements

| | |
|---|---|
| OS | Windows 10 / 11 for a live scan |
| Python | 3.10+ |
| Dependencies | none (standard library) |
| Privilege | works unprivileged, but see below |
| Tests | `pytest` |

**Run it elevated.** Much of what Bluejack reads lives under `HKLM`, and the bond
store (`BTHPORT\Parameters\Devices`) is ACL'd to SYSTEM and Administrators. An
unprivileged scan still runs and still reports — it just cannot see everything.
Bluejack tells you when that happens rather than presenting a blind scan as a clean
one. See *Unknown is not No* below.

Non-Windows hosts refuse a live scan unless `BLUEJACK_ALLOW_NON_WINDOWS` is set,
which exists for running the test suite off Windows.

---

## Layout

```
Bluejack.py               Audit logic, report model, CLI, human/JSON/NDJSON output
_windows_bt.py            Windows collector (batched CIM, winreg, ctypes)
test_bluejack_fixes.py    Audit-layer tests (fake backend, no Windows needed)
test_windows_bt.py        Collector tests (stubbed PowerShell)
```

Keep both modules in the same directory. `get_bluetooth_status()` is the public
entry point; it takes an injected backend, which is how the whole audit layer is
tested without a Windows machine.

---

## What it reports

### Quick Summary

Yes / No / Unknown indicators, printed first:

- Scan complete (leads the block — it qualifies everything under it)
- Hardware present
- Currently in use (a bond seen in the last 15 minutes; never guessed)
- Adapter enabled (PnP) and Radio enabled — two different facts, reported separately
- `bthserv` state
- Discoverable (T1120)
- Authentication required (T1200)
- KNOB-class minimum encryption key-length mitigation — highlighted in gold, because
  it is the cheapest fix on the list and the one people skim past
- Trusted without Authenticated — red on a colour-capable terminal
- Classic / BLE / dual-mode bond counts
- High/Critical count

### Sections

**Scan** — tool and schema version, start and finish in UTC, duration, host name, OS,
Python and PowerShell versions, process privilege, and the host's own local clock
reading with its UTC offset. Every other timestamp in the report is UTC; this line
is what lets you line the report up against local-time Windows event logs.

**Soft vs hard disable** — distinguishes a Settings toggle (adapter present, radio
off) from a PnP-disabled or missing adapter, with a one-sentence explanation and the
adapter status, radio power, service state and start type behind it.

**Encryption key length** — reads
`HKLM\SYSTEM\CurrentControlSet\Policies\Hardware\Bluetooth\EnableMinimumEncryptionKeySize`.
Missing or `0` is Off and produces a T1040 finding. The report prints the
`Set-ItemProperty` command; it does not run it.

**Profiles offered now** — HID, HOGP, SPP, DUN, A2DP, PAN. Current offer state, not
connection history. `UnsupportedServices` wins No, `SupportedServices` or a live
object wins Yes, and a row with neither stays Unknown. Radio off or adapter
hard-disabled makes every row No.

**Adapters** — name, PnP status, manufacturer, driver version and date, hardware ID,
InstanceId. Drivers older than 24 months are Medium / T1200.

**Paired devices** — three tables. Classic, BLE, and dual-mode. A dual-mode device
appears in all three: it stays in Classic and BLE so it cannot vanish from either
view, and the dual table makes the class obvious with a "Classified by" column
showing which signals decided it. Columns include OUI, address kind, category, CoD,
Trusted, Authenticated and last-seen.

**Stale-bond hygiene** — four deterministic checks (N defaults to 90 days;
`--role conference` suppresses the inventory-rot check):

| Check | Severity | MITRE |
|---|---|---|
| Bond with no trusted last-seen in N days | Low, or Medium if HID/HOGP or N≥180 | T1120 |
| HID / HOGP UUID or CoD major 5 | Medium | T1056.001 |
| Name looks like a keyboard or mouse but CoD is missing / Uncategorized | Medium | T1056.001 |
| More than 15 bonds on a workstation | Low | T1120 |

**Findings** — severity, rule ID, MITRE technique, target, remediation, and known
actors documented as using that technique. Long cells
wrap within their column rather than running off the terminal, and columns holding
unbreakable tokens (registry paths, InstanceIds) keep enough width to stay
copy-pasteable.

**ATT&CK techniques tagged by this scan** — for each technique actually raised: what
it is, why this particular Bluetooth weakness maps to it, the known actors, and a
link to MITRE. The KNOB entry explains CVE-2019-9506 specifically — an attacker
negotiating a 1-byte encryption key turns an encrypted link into a sniffable one,
which is why a missing DWORD is a High rather than a nag.

**Configuration, collection completeness, errors, collector notes** — see below.

---

## Design notes

These are the decisions that make the output trustworthy. They are the reason the
tool is longer than it looks like it needs to be.

### Absent is not denied, and neither is a failure

The completeness table has four statuses and they mean different things:

| Status | Meaning |
|---|---|
| `read` | value read successfully |
| `absent` | key readable, value not set on this host — a **result**, not a gap |
| `denied` | exists but could not be read; you were not elevated |
| `error` | failed for some other reason |

Only `denied` and `error` mean the scan was blind. `absent` against
`Authentication` or `AllowDiscoverableMode` is the normal state of a machine where
nobody has configured those explicitly. The table names the exact path and value
behind each row so you never have to guess which of the four you are looking at.

### Unknown is not No

A registry key Bluejack cannot *read* is not a key that is *unset*. Conflating the
two is how an audit tool reports a clean host it never actually saw. Every source
is recorded as `read`, `absent`, `denied` or `error` in a **collection completeness**
map, and every `Unknown` in the report should be explainable from it.

Consequences you will see:

- An unreadable KNOB policy key reports `Unknown`, not `Off`, and raises no finding.
  A genuinely *absent* DWORD still does raise one — that is a real misconfiguration.
- If the bond store is unreadable, the paired counts are `null` in JSON and
  "Unknown" in the report. Not `0`, which would read as "this host has no pairings".
- A blind scan raises one Medium "scan incomplete" finding naming the unreadable
  sources, and `Scan complete? No` leads the summary.

`--require-admin` exits 2 rather than printing a partial report at all.

### Timestamps are decoded, not trusted

Bond timestamps come from a magnitude heuristic that cannot always tell a FILETIME
from a Unix-milliseconds value, and a host may have written a bond while its clock
was wrong. Anything decoding outside a plausible window is marked `implausible`,
shown with its decoded value so you can see it, treated as stale, and excluded from
the in-use test. `Currently in use: Yes` is never produced from a timestamp Bluejack
does not trust.

### Findings have stable identities

Every finding carries a `rule_id` (`BJ-PAIR-TRUSTED-UNAUTH`, `BJ-ENC-KNOB-OFF`, …)
and a `finding_id` derived from that rule plus a hash of a **stable** key — a MAC, a
registry path, an InstanceId — rather than the human-readable target. Renaming a
paired device in Windows does not mint a new finding.

### One collector invocation

The Windows collector runs a single PowerShell invocation that returns one JSON
envelope, plus at most one more if the radio state needs a WinRT query. Service
state comes from the SCM through `ctypes` and start type from the registry, so no
`sc.exe` is spawned and nothing depends on parsing localized console output.

---

## CLI

| Flag | Effect |
|---|---|
| `--version` | Tool and JSON schema version |
| `--json` | Full report as JSON |
| `--format human\|json\|ndjson\|quiet` | Output format; `ndjson` is one finding per line |
| `--quiet` | Findings only, one per line |
| `--fail-on critical\|high\|medium\|low\|info\|any\|never` | Lowest severity that exits 1. Default `high` |
| `--exit-zero` | Alias for `--fail-on never` |
| `--stale-days N` | Stale-bond threshold, must be ≥ 1. Default 90 |
| `--role workstation\|conference` | `conference` suppresses inventory-rot and PAN findings |
| `--require-admin` | Exit 2 instead of reporting if any source was unreadable |
| `--width N` | Table width. `0` disables wrapping. Default: terminal width |
| `--no-color` | Never emit ANSI. `NO_COLOR` in the environment does the same |
| `--raise` | Abort on the first source error instead of recording it |

**Exit codes:** `0` below the failure threshold, `1` at or above it, `2` the scan
failed, was refused, or was not run on Windows.

---

## Output formats

`--json` is the complete report: scan metadata, summary, disable state, profiles,
adapters, all three device tables, configuration, findings, collection map, errors
and notes. `schema_version` in the `scan` object tells you what shape to expect.

`--format ndjson` emits one finding per line, each carrying enough scan context —
tool version, host, UTC offset, and whether the scan was complete — to stand alone
after something has split the lines apart.

⚠️ **Both contain your hostname, adapter InstanceIds and every paired MAC address.**
There is no redaction flag yet. Strip them before pasting output into a public issue
or attaching it to anything you do not control.

---

## Colour

Bluejack enables virtual terminal processing on Windows before emitting ANSI, and
falls back to plain text when the console will not accept it. If you see literal
`←[93m` sequences, that is a bug — please report it with your terminal and Windows
build. `--no-color` and `NO_COLOR` both disable colour outright.

---

## Vendor lookup (optional)

Bond MACs are shown with their OUI and an address classification — `public`,
`random-static`, `resolvable-private`, `non-resolvable-private` — which is derived
from the address bits and needs no lookup table. An unmatched OUI on a random BLE
address is expected, not a gap.

The vendor table ships **empty on purpose**: an unverified vendor attribution in a
report is worse than no attribution. To populate it, drop a `bluejack-oui.csv` next
to the module (or point `BLUEJACK_OUI_FILE` at one) with one `aa:bb:cc,Vendor Name`
pair per line. Build it yourself from the IEEE registry; Bluejack will not fetch
anything.

---

## What Bluejack will not do

- Write to the registry, stop `bthserv`, disable the adapter, or pair/unpair
- Dump link keys or any other secret
- Inject L2CAP or HID reports, or spoof advertisements
- Look up CVEs — they rotate, MITRE techniques do not
- Scan Linux BlueZ, macOS, or Android
- Make a network call, ever

If you want a tool that *applies* these settings, that belongs in a separate script
with an explicit `--commit`, a diff, and a rollback note. Writes do not belong in an
auditor.

---

## Testing

```
python -m pytest test_bluejack_fixes.py test_windows_bt.py -v
```

Both suites run on any OS. The audit layer is tested through an injected fake
backend, and the collector through a stubbed PowerShell, so no Windows machine is
required to run them — which is also why bugs in the Windows-specific paths are the
ones most likely to reach you.

---

## Known limitations

- **The PowerShell has had limited real-world exposure.** The WQL filters and the
  batched collector work on the hosts they have been run on. If your report shows
  empty adapter or profile sections, check the *Collector notes* and *Errors*
  sections first — they name which query fell back or failed, and the report records
  which PowerShell version answered.
- Profile detection infers "offered" partly from service state and from service
  GUIDs across all Bluetooth PnP children, which is broader than a per-adapter check.
  Treat a `Yes` as "the stack would accept this", not "this adapter advertises it".
- **Two locally-probed value names are not documented by Microsoft.**
  `Authentication` and `AllowDiscoverableMode` under `BTHPORT\Parameters` are read
  because they are cheap and harmless, but Microsoft documents `AllowDiscoverableMode`
  as a *PolicyManager* value, not a local one, and gives no registry home for
  `Authentication` at all — the Bluetooth authentication setting appears to be a
  runtime radio property rather than a persisted one. Expect both to report `absent`
  on a normal host, and treat the local half of the discoverability drift comparison
  as inert until proven otherwise. The policy-side read is documented and real.
- The ATT&CK actor lists are a **seed**, not an authority. Group-technique mappings
  change between ATT&CK releases. Every entry carries its group ID and every
  technique its URL so you can verify in one click; drop a `bluejack-attack.json`
  next to the module (or point `BLUEJACK_ATTACK_FILE` at one) to override them
  wholesale.
- The `BluetoothControlPanelTasks\state` value used for radio power is undocumented.
  It is consulted first because it is cheap and accurate in practice, with WinRT and
  `Get-NetAdapter` behind it.
- No redaction flag yet, as noted above.

### If your EDR objects

Bluejack spawns PowerShell with `-ExecutionPolicy Bypass` and reads Bluetooth keys
under `HKLM`. That combination resembles things EDR products are tuned to notice.
This is expected for a tool of this shape; the source is short enough to read before
you run it elevated, which is the correct way to treat any script you downloaded.

---

## Roadmap

Nothing here is promised. The tool is close to done for what it is.

- **Baseline diff** — compare against a previously emitted JSON and report what
  changed: new bonds, removed bonds, Trusted/Authenticated transitions, policy
  flips. For one person re-running on their own machine, "what changed since
  Tuesday" is more useful than any absolute snapshot. This is the one remaining
  feature worth building.
- **Redaction** — a `--redact` flag for sharing output.
- Deliberately excluded, permanently: packet injection, advertisement spoofing, HID
  report send, link-key extraction, CVE feeds. They would change what this tool is.

---

## License

MIT — see [LICENSE](LICENSE). Replace the copyright holder line with whatever name
or handle you want attached.

Run it only on systems you own or are authorised to inspect.
