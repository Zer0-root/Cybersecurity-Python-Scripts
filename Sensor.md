# Sensor.py — project status

**Written to survive thread loss.** Everything needed to pick this up cold is
here. Dated 17 September 2026. Companion to `README.md`, which covers usage;
this file covers *where the project is*.

---

## Current state

**3.26.0 / schema 3.26, 12,005 lines, six test suites, 313 assertions, all
green.**

A read-only Windows 11 host auditor that scans obscure peripheral and
root-of-trust surfaces and reports what it found, what it could not establish,
and which source could have lied about each value. Python 3, standalone, no
dependencies outside the standard library.

Eighteen sections: TPM, BitLocker, device inventory, device risk notes,
DMA/Thunderbolt, interception surface, boot integrity, low-level hardware
access, firmware surface, smart-card certificates, generic driver & INF audit,
SDR/TV tuner, historical residue, source trust, posture gaps, findings, host,
collection errors.

| Suite | Assertions | Job |
|---|---|---|
| `test_audit.py` | 25 | rounds 1–3 regression, behavioural |
| `test_hostdata.py` | 145 | host and specification evidence, replayed |
| `test_render.py` | 44 | layout invariants under adversarial fixtures |
| `test_boundary.py` | 14 | attach-to-read key preservation, registry status adjudication |
| `test_hostile.py` | 35 | attacker-controlled input, redaction |
| `test_tier.py` | 50 | tier layer, undetermined rule asserted first |

---

## Direction, decided 17 September 2026

**QUICK-WINS is dropped.** The seven proposed additions — Secure Boot cert
expiry, PKfail, BlackLotus/KB5025885, Secure Boot policy state,
`EnumSystemFirmwareTables`, ACPI DBG2/TPM2/SPCR, SMBIOS 24/43/45 — are **not
being built**. `QUICK-WINS.md` and `QUICKWINS_BUILD_PROMPT.md` are retained as
research, not as a plan.

The reason is worth keeping: analysis established that **none of the seven is
fixable from the OS.** Every one lands in firmware, boot configuration, or is
purely informational, which made the "capability" framing hollow.

**The direction instead:** keep refining what the tool already does best —
scanning ACPI tables, BitLocker, DMA/Thunderbolt and the rest accurately and
precisely — and make points of vulnerability *apparent*. Detect and flag.
**Fixing is the operator's job and the tool should not pretend otherwise.**

### Two consequences, neither implemented yet

**1 · Strip the remediation apparatus.** Present in the script and now out of
scope:

- `TierRow.command` field
- `command=` on **15 of the 20** tier rows
- the `--implement` flag and its `Proposed change:` renderer
- two `PLAN ONLY` disclaimer lines

Recommended split: **remove `command`** (the executable one-liner) and
`--implement`; **keep `mitigation`** as a one-line statement of *what the better
state is*, and **keep `blocked_reason`** for why it is not reachable here. Those
two are descriptive rather than remediation, and without them a Tier B or C row
cannot explain itself. That is a judgment call, not a settled decision.

**2 · Secure Boot state is not collected — and it is the headline thing to
highlight.** Verified: **zero references** to Secure Boot state in the source.
`DEVICE_GUARD_PROPERTIES[2] = 'Secure Boot'` reports *availability*, not whether
it is on.

This is the one tension in the new direction. Highlighting "Secure Boot is
switched off" requires collecting it, and the collector is
`Confirm-SecureBootUEFI` plus `Get-SecureBootUEFI -Name SetupMode` — which was
QUICK-WINS item 4. **So one narrow piece of the dropped work is a prerequisite
for the one capability that was kept.** It is also the lowest-risk of the seven:
documented cmdlets, documented failure modes, and it maps onto the existing
three-state contract with no new vocabulary.

`SetupMode` is worth collecting alongside on/off. A machine in Setup Mode has no
keys enrolled and Secure Boot is effectively unenforced while still reporting as
supported — nothing else surfaces that distinction.

**Code integrity needs no new work.** `BootIntegrityAssessment` already carries
`code_integrity_enabled`, `hvci_enabled`, `test_signing`, `debug_mode`,
`blocklist_enabled` and `ci_flags`, and tier rows already exist for `HVCI-OFF`,
`TESTSIGNING-ON` and `BLOCKLIST-OFF`.

---

## What is built

**Collection.** Firmware tables through `GetSystemFirmwareTable` with an
explicit ctypes prototype and a closed absent-error set (`{1168}`, measured).
SMBIOS walked with a correct double-null string terminator. Registry through two
helpers that **both** return `ok`/`missing`/`denied`. PowerShell with JSON
return and a delivery fallback. Authenticode and service-key reads with NT-path
normalisation done in Python, where fixtures can reach it.

**The tier / highlight layer.** 20 rows across 9 sections. `tier_of()` is
three-valued in and out:

| weak | os_fixable | hw_capable | tier |
|---|---|---|---|
| True | True | True | **A** — fixable from the OS |
| True | False | True | **B** — needs firmware or BIOS |
| True | any | False | **C** — not available on this hardware |
| any | any | any, with **any `None`** | **no row** |

All three tiers highlight — bold yellow on a terminal, a `>>` marker when
redirected. The tier carries the signal, not the presence of colour.

**The rule that matters:** an undetermined value produces **no tier row at
all** — not Tier C, not info, not a greyed variant. Tier C asserts *your
hardware cannot do this*; undetermined means *we did not establish it*.
Conflating them tells a reader their machine lacks a capability it may well
have. Enforced inside `tier_of` so no caller can bypass it.

**Reporting.** Lean and table-driven at a 120-column budget; interpretive prose
lives in `Key.md`. Finding detail behind `--findings`, provenance behind
`--collectors`, both always leaving a count. JSON carries everything the text
does — no flag changes the JSON. An unelevated run says so rather than exiting
silently.

## What is not built

- **Any write path.** No registry or service writes, no rollback capture.
  `--implement` is plan-only and is being removed.
- **Self-elevation.** `ShellExecuteW`/`runas` is designed in `DESIGN-NOTES.md`
  §2.3 and unbuilt. The unelevated notice is the prerequisite, not a substitute.
- **Secure Boot state collection.** See above.
- **`dbx` revocation currency** and **TCG measured-boot log parsing.**
  Researched in `NOVEL-COVERAGE.md`; both are projects, both deferred.

---

## The methodology is the real asset

Nine audit rounds produced a defect taxonomy and a constraint set that outlive
any particular fix. If one thing survives, keep this.

**Eighteen defect classes.** The ones that recur:

| | |
|---|---|
| **D3** | failure-as-negative — a failed read rendering as a clean absence |
| **D12** | verification theatre — source-text assertions that pass on a behavioural regression and fail on a rename |
| **D16** | fixture-certified defect |
| **D17** | laundered fixture — an expected value taken from a host capture *the defect itself produced*. Looks like the strongest evidence available. |
| **D18** | unverified printed claim — every row the terminal prints is a claim, and arithmetic correctness from wrong inputs still counts as unverified |

**Twenty-five constraints.** The six that earned their place:

1. Never make a failure look like a clean negative.
3. An expected value comes from the specification or a host measurement, never
   from the implementation.
19. "The host" means raw command output, never the tool's own report.
20. When a fix changes an input, re-verify everything downstream.
22. A value with two available sources must consult both. **Four** instances so
    far: firmware vs registry, `Get-Tpm` vs registry, the blocklist vs HVCI, and
    the DmaGuard policy status.
24. A three-state value reaching a renderer needs all three states asserted
    before it ships.

**The recurring cause, across every round:** the framework was sound and the
*input or the cascade* went unverified. No defect in this project has been an
architectural failure.

---

## Verification status

Nine audit rounds, six host passes. `HOST-VERIFY.md` through `-4.md` are closed
and `H-*`, `N-*`, `V-*` numbering is retired.

**`HOST-VERIFY-5.md` is written and not yet collected.** Scoped to the tier
layer, `W-*` numbering, thirteen gates, and it states a **falsifiable prediction
per item** rather than asking for raw output blind. On the operator's host it
predicts five certain Tier A rows — `BITLOCKER-WEAK-METHOD`, `CERT-EXPIRED`,
`DMAGUARD-NO-POLICY`, `KERNEL-RW-INSTALLED`, `TPM-OWNER-AUTH-FULL` — plus
`GENERIC-DRIVER-UNBOUND` flagged separately because it has never fired against
real collector output.

**HV-5 predates the direction change.** Removing `--implement` invalidates its
`W-8`; adding Secure Boot collection adds rows to `W-3`. **Amend before
collecting.**

### Three real limits — do not rediscover these

1. **Tier B and Tier C have never rendered on real data.** The operator's host
   produces neither, so two of three rungs ship fixture-verified only. The first
   host producing a Tier B row exercises untested display code.
2. **`INBOX_CLASS_FILTERS` completeness is not establishable from one host.** It
   is a hardcoded allowlist, so `THIRD-PARTY-FILTER` stays manual-only.
3. **`GENERIC-DRIVER-UNBOUND`** was added late and its predicate is unexercised
   end to end.

### Carried, unmeasurable, blocking nothing

`unknown(7)` DeviceGuard security service — no tier row may key on
`SecurityServicesRunning` until it is mapped. `ConvertTo-Json -Depth`
truncation — the test was void, since the identity classes are empty on this
host. `probe.stdin` returning empty at exit 0, unexplained for six rounds and
masked by a working fallback. BCD localization, needing a non-English host.

---

## Next steps, in order

1. **Strip the remediation apparatus** — `command`, `--implement`, the
   `Proposed change` renderer. Settle the `mitigation`/`blocked_reason`
   question.
2. **Add Secure Boot state collection**, narrowly — `Confirm-SecureBootUEFI`
   plus `SetupMode`, landing in **Boot integrity** rather than a new section.
   Two tier rows, `SECUREBOOT-OFF` and `SECUREBOOT-SETUP-MODE`, both Tier B.
3. **Amend `HOST-VERIFY-5.md`** for both, then collect it.
4. **Then** iterate on collection accuracy, which is the stated direction.

Steps 1 and 2 precede collection, because HV-5 measures the report they produce.

---

## Document inventory

**Keep as live**

| | |
|---|---|
| `README.md` | usage |
| `PROJECT-STATUS.md` | this file |
| `Key.md` | the reader's companion — interpretive prose lives here, not in the report |
| `AUDIT.md` … `AUDIT-9.md` | the nine rounds; constraints and defect classes accumulate here |
| `AUDIT-9.md` | also the 20 tier-row claim ledgers |
| `AUDIT-7.md` | the **section-row** claim ledgers — a different artefact from the tier ledgers, deliberately separate |
| `HOST-VERIFY-5.md` | the open verification pass |
| `DESIGN-NOTES.md` | tiering rationale, `--implement` open questions, self-elevation design |
| `HIGHLIGHT-ANALYSIS.md` | the 28-row highlight inventory and the ethos boundary |
| `ENGINEERING-LOG.md` | per-work-item record |

**Research only, not a plan**

`QUICK-WINS.md` and `QUICKWINS_BUILD_PROMPT.md` (dropped 17 Sept 2026);
`NOVEL-COVERAGE.md` and `THREAT-MAPPING-AND-AV-GAP.md` (what this covers that AV
does not); `SEQUENCING.md`, `STRATEGIC-ASSESSMENT.md`, `READINESS-3.24.md`
(superseded by this file); `HOST-VERIFY.md` … `-4.md` (closed).

---

## The ethos, in one paragraph

Surface critical defensive gaps **even when the host's hardware cannot support
the feature**. BitLocker off with no TPM still highlights; no IOMMU at all still
highlights. Someone who bought the machine deserves to learn what protections
they could have had. But highlight a gap between the current state and an
**achievable better state** — absence of an optional feature that *reduces*
attack surface is not a gap, which is why a policy-disabled biometric framework
is reported and never flagged. And the tool's most distinctive property is that
it reports **the boundary of its own knowledge**: `undetermined (not
established)` is a distinct rendering from an absence, everywhere, without
exception. No antivirus does that, and it is why the report can be trusted.
