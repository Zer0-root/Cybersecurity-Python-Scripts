"""Windows sensor, biometric, smart-card, infrared, and TPM assessment.

Purpose
-------
Read-only inventory and risk mapping of identity / presence peripherals and
the hardware root of trust. Intended for incident response and threat hunting
on a hypothetical already-compromised Windows host.

Scope
-----
* PnP classes: Sensor, Biometric, SmartCardReader, Infrared
* Related Windows Hello Face IR imagers classified as Camera/Image
* TPM presence, enablement, activation, ownership, spec, manufacturer, lockout
* BitLocker volume protection status (after TPM), including key-protector types
  without recovery-key material
* Kernel DMA Protection / DmaGuard policy, DmaSecurity AllowedBuses (BitLocker
  OEM exceptions), and PnP devices whose name or ID contains Thunderbolt / USB4
  / TBT — including Present=false nodes that still carry those strings. Not a
  Thunderbolt insert log and not a PCI Enum walk.
* Allowlisted software-defined radios and USB DVB-T sticks (RTL2832, HackRF,
  bladeRF, LimeSDR, USRP, …) including historical Enum last-write — not a
  full USB tree walk
* Historical / phantom Biometric, SmartCardReader, Infrared (and Hello-IR)
  devices from PnP Enum plus WinBio / Calais / Biometrics policy registry
  remnants — not USB mass-storage history

Non-goals
---------
Not an exploit toolkit. Does not disable devices, write firmware, extract
biometric templates, issue smart-card APDUs beyond inventory, or mutate TPM
state (no Clear-Tpm / Enable-Tpm / TakeOwnership).

ATT&CK coverage (Enterprise)
----------------------------
T1056, T1056.001, T1082, T1091, T1111, T1123, T1125, T1195.003, T1200, T1495,
T1497, T1518, T1542, T1542.001, T1550, T1553, T1555, T1556, T1556.006,
T1562, T1562.001, T1600, T1649.

Privileges
----------
Best-effort. TPM and some device properties may require Administrator.
Collection errors are recorded instead of aborting unless on_error='raise'.

REQUIREMENTS
------------
Python 3.11+. Standard library only required.
Optional: wmi, pywin32 (win32com / pythoncom) for native WMI.
PowerShell is used as the reliable Windows fallback. No network calls.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import codecs
import copy
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import unicodedata
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Literal, Sequence

# ---------------------------------------------------------------------------
# Optional native WMI
# ---------------------------------------------------------------------------
try:
    import wmi as _wmi_mod  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    _wmi_mod = None

try:
    import winreg as _winreg
except Exception:  # pragma: no cover
    _winreg = None

LOGGER = logging.getLogger("sensor_assess")

PNP_CLASSES = ("Sensor", "Biometric", "SmartCardReader", "Infrared")

# Generic USB drivers. A device bound to one of these has been detached from
# its class driver and handed raw bulk/control endpoint access in usermode.
# That is the precondition for SDR use, DFU firmware reflashing, and vendor
# control-request work — the binding is the substrate, not the act.
#
# The confidence grading matters. WinUSB is Microsoft's own in-box driver:
# vendors ship WinUSB INFs routinely, and a device advertising MS OS (WCID)
# descriptors is bound automatically with no user action at all, so a WinUSB
# binding is not evidence of intent. libusbK, libusb-win32 and UsbDk have no
# automatic binding path; something installed them deliberately, with admin.
GENERIC_USB_DRIVERS: tuple[tuple[str, str, str, str], ...] = (
    (
        "libusbK",
        "libusbK",
        "strong",
        "No automatic binding path exists. Installation is deliberate and requires "
        "administrator; Zadig is the usual installer.",
    ),
    (
        "libusb0",
        "libusb-win32",
        "strong",
        "Legacy libusb-win32 filter/device driver. No automatic binding path; "
        "installed deliberately, typically via Zadig.",
    ),
    (
        "UsbDk",
        "UsbDk",
        "strong",
        "Redirects whole devices away from their class driver. No automatic "
        "binding path.",
    ),
    (
        "WinUSB",
        "WinUSB",
        "weak",
        "Microsoft in-box generic driver. Legitimate vendor packages ship WinUSB "
        "INFs, and WCID devices bind automatically, so a binding alone is not "
        "evidence of intent. Corroborate with the INF provenance below.",
    ),
)

# Substrings that mark an OEM INF as a generic-driver package. These survive
# removal of the device itself, so they answer "was this ever done here".
GENERIC_DRIVER_INF_MARKERS = ("libusbk", "libusb0", "libusb-win32", "winusb", "usbdk")

SERVICE_START_LABELS = {
    0: "boot",
    1: "system",
    2: "automatic",
    3: "manual",
    4: "disabled",
}

# Bounded so a host with a large INF store cannot stall the scan.
INF_SCAN_FILE_CAP = 400
INF_SCAN_BYTE_CAP = 8192
PS_TIMEOUT_SEC = 30

SCHEMA_VERSION = "3.26"
__version__ = "3.26.0"

OnErrorMode = Literal["collect", "raise"]
Severity = Literal["high", "medium", "low", "info"]
SEVERITY_ORDER: dict[str, int] = {"high": 0, "medium": 1, "low": 2, "info": 3}
Relevance = Literal["direct", "enabling", "absence_risk", "hypothetical_abuse"]

ATTACK_BASE = "https://attack.mitre.org/techniques"

# Embedded FIGlet (standard font) of "Sensor" plus ".py" — no extra dependency.
BANNER = r"""
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
   ____
  / ___|  ___ _ __  ___  ___  _ __
  \___ \ / _ \ '_ \/ __|/ _ \| '__|
   ___) |  __/ | | \__ \ (_) | |
  |____/ \___|_| |_|___/\___/|_|      .py
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""


# ===========================================================================
# Data model
# ===========================================================================


@dataclass
class MitreIndicator:
    technique_id: str
    technique_name: str
    tactic: str
    subtechnique_id: str | None = None
    relevance: Relevance = "enabling"
    rationale: str = ""
    references: list[str] = field(default_factory=list)

    def display_id(self) -> str:
        return self.subtechnique_id or self.technique_id


@dataclass
class DeviceRecord:
    category: str
    name: str
    instance_id: str | None
    status: str
    manufacturer: str | None = None
    hardware_ids: list[str] = field(default_factory=list)
    virtual_or_software: bool = False
    # The inventory's "these are attached now" guarantee lived entirely in the
    # -PresentOnly switch inside a PowerShell string, with nothing in Python
    # able to state it. One string edit, or one host that takes the WMI path
    # instead, and a phantom enters the inventory with no predicate to stop it.
    present: bool | None = None
    problem_code: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    mitre: list[MitreIndicator] = field(default_factory=list)
    risk_notes: list[str] = field(default_factory=list)


@dataclass
class TpmRecord:
    present: bool | None = None
    enabled: bool | None = None
    activated: bool | None = None
    owned: bool | None = None
    ready: bool | None = None
    spec_version: str | None = None
    manufacturer_id: int | None = None
    manufacturer_id_text: str | None = None
    manufacturer_version: str | None = None
    # Presence of locally stored owner authorization, never its value.
    owner_auth_stored: bool | None = None
    owner_auth_status: str | None = None
    os_managed_auth_level: int | None = None
    os_managed_auth_label: str | None = None
    locked_out: bool | None = None
    lockout_count: int | None = None
    lockout_max: int | None = None
    auto_provisioning: str | None = None
    query_failed: bool = False
    # Set when the operator excluded this collector. Distinct from
    # query_failed: nothing was attempted, so nothing can be concluded.
    skipped: bool = False
    query_error: str | None = None
    sources: list[str] = field(default_factory=list)

    def status_label(self) -> str:
        if self.query_failed and self.present is None:
            return "Unknown"
        if self.present is False:
            return "Absent"
        if self.present is None:
            return "Unknown"
        if self.enabled is True:
            return "Enabled"
        if self.enabled is False:
            return "Disabled"
        return "Unknown"


KEY_PROTECTOR_NAMES = {
    0: "Tpm",
    1: "ExternalKey",
    2: "RecoveryPassword",
    3: "TpmPin",
    4: "TpmStartupKey",
    5: "RecoveryKey",
    6: "Password",
    7: "TpmPinStartupKey",
    8: "AdAccountOrSid",
    9: "PublicKey",
    10: "Passphrase",
    11: "TpmNetworkCertificate",
    12: "Sid",
}

_TPM_PROTECTOR_TYPES = {
    "tpm",
    "tpmpin",
    "tpmstartupkey",
    "tpmpinstartupkey",
    "tpmnetworkcertificate",
}


@dataclass
class BitLockerVolume:
    mount_point: str
    protection_status: str
    volume_status: str | None = None
    encryption_method: str | None = None
    encryption_percentage: float | None = None
    key_protectors: list[str] = field(default_factory=list)
    volume_type: str | None = None
    auto_unlock: bool | None = None
    source: str | None = None
    key_protectors_available: bool = True

    @property
    def is_protected(self) -> bool:
        status = (self.protection_status or "").strip().lower()
        return status in {"on", "protected", "1", "true"}

    @property
    def uses_tpm_protector(self) -> bool:
        return any(_normalize_protector(p) in _TPM_PROTECTOR_TYPES for p in self.key_protectors)


@dataclass
class BitLockerRecord:
    query_failed: bool = False
    # Set when the operator excluded this collector. Distinct from
    # query_failed: nothing was attempted, so nothing can be concluded.
    skipped: bool = False
    query_error: str | None = None
    volumes: list[BitLockerVolume] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def any_protected(self) -> bool:
        return any(v.is_protected for v in self.volumes)

    @property
    def all_protected(self) -> bool:
        return bool(self.volumes) and all(v.is_protected for v in self.volumes)

    @property
    def system_volume(self) -> BitLockerVolume | None:
        for vol in self.volumes:
            mount = (vol.mount_point or "").upper()
            vtype = (vol.volume_type or "").lower()
            if vtype in {"operatingsystem", "os", "system"} or mount.startswith("C:"):
                return vol
        return self.volumes[0] if self.volumes else None


# Win32_DeviceGuard enumerations. These are the documented values; the previous
# decoder tested for 4 in AvailableSecurityProperties (Secure Memory Overwrite)
# and 4 in SecurityServicesRunning (SMM firmware measurement), neither of which
# has anything to do with DMA, so the answer was always "Unknown".
DEVICE_GUARD_PROPERTIES = {
    0: "None",
    1: "Hypervisor support",
    2: "Secure Boot",
    3: "DMA protection",
    4: "Secure Memory Overwrite",
    5: "NX protections",
    6: "SMM mitigations",
    7: "Mode Based Execution Control",
    8: "APIC virtualization",
}

DEVICE_GUARD_SERVICES = {
    0: "None",
    1: "Credential Guard",
    2: "HVCI (memory integrity)",
    3: "System Guard Secure Launch",
    4: "SMM firmware measurement",
}

# HKLM\\SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin holds the owner
# authorization Windows retained at provisioning time. Presence only is ever
# read or reported here - the value itself is credential material and is
# covered by the no-secret-material invariant.
# HKLM\\HARDWARE\\ACPI enumerates the firmware tables present on the machine.
# DMAR is Intel VT-d, IVRS is AMD-Vi. Either one means an IOMMU exists; neither
# means Kernel DMA Protection cannot be enforcing whatever policy claims.
# [verify] that DMAR/IVRS surface here on the target hardware - if the key
# enumerates only a handful of tables the result is reported as inconclusive
# rather than as an absence.
# CertPropSvc copies certificates off an inserted smart card into the user's
# personal store. Where they survive, they identify *which* card was used -
# considerably stronger than the Calais ATR mapping, which only proves a
# minidriver was installed.
#
# Two honest limits, both encoded in the output rather than papered over:
#   * There is no insertion timestamp. NotBefore is issuance, not insertion.
#   * Whether entries survive card removal is policy and host dependent, so an
#     empty result is never reported as "no card was ever used".
SMARTCARD_LOGON_EKU = "1.3.6.1.4.1.311.20.2.2"
CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2"
EKU_LABELS = {
    SMARTCARD_LOGON_EKU: "Smart Card Logon",
    CLIENT_AUTH_EKU: "Client Authentication",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
}
# The key provider is the stronger tell; the EKU is the corroboration.
SMARTCARD_PROVIDER_MARKERS = ("smart card", "smartcard", "scard")

# [verify] the policy location on a live host before treating it as definitive.
CERTPROP_POLICY_KEY = "SOFTWARE\\Policies\\Microsoft\\Windows\\CertProp"
CERTPROP_SERVICE_KEY = "SYSTEM\\CurrentControlSet\\Services\\CertPropSvc"

# What the firmware declares to the OS. Reading the table list is a single
# subkey enumeration - the whole inventory costs one registry call, and it is
# the cheapest firmware fingerprint available from userspace.
#
# [verify] a few signatures against the target hardware; vendors ship tables
# that never appear in the specifications.
ACPI_TABLE_NOTES = {
    "DMAR": "Intel VT-d DMA remapping (IOMMU present)",
    "IVRS": "AMD-Vi I/O virtualization (IOMMU present)",
    "TPM2": "TPM 2.0 interface declared",
    "TCPA": "TPM 1.2 interface declared",
    "WSMT": "SMM security mitigations declared",
    "WPBT": "firmware-supplied executable that Windows runs at every boot",
    "DBG2": "firmware debug port declared",
    "DBGP": "firmware debug port declared (legacy)",
    "MSDM": "OEM Windows licence key table",
    "SLIC": "OEM licensing table",
    "BGRT": "boot graphics",
    "FPDT": "firmware performance data",
    "IORT": "IO remapping (ARM IOMMU)",
    "SDEV": "secure device table",
    "NHLT": "audio endpoints (microphone array topology)",
    "HPET": "high precision event timer",
    "MCFG": "PCIe memory-mapped configuration",
    "SRAT": "NUMA affinity",
    "APIC": "interrupt controller",
    "FACP": "fixed ACPI description",
    "DSDT": "differentiated system description",
    "SSDT": "secondary system description",
}

# Tables worth saying something about when they are present, or absent.
# GetSystemFirmwareTable can hand back the raw bytes of an ACPI table, which
# means WPBT can be read rather than merely counted. The table carries the size
# of the firmware-supplied executable and the command line it is launched with.
# The binary itself lives at a physical address that needs a driver to reach -
# but the session manager writes it to disk on the way, which does not.
FIRMWARE_PROVIDER_RSMB = 0x52534D42  # 'RSMB' - raw SMBIOS table
SMBIOS_HEADER_LEN = 8  # Windows prepends its own RawSMBIOSData header

# SMBIOS structure types worth pulling out. Everything else is counted and
# reported as present without being decoded.

# Type 3 Security Status. Documented as external-interface state - it is not a
# chassis intrusion latch, and this tool does not present it as one.
SMBIOS_SECURITY_STATUS = {
    1: "other",
    2: "unknown",
    3: "none",
    4: "external interface locked out",
    5: "external interface enabled",
}

SMBIOS_CHASSIS_TYPES = {
    3: "desktop", 4: "low profile desktop", 6: "mini tower", 7: "tower",
    8: "portable", 9: "laptop", 10: "notebook", 13: "all in one",
    14: "sub notebook", 23: "rack mount chassis", 30: "tablet", 31: "convertible",
}

FIRMWARE_PROVIDER_ACPI = 0x41435049  # 'ACPI'
# Table ids are byte-reversed relative to the provider signature: the API docs
# require the characters of the signature in reverse order.
DMAR_TABLE_ID = 0x52414D44  # 'DMAR' reversed - Intel VT-d
IVRS_TABLE_ID = 0x53525649  # 'IVRS' reversed - AMD-Vi
WPBT_TABLE_ID = 0x54425057  # 'WPBT' as a little-endian DWORD
WSMT_TABLE_ID = 0x544D5357  # 'WSMT'

# WSMT protection flags. Each is the firmware *asserting* it validates
# something - Windows records the claim and never tests it. Note what these
# do and do not cover: they address SMI handlers being tricked into writing
# into SMRAM through an unvalidated communication buffer. They say nothing
# about SMM callouts, where SMM code executes an address outside SMRAM; that
# is a separate chipset mitigation (SMM code access check) which is not
# reported through this table at all.
WSMT_PROTECTION_FLAGS = {
    0x1: "fixed communication buffers",
    0x2: "nested pointer protection",
    0x4: "system resource protection",
}  # 'WPBT' as a little-endian DWORD
ACPI_HEADER_LEN = 36
# The binary WPBT hands over is written here by the session manager.
# [verify] the path on a host that actually has WPBT.
WPBT_DROPPED_BINARY = "System32\\wpbbin.exe"

# Firmware from before roughly 2018 predates most of the mitigations this
# section reports on, so the release date is context for everything else.
FIRMWARE_MITIGATION_ERA = 2018

ACPI_NOTABLE_PRESENT = ("WPBT", "DBG2", "DBGP")

@dataclass(frozen=True)
class AnticheatEntry:
    """One tracked anti-cheat service.

    Parallel dicts keyed by driver name were getting out of step with the tuple
    table every time an entry moved. One record per anti-cheat, and the
    hardware-access table is built from it.
    """

    service: str          # exact service name; a trailing * matches by prefix
    vendor: str           # short vendor / product, sized for a table cell
    titles: str           # games that ship it, for the roster
    basis: str            # cve | incident | footprint
    note: str             # why it is tracked; the long form lives in Key.md
    ref: str              # the citation itself, sized for a table cell
    capabilities: tuple[str, ...] = ("kernelrw",)

    @property
    def name(self) -> str:
        return self.service[:-1] if self.service.endswith("*") else self.service


# Tracked anti-cheat, one record each. Three bases for inclusion, kept distinct
# rather than blurred, because they are not the same claim:
#
#   cve       - a CVE against the driver itself
#   incident  - publicly documented use against a host it was installed on
#   footprint - no published abuse; tracked because it is a persistent kernel
#               driver from this class of vendor and an operator wants to know
#               it is there
#
# This is still not a vulnerable-driver database. The boot integrity section's
# blocklist check is the control that covers the general case; this is a short
# roster of drivers a defender is likely to actually meet on a workstation.
#
# THE SERVICE NAMES ARE THE DETECTION. Each is the name under
# SYSTEM\\CurrentControlSet\\Services, which is not always the marketing name
# and not always the .sys filename. One wrong character is a silent false
# negative across the registry read, the CIM -like filter and the
# Enum\\Root\\LEGACY_ lookup at once. Tencent ACE registers ACE-BASE with a
# HYPHEN; an earlier revision used an underscore and never matched a live host.
# Verify with `sc query <name>` before editing.
#
# Versioned drivers get one record each rather than a prefix wildcard, because
# resolve_service_name() returns only the first match and mhyprot2 / mhyprot3
# can be installed side by side.
ANTICHEAT_ENTRIES: tuple[AnticheatEntry, ...] = (
    AnticheatEntry(
        "ACE-BASE", "Tencent ACE", "Delta Force, CrossFire, Arena Breakout, Naraka",
        "cve",
        "CVE-2024-22830: ACE-BASE.sys does not access-control its handling of "
        "system resources, letting a local user escalate to SYSTEM or PPL",
        ref="CVE-2024-22830",
    ),
    AnticheatEntry(
        "ACE-GAME", "Tencent ACE", "per-title half of the ACE pair",
        "footprint", "companion driver to ACE-BASE, installed by the same installer",
        ref="companion to ACE-BASE",
    ),
    AnticheatEntry(
        "TesSafe", "Tencent TenProtect", "older Tencent titles, WeGame",
        "footprint", "the pre-2021 TenProtect generation of ACE; Tencent kernel driver",
        ref="no published case",
    ),
    AnticheatEntry(
        "tesrsdt", "Tencent TenProtect", "older Tencent titles, WeGame",
        "footprint",
        "[verify] Tencent kernel driver reported by Windows memory integrity as "
        "an incompatible driver, which is Microsoft flagging it, not a CVE",
        ref="[verify] MS HVCI block",
    ),
    AnticheatEntry(
        "mhyprot2", "miHoYo", "Genshin Impact",
        "incident",
        "Trend Micro, Aug 2022: loaded by a ransomware actor to terminate endpoint "
        "protection from kernel mode. The game does not need to be installed for "
        "the driver to work, and public kernel read/write PoCs date to 2020",
        ref="Trend Micro, Aug 2022",
    ),
    AnticheatEntry(
        "mhyprot3", "miHoYo", "Genshin Impact, Honkai, Zenless Zone Zero",
        "footprint", "successor to mhyprot2; same vendor, same class of interface",
        ref="no published case",
    ),
    AnticheatEntry(
        "NeacSafe64", "NetEase NeacProtect", "Marvel Rivals, Where Winds Meet, FragPunk",
        "cve",
        "CVE-2025-45737: versions before v1.0.0.8 expose IOCTL handlers giving "
        "arbitrary kernel read/write, chainable to SYSTEM and to kernel-mode code "
        "execution. Catalogued on LOLDrivers with a public exploit",
        ref="CVE-2025-45737",
    ),
    AnticheatEntry(
        "NeacSafe", "NetEase NeacProtect", "Marvel Rivals, Where Winds Meet, FragPunk",
        "footprint",
        "32-bit / alternate name of the NeacProtect kernel component. NetEase loads "
        "it on demand and unloads it with the game, so the service key is often "
        "absent and the device node is the only residue",
        ref="no published case",
    ),
    AnticheatEntry(
        "GameDriverX64", "Hotta Studio", "Tower of Fantasy",
        "cve",
        "CVE-2025-61155: an IOCTL handler in GameDriverX64.sys v7.23.4.7 and "
        "earlier runs without access validation, letting an unprivileged local "
        "user terminate arbitrary processes including antivirus and core services",
        ref="CVE-2025-61155",
    ),
    AnticheatEntry(
        "xhunter1", "Wellbia XIGNCODE3", "Black Desert, TERA, CABAL, many CN/KR titles",
        "cve",
        "CVE-2026-3609 / KVE-2023-5589: the driver hands PROCESS_ALL_ACCESS to any "
        "caller for any process, including PPL targets such as lsass.exe",
        ref="CVE-2026-3609 / KVE-2023-5589",
    ),
    AnticheatEntry(
        "vgk", "Riot Vanguard (Tencent)", "VALORANT, League of Legends",
        "footprint",
        "no published abuse case. Tracked because it is boot-start: vgk.sys loads "
        "at every boot whether or not the game is launched, which is a wider "
        "residency than anything else on this list",
        ref="no published case; boot-start",
    ),
    AnticheatEntry(
        "gse", "unattributed", "unknown",
        "footprint",
        "[verify] no public abuse report located and no vendor confirmed; carried "
        "from an earlier revision of this table and due for removal",
        ref="[verify] unsourced",
    ),
    # User-mode halves. No kernel interface of their own, but they are installed
    # and removed on a different schedule from the drivers, so one surviving
    # without the other is evidence the removal was partial. Win32_SystemDriver
    # does not return these; the registry key is the whole evidence.
    AnticheatEntry(
        "AntiCheatExpert Service", "Tencent ACE", "ships beside ACE-BASE / ACE-GAME",
        "footprint", "user-mode component of the ACE stack", ref="user-mode half of ACE", capabilities=("acsvc",),
    ),
    AnticheatEntry(
        "AntiCheatExpert Protection", "Tencent ACE", "ships beside ACE-BASE / ACE-GAME",
        "footprint", "user-mode component of the ACE stack", ref="user-mode half of ACE", capabilities=("acsvc",),
    ),
    AnticheatEntry(
        "vgc", "Riot Vanguard (Tencent)", "ships beside vgk",
        "footprint", "user-mode service half of Vanguard", ref="user-mode half of Vanguard", capabilities=("acsvc",),
    ),
)

# Long-form basis labels. The roster prints the reference itself; these are the
# expansion, and Key.md documents what each basis claims.
ANTICHEAT_BASIS_LABELS = {
    "cve": "CVE against the driver",
    "incident": "documented abuse in the wild",
    "footprint": "kernel footprint; no CVE",
}

ABUSED_ANTICHEAT_DRIVERS: tuple[tuple[str, str, tuple[str, ...], str], ...] = tuple(
    (e.name, e.service, e.capabilities, e.vendor) for e in ANTICHEAT_ENTRIES
)

ANTICHEAT_BY_NAME: dict[str, AnticheatEntry] = {e.name: e for e in ANTICHEAT_ENTRIES}

# Membership, not capability, is what makes something anti-cheat. Deriving this
# from the table means a future HW_ACCESS_DRIVERS entry that happens to grant
# kernel read/write cannot silently be reported as a game anti-cheat.
ANTICHEAT_DRIVER_NAMES: frozenset[str] = frozenset(ANTICHEAT_BY_NAME)

# Voltage and frequency fault injection (Plundervolt, V0LTpwn, VoltJockey and
# relatives) needs writes to model-specific registers - MSR 0x150 on Intel for
# the undervolt mailbox. Usermode cannot write an MSR. It needs a kernel driver
# that exposes one, so the *capability* is what an auditor can see; the attack
# itself is live behaviour and belongs to EDR.
#
# This is not a vulnerable-driver database. Every entry below is a driver whose
# documented purpose is arbitrary hardware access - a short list that barely
# changes, not a CVE feed that goes stale. Most are shipped by legitimate
# monitoring and overclocking tools, which is exactly why presence alone is
# reported as capability rather than compromise.
#
# [verify] capability details per driver; they are recorded from public
# documentation and vary by version.
HW_ACCESS_DRIVERS: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("WinRing0", "WinRing0", ("msr", "physmem", "portio", "pci"),
     "OpenLibSys; LibreHardwareMonitor, OpenHardwareMonitor, ThrottleStop"),
    ("WinRing0x64", "WinRing0x64", ("msr", "physmem", "portio", "pci"),
     "OpenLibSys 64-bit build"),
    ("RTCore64", "RTCore64", ("msr", "physmem"), "MSI Afterburner"),
    ("RwDrv", "RwDrv", ("msr", "physmem", "portio", "pci"), "RWEverything"),
    ("AsrDrv101", "AsrDrv101", ("msr", "physmem"), "ASRock tuning utilities"),
    ("AsrDrv102", "AsrDrv102", ("msr", "physmem"), "ASRock tuning utilities"),
    ("AsrDrv103", "AsrDrv103", ("msr", "physmem"), "ASRock tuning utilities"),
    ("AsIO", "AsIO", ("physmem", "portio"), "ASUS system control"),
    ("AsIO2", "AsIO2", ("physmem", "portio"), "ASUS system control"),
    ("AsIO3", "AsIO3", ("physmem", "portio"), "ASUS system control"),
    ("GLCKIO2", "GLCKIO2", ("msr", "physmem"), "ASUS overclocking"),
    ("gdrv", "gdrv", ("msr", "physmem"), "Gigabyte utilities"),
    ("EneIo", "EneIo", ("physmem",), "ENE lighting control"),
    ("EneTechIo", "EneTechIo", ("physmem",), "ENE lighting control"),
    ("iqvw64e", "iqvw64e", ("physmem",), "Intel Ethernet diagnostics"),
    ("inpout32", "inpout32", ("portio",), "InpOut port I/O library"),
    ("inpoutx64", "inpoutx64", ("portio",), "InpOut port I/O library, 64-bit"),
    ("phymem", "phymem", ("physmem",), "generic physical memory driver"),
    ("DirectIo64", "DirectIo64", ("physmem", "portio"), "DirectIO"),
    ("HwRwDrv", "HwRwDrv", ("msr", "physmem"), "hardware read/write driver"),
    ("XtuAcpiDriver", "XtuAcpiDriver", ("msr",), "Intel Extreme Tuning Utility"),
    # Versioned service names: a trailing * matches by prefix.
    ("AMDRyzenMasterDriver", "AMDRyzenMasterDriver*", ("msr", "physmem"),
     "AMD Ryzen Master"),
    ("AMDPowerProfiler", "AMDPowerProfiler*", ("msr",), "AMD uProf power profiler"),
    ("AMDRyzenMasterSvc", "AMDRyzenMasterSvc*", ("msr",), "AMD Ryzen Master service"),
) + ABUSED_ANTICHEAT_DRIVERS

# Where a driver binary lives is the strongest attribution available without
# privileged handle enumeration. WinRing0 under a vendor's Program Files
# directory is a hardware monitor; the same file under %TEMP% is not.
# Windows creates a device node under Enum\\Root\\LEGACY_<SERVICE> when a
# non-PnP kernel driver service starts, and does not remove it when the service
# is deleted. The node outliving its service is durable evidence that a driver
# by that name ran on this host and was then taken away.
LEGACY_ENUM_ROOT = "SYSTEM\\CurrentControlSet\\Enum\\Root"
LEGACY_PREFIX = "LEGACY_"

DRIVER_SYSTEM_MARKERS = (
    "\\system32\\drivers\\", "\\syswow64\\drivers\\",
    # Not every driver lands in the drivers subdirectory. TesSafe.sys installs
    # to System32 itself, and without these a correctly-installed driver
    # classified as "unknown location".
    "\\windows\\system32\\", "\\windows\\syswow64\\",
)
# A .sys sitting directly in C:\Windows is not where any installer puts a
# driver, but it is not user-writable either, so neither existing class fits.
# XIGNCODE3 drops xhunter1.sys exactly here. Reported as its own class rather
# than silently as "unknown".
DRIVER_WINDOWS_ROOT_MARKERS = ("\\windows\\",)
DRIVER_VENDOR_MARKERS = ("\\program files\\", "\\program files (x86)\\")
# Directories shared by the whole OS. A process running out of one of these is
# not a co-located client - it just lives in the same place everything does.
# Without this, any driver in C:\Windows was "attributed" to explorer.exe.
DRIVER_SHARED_DIRECTORIES = (
    "c:\\windows",
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\system32\\drivers",
    "c:\\windows\\syswow64\\drivers",
    "c:\\windows\\temp",
)
DRIVER_USER_WRITABLE_MARKERS = (
    "\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\",
    "\\public\\", "\\programdata\\",
)

HW_CAPABILITY_LABELS = {
    "kernelrw": "arbitrary kernel read/write",
    "msr": "MSR read/write",
    "physmem": "physical memory",
    "portio": "port I/O",
    "pci": "PCI config space",
    # Not a hardware capability. Present so the user-mode halves of an
    # anti-cheat stack render a truthful cell instead of an empty one.
    "acsvc": "user-mode service (no kernel interface)",
}

# SYSTEM_CODEINTEGRITY_INFORMATION flags, from NtQuerySystemInformation class
# 103. This is the *effective* kernel state, not what was configured - which is
# why it is worth having alongside the boot configuration.
# [verify] the flags above 0x80 against a live host; the low four and HVCI are
# the ones this tool acts on.
CODE_INTEGRITY_FLAGS = {
    0x0001: "enabled",
    0x0002: "test signing",
    0x0004: "user-mode CI enabled",
    0x0008: "user-mode CI audit mode",
    0x0010: "user-mode CI exclusion paths",
    0x0020: "test build",
    0x0040: "preproduction build",
    0x0080: "debug mode",
    0x0100: "flight build",
    0x0200: "flighting enabled",
    0x0400: "HVCI kernel-mode CI",
    0x0800: "HVCI audit mode",
    0x1000: "HVCI strict mode",
}
CI_ENABLED = 0x0001
CI_TESTSIGN = 0x0002
CI_DEBUGMODE = 0x0080
CI_HVCI = 0x0400
SYSTEM_CODE_INTEGRITY_INFORMATION = 103

# Boot Configuration Data values that decide whether unsigned kernel code can
# load. A fixed handful on one object - nothing is enumerated, and this has no
# relationship to vulnerable-driver databases.
# Microsoft's vulnerable driver blocklist is the supported mitigation for the
# whole bring-your-own-driver class. Checking whether it is enforced is one
# registry read and covers every driver in it - which is why this tool checks
# the mitigation rather than trying to maintain a driver database of its own.
CI_CONFIG_KEY = "SYSTEM\\CurrentControlSet\\Control\\CI\\Config"
BLOCKLIST_VALUE = "VulnerableDriverBlocklistEnable"

BCD_FLAGS_OF_INTEREST = (
    "testsigning",
    "nointegritychecks",
    "debug",
    "bootdebug",
    "hypervisorlaunchtype",
    "vsmlaunchtype",
    "flightsigning",
    "integrityservices",
)

# Windows populates this from the UEFI System Resource Table. Each subkey is a
# firmware component that can be updated by capsule - system firmware, the
# management engine, TPM firmware, device firmware - with its current version
# and the outcome of the last update attempt. A failed attempt is worth seeing.
FIRMWARE_RESOURCES_KEY = "SYSTEM\\CurrentControlSet\\Control\\FirmwareResources"

# ACPI\\PNP0C14 is the WMI-ACPI mapper: firmware exposing WMI methods that the
# OS can call straight into. OEM management interfaces live here, and several
# have historically allowed far more than intended.
ACPI_WMI_ENUM_KEY = "SYSTEM\\CurrentControlSet\\Enum\\ACPI\\PNP0C14"

# Microcode revision. Relevant here because the mitigation that locks the Intel
# undervolt mailbox shipped as microcode, so this is the closest a read-only
# audit gets to "is Plundervolt still reachable on this silicon".
CPU_KEY = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"

BIOS_INFO_KEY = "HARDWARE\\DESCRIPTION\\System\\BIOS"

# The device property store. Get-PnpDeviceProperty makes one CIM round trip per
# device per property set, which is why the historical sweep - six classes with
# absent devices included - was the slowest query in the tool by an order of
# magnitude. The same values sit in the registry under each device's Enum key
# and read in microseconds.
#
# [verify] the property IDs on a live host. They are the low 16 bits of the
# DEVPKEY PID, written as four hex digits.
# Device setup class keys. Windows lets extra drivers be inserted into a class
# stack above or below the real driver - UpperFilters and LowerFilters. This is
# supported functionality, not an exploit, which is exactly why it is a good
# place to sit: an upper filter on the Keyboard class sees every keystroke
# before Windows does, and one on the Biometric class sits between the sensor
# and everything downstream.
#
# Filters are positional. There are only so many places to stand, so this is a
# bounded read - one key per class - not a driver enumeration.
INTERCEPTION_CLASSES = (
    ("Keyboard", "{4d36e96b-e325-11ce-bfc1-08002be10318}", "keystrokes"),
    ("Mouse", "{4d36e96f-e325-11ce-bfc1-08002be10318}", "pointer input"),
    ("HIDClass", "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}", "raw HID reports"),
    ("Biometric", "{53d29ef7-377c-4d14-864b-eb3a85769359}", "biometric samples"),
    ("SmartCardReader", "{50dd5230-ba8a-11d1-bf5d-0000f805f530}", "smart-card traffic"),
    ("Sensor", "{5175d334-c371-4806-b3ba-71fd53c9258d}", "sensor readings"),
    ("Camera", "{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}", "camera frames"),
    ("Image", "{6bdd1fc6-810f-11d0-bec7-08002be2092f}", "imaging device data"),
)

# Filters Windows ships or that arrive with mainstream input hardware. Anything
# outside this set is reported as additional - which is not the same as bad.
INBOX_CLASS_FILTERS = {
    # Input stacks
    "kbdclass", "mouclass", "kbdhid", "mouhid", "i8042prt", "sermouse",
    "hidusb", "hidclass", "terminpt", "hyperkbd", "vmusbmouse",
    # Smart card: scfilter is the Microsoft smart-card class filter and ships
    # with Windows. Treating it as additional raised a false high-severity
    # finding on an identity class.
    "scfilter",
    # Kernel streaming thunk, present on Camera and Image on every Windows host
    "ksthunk", "hypervideo",
    # Driver framework and bus plumbing
    "wudfpf", "wdmcompanionfilter", "usbccgp", "wmiacpi",
}

# The Windows Biometric Framework splits fingerprint handling into three
# replaceable DLLs, registered per device. The engine adapter is the one handed
# the raw sample in the clear, so a third-party DLL in that slot is not
# breaking anything - it has been given the fingerprint by design.
WINBIO_ADAPTER_VALUES = ("SensorAdapterBinary", "EngineAdapterBinary", "StorageAdapterBinary")
WINBIO_INBOX_ADAPTERS = {
    "winbiosensoradapter.dll", "winbioengineadapter.dll", "winbiostorageadapter.dll",
}

DEVPKEY_DEVICE_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
DEVPKEY_TIMESTAMP_PIDS = {
    "0064": "DEVPKEY_Device_InstallDate",
    "0065": "DEVPKEY_Device_FirstInstallDate",
    "0066": "DEVPKEY_Device_LastArrivalDate",
    "0067": "DEVPKEY_Device_LastRemovalDate",
}

ACPI_ROOT_KEY = "HARDWARE\\ACPI"
IOMMU_ACPI_TABLES = ("DMAR", "IVRS")
ACPI_MIN_TABLES_FOR_ABSENCE = 4

TPM_OWNER_AUTH_KEY = "SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin"
TPM_OWNER_AUTH_VALUE = "OwnerAuthFull"
TPM_POLICY_KEY = "SOFTWARE\\Policies\\Microsoft\\TPM"

# "Configure the level of TPM owner authorization information available to the
# operating system". [verify] the numeric mapping against a live host before
# treating a specific level as authoritative.
TPM_AUTH_LEVEL_LABELS = {
    0: "none (nothing retained)",
    2: "delegated (default)",
    4: "full (complete owner auth retained)",
}

DMA_GUARD_POLICY_LABELS = {
    0: "Block all",
    1: "Only after logon / unlock",
    2: "Allow all",
}


@dataclass
class DmaController:
    name: str
    instance_id: str | None = None
    present: bool = False
    status: str | None = None
    manufacturer: str | None = None
    last_write_utc: str | None = None
    source: str = "pnp-enum"


@dataclass
class AllowedBus:
    name: str
    hardware_id: str | None = None


@dataclass
class DmaAssessment:
    query_failed: bool = False
    # Set when the operator excluded this collector. Distinct from
    # query_failed: nothing was attempted, so nothing can be concluded.
    skipped: bool = False
    query_error: str | None = None
    # "Available" / "Not available" / "Unknown" — this is the platform
    # capability Win32_DeviceGuard reports, not a confirmed on/off state.
    kernel_dma_protection: str | None = None
    dma_protection_available: bool | None = None
    device_guard_properties: list[str] = field(default_factory=list)
    device_guard_services_running: list[str] = field(default_factory=list)
    # Independent corroboration for kernel_dma_protection: firmware tables say
    # whether an IOMMU physically exists, which Win32_DeviceGuard does not.
    acpi_tables: list[str] = field(default_factory=list)
    acpi_status: str | None = None
    iommu_table: str | None = None
    iommu_present: bool | None = None
    dma_guard_policy: int | None = None
    dma_guard_policy_label: str | None = None
    # P-5: which read established the policy value. Without it, `None` meant
    # key-absent, value-absent, denied OR unparseable, and the tier layer
    # asserted a gap from all four.
    dma_guard_policy_status: str | None = None
    allowed_buses: list[AllowedBus] = field(default_factory=list)
    controllers: list[DmaController] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def thunderbolt_present(self) -> bool:
        return any(c.present for c in self.controllers)

    @property
    def thunderbolt_historical(self) -> list[DmaController]:
        return [c for c in self.controllers if not c.present]


SDR_ALLOWLIST: tuple[tuple[str, str, str], ...] = (
    ("0BDA", "2832", "RTL2832U"),
    ("0BDA", "2838", "RTL2832U OEM"),
    ("0BDA", "2831", "RTL2832 variant"),
    ("1D50", "6089", "HackRF One"),
    ("1D50", "604B", "HackRF Jawbreaker"),
    ("1D50", "CC15", "rad1o"),
    ("1FC9", "000C", "NXP DFU (HackRF)"),
    ("2CF0", "5246", "bladeRF"),
    ("2CF0", "5250", "bladeRF 2.0 micro"),
    ("1D50", "6066", "bladeRF"),
    ("04B4", "00F3", "Cypress FX3 (bladeRF bootloader)"),
    ("1D50", "6108", "LimeSDR"),
    ("1D50", "6107", "LimeSDR Mini"),
    ("0403", "601F", "LimeSDR-USB"),
    ("2500", "0020", "Ettus USRP"),
    ("3923", "7813", "NI USRP"),
    ("1D50", "60A1", "Airspy"),
    ("1DF7", "2500", "SDRplay"),
)

SDR_NAME_NEEDLES = (
    "rtl2832",
    "rtl-sdr",
    "rtl sdr",
    "dvb-t",
    "dvbt",
    "hackrf",
    "bladerf",
    "limesdr",
    "usrp",
    "airspy",
    "sdrplay",
    "rtl2838",
)


@dataclass
class SdrDevice:
    name: str
    instance_id: str | None = None
    present: bool = False
    status: str | None = None
    vid_pid: str | None = None
    allowlist_hit: str | None = None
    last_write_utc: str | None = None
    source: str = "pnp-enum"
    manufacturer: str | None = None


@dataclass
class SdrAssessment:
    query_failed: bool = False
    # Set when the operator excluded this collector. Distinct from
    # query_failed: nothing was attempted, so nothing can be concluded.
    skipped: bool = False
    query_error: str | None = None
    devices: list[SdrDevice] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def present_devices(self) -> list[SdrDevice]:
        return [d for d in self.devices if d.present]

    @property
    def historical_devices(self) -> list[SdrDevice]:
        return [d for d in self.devices if not d.present]


@dataclass
class ClassFilter:
    device_class: str
    class_guid: str
    position: str          # UpperFilters | LowerFilters
    driver: str
    sees: str | None = None
    inbox: bool = False
    service_present: bool | None = None
    image_path: str | None = None
    start_label: str | None = None


@dataclass
class BiometricAdapter:
    instance_id: str | None = None
    device_name: str | None = None
    slot: str = ""         # sensor | engine | storage
    binary: str | None = None
    inbox: bool = False


@dataclass
class InterceptionAssessment:
    """What sits between an input device and the software that consumes it."""

    query_failed: bool = False
    # Set when the operator excluded this collector. Distinct from
    # query_failed: nothing was attempted, so nothing can be concluded.
    skipped: bool = False
    query_error: str | None = None
    filters: list[ClassFilter] = field(default_factory=list)
    adapters: list[BiometricAdapter] = field(default_factory=list)
    classes_checked: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def additional_filters(self) -> list[ClassFilter]:
        return [f for f in self.filters if not f.inbox]

    @property
    def input_filters(self) -> list[ClassFilter]:
        """Additional filters on classes that carry credentials or identity."""
        watched = {"Keyboard", "Biometric", "SmartCardReader", "HIDClass"}
        return [f for f in self.additional_filters if f.device_class in watched]

    @property
    def third_party_adapters(self) -> list[BiometricAdapter]:
        return [a for a in self.adapters if not a.inbox]

    @property
    def engine_adapters(self) -> list[BiometricAdapter]:
        return [a for a in self.third_party_adapters if a.slot == "engine"]

    @property
    def verdict(self) -> str:
        if self.query_failed:
            return "unknown"
        if self.input_filters:
            return "additional filter on an identity class"
        if self.third_party_adapters:
            return "third-party biometric adapter"
        if self.additional_filters:
            return "additional filters present"
        return "clear"


@dataclass
class BootIntegrityAssessment:
    """Whether this machine will load unsigned kernel code.

    Two independent sources: the kernel's own effective code-integrity state,
    and the boot configuration that was asked for. They should agree.
    """

    query_failed: bool = False
    # Set when the operator excluded this collector. Distinct from
    # query_failed: nothing was attempted, so nothing can be concluded.
    skipped: bool = False
    query_error: str | None = None
    ci_options: int | None = None
    ci_flags: list[str] = field(default_factory=list)
    ci_status: str | None = None
    test_signing: bool | None = None
    code_integrity_enabled: bool | None = None
    debug_mode: bool | None = None
    hvci_enabled: bool | None = None
    blocklist_enabled: bool | None = None
    blocklist_status: str | None = None
    bcd_status: str | None = None
    bcd_flags: dict[str, str] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

    @property
    def bcd_testsigning(self) -> bool | None:
        value = self.bcd_flags.get("testsigning")
        return None if value is None else value.strip().lower() in ("yes", "on", "true")

    @property
    def bcd_integrity_disabled(self) -> bool | None:
        value = self.bcd_flags.get("nointegritychecks")
        return None if value is None else value.strip().lower() in ("yes", "on", "true")

    @property
    def unsigned_kernel_code_permitted(self) -> bool | None:
        """Would this machine load a driver that fails signature verification?"""
        signals = [self.test_signing, self.bcd_testsigning, self.bcd_integrity_disabled]
        if any(s is True for s in signals):
            return True
        if all(s is False for s in signals if s is not None) and any(
            s is not None for s in signals
        ):
            return False
        return None

    @property
    def verdict(self) -> str:
        if self.query_failed:
            return "unknown"
        permitted = self.unsigned_kernel_code_permitted
        if permitted is True:
            return "unsigned kernel code PERMITTED"
        if permitted is False:
            return "enforcing"
        return "undetermined"


@dataclass
class HardwareAccessDriver:
    driver: str
    service: str
    present: bool = False
    start_type: int | None = None
    start_label: str | None = None
    image_path: str | None = None
    capabilities: list[str] = field(default_factory=list)
    capability_labels: list[str] = field(default_factory=list)
    shipped_by: str | None = None
    bound_instances: int = 0
    # Runtime state, from Win32_SystemDriver. The registry says a driver is
    # installed; only this says something currently has it loaded.
    running: bool | None = None
    runtime_state: str | None = None
    # Enum\\Root\\LEGACY_<name> residue. Present without a service means the
    # driver ran here and was removed.
    legacy_node: bool = False
    legacy_last_write_utc: str | None = None
    # Where the binary lives, and what that attributes it to.
    location_class: str | None = None
    attributed_to: str | None = None
    signature_status: str | None = None
    signer: str | None = None
    # Processes running out of the driver's own directory. Not proof of who
    # holds the handle, but in practice a client ships beside its driver.
    client_processes: list[str] = field(default_factory=list)
    # Set from ANTICHEAT_DRIVER_NAMES at collection time. Anti-cheat is a fact
    # about which table an entry came from, not something to re-derive from
    # capability flags downstream.
    is_anticheat: bool = False
    abuse_note: str | None = None
    resolved_path: str | None = None
    signer_not_after: str | None = None
    signature_timestamped: bool | None = None

    @property
    def signature_trusted(self) -> bool | None:
        if not self.signature_status:
            return None
        low = self.signature_status.lower()
        if low == "valid":
            return True
        # "file missing" is not a failed verification - there was nothing to
        # verify. Grading it False raised a high-severity "signature does not
        # verify" finding on drivers whose only fault was that the uninstaller
        # took the .sys and left the service key.
        # Exact membership again - the token is canonical once more.
        if low in ("not checked", "check failed", "file missing"):
            return None
        return False
    # When the service key was last written - when the capability was
    # established on this host, which is the closest thing to a timestamp
    # that exists for it.
    installed_utc: str | None = None

    @property
    def grants_msr(self) -> bool:
        return "msr" in self.capabilities

    @property
    def grants_kernel_rw(self) -> bool:
        return "kernelrw" in self.capabilities

    @property
    def unattributed(self) -> bool:
        """Present, but nothing accounts for it.

        A user-writable path, a signature that does not verify, or a loaded
        driver with nothing running from its own directory. Any one separates
        this from a hardware monitor; a vendor driver trips none of them.

        The co-located-client test only means something for a driver under a
        vendor install directory, because that is the only place a client would
        be. Nothing runs out of System32\\drivers, so applying it there flagged
        every correctly-installed driver in the system directory - anti-cheat
        included, since installers put those in System32\\drivers and run the
        game from elsewhere. Path and signature still speak for those.
        """
        if not self.present:
            return False
        if self.location_class == "user-writable":
            return True
        if self.signature_trusted is False:
            return True
        if self.location_class == "vendor install":
            return bool(self.running and not self.client_processes)
        return False

    @property
    def binary_missing(self) -> bool:
        """Service key present, driver file gone.

        The PowerShell side reports 'file missing' when the ImagePath does not
        resolve. It means an uninstaller took the binary and left the service
        registration, or the driver deleted itself after loading - which is
        exactly what NetEase's loader does, and what a BYOVD run looks like
        after cleanup.
        """
        # Exact match is correct again: the display path no longer lives in
        # this field, so the token is stable. Prefix matching was a workaround
        # for round 7 mixing display into the value.
        return (self.signature_status or "").strip().lower() == "file missing"

    @property
    def state(self) -> str:
        if not self.present:
            # "absent" read as though it might mean forensic residue. It does
            # not: residue is a separate, explicitly marked condition.
            return "residue only" if self.legacy_node else "not installed"
        if self.binary_missing:
            # Distinct from stopped. Stopped can be started; this cannot, until
            # something puts the file back.
            return "orphaned key"
        if self.running:
            return "loaded"
        if self.running is None:
            return "installed"
        return "stopped"


@dataclass
class HardwareAccessAssessment:
    """Capability to reach the hardware directly from usermode."""

    query_failed: bool = False
    # Set when the operator excluded this collector. Distinct from
    # query_failed: nothing was attempted, so nothing can be concluded.
    skipped: bool = False
    query_error: str | None = None
    drivers: list[HardwareAccessDriver] = field(default_factory=list)
    # Which privileged checks actually ran. Absence of a finding means nothing
    # if the check behind it never happened.
    signature_check: str = "not run"
    process_attribution: str = "not run"
    sources: list[str] = field(default_factory=list)

    @property
    def installed(self) -> list[HardwareAccessDriver]:
        return [d for d in self.drivers if d.present]

    @property
    def msr_capable(self) -> list[HardwareAccessDriver]:
        return [d for d in self.installed if d.grants_msr]

    @property
    def running_drivers(self) -> list[HardwareAccessDriver]:
        return [d for d in self.installed if d.running]

    @property
    def msr_running(self) -> list[HardwareAccessDriver]:
        return [d for d in self.msr_capable if d.running]

    @property
    def unattributed_drivers(self) -> list[HardwareAccessDriver]:
        return [d for d in self.installed if d.unattributed]

    @property
    def untrusted_signature(self) -> list[HardwareAccessDriver]:
        return [d for d in self.installed if d.signature_trusted is False]

    @property
    def anticheat_present(self) -> list[HardwareAccessDriver]:
        """Anti-cheat that is installed now or left a device node behind.

        Keyed on is_anticheat rather than the kernelrw capability. The old
        capability test quietly excluded the user-mode ACE services, which have
        no kernel interface and were therefore invisible even when installed.
        """
        return [d for d in self.drivers if d.is_anticheat and (d.present or d.legacy_node)]

    @property
    def anticheat_installed(self) -> list[HardwareAccessDriver]:
        return [d for d in self.drivers if d.is_anticheat and d.present]

    @property
    def anticheat_running(self) -> list[HardwareAccessDriver]:
        return [d for d in self.anticheat_installed if d.running]

    @property
    def anticheat_startable(self) -> list[HardwareAccessDriver]:
        """Stopped, binary on disk, kernel interface: can be started as-is."""
        return [
            d for d in self.anticheat_installed
            if d.grants_kernel_rw and not d.binary_missing and not d.running
        ]

    @property
    def anticheat_orphaned(self) -> list[HardwareAccessDriver]:
        """Service key registered, binary gone. A record, not an interface."""
        return [d for d in self.anticheat_installed if d.binary_missing]

    @property
    def anticheat_usermode(self) -> list[HardwareAccessDriver]:
        """Present, no kernel interface of its own."""
        return [
            d for d in self.anticheat_installed
            if not d.grants_kernel_rw and not d.binary_missing
        ]

    @property
    def anticheat_residue(self) -> list[HardwareAccessDriver]:
        """Anti-cheat that ran here and whose service is gone.

        The uninstaller took the service; Windows kept the device node. On a
        host where the game is long gone this is the only thing left to find.
        """
        return [d for d in self.drivers if d.is_anticheat and d.legacy_node and not d.present]

    @property
    def installed_drivers(self) -> list[HardwareAccessDriver]:
        """Installed entries that are actually kernel drivers.

        "Drivers installed 3" counted a user-mode service among them. The acsvc
        capability exists precisely to mark an entry with no kernel interface,
        and this counter did not consult it.
        """
        return [d for d in self.installed if "acsvc" not in d.capabilities]

    @property
    def installed_usermode(self) -> list[HardwareAccessDriver]:
        return [d for d in self.installed if "acsvc" in d.capabilities]

    @property
    def kernel_rw_installed(self) -> list[HardwareAccessDriver]:
        """Kernel read/write drivers that could actually be started.

        binary_missing was excluded because an orphaned service key is not an
        installed driver in any sense that matters: the .sys is gone, nothing
        can load it, and the verdict "kernel read/write driver installed" was
        being asserted on a host where no such binary existed on disk. Round 3
        introduced binary_missing and this property never consulted it.
        """
        return [d for d in self.installed if d.grants_kernel_rw and not d.binary_missing]

    @property
    def kernel_rw_orphaned(self) -> list[HardwareAccessDriver]:
        """Kernel-capable service keys whose binary is gone.

        Evidence that the capability was here, not that it is. Counted apart
        from kernel_rw_installed so neither claim borrows the other's weight.
        """
        return [d for d in self.installed if d.grants_kernel_rw and d.binary_missing]

    @property
    def orphaned_keys(self) -> list[HardwareAccessDriver]:
        return [d for d in self.installed if d.binary_missing]

    @property
    def signature_unverifiable(self) -> list[HardwareAccessDriver]:
        """Present, and the signature could not be checked either way.

        "Bad signature 0" printed beside two drivers whose status was
        "file missing" - correct, since a missing file is not a failed
        verification, but the KV block had no row that said so. The same D15
        question the single-value fields answered, applied to a counter.
        """
        # Scoped to entries that have a binary to verify. A user-mode service
        # has no .sys, so counting it as "unverifiable" implied a check that was
        # attempted and inconclusive when none was owed - the host reported 3
        # where two drivers are file-missing and the third is user-mode.
        return [
            d for d in self.installed
            if d.signature_trusted is None and "acsvc" not in d.capabilities
        ]

    @property
    def removal_residue(self) -> list[HardwareAccessDriver]:
        """Ran here once, service since deleted."""
        return [d for d in self.drivers if d.legacy_node and not d.present]

    @property
    def physmem_capable(self) -> list[HardwareAccessDriver]:
        return [d for d in self.installed if "physmem" in d.capabilities]

    @property
    def verdict(self) -> str:
        if self.query_failed:
            return "unknown"
        if any(d.grants_msr for d in self.unattributed_drivers):
            # An MSR interface from a path no installer uses. This is the case
            # that warrants attention; a loaded vendor driver does not.
            return "unattributed MSR driver"
        # Arbitrary kernel read/write is the widest interface in the table and
        # was previously unranked: a loaded anti-cheat driver graded "limited",
        # below a stopped overclocking utility. A kernel R/W driver that is
        # loaded is strictly more capable than an MSR interface that is loaded.
        if self.anticheat_running:
            return "anti-cheat kernel driver loaded"
        if self.msr_running:
            return "MSR interface loaded (attributed)"
        if self.kernel_rw_installed:
            return "kernel read/write driver installed"
        if self.kernel_rw_orphaned:
            # The key is registered and the binary is not on disk. The
            # capability was here; it cannot be exercised in this state.
            return "kernel read/write driver registered, binary absent"
        if self.msr_capable:
            return "fault-injection capable"
        if self.physmem_capable:
            return "physical memory access"
        if self.installed:
            return "limited"
        # Residue is not nothing. Reporting "none" for a host whose only
        # evidence is a device node discards the entire point of reading them.
        if self.anticheat_residue:
            return "anti-cheat removal residue"
        if self.removal_residue:
            return "removal residue only"
        return "none"


@dataclass
class AcpiTable:
    signature: str
    note: str | None = None
    notable: bool = False


@dataclass
class SmbiosInfo:
    """Decoded SMBIOS structures.

    Firmware-supplied and therefore firmware-trusted: everything here is what
    the board says about itself. See the disclaimer on the finding.
    """

    version: str | None = None
    structure_count: int = 0
    types_present: list[int] = field(default_factory=list)
    bios_vendor: str | None = None
    bios_version: str | None = None
    bios_release_date: str | None = None
    bios_rom_size_kb: int | None = None
    bios_release: str | None = None
    truncated: bool = False
    system_manufacturer: str | None = None
    system_product: str | None = None
    system_version: str | None = None
    serial_number: str | None = None
    uuid: str | None = None
    baseboard_manufacturer: str | None = None
    baseboard_product: str | None = None
    baseboard_serial: str | None = None
    chassis_type: str | None = None
    chassis_serial: str | None = None
    asset_tag: str | None = None
    security_status: str | None = None


@dataclass
class FirmwareResource:
    """One capsule-updatable firmware component, from the ESRT."""

    resource_id: str
    version: str | None = None
    lowest_supported_version: str | None = None
    last_attempt_version: str | None = None
    last_attempt_status: int | None = None

    @property
    def last_attempt_failed(self) -> bool:
        return self.last_attempt_status is not None and self.last_attempt_status != 0


@dataclass
class FirmwareAssessment:
    """What the firmware declares, and what it hands to Windows at boot."""

    query_failed: bool = False
    # Set when the operator excluded this collector. Distinct from
    # query_failed: nothing was attempted, so nothing can be concluded.
    skipped: bool = False
    query_error: str | None = None
    acpi_status: str | None = None
    tables: list[AcpiTable] = field(default_factory=list)
    wpbt_present: bool | None = None
    smbios: SmbiosInfo | None = None
    smbios_status: str | None = None
    resources: list[FirmwareResource] = field(default_factory=list)
    resources_status: str | None = None
    acpi_wmi_instances: list[str] = field(default_factory=list)
    acpi_wmi_status: str | None = None
    microcode_revision: str | None = None
    previous_microcode_revision: str | None = None
    cpu_identifier: str | None = None
    wsmt_flags: int | None = None
    wsmt_protections: list[str] = field(default_factory=list)
    wsmt_read_status: str | None = None
    wpbt_binary_size: int | None = None
    wpbt_command_line: str | None = None
    wpbt_content_type: int | None = None
    wpbt_read_status: str | None = None
    wpbt_dropped_path: str | None = None
    wpbt_dropped_size: int | None = None
    wpbt_dropped_mtime_utc: str | None = None
    bios_year: int | None = None
    predates_mitigations: bool | None = None
    iommu_table: str | None = None
    smm_mitigations_declared: bool | None = None
    debug_port_declared: bool | None = None
    tpm_interface: str | None = None
    bios_vendor: str | None = None
    bios_version: str | None = None
    bios_release_date: str | None = None
    system_manufacturer: str | None = None
    system_product: str | None = None
    sources: list[str] = field(default_factory=list)

    @property
    def signatures(self) -> list[str]:
        return [t.signature for t in self.tables]

    @property
    def notable_tables(self) -> list[AcpiTable]:
        return [t for t in self.tables if t.notable]


@dataclass
class CertificateRecord:
    """One certificate in a personal store, with its smart-card provenance."""

    thumbprint: str | None = None
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    store: str | None = None
    not_before_utc: str | None = None
    not_after_utc: str | None = None
    has_private_key: bool | None = None
    provider: str | None = None
    ekus: list[str] = field(default_factory=list)
    eku_labels: list[str] = field(default_factory=list)
    smartcard_logon: bool = False
    provider_is_smartcard: bool = False
    origin: str = "other"  # smart card | probable | other
    expired: bool | None = None


@dataclass
class CertificatePropagationAssessment:
    query_failed: bool = False
    # Set when the operator excluded this collector. Distinct from
    # query_failed: nothing was attempted, so nothing can be concluded.
    skipped: bool = False
    query_error: str | None = None
    certificates: list[CertificateRecord] = field(default_factory=list)
    cert_prop_enabled: bool | None = None
    cert_prop_status: str | None = None
    service_start_label: str | None = None
    sources: list[str] = field(default_factory=list)

    @property
    def smartcard_certificates(self) -> list[CertificateRecord]:
        return [c for c in self.certificates if c.origin in ("smart card", "probable")]

    @property
    def confirmed(self) -> list[CertificateRecord]:
        return [c for c in self.certificates if c.origin == "smart card"]

    @property
    def expired_smartcard(self) -> list[CertificateRecord]:
        return [c for c in self.smartcard_certificates if c.expired]


@dataclass
class GenericDriverBinding:
    """One device currently bound to a generic USB driver."""

    driver: str
    instance_id: str | None = None
    enumerator: str = "UNKNOWN"
    name: str | None = None
    manufacturer: str | None = None
    hardware_ids: list[str] = field(default_factory=list)
    vid_pid: str | None = None
    allowlist_hit: str | None = None
    confidence: str = "weak"
    last_write_utc: str | None = None
    source: str = "reg.Services.Enum"


@dataclass
class GenericDriverService:
    driver: str
    service: str
    present: bool = False
    start_type: int | None = None
    start_label: str | None = None
    image_path: str | None = None
    binding_count: int = 0
    confidence: str = "weak"


@dataclass
class OemInfHit:
    inf_file: str
    markers: list[str] = field(default_factory=list)
    mtime_utc: str | None = None


@dataclass
class ZadigIndicator:
    """One named indicator with its observed state.

    Every indicator is emitted on every run, present or not. An indicator that
    only appears when it fires is indistinguishable from one that never ran.
    """

    indicator: str
    observed: str
    signal: str  # direct | strong | weak | corroborating
    detail: str = ""

    @property
    def fired(self) -> bool:
        return self.observed not in ("no", "0", "none", "not scanned")


@dataclass
class DriverSubstitutionAssessment:
    query_failed: bool = False
    # Set when the operator excluded this collector. Distinct from
    # query_failed: nothing was attempted, so nothing can be concluded.
    skipped: bool = False
    query_error: str | None = None
    services: list[GenericDriverService] = field(default_factory=list)
    bindings: list[GenericDriverBinding] = field(default_factory=list)
    inf_hits: list[OemInfHit] = field(default_factory=list)
    inf_scan_performed: bool = False
    sources: list[str] = field(default_factory=list)

    @property
    def strong_bindings(self) -> list[GenericDriverBinding]:
        return [b for b in self.bindings if b.confidence == "strong"]

    @property
    def weak_bindings(self) -> list[GenericDriverBinding]:
        return [b for b in self.bindings if b.confidence != "strong"]

    @property
    def sdr_bindings(self) -> list[GenericDriverBinding]:
        return [b for b in self.bindings if b.allowlist_hit]

    @property
    def installed_services(self) -> list[GenericDriverService]:
        return [s for s in self.services if s.present]

    @property
    def strong_services(self) -> list[GenericDriverService]:
        """Installed drivers with no automatic binding path."""
        return [s for s in self.services if s.present and s.confidence == "strong"]

    @property
    def deliberate_inf_hits(self) -> list[OemInfHit]:
        """INF packages naming something other than WinUSB.

        A WinUSB INF is ordinary vendor packaging; libusbK, libusb-win32 or
        UsbDk in an INF means a generic driver was installed on purpose.
        """
        return [h for h in self.inf_hits if any(m != "winusb" for m in h.markers)]

    @property
    def verdict(self) -> str:
        """One-word summary of the generic-driver evidence on this host."""
        if self.query_failed:
            return "unknown"
        if self.sdr_bindings:
            return "confirmed"
        if self.strong_bindings or self.strong_services or self.deliberate_inf_hits:
            return "strong"
        if self.bindings or self.inf_hits:
            return "weak"
        return "none"


def zadig_indicators(drv: DriverSubstitutionAssessment) -> list[ZadigIndicator]:
    """Build the full indicator set for a driver-substitution assessment.

    Fixed shape: one row per generic driver, then the aggregate signals. Rows
    are emitted whether or not they fire, so "no evidence" is a visible result
    rather than an empty table.
    """
    rows: list[ZadigIndicator] = []
    by_service = {s.service: s for s in drv.services}

    for service, label, confidence, _rationale in GENERIC_USB_DRIVERS:
        record = by_service.get(service)
        if record is None:
            observed, detail = "unknown", "service key not read"
        elif not record.present:
            observed, detail = "no", "service not installed"
        else:
            observed = "yes"
            detail = (
                f"start: {record.start_label or 'unknown'}; "
                f"bound: {record.binding_count}"
            )
        rows.append(
            ZadigIndicator(
                indicator=f"{label} driver installed",
                observed=observed,
                signal=confidence,
                detail=detail,
            )
        )

    # All strong-signal bindings, allowlisted or not. The SDR row below is a
    # named subset of this one, not a separate population — the summary counter
    # and this row must agree.
    rows.append(
        ZadigIndicator(
            indicator="Devices on a deliberate generic driver",
            observed=str(len(drv.strong_bindings)),
            signal="strong",
            detail=summarize_items(
                drv.strong_bindings, lambda b: f"{b.name or 'device'} ({b.driver})", 4,
                separator=", ",
            )
            or "no device detached from its class driver this way",
        )
    )
    rows.append(
        ZadigIndicator(
            indicator="Devices on WinUSB",
            observed=str(len(drv.weak_bindings)),
            signal="weak",
            detail=(
                summarize_items(drv.weak_bindings, lambda b: f"{b.name or 'device'}", 4, separator=", ")
                or "none"
            )
            + " (WCID devices bind automatically; not evidence of intent)",
        )
    )
    rows.append(
        ZadigIndicator(
            indicator="Allowlisted SDR on a generic driver",
            observed=str(len(drv.sdr_bindings)),
            signal="direct",
            detail=summarize_items(
                drv.sdr_bindings, lambda b: f"{b.allowlist_hit} on {b.driver}", 4, separator=", "
            )
            or "no allowlisted RF peripheral is bound to a generic driver (subset of the row above)",
        )
    )
    residue = [s for s in drv.strong_services if s.binding_count == 0]
    rows.append(
        ZadigIndicator(
            indicator="Driver installed, nothing bound",
            observed=str(len(residue)),
            signal="strong",
            detail=", ".join(s.driver for s in residue)
            or "no leftover generic driver without a device",
        )
    )
    rows.append(
        ZadigIndicator(
            indicator="Generic-driver INF packages",
            observed=("not scanned" if not drv.inf_scan_performed else str(len(drv.deliberate_inf_hits))),
            signal="corroborating",
            detail=(
                summarize_items(
                    drv.deliberate_inf_hits,
                    lambda h: f"{h.inf_file} ({', '.join(h.markers)})", 4, separator=", ",
                )
                or ("INF store not readable" if not drv.inf_scan_performed else "no libusb/UsbDk INF in the store")
            ),
        )
    )
    return rows


def _normalize_protector(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


WBIO_LOCATION = {
    0: "unspecified",
    1: "front",
    2: "back",
    3: "left",
    4: "right",
    5: "top",
    6: "external",
    7: "dual-screen-right",
    12: "right-of-touchpad",
}

ENROLLED_FACTORS = {
    2: "Face",
    8: "Fingerprint",
    10: "Face+Fingerprint",
}

# Inbox catalog / policy rows — not evidence a peripheral was attached.
_CONTEXT_SOURCES = frozenset({"biometrics-policy", "wbio-database", "calais-smartcards"})

_FT_EPOCH = 116444736000000000  # 1601-01-01 to 1970-01-01 in 100-ns ticks


def as_int_safe(value: Any) -> int | None:
    """Coerce a registry / WMI value to int, or None. Never raises.

    Decimal only by design. ``_winreg_values`` hex-encodes REG_BINARY, so a
    binary value could be read as either base; guessing would silently produce
    a wrong number. Callers report the raw value alongside "unknown" instead.
    """
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def filetime_to_utc_iso(value: Any) -> str | None:
    """Convert a Windows FILETIME (int) to UTC ISO-8601."""
    if value is None or value == "":
        return None
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    if ticks <= _FT_EPOCH:
        return None
    seconds = (ticks - _FT_EPOCH) / 10_000_000
    if seconds < 0 or seconds > 4_102_444_800:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_TS_RE = re.compile(
    r"^(?P<body>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>[Zz]|[+-]\d{2}:?\d{2})$"
)


def parse_datetime_to_utc_iso(value: Any) -> str | None:
    """Normalize an *unambiguous* timestamp to UTC ISO-8601, else None.

    A naive timestamp is never assumed to be UTC. .NET and PowerShell render
    local time by default, so relabelling a naive value as UTC shifts it by the
    host's offset and silently corrupts every timeline the tool produces. The
    collectors are responsible for emitting round-trip ('o') format; anything
    that arrives here without an offset is reported as unparsed, not guessed.
    """
    if value is None or value == "" or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return filetime_to_utc_iso(value)
    text = str(value).strip()
    if not text or text.lower() in {"none", "null"}:
        return None
    if text.isdigit() and len(text) >= 17:
        return filetime_to_utc_iso(text)
    match = _TS_RE.match(text)
    if match is None:
        return None
    body = match.group("body").replace(" ", "T")
    frac = match.group("frac")
    tz = match.group("tz")
    offset = "+00:00" if tz in ("Z", "z") else (tz if ":" in tz else f"{tz[:3]}:{tz[3:]}")
    # fromisoformat accepts 3 or 6 fractional digits; .NET 'o' emits 7.
    fraction = f".{frac[:6].ljust(6, '0')}" if frac else ""
    try:
        parsed = datetime.fromisoformat(f"{body}{fraction}{offset}")
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")




def is_historical_context(rec: HistoricalRecord) -> bool:
    """True for inbox catalog / policy rows that are not device-connection evidence."""
    if rec.source in _CONTEXT_SOURCES:
        return True
    if rec.source == "winbio-account":
        factors = (rec.extra or {}).get("enrolled_factors")
        if factors in (None, "", "unknown"):
            return True
        parsed = as_int_safe(factors)
        return parsed is None or parsed == 0
    return False


@dataclass
class HistoricalRecord:
    category: str
    name: str
    instance_id: str | None = None
    source: str = ""
    present: bool = False
    first_install: str | None = None
    last_arrival: str | None = None
    last_removal: str | None = None
    last_write_utc: str | None = None
    manufacturer: str | None = None
    status: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def is_absent_now(self) -> bool:
        return not self.present

    @property
    def first_seen_utc(self) -> str | None:
        return self.first_install or self.last_arrival or self.last_write_utc

    @property
    def last_seen_utc(self) -> str | None:
        return self.last_arrival or self.last_write_utc


@dataclass
class HistoricalAssessment:
    query_failed: bool = False
    # Set when the operator excluded this collector. Distinct from
    # query_failed: nothing was attempted, so nothing can be concluded.
    skipped: bool = False
    query_error: str | None = None
    records: list[HistoricalRecord] = field(default_factory=list)
    policy: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

    @property
    def absent_identity_devices(self) -> list[HistoricalRecord]:
        return [
            r
            for r in self.records
            # Was {"Biometric", "SmartCardReader", "Infrared"} - a third class
            # set, narrower than PNP_CLASSES and narrower than the historical
            # classifier, so an absent Sensor-class device was counted by
            # neither "Absent now" nor FIND-HISTORICAL-IDENTITY-DEVICE while
            # still being enumerated by the collector that found it.
            if r.category in PNP_CLASSES
            and r.is_absent_now
            and not is_historical_context(r)
        ]

    @property
    def present_identity_devices(self) -> list[HistoricalRecord]:
        """Identity-class rows this collector saw as PRESENT.

        The historical PnP script scans the same four classes as the inventory
        collector but without -PresentOnly, and records Present per row. That
        makes it an independent second reading of exactly the question the
        inventory answers, and until now nothing compared the two. A device
        here that is missing from the inventory is a proven inventory failure,
        not a phantom.
        """
        return [
            r
            for r in self.records
            if r.category in PNP_CLASSES
            and r.present is True
            and not is_historical_context(r)
        ]

    def hardware_records(self) -> list[HistoricalRecord]:
        return [r for r in self.records if not is_historical_context(r)]

    def context_records(self) -> list[HistoricalRecord]:
        return [r for r in self.records if is_historical_context(r)]


@dataclass
class Finding:
    id: str
    severity: Severity
    title: str
    detail: str
    category: str
    related_instance_id: str | None = None
    mitre: list[MitreIndicator] = field(default_factory=list)


@dataclass
class AssessmentResult:
    hostname: str
    collected_at_utc: str
    scanner_context: dict[str, Any]
    devices: list[DeviceRecord]
    tpm: TpmRecord
    bitlocker: BitLockerRecord
    dma: DmaAssessment
    sdr: SdrAssessment
    historical: HistoricalAssessment
    findings: list[Finding]
    collection_errors: list[str]
    # Defaulted so existing constructions keep working; a default-constructed
    # assessment reports query_failed=False with nothing found, which the
    # findings layer reads as "no generic drivers installed".
    drivers: DriverSubstitutionAssessment = field(default_factory=DriverSubstitutionAssessment)
    firmware: FirmwareAssessment = field(default_factory=FirmwareAssessment)
    hardware_access: HardwareAccessAssessment = field(
        default_factory=HardwareAccessAssessment
    )
    boot_integrity: BootIntegrityAssessment = field(default_factory=BootIntegrityAssessment)
    interception: InterceptionAssessment = field(default_factory=InterceptionAssessment)
    certificates: CertificatePropagationAssessment = field(
        default_factory=CertificatePropagationAssessment
    )
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool_version": __version__,
            "hostname": self.hostname,
            "collected_at_utc": self.collected_at_utc,
            "scanner_context": self.scanner_context,
            "devices": [_device_to_dict(d) for d in self.devices],
            "tpm": asdict(self.tpm),
            "bitlocker": _section_to_dict(
                self.bitlocker,
                any_protected=self.bitlocker.any_protected,
                all_protected=self.bitlocker.all_protected,
            ),
            "dma": _section_to_dict(
                self.dma, thunderbolt_present=self.dma.thunderbolt_present
            ),
            "sdr": _section_to_dict(
                self.sdr,
                present_count=len(self.sdr.present_devices),
                historical_count=len(self.sdr.historical_devices),
            ),
            "interception": _section_to_dict(
                self.interception,
                verdict=self.interception.verdict,
                additional_filter_count=len(self.interception.additional_filters),
                third_party_adapter_count=len(self.interception.third_party_adapters),
            ),
            "boot_integrity": _section_to_dict(
                self.boot_integrity,
                verdict=self.boot_integrity.verdict,
                unsigned_kernel_code_permitted=self.boot_integrity.unsigned_kernel_code_permitted,
            ),
            # P-2. The rows existed only in the pretty report, which breaks the
            # tool's own contract: --findings and --collectors both hide
            # terminal detail and keep JSON complete. It also left
            # TierRow.key - the join surface --implement depends on - with
            # nothing outside a rendered string to join to.
            "posture_gaps": [
                {
                    "key": r.key, "tier": r.tier, "section": r.section,
                    "title": r.title, "detail": r.detail,
                    "mitigation": r.mitigation, "command": r.command,
                    "blocked_reason": r.blocked_reason,
                }
                for r in assess_tiers(self)
            ],
            "hardware_access": _section_to_dict(
                self.hardware_access,
                verdict=self.hardware_access.verdict,
                installed_count=len(self.hardware_access.installed),
                msr_capable_count=len(self.hardware_access.msr_capable),
                anticheat_tracked_count=len(ANTICHEAT_DRIVER_NAMES),
                anticheat_present_count=len(self.hardware_access.anticheat_present),
                anticheat_running_count=len(self.hardware_access.anticheat_running),
                anticheat_residue_count=len(self.hardware_access.anticheat_residue),
                anticheat_drivers=[
                    d.driver for d in self.hardware_access.anticheat_present
                ],
            ),
            "firmware": _section_to_dict(
                self.firmware,
                table_count=len(self.firmware.tables),
                signatures=self.firmware.signatures,
            ),
            "smartcard_certificates": _section_to_dict(
                self.certificates,
                smartcard_count=len(self.certificates.smartcard_certificates),
                confirmed_count=len(self.certificates.confirmed),
                expired_count=len(self.certificates.expired_smartcard),
            ),
            "driver_substitution": _section_to_dict(
                self.drivers,
                verdict=self.drivers.verdict,
                indicators=[asdict(i) for i in zadig_indicators(self.drivers)],
                strong_binding_count=len(self.drivers.strong_bindings),
                weak_binding_count=len(self.drivers.weak_bindings),
                sdr_binding_count=len(self.drivers.sdr_bindings),
                installed_service_count=len(self.drivers.installed_services),
            ),
            "historical": _section_to_dict(
                self.historical,
                absent_identity_count=len(self.historical.absent_identity_devices),
            ),
            "findings": [_finding_to_dict(f) for f in self.findings],
            "collection_errors": list(self.collection_errors),
            "summary": self.summary,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, ensure_ascii=True)


def _section_to_dict(section: Any, **computed: Any) -> dict[str, Any]:
    """Serialize a dataclass section from its fields, then overlay properties.

    Driving the field half from asdict means a new dataclass field can never be
    silently dropped from the JSON report; only the derived values that have no
    backing field are listed by hand.
    """
    payload = asdict(section)
    payload.update(computed)
    return payload


def _mitre_to_dict(ind: MitreIndicator) -> dict[str, Any]:
    return asdict(ind)


def _device_to_dict(dev: DeviceRecord) -> dict[str, Any]:
    payload = asdict(dev)
    payload["mitre"] = [_mitre_to_dict(m) for m in dev.mitre]
    return payload


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    payload = asdict(finding)
    payload["mitre"] = [_mitre_to_dict(m) for m in finding.mitre]
    return payload


# ===========================================================================
# ATT&CK catalog
# ===========================================================================


def _attack_url(technique_id: str, subtechnique_id: str | None = None) -> str:
    if subtechnique_id:
        parent, _, child = subtechnique_id.partition(".")
        return f"{ATTACK_BASE}/{parent}/{child}/"
    return f"{ATTACK_BASE}/{technique_id}/"


def mitre(
    technique_id: str,
    technique_name: str,
    tactic: str,
    *,
    subtechnique_id: str | None = None,
    relevance: Relevance = "enabling",
    rationale: str = "",
) -> MitreIndicator:
    return MitreIndicator(
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        subtechnique_id=subtechnique_id,
        relevance=relevance,
        rationale=rationale,
        references=[_attack_url(technique_id, subtechnique_id)],
    )


def indicators_for_usb_addition(*, enumerator: str, manufacturer: str | None) -> list[MitreIndicator]:
    if (enumerator or "").upper() != "USB":
        return []
    mfg = (manufacturer or "").strip()
    unknown = not mfg or mfg.lower() in {"unknown", "generic", "(standard system devices)"}
    out = [
        mitre(
            "T1200",
            "Hardware Additions",
            "Initial Access",
            relevance="enabling",
            rationale=(
                "USB-attached identity or sensing hardware can be introduced after "
                "compromise as a hardware addition (external reader, IR dongle, or "
                "unexpected composite device)."
            ),
        ),
        mitre(
            "T1091",
            "Replication Through Removable Media",
            "Lateral Movement",
            relevance="enabling",
            rationale=(
                "USB enumerators can also carry composite functions. Presence is an "
                "enabling removable-media surface, not evidence of payload delivery."
            ),
        ),
    ]
    if unknown:
        out.append(
            mitre(
                "T1195",
                "Supply Chain Compromise",
                "Initial Access",
                subtechnique_id="T1195.003",
                relevance="hypothetical_abuse",
                rationale=(
                    "Manufacturer or VID/PID is missing or generic. Treat as a "
                    "supply-chain review item only; this module cannot prove firmware "
                    "or hardware tampering."
                ),
            )
        )
    return out


def indicators_for_biometric(dev_name: str, *, hello_face: bool) -> list[MitreIndicator]:
    notes = [
        mitre(
            "T1111",
            "Multi-Factor Authentication Interception",
            "Credential Access",
            relevance="enabling",
            rationale=(
                f"A biometric sensor ({dev_name}) on a compromised host enables "
                "attempts to intercept or proxy a Windows Hello / WinBio ceremony. "
                "Presence is not proof that interception occurred."
            ),
        ),
        mitre(
            "T1556",
            "Modify Authentication Process",
            "Credential Access",
            subtechnique_id="T1556.006",
            relevance="enabling",
            rationale=(
                "Local malware can target the biometric service stack or Hello "
                "policy rather than the user's password."
            ),
        ),
        mitre(
            "T1056",
            "Input Capture",
            "Credential Access",
            relevance="enabling",
            rationale=(
                "Hello companion PIN or fallback prompts remain keylogger-adjacent "
                "even when the biometric factor itself is present."
            ),
        ),
        mitre(
            "T1555",
            "Credentials from Password Stores",
            "Credential Access",
            relevance="enabling",
            rationale=(
                "NGC / Hello keys sit next to biometric unlock. This module does "
                "not read those stores; it only flags the adjacent surface."
            ),
        ),
        mitre(
            "T1497",
            "Virtualization/Sandbox Evasion",
            "Defense Evasion",
            relevance="hypothetical_abuse",
            rationale="Malware may use biometric device presence as an environment fingerprint.",
        ),
    ]
    if hello_face:
        notes[0].rationale += (
            " Windows Hello Face / NIR matching additionally admits presentation "
            "or replay-style abuse of the IR pipeline."
        )
    return notes


def indicators_for_smartcard(*, virtual: bool) -> list[MitreIndicator]:
    items = [
        mitre(
            "T1111",
            "Multi-Factor Authentication Interception",
            "Credential Access",
            relevance="direct",
            rationale=(
                "A smart-card reader is the classic T1111 hardware-token proxy "
                "surface (wait for insertion, capture PIN, relay CSP/minidriver "
                "operations). Observed historically with families such as Sykipot."
            ),
        ),
        mitre(
            "T1556",
            "Modify Authentication Process",
            "Credential Access",
            relevance="enabling",
            rationale="Minidriver, KSP, or PIN-dialog substitution can alter how card auth is performed.",
        ),
        mitre(
            "T1056",
            "Input Capture",
            "Credential Access",
            subtechnique_id="T1056.001",
            relevance="enabling",
            rationale="Smart-card PINs are commonly captured with a keylogger alongside reader access.",
        ),
        mitre(
            "T1649",
            "Steal or Forge Authentication Certificates",
            "Credential Access",
            relevance="enabling",
            rationale="PIV/CAC or virtual smart cards expose certificate-backed identity material.",
        ),
        mitre(
            "T1550",
            "Use Alternate Authentication Material",
            "Defense Evasion",
            relevance="enabling",
            rationale="Stolen or proxied card assertions become alternate auth material on the network.",
        ),
        mitre(
            "T1600",
            "Weaken Encryption",
            "Defense Evasion",
            relevance="hypothetical_abuse",
            rationale=(
                "Hypothetical minidriver/CSP substitution could weaken how card "
                "cryptography is invoked. Not observed by this inventory alone."
            ),
        ),
    ]
    if virtual:
        items.append(
            mitre(
                "T1553",
                "Subvert Trust Controls",
                "Defense Evasion",
                relevance="enabling",
                rationale=(
                    "Virtual smart cards are typically TPM-backed. Compromise of "
                    "the virtual reader path is tied to TPM key isolation quality."
                ),
            )
        )
    return items


def indicators_for_infrared(*, imaging: bool, hello_face: bool) -> list[MitreIndicator]:
    if imaging or hello_face:
        items = [
            mitre(
                "T1125",
                "Video Capture",
                "Collection",
                relevance="direct" if imaging else "enabling",
                rationale=(
                    "An IR imaging device can be opened as a camera handle for "
                    "covert collection if a compromised process can access it."
                ),
            ),
            mitre(
                "T1111",
                "Multi-Factor Authentication Interception",
                "Credential Access",
                relevance="enabling",
                rationale=(
                    "Hello Face NIR cameras are a presentation/replay target for "
                    "phishing-resistant MFA that still depends on the local sensor."
                ),
            ),
            mitre(
                "T1556",
                "Modify Authentication Process",
                "Credential Access",
                subtechnique_id="T1556.006",
                relevance="enabling",
                rationale="Face-auth policy or the WinBio pipeline can be altered on a compromised host.",
            ),
        ]
        return items
    return [
        mitre(
            "T1497",
            "Virtualization/Sandbox Evasion",
            "Defense Evasion",
            relevance="enabling",
            rationale=(
                "Ambient IR / proximity sensors are a weak collection device but "
                "a useful environment-awareness signal for sandbox detection."
            ),
        )
    ]


def indicators_for_generic_sensor(*, location_like: bool) -> list[MitreIndicator]:
    items = [
        mitre(
            "T1497",
            "Virtualization/Sandbox Evasion",
            "Defense Evasion",
            relevance="enabling",
            rationale=(
                "Accelerometer, gyro, and light sensors are commonly sampled to "
                "tell real hardware from VMs or automated sandboxes."
            ),
        ),
        mitre(
            "T1082",
            "System Information Discovery",
            "Discovery",
            relevance="enabling",
            rationale="Sensor inventory itself is a stable host fingerprint.",
        ),
        mitre(
            "T1518",
            "Software Discovery",
            "Discovery",
            relevance="enabling",
            rationale="Companion sensor services and drivers expand software discovery.",
        ),
    ]
    if location_like:
        items[1].rationale += (
            " Location/GNSS sensors additionally leak geolocation privacy on a "
            "compromised laptop; this is framed as host information, not a forced "
            "Collection technique ID."
        )
    return items


def indicators_for_tpm(*, present: bool, healthy: bool) -> list[MitreIndicator]:
    if not present:
        return [
            mitre(
                "T1553",
                "Subvert Trust Controls",
                "Defense Evasion",
                relevance="absence_risk",
                rationale="Without a TPM, Measured Boot, BitLocker protectors, and Hello key isolation lack a hardware root of trust.",
            ),
            mitre(
                "T1542",
                "Pre-OS Boot",
                "Persistence",
                subtechnique_id="T1542.001",
                relevance="absence_risk",
                rationale="Firmware attestation is weaker when PCR quotes and secure-boot measurements cannot be bound to a TPM.",
            ),
            mitre(
                "T1556",
                "Modify Authentication Process",
                "Credential Access",
                relevance="absence_risk",
                rationale="Authentication features that assume TPM-backed NGC/Hello keys are easier to tamper with.",
            ),
        ]
    items = [
        mitre(
            "T1553",
            "Subvert Trust Controls",
            "Defense Evasion",
            relevance="enabling",
            rationale="Adversaries targeting this host must subvert TPM-backed trust (Measured Boot, BitLocker, Hello keys) rather than ignore it.",
        ),
        mitre(
            "T1542",
            "Pre-OS Boot",
            "Persistence",
            subtechnique_id="T1542.001",
            relevance="enabling",
            rationale="System firmware feeds TPM PCRs. Firmware implants remain a way to undermine the root of trust.",
        ),
        mitre(
            "T1495",
            "Firmware Corruption",
            "Impact",
            relevance="hypothetical_abuse",
            rationale="High-impact firmware corruption would also break TPM-anchored integrity measurements.",
        ),
        mitre(
            "T1600",
            "Weaken Encryption",
            "Defense Evasion",
            relevance="hypothetical_abuse",
            rationale="Dictionary or reset attacks against TPM auth values are limited by anti-hammering / lockout when those fields are healthy.",
        ),
        mitre(
            "T1556",
            "Modify Authentication Process",
            "Credential Access",
            relevance="enabling",
            rationale="Hello, Credential Guard, and NGC keys are bound to the TPM when it is present.",
        ),
    ]
    if not healthy:
        for ind in items:
            if ind.technique_id in {"T1553", "T1556", "T1600"}:
                ind.relevance = "absence_risk"
                ind.rationale += " TPM is present but not fully enabled/ready, so those controls may not actually bind."
    return items


def indicators_for_bitlocker(*, protected: bool, uses_tpm_protector: bool, tpm_present: bool) -> list[MitreIndicator]:
    if not protected:
        return [
            mitre(
                "T1553",
                "Subvert Trust Controls",
                "Defense Evasion",
                relevance="absence_risk",
                rationale=(
                    "BitLocker is off or unprotected. Full-volume encryption that would "
                    "bind OS volumes to the TPM is not defending data at rest."
                ),
            ),
            mitre(
                "T1562",
                "Impair Defenses",
                "Defense Evasion",
                subtechnique_id="T1562.001",
                relevance="absence_risk",
                rationale=(
                    "Disabled volume encryption is equivalent to a missing host defense "
                    "on a compromised laptop or workstation."
                ),
            ),
            mitre(
                "T1600",
                "Weaken Encryption",
                "Defense Evasion",
                relevance="absence_risk",
                rationale="No volume encryption means disk imaging after compromise yields plaintext files.",
            ),
        ]
    items = [
        mitre(
            "T1553",
            "Subvert Trust Controls",
            "Defense Evasion",
            relevance="enabling",
            rationale=(
                "BitLocker is protecting at least one volume. An operator must steal "
                "a protector (TPM unseal, PIN, password, or recovery material) rather "
                "than read the disk offline in the default case."
            ),
        ),
        mitre(
            "T1600",
            "Weaken Encryption",
            "Defense Evasion",
            relevance="hypothetical_abuse",
            rationale="Adversaries may try to suspend protection, add a protector, or harvest recovery material.",
        ),
    ]
    if protected and not uses_tpm_protector:
        items.append(
            mitre(
                "T1555",
                "Credentials from Password Stores",
                "Credential Access",
                relevance="enabling",
                rationale=(
                    "Protection is on but no TPM protector was observed. Password, "
                    "passphrase, or external-key protectors are more portable if stolen."
                ),
            )
        )
    if protected and uses_tpm_protector and tpm_present:
        items.append(
            mitre(
                "T1542",
                "Pre-OS Boot",
                "Persistence",
                subtechnique_id="T1542.001",
                relevance="enabling",
                rationale="TPM-bound BitLocker still depends on firmware measurements that feed PCRs.",
            )
        )
    return items


def indicators_for_dma(*, kernel_state: str | None, policy: int | None, controller_present: bool) -> list[MitreIndicator]:
    state = (kernel_state or "unknown").strip().lower()
    items = [
        mitre(
            "T1200",
            "Hardware Additions",
            "Initial Access",
            relevance="enabling" if controller_present else "hypothetical_abuse",
            rationale=(
                "Thunderbolt / USB4 host controllers expose a hot-plug DMA path. "
                "A dock or adapter attached after compromise is a hardware addition, "
                "not a USB mass-storage insertion."
            ),
        ),
        mitre(
            "T1553",
            "Subvert Trust Controls",
            "Defense Evasion",
            relevance=(
                "absence_risk"
                if state in {"off", "unsupported", "not available"}
                else "enabling"
            ),
            rationale=(
                "Kernel DMA Protection (IOMMU / Memory Access Protection) is the "
                "Windows control that constrains external DMA. When the platform "
                "does not report DMA protection as available, firmware and IOMMU "
                "policy are the only remaining barrier."
            ),
        ),
    ]
    if policy == 2:
        items.append(
            mitre(
                "T1562",
                "Impair Defenses",
                "Defense Evasion",
                subtechnique_id="T1562.001",
                relevance="direct",
                rationale="DmaGuard DeviceEnumerationPolicy=2 allows remapping-incompatible external devices.",
            )
        )
    elif policy == 0:
        items.append(
            mitre(
                "T1562",
                "Impair Defenses",
                "Defense Evasion",
                subtechnique_id="T1562.001",
                relevance="enabling",
                rationale="DmaGuard is set to block remapping-incompatible external devices.",
            )
        )
    else:
        items.append(
            mitre(
                "T1562",
                "Impair Defenses",
                "Defense Evasion",
                subtechnique_id="T1562.001",
                relevance="enabling",
                rationale="DmaGuard default (after unlock) still admits DMA-capable devices once an authorized session exists.",
            )
        )
    return items


def indicators_for_driver_substitution(
    *, bound: bool, strong: bool, sdr_match: bool
) -> list[MitreIndicator]:
    """Indicators for a device rebound to a generic USB driver.

    Deliberately narrow. Installing a generic driver is legitimate software
    doing a legitimate thing; what it grants is unmediated endpoint access.
    T1200 as *enabling* is the honest placement. It is not mapped to T1543,
    because a service key existing is not service abuse.
    """
    return [
        mitre(
            "T1200",
            "Hardware Additions",
            "Initial Access",
            relevance="direct" if sdr_match else ("enabling" if strong else "hypothetical_abuse"),
            rationale=(
                "A device detached from its class driver and bound to a generic USB "
                "driver has raw bulk and control endpoint access from usermode. That "
                "is the precondition for SDR capture, DFU firmware reflashing, and "
                "vendor-specific control requests."
                + (
                    " A known RF peripheral is bound this way."
                    if sdr_match
                    else ""
                )
            ),
        ),
        mitre(
            "T1082",
            "System Information Discovery",
            "Discovery",
            relevance="enabling" if bound else "absence_risk",
            rationale=(
                "Generic-driver service keys and OEM INF residue are a distinctive "
                "host fingerprint that outlives the hardware."
            ),
        ),
    ]


def indicators_for_sdr(*, present: bool) -> list[MitreIndicator]:
    return [
        mitre(
            "T1200",
            "Hardware Additions",
            "Initial Access",
            relevance="direct" if present else "enabling",
            rationale=(
                "An allowlisted SDR or DVB-T dongle is RF collection hardware. "
                "Presence or a leftover Enum node is a peripheral addition, not USBSTOR."
            ),
        ),
        mitre(
            "T1123",
            "Audio Capture",
            "Collection",
            relevance="hypothetical_abuse",
            rationale=(
                "Closest Enterprise Collection analog for an RF receiver. This module "
                "does not tune or demodulate; it only flags the radio peripheral."
            ),
        ),
        mitre(
            "T1082",
            "System Information Discovery",
            "Discovery",
            relevance="enabling",
            rationale="SDR VID/PID leftovers are a distinctive host fingerprint.",
        ),
    ]


def match_sdr_allowlist(instance_id: str | None, name: str | None, hardware_ids: Iterable[str] | None = None) -> str | None:
    """Return allowlist label if instance/name/HWID hits a known SDR or DVB-T stick."""
    blob = " ".join(
        [
            instance_id or "",
            name or "",
            " ".join(hardware_ids or ()),
        ]
    ).upper()
    for vid, pid, label in SDR_ALLOWLIST:
        token = f"VID_{vid}&PID_{pid}"
        compact = f"{vid}:{pid}"
        if token in blob or compact in blob.replace(" ", ""):
            return f"{label} ({vid}:{pid})"
    lower = blob.lower()
    for needle in SDR_NAME_NEEDLES:
        if needle in lower:
            return needle
    return None


def looks_like_thunderbolt_controller(instance_id: str | None, name: str | None, pnp_class: str | None = None) -> bool:
    blob = " ".join([instance_id or "", name or "", pnp_class or ""]).lower()
    if any(tok in blob for tok in ("thunderbolt", "usb4", "usb 4")):
        if any(tok in blob for tok in ("controller", "host", "router", "port", "tunnel", "tbt", "usb4")):
            return True
        if "thunderbolt" in blob or "usb4" in blob:
            return True
    if r"\tbt" in blob or "tbt_" in blob or blob.startswith("tbt"):
        return True
    return False


# ===========================================================================
# Classification helpers (pure — unit-testable off Windows)
# ===========================================================================


def decode_tpm_manufacturer_id(value: int | str | None) -> str | None:
    if value is None or value == "":
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        text = str(value).strip()
        return text or None
    raw = number.to_bytes(4, byteorder="big", signed=False)
    printable = bytes(b for b in raw if 32 <= b < 127)
    decoded = printable.decode("ascii", errors="ignore").strip()
    return decoded or None


def enumerator_from_instance_id(instance_id: str | None) -> str:
    if not instance_id:
        return "UNKNOWN"
    token = instance_id.replace("/", "\\").split("\\", 1)[0].upper()
    return token or "UNKNOWN"


def is_virtual_or_software(instance_id: str | None, name: str | None) -> bool:
    iid = (instance_id or "").replace("/", "\\").upper()
    if iid.startswith(("SWD\\", "ROOT\\", "UMB\\")):
        return True
    lowered = (name or "").lower()
    needles = (
        "software device",
        "virtual smart",
        "virtual smartcard",
        "virtual smart card",
        "remote desktop",
        "redirected",
        "rdp",
    )
    return any(n in lowered for n in needles)


def looks_like_hello_face(name: str | None, hardware_ids: Iterable[str], pnp_class: str | None = None) -> bool:
    blob = " ".join([name or "", pnp_class or "", *hardware_ids]).lower()
    return any(
        token in blob
        for token in (
            "windows hello",
            "winhello",
            "hello face",
            "rgbir",
            "ir camera",
            "infrared camera",
            "nir",
        )
    )


def looks_like_ir_imager(name: str | None, hardware_ids: Iterable[str], pnp_class: str | None = None) -> bool:
    blob = " ".join([name or "", pnp_class or "", *hardware_ids]).lower()
    if looks_like_hello_face(name, hardware_ids, pnp_class):
        return True
    tokens = (
        "infrared",
        " ir ",
        "ir-cut",
        "ir camera",
        "ircam",
        "nir",
        "thermal",
    )
    if any(t in f" {blob} " for t in tokens):
        return True
    return (pnp_class or "").lower() in {"camera", "image"} and "ir" in blob.split()


def looks_like_related_ir_camera(name: str | None, hardware_ids: Iterable[str], pnp_class: str | None) -> bool:
    cls = (pnp_class or "").lower()
    if cls not in {"camera", "image", "media"}:
        return False
    blob = " ".join([name or "", *hardware_ids]).lower()
    hints = ("ir", "infrared", "hello", "rgbir", "winhello", "nir")
    return any(h in blob for h in hints)


def looks_like_location_sensor(name: str | None, hardware_ids: Iterable[str]) -> bool:
    blob = " ".join([name or "", *hardware_ids]).lower()
    return any(t in blob for t in ("gps", "gnss", "geolocation", "location sensor", "lps"))


def is_unknown_manufacturer(manufacturer: str | None) -> bool:
    if not manufacturer or not str(manufacturer).strip():
        return True
    return str(manufacturer).strip().lower() in {
        "unknown",
        "generic",
        "(standard system devices)",
    }


def spec_is_1_2_only(spec_version: str | None) -> bool:
    if not spec_version:
        return False
    text = spec_version.lower()
    has_12 = "1.2" in text
    has_20 = "2.0" in text or "2.0," in text
    return has_12 and not has_20


def tpm_is_healthy(tpm: TpmRecord) -> bool:
    return bool(tpm.present) and tpm.enabled is True and tpm.ready is not False


# ===========================================================================
# Windows collection
# ===========================================================================


class CollectionError(RuntimeError):
    """Raised when a collector fails and on_error='raise'."""


def _is_windows() -> bool:
    return sys.platform == "win32"


def _is_admin() -> bool | None:
    if not _is_windows():
        return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return None


def _windows_version() -> str:
    if not _is_windows():
        return platform.platform()
    try:
        ver = platform.win32_ver()
        # platform.win32_ver()[0] is derived from the major version, which is
        # still 10 on Windows 11, so a live Windows 11 host printed
        # "Windows 10 10.0.26200 SP0 Multiprocessor Free" on the second line of
        # the report. The build number is what separates them: 22000 is the
        # first Windows 11 build. Server builds are left alone - there is no
        # reliable build threshold for them here, so they keep the raw release.
        parts = [p for p in ver if p]
        build = 0
        if len(ver) > 1:
            tail = str(ver[1]).split(".")[-1]
            build = int(tail) if tail.isdigit() else 0
        if parts and parts[0] == "10" and build >= 22000:
            parts[0] = "11"
        return " ".join(parts)
    except Exception:
        return platform.platform()


# Prepended to every script. Pins the module search path so a planted module
# earlier in PSModulePath cannot shadow an inbox cmdlet, and forces UTF-8 out
# so non-ASCII manufacturer and device names survive the pipe intact.
# Prepended to every script. Pinning PSModulePath is what actually resists a
# planted module shadowing an inbox cmdlet; module-qualified command names were
# tried on top of this and regressed every collector, so they are not used.
#
# The encoding object is deliberately UTF8Encoding($false), not
# [Text.Encoding]::UTF8. The latter carries a byte-order mark, and a BOM on
# stdout makes json.loads reject the entire document — which fails every
# collector at once and looks exactly like "the query failed".
_PS_PROLOGUE = (
    "$__spm = \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\Modules\"\n"
    "if (Test-Path -LiteralPath $__spm) { $env:PSModulePath = $__spm }\n"
    "try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}\n"
)

# Non-terminating PowerShell errors arrive on stderr with a zero exit code.
# Collectors have no error channel of their own, so warnings accumulate here
# and assess_sensors drains them into collection_errors.
_PS_WARNINGS: list[str] = []
_PS_STDERR_CAP = 500

_POWERSHELL_PATH: str | None = None


def reset_powershell_warnings() -> None:
    _PS_WARNINGS.clear()


def drain_powershell_warnings() -> list[str]:
    drained = list(_PS_WARNINGS)
    _PS_WARNINGS.clear()
    return drained


def set_powershell_timeout(seconds: int) -> None:
    """Set the per-query PowerShell timeout for this process.

    A module-level default rather than a threaded parameter, because every
    collector currently calls _run_powershell with the default. Threading it
    properly belongs with the collector-registry refactor (P2-2).
    """
    global PS_TIMEOUT_SEC
    if seconds <= 0:
        raise ValueError("timeout must be positive")
    PS_TIMEOUT_SEC = seconds


def summarize_items(
    items: Sequence[Any],
    render: Callable[[Any], str],
    limit: int = 6,
    noun: str = "more",
    separator: str = "; ",
) -> str:
    """Render a capped list that always declares what it left out.

    A tool that silently truncates is worse than one that refuses to answer:
    the reader has no way to know something was withheld. Every cap in this
    module goes through here so the count of omitted entries is always stated.
    """
    if not items:
        return ""
    shown = separator.join(render(item) for item in items[:limit])
    if len(items) > limit:
        shown += f" (+{len(items) - limit} {noun} not shown)"
    return shown


def _short_error(exc: BaseException) -> str:
    """A one-line description of a collection failure.

    subprocess.TimeoutExpired stringifies to the entire command, which puts the
    whole PowerShell body into the report and buries the actual fact: it ran
    out of time.
    """
    if isinstance(exc, subprocess.TimeoutExpired):
        return f"timed out after {int(exc.timeout or 0)}s"
    text = str(exc).strip()
    return text or exc.__class__.__name__


def _resolve_powershell() -> str:
    """Absolute path to the inbox Windows PowerShell host.

    Never resolved through PATH: the tool's own threat model is a compromised
    host, and PATH order is attacker-influenced. A 32-bit interpreter on 64-bit
    Windows is redirected away from the real System32 by WOW64, so it reaches
    the 64-bit host through the Sysnative alias instead.
    """
    global _POWERSHELL_PATH
    if _POWERSHELL_PATH is not None:
        return _POWERSHELL_PATH
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    tail = os.path.join("WindowsPowerShell", "v1.0", "powershell.exe")
    wow64 = sys.maxsize <= 2**32 and bool(os.environ.get("PROCESSOR_ARCHITEW6432"))
    candidates = [os.path.join(system_root, "Sysnative", tail)] if wow64 else []
    candidates.append(os.path.join(system_root, "System32", tail))
    for candidate in candidates:
        if os.path.isfile(candidate):
            _POWERSHELL_PATH = candidate
            return candidate
    raise CollectionError(
        f"powershell.exe not found under {system_root}; refusing to resolve it through PATH"
    )



# How the query body reaches PowerShell.
#
#   stdin   -Command - with the script piped in. The body never appears on the
#           command line, so process-creation telemetry (Sysmon EventID 1) sees
#           an inert invocation instead of the full query text.
#   command the script as a -Command argument. Always works; puts the body in
#           telemetry.
#   auto    probe stdin once, use it if the round trip succeeds, otherwise fall
#           back to command.
#
# An earlier attempt switched to stdin unverified and regressed every collector.
# The probe exists so this is decided by evidence from the host rather than by
# assumption, and so a failure degrades to a working tool rather than a dead one.
_SCRIPT_DELIVERY: str = "auto"
_STDIN_DELIVERY_OK: bool | None = None

# Deliberately not a one-liner: it exercises multi-line input, the script-block
# wrapper, a pipeline, ConvertTo-Json and the empty-result guard - everything a
# real query depends on. A trivial Write-Output would prove nothing.
_PS_STDIN_PROBE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$rows = @(
  [pscustomobject]@{
    probe = 'ok'
  }
)
$json = @($rows) | ConvertTo-Json -Compress
if (-not $json) { $json = '[]' }
$json
"""


def set_script_delivery(mode: str) -> None:
    global _SCRIPT_DELIVERY, _STDIN_DELIVERY_OK
    if mode not in ("auto", "stdin", "command"):
        raise ValueError(f"unknown script delivery mode: {mode}")
    _SCRIPT_DELIVERY = mode
    _STDIN_DELIVERY_OK = None


def _stdin_payload(script: str, *, prologue: bool = True, wrap: bool = True) -> str:
    """Wrap a script for delivery on stdin.

    The script block keeps multi-line constructs intact when the host reads
    piped input as if typed; blank lines are dropped because an empty line can
    close an incomplete statement in that mode.
    """
    body = "\n".join(line for line in script.splitlines() if line.strip())
    head = _PS_PROLOGUE if prologue else ""
    if not wrap:
        # Flat form, for the diagnostic probe: some hosts execute piped input
        # statement by statement and never close an opened script block.
        return f"{head}{body}\n"
    return f"{head}& {{\n{body}\n}}\n"


def _powershell_command(
    script: str | None = None, *, prologue: bool = True, stdin: bool = False
) -> list[str]:
    """Build the argv for one query. Kept separate so --diagnose can show it."""
    argv = [_resolve_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive"]
    if stdin:
        # No -InputFormat here. It describes how *data* piped to PowerShell is
        # interpreted; with "-Command -" the pipe carries commands, and asking
        # for both makes the host consume stdin as input and execute nothing -
        # exit 0, no output, no error, which is exactly what the host reported.
        return argv + ["-Command", "-"]
    return argv + ["-Command", (_PS_PROLOGUE + (script or "")) if prologue else (script or "")]


def _encode_stdin(payload: str) -> bytes:
    """Encode a script for stdin. Plain UTF-8, never utf-8-sig.

    The utf-8-sig *encoder* prepends a byte-order mark. Passing that codec to
    subprocess.run applies it in both directions, so the script arrived at
    PowerShell as "\ufeff$__spm = ..." and the first token was parsed as a
    command name. Input and output encodings are therefore chosen separately:
    write clean UTF-8, strip a BOM only when reading. The lstrip is defensive:
    a marker that reached the payload by any other route is removed here rather
    than shipped to the parser.
    """
    return payload.lstrip("\ufeff").encode("utf-8")


def _decode_output(raw: bytes | None) -> str:
    """Decode PowerShell output, tolerating a byte-order mark from the host."""
    return (raw or b"").decode("utf-8-sig", errors="replace")


def stdin_first_bytes(count: int = 8) -> bytes:
    """The leading bytes this build would actually write to PowerShell's stdin.

    Computed locally, no subprocess involved, so --diagnose can answer the
    "is a byte-order mark being sent" question with evidence from the host
    rather than by inference from an error message.
    """
    return _encode_stdin(_stdin_payload(_PS_STDIN_PROBE_SCRIPT))[:count]


def probe_stdin_delivery(timeout: int | None = None) -> bool:
    """One round trip to confirm the host executes a piped script block."""
    global _STDIN_DELIVERY_OK
    if _STDIN_DELIVERY_OK is not None:
        return _STDIN_DELIVERY_OK
    try:
        # Reuses the real runner so the probe cannot drift from the path it
        # is meant to validate. delivery= short-circuits the mode lookup, so
        # there is no recursion back into this function.
        completed = _run_powershell_raw(
            _PS_STDIN_PROBE_SCRIPT, timeout, delivery="stdin"
        )
        rows = _loads_ps_json((completed.stdout or "").strip())
        _STDIN_DELIVERY_OK = completed.returncode == 0 and rows == [{"probe": "ok"}]
        if not _STDIN_DELIVERY_OK:
            LOGGER.debug(
                "stdin delivery probe failed (exit %s): %r",
                completed.returncode,
                (completed.stderr or completed.stdout or "")[:200],
            )
    except (OSError, subprocess.TimeoutExpired, CollectionError) as exc:
        LOGGER.debug("stdin delivery probe error: %s", exc)
        _STDIN_DELIVERY_OK = False
    return _STDIN_DELIVERY_OK


def active_script_delivery(timeout: int | None = None) -> str:
    """Resolve 'auto' to the mode actually in use, so the report can state it."""
    if _SCRIPT_DELIVERY != "auto":
        return _SCRIPT_DELIVERY
    if not _is_windows():
        return "command"
    return "stdin" if probe_stdin_delivery(timeout) else "command"


def _run_powershell_raw(
    script: str,
    timeout: int | None = None,
    *,
    prologue: bool = True,
    delivery: str | None = None,
    wrap: bool = True,
) -> subprocess.CompletedProcess:
    """Execute one query and return the completed process untouched.

    Delivery is chosen by active_script_delivery(): stdin when the host proves
    it works, command line otherwise. Output is decoded with utf-8-sig so a
    byte-order mark from the host cannot fail every JSON parse at once; input
    is encoded as plain UTF-8 so we never send one ourselves.
    """
    if not _is_windows():
        raise CollectionError("PowerShell collection requires Windows")
    use_stdin = (delivery or active_script_delivery(timeout)) == "stdin"
    # Bytes in, bytes out. A single text= encoding would be applied to stdin
    # and stdout alike, and the two directions need different codecs.
    completed = subprocess.run(
        _powershell_command(script, prologue=prologue, stdin=use_stdin),
        input=(
            _encode_stdin(_stdin_payload(script, prologue=prologue, wrap=wrap))
            if use_stdin
            else None
        ),
        capture_output=True,
        timeout=PS_TIMEOUT_SEC if timeout is None else timeout,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return subprocess.CompletedProcess(
        completed.args,
        completed.returncode,
        stdout=_decode_output(completed.stdout),
        stderr=_decode_output(completed.stderr),
    )


def _run_powershell(script: str, timeout: int | None = None) -> str:
    global _STDIN_DELIVERY_OK
    completed = _run_powershell_raw(script, timeout)
    stderr = (completed.stderr or "").strip()

    # Self-healing fallback. The probe validates one representative script; if a
    # real query still misbehaves under stdin, drop to the command line for this
    # query and every one after it rather than returning a broken report. The
    # switch is recorded, never silent.
    if (
        active_script_delivery(timeout) == "stdin"
        and (completed.returncode != 0 or (not (completed.stdout or "").strip() and stderr))
    ):
        retry = _run_powershell_raw(script, timeout, delivery="command")
        if retry.returncode == 0 and (retry.stdout or "").strip():
            _STDIN_DELIVERY_OK = False
            _PS_WARNINGS.append(
                "stdin script delivery failed for a query and was abandoned for the "
                f"rest of this run; falling back to the command line. First error: "
                f"{stderr[:200] or 'empty output'}"
            )
            LOGGER.warning("stdin delivery failed mid-run; falling back to command line")
            completed, stderr = retry, (retry.stderr or "").strip()

    if completed.returncode != 0:
        err = stderr or (completed.stdout or "").strip()
        raise CollectionError(err or f"PowerShell exited {completed.returncode}")
    if stderr:
        # Exit code 0 with stderr output means partial collection. Surfacing it
        # is the difference between "nothing found" and "the query failed".
        truncated = stderr[:_PS_STDERR_CAP]
        suffix = "..." if len(stderr) > _PS_STDERR_CAP else ""
        _PS_WARNINGS.append(f"PowerShell non-terminating error: {truncated}{suffix}")
        LOGGER.debug("PowerShell stderr: %s", stderr)
    return completed.stdout.strip()


def _loads_ps_json(raw: str) -> list[dict[str, Any]]:
    if not raw:
        return []
    raw = raw.lstrip("\ufeff")  # belt and braces; the decode already strips a BOM
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        snippet = raw[:200].replace("\n", " ")
        raise CollectionError(
            f"PowerShell JSON parse failed: {_short_error(exc)} | first 200 chars: {snippet!r}"
        ) from exc
    if data is None:
        return []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v is not None and str(v)]
    text = str(value).strip()
    return [text] if text else []


def _as_bool(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"true", "yes", "enabled"}:
        return True
    if text in {"false", "no", "disabled"}:
        return False
    return None


_as_int = as_int_safe


def _collect_pnp_via_wmi() -> list[dict[str, Any]]:
    if _wmi_mod is None:
        raise CollectionError("Python 'wmi' package is not installed")
    # WMI needs COM initialized on the calling thread. Harmless on the main
    # thread today; required the moment collectors run concurrently.
    try:
        import pythoncom  # type: ignore

        pythoncom.CoInitialize()
    except Exception as exc:  # pragma: no cover - pywin32 is optional
        LOGGER.debug("COM initialisation unavailable: %s", exc)
    client = _wmi_mod.WMI()
    rows: list[dict[str, Any]] = []
    for cls in PNP_CLASSES:
        try:
            # Present=True mirrors what Get-PnpDevice -PresentOnly compiles
            # to, proven by the CIM error text in HOST-VERIFY H-5:
            #   SELECT * FROM Win32_PnPEntity WHERE PNPClass=... AND Present=TRUE
            # This path had no presence filter, so on a host with the `wmi`
            # package installed the inventory would accept phantom devices -
            # and the presence guard could not catch them either, because the
            # row built below carried no Present key to test.
            matches = client.Win32_PnPEntity(PNPClass=cls, Present=True)
        except Exception as exc:
            LOGGER.debug("WMI class %s failed: %s", cls, exc)
            continue
        for entity in matches:
            rows.append(
                {
                    "Class": getattr(entity, "PNPClass", None) or cls,
                    "Status": getattr(entity, "Status", None) or "Unknown",
                    "FriendlyName": getattr(entity, "Name", None) or getattr(entity, "Caption", None) or "Unknown device",
                    "InstanceId": getattr(entity, "PNPDeviceID", None) or getattr(entity, "DeviceID", None),
                    "Manufacturer": getattr(entity, "Manufacturer", None),
                    "HardwareID": list(getattr(entity, "HardwareID", None) or []),
                    "Problem": getattr(entity, "ConfigManagerErrorCode", None),
                    # Read back rather than inferred from the filter, so the
                    # presence guard has something to enforce on either path.
                    "Present": getattr(entity, "Present", None),
                    "Description": getattr(entity, "Description", None),
                    "Service": getattr(entity, "Service", None),
                    "Source": "wmi",
                }
            )
    return rows


_PS_PNP_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
$classes = @('Sensor','Biometric','SmartCardReader','Infrared')
$rows = foreach ($c in $classes) {
  Get-PnpDevice -Class $c -PresentOnly -ErrorAction SilentlyContinue | ForEach-Object {
    $props = @{}
    try {
      $keys = @(
        'DEVPKEY_Device_Manufacturer',
        'DEVPKEY_Device_DriverVersion',
        'DEVPKEY_Device_DriverDate',
        'DEVPKEY_Device_HardwareIds',
        'DEVPKEY_Device_ProblemCode',
        'DEVPKEY_Device_HasProblem',
        'DEVPKEY_Device_LocationInfo'
      )
      $_ | Get-PnpDeviceProperty -KeyName $keys -ErrorAction SilentlyContinue | ForEach-Object {
        $data = $_.Data
        if ($data -is [datetime]) {
          $props[$_.KeyName] = $data.ToUniversalTime().ToString('o')
        } elseif ($data -is [array]) {
          $props[$_.KeyName] = @($data | ForEach-Object { [string]$_ })
        } else {
          $props[$_.KeyName] = [string]$data
        }
      }
    } catch {}
    [pscustomobject]@{
      Class        = $_.Class
      Status       = [string]$_.Status
      FriendlyName = $_.FriendlyName
      InstanceId   = $_.InstanceId
      Manufacturer = $_.Manufacturer
      HardwareID   = @($_.HardwareID)
      Problem      = $_.Problem
      Service      = $_.Service
      Properties   = $props
      Source       = 'Get-PnpDevice'
    }
  }
}
if ($null -eq $rows) { $rows = @() }
$json = @($rows) | ConvertTo-Json -Depth 8 -Compress
if (-not $json) { $json = '[]' }
$json
"""

_PS_CAMERA_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
$rows = foreach ($c in @('Camera','Image')) {
  Get-PnpDevice -Class $c -PresentOnly -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
      Class        = $_.Class
      Status       = [string]$_.Status
      FriendlyName = $_.FriendlyName
      InstanceId   = $_.InstanceId
      Manufacturer = $_.Manufacturer
      HardwareID   = @($_.HardwareID)
      Problem      = $_.Problem
      Service      = $_.Service
      Source       = 'Get-PnpDevice-Camera'
    }
  }
}
if ($null -eq $rows) { $rows = @() }
$json = @($rows) | ConvertTo-Json -Depth 6 -Compress
if (-not $json) { $json = '[]' }
$json
"""

_PS_TPM_GET_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Get-Tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,TpmOwned,
  ManagedAuthLevel,RestartPending,
  ManufacturerIdTxt,ManufacturerVersion,ManufacturerId,LockedOut,LockoutCount,
  LockoutMax,AutoProvisioning | ConvertTo-Json -Compress
"""

_PS_TPM_WMI_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Get-CimInstance -Namespace 'root/CIMv2/Security/MicrosoftTpm' -ClassName Win32_Tpm |
  Select-Object SpecVersion,ManufacturerId,ManufacturerVersion,
    IsEnabled_InitialValue,IsActivated_InitialValue,IsOwned_InitialValue,
    IsPresent_InitialValue | ConvertTo-Json -Compress
"""

_PS_BITLOCKER_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$vols = Get-BitLockerVolume -ErrorAction Stop
$rows = foreach ($v in @($vols)) {
  $protectors = @()
  foreach ($k in @($v.KeyProtector)) {
    if ($null -eq $k) { continue }
    $label = $null
    if ($k.KeyProtectorType) { $label = [string]$k.KeyProtectorType }
    elseif ($null -ne $k.KeyProtectorType) { $label = [string]$k.KeyProtectorType }
    if ($label) { $protectors += $label }
  }
  [pscustomobject]@{
    MountPoint            = [string]$v.MountPoint
    VolumeStatus          = [string]$v.VolumeStatus
    ProtectionStatus      = [string]$v.ProtectionStatus
    EncryptionMethod      = [string]$v.EncryptionMethod
    EncryptionPercentage  = $v.EncryptionPercentage
    VolumeType            = [string]$v.VolumeType
    AutoUnlockEnabled     = $v.AutoUnlockEnabled
    KeyProtector          = $protectors
  }
}
if ($null -eq $rows) { $rows = @() }
$json = @($rows) | ConvertTo-Json -Depth 6 -Compress
if (-not $json) { $json = '[]' }
$json
"""

_PS_BITLOCKER_WMI_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume |
  Select-Object DriveLetter, ProtectionStatus, ConversionStatus, EncryptionMethod, VolumeType |
  ConvertTo-Json -Compress
"""

_PS_HISTORICAL_PNP_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
$classes = @('Sensor','Biometric','SmartCardReader','Infrared','Camera','Image')
$rows = foreach ($c in $classes) {
  Get-PnpDevice -Class $c -ErrorAction SilentlyContinue | ForEach-Object {
    $present = $false
    try { if ($_.Present) { $present = $true } } catch {}
    if (-not $present -and [string]$_.Status -eq 'OK') { $present = $true }
    [pscustomobject]@{
      Class        = $_.Class
      Status       = [string]$_.Status
      FriendlyName = $_.FriendlyName
      InstanceId   = $_.InstanceId
      Manufacturer = $_.Manufacturer
      HardwareID   = @($_.HardwareID)
      Present      = $present
      Source       = 'Get-PnpDevice-historical'
    }
  }
}
if ($null -eq $rows) { $rows = @() }
$json = @($rows) | ConvertTo-Json -Depth 8 -Compress
if (-not $json) { $json = '[]' }
$json
"""


def _collect_pnp_via_powershell() -> list[dict[str, Any]]:
    raw = _run_powershell(_PS_PNP_SCRIPT)
    return _loads_ps_json(raw)


def _collect_related_cameras_via_powershell() -> list[dict[str, Any]]:
    raw = _run_powershell(_PS_CAMERA_SCRIPT)
    return _loads_ps_json(raw)


def _normalize_raw_device(raw: dict[str, Any]) -> dict[str, Any]:
    props = raw.get("Properties") if isinstance(raw.get("Properties"), dict) else {}
    hardware = _as_str_list(raw.get("HardwareID") or raw.get("HardwareIds"))
    if not hardware:
        hardware = _as_str_list(props.get("DEVPKEY_Device_HardwareIds"))
    manufacturer = raw.get("Manufacturer") or props.get("DEVPKEY_Device_Manufacturer")
    problem = raw.get("Problem")
    if problem is None:
        problem = props.get("DEVPKEY_Device_ProblemCode")
    return {
        "Class": raw.get("Class") or raw.get("PNPClass") or "Unknown",
        "Status": str(raw.get("Status") or "Unknown"),
        "FriendlyName": str(raw.get("FriendlyName") or raw.get("Name") or "Unknown device"),
        "InstanceId": raw.get("InstanceId") or raw.get("PNPDeviceID") or raw.get("DeviceID"),
        "Manufacturer": str(manufacturer).strip() if manufacturer else None,
        "HardwareID": hardware,
        "Problem": _as_int(problem),
        "Service": raw.get("Service"),
        "DriverVersion": props.get("DEVPKEY_Device_DriverVersion"),
        "DriverDate": str(props.get("DEVPKEY_Device_DriverDate") or "") or None,
        "LocationInfo": props.get("DEVPKEY_Device_LocationInfo"),
        "HasProblem": _as_bool(props.get("DEVPKEY_Device_HasProblem")),
        "Source": raw.get("Source") or "unknown",
        # Both of these were dropped here, and both carried a fix that then
        # silently stopped working:
        #   _origin  - round 3's per-scan counter. Every row defaulted to
        #              "identity", so a host whose identity scan returned 0 and
        #              whose camera scan returned 2 reported identity=2,
        #              camera=0. Exactly inverted, and printed in the scope line.
        #   Present  - round 3's presence invariant. record.present was always
        #              None, so _inventory_admits never refused anything and
        #              pnp_rows_nonpresent was structurally 0. The host reading
        #              of 0 was evidence the guard was dead, not that it worked.
        # This function returns a fixed key set, so anything a caller attaches
        # upstream has to be named here or it does not survive.
        "_origin": raw.get("_origin"),
        "Present": raw.get("Present"),
    }


def _collect_pnp_devices(
    *,
    include_related_ir_cameras: bool = True,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Return (normalized devices, collector names used, errors)."""
    errors: list[str] = []
    used: list[str] = []
    raw_rows: list[dict[str, Any]] = []

    if not _is_windows():
        raise CollectionError("PnP collection requires Windows")

    try:
        raw_rows = _collect_pnp_via_wmi()
        if raw_rows:
            used.append("wmi.Win32_PnPEntity")
    except Exception as exc:
        errors.append(f"WMI PnP collector unavailable: {_short_error(exc)}")
        LOGGER.info("WMI PnP collector skipped: %s", exc)

    if not raw_rows:
        try:
            raw_rows = _collect_pnp_via_powershell()
            used.append("powershell.Get-PnpDevice")
        except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
            errors.append(f"PowerShell Get-PnpDevice failed: {_short_error(exc)}")
            raise CollectionError(f"All PnP collectors failed: {_short_error(exc)}") from exc

    # Origin tag. The scope line in the inventory renderer counted pnp rows and
    # camera rows as one number under the heading "Scanned classes: Sensor,
    # Biometric, SmartCardReader, Infrared" - so two rows from the Camera/Image
    # scan read as two identity-class rows found and discarded, when the
    # identity scan had in fact returned nothing at all.
    for row in raw_rows:
        row.setdefault("_origin", "identity")
    if include_related_ir_cameras:
        try:
            cameras = _collect_related_cameras_via_powershell()
            used.append("powershell.Get-PnpDevice.Camera")
            for row in cameras:
                row["_origin"] = "camera"
            raw_rows.extend(cameras)
        except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
            errors.append(f"Related camera collector failed: {_short_error(exc)}")

    normalized = [_normalize_raw_device(r) for r in raw_rows]
    return normalized, used, errors


def _collect_tpm_owner_auth() -> tuple[bool | None, str, int | None, str | None, list[str]]:
    """Is TPM owner authorization stored locally on this host?

    Returns (stored, status, level, level_label, sources). Only the presence of
    the value is examined; it is never read, logged, or emitted.
    """
    sources: list[str] = []
    values, status = _winreg_read(TPM_OWNER_AUTH_KEY)
    if status == "ok":
        sources.append("reg.Services.TPM.WMI.Admin")
        stored: bool | None = TPM_OWNER_AUTH_VALUE in values
        detail = "stored" if stored else "absent"
    elif status == "missing":
        sources.append("reg.Services.TPM.WMI.Admin")
        stored, detail = False, "absent (key not present)"
    elif status == "denied":
        # Not readable without elevation. Absence here is not evidence.
        stored, detail = None, "access denied (run elevated to determine)"
    else:
        stored, detail = None, status

    policy, policy_status = _winreg_read(TPM_POLICY_KEY)
    level = as_int_safe(policy.get("OSManagedAuthLevel")) if policy_status == "ok" else None
    if policy_status == "ok":
        sources.append("reg.Policies.Microsoft.TPM")
    label = TPM_AUTH_LEVEL_LABELS.get(level) if level is not None else None
    if level is not None and label is None:
        # Undocumented value. HOST-VERIFY N-11 measured OSManagedAuthLevel = 5
        # on a host where Get-Tpm reports ManagedAuthLevel "Full", and the
        # policy UI can only set 0/2/4 - so 5 is a combination the registry
        # carries and the documented map cannot express. Saying so is correct;
        # _resolve_tpm_auth_label below prefers the name Get-Tpm already hands
        # us, which is the A-1 lesson applied to this field.
        label = f"unrecognised level {level}"
    return stored, detail, level, label, sources


def signature_cell(d: "HardwareAccessDriver") -> str:
    """Signature status with its signer and expiry, per HOST-VERIFY V-8 (c).

    The operator chose option (c) over bare status, and the host data supports
    it: both drivers verify Valid over signer certificates that expired in
    2025, because both signatures are timestamped. "Valid" alone hides that a
    Microsoft WHCP signature and a KR vendor signature carry different weight,
    and hides that the signer is expired at all.
    """
    status = (d.signature_status or "").strip()
    if not status:
        return "-"
    # Operator direction (V-8): name the STATE, not the cause. But the tested
    # path must survive - it is the only reason V-1 became adjudicable, and a
    # bare "Unverifiable" is exactly as unfalsifiable as a bare "file missing"
    # was. So the state leads and the cause and path follow it.
    low = status.lower()
    if low in ("file missing", "not checked", "check failed"):
        cause = {"file missing": "file missing",
                 "not checked": "not checked",
                 "check failed": "verification failed"}[low]
        where = f": {d.resolved_path}" if d.resolved_path else ""
        return f"Unverifiable ({cause}{where})"
    cn = ""
    if d.signer:
        head = d.signer.split(",")[0].strip()
        cn = head[3:] if head.upper().startswith("CN=") else head
        cn = cn.strip('"')
    if not cn:
        return status
    bits = [cn]
    if d.signer_not_after:
        expired = d.signer_not_after < datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if expired:
            bits.append(f"signer expired {d.signer_not_after}"
                        + (", timestamped" if d.signature_timestamped else
                           ", NOT timestamped"))
    return f"{status} ({'; '.join(bits)})"


def _blocklist_enforced(dword: int | None, ci_options: int | None) -> bool | None:
    """Is the vulnerable driver blocklist actually being enforced?

    It has TWO independent enforcement paths and this only ever consulted one:
    the explicit VulnerableDriverBlocklistEnable value, and implicit
    enforcement whenever HVCI is active. Windows Security greys out its own
    toggle in the HVCI case for exactly that reason. The other source was
    already collected in the same assessment - ci_options carries CI_HVCI - and
    was never read, so a host running HVCI with no DWORD set printed
    "Driver blocklist: no" while the blocklist was being enforced.

    Truth table, and note that only one cell is False:
        DWORD 1,      any HVCI -> True   (explicitly configured)
        DWORD 0,      HVCI on  -> True   (enforced anyway; policy conflict)
        DWORD 0,      HVCI off -> False  (not enforced)
        DWORD absent, HVCI on  -> True   (enforced via HVCI)
        DWORD absent, HVCI off -> None   (undetermined - the OS default has
                                          applied since KB5018482/KB5018483 and
                                          this tool cannot establish the patch
                                          level that decides it)
    """
    hvci = None if ci_options is None else bool(ci_options & CI_HVCI)
    if dword:
        return True
    if hvci:
        return True
    if dword == 0:
        return False
    return None


def _blocklist_source_label(
    dword: int | None, registry_status: str, ci_options: int | None
) -> str:
    """Which path established the blocklist reading.

    A bare yes/no was the defect, not the value: the row never said which of
    the two sources decided it, so a policy conflict was invisible.
    """
    hvci = None if ci_options is None else bool(ci_options & CI_HVCI)
    if registry_status != "ok":
        return registry_status
    if dword:
        return "set explicitly (registry)"
    if dword == 0 and hvci:
        return "CONFLICT: disabled in registry, enforced by HVCI"
    if dword == 0:
        return "disabled explicitly (registry)"
    if hvci:
        return "not configured; enforced by HVCI"
    return "not configured and HVCI off - OS default undetermined"


def _resolve_tpm_auth_label(registry_label: str | None, gettpm_level: Any) -> str | None:
    """Prefer the name Get-Tpm resolved over an integer we cannot map.

    The collector reads both and used only the registry integer, so a host
    whose Get-Tpm said "Full" printed "unrecognised level 5". Get-Tpm resolves
    the enum itself; the registry value is corroboration and is carried in the
    text so a mismatch between the two stays visible.
    """
    name = str(gettpm_level).strip() if gettpm_level not in (None, "") else ""
    if not name:
        return registry_label
    if registry_label and registry_label.startswith("unrecognised level "):
        raw = registry_label.rsplit(" ", 1)[-1]
        return f"{name} (Get-Tpm; registry OSManagedAuthLevel={raw}, undocumented)"
    if registry_label:
        return f"{name} (Get-Tpm; registry says {registry_label})"
    return f"{name} (Get-Tpm)"


def _collect_tpm_via_gettpm() -> dict[str, Any]:
    raw = _run_powershell(_PS_TPM_GET_SCRIPT)
    rows = _loads_ps_json(raw)
    return rows[0] if rows else {}


def _collect_tpm_via_wmi_class() -> dict[str, Any]:
    raw = _run_powershell(_PS_TPM_WMI_SCRIPT)
    rows = _loads_ps_json(raw)
    return rows[0] if rows else {}


def _collect_tpm() -> tuple[TpmRecord, list[str], list[str]]:
    if not _is_windows():
        raise CollectionError("TPM collection requires Windows")

    errors: list[str] = []
    used: list[str] = []
    gettpm: dict[str, Any] = {}
    wmi_tpm: dict[str, Any] = {}

    try:
        gettpm = _collect_tpm_via_gettpm()
        used.append("powershell.Get-Tpm")
    except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        errors.append(f"Get-Tpm failed: {_short_error(exc)}")

    try:
        wmi_tpm = _collect_tpm_via_wmi_class()
        used.append("cim.Win32_Tpm")
    except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        errors.append(f"Win32_Tpm failed: {_short_error(exc)}")

    owner_auth_stored: bool | None = None
    owner_auth_status = "not collected"
    owner_auth_level: int | None = None
    owner_auth_label: str | None = None
    try:
        (
            owner_auth_stored,
            owner_auth_status,
            owner_auth_level,
            owner_auth_label,
            auth_sources,
        ) = _collect_tpm_owner_auth()
        used.extend(auth_sources)
    except (CollectionError, OSError) as exc:
        errors.append(f"TPM owner auth check failed: {_short_error(exc)}")
        owner_auth_status = f"error: {_short_error(exc)}"

    if not gettpm and not wmi_tpm:
        # The registry check stands on its own even when the WMI queries fail.
        record = TpmRecord(
            query_failed=True,
            query_error="; ".join(errors) or "TPM query returned no data",
            owner_auth_stored=owner_auth_stored,
            owner_auth_status=owner_auth_status,
            os_managed_auth_level=owner_auth_level,
            os_managed_auth_label=_resolve_tpm_auth_label(
                owner_auth_label, gettpm.get("ManagedAuthLevel")
            ),
            sources=used,
        )
        return record, used, errors

    manufacturer_id = _as_int(gettpm.get("ManufacturerId"))
    if manufacturer_id is None:
        manufacturer_id = _as_int(wmi_tpm.get("ManufacturerId"))
    manufacturer_text = gettpm.get("ManufacturerIdTxt") or decode_tpm_manufacturer_id(manufacturer_id)

    present = _as_bool(gettpm.get("TpmPresent"))
    if present is None:
        present = _as_bool(wmi_tpm.get("IsPresent_InitialValue"))

    enabled = _as_bool(gettpm.get("TpmEnabled"))
    if enabled is None:
        enabled = _as_bool(wmi_tpm.get("IsEnabled_InitialValue"))

    activated = _as_bool(gettpm.get("TpmActivated"))
    if activated is None:
        activated = _as_bool(wmi_tpm.get("IsActivated_InitialValue"))

    owned = _as_bool(gettpm.get("TpmOwned"))
    if owned is None:
        owned = _as_bool(wmi_tpm.get("IsOwned_InitialValue"))

    record = TpmRecord(
        present=present,
        enabled=enabled,
        activated=activated,
        owned=owned,
        ready=_as_bool(gettpm.get("TpmReady")),
        spec_version=(str(wmi_tpm.get("SpecVersion")).strip() if wmi_tpm.get("SpecVersion") else None),
        manufacturer_id=manufacturer_id,
        manufacturer_id_text=str(manufacturer_text).strip() if manufacturer_text else None,
        manufacturer_version=(
            str(gettpm.get("ManufacturerVersion") or wmi_tpm.get("ManufacturerVersion") or "").strip() or None
        ),
        owner_auth_stored=owner_auth_stored,
        owner_auth_status=owner_auth_status,
        os_managed_auth_level=owner_auth_level,
        os_managed_auth_label=_resolve_tpm_auth_label(
            owner_auth_label, gettpm.get("ManagedAuthLevel")
        ),
        locked_out=_as_bool(gettpm.get("LockedOut")),
        lockout_count=_as_int(gettpm.get("LockoutCount")),
        lockout_max=_as_int(gettpm.get("LockoutMax")),
        auto_provisioning=(
            str(gettpm.get("AutoProvisioning")).strip() if gettpm.get("AutoProvisioning") is not None else None
        ),
        query_failed=False,
        sources=used,
    )
    return record, used, errors


def _protector_label(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    number = _as_int(value)
    if number is not None and number in KEY_PROTECTOR_NAMES:
        return KEY_PROTECTOR_NAMES[number]
    text = str(value).strip()
    return text or None


# Win32_EncryptableVolume reports these as uint32; Get-BitLockerVolume reports
# the same field names as enum *names*. The parser decoded ProtectionStatus and
# nothing else, so on the WMI fallback path the report printed
# "EncryptionMethod: 7" and "VolumeType: 0" as though they were names.
# Get-BitLockerVolume returns enum NAMES and Win32_EncryptableVolume returns
# uint32. Round 4 decoded the integers to "XTS-AES-128" and left the enum names
# raw, so the same volume encrypted the same way reads "XtsAes128" from one
# source and "XTS-AES-128" from the other. One spelling, whichever source
# answered.
BITLOCKER_PS_ENCRYPTION_METHOD = {
    "none": "None",
    "aes128diffuser": "AES-128 with diffuser",
    "aes256diffuser": "AES-256 with diffuser",
    "aes128": "AES-128",
    "aes256": "AES-256",
    "hardwareencryption": "Hardware encryption",
    "xtsaes128": "XTS-AES-128",
    "xtsaes256": "XTS-AES-256",
}

BITLOCKER_WMI_ENCRYPTION_METHOD = {
    0: "None", 1: "AES-128 with diffuser", 2: "AES-256 with diffuser",
    3: "AES-128", 4: "AES-256", 6: "Hardware encryption",
    7: "XTS-AES-128", 8: "XTS-AES-256",
}
BITLOCKER_WMI_VOLUME_TYPE = {
    0: "OperatingSystem", 1: "FixedDisk", 2: "Removable",
}
BITLOCKER_WMI_CONVERSION_STATUS = {
    0: "FullyDecrypted", 1: "FullyEncrypted", 2: "EncryptionInProgress",
    3: "DecryptionInProgress", 4: "EncryptionPaused", 5: "DecryptionPaused",
}


def _parse_bitlocker_volume(raw: dict[str, Any], source: str | None = None) -> BitLockerVolume:
    protectors_raw = raw.get("KeyProtector") or raw.get("KeyProtectors") or raw.get("key_protectors") or []
    if not isinstance(protectors_raw, list):
        protectors_raw = [protectors_raw]
    protectors = [p for p in (_protector_label(x) for x in protectors_raw) if p]
    protection = raw.get("ProtectionStatus")
    if protection is None:
        protection = raw.get("protection_status")
    # WMI ProtectionStatus: 0 Unprotected, 1 Protected, 2 Unknown
    if isinstance(protection, int):
        protection = {0: "Off", 1: "On", 2: "Unknown"}.get(protection, str(protection))
    pct = raw.get("EncryptionPercentage")
    try:
        pct_val = float(pct) if pct is not None and pct != "" else None
    except (TypeError, ValueError):
        pct_val = None
    method = raw.get("EncryptionMethod")
    if isinstance(method, int) and not isinstance(method, bool):
        method = BITLOCKER_WMI_ENCRYPTION_METHOD.get(method, f"unknown({method})")
    elif isinstance(method, str) and method.strip():
        key = re.sub(r"[^a-z0-9]", "", method.lower())
        method = BITLOCKER_PS_ENCRYPTION_METHOD.get(key, method)
    vtype = raw.get("VolumeType")
    if isinstance(vtype, int) and not isinstance(vtype, bool):
        vtype = BITLOCKER_WMI_VOLUME_TYPE.get(vtype, f"unknown({vtype})")
    # ConversionStatus is the WMI name for what Get-BitLockerVolume calls
    # VolumeStatus. The WMI query selects it explicitly and the parser read
    # only VolumeStatus, so the field was fetched and discarded on that path.
    vstatus = raw.get("VolumeStatus")
    if vstatus is None:
        vstatus = raw.get("ConversionStatus")
        if isinstance(vstatus, int) and not isinstance(vstatus, bool):
            vstatus = BITLOCKER_WMI_CONVERSION_STATUS.get(vstatus, f"unknown({vstatus})")
    mount = raw.get("MountPoint") or raw.get("DriveLetter") or "?"
    return BitLockerVolume(
        mount_point=str(mount),
        protection_status=str(protection or "Unknown"),
        volume_status=(str(vstatus) if vstatus is not None else None),
        encryption_method=(str(method) if method is not None else None),
        encryption_percentage=pct_val,
        key_protectors=protectors,
        volume_type=(str(vtype) if vtype is not None else None),
        auto_unlock=_as_bool(raw.get("AutoUnlockEnabled")),
        # Which read produced this row. The two sources supply different field
        # sets, so an empty key-protector list means "none" from one and "never
        # asked" from the other - and the section could not previously tell a
        # reader which.
        source=source,
        key_protectors_available=("KeyProtector" in raw or "KeyProtectors" in raw),
    )


def _collect_bitlocker() -> tuple[BitLockerRecord, list[str], list[str]]:
    if not _is_windows():
        raise CollectionError("BitLocker collection requires Windows")

    errors: list[str] = []
    used: list[str] = []
    rows: list[dict[str, Any]] = []

    try:
        raw = _run_powershell(_PS_BITLOCKER_SCRIPT)
        rows = _loads_ps_json(raw)
        used.append("powershell.Get-BitLockerVolume")
    except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        errors.append(f"Get-BitLockerVolume failed: {_short_error(exc)}")

    if not rows:
        try:
            raw = _run_powershell(_PS_BITLOCKER_WMI_SCRIPT)
            rows = _loads_ps_json(raw)
            used.append("cim.Win32_EncryptableVolume")
        except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
            errors.append(f"Win32_EncryptableVolume failed: {_short_error(exc)}")

    if not rows and errors:
        return (
            BitLockerRecord(query_failed=True, query_error="; ".join(errors), sources=used),
            used,
            errors,
        )

    # The tag for whichever read actually produced rows, not both.
    row_source = used[-1] if used else None
    volumes = [_parse_bitlocker_volume(r, source=row_source) for r in rows]
    return BitLockerRecord(query_failed=False, volumes=volumes, sources=used), used, errors


_PS_DMA_CONTROLLER_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$needles = 'Thunderbolt','USB4','USB 4','TBT'
$rows = Get-PnpDevice | Where-Object {
  $blob = ('{0} {1} {2} {3}' -f $_.FriendlyName, $_.InstanceId, $_.Class, $_.Manufacturer)
  foreach ($n in $needles) { if ($blob -like ('*{0}*' -f $n)) { return $true } }
  return $false
} | ForEach-Object {
  [pscustomobject]@{
    FriendlyName = [string]$_.FriendlyName
    InstanceId   = [string]$_.InstanceId
    Status       = [string]$_.Status
    Class        = [string]$_.Class
    Manufacturer = [string]$_.Manufacturer
    Present      = [bool]$_.Present
  }
}
$json = @($rows) | ConvertTo-Json -Depth 4 -Compress
if (-not $json) { $json = '[]' }
$json
"""

_PS_DEVICEGUARD_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$g = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard
if ($g) {
  [pscustomobject]@{
    VirtualizationBasedSecurityStatus = $g.VirtualizationBasedSecurityStatus
    SecurityServicesRunning           = @($g.SecurityServicesRunning)
    SecurityServicesConfigured        = @($g.SecurityServicesConfigured)
    AvailableSecurityProperties       = @($g.AvailableSecurityProperties)
  } | ConvertTo-Json -Compress
} else {
  '[]'
}
"""

# NOTHING in this script may touch $cert.PrivateKey, GetRSAPrivateKey, or any
# other accessor that opens a key container. For a card-backed key that call
# asks the CSP for the key, which raises a modal "insert a smart card" dialog,
# can prompt for a PIN, and blocks the query until a human dismisses it. A
# read-only auditor must never drive a cryptographic provider. HasPrivateKey is
# safe: it reads the stored property, it does not open anything. The provider
# name is recovered passively from the store blob instead - see
# _cert_provider_map.
# Win32_SystemDriver carries running state and the binary path, neither of
# which the registry has. The signature check runs only for the drivers in
# HW_ACCESS_DRIVERS - Get-AuthenticodeSignature does a catalog lookup per file,
# and checking every driver on the machine would cost tens of seconds.
#
# This is the one script with a substituted value. The names come from a module
# constant, never from user input, and each is validated against a strict
# character class before substitution. There is a test for both halves.
_PS_SYSTEM_DRIVER_TEMPLATE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$names = @(__DRIVER_NAMES__)
$rows = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue |
  Where-Object { $n = $_.Name; @($names | Where-Object { $n -like $_ }).Count -gt 0 } |
  ForEach-Object {
    $raw = [string]$_.PathName
    # The normalization below is retained for the Test-Path call, but the RAW
    # value is now returned as well. HOST-VERIFY V-1 showed a host reporting
    # 'file missing' for two drivers that were on disk, and the report gave no
    # way to tell which path had been tested - so the claim was unfalsifiable
    # from the output. Python re-derives the path with _normalize_driver_path,
    # which has fixtures; a regex inside a PowerShell string does not.
    # WAS: $raw -replace '^..\\', '' — which is the regex "any two characters
    # then a backslash". Against \??\C:\Windows\... that matches nothing:
    # position 2 is '?', not a backslash. So $clean stayed an NT device path,
    # Test-Path could not resolve it, and EVERY driver whose ImagePath carries
    # the \??\ prefix reported 'file missing'.
    #
    # HOST-VERIFY N-5 proved the cost: ACE-BASE.sys and xhunter1.sys are both
    # on disk with Authenticode Status 'Valid', and the report called them
    # orphaned keys with missing binaries. Worse, 'Bad signature' was
    # unreachable for any NT-prefixed path, so an unsigned driver would have
    # read as 'file missing' rather than as a signature failure.
    $clean = $raw -replace '^\\\?\?\\', ''
    # A service ImagePath may be quoted and may carry arguments; both break
    # Test-Path. \SystemRoot\ and a bare System32\ prefix need expanding.
    if ($clean -match '^"([^"]+)"') { $clean = $matches[1] }
    elseif ($clean -match '^(.+?\.(?i:sys|exe|dll))(\s|$)') { $clean = $matches[1] }
    if ($clean -like '\SystemRoot\*') { $clean = $env:SystemRoot + $clean.Substring(11) }
    elseif ($clean -like 'System32\*')  { $clean = $env:SystemRoot + '\' + $clean }
    $sig = 'not checked'
    $signer = ''
    $notAfter = ''
    $stamped = $false
    if ($clean -and (Test-Path -LiteralPath $clean)) {
      try {
        $s = Get-AuthenticodeSignature -LiteralPath $clean
        $sig = [string]$s.Status
        if ($s.SignerCertificate) {
      $signer = [string]$s.SignerCertificate.Subject
      $notAfter = $s.SignerCertificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd')
    }
    # A signature stays Valid over an expired signer when it is timestamped.
    # HOST-VERIFY V-1 measured exactly that on both drivers, so the report can
    # distinguish "valid" from "valid, signer expired, timestamped".
    if ($s.TimeStamperCertificate) { $stamped = $true }
      } catch { $sig = 'check failed' }
    } elseif ($clean) {
      $sig = 'file missing'
    }
    [pscustomobject]@{
      Name      = [string]$_.Name
      State     = [string]$_.State
      Started   = [bool]$_.Started
      StartMode = [string]$_.StartMode
      PathName  = $raw
      Signature = $sig
      RawPath = $raw
      ResolvedPath = $clean
      Signer    = $signer
      SignerNotAfter = $notAfter
      Timestamped    = $stamped
    }
  }
$json = @($rows) | ConvertTo-Json -Depth 4 -Compress
if (-not $json) { $json = '[]' }
$json
"""

# Every process with its image path, so a loaded driver can be tied to whatever
# is running out of the same directory.
# bcdedit is the supported way to read the boot store. It needs elevation,
# which this tool assumes. Output is captured whole and parsed in Python.
_PS_BCD_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$exe = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
$text = ''
if (Test-Path -LiteralPath $exe) {
  try { $text = (& $exe /enum '{current}' 2>&1 | Out-String) } catch { $text = '' }
}
[pscustomobject]@{ Output = [string]$text } | ConvertTo-Json -Compress
"""


_PS_PROCESS_PATH_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$rows = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{
    Name           = [string]$_.Name
    ProcessId      = [int]$_.ProcessId
    ExecutablePath = [string]$_.ExecutablePath
  }
}
$json = @($rows) | ConvertTo-Json -Depth 3 -Compress
if (-not $json) { $json = '[]' }
$json
"""

# A service name, optionally with a single trailing * for versioned drivers.
# Still strict: nothing that could carry meaning into the PowerShell string.
#
# Real service names are not identifiers. ACE-BASE has a hyphen, "AntiCheatExpert
# Service" has a space, and an earlier character class of [A-Za-z0-9_]+ meant
# those names could not be expressed at all - which is why the anti-cheat table
# carried underscored approximations that never matched anything. Hyphen, space
# and dot are now allowed internally.
#
# The class is still an allowlist and still excludes everything that could carry
# meaning into a single-quoted PowerShell string or the -like operator: no
# quote, backtick, dollar, semicolon, bracket or question mark. Names must begin
# and end with an identifier character, so no leading or trailing whitespace can
# be smuggled in either.
_DRIVER_NAME_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_ .-]*[A-Za-z0-9_])?\*?$")


def build_system_driver_script() -> str:
    """Substitute the driver allowlist into the query, with validation.

    Raises CollectionError, not ValueError. run_collectors() catches
    CollectionError and degrades the section; a ValueError escapes it and takes
    the whole run down. A typo in a table constant should cost one section, not
    the report - and it is a table constant, so the failure names the entry.
    """
    names = []
    for _driver, pattern, _caps, _shipped in HW_ACCESS_DRIVERS:
        if not _DRIVER_NAME_RE.match(pattern):
            raise CollectionError(f"refusing to substitute driver name {pattern!r}")
        names.append("'" + pattern + "'")
    return _PS_SYSTEM_DRIVER_TEMPLATE.replace("__DRIVER_NAMES__", ",".join(names))


_PS_SMARTCARD_CERT_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$stores = @('Cert:\CurrentUser\My','Cert:\LocalMachine\My')
$rows = foreach ($store in $stores) {
  Get-ChildItem -Path $store -ErrorAction SilentlyContinue | ForEach-Object {
    $c = $_
    $ekus = New-Object System.Collections.ArrayList
    foreach ($ext in $c.Extensions) {
      if ($ext.Oid.Value -eq '2.5.29.37') {
        try {
          foreach ($u in $ext.EnhancedKeyUsages) { [void]$ekus.Add([string]$u.Value) }
        } catch {}
      }
    }
    [pscustomobject]@{
      Store         = [string]$store
      Subject       = [string]$c.Subject
      Issuer        = [string]$c.Issuer
      Thumbprint    = [string]$c.Thumbprint
      SerialNumber  = [string]$c.SerialNumber
      NotBefore     = $c.NotBefore.ToUniversalTime().ToString('o')
      NotAfter      = $c.NotAfter.ToUniversalTime().ToString('o')
      HasPrivateKey = [bool]$c.HasPrivateKey
      Ekus          = @($ekus)
    }
  }
}
$json = @($rows) | ConvertTo-Json -Depth 5 -Compress
if (-not $json) { $json = '[]' }
$json
"""


_PS_SDR_PNP_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$vids = @(
  'VID_0BDA&PID_2832','VID_0BDA&PID_2838','VID_0BDA&PID_2831',
  'VID_1D50&PID_6089','VID_1D50&PID_604B','VID_1D50&PID_CC15','VID_1FC9&PID_000C',
  'VID_2CF0&PID_5246','VID_2CF0&PID_5250','VID_1D50&PID_6066','VID_04B4&PID_00F3',
  'VID_1D50&PID_6108','VID_1D50&PID_6107','VID_0403&PID_601F',
  'VID_2500&PID_0020','VID_3923&PID_7813','VID_1D50&PID_60A1','VID_1DF7&PID_2500'
)
$names = @('RTL2832','RTL-SDR','DVB-T','HackRF','bladeRF','LimeSDR','USRP','Airspy','SDRplay','RTL2838')
$rows = Get-PnpDevice | Where-Object {
  $blob = ('{0} {1} {2}' -f $_.FriendlyName, $_.InstanceId, (($_.HardwareID) -join ' '))
  foreach ($v in $vids) { if ($blob -like ('*{0}*' -f $v)) { return $true } }
  foreach ($n in $names) { if ($blob -like ('*{0}*' -f $n)) { return $true } }
  return $false
} | ForEach-Object {
  [pscustomobject]@{
    FriendlyName = [string]$_.FriendlyName
    InstanceId   = [string]$_.InstanceId
    Status       = [string]$_.Status
    Class        = [string]$_.Class
    Manufacturer = [string]$_.Manufacturer
    Present      = [bool]$_.Present
    HardwareID   = @($_.HardwareID)
  }
}
$json = @($rows) | ConvertTo-Json -Depth 5 -Compress
if (-not $json) { $json = '[]' }
$json
"""


def _dma_policy_from_registry() -> tuple[int | None, str, list[AllowedBus], list[str]]:
    used: list[str] = []
    policy = None
    buses: list[AllowedBus] = []
    # STATUS CONSUMED. This is the site the P-5 defect was about: an absent
    # policy and an unreadable one must not both render as "no policy set".
    vals, policy_status = _winreg_values(
        r"SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection")
    if policy_status == "ok":
        used.append("reg.KernelDmaProtection")
        raw = vals.get("DeviceEnumerationPolicy")
        try:
            policy = int(raw) if raw is not None else None
        except (TypeError, ValueError):
            policy = None
    # STATUS IGNORED: absent and denied both yield no buses to report, and
    # the section's own source tag records whether the key was reachable.
    bus_vals, _ = _winreg_values(r"SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowedBuses")
    if bus_vals:
        used.append("reg.DmaSecurity.AllowedBuses")
        for name, hid in bus_vals.items():
            buses.append(AllowedBus(name=str(name), hardware_id=str(hid) if hid is not None else None))
    # policy_status returned so the caller can tell a measured absence from
    # an unreadable key. Without it the tier layer asserted a gap from both.
    return policy, policy_status, buses, used


def _as_int_list(value: Any) -> list[int]:
    """Coerce a WMI uint32 array to ints. Tolerates a scalar: PowerShell can
    serialize a single-element array as a bare value."""
    if value is None:
        return []
    items = value if isinstance(value, (list, tuple)) else [value]
    return [n for n in (as_int_safe(x) for x in items) if n is not None]


def _normalize_driver_path(image_path: str | None) -> str | None:
    """Turn a service ImagePath into a plain filesystem path."""
    if not image_path:
        return None
    text = str(image_path).strip()
    # A service ImagePath may be quoted AND carry arguments:
    #   "C:\Program Files\AntiCheatExpert\SGuard\x64\SGuardSvc64.exe" -autorun
    # .strip('"') removed the leading quote and left the trailing quote and the
    # argument attached, so the path never resolved. HOST-VERIFY N-5 measured
    # exactly this shape and Test-Path returned False for it.
    quoted = re.match(r'^"([^"]+)"', text)
    if quoted:
        text = quoted.group(1)
    else:
        unquoted = re.match(r"^(.+?\.(?:sys|exe|dll))(?:\s|$)", text, re.IGNORECASE)
        if unquoted:
            text = unquoted.group(1)
    text = text.strip().strip('"')
    for prefix in ("\\??\\", "\\\\?\\"):
        if text.lower().startswith(prefix.lower()):
            text = text[len(prefix):]
    if text.lower().startswith("\\systemroot\\"):
        root = os.environ.get("SystemRoot") or "C:\\Windows"
        text = root.rstrip("\\") + text[len("\\systemroot"):]
    elif text.lower().startswith("system32\\"):
        root = os.environ.get("SystemRoot") or "C:\\Windows"
        text = root.rstrip("\\") + "\\" + text
    return text or None


def classify_driver_path(image_path: str | None) -> tuple[str, str | None]:
    """Return (location_class, attributed_application).

    This is attribution by location, which is what an unprivileged audit can
    reach. Naming the *process* holding the driver open would require
    system-wide handle enumeration through NtQuerySystemInformation, needs
    elevation, and is out of scope for a read-only tool. Location answers the
    question that actually matters in practice: did an installer put this here,
    or did something drop it somewhere anyone can write.
    """
    path = _normalize_driver_path(image_path)
    if not path:
        return "unknown", None
    low = path.lower()
    if any(m in low for m in DRIVER_USER_WRITABLE_MARKERS):
        return "user-writable", None
    if any(m in low for m in DRIVER_VENDOR_MARKERS):
        parts = [p for p in path.replace("/", "\\").split("\\") if p]
        app = None
        for index, part in enumerate(parts):
            if part.lower().startswith("program files"):
                app = parts[index + 1] if index + 1 < len(parts) else None
                break
        return "vendor install", app
    if any(m in low for m in DRIVER_SYSTEM_MARKERS):
        return "system drivers", None
    if any(m in low for m in DRIVER_WINDOWS_ROOT_MARKERS):
        return "windows root", None
    return "unknown", None


def _service_detail(name: str) -> tuple[bool, str | None, str | None]:
    """Is this filter driver actually installed, and where does it live?"""
    values, status = _winreg_read(f"SYSTEM\\CurrentControlSet\\Services\\{name}")
    if status != "ok" or not values:
        return (status == "ok"), None, None
    start = as_int_safe(values.get("Start"))
    return True, values.get("ImagePath"), SERVICE_START_LABELS.get(start) if start is not None else None


def _collect_interception() -> tuple[InterceptionAssessment, list[str], list[str]]:
    """Read class filter drivers and biometric adapter registrations.

    One key per device class plus one per biometric device. Bounded: filters
    are positional, so there is nothing to walk.
    """
    if not _is_windows():
        raise CollectionError("Interception collection requires Windows")
    errors: list[str] = []
    used: list[str] = []
    filters: list[ClassFilter] = []
    checked: list[str] = []

    for class_name, guid, sees in INTERCEPTION_CLASSES:
        values, status = _winreg_read(f"SYSTEM\\CurrentControlSet\\Control\\Class\\{guid}")
        if status == "denied":
            errors.append(f"class {class_name} not readable (access denied)")
            continue
        checked.append(class_name)
        if status != "ok":
            continue
        used.append("reg.Control.Class")
        for position in ("UpperFilters", "LowerFilters"):
            entries = values.get(position)
            if not entries:
                continue
            for driver in _as_str_list(entries):
                driver = str(driver).strip()
                if not driver:
                    continue
                present, image, start = _service_detail(driver)
                filters.append(
                    ClassFilter(
                        device_class=class_name,
                        class_guid=guid,
                        position=position,
                        driver=driver,
                        sees=sees,
                        inbox=driver.lower() in INBOX_CLASS_FILTERS,
                        service_present=present,
                        image_path=image,
                        start_label=start,
                    )
                )

    adapters: list[BiometricAdapter] = []
    biometric_guid = "{53d29ef7-377c-4d14-864b-eb3a85769359}"
    try:
        enum_root = "SYSTEM\\CurrentControlSet\\Enum"
        for enumerator in _winreg_subkeys(enum_root):
            for device in _winreg_subkeys(f"{enum_root}\\{enumerator}"):
                for instance in _winreg_subkeys(f"{enum_root}\\{enumerator}\\{device}"):
                    base = f"{enum_root}\\{enumerator}\\{device}\\{instance}"
                    values, status = _winreg_read(base)
                    if status != "ok":
                        continue
                    if str(values.get("ClassGUID") or "").lower() != biometric_guid:
                        continue
                    name = values.get("FriendlyName") or values.get("DeviceDesc")
                    for slot_index in _winreg_subkeys(
                        f"{base}\\Device Parameters\\WinBio\\Configurations"
                    ) or ["0"]:
                        cfg, cfg_status = _winreg_read(
                            f"{base}\\Device Parameters\\WinBio\\Configurations\\{slot_index}"
                        )
                        if cfg_status != "ok":
                            continue
                        used.append("reg.Enum.WinBio.Configurations")
                        for value_name in WINBIO_ADAPTER_VALUES:
                            binary = cfg.get(value_name)
                            if not binary:
                                continue
                            adapters.append(
                                BiometricAdapter(
                                    instance_id=f"{enumerator}\\{device}\\{instance}",
                                    device_name=str(name) if name else None,
                                    slot=value_name.replace("AdapterBinary", "").lower(),
                                    binary=str(binary),
                                    inbox=str(binary).strip().lower() in WINBIO_INBOX_ADAPTERS,
                                )
                            )
    except (CollectionError, OSError) as exc:
        errors.append(f"biometric adapter enumeration failed: {_short_error(exc)}")

    assessment = InterceptionAssessment(
        query_failed=bool(errors) and not filters and not adapters,
        query_error="; ".join(errors) if errors else None,
        filters=filters,
        adapters=adapters,
        classes_checked=checked,
        sources=sorted(set(used)),
    )
    return assessment, used, errors


def _query_code_integrity() -> tuple[int | None, str]:
    """Effective kernel code-integrity state via NtQuerySystemInformation.

    ctypes is standard library, and this is the authoritative answer: it is
    what the kernel is actually doing, rather than what the boot store asked
    for. No elevation is required for this particular class.
    """
    if not _is_windows():
        return None, "not Windows"
    try:
        import ctypes
    except ImportError:  # pragma: no cover - ctypes ships with CPython
        return None, "ctypes unavailable"

    class _CodeIntegrityInformation(ctypes.Structure):
        _fields_ = [
            ("Length", ctypes.c_ulong),
            ("CodeIntegrityOptions", ctypes.c_ulong),
        ]

    try:
        ntdll = ctypes.WinDLL("ntdll")  # type: ignore[attr-defined]
    except (AttributeError, OSError) as exc:
        return None, f"ntdll unavailable: {exc}"
    info = _CodeIntegrityInformation()
    info.Length = ctypes.sizeof(info)
    returned = ctypes.c_ulong(0)
    try:
        status = ntdll.NtQuerySystemInformation(
            SYSTEM_CODE_INTEGRITY_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
            ctypes.byref(returned),
        )
    except OSError as exc:
        return None, f"query failed: {exc}"
    if status != 0:
        return None, f"NTSTATUS 0x{status & 0xFFFFFFFF:08x}"
    return int(info.CodeIntegrityOptions), "ok"


def parse_bcd_output(text: str) -> dict[str, str]:
    """Pull the flags of interest out of `bcdedit /enum {current}`.

    Output is two columns separated by whitespace, one setting per line.
    Anything not in BCD_FLAGS_OF_INTEREST is ignored.
    """
    flags: dict[str, str] = {}
    for line in (text or "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        name = parts[0].strip().lower()
        if name in BCD_FLAGS_OF_INTEREST:
            flags[name] = parts[1].strip()
    return flags


def _collect_boot_integrity() -> tuple[BootIntegrityAssessment, list[str], list[str]]:
    if not _is_windows():
        raise CollectionError("Boot integrity collection requires Windows")
    errors: list[str] = []
    used: list[str] = []

    options, ci_status = _query_code_integrity()
    if ci_status == "ok":
        used.append("ntdll.SystemCodeIntegrityInformation")
    else:
        errors.append(f"code integrity query: {ci_status}")

    flags = (
        [label for bit, label in sorted(CODE_INTEGRITY_FLAGS.items()) if options & bit]
        if options is not None
        else []
    )

    ci_config, ci_config_status = _winreg_read(CI_CONFIG_KEY)
    blocklist = as_int_safe(ci_config.get(BLOCKLIST_VALUE)) if ci_config_status == "ok" else None
    if ci_config_status == "ok":
        used.append("reg.Control.CI.Config")
    blocklist_status = (
        ci_config_status
        if ci_config_status != "ok"
        else ("set" if blocklist is not None else "not configured (OS default applies)")
    )

    bcd_flags: dict[str, str] = {}
    bcd_status = "not run"
    try:
        rows = _loads_ps_json(_run_powershell(_PS_BCD_SCRIPT))
        text = str(rows[0].get("Output") or "") if rows and isinstance(rows[0], dict) else ""
        bcd_flags = parse_bcd_output(text)
        if text.strip():
            used.append("bcdedit.enum.current")
            bcd_status = "ok"
        else:
            bcd_status = "empty (bcdedit needs elevation)"
    except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        bcd_status = f"failed: {_short_error(exc)}"
        errors.append(f"bcdedit: {_short_error(exc)}")

    assessment = BootIntegrityAssessment(
        query_failed=options is None and not bcd_flags,
        query_error="; ".join(errors) if errors else None,
        ci_options=options,
        ci_flags=flags,
        ci_status=ci_status,
        test_signing=None if options is None else bool(options & CI_TESTSIGN),
        code_integrity_enabled=None if options is None else bool(options & CI_ENABLED),
        debug_mode=None if options is None else bool(options & CI_DEBUGMODE),
        hvci_enabled=None if options is None else bool(options & CI_HVCI),
        blocklist_enabled=_blocklist_enforced(blocklist, options),
        blocklist_status=_blocklist_source_label(blocklist, blocklist_status, options),
        bcd_status=bcd_status,
        bcd_flags=bcd_flags,
        sources=sorted(set(used)),
    )
    return assessment, used, errors


def resolve_service_name(pattern: str, installed: Sequence[str]) -> str:
    """Resolve a driver entry to the service actually present.

    A trailing * matches by prefix, because some vendors version the service
    name (AMDRyzenMasterDriverV19, V20 and so on). Without a match the pattern
    is returned with the wildcard stripped, so the record still reports the
    driver as absent under a sensible name.
    """
    if not pattern.endswith("*"):
        return pattern
    prefix = pattern[:-1].lower()
    for name in installed:
        if name.lower().startswith(prefix):
            return name
    return pattern[:-1]


def _collect_hardware_access() -> tuple[HardwareAccessAssessment, list[str], list[str]]:
    """Which drivers on this host can reach the hardware directly.

    Service-first, exactly like the generic USB driver check: each known driver
    is asked whether it is installed rather than walking every service on the
    machine. Twenty-one registry reads, bounded and stable.
    """
    if not _is_windows():
        raise CollectionError("Hardware access collection requires Windows")
    errors: list[str] = []
    used: list[str] = []
    drivers: list[HardwareAccessDriver] = []

    runtime: dict[str, dict[str, Any]] = {}
    signature_check = "not run"
    try:
        for row in _loads_ps_json(_run_powershell(build_system_driver_script())):
            if isinstance(row, dict) and row.get("Name"):
                runtime[str(row["Name"]).strip().lower()] = row
        used.append("cim.Win32_SystemDriver")
        signature_check = "ran" if _is_admin() else "ran (unelevated: may be partial)"
    except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        # Registry state alone is still worth having; runtime is the bonus.
        errors.append(f"driver runtime state unavailable: {_short_error(exc)}")
        signature_check = f"failed: {_short_error(exc)}"

    # One enumeration of Enum\\Root, matched against the names we track.
    legacy_nodes: dict[str, str] = {}
    try:
        for name in _winreg_subkeys(LEGACY_ENUM_ROOT):
            if not name.upper().startswith(LEGACY_PREFIX):
                continue
            service = name[len(LEGACY_PREFIX) :].lower()
            legacy_nodes[service] = _winreg_last_write_utc(f"{LEGACY_ENUM_ROOT}\\{name}") or ""
        if legacy_nodes:
            used.append("reg.Enum.Root.LEGACY")
    except (CollectionError, OSError) as exc:
        errors.append(f"legacy device node enumeration failed: {_short_error(exc)}")

    by_directory: dict[str, list[str]] = {}
    process_attribution = "not run"
    try:
        for row in _loads_ps_json(_run_powershell(_PS_PROCESS_PATH_SCRIPT)):
            if not isinstance(row, dict):
                continue
            exe = str(row.get("ExecutablePath") or "").strip()
            if not exe:
                continue
            directory = os.path.dirname(exe).rstrip("\\").lower()
            by_directory.setdefault(directory, []).append(
                f"{row.get('Name') or '?'} (pid {row.get('ProcessId')})"
            )
        used.append("cim.Win32_Process")
        process_attribution = (
            "ran" if _is_admin() else "ran (unelevated: other users' paths hidden)"
        )
    except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        errors.append(f"process attribution unavailable: {_short_error(exc)}")
        process_attribution = f"failed: {_short_error(exc)}"

    # One enumeration of the service list so prefix entries resolve to the
    # actual versioned name present on this host.
    installed_services: list[str] = []
    try:
        installed_services = _winreg_subkeys("SYSTEM\\CurrentControlSet\\Services")
    except (CollectionError, OSError) as exc:
        errors.append(f"service enumeration failed: {_short_error(exc)}")

    for driver, service_pattern, capabilities, shipped_by in HW_ACCESS_DRIVERS:
        service = resolve_service_name(service_pattern, installed_services)
        base = f"SYSTEM\\CurrentControlSet\\Services\\{service}"
        values, status = _winreg_read(base)
        record = HardwareAccessDriver(
            driver=driver,
            service=service,
            capabilities=list(capabilities),
            capability_labels=[HW_CAPABILITY_LABELS.get(c, c) for c in capabilities],
            shipped_by=shipped_by,
            is_anticheat=driver in ANTICHEAT_DRIVER_NAMES,
            abuse_note=(
                ANTICHEAT_BY_NAME[driver].note if driver in ANTICHEAT_BY_NAME else None
            ),
        )
        # Residue first. The device node lives under Enum\\Root, not under the
        # service key, so a denied service key does not stop us reading it -
        # and on a host where the service is ACL'd shut, the node may be the
        # only evidence available.
        if service.lower() in legacy_nodes:
            record.legacy_node = True
            record.legacy_last_write_utc = legacy_nodes[service.lower()] or None
        if status == "denied":
            errors.append(f"service {service} not readable (access denied)")
            drivers.append(record)
            continue
        # Credited only when the key existed AND held values, so a service that
        # was read and found absent left no provenance at all: the Sources list
        # said "found" while reading as "read", and fifteen tracked services
        # produced three tags. An absence this tool reports as a result needs
        # the source that established it named like any other.
        if status in ("ok", "missing", "denied"):
            used.append(f"reg.Services.{service}")
        if status == "ok" and values:
            start = as_int_safe(values.get("Start"))
            record.present = True
            record.start_type = start
            record.start_label = SERVICE_START_LABELS.get(start) if start is not None else None
            record.image_path = values.get("ImagePath")
            record.installed_utc = _winreg_last_write_utc(base)
            try:
                record.bound_instances = len(_bound_instances(service))
            except (CollectionError, OSError):
                record.bound_instances = 0
            live = runtime.get(service.lower())
            if live:
                record.runtime_state = str(live.get("State") or "").strip() or None
                record.running = _as_bool(live.get("Started"))
                record.image_path = record.image_path or live.get("PathName")
                record.signature_status = str(live.get("Signature") or "").strip() or None
                # The resolved path the signature check actually tested, and
                # the signer. HOST-VERIFY V-1 showed the report claiming
                # "file missing" for two drivers that were on disk, with no way
                # to tell which path had been tested - an unfalsifiable claim.
                # Python re-derives it from the raw value with a function that
                # has fixtures, and keeps PowerShell's answer alongside so a
                # disagreement between the two is visible rather than silent.
                record.resolved_path = (
                    _normalize_driver_path(live.get("RawPath"))
                    or str(live.get("ResolvedPath") or "").strip()
                    or None
                )
                record.signer_not_after = str(live.get("SignerNotAfter") or "").strip() or None
                record.signature_timestamped = _as_bool(live.get("Timestamped"))
                # Round 7 appended the tested path INTO signature_status, which
                # mixed display text into a canonical value and immediately broke
                # binary_missing and signature_trusted, both of which matched the
                # token. Renaming it again to "Unverifiable" would break them a
                # third time. So signature_status stays a canonical token, the
                # path lives in resolved_path where it already was, and the
                # wording is composed in signature_cell() at render time.
                # Constraint 20, permanently: display never edits the value a
                # property matches on.
                record.signer = str(live.get("Signer") or "").strip() or None
            record.location_class, record.attributed_to = classify_driver_path(
                record.image_path
            )
            normalized = _normalize_driver_path(record.image_path)
            if normalized:
                directory = os.path.dirname(normalized).rstrip("\\").lower()
                # A shared OS directory is not a client relationship. explorer.exe
                # runs from C:\Windows and so does xhunter1.sys, which is not
                # attribution - it is a coincidence of where Windows puts things.
                if directory not in DRIVER_SHARED_DIRECTORIES:
                    record.client_processes = sorted(set(by_directory.get(directory, [])))
        drivers.append(record)

    assessment = HardwareAccessAssessment(
        # Residue counts as a result. The old test looked only at `present`, so
        # a host whose sole evidence was a LEGACY device node - the exact case
        # of an anti-cheat that was installed and later uninstalled - graded as
        # a failed query the moment any unrelated error was recorded, and
        # _findings_hardware_access suppressed every finding in the section
        # including the anti-cheat one.
        query_failed=bool(errors) and not any(d.present or d.legacy_node for d in drivers),
        query_error="; ".join(errors) if errors else None,
        drivers=drivers,
        signature_check=signature_check,
        process_attribution=process_attribution,
        sources=sorted(set(used)),
    )
    return assessment, used, errors


def _version_text(value: Any) -> str | None:
    """Render a version-ish registry value. Hex blobs stay hex; ints go decimal."""
    if value is None:
        return None
    if isinstance(value, int):
        return str(value)
    text = str(value).strip()
    return text or None


def _bios_year(release_date: str | None) -> int | None:
    """Year from a BIOS release date. Vendors use several formats."""
    if not release_date:
        return None
    years = re.findall(r"\b(19|20)(\d{2})\b", str(release_date))
    if not years:
        return None
    return int(years[-1][0] + years[-1][1])


# GetSystemFirmwareTable returns 0 for EVERY failure, not only for a table that
# is not there: an unsupported provider, a bad table id, and a call that could
# not be serviced all return 0. The previous revision mapped that single zero
# onto the string "table not present", which is the exact defect this tool
# exists to avoid - a collection failure rendered as a measured negative. The
# absence findings downstream (FIND-NO-SMM-MITIGATIONS, FIND-IOMMU-ABSENT)
# consumed that string and asserted absence on the strength of it.
#
# GetLastError is the only thing that separates the two, so the handle is opened
# with use_last_error and the code is carried in the status string. Statuses are
# now a closed set that callers must switch on: "ok", "absent", "unavailable: N",
# "not Windows", or "error: ...". Only "absent" licenses an absence claim.
FIRMWARE_TABLE_ABSENT_ERRORS = frozenset((
    # Host-verified, HOST-VERIFY H-2. A probe of WSMT/WPBT/DMAR/IVRS plus a
    # deliberately invalid table id returned:
    #   WSMT size=40  err=122    WPBT size=52  err=122    DMAR size=136 err=122
    #   IVRS size=0   err=1168   XXXX size=0   err=1168  (invalid id, control)
    # An absent table and an invalid id both answer ERROR_NOT_FOUND, and a
    # successful sizing call leaves ERROR_INSUFFICIENT_BUFFER (122) behind -
    # which is why the error is consulted only when the size is zero.
    #
    # 0 and 87 were here as reasoned guesses and are removed: neither was ever
    # observed for an absent table, and either would convert a real call
    # failure into a confident "absent", the precise defect A-2 was raised to
    # stop. Anything outside this set degrades to "unavailable".
    1168,   # ERROR_NOT_FOUND
))


def _read_firmware_table(provider: int, table_id: int) -> tuple[bytes | None, str]:
    """Fetch a raw firmware table via GetSystemFirmwareTable.

    Returns (bytes, status). Status is "ok", "absent", "unavailable: <code>",
    "not Windows", or "error: ...". Treating anything other than "absent" as
    absence is a bug; see FIRMWARE_TABLE_ABSENT_ERRORS above.
    """
    if not _is_windows():
        return None, "not Windows"
    try:
        import ctypes
    except ImportError:  # pragma: no cover
        return None, "ctypes unavailable"
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    except (AttributeError, OSError) as exc:
        return None, f"kernel32 unavailable: {exc}"

    # Without an explicit prototype ctypes infers c_int for the return, which is
    # signed 32-bit, and passes the buffer pointer untyped. Both are wrong for a
    # UINT-returning API taking a PVOID.
    try:
        fn = kernel32.GetSystemFirmwareTable
        fn.restype = ctypes.c_uint
        fn.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
    except AttributeError as exc:
        return None, f"GetSystemFirmwareTable unavailable: {exc}"

    try:
        ctypes.set_last_error(0)
        size = fn(provider, table_id, None, 0)
        if not size:
            code = ctypes.get_last_error()
            return None, ("absent" if code in FIRMWARE_TABLE_ABSENT_ERRORS
                          else f"unavailable: {code}")
        buffer = ctypes.create_string_buffer(size)
        ctypes.set_last_error(0)
        written = fn(provider, table_id, ctypes.cast(buffer, ctypes.c_void_p), size)
        if not written:
            return None, f"unavailable: {ctypes.get_last_error()}"
        # A second call can legitimately return a larger required size if the
        # table grew between calls; only a value that fits was actually written.
        if written > size:
            return None, "unavailable: table grew between sizing and read"
        return buffer.raw[:written], "ok"
    except (OSError, ValueError, ctypes.ArgumentError) as exc:
        return None, f"error: {exc}"


def _acpi_table_present(table_id: int) -> tuple[bool | None, str]:
    """Ask the firmware directly whether one ACPI table exists.

    True / False / None-for-undetermined. This is the authoritative source and
    the reason it exists: HKLM\\HARDWARE\\ACPI enumerates the tables the ACPI
    *namespace driver* registered, which is a subset. DMAR, IVRS, WSMT and WPBT
    are consumed by the kernel and do not reliably appear there, so their
    absence from that key never meant they were absent from the machine.
    """
    raw, status = _read_firmware_table(FIRMWARE_PROVIDER_ACPI, table_id)
    if status == "ok" and raw:
        return True, status
    if status == "absent":
        return False, status
    return None, status


# Sentinel type appended by _smbios_structures when the walk stops early.
# Not a real SMBIOS type; 256 cannot collide with a one-byte type value.
SMBIOS_TRUNCATED_MARKER = 256


def _smbios_structures(data: bytes) -> list[tuple[int, bytes, list[str]]]:
    """Split the SMBIOS table into (type, formatted area, strings)."""
    out: list[tuple[int, bytes, list[str]]] = []
    offset = 0
    limit = len(data)
    while offset + 4 <= limit:
        stype = data[offset]
        length = data[offset + 1]
        if length < 4 or offset + length > limit:
            # Malformed length. Stop, but the caller has to know the inventory
            # is partial - structure_count previously reported a truncated walk
            # as though it were the whole table.
            out.append((SMBIOS_TRUNCATED_MARKER, b"", []))
            break
        formatted = data[offset : offset + length]
        cursor = offset + length
        strings: list[str] = []
        while cursor < limit:
            end = data.find(b"\x00", cursor)
            if end == -1:
                cursor = limit
                break
            if end == cursor:
                # A structure WITH strings ends "str1\0str2\0\0" - the last
                # string's own null, then one terminator, so one byte here.
                # A structure with NO strings has only the double null, so two.
                # Consuming one either way left the cursor on the second null of
                # an empty table; the next pass then read stype=0 with a bogus
                # length and either broke out of the walk or emitted a phantom
                # type-0 structure whose zeroed formatted area overwrote the
                # real BIOS vendor, version and date with None.
                cursor += 1 if strings else 2
                break
            strings.append(data[cursor:end].decode("latin-1", errors="replace").strip())
            cursor = end + 1
        out.append((stype, formatted, strings))
        if stype == 127:  # end-of-table
            break
        offset = cursor
    return out


def parse_smbios(raw: bytes | None) -> SmbiosInfo | None:
    """Decode the SMBIOS structures Windows hands back for provider 'RSMB'.

    Windows prepends an 8-byte RawSMBIOSData header carrying the SMBIOS
    version, then the raw table follows.
    """
    if not raw or len(raw) <= SMBIOS_HEADER_LEN:
        return None
    info = SmbiosInfo(version=f"{raw[1]}.{raw[2]}")
    structures = _smbios_structures(raw[SMBIOS_HEADER_LEN:])
    info.truncated = any(s[0] == SMBIOS_TRUNCATED_MARKER for s in structures)
    structures = [s for s in structures if s[0] != SMBIOS_TRUNCATED_MARKER]
    info.structure_count = len(structures)
    info.types_present = sorted({s[0] for s in structures})

    def text(formatted: bytes, strings: list[str], offset: int) -> str | None:
        if offset >= len(formatted):
            return None
        index = formatted[offset]
        if index == 0 or index > len(strings):
            return None
        return strings[index - 1] or None

    for stype, formatted, strings in structures:
        if stype == 0:
            info.bios_vendor = text(formatted, strings, 0x04)
            info.bios_version = text(formatted, strings, 0x05)
            info.bios_release_date = text(formatted, strings, 0x08)
            # SMBIOS type 0, offset 0x09: "Size (n) where 64K * (n+1) is the
            # size of the physical device containing the BIOS, in bytes. 0xFF
            # means see Extended BIOS ROM Size."
            #
            # 0xFF was being treated as the literal 255, giving
            # (255+1)*64 = 16384 KB - exactly 16 MB, which looks like a real
            # answer. HOST-VERIFY H-11 dumped a structure with 0xFF at 0x09 and
            # 0x0020 at 0x18: a 32 MB ROM reported as 16 MB, wrong by 2x and
            # plausible enough that four rounds of auditing walked past it.
            #
            # Offset 0x18 is a WORD: bits 0-13 the size, bits 14-15 the unit
            # (00b megabytes, 01b gigabytes). The escape is only resolvable on a
            # structure long enough to hold it, so a short structure yields None
            # - undetermined - rather than a number derived from the escape.
            if len(formatted) > 0x09:
                rom_byte = formatted[0x09]
                if rom_byte != 0xFF:
                    info.bios_rom_size_kb = (rom_byte + 1) * 64
                elif len(formatted) >= 0x1A:
                    ext = int.from_bytes(formatted[0x18:0x1A], "little")
                    size, unit = ext & 0x3FFF, (ext >> 14) & 0x3
                    if unit == 0:            # megabytes
                        info.bios_rom_size_kb = size * 1024
                    elif unit == 1:          # gigabytes
                        info.bios_rom_size_kb = size * 1024 * 1024
                    # unit 10b/11b are reserved; leave undetermined rather than
                    # guessing a multiplier.
            # System BIOS release at 0x14/0x15. Read because the structure
            # carries it and the section already reports BIOS version, which is
            # the vendor's string and not this.
            if len(formatted) > 0x15 and formatted[0x14] != 0xFF:
                info.bios_release = f"{formatted[0x14]}.{formatted[0x15]}"
        elif stype == 1:
            info.system_manufacturer = text(formatted, strings, 0x04)
            info.system_product = text(formatted, strings, 0x05)
            info.system_version = text(formatted, strings, 0x06)
            info.serial_number = text(formatted, strings, 0x07)
            if len(formatted) >= 0x18:
                blob = formatted[0x08:0x18]
                if any(b not in (0x00, 0xFF) for b in blob):
                    info.uuid = "-".join(
                        (
                            blob[3::-1].hex(), blob[5:3:-1].hex(), blob[7:5:-1].hex(),
                            blob[8:10].hex(), blob[10:16].hex(),
                        )
                    )
        elif stype == 2:
            info.baseboard_manufacturer = text(formatted, strings, 0x04)
            info.baseboard_product = text(formatted, strings, 0x05)
            info.baseboard_serial = text(formatted, strings, 0x07)
        elif stype == 3:
            if len(formatted) > 0x05:
                info.chassis_type = SMBIOS_CHASSIS_TYPES.get(
                    formatted[0x05] & 0x7F, f"type {formatted[0x05] & 0x7F}"
                )
            info.chassis_serial = text(formatted, strings, 0x07)
            info.asset_tag = text(formatted, strings, 0x08)
            if len(formatted) > 0x0C:
                info.security_status = SMBIOS_SECURITY_STATUS.get(
                    formatted[0x0C], f"unknown ({formatted[0x0C]})"
                )
    return info


def parse_wsmt(raw: bytes | None) -> int | None:
    """The 32-bit protection flags field that follows the ACPI header."""
    if not raw or len(raw) < ACPI_HEADER_LEN + 4:
        return None
    return int.from_bytes(raw[ACPI_HEADER_LEN : ACPI_HEADER_LEN + 4], "little")


def parse_wpbt(raw: bytes | None) -> dict[str, Any]:
    """Pull the interesting fields out of a WPBT table.

    Layout after the 36-byte ACPI header: an 8-byte physical address, a 4-byte
    binary size, one byte of content layout, one byte of content type, then a
    2-byte command-line length and the command line as UTF-16.
    """
    if not raw or len(raw) < ACPI_HEADER_LEN + 14:
        return {}
    body = raw[ACPI_HEADER_LEN:]
    out: dict[str, Any] = {
        "binary_size": int.from_bytes(body[8:12], "little"),
        "content_layout": body[12],
        "content_type": body[13],
    }
    if len(body) >= 16:
        cmd_len = int.from_bytes(body[14:16], "little")
        blob = body[16 : 16 + cmd_len]
        try:
            text = blob.decode("utf-16-le", errors="replace").rstrip("\x00").strip()
        except (UnicodeDecodeError, ValueError):
            text = ""
        if text:
            out["command_line"] = text
    return out


def _collect_firmware() -> tuple[FirmwareAssessment, list[str], list[str]]:
    """Inventory the firmware surface.

    Deliberately cheap: one subkey enumeration for the entire ACPI table list
    plus one value read for the BIOS identity. There is nothing to walk and no
    list to maintain - the firmware declares what it declares.
    """
    if not _is_windows():
        raise CollectionError("Firmware collection requires Windows")
    errors: list[str] = []
    used: list[str] = []

    try:
        signatures = sorted(
            {name.strip().upper() for name in _winreg_subkeys(ACPI_ROOT_KEY) if name.strip()}
        )
        acpi_status = "ok" if signatures else "missing"
        if signatures:
            used.append("reg.HARDWARE.ACPI")
    except (CollectionError, OSError) as exc:
        signatures, acpi_status = [], f"error: {_short_error(exc)}"
        errors.append(f"ACPI enumeration failed: {_short_error(exc)}")

    tables = [
        AcpiTable(
            signature=sig,
            note=ACPI_TABLE_NOTES.get(sig),
            notable=sig in ACPI_NOTABLE_PRESENT,
        )
        for sig in signatures
    ]

    resources: list[FirmwareResource] = []
    resources_status = "not read"
    try:
        names = _winreg_subkeys(FIRMWARE_RESOURCES_KEY)
        resources_status = "ok" if names else "no resources listed"
        for name in names:
            values, status = _winreg_read(f"{FIRMWARE_RESOURCES_KEY}\\{name}")
            if status != "ok":
                continue
            resources.append(
                FirmwareResource(
                    resource_id=name,
                    version=_version_text(values.get("Version")),
                    lowest_supported_version=_version_text(values.get("LowestSupportedVersion")),
                    last_attempt_version=_version_text(values.get("LastAttemptVersion")),
                    last_attempt_status=as_int_safe(values.get("LastAttemptStatus")),
                )
            )
        if resources:
            used.append("reg.Control.FirmwareResources")
    except (CollectionError, OSError) as exc:
        resources_status = f"error: {_short_error(exc)}"

    acpi_wmi: list[str] = []
    acpi_wmi_labels: list[str] = []
    acpi_wmi_status = "not read"
    try:
        instances = _winreg_subkeys(ACPI_WMI_ENUM_KEY)
        acpi_wmi_status = "ok" if instances else "none present"
        for instance in instances:
            values, status = _winreg_read(f"{ACPI_WMI_ENUM_KEY}\\{instance}")
            # DeviceDesc was read first and it is the raw INF indirect string
            # (@wmiacpi.inf,%*pnp0c14.devicedesc%;<fallback>), identical for
            # every PNP0C14 node - six rows, six byte-identical labels, no
            # information. FriendlyName is the resolved value where one exists;
            # otherwise take the fallback text the indirect string carries after
            # its last semicolon, and print nothing rather than a token.
            label = None
            if status == "ok":
                label = _resolve_inf_string(
                    values.get("FriendlyName") or values.get("DeviceDesc")
                )
            acpi_wmi.append(f"{instance}" + (f" ({label})" if label else ""))
            acpi_wmi_labels.append(label or "")
        # HOST-VERIFY H-8: on a real host every PNP0C14 node had an empty
        # FriendlyName and the same DeviceDesc, so resolving the indirect
        # string removed the raw token but still left six identical
        # parentheticals. A column where every row reads the same carries no
        # information; the instance names, which do differ, are the signal.
        # State the shared description once instead of per row.
        shared = {lbl for lbl in acpi_wmi_labels if lbl}
        if len(shared) == 1 and len(acpi_wmi_labels) > 1:
            acpi_wmi = list(instances)
            acpi_wmi_status = f"ok (all: {shared.pop()})"
        if instances:
            used.append("reg.Enum.ACPI.PNP0C14")
    except (CollectionError, OSError) as exc:
        acpi_wmi_status = f"error: {_short_error(exc)}"

    cpu_values, cpu_status = _winreg_read(CPU_KEY)
    if cpu_status == "ok":
        used.append("reg.HARDWARE.CentralProcessor")

    smbios_raw, smbios_status = _read_firmware_table(FIRMWARE_PROVIDER_RSMB, 0)
    smbios = parse_smbios(smbios_raw)
    if smbios_status == "ok" and smbios:
        used.append("firmware.SMBIOS")

    wsmt_raw, wsmt_status = _read_firmware_table(FIRMWARE_PROVIDER_ACPI, WSMT_TABLE_ID)
    wsmt_flags = parse_wsmt(wsmt_raw)
    if wsmt_status == "ok":
        used.append("firmware.ACPI.WSMT")

    wpbt_raw, wpbt_status = _read_firmware_table(FIRMWARE_PROVIDER_ACPI, WPBT_TABLE_ID)
    wpbt = parse_wpbt(wpbt_raw)
    if wpbt_status == "ok":
        used.append("firmware.ACPI.WPBT")

    dropped_path = dropped_size = dropped_mtime = None
    root = os.environ.get("SystemRoot")
    if root:
        candidate = os.path.join(root, WPBT_DROPPED_BINARY)
        try:
            if os.path.isfile(candidate):
                dropped_path = candidate
                dropped_size = os.path.getsize(candidate)
                dropped_mtime = datetime.fromtimestamp(
                    os.path.getmtime(candidate), timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                used.append("file.wpbbin")
        except OSError as exc:
            # "not there" and "not allowed to look" must not render alike.
            errors.append(f"WPBT dropped binary not readable: {_short_error(exc)}")

    bios, bios_status = _winreg_read(BIOS_INFO_KEY)
    if bios_status == "ok":
        used.append("reg.HARDWARE.DESCRIPTION.BIOS")

    def _text(key: str) -> str | None:
        value = bios.get(key)
        return str(value).strip() or None if value is not None else None

    # Absence is only meaningful when the enumeration itself was trustworthy.
    known = acpi_status == "ok" and len(signatures) >= ACPI_MIN_TABLES_FOR_ABSENCE

    # WSMT and WPBT were read from the firmware a few lines above, parsed, and
    # then ignored: presence was decided by whether the signature appeared as a
    # subkey of HKLM\\HARDWARE\\ACPI. It does not appear there - that key lists
    # what the ACPI namespace driver registered, and these are kernel-consumed
    # tables - so the flags were effectively hardwired to False and
    # FIND-NO-SMM-MITIGATIONS fired on hosts whose WSMT had just been parsed
    # successfully. Presence now comes from the read that actually asked.
    wsmt_present = (True if wsmt_status == "ok"
                    else False if wsmt_status == "absent" else None)
    wpbt_seen = (True if wpbt_status == "ok"
                 else False if wpbt_status == "absent" else None)
    iommu_found, iommu_status = _acpi_iommu_from_firmware()
    assessment = FirmwareAssessment(
        query_failed=bool(errors) and not signatures and bios_status != "ok",
        query_error="; ".join(errors) if errors else None,
        acpi_status=acpi_status,
        tables=tables,
        wpbt_present=wpbt_seen,
        iommu_table=iommu_found,
        smm_mitigations_declared=wsmt_present,
        # A registry hit is evidence of presence; a registry miss is not
        # evidence of absence, because these are kernel-consumed tables that do
        # not reliably register under HARDWARE\\ACPI. The previous revision
        # asserted the negative from a miss - "none declared" for the TPM
        # interface on hosts whose TPM section reports a healthy TPM 2.0.
        # Absence here is undetermined until something authoritative says
        # otherwise; the "known" gate did not help, because it only measured
        # how many namespace tables were listed.
        debug_port_declared=(
            True if any(t in signatures for t in ("DBG2", "DBGP")) else None
        ),
        tpm_interface=(
            "TPM 2.0" if "TPM2" in signatures
            else "TPM 1.2" if "TCPA" in signatures
            else None
        ),
        smbios=smbios,
        smbios_status=smbios_status,
        resources=resources,
        resources_status=resources_status,
        acpi_wmi_instances=acpi_wmi,
        acpi_wmi_status=acpi_wmi_status,
        microcode_revision=_version_text(cpu_values.get("Update Revision")),
        previous_microcode_revision=_version_text(cpu_values.get("Previous Update Revision")),
        cpu_identifier=(str(cpu_values.get("ProcessorNameString") or "").strip() or None),
        wsmt_flags=wsmt_flags,
        wsmt_protections=(
            [label for bit, label in sorted(WSMT_PROTECTION_FLAGS.items()) if wsmt_flags & bit]
            if wsmt_flags is not None
            else []
        ),
        wsmt_read_status=wsmt_status,
        wpbt_binary_size=wpbt.get("binary_size"),
        wpbt_command_line=wpbt.get("command_line"),
        wpbt_content_type=wpbt.get("content_type"),
        wpbt_read_status=wpbt_status,
        wpbt_dropped_path=dropped_path,
        wpbt_dropped_size=dropped_size,
        wpbt_dropped_mtime_utc=dropped_mtime,
        bios_year=_bios_year(_text("BIOSReleaseDate")),
        predates_mitigations=(
            None
            if _bios_year(_text("BIOSReleaseDate")) is None
            else _bios_year(_text("BIOSReleaseDate")) < FIRMWARE_MITIGATION_ERA
        ),
        bios_vendor=_text("BIOSVendor"),
        bios_version=_text("BIOSVersion"),
        bios_release_date=_text("BIOSReleaseDate"),
        system_manufacturer=_text("SystemManufacturer"),
        system_product=_text("SystemProductName"),
        sources=sorted(set(used)),
    )
    return assessment, used, errors


def _acpi_iommu_from_firmware() -> tuple[str | None, str]:
    """Probe the firmware for DMAR then IVRS. Returns (table_name, status).

    Authoritative where the registry enumeration was only suggestive. Status is
    "present", "absent", or "undetermined: <reason>" - and "undetermined" must
    never be collapsed into "absent" by a caller.
    """
    reasons: list[str] = []
    for name, table_id in (("DMAR", DMAR_TABLE_ID), ("IVRS", IVRS_TABLE_ID)):
        present, status = _acpi_table_present(table_id)
        if present:
            return name, "present"
        if present is None:
            reasons.append(f"{name}: {status}")
    if reasons:
        return None, "undetermined: " + "; ".join(reasons)
    return None, "absent"


def _collect_acpi_iommu() -> tuple[list[str], str | None, bool | None, str, list[str]]:
    """Enumerate ACPI table signatures and look for an IOMMU.

    Returns (tables, iommu_table, iommu_present, status, sources). A short or
    unreadable table list yields iommu_present=None: this answers "is there an
    IOMMU" only when the enumeration is trustworthy enough to make absence
    meaningful.
    """
    sources: list[str] = []
    if _winreg is None:
        return [], None, None, "unavailable", sources
    try:
        tables = sorted({name.strip().upper() for name in _winreg_subkeys(ACPI_ROOT_KEY) if name.strip()})
    except (CollectionError, OSError) as exc:
        return [], None, None, f"error: {_short_error(exc)}", sources
    if not tables:
        return [], None, None, "missing", sources
    sources.append("reg.HARDWARE.ACPI")

    # The registry list can only ever corroborate. It is a list of what the ACPI
    # namespace driver registered, and DMAR/IVRS are not namespace tables, so
    # their absence from it was never evidence that no IOMMU exists - yet the
    # previous revision returned iommu_present=False on exactly that basis, and
    # FIND-IOMMU-ABSENT fired at HIGH because of it. The firmware probe decides;
    # a registry hit is still accepted as positive corroboration.
    # Siblings of this tag name the table they read - firmware.ACPI.WPBT,
    # firmware.ACPI.WSMT. "firmware.ACPI" alone left a reader unable to tell
    # which tables the probe covered, which is the whole job of a source tag.
    firmware_table, firmware_status = _acpi_iommu_from_firmware()
    if firmware_status == "present":
        sources.append(f"firmware.ACPI.{firmware_table}")
        return tables, firmware_table, True, "ok", sources
    if firmware_status == "absent":
        # Both were probed and both answered; both are provenance for the
        # negative, and the negative is what FIND-IOMMU-ABSENT rests on.
        sources.extend(f"firmware.ACPI.{t}" for t in IOMMU_ACPI_TABLES)
        return tables, None, False, "ok", sources

    # Firmware could not answer. Fall back to the registry, but only in the
    # direction it can actually support: a hit is evidence of presence, a miss
    # is not evidence of absence.
    found = next((t for t in IOMMU_ACPI_TABLES if t in tables), None)
    if found:
        return tables, found, True, "ok (registry corroboration only)", sources
    return tables, None, None, f"undetermined ({firmware_status})", sources


def _kernel_dma_from_deviceguard(
    payload: dict[str, Any],
) -> tuple[str, bool | None, list[str], list[str]]:
    """Decode Win32_DeviceGuard into (label, dma_available, properties, services).

    AvailableSecurityProperties value 3 is DMA protection. That is a *platform
    capability* report — the firmware exposes an IOMMU and Windows can use it.
    It is not a confirmation that Kernel DMA Protection is currently enforcing,
    and this function does not claim otherwise.
    """
    codes = _as_int_list(payload.get("AvailableSecurityProperties"))
    running = [
        DEVICE_GUARD_SERVICES.get(n, f"unknown({n})")
        for n in _as_int_list(payload.get("SecurityServicesRunning"))
    ]
    names = [DEVICE_GUARD_PROPERTIES.get(n, f"unknown({n})") for n in codes]
    if not codes:
        return "Unknown", None, names, running
    if 3 in codes:
        return "Available", True, names, running
    return "Not available", False, names, running


def _collect_dma() -> tuple[DmaAssessment, list[str], list[str]]:
    if not _is_windows():
        raise CollectionError("DMA collection requires Windows")
    errors: list[str] = []
    used: list[str] = []
    policy, policy_status, buses, reg_used = _dma_policy_from_registry()
    used.extend(reg_used)
    kernel_state = "Unknown"
    acpi_tables: list[str] = []
    acpi_status: str | None = None
    iommu_table: str | None = None
    iommu_present: bool | None = None
    dma_available: bool | None = None
    dg_properties: list[str] = []
    dg_running: list[str] = []

    # Firmware evidence first: registry-only, no elevation needed, and it stands
    # even when the DeviceGuard query fails entirely.
    try:
        acpi_tables, iommu_table, iommu_present, acpi_status, acpi_sources = _collect_acpi_iommu()
        used.extend(acpi_sources)
    except (CollectionError, OSError) as exc:
        errors.append(f"ACPI table enumeration failed: {_short_error(exc)}")
        acpi_status = f"error: {_short_error(exc)}"

    try:
        raw = _run_powershell(_PS_DEVICEGUARD_SCRIPT)
        rows = _loads_ps_json(raw)
        if rows:
            used.append("cim.Win32_DeviceGuard")
            payload = rows[0] if isinstance(rows[0], dict) else {}
            (
                kernel_state,
                dma_available,
                dg_properties,
                dg_running,
            ) = _kernel_dma_from_deviceguard(payload)
    except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        errors.append(f"DeviceGuard query failed: {_short_error(exc)}")

    controllers: list[DmaController] = []
    try:
        raw = _run_powershell(_PS_DMA_CONTROLLER_SCRIPT)
        rows = _loads_ps_json(raw)
        used.append("powershell.PnpDevice.Thunderbolt")
        for row in rows:
            name = str(row.get("FriendlyName") or "Thunderbolt device")
            instance = row.get("InstanceId")
            if not looks_like_thunderbolt_controller(instance, name, row.get("Class")):
                continue
            controllers.append(
                DmaController(
                    name=name,
                    instance_id=str(instance) if instance else None,
                    present=bool(row.get("Present")),
                    status=str(row.get("Status") or ""),
                    manufacturer=str(row.get("Manufacturer") or "") or None,
                    last_write_utc=_winreg_last_write_utc(_enum_path_for_instance(instance) or ""),
                    source="pnp-enum",
                )
            )
    except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        errors.append(f"Thunderbolt PnP query failed: {_short_error(exc)}")

    label = (
        DMA_GUARD_POLICY_LABELS.get(policy)
        if policy is not None
        else "no GPO (OS default if Kernel DMA exists)"
    )
    query_failed = bool(errors) and not controllers and policy is None and not buses
    return (
        DmaAssessment(
            query_failed=query_failed,
            query_error="; ".join(errors) if query_failed else None,
            kernel_dma_protection=kernel_state,
            dma_protection_available=dma_available,
            acpi_tables=acpi_tables,
            acpi_status=acpi_status,
            iommu_table=iommu_table,
            iommu_present=iommu_present,
            device_guard_properties=dg_properties,
            device_guard_services_running=dg_running,
            dma_guard_policy=policy,
            dma_guard_policy_label=label,
            dma_guard_policy_status=policy_status,
            allowed_buses=buses,
            controllers=_dedupe_dma_controllers(controllers),
            sources=used,
        ),
        used,
        errors,
    )


def _dedupe_dma_controllers(rows: list[DmaController]) -> list[DmaController]:
    seen: set[str] = set()
    out: list[DmaController] = []
    for row in rows:
        key = row.instance_id or row.name
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _sdr_vid_pid_from_instance(instance_id: str | None) -> str | None:
    if not instance_id:
        return None
    text = instance_id.upper()
    for vid, pid, _label in SDR_ALLOWLIST:
        token = f"VID_{vid}&PID_{pid}"
        if token in text:
            return f"{vid}:{pid}"
    return None


def _collect_sdr_registry() -> list[SdrDevice]:
    """Open only allowlisted USB VID/PID keys — no USB root walk."""
    devices: list[SdrDevice] = []
    if _winreg is None:
        return devices
    for vid, pid, label in SDR_ALLOWLIST:
        path = rf"SYSTEM\CurrentControlSet\Enum\USB\VID_{vid}&PID_{pid}"
        children = _winreg_subkeys(path)
        parent_write = _winreg_last_write_utc(path)
        if not children and parent_write:
            devices.append(
                SdrDevice(
                    name=label,
                    instance_id=f"USB\\VID_{vid}&PID_{pid}",
                    present=False,
                    vid_pid=f"{vid}:{pid}",
                    allowlist_hit=f"{label} ({vid}:{pid})",
                    last_write_utc=parent_write,
                    source="enum-usb-allowlist",
                )
            )
            continue
        for child in children:
            inst = rf"USB\VID_{vid}&PID_{pid}\{child}"
            child_path = path + "\\" + child
            # STATUS IGNORED: enumerating class subkeys; an unreadable child is
            # absent from the filter inventory either way, and classes_checked
            # records the scope that was attempted.
            vals, _ = _winreg_values(child_path)
            desc = vals.get("DeviceDesc") or vals.get("FriendlyName") or label
            if isinstance(desc, str) and ";" in desc:
                desc = desc.split(";")[-1]
            devices.append(
                SdrDevice(
                    name=str(desc),
                    instance_id=inst,
                    present=False,
                    vid_pid=f"{vid}:{pid}",
                    allowlist_hit=f"{label} ({vid}:{pid})",
                    last_write_utc=_winreg_last_write_utc(child_path) or parent_write,
                    source="enum-usb-allowlist",
                    manufacturer=str(vals.get("Mfg") or "") or None,
                )
            )
    return devices


def _scan_oem_infs() -> tuple[list[OemInfHit], str | None]:
    """Look for generic-driver markers in %WINDIR%\\INF\\oem*.inf.

    An OEM INF outlives the device it was installed for, so this answers
    "was a generic driver ever installed here" even when nothing is bound now.
    Bounded in both file count and bytes read so a large INF store cannot stall
    the scan. Returns (hits, skip_reason).
    """
    windir = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    if not windir:
        return [], "SystemRoot not set"
    inf_dir = os.path.join(windir, "INF")
    try:
        names = sorted(
            n for n in os.listdir(inf_dir)
            if n.lower().startswith("oem") and n.lower().endswith(".inf")
        )
    except OSError as exc:
        return [], f"{inf_dir} not readable ({exc.__class__.__name__})"

    skipped = max(0, len(names) - INF_SCAN_FILE_CAP)
    hits: list[OemInfHit] = []
    for name in names[:INF_SCAN_FILE_CAP]:
        path = os.path.join(inf_dir, name)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                blob = handle.read(INF_SCAN_BYTE_CAP).lower()
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        markers = sorted({m for m in GENERIC_DRIVER_INF_MARKERS if m in blob})
        if markers:
            hits.append(
                OemInfHit(
                    inf_file=name,
                    markers=markers,
                    mtime_utc=datetime.fromtimestamp(mtime, timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                )
            )
    if skipped:
        # Declared rather than swallowed: the reader needs to know the scan was
        # not exhaustive, and by how much.
        return hits, f"scanned {INF_SCAN_FILE_CAP} of {len(names)} OEM INFs ({skipped} not examined)"
    return hits, None


def instance_ids_from_enum_values(values: dict[str, Any]) -> list[str]:
    """Pull device instance IDs out of a Services\\<name>\\Enum value set.

    The numeric value names are the bound devices; Count and NextInstance are
    bookkeeping. Kept separate from the registry read so the parsing is
    testable without Windows.
    """
    instances: list[str] = []
    for key in sorted(values, key=lambda k: (not k.isdigit(), as_int_safe(k) or 0, k)):
        if not key.isdigit():
            continue
        text = str(values[key]).strip()
        if text:
            instances.append(text)
    return instances


def _bound_instances(service: str) -> list[str]:
    """Instance IDs the driver itself reports owning.

    Service-first by design: each generic driver is asked what it owns rather
    than walking the USB tree looking for candidates. Four registry keys, no
    enumeration.
    """
    # STATUS IGNORED: bound-instance count only; a denied Enum key and an
    # absent one both mean no count is available and the caller renders '-'
    # for both.
    values, _ = _winreg_values(f"SYSTEM\\CurrentControlSet\\Services\\{service}\\Enum")
    return instance_ids_from_enum_values(values)


def _describe_bound_device(instance_id: str) -> dict[str, Any]:
    """Read one Enum node for a known instance. Targeted, not a tree walk."""
    path = _enum_path_for_instance(instance_id)
    if not path:
        return {}
    # STATUS IGNORED: the caller already reads this key via _winreg_read for its
    # own status; this is a supplementary value sweep of the same path.
    values, _ = _winreg_values(path)
    return {
        "name": values.get("FriendlyName") or values.get("DeviceDesc"),
        "manufacturer": values.get("Mfg"),
        "hardware_ids": _as_str_list(values.get("HardwareID")),
        "last_write_utc": _winreg_last_write_utc(path),
    }


def _collect_driver_substitution() -> tuple[DriverSubstitutionAssessment, list[str], list[str]]:
    if not _is_windows():
        raise CollectionError("Driver substitution collection requires Windows")
    errors: list[str] = []
    used: list[str] = []
    services: list[GenericDriverService] = []
    bindings: list[GenericDriverBinding] = []

    for service, label, confidence, _rationale in GENERIC_USB_DRIVERS:
        base = f"SYSTEM\\CurrentControlSet\\Services\\{service}"
        try:
            # STATUS IGNORED: per-service sweep inside a loop whose membership is
            # already established by _winreg_read; a denied service key is
            # reported through that path, not this one.
            svc_values, _ = _winreg_values(base)
        except (CollectionError, OSError) as exc:
            errors.append(f"service {service}: {_short_error(exc)}")
            continue
        record = GenericDriverService(
            driver=label, service=service, confidence=confidence, present=bool(svc_values)
        )
        if not svc_values:
            services.append(record)
            continue
        used.append(f"reg.Services.{service}")
        start = as_int_safe(svc_values.get("Start"))
        record.start_type = start
        record.start_label = SERVICE_START_LABELS.get(start) if start is not None else None
        record.image_path = svc_values.get("ImagePath")

        try:
            instances = _bound_instances(service)
        except (CollectionError, OSError) as exc:
            errors.append(f"service {service} Enum: {_short_error(exc)}")
            instances = []
        record.binding_count = len(instances)
        services.append(record)

        for instance in instances:
            try:
                detail = _describe_bound_device(instance)
            except (CollectionError, OSError):
                detail = {}
            hardware_ids = detail.get("hardware_ids") or []
            name = detail.get("name") or instance
            allowlist_hit = match_sdr_allowlist(instance, name, hardware_ids)
            bindings.append(
                GenericDriverBinding(
                    driver=label,
                    instance_id=instance,
                    enumerator=enumerator_from_instance_id(instance),
                    name=name,
                    manufacturer=detail.get("manufacturer"),
                    hardware_ids=hardware_ids,
                    vid_pid=_sdr_vid_pid_from_instance(instance)
                    or next(
                        (v for v in (_sdr_vid_pid_from_instance(h) for h in hardware_ids) if v),
                        None,
                    ),
                    allowlist_hit=allowlist_hit,
                    # A known RF peripheral on any generic driver is a direct
                    # hit regardless of which driver it landed on.
                    confidence="strong" if (confidence == "strong" or allowlist_hit) else "weak",
                    last_write_utc=detail.get("last_write_utc"),
                )
            )

    inf_hits, inf_skip = _scan_oem_infs()
    if inf_skip:
        errors.append(f"OEM INF scan skipped: {inf_skip}")
    else:
        used.append("file.WINDIR.INF.oem")

    assessment = DriverSubstitutionAssessment(
        query_failed=bool(errors) and not services and not bindings,
        query_error="; ".join(errors) if errors else None,
        services=services,
        bindings=bindings,
        inf_hits=inf_hits,
        inf_scan_performed=inf_skip is None,
        sources=sorted(set(used)),
    )
    return assessment, used, errors


CERT_STORE_PATHS = (
    "SOFTWARE\\Microsoft\\SystemCertificates\\My\\Certificates",
)

# Providers whose name does not itself say "smart card" but that are software
# based. Used to avoid promoting an ordinary certificate on EKU alone.
SOFTWARE_PROVIDER_MARKERS = (
    "software key storage",
    "enhanced cryptographic",
    "base cryptographic",
    "strong cryptographic",
    "rsa schannel",
    "enhanced rsa and aes",
)


def _provider_from_cert_blob(blob: bytes) -> str | None:
    """Recover the key provider name from a serialized certificate blob.

    The store keeps CERT_KEY_PROV_INFO alongside the certificate, so the
    provider name is readable as passive metadata. That is the entire point of
    doing it this way: asking the certificate object for its PrivateKey opens
    the key container, and for a card-backed key that raises a modal insert-card
    dialog and blocks. Reading bytes cannot prompt anyone for anything.

    Strings inside the blob are UTF-16LE and may sit at either byte alignment,
    so both are scanned. Only strings that look like a provider name are
    accepted, which keeps a subject containing the words "smart card" from
    being mistaken for one.
    """
    for offset in (0, 1):
        try:
            text = blob[offset:].decode("utf-16-le", errors="ignore")
        except (UnicodeDecodeError, ValueError):
            continue
        for candidate in text.split("\x00"):
            candidate = candidate.strip()
            if not (8 <= len(candidate) <= 128) or not candidate.isprintable():
                continue
            low = candidate.lower()
            if "provider" in low or "key storage" in low or low.endswith(" csp"):
                return candidate
    return None


def _cert_provider_map() -> tuple[dict[str, str], list[str], list[str]]:
    """thumbprint -> key provider name, read from the certificate store blobs.

    Returns (mapping, sources, errors). Walks the current user's store and the
    machine store; neither read invokes a cryptographic provider.
    """
    mapping: dict[str, str] = {}
    sources: list[str] = []
    errors: list[str] = []
    if _winreg is None:
        return mapping, sources, ["winreg unavailable"]
    hives = [("HKCU", _winreg.HKEY_CURRENT_USER), ("HKLM", _winreg.HKEY_LOCAL_MACHINE)]
    for hive_label, hive in hives:
        for store_path in CERT_STORE_PATHS:
            try:
                thumbprints = _winreg_subkeys(store_path, hive)
            except (CollectionError, OSError) as exc:
                errors.append(f"{hive_label} certificate store not readable: {_short_error(exc)}")
                continue
            if not thumbprints:
                continue
            sources.append(f"reg.{hive_label}.SystemCertificates.My")
            for thumbprint in thumbprints:
                values, status = _winreg_read(f"{store_path}\\{thumbprint}", hive)
                if status != "ok":
                    continue
                raw = values.get("Blob")
                if not isinstance(raw, str):
                    continue
                try:
                    blob = bytes.fromhex(raw)
                except ValueError:
                    continue
                provider = _provider_from_cert_blob(blob)
                if provider:
                    mapping[thumbprint.strip().upper()] = provider
    return mapping, sorted(set(sources)), errors


def _classify_certificate(
    row: dict[str, Any], providers: dict[str, str] | None = None
) -> CertificateRecord:
    """Decide whether a certificate came off a smart card, and how sure we are."""
    ekus = [str(e).strip() for e in _as_str_list(row.get("Ekus")) if str(e).strip()]
    thumbprint = str(row.get("Thumbprint") or "").strip() or None
    provider = (providers or {}).get((thumbprint or "").upper())
    provider = (provider or "").strip() or None
    low = (provider or "").lower()
    smartcard_logon = SMARTCARD_LOGON_EKU in ekus
    provider_is_smartcard = bool(
        provider and any(m in low for m in SMARTCARD_PROVIDER_MARKERS)
    )
    provider_is_software = bool(
        provider and any(m in low for m in SOFTWARE_PROVIDER_MARKERS)
    )
    if provider_is_smartcard:
        # The provider name says the key lives on a card. Strong tell.
        origin = "smart card"
    elif smartcard_logon and provider_is_software:
        # Right purpose, but a named software provider holds the key: this is a
        # soft certificate issued for smart-card logon, not a card.
        origin = "other"
    elif smartcard_logon:
        # Right purpose, provider unknown or a vendor CSP that does not name
        # itself. Not claimed as confirmed.
        origin = "probable"
    else:
        origin = "other"

    not_after = parse_datetime_to_utc_iso(row.get("NotAfter"))
    expired: bool | None = None
    if not_after:
        expired = not_after < datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return CertificateRecord(
        thumbprint=str(row.get("Thumbprint") or "").strip() or None,
        subject=str(row.get("Subject") or "").strip() or None,
        issuer=str(row.get("Issuer") or "").strip() or None,
        serial_number=str(row.get("SerialNumber") or "").strip() or None,
        store=str(row.get("Store") or "").strip() or None,
        not_before_utc=parse_datetime_to_utc_iso(row.get("NotBefore")),
        not_after_utc=not_after,
        has_private_key=_as_bool(row.get("HasPrivateKey")),
        provider=provider,
        ekus=ekus,
        eku_labels=[EKU_LABELS.get(e, e) for e in ekus],
        smartcard_logon=smartcard_logon,
        provider_is_smartcard=provider_is_smartcard,
        origin=origin,
        expired=expired,
    )


def _collect_smartcard_certificates() -> tuple[
    CertificatePropagationAssessment, list[str], list[str]
]:
    if not _is_windows():
        raise CollectionError("Certificate propagation collection requires Windows")
    errors: list[str] = []
    used: list[str] = []
    certificates: list[CertificateRecord] = []
    provider_map: dict[str, str] = {}

    try:
        provider_map, provider_sources, provider_errors = _cert_provider_map()
        used.extend(provider_sources)
        errors.extend(provider_errors)
    except (CollectionError, OSError) as exc:
        errors.append(f"certificate provider lookup failed: {_short_error(exc)}")
        provider_map = {}

    try:
        rows = _loads_ps_json(_run_powershell(_PS_SMARTCARD_CERT_SCRIPT))
        used.append("powershell.Cert.My")
        for row in rows:
            if isinstance(row, dict):
                certificates.append(_classify_certificate(row, provider_map))
    except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        errors.append(f"certificate store query failed: {_short_error(exc)}")

    # Whether propagated certificates survive card removal is policy dependent,
    # so the policy is reported alongside them and an empty result is qualified.
    policy, policy_status = _winreg_read(CERTPROP_POLICY_KEY)
    enabled: bool | None = None
    if policy_status == "ok":
        used.append("reg.Policies.CertProp")
        raw = as_int_safe(policy.get("CertPropEnabled"))
        enabled = None if raw is None else bool(raw)
    status = policy_status if policy_status != "ok" else ("set" if enabled is not None else "not configured")

    service, service_status = _winreg_read(CERTPROP_SERVICE_KEY)
    start_label = None
    if service_status == "ok":
        used.append("reg.Services.CertPropSvc")
        start_label = SERVICE_START_LABELS.get(as_int_safe(service.get("Start")))

    assessment = CertificatePropagationAssessment(
        query_failed=bool(errors) and not certificates,
        query_error="; ".join(errors) if errors else None,
        certificates=certificates,
        cert_prop_enabled=enabled,
        cert_prop_status=status,
        service_start_label=start_label,
        sources=sorted(set(used)),
    )
    return assessment, used, errors


def _collect_sdr() -> tuple[SdrAssessment, list[str], list[str]]:
    if not _is_windows():
        raise CollectionError("SDR collection requires Windows")
    errors: list[str] = []
    used: list[str] = []
    devices: list[SdrDevice] = []
    try:
        raw = _run_powershell(_PS_SDR_PNP_SCRIPT)
        rows = _loads_ps_json(raw)
        used.append("powershell.PnpDevice.SDRAllowlist")
        for row in rows:
            name = str(row.get("FriendlyName") or "SDR device")
            instance = row.get("InstanceId")
            hwids = _as_str_list(row.get("HardwareID"))
            hit = match_sdr_allowlist(instance, name, hwids)
            if not hit:
                continue
            devices.append(
                SdrDevice(
                    name=name,
                    instance_id=str(instance) if instance else None,
                    present=bool(row.get("Present")),
                    status=str(row.get("Status") or ""),
                    vid_pid=_sdr_vid_pid_from_instance(instance),
                    allowlist_hit=hit,
                    last_write_utc=_winreg_last_write_utc(_enum_path_for_instance(instance) or ""),
                    source="pnp-enum",
                    manufacturer=str(row.get("Manufacturer") or "") or None,
                )
            )
    except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        errors.append(f"SDR PnP query failed: {_short_error(exc)}")

    try:
        reg_devs = _collect_sdr_registry()
        if reg_devs:
            used.append("reg.Enum.USB.allowlist")
        devices.extend(reg_devs)
    except OSError as exc:
        errors.append(f"SDR registry allowlist failed: {_short_error(exc)}")

    deduped = _dedupe_sdr(devices)
    query_failed = bool(errors) and not deduped
    return (
        SdrAssessment(
            query_failed=query_failed,
            query_error="; ".join(errors) if query_failed else None,
            devices=deduped,
            sources=used,
        ),
        used,
        errors,
    )


def _dedupe_sdr(rows: list[SdrDevice]) -> list[SdrDevice]:
    by_id: dict[str, SdrDevice] = {}
    for row in rows:
        key = (row.instance_id or row.name).upper()
        existing = by_id.get(key)
        if existing is None:
            by_id[key] = row
            continue
        if row.present and not existing.present:
            by_id[key] = row
        elif row.last_write_utc and not existing.last_write_utc:
            existing.last_write_utc = row.last_write_utc
    return list(by_id.values())


def _classify_historical_pnp(raw: dict[str, Any]) -> str | None:
    pnp_class = str(raw.get("Class") or "")
    name = str(raw.get("FriendlyName") or raw.get("Name") or "")
    hwids = _as_str_list(raw.get("HardwareID") or raw.get("HardwareIds"))
    if pnp_class in {"Biometric", "SmartCardReader", "Infrared", "Sensor"}:
        return pnp_class
    if looks_like_related_ir_camera(name, hwids, pnp_class) or looks_like_hello_face(name, hwids, pnp_class):
        return "Infrared"
    return None


def _winreg_open(path: str, root: int | None = None):
    """Open a registry key in the native 64-bit view.

    KEY_WOW64_64KEY is explicit: without it a 32-bit interpreter on 64-bit
    Windows is redirected into WOW6432Node and silently reads the wrong view of
    SOFTWARE\\Microsoft\\Cryptography\\Calais and the WinBio keys.
    """
    if _winreg is None:
        raise CollectionError("winreg unavailable")
    access = _winreg.KEY_READ | getattr(_winreg, "KEY_WOW64_64KEY", 0)
    hive = _winreg.HKEY_LOCAL_MACHINE if root is None else root
    return _winreg.OpenKey(hive, path, 0, access)


def _winreg_read(path: str, root: int | None = None) -> tuple[dict[str, Any], str]:
    """Read a key's values and report *why* it came back empty.

    _winreg_values collapses a missing key and an access denial into the same
    empty dict. For a presence check that difference is the whole answer: an
    absent value means the weakness is not there, a denial means we do not
    know. Status is one of ok / missing / denied / error / unavailable.
    """
    if _winreg is None:
        return {}, "unavailable"
    try:
        key = _winreg_open(path, root)
    except FileNotFoundError:
        return {}, "missing"
    except PermissionError:
        return {}, "denied"
    except OSError:
        return {}, "error"
    values: dict[str, Any] = {}
    try:
        index = 0
        while True:
            try:
                name, value, _typ = _winreg.EnumValue(key, index)
            except OSError:
                break
            if name:
                values[name] = value.hex() if isinstance(value, bytes) else value
            index += 1
    finally:
        _winreg.CloseKey(key)
    return values, "ok"


def _winreg_values(path: str) -> tuple[dict[str, Any], str]:
    """Read every value under a key. Returns (values, status).

    WAS `-> dict[str, Any]`, returning {} for BOTH an absent key and a denied
    read. `_winreg_read` has always returned a status; this one did not, and 13
    call sites inherited the ambiguity. The consequence landed under the tier
    layer: `dma_guard_policy is None` meant key-absent, value-absent, denied OR
    unparseable, and the DMAGUARD-NO-POLICY row asserted a gap from all four -
    a Tier A false positive with a remediation command attached.

    Status vocabulary matches `_winreg_read` exactly: ok / missing / denied.
    A caller that deliberately ignores the status must say so in a comment;
    a silently discarded status is indistinguishable from an overlooked one.
    """
    out: dict[str, Any] = {}
    try:
        key = _winreg_open(path)
    except PermissionError:
        return out, "denied"
    except FileNotFoundError:
        return out, "missing"
    except OSError as exc:
        return out, "denied" if getattr(exc, "winerror", 0) == 5 else "missing"
    try:
        index = 0
        while True:
            try:
                name, value, _typ = _winreg.EnumValue(key, index)
            except OSError:
                break
            if name:
                if isinstance(value, bytes):
                    out[name] = value.hex()
                else:
                    out[name] = value
            index += 1
    finally:
        _winreg.CloseKey(key)
    return out, "ok"


def _winreg_subkeys(path: str, root: int | None = None) -> list[str]:
    names: list[str] = []
    try:
        key = _winreg_open(path, root)
    except OSError:
        return names
    try:
        index = 0
        while True:
            try:
                names.append(_winreg.EnumKey(key, index))
            except OSError:
                break
            index += 1
    finally:
        _winreg.CloseKey(key)
    return names


def _winreg_last_write_utc(path: str) -> str | None:
    """UTC last-write time of a HKLM key (registry FILETIME)."""
    if _winreg is None:
        return None
    try:
        key = _winreg_open(path)
    except OSError:
        return None
    try:
        _subkeys, _values, last_write = _winreg.QueryInfoKey(key)
    except OSError:
        return None
    finally:
        _winreg.CloseKey(key)
    return filetime_to_utc_iso(last_write)


def filetime_from_registry_value(value: Any) -> str | None:
    """Decode a FILETIME stored as REG_BINARY into UTC ISO-8601.

    _winreg_read hex-encodes binary values, so this takes the hex string,
    reads eight little-endian bytes and hands them to the existing converter.
    """
    if value is None:
        return None
    if isinstance(value, int):
        return filetime_to_utc_iso(value)
    text = str(value).strip()
    if len(text) < 16:
        return None
    try:
        raw = bytes.fromhex(text[:16])
    except ValueError:
        return None
    return filetime_to_utc_iso(int.from_bytes(raw, "little"))


def device_timestamps_from_registry(instance_id: str | None) -> dict[str, str]:
    """Read install / arrival / removal dates straight from the property store.

    Four registry reads per device instead of a CIM round trip, and it works on
    devices that are no longer present - which is the entire point of the
    historical collector.
    """
    base = _enum_path_for_instance(instance_id)
    if not base:
        return {}
    found: dict[str, str] = {}
    for pid, key_name in DEVPKEY_TIMESTAMP_PIDS.items():
        values, status = _winreg_read(f"{base}\\Properties\\{DEVPKEY_DEVICE_GUID}\\{pid}")
        if status != "ok":
            continue
        for raw in values.values():
            stamp = filetime_from_registry_value(raw)
            if stamp:
                found[key_name] = stamp
                break
    return found


def _enum_path_for_instance(instance_id: str | None) -> str | None:
    if not instance_id:
        return None
    return "SYSTEM\\CurrentControlSet\\Enum\\" + str(instance_id).replace("/", "\\")


def _collect_historical_pnp() -> list[HistoricalRecord]:
    raw = _run_powershell(_PS_HISTORICAL_PNP_SCRIPT)
    rows = _loads_ps_json(raw)
    records: list[HistoricalRecord] = []
    for row in rows:
        category = _classify_historical_pnp(row)
        if category is None:
            continue
        name = str(row.get("FriendlyName") or "Unknown device")
        instance_id = row.get("InstanceId")
        # Straight from the device property store rather than a CIM call per
        # device. Works on absent devices, which is what this collector is for.
        stamps = device_timestamps_from_registry(instance_id)
        present = bool(row.get("Present"))
        notes = []
        if not present:
            notes.append("PnP node remains after the device left — phantom / historical instance.")
        if category == "Infrared" and looks_like_hello_face(name, _as_str_list(row.get("HardwareID")), row.get("Class")):
            notes.append("Name/IDs match Windows Hello Face / NIR imaging.")
        records.append(
            HistoricalRecord(
                category=category,
                name=name,
                instance_id=str(instance_id) if instance_id else None,
                source="pnp-enum",
                present=present,
                first_install=stamps.get("DEVPKEY_Device_FirstInstallDate")
                or stamps.get("DEVPKEY_Device_InstallDate"),
                last_arrival=stamps.get("DEVPKEY_Device_LastArrivalDate"),
                last_removal=stamps.get("DEVPKEY_Device_LastRemovalDate"),
                last_write_utc=_winreg_last_write_utc(_enum_path_for_instance(instance_id) or ""),
                manufacturer=(str(row.get("Manufacturer")).strip() if row.get("Manufacturer") else None),
                status=str(row.get("Status") or ""),
                extra={
                    "enumerator": enumerator_from_instance_id(instance_id),
                    "hardware_ids": _as_str_list(row.get("HardwareID")),
                    "pnp_class": row.get("Class"),
                },
                notes=notes,
            )
        )
    return records


def _collect_historical_registry() -> tuple[list[HistoricalRecord], dict[str, Any], list[str]]:
    records: list[HistoricalRecord] = []
    policy: dict[str, Any] = {}
    used: list[str] = []
    if _winreg is None:
        return records, policy, used

    bio_path = r"SOFTWARE\Policies\Microsoft\Biometrics"
    # STATUS IGNORED: biometric policy sweep; absence is the common case and the
    # section reports the policy as undetermined when nothing is found.
    bio_vals, _ = _winreg_values(bio_path)
    # STATUS IGNORED: a sub-key of the same policy hive; same reasoning as
    # the parent.
    cred_vals, _ = _winreg_values(bio_path + r"\Credential Provider")
    if bio_vals or cred_vals:
        used.append("reg.Policies.Biometrics")
        policy["path"] = r"HKLM\SOFTWARE\Policies\Microsoft\Biometrics"
        policy["enabled"] = bio_vals.get("Enabled")
        policy["credential_provider"] = cred_vals
        policy["values"] = {k: v for k, v in bio_vals.items()}
        enabled = bio_vals.get("Enabled")
        notes = [
            "GPO/MDM biometric policy hive. Absence of the key usually means 'not configured', not disabled."
        ]
        if enabled in (0, "0"):
            notes.append("Enabled=0 — Windows Biometric Framework is policy-disabled.")
        records.append(
            HistoricalRecord(
                category="Biometric",
                name="Biometrics policy",
                instance_id=bio_path,
                source="biometrics-policy",
                present=True,
                last_write_utc=_winreg_last_write_utc(bio_path),
                extra={"enabled": enabled, "credential_provider": cred_vals},
                notes=notes,
            )
        )

    layout_root = r"SYSTEM\CurrentControlSet\Services\WbioSrvc\Service Providers\Fingerprint\Sensor Layout"
    layout_keys = _winreg_subkeys(layout_root)
    if layout_keys:
        used.append("reg.WbioSrvc.SensorLayout")
    for key_name in layout_keys:
        # STATUS IGNORED: historical residue enumeration; an unreadable key
        # contributes no residue record, the same outcome as absence, and the
        # omitted-context count reports what was skipped.
        vals, _ = _winreg_values(layout_root + "\\" + key_name)
        loc = vals.get("location")
        loc_int = as_int_safe(loc)
        loc_label = WBIO_LOCATION.get(loc_int, str(loc)) if loc_int is not None else loc
        notes = [f"WinBio fingerprint sensor layout remnant ({key_name})."]
        if loc_label == "external" or loc == 6:
            notes.append("Layout marks this sensor as external — likely a dongle that may no longer be attached.")
        records.append(
            HistoricalRecord(
                category="Biometric",
                name=f"Fingerprint layout: {key_name}",
                instance_id=key_name,
                source="wbio-layout",
                present=False,
                last_write_utc=_winreg_last_write_utc(layout_root + "\\" + key_name),
                extra={"location": loc_label, "shape": vals.get("shape"), "values": vals},
                notes=notes,
            )
        )

    # One append per subkey put the same label in the list once per database,
    # so a host with three enrolled databases printed
    # "reg.WbioSrvc.Databases, reg.WbioSrvc.Databases, reg.WbioSrvc.Databases".
    # The three reads are three subkeys of one enumerated root, which is one
    # acquisition point; the per-database count is already reported by the
    # historical section's context row.
    db_root = r"SYSTEM\CurrentControlSet\Services\WbioSrvc\Databases"
    db_guids = list(_winreg_subkeys(db_root))
    if db_guids:
        used.append("reg.WbioSrvc.Databases")
    for guid in db_guids:
        # STATUS IGNORED: WinBio database residue; same reasoning as the layout
        # root.
        vals, _ = _winreg_values(db_root + "\\" + guid)
        btype = vals.get("BiometricType")
        btype_int = as_int_safe(btype)
        if btype_int is not None:
            label = {8: "Fingerprint", 2: "Face", 4: "Voice", 16: "Iris"}.get(btype_int, str(btype_int))
        elif btype is not None:
            label = f"unknown (raw: {btype})"
        else:
            label = "unknown"
        records.append(
            HistoricalRecord(
                category="Biometric",
                name=f"WinBio database ({label})",
                instance_id=guid,
                source="wbio-database",
                present=True,
                last_write_utc=_winreg_last_write_utc(db_root + "\\" + guid),
                extra={"biometric_type": btype, "filepath_set": bool(vals.get("FilePath"))},
                notes=["WinBio database registration. Template bytes are not read."],
            )
        )

    acct_root = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo"
    sids = _winreg_subkeys(acct_root)
    if sids:
        used.append("reg.WinBio.AccountInfo")
    for sid in sids:
        # STATUS IGNORED: WinBio account residue; same reasoning.
        vals, _ = _winreg_values(acct_root + "\\" + sid)
        factors = vals.get("EnrolledFactors")
        factors_int = as_int_safe(factors)
        if factors_int is not None:
            factor_label = ENROLLED_FACTORS.get(factors_int, str(factors_int))
        elif factors is not None:
            factor_label = f"unknown (raw: {factors})"
        else:
            factor_label = "unknown"
        records.append(
            HistoricalRecord(
                category="Biometric",
                name=f"Enrolled factors: {factor_label}",
                instance_id=sid,
                source="winbio-account",
                present=True,
                last_write_utc=_winreg_last_write_utc(acct_root + "\\" + sid),
                extra={"enrolled_factors": factors},
                notes=["Account enrolled Hello face and/or fingerprint. Templates are not exported."],
            )
        )

    readers_root = r"SOFTWARE\Microsoft\Cryptography\Calais\Readers"
    reader_names = _winreg_subkeys(readers_root)
    if reader_names:
        used.append("reg.Calais.Readers")
    for reader in reader_names:
        # STATUS IGNORED: Calais reader residue; same reasoning.
        vals, _ = _winreg_values(readers_root + "\\" + reader)
        records.append(
            HistoricalRecord(
                category="SmartCardReader",
                name=reader,
                instance_id=str(vals.get("Device") or reader),
                source="calais-readers",
                present=False,
                last_write_utc=_winreg_last_write_utc(readers_root + "\\" + reader),
                extra={"groups": vals.get("Groups"), "device": vals.get("Device")},
                notes=["Calais resource-manager reader entry. Persists after many unplug events."],
            )
        )

    cards_root = r"SOFTWARE\Microsoft\Cryptography\Calais\SmartCards"
    card_names = _winreg_subkeys(cards_root)
    if card_names:
        used.append("reg.Calais.SmartCards")
    for card in card_names:
        # STATUS IGNORED: Calais card-type residue; same reasoning.
        vals, _ = _winreg_values(cards_root + "\\" + card)
        atr = vals.get("ATR")
        atr_disp = atr
        records.append(
            HistoricalRecord(
                category="SmartCardReader",
                name=f"Card type: {card}",
                instance_id=card,
                source="calais-smartcards",
                present=True,
                last_write_utc=_winreg_last_write_utc(cards_root + "\\" + card),
                extra={"atr": atr_disp, "provider": vals.get("Crypto Provider") or vals.get("Smart Card Key Storage Provider")},
                notes=["Installed smart-card minidriver / ATR mapping. Not a live card insertion log."],
            )
        )

    return records, policy, used


def _dedupe_historical(records: list[HistoricalRecord]) -> list[HistoricalRecord]:
    seen: set[tuple[str, str | None, str]] = set()
    out: list[HistoricalRecord] = []
    for rec in records:
        key = (rec.category, rec.instance_id, rec.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def _collect_historical() -> tuple[HistoricalAssessment, list[str], list[str]]:
    if not _is_windows():
        raise CollectionError("Historical collection requires Windows")
    errors: list[str] = []
    used: list[str] = []
    records: list[HistoricalRecord] = []
    policy: dict[str, Any] = {}

    try:
        pnp_rows = _collect_historical_pnp()
        records.extend(pnp_rows)
        used.append("powershell.Get-PnpDevice.historical")
    except (CollectionError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        errors.append(f"Historical PnP failed: {_short_error(exc)}")

    try:
        reg_rows, policy, reg_used = _collect_historical_registry()
        records.extend(reg_rows)
        used.extend(reg_used)
    except (CollectionError, OSError) as exc:
        errors.append(f"Historical registry failed: {_short_error(exc)}")

    if not records and errors:
        return (
            HistoricalAssessment(query_failed=True, query_error="; ".join(errors), sources=used),
            used,
            errors,
        )
    return (
        HistoricalAssessment(records=_dedupe_historical(records), policy=policy, sources=used),
        used,
        errors,
    )


# Overridable seams for tests
# What an attacker at a given level could make each source say. The tool reads
# from above the layers it reports on, so every answer is only as trustworthy
# as the layer beneath it - this makes that explicit per collector rather than
# leaving the reader to assume.
SOURCE_TRUST = {
    "hardware": "anchored in hardware; cannot be rewritten after the fact by software",
    "firmware": "supplied by firmware; an administrator cannot alter it, firmware itself can",
    "kernel": "reported by the running kernel; a kernel-level attacker can lie",
    "os": "OS state an administrator can write",
}
SOURCE_TRUST_ORDER = ("hardware", "firmware", "kernel", "os")


@dataclass(frozen=True)
class CollectorSpec:
    """One collection domain.

    name      stable key used in results and scanner_context
    label     human wording for the error message
    run       () -> (value, sources_used, non_fatal_errors)
    fallback  (error_text) -> a value standing in for the failed collection
    """

    name: str
    label: str
    run: Callable[[], tuple[Any, list[str], list[str]]]
    fallback: Callable[[str], Any]
    # Multiplier on the global PowerShell budget. One flat timeout across every
    # query is wrong: Get-Tpm returns in well under a second, while the
    # historical sweep walks six device classes with no -PresentOnly and makes
    # a CIM round trip per device. Scaled rather than absolute so --timeout
    # still governs the whole run.
    timeout_scale: float = 1.0
    # Which layer this collector's answers come from, and therefore who could
    # have altered them. See SOURCE_TRUST.
    trust: str = "os"
    reads: str = ""


@dataclass
class CollectorOutcome:
    values: dict[str, Any] = field(default_factory=dict)
    failed: set[str] = field(default_factory=set)

    def ok(self, name: str) -> bool:
        """Did this collector run to completion? Not the same as finding data."""
        return name in self.values and name not in self.failed


def default_collectors(*, include_related_ir_cameras: bool = True) -> tuple[CollectorSpec, ...]:
    """The standard collection set.

    Adding a domain is one entry here and nothing else in the orchestration.
    The callables resolve the module-level collect_* names at call time, so
    those seams stay replaceable for testing.
    """
    return (
        CollectorSpec(
            "pnp",
            "PnP",
            lambda: collect_pnp_devices(include_related_ir_cameras=include_related_ir_cameras),
            lambda _error: [],
            # four classes, a CIM property call per device
            timeout_scale=2.0,
            trust="os",
            reads="PnP device tree via CIM",
        ),
        CollectorSpec(
            "tpm", "TPM", lambda: collect_tpm(),
            lambda error: TpmRecord(query_failed=True, query_error=error),
            trust="os",
            reads="TPM state via WMI, owner-auth presence via registry",
        ),
        CollectorSpec(
            "bitlocker", "BitLocker", lambda: collect_bitlocker(),
            lambda error: BitLockerRecord(query_failed=True, query_error=error),
            trust="os",
            reads="volume protection via WMI",
        ),
        CollectorSpec(
            "dma", "DMA", lambda: collect_dma(),
            lambda error: DmaAssessment(query_failed=True, query_error=error),
            trust="firmware",
            reads="Win32_DeviceGuard (kernel) corroborated by ACPI tables (firmware)",
        ),
        CollectorSpec(
            "sdr", "SDR", lambda: collect_sdr(),
            lambda error: SdrAssessment(query_failed=True, query_error=error),
            trust="os",
            reads="PnP allowlist match",
        ),
        CollectorSpec(
            "drivers", "Driver substitution", lambda: collect_driver_substitution(),
            lambda error: DriverSubstitutionAssessment(query_failed=True, query_error=error),
            trust="os",
            reads="driver service keys and the INF store",
        ),
        CollectorSpec(
            "interception", "Interception surface", lambda: collect_interception(),
            lambda error: InterceptionAssessment(query_failed=True, query_error=error),
            trust="os",
            reads="class filter and biometric adapter registry keys",
        ),
        CollectorSpec(
            "boot-integrity", "Boot integrity", lambda: collect_boot_integrity(),
            lambda error: BootIntegrityAssessment(query_failed=True, query_error=error),
            trust="kernel",
            reads="kernel code-integrity state and the boot store",
        ),
        CollectorSpec(
            "hardware-access", "Hardware access", lambda: collect_hardware_access(),
            lambda error: HardwareAccessAssessment(query_failed=True, query_error=error),
            trust="os",
            reads="driver service keys, runtime state, Authenticode",
        ),
        CollectorSpec(
            "firmware", "Firmware", lambda: collect_firmware(),
            lambda error: FirmwareAssessment(query_failed=True, query_error=error),
            trust="firmware",
            reads="ACPI tables and firmware resource registrations",
        ),
        CollectorSpec(
            "certificates", "Certificate propagation",
            lambda: collect_smartcard_certificates(),
            lambda error: CertificatePropagationAssessment(
                query_failed=True, query_error=error
            ),
            # two certificate stores plus a registry blob walk
            timeout_scale=2.0,
            trust="os",
            reads="certificate stores and their registry blobs",
        ),
        CollectorSpec(
            "historical", "Historical", lambda: collect_historical(),
            lambda error: HistoricalAssessment(query_failed=True, query_error=error),
            # six classes including absent devices, a CIM call per device:
            # comfortably the most expensive query in the tool
            timeout_scale=3.0,
            trust="os",
            reads="device property store in the registry",
        ),
    )


def _collector_value(
    values: dict[str, Any],
    name: str,
    expected: type,
    factory: Callable[[], Any],
    errors: list[str],
) -> Any:
    """Take a collector's value only if it is the type this domain expects.

    Collectors are an injection seam, so the value is external input as far as
    the orchestration is concerned. A wrong type degrades to the not-collected
    stand-in and says so, rather than raising several frames away from the
    collector that actually produced it.
    """
    value = values.get(name)
    if value is None:
        return factory()
    if not isinstance(value, expected):
        errors.append(
            f"{name} collector returned {type(value).__name__}, expected "
            f"{expected.__name__}; treating it as not collected"
        )
        return factory()
    return value


def select_collectors(
    specs: Sequence[CollectorSpec],
    *,
    only: Sequence[str] | None = None,
    skip: Sequence[str] | None = None,
) -> tuple[tuple[CollectorSpec, ...], tuple[CollectorSpec, ...]]:
    """Split a registry into (selected, skipped).

    An operator needs a way to take one collector out of the run without
    editing the tool - a query that misbehaves on their hardware should not
    cost them the whole report.
    """
    known = {spec.name for spec in specs}
    for requested in list(only or []) + list(skip or []):
        if requested not in known:
            raise ValueError(
                f"unknown collector {requested!r}; known: {', '.join(sorted(known))}"
            )
    selected = tuple(
        spec
        for spec in specs
        if (not only or spec.name in only) and spec.name not in (skip or ())
    )
    chosen = {spec.name for spec in selected}
    return selected, tuple(spec for spec in specs if spec.name not in chosen)


NOT_COLLECTED_REASON = "not collected (skipped)"


def run_collectors(
    specs: Sequence[CollectorSpec],
    *,
    on_error: OnErrorMode,
    errors: list[str],
    used_collectors: list[str],
) -> CollectorOutcome:
    """Run every registered collector, honouring the on_error contract once."""
    outcome = CollectorOutcome()
    base_timeout = PS_TIMEOUT_SEC
    for spec in specs:
        budget = max(1, int(round(base_timeout * spec.timeout_scale)))
        try:
            set_powershell_timeout(budget)
            value, used, collector_errors = spec.run()
            used_collectors.extend(used)
            errors.extend(collector_errors)
            outcome.values[spec.name] = value
        except subprocess.TimeoutExpired:
            if on_error == "raise":
                raise
            # Name the remedy: an operator cannot act on "it timed out".
            message = (
                f"{spec.label} collection timed out after {budget}s. "
                f"Retry with --timeout {max(base_timeout * 2, 60)} "
                f"or drop it with --skip {spec.name}."
            )
            errors.append(message)
            outcome.values[spec.name] = spec.fallback(message)
            outcome.failed.add(spec.name)
        except (CollectionError, OSError, TimeoutError) as exc:
            if on_error == "raise":
                raise
            errors.append(f"{spec.label} collection failed: {_short_error(exc)}")
            outcome.values[spec.name] = spec.fallback(_short_error(exc))
            outcome.failed.add(spec.name)
        finally:
            set_powershell_timeout(base_timeout)
    return outcome


collect_pnp_devices: Callable[..., tuple[list[dict[str, Any]], list[str], list[str]]] = _collect_pnp_devices
collect_tpm: Callable[..., tuple[TpmRecord, list[str], list[str]]] = _collect_tpm
collect_bitlocker: Callable[..., tuple[BitLockerRecord, list[str], list[str]]] = _collect_bitlocker
collect_dma: Callable[..., tuple[DmaAssessment, list[str], list[str]]] = _collect_dma
collect_sdr: Callable[..., tuple[SdrAssessment, list[str], list[str]]] = _collect_sdr
collect_interception: Callable[
    ..., tuple[InterceptionAssessment, list[str], list[str]]
] = _collect_interception
collect_boot_integrity: Callable[
    ..., tuple[BootIntegrityAssessment, list[str], list[str]]
] = _collect_boot_integrity
collect_hardware_access: Callable[
    ..., tuple[HardwareAccessAssessment, list[str], list[str]]
] = _collect_hardware_access
collect_firmware: Callable[
    ..., tuple[FirmwareAssessment, list[str], list[str]]
] = _collect_firmware
collect_smartcard_certificates: Callable[
    ..., tuple[CertificatePropagationAssessment, list[str], list[str]]
] = _collect_smartcard_certificates
collect_driver_substitution: Callable[
    ..., tuple[DriverSubstitutionAssessment, list[str], list[str]]
] = _collect_driver_substitution
collect_historical: Callable[..., tuple[HistoricalAssessment, list[str], list[str]]] = _collect_historical


# ===========================================================================
# Enrichment / findings
# ===========================================================================


def _build_device_record(raw: dict[str, Any], *, force_category: str | None = None) -> DeviceRecord | None:
    pnp_class = str(raw.get("Class") or "Unknown")
    raw_name = str(raw.get("FriendlyName") or "Unknown device")
    name = sanitize_display(raw_name) or "Unknown device"
    name_was_hostile = name != raw_name
    instance_id = raw.get("InstanceId")
    hardware_ids = list(raw.get("HardwareID") or [])
    manufacturer = raw.get("Manufacturer")
    virtual = is_virtual_or_software(instance_id, name)
    # None means the source did not say. Only an explicit False excludes.
    raw_present = raw.get("Present")
    present = None if raw_present is None else bool(raw_present)
    enumerator = enumerator_from_instance_id(instance_id)
    hello = looks_like_hello_face(name, hardware_ids, pnp_class)
    location = looks_like_location_sensor(name, hardware_ids)

    category = force_category or pnp_class
    if category not in PNP_CLASSES and category != "TPM":
        if looks_like_related_ir_camera(name, hardware_ids, pnp_class):
            category = "Infrared"
        else:
            return None

    imaging = category == "Infrared" and (
        looks_like_ir_imager(name, hardware_ids, pnp_class) or hello or pnp_class in {"Camera", "Image"}
    )

    if category == "Biometric":
        tags = indicators_for_biometric(name, hello_face=hello)
        risk = [
            (
                "Post-compromise, operators can attempt WinBio/Hello interception "
                "or pair a keylogger with this sensor to defeat MFA that users "
                "believe is phishing-resistant. Presence does not prove an "
                "MFA-bypass occurred."
            )
        ]
        if hello:
            risk.append(
                "Device appearance matches Windows Hello Face / NIR. Presentation "
                "or replay against the IR pipeline is an additional T1111/T1556.006 path."
            )
    elif category == "SmartCardReader":
        tags = indicators_for_smartcard(virtual=virtual)
        risk = [
            "Classic T1111 smart-card proxy pattern: malware waits for card "
            "insertion, captures PIN (T1056.001), and relays PKCS#11/CSP "
            "operations to reach card-protected resources."
        ]
        if virtual:
            risk.append(
                "Virtual / software smart-card reader — often TPM-backed. Quality "
                "of isolation tracks the TPM record on this host."
            )
    elif category == "Infrared":
        tags = indicators_for_infrared(imaging=imaging, hello_face=hello)
        if imaging or hello:
            risk = [
                "NIR / IR imaging pipeline can be targeted with presentation or "
                "replay; it is also a T1125 collection device if a compromised "
                "process can open the camera handle."
            ]
        else:
            risk = [
                "Ambient IR or proximity sensor is a low-bandwidth collection "
                "device but remains useful for environment awareness (T1497)."
            ]
    else:
        tags = indicators_for_generic_sensor(location_like=location)
        risk = [
            "On a compromised host these sensors mainly help an operator "
            "fingerprint hardware and evade sandboxes (T1497 / T1082)."
        ]
        if location:
            risk.append(
                "Location/GNSS capability can expose geolocation privacy if an "
                "operator queries the sensor stack. No Collection technique ID is forced."
            )

    tags = tags + indicators_for_usb_addition(enumerator=enumerator, manufacturer=manufacturer)

    extra = {
        "pnp_class": pnp_class,
        "enumerator": enumerator,
        "service": raw.get("Service"),
        "driver_version": raw.get("DriverVersion"),
        "driver_date": raw.get("DriverDate"),
        "location_info": raw.get("LocationInfo"),
        "has_problem": raw.get("HasProblem"),
        "source": raw.get("Source"),
        "hello_face": hello,
        "imaging": imaging if category == "Infrared" else False,
        "location_sensor": location,
    }
    return DeviceRecord(
        category=category,
        present=present,
        name=name,
        instance_id=str(instance_id) if instance_id else None,
        status=str(raw.get("Status") or "Unknown"),
        manufacturer=manufacturer,
        hardware_ids=hardware_ids,
        virtual_or_software=virtual,
        problem_code=raw.get("Problem"),
        extra=extra,
        mitre=tags,
        risk_notes=(
            risk
            + (
                [
                    "Device name contained terminal control or bidirectional "
                    "override characters. They were stripped for display; a name "
                    "crafted this way is itself suspicious."
                ]
                if name_was_hostile
                else []
            )
        ),
    )


def _sources_row(tags: Iterable[str], detail: bool) -> tuple[str, str]:
    """The Sources KV row, with the enumeration behind --collectors.

    The count is never hidden. A section that read from eight sources and one
    that read from none are different results, not different amounts of
    reference material, so the number survives the flag and zero says so
    plainly.
    """
    items = provenance_list(tags)
    if not items:
        return "Sources", "NONE - this section read from no source"
    if detail:
        return "Sources", ", ".join(items)
    return "Sources", f"{len(items)} (--collectors for the list)"


# ---------------------------------------------------------------------------
# Actionable-weakness highlighting
#
# The report already names every weakness it finds; what it does not do is
# separate the ones an operator can act on from the ones that are facts about
# the hardware. A MITRE tag alone is not the test - almost every row carries
# one, including "TPM is present and healthy". The test is: is there a
# weakness, AND is there a concrete mitigation available on THIS host?
#
# BitLocker off on a machine with a working TPM is actionable. No IOMMU on a
# board whose firmware does not expose one is not - it is a purchasing
# decision, not a remediation. Highlighting both teaches the reader to ignore
# the colour.
_ANSI_HIGHLIGHT = "\x1b[1;33m"      # bold yellow
_ANSI_RESET = "\x1b[0m"


# ---------------------------------------------------------------------------
# Tier layer
#
# Tier A  fixable now, from the OS
# Tier B  needs a firmware or BIOS change
# Tier C  not available on this hardware
#
# All three highlight. The tier carries the signal, not the presence of colour.
# Tier C is informational and still highlighted, because its value is telling a
# reader what this class of machine should have had.
#
# THE RULE THAT MATTERS: an undetermined value produces NO tier row. Not Tier C,
# not info, not a greyed variant. Tier C asserts "your hardware cannot do this";
# undetermined means "we did not establish it". Conflating them tells a reader
# their machine lacks a capability it may well have, which is the inverse of the
# whole point. Enforced in tier_of() rather than at the renderer, so no caller
# can bypass it.
TIER_A = "A"
TIER_B = "B"
TIER_C = "C"
TIER_LABELS = {
    TIER_A: "fixable now, from the OS",
    TIER_B: "needs a firmware or BIOS change",
    TIER_C: "not available on this hardware",
}


def tier_of(weak: bool | None, os_fixable: bool | None,
            hw_capable: bool | None) -> str | None:
    # Callers must pass the three-state field ITSELF, never `(field is True)`.
    # That expression coerces None to False and turns "we did not establish it"
    # into "the hardware cannot do it" - Tier C on a host that may well be
    # capable. It is the inverse of the ethos and it is the defect this
    # signature exists to make visible.
    """Assign a tier, or None when no row may be produced.

    Three-valued in, three-valued out. Every argument is `bool | None` because
    every one of them can be undetermined, and any single undetermined input
    forfeits the row - a tier is a claim about what this host could be, and a
    claim needs all of its evidence.

        weak       is the current state worse than achievable?
        os_fixable can it be changed from the OS?
        hw_capable can this hardware reach the better state at all?
    """
    if weak is None or hw_capable is None:
        return None            # we do not know; say nothing
    if not weak:
        return None            # nothing to surface
    if not hw_capable:
        return TIER_C          # real gap, unreachable on this hardware
    if os_fixable is None:
        return None            # reachable, but we cannot say how - not a tier
    return TIER_A if os_fixable else TIER_B


@dataclass
class TierRow:
    """One highlighted posture row.

    `key` is stable and becomes a compatibility surface the day --implement
    joins against it, so it is never derived from display text.
    """

    key: str
    tier: str
    section: str
    title: str
    detail: str
    mitigation: str
    command: str | None = None
    blocked_reason: str | None = None


def assess_tiers(result: "AssessmentResult") -> list[TierRow]:
    """Posture rows with a better state available somewhere.

    Every tier is COMPUTED from collected evidence. TPM-PRESENT-DISABLED is
    Tier B on a host with a TPM and Tier C on one without, and the tool can
    tell those apart - so nothing here is hardcoded.

    The boundary from the highlight analysis holds: highlight a gap between the
    current state and an ACHIEVABLE BETTER state. Absence of an optional feature
    that reduces attack surface is not a gap, which is why the biometric policy
    being disabled on a host does not appear below.
    """
    rows: list[TierRow] = []

    def add(key, section, title, detail, mitigation, *, weak, os_fixable,
            hw_capable, command=None, blocked=None):
        tier = tier_of(weak, os_fixable, hw_capable)
        if tier is None:
            return
        rows.append(TierRow(
            key=key, tier=tier, section=section, title=title, detail=detail,
            mitigation=mitigation, command=command,
            blocked_reason=blocked if tier != TIER_A else None))

    tpm, bl, dma = result.tpm, result.bitlocker, result.dma
    drv = result.drivers
    boot, fw, hw = result.boot_integrity, result.firmware, result.hardware_access
    certs, icp = result.certificates, result.interception

    # --- TPM ---------------------------------------------------------------
    if tpm and not tpm.query_failed:
        add("TPM-ABSENT", "TPM", "No TPM fitted",
            "No TPM detected; BitLocker, Hello and attestation all depend on one",
            "A TPM 2.0 module or a CPU with firmware TPM support",
            weak=(tpm.present is False), os_fixable=False,
            hw_capable=False,
            blocked="no TPM on this board; a firmware TPM may be available in BIOS")
        add("TPM-NOT-READY", "TPM", "TPM present but not ready",
            f"present={tpm.present}, enabled={tpm.enabled}, ready={tpm.ready}",
            "Enable and initialise the TPM, then let Windows provision it",
            weak=(True if (tpm.present and tpm.ready is False) else
                  False if tpm.present and tpm.ready else None),
            os_fixable=tpm.enabled, hw_capable=tpm.present,
            command="tpm.msc  # or enable in firmware first",
            blocked="the TPM is disabled in firmware; enable it in BIOS")
        add("TPM-OWNER-AUTH-FULL", "TPM", "Full TPM owner authorization retained in the OS",
            tpm.os_managed_auth_label or "full",
            "Reduce to delegated so the OS holds less owner authority",
            weak=(True if (tpm.os_managed_auth_label or "").lower().startswith("full")
                  else None),
            os_fixable=True, hw_capable=tpm.present,
            command="Group Policy: Configure the level of TPM owner authorization "
                    "information available to the OS -> Delegated")

    # --- BitLocker ---------------------------------------------------------
    if bl and not bl.query_failed and bl.volumes:
        unprot = [v for v in bl.volumes if (v.protection_status or "").lower() != "on"]
        add("BITLOCKER-OFF", "BitLocker", "Volume not protected",
            ", ".join(v.mount_point or "?" for v in unprot) or "-",
            "Enable BitLocker and escrow the recovery key",
            weak=bool(unprot), os_fixable=True,
            # Highlighted even with no TPM - operator ethos. A password or
            # startup-key protector makes it reachable on any machine.
            hw_capable=True,
            command="Enable-BitLocker -MountPoint '<drive>' -TpmProtector "
                    "-EncryptionMethod XtsAes256"
                    + ("   # no usable TPM: use -PasswordProtector"
                       if not (tpm and tpm.present and tpm.ready) else ""))
        weakm = [v for v in bl.volumes
                 if (v.encryption_method or "").upper() in
                 ("AES-128", "XTS-AES-128", "AES-128 WITH DIFFUSER")]
        add("BITLOCKER-WEAK-METHOD", "BitLocker", "Encryption weaker than available",
            ", ".join(f"{v.mount_point}: {v.encryption_method}" for v in weakm) or "-",
            "XTS-AES-256; requires decrypt and re-encrypt",
            weak=bool(weakm), os_fixable=True, hw_capable=True,
            # OS-fixable, but not by one command - and it is destructive if
            # interrupted. The invariant is that every Tier A row states the
            # change; it does not promise the change is a one-liner.
            command="manage-bde -off <drive>   # wait for full decryption, then "
                    "Enable-BitLocker -EncryptionMethod XtsAes256. Back up first.")
        tpmonly = [v for v in bl.volumes
                   if v.key_protectors_available
                   and any("tpm" == k.lower() for k in v.key_protectors)
                   and not any(k.lower() in ("tpmpin", "tpmpinstartupkey",
                                             "tpmstartupkey")
                               for k in v.key_protectors)]
        add("BITLOCKER-TPM-ONLY", "BitLocker", "TPM-only protector, no PIN",
            ", ".join(v.mount_point or "?" for v in tpmonly) or "-",
            "Add a PIN: the key is otherwise released on any successful boot, "
            "which composes with DMA memory extraction",
            weak=bool(tpmonly), os_fixable=True, hw_capable=(tpm.present if tpm else None),
            command="manage-bde -protectors -add C: -TPMAndPIN")

    # --- DMA ---------------------------------------------------------------
    if dma and not dma.query_failed:
        add("IOMMU-ABSENT", "DMA / Thunderbolt", "No IOMMU in firmware",
            "Neither DMAR nor IVRS present; Kernel DMA Protection cannot enforce",
            "A platform whose firmware exposes VT-d / AMD-Vi",
            weak=(dma.iommu_present is False), os_fixable=False,
            hw_capable=False,
            blocked="the firmware exposes no IOMMU table; this is a platform "
                    "property, not a setting")
        add("DMA-UNPROTECTED", "DMA / Thunderbolt",
            "IOMMU present but DMA protection not reported",
            f"IOMMU {dma.iommu_table or 'present'}, DeviceGuard reports unavailable",
            "Enable VT-d/AMD-Vi and Kernel DMA Protection in firmware",
            weak=(True if (dma.iommu_present and
                           dma.dma_protection_available is False) else None),
            os_fixable=False, hw_capable=True,
            blocked="negotiated at boot from firmware settings; no OS-side change "
                    "turns it on")
        add("DMAGUARD-NO-POLICY", "DMA / Thunderbolt",
            "No external-DMA enumeration policy set",
            "OS default applies; a policy makes the posture explicit",
            "Set a DmaGuard device enumeration policy",
            # P-5, three-valued. `policy is None` alone covered key-absent,
            # value-absent, denied AND unparseable, so this row asserted a gap
            # from a failed read - a Tier A false positive carrying a command.
            # Now: a measured absence is weak, an unreadable key is undetermined
            # and produces no row at all.
            weak=(None if dma.dma_guard_policy_status not in ("ok", "missing")
                  else dma.dma_guard_policy is None),
            os_fixable=True,
            hw_capable=dma.iommu_present,
            command="reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\"
                    "Kernel DMA Protection\" /v DeviceEnumerationPolicy "
                    "/t REG_DWORD /d 0 /f")

    # --- Boot integrity ----------------------------------------------------
    if boot and not boot.query_failed:
        add("BLOCKLIST-OFF", "Boot integrity",
            "Vulnerable driver blocklist not enforced",
            boot.blocklist_status or "-",
            "Enable the Microsoft vulnerable driver blocklist",
            weak=(boot.blocklist_enabled is False), os_fixable=True,
            hw_capable=True,
            command="reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config "
                    "/v VulnerableDriverBlocklistEnable /t REG_DWORD /d 1 /f")
        add("HVCI-OFF", "Boot integrity", "Memory integrity (HVCI) not running",
            "Kernel code is not verified before execution",
            "Enable memory integrity; needs VBS and a reboot",
            weak=(boot.hvci_enabled is False), os_fixable=True, hw_capable=True,
            command="Windows Security -> Device security -> Core isolation")
        add("TESTSIGNING-ON", "Boot integrity", "Test signing enabled",
            "Unsigned kernel drivers can load",
            "Turn test signing off and reboot",
            weak=boot.test_signing, os_fixable=True, hw_capable=True,
            command="bcdedit /set testsigning off")

    # --- Firmware ----------------------------------------------------------
    if fw and not fw.query_failed:
        add("NO-SMM-MITIGATIONS", "Firmware surface",
            "Firmware declares no SMM mitigations",
            "No WSMT table; Windows will not enable features that need that "
            "assertion",
            "A firmware update that publishes WSMT",
            weak=(fw.smm_mitigations_declared is False), os_fixable=False,
            hw_capable=True,
            blocked="WSMT is published by firmware; only a BIOS update adds it")
        add("FIRMWARE-PREDATES-MITIGATIONS", "Firmware surface",
            "Firmware predates the mitigation era",
            "Most mitigations reported in this section postdate this BIOS",
            "Update the BIOS if the vendor still ships one",
            weak=fw.predates_mitigations, os_fixable=False,
            hw_capable=True, blocked="requires a vendor BIOS release")

    # --- Low-level hardware access -----------------------------------------
    if hw and not hw.query_failed:
        add("KERNEL-RW-INSTALLED", "Low-level hardware access",
            "Kernel read/write driver installed and startable",
            ", ".join(d.driver for d in hw.kernel_rw_installed) or "-",
            "Remove the service and its binary if the game that installed it "
            "is gone",
            weak=bool(hw.kernel_rw_installed), os_fixable=True, hw_capable=True,
            command="sc.exe delete <service>   # then remove the .sys")
        add("ORPHANED-SERVICE-KEY", "Low-level hardware access",
            "Service key registered with no binary",
            ", ".join(d.driver for d in hw.orphaned_keys) or "-",
            "Delete the stale registration; it is a pre-authorised load path",
            weak=bool(hw.orphaned_keys), os_fixable=True, hw_capable=True,
            command="sc.exe delete <service>")

    # --- Smart-card certificates -------------------------------------------
    if certs and not certs.query_failed:
        expired = [c for c in certs.certificates if getattr(c, "expired", None)]
        add("CERT-EXPIRED", "Smart-card certificates",
            "Expired certificate still in the store",
            f"{len(expired)} certificate(s)",
            "Remove it; store hygiene against certificate-based credential theft",
            weak=bool(expired), os_fixable=True, hw_capable=True)

    # --- Interception ------------------------------------------------------
    if icp and not icp.query_failed:
        third = [f for f in icp.filters if f.inbox is False]
        add("THIRD-PARTY-FILTER", "Interception surface",
            "Non-inbox filter on an identity device class",
            ", ".join(f"{f.device_class}:{f.driver}" for f in third) or "-",
            "Identify the vendor and remove if unaccounted for - MANUAL ONLY, "
            "a misidentified filter can remove the input stack",
            weak=bool(third), os_fixable=True, hw_capable=True)

    # --- Generic driver & INF audit (P-3) ----------------------------------
    if drv and not drv.query_failed:
        unbound = [x for x in drv.services if x.present and not x.binding_count]
        add("GENERIC-DRIVER-UNBOUND", "Generic driver & INF audit",
            "Generic USB driver installed with nothing bound to it",
            ", ".join(x.service for x in unbound) or "-",
            "Remove the driver if the device it was installed for is gone - a "
            "generic driver with no device is an unused raw-endpoint path",
            weak=bool(unbound), os_fixable=True, hw_capable=True,
            command="pnputil /delete-driver <oemNN.inf> /uninstall")
        add("DELIBERATE-INF-RESIDUE", "Generic driver & INF audit",
            "INF package in the driver store naming a deliberate generic driver",
            ", ".join(x.inf_file for x in drv.deliberate_inf_hits) or "-",
            "Remove the package; libusb and UsbDk have no automatic binding "
            "path, so their presence implies a deliberate install",
            # deliberate_inf_hits deliberately excludes WinUSB-only packages:
            # those are ordinary vendor packaging, not a manual override.
            weak=bool(drv.deliberate_inf_hits), os_fixable=True, hw_capable=True,
            command="pnputil /delete-driver <oemNN.inf>")

    # NOTE: deliberately no row keyed on SecurityServicesRunning. Value 7 is
    # unmapped, and a tier over an incomplete enum is a guess.
    return rows


def highlight_enabled(stream: Any = None) -> bool:
    """True when colour should be emitted.

    Off when piped or redirected, because sanitize_display exists precisely to
    keep escape sequences out of captured output - emitting our own into a file
    an analyst greps would be the same defect from the other direction.
    NO_COLOR is honoured (no-color.org).
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("SENSOR_FORCE_COLOR"):
        return True
    target = stream if stream is not None else sys.stdout
    try:
        return bool(target.isatty())
    except Exception:
        return False


def mark_actionable(text: str, *, enabled: bool) -> str:
    """Wrap a rendered row so it reads as actionable.

    When colour is off the row still carries a marker, so a redirected report
    and a terminal report flag the same rows. A highlight that vanishes on
    redirect is a highlight an operator cannot put in a ticket.
    """
    if enabled:
        return f"{_ANSI_HIGHLIGHT}{text}{_ANSI_RESET}"
    return text if text.startswith("  >>") else "  >>" + text[2:] if text.startswith("  ") else text


def tri_state(value: Any, absent: str = "none declared") -> str:
    """Render a three-state field without collapsing it onto one glyph.

    The tool has three answers to express and the renderers had one symbol for
    all of them: absent, undetermined, and not-applicable all printed "-".
    Round 1's A-4 fix stopped the collectors asserting a negative from a
    registry miss and made the value None; the renderer then turned None back
    into "-", which a reader takes as "none". The fix moved the defect rather
    than ending it.

    None is undetermined and says so. An explicit empty value is an absence and
    gets the caller's wording. Anything else prints as itself.
    """
    if value is None:
        return "undetermined (not established)"
    if value is False:
        return absent
    text = str(value).strip()
    return text if text else absent


def tri_measure(value: Any, unit: str = "", *, unavailable: str | None = None,
                not_applicable: bool = False) -> str:
    """Render a measured quantity that can legitimately be zero.

    Third instance of the falsy family, after tri_state(True) printing a Python
    repr and the six `is True` coercions in the tier layer. `if value` is false
    for None AND for 0, so a WPBT declaring a zero-length image rendered as
    "not read" - a measured zero reported as an absent measurement.

    A helper rather than a third bespoke fix, because the pattern has now
    recurred three times and the next `int | None` reaching a renderer will hit
    it too.
    """
    if not_applicable:
        return "n/a"
    if value is None:
        return f"not read ({unavailable})" if unavailable else "not read"
    return f"{value} {unit}".strip() if unit else str(value)


def tri_bool(value: bool | None, yes: str = "yes", no: str = "no") -> str:
    """Render a three-state BOOLEAN. Sibling of tri_state, not a branch of it.

    tri_state passes an unrecognised value through as itself, which is right for
    "DMAR" and wrong for True: round 7 wrapped the blocklist row in tri_state to
    protect its new None case and the row began printing the Python repr `True`
    where it used to print `yes`.

    A sibling rather than a special case inside tri_state, because tri_state is
    correctly written for `str | None` and pass-through IS its contract. Teaching
    it to special-case bool would give one helper two contradictory contracts,
    and the next `int | None` or `list | None` would fork it again. A typed
    sibling makes the call site declare what it is rendering, which is the thing
    that was missing.
    """
    if value is None:
        return "undetermined (not established)"
    return yes if value else no


def _resolve_inf_string(value: Any) -> str | None:
    """Resolve an INF indirect string to displayable text, or None.

    Windows stores DeviceDesc as "@file.inf,%token%;Fallback Text". The token
    resolves through the INF at display time; the fallback after the last
    semicolon is what the OS shows when it cannot. Neither the token nor the
    raw form belongs in a report, so an unresolvable indirect string yields
    None and the caller prints the instance name alone.
    """
    text = str(value).strip() if value is not None else ""
    if not text:
        return None
    if text.startswith("@"):
        fallback = text.rsplit(";", 1)[-1].strip() if ";" in text else ""
        return fallback or None
    return text


def provenance_list(tags: Iterable[str]) -> list[str]:
    """Normalize a source list for display or serialization.

    A source tag is a claim about where data came from, so the list is a set of
    acquisition points, not a read log: three reads of three subkeys under one
    enumerated root are one provenance claim, and rendering the same name three
    times told the reader nothing except that a loop ran.

    Commas are rejected because the list is comma-joined for display and a tag
    containing one would silently split into two fictitious sources. Service
    names reach these tags by interpolation, so nothing upstream guarantees the
    character class.
    """
    seen: set[str] = set()
    out: list[str] = []
    for tag in tags:
        clean = str(tag).replace(",", "\u2e32") if "," in str(tag) else str(tag)
        if clean not in seen:
            seen.add(clean)
            out.append(clean)
    return out


def _inventory_admits(record: DeviceRecord) -> bool:
    """Is this device attached to the machine right now?

    The Device Inventory section's whole claim is that everything in it is
    present. That test was an inline `if record.present is False` in the
    orchestration loop, which meant the invariant had no seam a test could grip:
    it could only be exercised by running the entire collector. An invariant
    with no callable is an invariant with no regression guard.

    False only for an explicit negative. None means the source did not say, and
    a silent source is not evidence of absence - excluding on None would drop
    every row from a collector that omits the field.
    """
    return record.present is not False


def _tpm_device_record(tpm: TpmRecord) -> DeviceRecord:
    if tpm.query_failed and tpm.present is None:
        name = "TPM (query failed)"
        status = "Unknown"
    elif tpm.present is False:
        name = "TPM (Not detected)"
        status = "Absent"
    else:
        spec = tpm.spec_version or ""
        name = f"TPM {spec}".strip()
        status = tpm.status_label()
    healthy = tpm_is_healthy(tpm)
    present = bool(tpm.present)
    return DeviceRecord(
        category="TPM",
        name=name,
        instance_id=str(tpm.manufacturer_id) if tpm.manufacturer_id is not None else None,
        status=status,
        manufacturer=tpm.manufacturer_id_text,
        hardware_ids=[],
        virtual_or_software=False,
        problem_code=None,
        extra={
            "present": tpm.present,
            "enabled": tpm.enabled,
            "activated": tpm.activated,
            "owned": tpm.owned,
            "ready": tpm.ready,
            "spec_version": tpm.spec_version,
            "locked_out": tpm.locked_out,
            "lockout_count": tpm.lockout_count,
            "lockout_max": tpm.lockout_max,
            "auto_provisioning": tpm.auto_provisioning,
            "query_failed": tpm.query_failed,
            "sources": list(tpm.sources),
        },
        mitre=indicators_for_tpm(present=present, healthy=healthy if present else False),
        risk_notes=_tpm_risk_notes(tpm),
    )


def _tpm_risk_notes(tpm: TpmRecord) -> list[str]:
    if tpm.query_failed and tpm.present is None:
        return [
            "TPM state could not be queried. Treat hardware-root-of-trust "
            "controls as unverified on this host."
        ]
    if tpm.present is False:
        return [
            "No TPM detected. This host lacks a hardware root of trust for "
            "Measured Boot, BitLocker key protection, and Windows Hello key "
            "isolation. On an infected system, credential and boot-integrity "
            "defenses that assume TPM-backed attestation are unavailable."
        ]
    notes = [
        "TPM is present. Operators who persist here must contend with (or "
        "subvert) Measured Boot PCRs, BitLocker protectors, and Hello/NGC "
        "keys bound to this module — T1553 / T1542.001 / T1556."
    ]
    if tpm.enabled is False or tpm.ready is False or tpm.activated is False:
        notes.append(
            "TPM is not fully enabled/activated/ready, so those bindings may "
            "not actually be in force despite the chip existing."
        )
    if tpm.locked_out:
        notes.append(
            f"TPM reports lockout (count={tpm.lockout_count}, max={tpm.lockout_max}). "
            "Crypto services that depend on TPM auth may be temporarily unavailable (T1600 availability)."
        )
    if spec_is_1_2_only(tpm.spec_version):
        notes.append(
            "Specification version appears to be TPM 1.2 only. Algorithm agility "
            "and modern Windows Hello bindings are weaker than TPM 2.0."
        )
    if tpm.lockout_max is not None:
        notes.append(
            f"Anti-hammering window observed: lockout_count={tpm.lockout_count} "
            f"lockout_max={tpm.lockout_max}."
        )
    return notes


def _append_finding(bucket: list[Finding], finding: Finding) -> None:
    key = (finding.id, finding.related_instance_id)
    if any((f.id, f.related_instance_id) == key for f in bucket):
        return
    bucket.append(finding)


def _findings_tpm(findings: list[Finding], tpm: TpmRecord) -> None:
    """TPM state: presence, readiness, lockout and owner authorization."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(tpm, "skipped", False):
        return
    tpm_abs = indicators_for_tpm(present=False, healthy=False)
    tpm_present_inds = indicators_for_tpm(present=True, healthy=tpm_is_healthy(tpm))
    if tpm.query_failed and tpm.present is None:
        _append_finding(
            findings,
            Finding(
                id="FIND-TPM-QUERY-FAILED",
                severity="low",
                title="TPM query failed",
                detail=(
                    "The TPM could not be queried. Hardware root-of-trust state is "
                    f"unknown. {tpm.query_error or ''}"
                ).strip(),
                category="TPM",
                mitre=tpm_abs,
            ),
        )
    elif tpm.present is False:
        _append_finding(
            findings,
            Finding(
                id="FIND-TPM-ABSENT",
                severity="medium",
                title="No TPM detected",
                detail=(
                    "No TPM detected. This host lacks a hardware root of trust for "
                    "Measured Boot, BitLocker key protection, and Windows Hello key "
                    "isolation. On an infected system, credential and boot-integrity "
                    "defenses that assume TPM-backed attestation are unavailable."
                ),
                category="TPM",
                mitre=tpm_abs,
            ),
        )
    else:
        if tpm.enabled is False:
            _append_finding(
                findings,
                Finding(
                    id="FIND-TPM-DISABLED",
                    severity="high",
                    title="TPM present but disabled",
                    detail=(
                        "A TPM is present but reports disabled. BitLocker protectors, "
                        "Hello keys, and Measured Boot bindings that depend on an "
                        "enabled TPM may not be active."
                    ),
                    category="TPM",
                    mitre=indicators_for_tpm(present=True, healthy=False),
                ),
            )
        if tpm.ready is False or tpm.activated is False:
            _append_finding(
                findings,
                Finding(
                    id="FIND-TPM-NOT-READY",
                    severity="medium",
                    title="TPM not ready or not activated",
                    detail=(
                        f"TPM ready={tpm.ready} activated={tpm.activated} owned={tpm.owned}. "
                        "Windows may not be using the module as a live root of trust."
                    ),
                    category="TPM",
                    mitre=indicators_for_tpm(present=True, healthy=False),
                ),
            )
        if tpm.owner_auth_stored:
            _append_finding(
                findings,
                Finding(
                    id="FIND-TPM-OWNER-AUTH-STORED",
                    severity="medium",
                    title="TPM owner authorization stored locally",
                    detail=(
                        f"OwnerAuthFull is present under {TPM_OWNER_AUTH_KEY}. Windows is "
                        "retaining the TPM owner authorization on disk, so anything able to "
                        "read that key inherits owner-level control of the TPM without the "
                        "operator's involvement."
                        + (
                            f" Policy OSManagedAuthLevel is {tpm.os_managed_auth_label}."
                            if tpm.os_managed_auth_label
                            else ""
                        )
                        + " The value itself is credential material and is never read or "
                        "reported by this tool."
                    ),
                    category="TPM",
                    mitre=[
                        mitre(
                            "T1552",
                            "Unsecured Credentials",
                            "Credential Access",
                            relevance="direct",
                            rationale=(
                                "Owner authorization retained in the registry is an at-rest "
                                "credential for the platform root of trust."
                            ),
                        )
                    ],
                ),
            )
        elif tpm.owner_auth_stored is None and tpm.owner_auth_status:
            _append_finding(
                findings,
                Finding(
                    id="FIND-TPM-OWNER-AUTH-UNKNOWN",
                    severity="info",
                    title="TPM owner authorization state not determined",
                    detail=(
                        "Could not establish whether owner authorization is stored locally: "
                        f"{tpm.owner_auth_status}. Absence of a finding here is not evidence "
                        "of absence."
                    ),
                    category="TPM",
                ),
            )

        if tpm.locked_out:
            _append_finding(
                findings,
                Finding(
                    id="FIND-TPM-LOCKOUT",
                    severity="medium",
                    title="TPM lockout asserted",
                    detail=(
                        f"Get-Tpm reports LockedOut=True (count={tpm.lockout_count}, "
                        f"max={tpm.lockout_max}). TPM-auth-gated services may fail."
                    ),
                    category="TPM",
                    mitre=[
                        mitre(
                            "T1600",
                            "Weaken Encryption",
                            "Defense Evasion",
                            relevance="absence_risk",
                            rationale="Lockout indicates auth-value pressure or a prior failed unseal/auth burst.",
                        )
                    ],
                ),
            )
        if spec_is_1_2_only(tpm.spec_version):
            _append_finding(
                findings,
                Finding(
                    id="FIND-TPM-1.2",
                    severity="low",
                    title="TPM 1.2 only",
                    detail=(
                        f"SpecVersion={tpm.spec_version}. TPM 1.2 lacks the algorithm "
                        "set and session model of 2.0; treat modern Hello bindings as weaker (T1600 hypothetical)."
                    ),
                    category="TPM",
                    mitre=[
                        mitre(
                            "T1600",
                            "Weaken Encryption",
                            "Defense Evasion",
                            relevance="hypothetical_abuse",
                            rationale="Older TPM 1.2 algorithm constraints versus TPM 2.0.",
                        )
                    ],
                ),
            )
        if tpm_is_healthy(tpm) and not spec_is_1_2_only(tpm.spec_version):
            _append_finding(
                findings,
                Finding(
                    id="FIND-TPM-HEALTHY",
                    severity="info",
                    title="TPM present, enabled, and ready",
                    detail=(
                        f"Hardware root of trust observed ({tpm.spec_version or 'spec unknown'}, "
                        f"manufacturer={tpm.manufacturer_id_text or tpm.manufacturer_id}). "
                        "Adversaries on this host must bypass TPM-backed controls rather than skip them."
                    ),
                    category="TPM",
                    mitre=tpm_present_inds,
                ),
            )



def _findings_device_categories(findings: list[Finding], devices: list[DeviceRecord]) -> None:
    """Class-level summaries: biometric, smart-card reader and IR imager presence."""
    biometric = [d for d in devices if d.category == "Biometric"]
    readers = [d for d in devices if d.category == "SmartCardReader"]
    infrared = [d for d in devices if d.category == "Infrared"]
    if biometric:
        _append_finding(
            findings,
            Finding(
                id="FIND-BIOMETRIC-PRESENT",
                severity="low",
                title="Biometric sensor(s) present",
                detail=(
                    f"{len(biometric)} biometric device(s) enumerated. On a compromised "
                    "host this is an MFA-interception and WinBio-tamper surface (T1111 / T1556.006)."
                ),
                category="Biometric",
                related_instance_id=biometric[0].instance_id,
                mitre=indicators_for_biometric(biometric[0].name, hello_face=bool(biometric[0].extra.get("hello_face"))),
            ),
        )
    if readers:
        physical_usb = [
            d
            for d in readers
            if not d.virtual_or_software and str(d.extra.get("enumerator") or "").upper() == "USB"
        ]
        inbox_only = all(
            d.virtual_or_software or "microsoft" in (d.manufacturer or "").lower() or "microsoft" in d.name.lower()
            for d in readers
        )
        severity = "medium" if physical_usb else ("low" if inbox_only else "low")
        _append_finding(
            findings,
            Finding(
                id="FIND-SMARTCARD-READER-PRESENT",
                severity=severity,
                title="Smart-card reader(s) present",
                detail=(
                    f"{len(readers)} reader(s) enumerated "
                    f"({len(physical_usb)} physical USB). Classic T1111 proxy + PIN capture surface."
                ),
                category="SmartCardReader",
                related_instance_id=readers[0].instance_id,
                mitre=indicators_for_smartcard(virtual=readers[0].virtual_or_software),
            ),
        )
    imagers = [d for d in infrared if d.extra.get("imaging") or d.extra.get("hello_face")]
    if imagers:
        _append_finding(
            findings,
            Finding(
                id="FIND-IR-IMAGER-PRESENT",
                severity="medium" if any(d.extra.get("hello_face") for d in imagers) else "low",
                title="IR / Hello Face imaging device present",
                detail=(
                    f"{len(imagers)} IR imaging device(s) enumerated. T1125 collection "
                    "and Hello Face presentation-replay (T1111 / T1556.006) are in scope "
                    "on a compromised host."
                ),
                category="Infrared",
                related_instance_id=imagers[0].instance_id,
                mitre=indicators_for_infrared(imaging=True, hello_face=True),
            ),
        )



def _findings_device_records(findings: list[Finding], devices: list[DeviceRecord]) -> None:
    """Per-device findings from the inventory."""
    for dev in devices:
        if dev.category == "TPM":
            continue
        status_ok = (dev.status or "").upper() in {"OK", "UNKNOWN", ""}
        problem = dev.problem_code not in (None, 0)
        if problem or not status_ok:
            _append_finding(
                findings,
                Finding(
                    id="FIND-DEVICE-ERROR",
                    severity="low",
                    title=f"Device problem: {dev.name}",
                    detail=(
                        f"Status={dev.status} problem_code={dev.problem_code}. "
                        "A failed identity peripheral can force fallback auth or hide a replaced device."
                    ),
                    category=dev.category,
                    related_instance_id=dev.instance_id,
                    mitre=[
                        mitre(
                            "T1200",
                            "Hardware Additions",
                            "Initial Access",
                            relevance="hypothetical_abuse",
                            rationale="Error state can coincide with device replacement or driver tampering.",
                        )
                    ],
                ),
            )
        if dev.virtual_or_software and dev.category in {"Biometric", "SmartCardReader", "Infrared"}:
            _append_finding(
                findings,
                Finding(
                    id="FIND-VIRTUAL-REDIRECTED-DEVICE",
                    severity="info",
                    title=f"Virtual or redirected device: {dev.name}",
                    detail=(
                        "Software, ROOT/SWD/UMB, or Remote Desktop redirected identity "
                        "device. Useful for T1497 environment interpretation and for "
                        "tracking RDP-redirected readers/cameras."
                    ),
                    category=dev.category,
                    related_instance_id=dev.instance_id,
                    mitre=[
                        mitre(
                            "T1497",
                            "Virtualization/Sandbox Evasion",
                            "Defense Evasion",
                            relevance="enabling",
                            rationale="Virtual/redirected peripherals change how the host should be baselined.",
                        )
                    ],
                ),
            )
        enumerator = str(dev.extra.get("enumerator") or "")
        identity_class = dev.category in {"Biometric", "SmartCardReader", "Infrared"}
        if identity_class and enumerator.upper() == "USB" and not dev.virtual_or_software:
            mfg_unknown = is_unknown_manufacturer(dev.manufacturer) or not dev.hardware_ids
            # Microsoft inbox USB readers still get a lower-weight USB note via T1200 on the device
            if mfg_unknown or (
                dev.manufacturer
                and "microsoft" not in dev.manufacturer.lower()
                and enumerator.upper() == "USB"
            ):
                if mfg_unknown:
                    _append_finding(
                        findings,
                        Finding(
                            id="FIND-UNEXPECTED-USB-IDENTITY-PERIPHERAL",
                            severity="medium",
                            title=f"Unexpected USB identity peripheral: {dev.name}",
                            detail=(
                                f"USB {dev.category} with manufacturer={dev.manufacturer!r} "
                                f"and hardware_ids={dev.hardware_ids or []}. On a hypothetical "
                                "infected host this is a T1200 review item — unexpected reader, "
                                "IR dongle, or swapped dongle versus an onboard ACPI device."
                            ),
                            category=dev.category,
                            related_instance_id=dev.instance_id,
                            mitre=indicators_for_usb_addition(enumerator="USB", manufacturer=dev.manufacturer),
                        ),
                    )



def _findings_bitlocker(findings: list[Finding], bitlocker: BitLockerRecord | None, tpm: TpmRecord) -> None:
    """Volume protection, protector composition and its dependence on the TPM."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(bitlocker, "skipped", False):
        return
    if bitlocker is not None:
        tpm_present = bool(tpm.present)
        if bitlocker.query_failed:
            _append_finding(
                findings,
                Finding(
                    id="FIND-BITLOCKER-QUERY-FAILED",
                    severity="low",
                    title="BitLocker query failed",
                    detail=(
                        "BitLocker state could not be read after the TPM check. "
                        f"{bitlocker.query_error or ''} "
                        "Volume encryption is unverified."
                    ).strip(),
                    category="BitLocker",
                    mitre=indicators_for_bitlocker(
                        protected=False, uses_tpm_protector=False, tpm_present=tpm_present
                    ),
                ),
            )
        elif not bitlocker.volumes:
            _append_finding(
                findings,
                Finding(
                    id="FIND-BITLOCKER-NO-VOLUMES",
                    severity="low",
                    title="No BitLocker volumes returned",
                    detail="The BitLocker collector returned no encryptable volumes.",
                    category="BitLocker",
                    mitre=indicators_for_bitlocker(
                        protected=False, uses_tpm_protector=False, tpm_present=tpm_present
                    ),
                ),
            )
        elif not bitlocker.any_protected:
            _append_finding(
                findings,
                Finding(
                    id="FIND-BITLOCKER-DISABLED",
                    severity="high" if tpm_present else "medium",
                    title="BitLocker protection is off",
                    detail=(
                        f"{len(bitlocker.volumes)} encryptable volume(s) enumerated and none "
                        "report ProtectionStatus=On. After a TPM check this means data-at-rest "
                        "encryption is not defending the disk on a hypothetical infected host."
                    ),
                    category="BitLocker",
                    mitre=indicators_for_bitlocker(
                        protected=False, uses_tpm_protector=False, tpm_present=tpm_present
                    ),
                ),
            )
        else:
            unprotected = [v.mount_point for v in bitlocker.volumes if not v.is_protected]
            if unprotected:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-BITLOCKER-PARTIAL",
                        severity="medium",
                        title="BitLocker only protects some volumes",
                        detail=(
                            "Protected volumes exist, but these mount points are off: "
                            + ", ".join(unprotected)
                        ),
                        category="BitLocker",
                        mitre=indicators_for_bitlocker(
                            protected=True,
                            uses_tpm_protector=any(v.uses_tpm_protector for v in bitlocker.volumes),
                            tpm_present=tpm_present,
                        ),
                    ),
                )
            system = bitlocker.system_volume
            uses_tpm = any(v.uses_tpm_protector for v in bitlocker.volumes if v.is_protected)
            if bitlocker.any_protected and tpm_present and not uses_tpm:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-BITLOCKER-NO-TPM-PROTECTOR",
                        severity="medium",
                        title="BitLocker on, but no TPM key protector",
                        detail=(
                            "Protection is enabled yet no TPM / TPM+PIN protector type was "
                            "listed. Encryption may depend on password, passphrase, or external "
                            "key material that is easier to steal post-compromise. Recovery "
                            "passwords themselves are not collected."
                        ),
                        category="BitLocker",
                        related_instance_id=system.mount_point if system else None,
                        mitre=indicators_for_bitlocker(
                            protected=True, uses_tpm_protector=False, tpm_present=True
                        ),
                    ),
                )
            if bitlocker.any_protected and not tpm_present:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-BITLOCKER-ENABLED-NO-TPM",
                        severity="medium",
                        title="BitLocker enabled without a detected TPM",
                        detail=(
                            "Volume encryption is on but no TPM was detected. Protectors are "
                            "likely password, recovery, or external-key based."
                        ),
                        category="BitLocker",
                        mitre=indicators_for_bitlocker(
                            protected=True, uses_tpm_protector=False, tpm_present=False
                        ),
                    ),
                )
            if bitlocker.any_protected:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-BITLOCKER-ENABLED",
                        severity="info",
                        title="BitLocker protection observed",
                        detail=(
                            f"{sum(1 for v in bitlocker.volumes if v.is_protected)}/"
                            f"{len(bitlocker.volumes)} volume(s) protected. "
                            "TPM-bound unseal still depends on firmware measurements and PIN policy."
                        ),
                        category="BitLocker",
                        related_instance_id=system.mount_point if system else None,
                        mitre=indicators_for_bitlocker(
                            protected=True, uses_tpm_protector=uses_tpm, tpm_present=tpm_present
                        ),
                    ),
                )



def _findings_dma(findings: list[Finding], dma: DmaAssessment | None) -> None:
    """Kernel DMA Protection, DmaGuard policy, IOMMU corroboration and Thunderbolt."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(dma, "skipped", False):
        return
    if dma is not None:
        dma_inds = indicators_for_dma(
            kernel_state=dma.kernel_dma_protection,
            policy=dma.dma_guard_policy,
            controller_present=dma.thunderbolt_present,
        )
        if dma.query_failed:
            _append_finding(
                findings,
                Finding(
                    id="FIND-DMA-QUERY-FAILED",
                    severity="low",
                    title="Kernel DMA / Thunderbolt query failed",
                    detail=dma.query_error or "DmaGuard policy and Thunderbolt controllers could not be read.",
                    category="DMA",
                    mitre=dma_inds,
                ),
            )
        if dma.dma_guard_policy == 2:
            _append_finding(
                findings,
                Finding(
                    id="FIND-DMA-POLICY-ALLOW-ALL",
                    severity="high",
                    title="DmaGuard policy allows all external DMA devices",
                    detail=(
                        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection "
                        "DeviceEnumerationPolicy=2 (Allow all). Remapping-incompatible "
                        "Thunderbolt/USB4 devices can start without an unlocked session."
                    ),
                    category="DMA",
                    mitre=dma_inds,
                ),
            )
        elif dma.dma_guard_policy == 0:
            _append_finding(
                findings,
                Finding(
                    id="FIND-DMA-POLICY-BLOCK-ALL",
                    severity="info",
                    title="DmaGuard policy blocks incompatible external DMA devices",
                    detail="DeviceEnumerationPolicy=0 (Block all).",
                    category="DMA",
                    mitre=dma_inds,
                ),
            )
        elif dma.thunderbolt_present and dma.dma_guard_policy in (None, 1):
            _append_finding(
                findings,
                Finding(
                    id="FIND-DMA-THUNDERBOLT-AND-POLICY",
                    severity="medium",
                    title="Thunderbolt/USB4 host present with default or unset DmaGuard policy",
                    detail=(
                        f"{sum(1 for c in dma.controllers if c.present)} live Thunderbolt/USB4 "
                        "controller(s) and DeviceEnumerationPolicy="
                        f"{dma.dma_guard_policy_label}. Default is allow-after-unlock."
                    ),
                    category="DMA",
                    related_instance_id=next((c.instance_id for c in dma.controllers if c.present), None),
                    mitre=dma_inds,
                ),
            )
        elif dma.thunderbolt_present:
            _append_finding(
                findings,
                Finding(
                    id="FIND-THUNDERBOLT-CONTROLLER-PRESENT",
                    severity="medium",
                    title="Thunderbolt or USB4 host controller present",
                    detail=(
                        f"{sum(1 for c in dma.controllers if c.present)} controller(s) enumerated. "
                        "This is the DMA-capable port, not a USB flash-drive history."
                    ),
                    category="DMA",
                    related_instance_id=next((c.instance_id for c in dma.controllers if c.present), None),
                    mitre=dma_inds,
                ),
            )
        historical_ctrl = dma.thunderbolt_historical
        if historical_ctrl and not dma.thunderbolt_present:
            _append_finding(
                findings,
                Finding(
                    id="FIND-THUNDERBOLT-CONTROLLER-HISTORICAL",
                    severity="low",
                    title="Disconnected Thunderbolt/USB4-named PnP node",
                    detail=(
                        f"{len(historical_ctrl)} PnP node(s) still match Thunderbolt/USB4/TBT "
                        f"in name or ID but Present=false. Example: {historical_ctrl[0].name}. "
                        "This is a leftover named node, not a connection journal."
                    ),
                    category="DMA",
                    related_instance_id=historical_ctrl[0].instance_id,
                    mitre=dma_inds,
                ),
            )
        if dma.allowed_buses:
            _append_finding(
                findings,
                Finding(
                    id="FIND-DMA-ALLOWED-BUSES",
                    severity="low",
                    title="DmaSecurity AllowedBuses entries present",
                    detail=(
                        f"{len(dma.allowed_buses)} exception(s) under "
                        r"HKLM\SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowedBuses. "
                        "These are OEM/IT BitLocker auto-encrypt exceptions for internal "
                        "buses (often Intel PEG/root ports), not Thunderbolt attach history."
                    ),
                    category="DMA",
                    mitre=dma_inds,
                ),
            )
        state = (dma.kernel_dma_protection or "").lower()
        if state == "off":
            _append_finding(
                findings,
                Finding(
                    id="FIND-KERNEL-DMA-OFF",
                    severity="high",
                    title="Kernel DMA Protection appears off",
                    detail="Memory Access Protection / Kernel DMA Protection was reported off.",
                    category="DMA",
                    mitre=dma_inds,
                ),
            )
        elif dma.dma_protection_available is False:
            _append_finding(
                findings,
                Finding(
                    id="FIND-KERNEL-DMA-UNAVAILABLE",
                    severity="high",
                    title="Platform does not report DMA protection as available",
                    detail=(
                        "Win32_DeviceGuard.AvailableSecurityProperties does not include "
                        "DMA protection (value 3). Available properties: "
                        + (", ".join(dma.device_guard_properties) or "none reported")
                        + ". Kernel DMA Protection cannot be enforcing on this host, so "
                        "external DMA is constrained only by firmware and DmaGuard policy."
                    ),
                    category="DMA",
                    mitre=dma_inds,
                ),
            )
        elif dma.iommu_present is False:
            _append_finding(
                findings,
                Finding(
                    id="FIND-IOMMU-ABSENT",
                    severity="high",
                    title="No IOMMU present in firmware",
                    detail=(
                        "Neither DMAR (Intel VT-d) nor IVRS (AMD-Vi) was returned by the "
                        "firmware when asked for them directly. Without an "
                        "IOMMU, Kernel DMA Protection cannot be enforcing regardless of what "
                        "policy or Win32_DeviceGuard reports, and an attached DMA-capable "
                        "device has unmediated access to physical memory."
                    ),
                    category="DMA",
                    mitre=dma_inds,
                ),
            )
        elif dma.dma_protection_available is True:
            _append_finding(
                findings,
                Finding(
                    id="FIND-KERNEL-DMA-AVAILABLE",
                    severity="info",
                    title="Platform reports DMA protection as available",
                    detail=(
                        "Win32_DeviceGuard.AvailableSecurityProperties includes DMA "
                        "protection (value 3), so the firmware exposes an IOMMU that "
                        "Windows can use. This is a capability report, not a "
                        "confirmation that Kernel DMA Protection is currently "
                        "enforcing. Available properties: "
                        + (", ".join(dma.device_guard_properties) or "none reported")
                        + "."
                    ),
                    category="DMA",
                    mitre=dma_inds,
                ),
            )

        # Two independent sources. Agreement raises confidence; disagreement is
        # itself the finding, and is never quietly resolved in either direction.
        if dma.dma_protection_available is not None and dma.iommu_present is not None:
            if dma.dma_protection_available != dma.iommu_present:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-DMA-EVIDENCE-CONFLICT",
                        severity="medium",
                        title="DMA protection sources disagree",
                        detail=(
                            "Win32_DeviceGuard reports DMA protection "
                            + ("available" if dma.dma_protection_available else "unavailable")
                            + ", but the firmware tables say an IOMMU is "
                            + (
                                f"present ({dma.iommu_table})"
                                if dma.iommu_present
                                else "absent"
                            )
                            + ". One of the two readings is wrong; treat the DMA posture as "
                            "undetermined until it is resolved on the host."
                        ),
                        category="DMA",
                        mitre=dma_inds,
                    ),
                )
            elif dma.dma_protection_available:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-DMA-PROTECTION-CORROBORATED",
                        severity="info",
                        title="DMA protection confirmed by two sources",
                        detail=(
                            "Win32_DeviceGuard reports DMA protection available and the "
                            f"firmware exposes {dma.iommu_table}, so the platform capability "
                            "is confirmed independently. This remains a capability report, "
                            "not proof that Kernel DMA Protection is enforcing."
                        ),
                        category="DMA",
                        mitre=dma_inds,
                    ),
                )



def _findings_sdr(findings: list[Finding], sdr: SdrAssessment | None) -> None:
    """Allowlisted SDR and TV tuner hardware, present and historical."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(sdr, "skipped", False):
        return
    if sdr is not None:
        sdr_inds = indicators_for_sdr(present=bool(sdr.present_devices))
        if sdr.query_failed:
            _append_finding(
                findings,
                Finding(
                    id="FIND-SDR-QUERY-FAILED",
                    severity="low",
                    title="SDR / DVB-T allowlist query failed",
                    detail=sdr.query_error or "Allowlisted radio peripherals could not be read.",
                    category="SDR",
                    mitre=sdr_inds,
                ),
            )
        if sdr.present_devices:
            sample = summarize_items(sdr.present_devices, lambda d: d.name, 4, separator=", ")
            _append_finding(
                findings,
                Finding(
                    id="FIND-SDR-PRESENT",
                    severity="medium",
                    title="Allowlisted SDR or USB TV-tuner present",
                    detail=(
                        f"{len(sdr.present_devices)} radio peripheral(s) match the SDR/DVB-T "
                        f"allowlist. Examples: {sample}."
                    ),
                    category="SDR",
                    related_instance_id=sdr.present_devices[0].instance_id,
                    mitre=sdr_inds,
                ),
            )
        if sdr.historical_devices:
            sample = summarize_items(sdr.historical_devices, lambda d: d.name, 4, separator=", ")
            _append_finding(
                findings,
                Finding(
                    id="FIND-SDR-HISTORICAL",
                    severity="low",
                    title="Historical SDR or USB TV-tuner Enum remnant",
                    detail=(
                        f"{len(sdr.historical_devices)} allowlisted radio node(s) remain in "
                        f"PnP or Enum\\USB after unplug. Examples: {sample}."
                    ),
                    category="SDR",
                    related_instance_id=sdr.historical_devices[0].instance_id,
                    mitre=indicators_for_sdr(present=False),
                ),
            )



def _findings_historical(findings: list[Finding], historical: HistoricalAssessment | None) -> None:
    """Absent identity devices retained in the Enum tree."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(historical, "skipped", False):
        return
    if historical is not None:
        if historical.query_failed:
            _append_finding(
                findings,
                Finding(
                    id="FIND-HISTORICAL-QUERY-FAILED",
                    severity="low",
                    title="Historical identity-device query failed",
                    detail=historical.query_error or "PnP Enum / WinBio / Calais history could not be read.",
                    category="Historical",
                    mitre=[
                        mitre(
                            "T1082",
                            "System Information Discovery",
                            "Discovery",
                            relevance="enabling",
                            rationale="Inability to read historical identity-peripheral nodes is itself a collection gap.",
                        )
                    ],
                ),
            )
        absent = historical.absent_identity_devices
        if absent:
            sample = summarize_items(absent, lambda r: f"{r.category}:{r.name}", 4, separator=", ")
            _append_finding(
                findings,
                Finding(
                    id="FIND-HISTORICAL-IDENTITY-DEVICE",
                    severity="medium",
                    title="Historical identity peripheral no longer present",
                    detail=(
                        f"{len(absent)} biometric / smart-card / IR node(s) remain in PnP or "
                        f"WinBio/Calais after the hardware left. Examples: {sample}. "
                        "This is the trail of a once-attached fingerprint dongle, reader, or IR unit — "
                        "not a USB flash-drive history."
                    ),
                    category="Historical",
                    related_instance_id=absent[0].instance_id,
                    mitre=[
                        mitre(
                            "T1200",
                            "Hardware Additions",
                            "Initial Access",
                            relevance="enabling",
                            rationale="A disappeared identity peripheral still registered in Enum is a hardware-addition breadcrumb.",
                        ),
                        mitre(
                            "T1111",
                            "Multi-Factor Authentication Interception",
                            "Credential Access",
                            relevance="hypothetical_abuse",
                            rationale="Prior biometric or smart-card hardware may have been used in an MFA ceremony on this host.",
                        ),
                    ],
                ),
            )
        enabled = None
        if historical.policy:
            enabled = historical.policy.get("enabled")
        if enabled in (0, "0"):
            _append_finding(
                findings,
                Finding(
                    id="FIND-BIOMETRIC-POLICY-DISABLED",
                    severity="medium",
                    title="Biometrics policy disables WBF",
                    detail=(
                        r"HKLM\SOFTWARE\Policies\Microsoft\Biometrics Enabled=0. "
                        "Windows Hello / WinBio sensors may be installed but policy-blocked."
                    ),
                    category="Biometric",
                    mitre=[
                        mitre(
                            "T1562",
                            "Impair Defenses",
                            "Defense Evasion",
                            subtechnique_id="T1562.001",
                            relevance="absence_risk",
                            rationale="Policy-off biometrics changes how MFA hardware on the box can be used.",
                        )
                    ],
                ),
            )
        external = [
            r
            for r in historical.records
            if r.source == "wbio-layout" and str((r.extra or {}).get("location") or "").lower() == "external"
        ]
        if external:
            _append_finding(
                findings,
                Finding(
                    id="FIND-EXTERNAL-FINGERPRINT-LAYOUT",
                    severity="low",
                    title="WinBio layout lists an external fingerprint sensor",
                    detail=(
                        f"{len(external)} WbioSrvc sensor-layout key(s) marked location=external. "
                        "Typical of a USB fingerprint dongle that Windows still remembers."
                    ),
                    category="Biometric",
                    related_instance_id=external[0].instance_id,
                    mitre=[
                        mitre(
                            "T1200",
                            "Hardware Additions",
                            "Initial Access",
                            relevance="enabling",
                            rationale="External fingerprint hardware is an identity dongle, not a mass-storage stick.",
                        )
                    ],
                ),
            )



def _findings_inventory(
    findings: list[Finding],
    devices: list[DeviceRecord],
    inventory_ok: bool,
    historical: HistoricalAssessment | None = None,
) -> None:
    """Statement for an empty identity-device inventory, gated on the query having run.

    Also reconciles the two independent presence readings. The inventory scans
    four classes with -PresentOnly; the historical collector scans the same four
    without it and records Present per row. Nothing compared them, so an
    inventory that missed a present device and an inventory that correctly found
    none produced the same output.
    """
    scanned_classes = ", ".join(PNP_CLASSES)
    identity_devices = [
        d for d in devices if d.category in PNP_CLASSES
    ]
    inventory_ids = {
        (d.instance_id or "").upper() for d in identity_devices if d.instance_id
    }
    inventory_names = {(d.name or "").strip().lower() for d in identity_devices}

    seen_elsewhere = list(historical.present_identity_devices) if historical else []
    missed = [
        r for r in seen_elsewhere
        if (r.instance_id or "").upper() not in inventory_ids
        and (r.name or "").strip().lower() not in inventory_names
    ]
    if missed:
        _append_finding(
            findings,
            Finding(
                id="FIND-INVENTORY-PRESENCE-DISAGREEMENT",
                severity="high",
                title="Present device seen by one collector and not the other",
                detail=(
                    summarize_items(
                        missed,
                        lambda r: f"{r.category}: {r.name} ({r.instance_id or 'no instance id'})",
                        6,
                    )
                    + ". The historical PnP scan reports these as present. The device "
                    "inventory scan, which covers the same classes with -PresentOnly, "
                    "did not return them. Both readings cannot be right. Until this is "
                    "resolved on the host, treat the inventory as incomplete rather "
                    "than as an absence, and disregard any finding that rests on the "
                    "identity attack surface being empty."
                ),
                category="Inventory",
            ),
        )

    if inventory_ok and not identity_devices and not missed:
        _append_finding(
            findings,
            Finding(
                id="FIND-NO-IDENTITY-PERIPHERALS",
                severity="info",
                title="No identity peripherals present",
                detail=(
                    f"No present devices in any scanned class ({scanned_classes}), "
                    "and the historical scan of the same classes agrees. The query "
                    "ran, so the absence of related findings reflects the hardware "
                    "rather than a gap in collection. This is a statement about what "
                    "is attached now, not about what was ever attached - residue from "
                    "a device that has since left is reported in the historical "
                    "section and does not contradict this."
                ),
                category="Inventory",
            ),
        )



def _findings_sdr_absent(findings: list[Finding], sdr: SdrAssessment | None) -> None:
    """Statement for an SDR query that ran and matched nothing."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(sdr, "skipped", False):
        return
    if sdr is not None and not sdr.query_failed and not sdr.devices:
        _append_finding(
            findings,
            Finding(
                id="FIND-NO-SDR-DEVICES",
                severity="info",
                title="No allowlisted SDR or TV tuner nodes",
                detail=(
                    "The SDR query completed and matched nothing, present or "
                    "historical. Note this is allowlist-based: hardware outside the "
                    "signature set would not appear here. The driver-substitution "
                    "check is the behaviour-based counterpart."
                ),
                category="SDR",
            ),
        )



def _findings_dma_absent(findings: list[Finding], dma: DmaAssessment | None) -> None:
    """Statement for a DMA controller query that ran and matched nothing."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(dma, "skipped", False):
        return
    if dma is not None and not dma.query_failed and not dma.controllers:
        _append_finding(
            findings,
            Finding(
                id="FIND-NO-DMA-CONTROLLERS",
                severity="info",
                title="No Thunderbolt or USB4 controllers found",
                detail=(
                    "The name filter matched no Thunderbolt, USB4 or TBT node, "
                    "present or historical. No external DMA-capable port surface was "
                    "detected by name on this host."
                ),
                category="DMA",
            ),
        )



def _findings_driver_substitution(findings: list[Finding], drivers: DriverSubstitutionAssessment | None) -> None:
    """Generic USB driver substitution - the generic-driver tell."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(drivers, "skipped", False):
        return
    if drivers is not None:
        if drivers.query_failed:
            _append_finding(
                findings,
                Finding(
                    id="FIND-DRIVER-SUBSTITUTION-QUERY-FAILED",
                    severity="low",
                    title="Generic USB driver check failed",
                    detail=drivers.query_error or "unknown error",
                    category="GenericDriver",
                ),
            )
        else:
            for binding in drivers.sdr_bindings:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-SDR-ON-GENERIC-DRIVER",
                        severity="high",
                        title=f"Known RF peripheral bound to {binding.driver}",
                        detail=(
                            f"{binding.name or 'device'} ({binding.vid_pid or 'unknown VID:PID'}) "
                            f"matches the SDR allowlist as '{binding.allowlist_hit}' and is bound "
                            f"to the generic driver {binding.driver}. The device has been detached "
                            "from its class driver and given raw endpoint access from usermode."
                        ),
                        category="GenericDriver",
                        related_instance_id=binding.instance_id,
                        mitre=indicators_for_driver_substitution(
                            bound=True, strong=True, sdr_match=True
                        ),
                    ),
                )

            strong = [b for b in drivers.strong_bindings if not b.allowlist_hit]
            for binding in strong:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-GENERIC-USB-DRIVER-BINDING",
                        severity="medium",
                        title=f"Device bound to {binding.driver}",
                        detail=(
                            f"{binding.name or 'device'} ({binding.vid_pid or 'unknown VID:PID'}) "
                            f"is bound to {binding.driver}, which has no automatic binding path. "
                            "Something installed it deliberately, with administrator rights, and "
                            "the device now has raw bulk and control endpoint access. This is not "
                            "an allowlisted peripheral, so it is reported rather than named."
                        ),
                        category="GenericDriver",
                        related_instance_id=binding.instance_id,
                        mitre=indicators_for_driver_substitution(
                            bound=True, strong=True, sdr_match=False
                        ),
                    ),
                )

            weak = [b for b in drivers.weak_bindings if not b.allowlist_hit]
            if weak:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-WINUSB-BINDING",
                        severity="low",
                        title=f"{len(weak)} device(s) bound to WinUSB",
                        detail=(
                            "WinUSB is Microsoft's in-box generic driver. Legitimate vendor "
                            "packages ship WinUSB INFs, and a device advertising MS OS (WCID) "
                            "descriptors binds automatically with no user action, so this is "
                            "not on its own evidence of intent. Devices: "
                            + summarize_items(
                                weak, lambda b: f"{b.name or 'device'} ({b.vid_pid or 'unknown'})", 8
                            )
                        ),
                        category="GenericDriver",
                        mitre=indicators_for_driver_substitution(
                            bound=True, strong=False, sdr_match=False
                        ),
                    ),
                )

            residue = [
                s for s in drivers.installed_services
                if s.confidence == "strong" and s.binding_count == 0
            ]
            if residue:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-GENERIC-USB-DRIVER-RESIDUE",
                        severity="medium",
                        title="Generic USB driver installed with nothing bound",
                        detail=(
                            "Installed with no device currently bound: "
                            + ", ".join(f"{s.driver} (start: {s.start_label or '?'})" for s in residue)
                            + ". The driver outlives the hardware it was installed for, so this "
                            "indicates a device was prepared for raw endpoint access on this host "
                            "and has since been removed."
                        ),
                        category="GenericDriver",
                        mitre=indicators_for_driver_substitution(
                            bound=False, strong=True, sdr_match=False
                        ),
                    ),
                )

            strong_infs = drivers.deliberate_inf_hits
            if strong_infs and not drivers.strong_bindings and not residue:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-GENERIC-USB-DRIVER-INF-RESIDUE",
                        severity="low",
                        title="Generic driver INF present with no matching service",
                        detail=(
                            "OEM INF packages reference a generic USB driver although no "
                            "corresponding service is installed: "
                            + summarize_items(
                                strong_infs,
                                lambda h: f"{h.inf_file} ({', '.join(h.markers)})",
                                6, separator=", ",
                            )
                            + ". The INF store keeps a record after uninstall."
                        ),
                        category="GenericDriver",
                        mitre=indicators_for_driver_substitution(
                            bound=False, strong=False, sdr_match=False
                        ),
                    ),
                )

            # A clean host must get a positive statement. The previous test
            # required zero installed services, but WinUSB ships in-box on most
            # Windows hosts, so a clean machine produced no finding at all.
            if drivers.verdict == "none":
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-NO-ZADIG-INDICATORS",
                        severity="info",
                        title="No Zadig indicators",
                        detail=(
                            "No deliberate generic USB driver is installed ("
                            + ", ".join(
                                label
                                for _, label, conf, _ in GENERIC_USB_DRIVERS
                                if conf == "strong"
                            )
                            + "), nothing is bound to one, and the INF store holds no "
                            "libusb or UsbDk package. No device on this host has been "
                            "detached from its class driver for raw endpoint access."
                        ),
                        category="GenericDriver",
                    ),
                )
            elif drivers.verdict == "weak":
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-ZADIG-WEAK-SIGNAL-ONLY",
                        severity="info",
                        title="Only weak generic-driver signals present",
                        detail=(
                            "WinUSB activity was found but no deliberate generic driver "
                            "(libusbK, libusb-win32, UsbDk) is installed and nothing is "
                            "bound to one. WinUSB is Microsoft's in-box driver and WCID "
                            "devices bind to it automatically, so this is consistent with "
                            "ordinary vendor hardware rather than Zadig."
                        ),
                        category="GenericDriver",
                    ),
                )



def _findings_interception(findings: list[Finding], interception: InterceptionAssessment | None) -> None:
    """Class filter drivers and biometric adapters on the identity path."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(interception, "skipped", False):
        return
    if interception is not None and not interception.query_failed:
        icept_inds = [
            mitre(
                "T1056.001",
                "Input Capture: Keylogging",
                "Collection",
                relevance="direct" if interception.input_filters else "absence_risk",
                rationale=(
                    "A filter driver above the Keyboard or HID class receives input before "
                    "the rest of Windows does. This is supported functionality, which is "
                    "what makes it a durable place to sit."
                ),
            ),
            mitre(
                "T1111",
                "Multi-Factor Authentication Interception",
                "Credential Access",
                relevance="enabling",
                rationale=(
                    "The biometric engine adapter is handed the raw sample by design, and a "
                    "filter on the smart-card class sees card traffic."
                ),
            ),
        ]
        for f in interception.input_filters:
            _append_finding(
                findings,
                Finding(
                    id="FIND-IDENTITY-CLASS-FILTER",
                    severity="high",
                    title=f"Additional {f.position[:-7].lower()} filter on the {f.device_class} class",
                    detail=(
                        f"{f.driver} is registered as an {f.position} entry on the "
                        f"{f.device_class} class, so it sees {f.sees or 'that class traffic'} "
                        "as it passes through the driver stack. "
                        + (
                            f"Service present, image {f.image_path or 'unknown'}, start "
                            f"{f.start_label or 'unknown'}. "
                            if f.service_present
                            else "No matching service is installed, which is itself odd. "
                        )
                        + "This is supported Windows functionality and vendors use it "
                        "legitimately - touchpad and security software both do. It is "
                        "reported because it is a position worth knowing the occupant of, not "
                        "because it is inherently malicious."
                    ),
                    category="Interception",
                    mitre=icept_inds,
                ),
            )
        other = [f for f in interception.additional_filters if f not in interception.input_filters]
        if other:
            _append_finding(
                findings,
                Finding(
                    id="FIND-CLASS-FILTER-PRESENT",
                    severity="low",
                    title=f"{len(other)} additional class filter(s) outside the identity classes",
                    detail=summarize_items(
                        other, lambda f: f"{f.driver} ({f.position} on {f.device_class})", 6
                    ),
                    category="Interception",
                    mitre=icept_inds,
                ),
            )
        for a in interception.engine_adapters:
            _append_finding(
                findings,
                Finding(
                    id="FIND-THIRD-PARTY-BIOMETRIC-ENGINE",
                    severity="medium",
                    title="Third-party biometric engine adapter",
                    detail=(
                        f"{a.binary} is registered as the engine adapter for "
                        f"{a.device_name or a.instance_id or 'a biometric device'}. The "
                        "engine adapter is the component handed the raw fingerprint sample "
                        "and asked to turn it into a match decision, so it sees biometric "
                        "data in the clear by design. Vendor sensors normally ship their "
                        "own, so this is expected on vendor hardware - worth knowing which "
                        "DLL holds that position."
                    ),
                    category="Interception",
                    related_instance_id=a.instance_id,
                    mitre=icept_inds,
                ),
            )
        sensor_storage = [a for a in interception.third_party_adapters if a.slot != "engine"]
        if sensor_storage:
            _append_finding(
                findings,
                Finding(
                    id="FIND-THIRD-PARTY-BIOMETRIC-ADAPTER",
                    severity="low",
                    title=f"{len(sensor_storage)} third-party biometric adapter(s)",
                    detail=summarize_items(sensor_storage, lambda a: f"{a.slot}: {a.binary}", 6)
                    + ". Sensor and storage adapters are normal for vendor hardware.",
                    category="Interception",
                    mitre=icept_inds,
                ),
            )
        if not interception.additional_filters and not interception.third_party_adapters:
            _append_finding(
                findings,
                Finding(
                    id="FIND-NO-INTERCEPTION-SURFACE",
                    severity="info",
                    title="No additional filters or adapters on the identity path",
                    detail=(
                        "Classes checked: "
                        + (", ".join(interception.classes_checked) or "none")
                        + ". Every filter registered is one Windows or mainstream input "
                        "hardware ships, and every biometric adapter is the inbox one. "
                        "Nothing extra is sitting between an input device and the software "
                        "that consumes it."
                    ),
                    category="Interception",
                ),
            )



def _findings_boot_integrity(findings: list[Finding], boot_integrity: BootIntegrityAssessment | None) -> None:
    """Test signing, integrity checks, kernel debug, HVCI and the driver blocklist."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(boot_integrity, "skipped", False):
        return
    if boot_integrity is not None and not boot_integrity.query_failed:
        boot_inds = [
            mitre(
                "T1553.006",
                "Subvert Trust Controls: Code Signing Policy Modification",
                "Defense Evasion",
                relevance="direct" if boot_integrity.unsigned_kernel_code_permitted else "absence_risk",
                rationale=(
                    "Test signing and disabled integrity checks are the supported ways to "
                    "make Windows load kernel code that does not verify. They are boot "
                    "settings, so they persist and apply to everything loaded afterwards."
                ),
            )
        ]
        if boot_integrity.test_signing or boot_integrity.bcd_testsigning:
            _append_finding(
                findings,
                Finding(
                    id="FIND-TEST-SIGNING-ENABLED",
                    severity="high",
                    title="Test signing is enabled",
                    detail=(
                        "Windows is accepting kernel drivers signed with test certificates "
                        "rather than production ones. This is the setting a developer uses "
                        "to load their own unsigned driver, and it is equally the setting "
                        "that lets anything else load one. Everything loaded after boot "
                        "inherits it. Kernel state: "
                        f"{'test signing' if boot_integrity.test_signing else 'not reported'}; "
                        f"boot configuration: {boot_integrity.bcd_flags.get('testsigning', 'not read')}."
                    ),
                    category="BootIntegrity",
                    mitre=boot_inds,
                ),
            )
        if boot_integrity.bcd_integrity_disabled:
            _append_finding(
                findings,
                Finding(
                    id="FIND-INTEGRITY-CHECKS-DISABLED",
                    severity="high",
                    title="Kernel driver signature enforcement is disabled",
                    detail=(
                        "nointegritychecks is set in the boot configuration, so Windows is "
                        "not verifying kernel driver signatures at all. Nothing that loads "
                        "afterwards is checked."
                    ),
                    category="BootIntegrity",
                    mitre=boot_inds,
                ),
            )
        if boot_integrity.debug_mode:
            _append_finding(
                findings,
                Finding(
                    id="FIND-KERNEL-DEBUG-ENABLED",
                    severity="medium",
                    title="Kernel debug mode is enabled",
                    detail=(
                        "The kernel reports debug mode. A debugger attached to the kernel "
                        "can read and write anything, including the memory that holds "
                        "signature enforcement decisions."
                    ),
                    category="BootIntegrity",
                    mitre=boot_inds,
                ),
            )
        if boot_integrity.blocklist_enabled is False:
            _append_finding(
                findings,
                Finding(
                    id="FIND-DRIVER-BLOCKLIST-DISABLED",
                    severity="high",
                    title="Vulnerable driver blocklist is switched off",
                    detail=(
                        f"{BLOCKLIST_VALUE} is 0. Microsoft's blocklist is the supported "
                        "mitigation for signed-but-abusable kernel drivers - the "
                        "bring-your-own-driver problem. Turned off, a driver on that list "
                        "loads normally despite being known to grant arbitrary kernel "
                        "access. This is the control that covers the whole class, which is "
                        "why it is worth more than any list this tool could maintain."
                    ),
                    category="BootIntegrity",
                    mitre=boot_inds,
                ),
            )
        elif boot_integrity.blocklist_enabled:
            _append_finding(
                findings,
                Finding(
                    id="FIND-DRIVER-BLOCKLIST-ENABLED",
                    severity="info",
                    title="Vulnerable driver blocklist is enforced",
                    detail=(
                        "Known-abusable signed drivers are blocked from loading. Note the "
                        "blocklist ships with Windows updates, so its usefulness tracks how "
                        "current the machine is."
                    ),
                    category="BootIntegrity",
                ),
            )

        if boot_integrity.hvci_enabled is False:
            _append_finding(
                findings,
                Finding(
                    id="FIND-HVCI-DISABLED",
                    severity="low",
                    title="Memory integrity (HVCI) is not enabled",
                    detail=(
                        "Hypervisor-enforced code integrity is off, so kernel code pages "
                        "are not validated by the hypervisor. Common on consumer hardware "
                        "and on machines running virtualization software."
                    ),
                    category="BootIntegrity",
                    mitre=boot_inds,
                ),
            )
        if boot_integrity.unsigned_kernel_code_permitted is False:
            _append_finding(
                findings,
                Finding(
                    id="FIND-BOOT-INTEGRITY-ENFORCING",
                    severity="info",
                    title="Kernel signature enforcement is on",
                    detail=(
                        "Test signing is off and integrity checks are enabled, so a driver "
                        "that fails signature verification would not load. Kernel flags: "
                        + (", ".join(boot_integrity.ci_flags) or "none reported")
                        + "."
                    ),
                    category="BootIntegrity",
                ),
            )
        # The two sources should agree; if they do not, say so rather than pick.
        if (
            boot_integrity.test_signing is not None
            and boot_integrity.bcd_testsigning is not None
            and boot_integrity.test_signing != boot_integrity.bcd_testsigning
        ):
            _append_finding(
                findings,
                Finding(
                    id="FIND-BOOT-INTEGRITY-CONFLICT",
                    severity="medium",
                    title="Kernel and boot configuration disagree on test signing",
                    detail=(
                        f"The kernel reports test signing "
                        f"{'on' if boot_integrity.test_signing else 'off'} while the boot "
                        f"store says {boot_integrity.bcd_flags.get('testsigning')}. A "
                        "pending reboot explains this innocently; so does tampering with "
                        "one of the two. Resolve it on the host."
                    ),
                    category="BootIntegrity",
                    mitre=boot_inds,
                ),
            )



def _findings_hardware_access(findings: list[Finding], hardware_access: HardwareAccessAssessment | None) -> None:
    """MSR and physical-memory driver capability, attribution and removal residue."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(hardware_access, "skipped", False):
        return
    if hardware_access is not None and not hardware_access.query_failed:
        hw_inds = [
            mitre(
                "T1068",
                "Exploitation for Privilege Escalation",
                "Privilege Escalation",
                relevance="enabling",
                rationale=(
                    "A driver exposing MSR writes or physical memory to usermode is the "
                    "mechanism voltage and frequency fault injection needs. The driver is "
                    "the capability; the attack is live behaviour and is not visible here."
                ),
            ),
            mitre(
                "T1200",
                "Hardware Additions",
                "Initial Access",
                relevance="hypothetical_abuse",
                rationale=(
                    "The same interfaces reach PCI configuration space and port I/O, which "
                    "is direct access to attached hardware."
                ),
            ),
        ]
        # Attribution first. Liveness on its own says almost nothing: a tray
        # hardware monitor keeps an MSR driver loaded all day. What separates
        # that from something worth investigating is where the binary lives.
        unattributed_msr = [
            d for d in hardware_access.unattributed_drivers if d.grants_msr
        ]
        if unattributed_msr:
            _append_finding(
                findings,
                Finding(
                    id="FIND-MSR-DRIVER-UNATTRIBUTED",
                    severity="high",
                    title="MSR-capable driver loaded from a user-writable path",
                    detail=(
                        "; ".join(
                            f"{d.driver} at {d.image_path or 'unknown path'} "
                            f"({d.state}, {d.location_class or 'unknown location'}, "
                            f"signature {d.signature_status or 'unchecked'}, "
                            f"clients {', '.join(d.client_processes) or 'none found'}, "
                            f"installed {d.installed_utc or 'unknown'})"
                            for d in unattributed_msr
                        )
                        + ". Nothing accounts for this driver. It is in a user-writable "
                        "directory, its signature does not verify, or it is loaded with no "
                        "process running from its own directory. A monitoring tool trips "
                        "none of those: it ships a signed driver inside its install "
                        "directory and runs beside it. That is the distinction - not that "
                        "the driver exists, and not that it is loaded."
                    ),
                    category="HardwareAccess",
                    mitre=hw_inds,
                ),
            )

        attributed_running = [
            d for d in hardware_access.msr_running if not d.unattributed
        ]
        if attributed_running:
            _append_finding(
                findings,
                Finding(
                    id="FIND-MSR-DRIVER-LOADED",
                    severity="medium",
                    title="MSR-capable driver is loaded",
                    detail=(
                        "; ".join(
                            f"{d.driver} at {d.image_path or 'unknown path'} "
                            f"({d.location_class or 'unknown location'}"
                            + (f", {d.attributed_to}" if d.attributed_to else "")
                            + f", signature {d.signature_status or 'unchecked'}, "
                            f"client {', '.join(d.client_processes) or 'none found'}, "
                            f"installed {d.installed_utc or 'unknown'})"
                            for d in attributed_running
                        )
                        + ". These drivers are demand-loaded, so a loaded one means "
                        "something has the MSR interface open. This is the normal state "
                        "for a hardware monitor or fan-control utility sitting in the "
                        "tray, the binary is where an installer would put it, and a "
                        "process is running from that same directory - so read this as "
                        "inventory rather than alarm. The client named above is the "
                        "process co-located with the driver, which is how these tools "
                        "ship. It is not proof of which process holds the handle: that "
                        "needs system-wide handle enumeration through "
                        "NtQuerySystemInformation, which can block on synchronous handles "
                        "and is not attempted here."
                    ),
                    category="HardwareAccess",
                    mitre=hw_inds,
                ),
            )

        # Anti-cheat is graded by state rather than emitted as one flat high.
        # A driver that is loaded right now, one that is installed but stopped,
        # and one that is gone but left a device node are three different facts
        # about a host and an operator triages them differently.
        ac_inds = hw_inds + [
            mitre(
                "T1543.003",
                "Create or Modify System Process: Windows Service",
                "Persistence",
                relevance="enabling",
                rationale=(
                    "The driver is installed as a kernel service. That service, not the "
                    "game, is what survives on the host and what an attacker reaches for."
                ),
            ),
            mitre(
                "T1562.001",
                "Impair Defenses: Disable or Modify Tools",
                "Defense Evasion",
                relevance="hypothetical_abuse",
                rationale=(
                    "Arbitrary kernel read/write through a signed driver is the documented "
                    "route by which these have been used to terminate endpoint protection."
                ),
            ),
        ]

        def _ac_row(d: HardwareAccessDriver) -> str:
            note = f"; {d.abuse_note}" if d.abuse_note else ""
            return f"{d.driver} ({d.state}, {d.shipped_by}{note})"

        ac_running = [d for d in hardware_access.anticheat_running if d.grants_kernel_rw]
        if ac_running:
            _append_finding(
                findings,
                Finding(
                    id="FIND-ANTICHEAT-DRIVER-LOADED",
                    severity="high",
                    title="Anti-cheat kernel driver is loaded now",
                    detail=(
                        summarize_items(ac_running, _ac_row, 6)
                        + ". These are demand-loaded, so loaded means something has the "
                        "interface open. The capability on the other side of it is "
                        "arbitrary kernel read/write, reached through a signed driver a "
                        "user installed to play a game - and in the documented cases the "
                        "game did not need to be running, or even installed, for the "
                        "driver to be usable. A game session accounts for this; nothing "
                        "here says otherwise. What it establishes is that ring 0 is "
                        "reachable on this host through a driver Windows will load without "
                        "complaint."
                    ),
                    category="HardwareAccess",
                    mitre=ac_inds,
                ),
            )

        # running is False means Win32_SystemDriver was asked and said stopped.
        # running is None means it was never asked - which is the normal case
        # for the user-mode halves of the stack, since that class only returns
        # kernel drivers. Calling those "not loaded" would be asserting
        # something the collector never established.
        ac_stopped = [
            d for d in hardware_access.anticheat_installed
            if d.grants_kernel_rw and d.running is False and not d.binary_missing
        ]
        if ac_stopped:
            _append_finding(
                findings,
                Finding(
                    id="FIND-ANTICHEAT-DRIVER-INSTALLED",
                    severity="medium",
                    title="Anti-cheat kernel driver is installed but not loaded",
                    detail=(
                        summarize_items(ac_stopped, _ac_row, 6)
                        + ". The service exists and the binary is on disk, so the driver "
                        "can be started without installing anything new and without "
                        "tripping a driver-load event that looks unusual. Anti-cheat "
                        "outlives the game that brought it: uninstalling the title "
                        "routinely leaves these behind. Check the start type - a "
                        "boot-start or auto-start entry for a game that is no longer "
                        "installed is the case worth pulling on."
                    ),
                    category="HardwareAccess",
                    mitre=ac_inds,
                ),
            )

        ac_unknown = [
            d for d in hardware_access.anticheat_installed
            if d.grants_kernel_rw and d.running is None
        ]
        if ac_unknown:
            _append_finding(
                findings,
                Finding(
                    id="FIND-ANTICHEAT-DRIVER-STATE-UNKNOWN",
                    severity="medium",
                    title="Anti-cheat kernel driver installed, runtime state undetermined",
                    detail=(
                        summarize_items(ac_unknown, _ac_row, 6)
                        + ". The service key is present, so the driver is installed. Whether "
                        "it is loaded right now could not be established - the "
                        "Win32_SystemDriver query did not return a row for it, which happens "
                        "when that query failed or was answered without the privilege to see "
                        "the driver. Read this as installed, not as stopped. The section "
                        "header records whether the runtime query ran."
                    ),
                    category="HardwareAccess",
                    mitre=ac_inds,
                ),
            )

        # The user-mode halves survive `sc delete ACE-BASE` because people
        # delete the driver and stop there. On a host where the kernel services
        # are already gone this is the only thing still naming the vendor.
        ac_usermode = [
            d for d in hardware_access.anticheat_present
            if not d.grants_kernel_rw and "acsvc" in d.capabilities
        ]
        if ac_usermode:
            _append_finding(
                findings,
                Finding(
                    id="FIND-ANTICHEAT-USERMODE-COMPONENT",
                    severity="low",
                    title="Anti-cheat user-mode component present",
                    detail=(
                        summarize_items(
                            ac_usermode, lambda d: f"{d.driver} ({d.state}, {d.shipped_by})", 6
                        )
                        + ". These carry no kernel interface of their own and are not a "
                        "finding about capability. They are a finding about completeness: "
                        "the user-mode and kernel halves of an anti-cheat stack are "
                        "installed together and removed separately, so one surviving without "
                        "the other says the removal was partial. If no kernel driver is "
                        "reported alongside these, the driver was deleted and its service "
                        "key is gone - check the device node column above for what it left."
                    ),
                    category="HardwareAccess",
                    mitre=ac_inds,
                ),
            )

        ac_orphaned = [
            d for d in hardware_access.anticheat_installed if d.binary_missing
        ]
        if ac_orphaned:
            _append_finding(
                findings,
                Finding(
                    id="FIND-ANTICHEAT-ORPHANED-KEY",
                    severity="medium",
                    title="Anti-cheat service key survives, driver binary is gone",
                    detail=(
                        summarize_items(
                            ac_orphaned,
                            lambda d: (
                                f"{d.driver} ({d.shipped_by}, ImagePath "
                                f"{d.image_path or 'unknown'}, key written "
                                f"{d.installed_utc or 'at an unknown time'})"
                            ),
                            6,
                        )
                        + ". The service is registered and points at a file that is not there. "
                        "Nothing can start it in this state, so this is not a live interface - "
                        "it is a record of one. Three things produce it: an uninstaller that "
                        "removed the binary and left the registration, a driver that deletes "
                        "itself from disk after loading, which is how NetEase's loader "
                        "behaves, or a BYOVD run that cleaned up the file and not the service. "
                        "The ImagePath is worth reading on its own - it names where the "
                        "binary was, and a path outside Program Files or System32\\drivers "
                        "tells you it was not an installer that put it there."
                    ),
                    category="HardwareAccess",
                    mitre=ac_inds,
                ),
            )

        ac_residue = hardware_access.anticheat_residue
        if ac_residue:
            _append_finding(
                findings,
                Finding(
                    id="FIND-ANTICHEAT-REMOVAL-RESIDUE",
                    severity="medium",
                    title="Anti-cheat kernel driver ran here and was removed",
                    detail=(
                        summarize_items(
                            ac_residue,
                            lambda d: (
                                f"{d.driver} ({d.shipped_by}, device node last written "
                                f"{d.legacy_last_write_utc or 'at an unknown time'})"
                            ),
                            6,
                        )
                        + ". No service by these names is installed now. The device node "
                        "under Enum\\Root\\LEGACY_<name> is what remains, and Windows only "
                        "creates one when the driver actually started - so this is a record "
                        "that the driver ran on this host, roughly when it last did, and "
                        "that something then took the service away. A normal game "
                        "uninstall produces exactly this trace. It is still the only "
                        "evidence that will survive on a host where the game is long gone."
                    ),
                    category="HardwareAccess",
                    mitre=ac_inds,
                ),
            )

        # Anti-cheat residue has its own finding above with its own wording;
        # emitting both puts the same driver in the report twice.
        residue = [d for d in hardware_access.removal_residue if not d.is_anticheat]
        if residue:
            _append_finding(
                findings,
                Finding(
                    id="FIND-HW-DRIVER-REMOVAL-RESIDUE",
                    severity="high",
                    title="Hardware-access driver was installed and removed",
                    detail=(
                        "; ".join(
                            f"{d.driver} (device node last written "
                            f"{d.legacy_last_write_utc or 'at an unknown time'})"
                            for d in residue
                        )
                        + ". Windows creates a device node under Enum\\Root\\LEGACY_<name> "
                        "when a non-PnP kernel driver starts, and leaves it behind when the "
                        "service is deleted. No service by these names is installed now, so "
                        "the node is what remains: a driver granting direct hardware access "
                        "ran on this host and was then taken away. The node timestamp is "
                        "roughly when it last started. Uninstalling a monitoring tool leaves "
                        "exactly this trace, so it is not proof of anything on its own - but "
                        "it is a record that survives the removal."
                    ),
                    category="HardwareAccess",
                    mitre=hw_inds,
                ),
            )

        untrusted = hardware_access.untrusted_signature
        if untrusted:
            _append_finding(
                findings,
                Finding(
                    id="FIND-HW-DRIVER-SIGNATURE-UNTRUSTED",
                    severity="high",
                    title="Hardware-access driver signature does not verify",
                    detail=(
                        "; ".join(
                            f"{d.driver} at {d.image_path or 'unknown path'} "
                            f"(signature {d.signature_status}, signer "
                            f"{d.signer or 'none'})"
                            for d in untrusted
                        )
                        + ". Windows will not load an unsigned kernel driver unless test "
                        "signing is enabled or signature enforcement has been bypassed, so "
                        "a loaded driver that fails verification means one of those is "
                        "true. See the boot integrity section: this tool now checks it."
                    ),
                    category="HardwareAccess",
                    mitre=hw_inds,
                ),
            )

        msr = hardware_access.msr_capable
        if msr:
            _append_finding(
                findings,
                Finding(
                    id="FIND-MSR-ACCESS-DRIVER",
                    severity="high",
                    title="Driver exposing MSR access is installed",
                    detail=(
                        "Installed: "
                        + "; ".join(
                            f"{d.driver} ({d.state}, {d.location_class or 'unknown location'}"
                            + (f", {d.attributed_to}" if d.attributed_to else "")
                            + f", installed {d.installed_utc or 'unknown'}, "
                            f"usually shipped by {d.shipped_by})"
                            for d in msr
                        )
                        + ". These expose model-specific register writes to usermode, which "
                        "is the mechanism Plundervolt-class voltage and frequency fault "
                        "injection requires - MSR 0x150 on Intel. Monitoring and overclocking "
                        "tools install these legitimately, so this is capability, not "
                        "compromise. What it means is that the undervolt interface is "
                        "reachable without loading anything new."
                    ),
                    category="HardwareAccess",
                    mitre=hw_inds,
                ),
            )
        physmem_only = [d for d in hardware_access.physmem_capable if not d.grants_msr]
        if physmem_only:
            _append_finding(
                findings,
                Finding(
                    id="FIND-PHYSMEM-ACCESS-DRIVER",
                    severity="medium",
                    title="Driver exposing physical memory is installed",
                    detail=(
                        "Installed: "
                        + "; ".join(f"{d.driver} ({d.state})" for d in physmem_only)
                        + ". Arbitrary physical memory access from usermode, without MSR "
                        "write. Sufficient for kernel tampering, not for the voltage "
                        "mailbox."
                    ),
                    category="HardwareAccess",
                    mitre=hw_inds,
                ),
            )
        # Absence, stated explicitly, because the check ran. This is the whole
        # value of the section on a clean host: not silence, but a negative
        # result with the size of the list that produced it.
        if not hardware_access.anticheat_present:
            _append_finding(
                findings,
                Finding(
                    id="FIND-NO-ANTICHEAT-DRIVERS",
                    severity="info",
                    title="No anti-cheat kernel drivers found",
                    detail=(
                        f"None of the {len(ABUSED_ANTICHEAT_DRIVERS)} tracked anti-cheat "
                        "services is installed and none left a device node behind. The list "
                        "covers drivers with a documented history of abuse against the host "
                        "they were installed on - Tencent ACE and TenProtect, miHoYo, "
                        "NetEase and Wellbia. It is deliberately short and is not a "
                        "vulnerable-driver database: the blocklist check in the boot "
                        "integrity section is the control that covers the general case."
                    ),
                    category="HardwareAccess",
                ),
            )

        if not hardware_access.installed:
            hw_only = len(HW_ACCESS_DRIVERS) - len(ABUSED_ANTICHEAT_DRIVERS)
            _append_finding(
                findings,
                Finding(
                    id="FIND-NO-HARDWARE-ACCESS-DRIVERS",
                    severity="info",
                    title="No low-level hardware access drivers installed",
                    detail=(
                        f"None of the {hw_only} known MSR, physical-memory or port-I/O "
                        "drivers is installed. Voltage and frequency fault injection would "
                        "require loading a driver first, which needs administrator and "
                        "leaves its own trace."
                    ),
                    category="HardwareAccess",
                ),
            )



def _findings_firmware(findings: list[Finding], firmware: FirmwareAssessment | None) -> None:
    """ACPI inventory, WPBT, WSMT assertions, SMBIOS and capsule-updatable components."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(firmware, "skipped", False):
        return
    if firmware is not None and not firmware.query_failed:
        fw_inds = [
            mitre(
                "T1542.001",
                "Pre-OS Boot: System Firmware",
                "Persistence",
                relevance="enabling",
                rationale=(
                    "The firmware runs before Windows and survives reinstallation. What "
                    "it declares to the OS bounds what the OS can enforce afterwards."
                ),
            )
        ]
        if firmware.wpbt_present:
            _append_finding(
                findings,
                Finding(
                    id="FIND-WPBT-PRESENT",
                    severity="medium",
                    title="Firmware supplies an executable that Windows runs at boot (WPBT)",
                    detail=(
                        "The Windows Platform Binary Table is present in firmware. WPBT "
                        "hands Windows an executable from the firmware image, which the "
                        "session manager runs on every boot before anything on disk is "
                        "trusted. Reinstalling Windows does not remove it and it is not "
                        "visible in any normal software inventory. OEMs use it legitimately "
                        "for anti-theft and driver installers; it is also a documented "
                        "persistence mechanism. Presence is not compromise - it is a "
                        "capability that should be known about and rarely is. "
                        + (
                            f"The table declares a {firmware.wpbt_binary_size}-byte binary"
                            if firmware.wpbt_binary_size
                            else "The table contents were not read"
                        )
                        + (
                            f" launched with: {firmware.wpbt_command_line}"
                            if firmware.wpbt_command_line
                            else ""
                        )
                        + ". "
                        + (
                            f"The handed-over binary is on disk at "
                            f"{firmware.wpbt_dropped_path} ({firmware.wpbt_dropped_size} "
                            f"bytes, modified {firmware.wpbt_dropped_mtime_utc}) - that is "
                            "the copy to examine, since the firmware original sits in "
                            "physical memory a driver would be needed to reach."
                            if firmware.wpbt_dropped_path
                            else "No dropped copy was found on disk."
                        )
                    ),
                    category="Firmware",
                    mitre=fw_inds,
                ),
            )
        if firmware.debug_port_declared:
            _append_finding(
                findings,
                Finding(
                    id="FIND-FIRMWARE-DEBUG-PORT",
                    severity="low",
                    title="Firmware declares a debug port",
                    detail=(
                        "A DBG2 or DBGP table is present, so the firmware advertises a "
                        "hardware debug interface to the OS. Normal on engineering samples "
                        "and some server boards; unexpected on a production laptop."
                    ),
                    category="Firmware",
                    mitre=fw_inds,
                ),
            )
        if firmware.smm_mitigations_declared is False:
            _append_finding(
                findings,
                Finding(
                    id="FIND-NO-SMM-MITIGATIONS",
                    severity="low",
                    title="Firmware does not declare SMM security mitigations",
                    detail=(
                        "No WSMT table. The firmware makes no assertion about validating "
                        "SMI communication buffers, and Windows will not enable the "
                        "virtualization-based features that require that assertion. Common "
                        "on older firmware. Note this is about a declaration, not a "
                        "verified property: Windows records what the table claims and never "
                        "tests it."
                    ),
                    category="Firmware",
                    mitre=fw_inds,
                ),
            )
        if firmware.wsmt_flags is not None and set(WSMT_PROTECTION_FLAGS) - {
            bit for bit in WSMT_PROTECTION_FLAGS if firmware.wsmt_flags & bit
        }:
            missing = [
                label
                for bit, label in sorted(WSMT_PROTECTION_FLAGS.items())
                if not (firmware.wsmt_flags & bit)
            ]
            _append_finding(
                findings,
                Finding(
                    id="FIND-SMM-MITIGATIONS-PARTIAL",
                    severity=(
                        "medium"
                        if (firmware.wsmt_flags & 0x1) and not (firmware.wsmt_flags & 0x2)
                        else "low"
                    ),
                    title="Firmware asserts only some SMM mitigations",
                    detail=(
                        f"WSMT flags 0x{firmware.wsmt_flags:02x}. Declared: "
                        + (", ".join(firmware.wsmt_protections) or "none")
                        + ". Not declared: "
                        + ", ".join(missing)
                        + ". These flags cover SMI handlers validating the communication "
                        "buffers they are handed, so a handler cannot be tricked into "
                        "writing into SMRAM. They do not cover SMM callouts - SMM executing "
                        "an address outside SMRAM - which is a separate chipset mitigation "
                        "this table says nothing about. All of it is the firmware's own "
                        "claim; nothing here verifies it."
                        + (
                            " Note specifically that fixed communication buffers are "
                            "asserted without nested pointer protection. Validating the "
                            "outer buffer is the easy half; a structure inside it holding "
                            "another pointer is where the confused-deputy writes into SMRAM "
                            "come from, and this firmware makes no claim about that."
                            if (firmware.wsmt_flags & 0x1) and not (firmware.wsmt_flags & 0x2)
                            else ""
                        )
                    ),
                    category="Firmware",
                    mitre=fw_inds,
                ),
            )

        if firmware.smbios:
            sm = firmware.smbios
            _append_finding(
                findings,
                Finding(
                    id="FIND-SMBIOS-INVENTORY",
                    severity="info",
                    title=f"SMBIOS {sm.version or '?'}: {sm.structure_count} structures",
                    detail=(
                        f"System: {sm.system_manufacturer or '?'} "
                        f"{sm.system_product or '?'}; baseboard "
                        f"{sm.baseboard_manufacturer or '?'} {sm.baseboard_product or '?'}; "
                        f"chassis {sm.chassis_type or '?'}; BIOS {sm.bios_vendor or '?'} "
                        f"{sm.bios_version or '?'} dated {sm.bios_release_date or '?'}, ROM "
                        f"{sm.bios_rom_size_kb or '?'} KB. "
                        "DISCLAIMER: this is what the firmware says about itself, and it is "
                        "the only source for any of it. The registry values under "
                        "HARDWARE\\DESCRIPTION are populated from this same table, so "
                        "agreement between the two proves nothing - they are one source read "
                        "twice. Firmware capable of lying here would lie consistently. Treat "
                        "this as inventory, not as an integrity check; verifying it needs an "
                        "out-of-band flash dump or TPM measurements, neither of which this "
                        "tool does."
                    ),
                    category="Firmware",
                ),
            )

        failed = [r for r in firmware.resources if r.last_attempt_failed]
        if failed:
            _append_finding(
                findings,
                Finding(
                    id="FIND-FIRMWARE-UPDATE-FAILED",
                    severity="medium",
                    title="A firmware component reports a failed update attempt",
                    detail=(
                        "; ".join(
                            f"{r.resource_id} at version {r.version or 'unknown'}, last "
                            f"attempt {r.last_attempt_version or 'unknown'} returned status "
                            f"{r.last_attempt_status}"
                            for r in failed
                        )
                        + ". A capsule update that did not complete can leave a component "
                        "on older firmware than the vendor intended, and the failure itself "
                        "is worth understanding before trusting the version numbers here."
                    ),
                    category="Firmware",
                    mitre=fw_inds,
                ),
            )
        if firmware.resources:
            _append_finding(
                findings,
                Finding(
                    id="FIND-FIRMWARE-RESOURCES",
                    severity="info",
                    title=f"{len(firmware.resources)} capsule-updatable firmware components",
                    detail=(
                        "Each of these is firmware that can be replaced by a signed capsule "
                        "update, independently of the OS: "
                        + summarize_items(
                            firmware.resources, lambda r: f"{r.resource_id} v{r.version or '?'}", 8
                        )
                        + ". This is the inventory of what firmware actually exists on the "
                        "board, which is not shown in any ordinary software inventory."
                    ),
                    category="Firmware",
                ),
            )
        if firmware.acpi_wmi_instances:
            _append_finding(
                findings,
                Finding(
                    id="FIND-ACPI-WMI-INTERFACE",
                    severity="info",
                    title=f"{len(firmware.acpi_wmi_instances)} firmware WMI interface(s) exposed",
                    detail=(
                        "ACPI\\PNP0C14 instances: "
                        + summarize_items(firmware.acpi_wmi_instances, str, 6)
                        + ". These are WMI methods implemented in firmware that the OS can "
                        "call directly. OEM management and configuration interfaces live "
                        "here, and several vendors have shipped ones that allowed more than "
                        "intended. Presence is normal on branded hardware; this reports what "
                        "surface exists."
                    ),
                    category="Firmware",
                ),
            )

        if firmware.tables:
            _append_finding(
                findings,
                Finding(
                    id="FIND-FIRMWARE-INVENTORY",
                    severity="info",
                    title=f"{len(firmware.tables)} ACPI tables declared by firmware",
                    detail=(
                        "Firmware: "
                        + " / ".join(
                            x for x in (
                                firmware.bios_vendor, firmware.bios_version,
                                firmware.bios_release_date,
                            ) if x
                        )
                        + ". Tables: " + ", ".join(firmware.signatures)
                        + f". TPM interface: {firmware.tpm_interface or 'unknown'}; "
                        + f"IOMMU: {firmware.iommu_table or 'none declared'}."
                    ),
                    category="Firmware",
                ),
            )



def _findings_certificates(findings: list[Finding], certificates: CertificatePropagationAssessment | None) -> None:
    """Smart-card certificate propagation."""
    # Excluded by --only/--skip: nothing was attempted here, so this
    # function asserts nothing - not even absence.
    if getattr(certificates, "skipped", False):
        return
    if certificates is not None:
        cert_inds = [
            mitre(
                "T1649",
                "Steal or Forge Authentication Certificates",
                "Credential Access",
                relevance="enabling" if certificates.smartcard_certificates else "absence_risk",
                rationale=(
                    "Certificates propagated from a smart card show that certificate-backed "
                    "authentication is in use on this host. The private key stays on the "
                    "card, so the propagated certificate is not itself credential material - "
                    "it is an identifier for the card that was inserted."
                ),
            )
        ]
        if certificates.query_failed:
            _append_finding(
                findings,
                Finding(
                    id="FIND-SMARTCARD-CERT-QUERY-FAILED",
                    severity="low",
                    title="Certificate propagation query failed",
                    detail=certificates.query_error or "unknown error",
                    category="SmartCardCerts",
                ),
            )
        else:
            for cert in certificates.confirmed:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-SMARTCARD-CERT-PROPAGATED",
                        severity="info",
                        title="Certificate propagated from a smart card",
                        detail=(
                            f"{cert.subject or 'unknown subject'} issued by "
                            f"{cert.issuer or 'unknown issuer'} (thumbprint "
                            f"{cert.thumbprint or '-'}), key provider "
                            f"{cert.provider or 'unknown'}, valid until "
                            f"{cert.not_after_utc or 'unknown'}. This identifies the card that "
                            "was inserted. There is no insertion timestamp: NotBefore is "
                            "issuance, not insertion."
                        ),
                        category="SmartCardCerts",
                        mitre=cert_inds,
                    ),
                )
            probable = [c for c in certificates.certificates if c.origin == "probable"]
            if probable:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-SMARTCARD-LOGON-CERT-PRESENT",
                        severity="info",
                        title=f"{len(probable)} smart-card logon certificate(s), provider unconfirmed",
                        detail=(
                            "Certificates carry the Smart Card Logon EKU but the key provider "
                            "could not be confirmed as a smart-card provider, so a soft "
                            "certificate issued for the same purpose looks identical from "
                            "here: "
                            + summarize_items(
                                probable,
                                lambda c: f"{c.subject or 'unknown'} ({c.thumbprint or '-'})",
                                4,
                            )
                        ),
                        category="SmartCardCerts",
                        mitre=cert_inds,
                    ),
                )
            if certificates.expired_smartcard:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-SMARTCARD-CERT-EXPIRED",
                        severity="low",
                        title="Expired smart-card certificate still in the store",
                        detail=(
                            "Expired but not removed: "
                            + summarize_items(
                                certificates.expired_smartcard,
                                lambda c: f"{c.subject or 'unknown'} expired {c.not_after_utc}",
                                4,
                            )
                            + ". Residue of a card that was used and has since lapsed."
                        ),
                        category="SmartCardCerts",
                        mitre=cert_inds,
                    ),
                )
            if not certificates.smartcard_certificates:
                _append_finding(
                    findings,
                    Finding(
                        id="FIND-NO-SMARTCARD-CERTS",
                        severity="info",
                        title="No smart-card certificates in the personal stores",
                        detail=(
                            "No certificate in CurrentUser\\My or LocalMachine\\My carries a "
                            "smart-card key provider or the Smart Card Logon EKU. Note that "
                            "cleanup on card removal is the documented default, so this is not "
                            "evidence that no card was ever used. CertProp policy: "
                            f"{certificates.cert_prop_status or 'unknown'}; CertPropSvc start: "
                            f"{certificates.service_start_label or 'unknown'}."
                        ),
                        category="SmartCardCerts",
                    ),
                )


def _findings_skipped(findings: list[Finding], domains: list[tuple[str, Any]]) -> None:
    """State plainly which collectors the operator excluded.

    A skipped collector produces no findings at all, which without this would
    be indistinguishable from a clean result. Declaring the omission is the
    same rule the module applies to truncated lists.
    """
    excluded = [label for label, value in domains if getattr(value, "skipped", False)]
    if not excluded:
        return
    _append_finding(
        findings,
        Finding(
            id="FIND-COLLECTORS-SKIPPED",
            severity="info",
            title=f"{len(excluded)} collector(s) excluded from this run",
            detail=(
                "Not collected: "
                + ", ".join(excluded)
                + ". These were excluded by --only or --skip, so nothing in this report "
                "says anything about them. Absence of a finding for these domains is not "
                "evidence of absence."
            ),
            category="Inventory",
        ),
    )


def build_findings(
    devices: list[DeviceRecord],
    tpm: TpmRecord,
    bitlocker: BitLockerRecord | None = None,
    historical: HistoricalAssessment | None = None,
    dma: DmaAssessment | None = None,
    sdr: SdrAssessment | None = None,
    drivers: DriverSubstitutionAssessment | None = None,
    certificates: CertificatePropagationAssessment | None = None,
    firmware: FirmwareAssessment | None = None,
    hardware_access: HardwareAccessAssessment | None = None,
    boot_integrity: BootIntegrityAssessment | None = None,
    interception: InterceptionAssessment | None = None,
    inventory_ok: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    _findings_tpm(findings, tpm)
    _findings_device_categories(findings, devices)
    _findings_device_records(findings, devices)
    _findings_bitlocker(findings, bitlocker, tpm)
    _findings_dma(findings, dma)
    _findings_sdr(findings, sdr)
    _findings_historical(findings, historical)
    _findings_inventory(findings, devices, inventory_ok, historical)
    _findings_sdr_absent(findings, sdr)
    _findings_dma_absent(findings, dma)
    _findings_driver_substitution(findings, drivers)
    _findings_interception(findings, interception)
    _findings_boot_integrity(findings, boot_integrity)
    _findings_hardware_access(findings, hardware_access)
    _findings_firmware(findings, firmware)
    _findings_certificates(findings, certificates)
    _findings_skipped(findings, [
        ("TPM", tpm), ("BitLocker", bitlocker), ("DMA", dma), ("SDR", sdr),
        ("Historical", historical), ("Driver substitution", drivers),
        ("Certificate propagation", certificates), ("Firmware", firmware),
        ("Hardware access", hardware_access), ("Boot integrity", boot_integrity),
        ("Interception", interception),
    ])
    return findings


def build_summary(
    devices: list[DeviceRecord],
    findings: list[Finding],
    tpm: TpmRecord,
    bitlocker: BitLockerRecord | None = None,
    historical: HistoricalAssessment | None = None,
    dma: DmaAssessment | None = None,
    sdr: SdrAssessment | None = None,
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for dev in devices:
        counts[dev.category] = counts.get(dev.category, 0) + 1
    sev: dict[str, int] = {}
    for finding in findings:
        sev[finding.severity] = sev.get(finding.severity, 0) + 1
    histogram: dict[str, int] = {}
    for owner in (*devices, *findings):
        for ind in owner.mitre:
            key = ind.display_id()
            histogram[key] = histogram.get(key, 0) + 1
    return {
        "device_counts": counts,
        "finding_severities": sev,
        "technique_histogram": dict(sorted(histogram.items())),
        "tpm_status": tpm.status_label(),
        "tpm_present": tpm.present,
        "bitlocker_protected": None if bitlocker is None else bitlocker.any_protected,
        "bitlocker_volumes": 0 if bitlocker is None else len(bitlocker.volumes),
        "historical_records": 0 if historical is None else len(historical.records),
        "historical_absent": 0 if historical is None else len(historical.absent_identity_devices),
        "dma_kernel": None if dma is None else dma.kernel_dma_protection,
        "dma_policy": None if dma is None else dma.dma_guard_policy_label,
        "thunderbolt_present": None if dma is None else dma.thunderbolt_present,
        "sdr_present": 0 if sdr is None else len(sdr.present_devices),
        "sdr_historical": 0 if sdr is None else len(sdr.historical_devices),
        "device_total": len(devices),
        # The count the Device inventory section actually displays. device_total
        # includes the synthetic TPM record, which that section filters out.
        "identity_device_total": len([d for d in devices if d.category != "TPM"]),
        "finding_total": len(findings),
    }


# ===========================================================================
# Public API
# ===========================================================================


def assess_sensors(
    *,
    include_related_ir_cameras: bool = True,
    on_error: OnErrorMode = "collect",
    collectors: Sequence[CollectorSpec] | None = None,
    only: Sequence[str] | None = None,
    skip: Sequence[str] | None = None,
) -> AssessmentResult:
    """Inventory sensors / identity peripherals / TPM and map ATT&CK exposure.

    collectors overrides the registered set. Injected collectors run on any
    platform, which is what lets the whole pipeline be exercised without
    Windows; the default set still refuses to pretend off-Windows.
    """
    if on_error not in {"collect", "raise"}:
        raise ValueError("on_error must be 'collect' or 'raise'")

    reset_powershell_warnings()
    # The delivery probe caches its result for the process. A run that fell
    # back to the command line must not silently decide that for the next one.
    global _STDIN_DELIVERY_OK
    _STDIN_DELIVERY_OK = None
    errors: list[str] = []
    used_collectors: list[str] = []
    injected = collectors is not None
    registry = tuple(collectors) if injected else default_collectors(
        include_related_ir_cameras=include_related_ir_cameras
    )
    specs, skipped_specs = select_collectors(registry, only=only, skip=skip)

    if not injected and not _is_windows():
        msg = "Sensor assessment collection requires Windows"
        if on_error == "raise":
            raise CollectionError(msg)
        errors.append(msg)
        outcome = CollectorOutcome(
            values={spec.name: spec.fallback("not collected") for spec in specs},
            failed={spec.name for spec in specs},
        )
    else:
        outcome = run_collectors(
            specs, on_error=on_error, errors=errors, used_collectors=used_collectors
        )

    # A skipped collector did not run, so its absence is not evidence either.
    for spec in skipped_specs:
        value = spec.fallback(NOT_COLLECTED_REASON)
        # Mark it, so downstream can tell "excluded" from "attempted and failed".
        if hasattr(value, "skipped"):
            value.skipped = True
        outcome.values[spec.name] = value
        outcome.failed.add(spec.name)

    values = outcome.values

    def _missing(cls: type) -> Callable[[], Any]:
        return lambda: cls(query_failed=True, query_error="not collected")

    raw_devices: list[dict[str, Any]] = _collector_value(values, "pnp", list, list, errors)
    # "the query ran" is not "the query found something"; the empty-inventory
    # statement depends on that difference.
    inventory_ok = outcome.ok("pnp")
    tpm = _collector_value(values, "tpm", TpmRecord, _missing(TpmRecord), errors)
    bitlocker = _collector_value(
        values, "bitlocker", BitLockerRecord, _missing(BitLockerRecord), errors
    )
    dma = _collector_value(values, "dma", DmaAssessment, _missing(DmaAssessment), errors)
    sdr = _collector_value(values, "sdr", SdrAssessment, _missing(SdrAssessment), errors)
    drivers = _collector_value(
        values, "drivers", DriverSubstitutionAssessment,
        _missing(DriverSubstitutionAssessment), errors,
    )
    historical = _collector_value(
        values, "historical", HistoricalAssessment, _missing(HistoricalAssessment), errors
    )
    certificates = _collector_value(
        values, "certificates", CertificatePropagationAssessment,
        _missing(CertificatePropagationAssessment), errors,
    )
    firmware = _collector_value(
        values, "firmware", FirmwareAssessment, _missing(FirmwareAssessment), errors
    )
    hardware_access = _collector_value(
        values, "hardware-access", HardwareAccessAssessment,
        _missing(HardwareAccessAssessment), errors,
    )
    boot_integrity = _collector_value(
        values, "boot-integrity", BootIntegrityAssessment,
        _missing(BootIntegrityAssessment), errors,
    )
    interception = _collector_value(
        values, "interception", InterceptionAssessment,
        _missing(InterceptionAssessment), errors,
    )

    errors.extend(drain_powershell_warnings())

    devices: list[DeviceRecord] = []
    seen: set[tuple[str, str | None]] = set()
    # _build_device_record returns None for a row outside the identity classes -
    # an ordinary webcam from the related-camera scan, most often. That is
    # correct, but the count was thrown away, so a section that rendered
    # "(none)" could not say whether it had examined nothing or examined
    # fourteen rows and kept none of them.
    pnp_excluded = 0
    pnp_nonpresent = 0
    origin_examined: dict[str, int] = {"identity": 0, "camera": 0}
    origin_excluded: dict[str, int] = {"identity": 0, "camera": 0}
    for raw in raw_devices:
        origin = str(raw.get("_origin") or "identity")
        origin_examined[origin] = origin_examined.get(origin, 0) + 1
        record = _build_device_record(raw)
        if record is None:
            pnp_excluded += 1
            origin_excluded[origin] = origin_excluded.get(origin, 0) + 1
            continue
        # The Device Inventory section states that everything in it is attached
        # now. Enforce that here rather than inheriting it from a PowerShell
        # switch, and count what the enforcement removes - a silent filter is
        # indistinguishable from a source that returned nothing.
        if not _inventory_admits(record):
            pnp_nonpresent += 1
            continue
        key = (record.category, record.instance_id)
        if key in seen:
            continue
        seen.add(key)
        devices.append(record)

    tpm_dev = _tpm_device_record(tpm)
    devices.append(tpm_dev)

    findings = build_findings(
        devices, tpm, bitlocker, historical, dma, sdr, drivers, certificates, firmware,
        hardware_access, boot_integrity, interception, inventory_ok=inventory_ok,
    )
    summary = build_summary(devices, findings, tpm, bitlocker, historical, dma, sdr)

    result = AssessmentResult(
        hostname=socket.gethostname(),
        collected_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        scanner_context={
            "platform": platform.platform(),
            "windows_version": _windows_version(),
            "python": sys.version.split()[0],
            "is_admin": _is_admin(),
            "is_windows": _is_windows(),
            "pid": os.getpid(),
            "collectors": sorted(set(used_collectors)),
            "collectors_registered": [spec.name for spec in registry],
            "source_trust": {
                spec.name: {"trust": spec.trust, "reads": spec.reads} for spec in registry
            },
            "collectors_skipped": [spec.name for spec in skipped_specs],
            "collectors_failed": sorted(outcome.failed),
            "script_delivery": active_script_delivery(),
            "include_related_ir_cameras": include_related_ir_cameras,
            "pnp_rows_examined": len(raw_devices),
            "pnp_rows_excluded": pnp_excluded,
            "pnp_inventory_ok": inventory_ok,
            "pnp_rows_nonpresent": pnp_nonpresent,
            "pnp_rows_by_origin": dict(origin_examined),
            "pnp_excluded_by_origin": dict(origin_excluded),
        },
        devices=devices,
        tpm=tpm,
        bitlocker=bitlocker,
        dma=dma,
        sdr=sdr,
        historical=historical,
        drivers=drivers,
        certificates=certificates,
        firmware=firmware,
        hardware_access=hardware_access,
        boot_integrity=boot_integrity,
        interception=interception,
        findings=findings,
        collection_errors=errors,
        summary=summary,
    )
    return result


# C0/C1 controls (tab excepted), plus the Unicode bidirectional overrides used
# to make a hostile string render as something else entirely.
_UNSAFE_DISPLAY_RE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]"
)
# Tab (\x09) and newline (\x0a) sat in the gaps of the class above and reached
# the terminal intact. Neither carries meaning in a device name and both break
# the layout rather than the escape sequences the class was written for: a tab
# in a table cell shifts every column after it, and a newline injects an
# unindented row that _column_widths never measured, because it sizes on
# .split("\n")[0] and renders the whole value. Folded to a single space, not
# deleted, so a name does not silently lose a word boundary.
_LAYOUT_BREAKING_WS_RE = re.compile("[\t\n\r\v\f\u0085\u2028\u2029]+")


def sanitize_display(text: str) -> str:
    """Strip terminal control and bidi-override characters from a string.

    Device FriendlyName values and registry strings are attacker-influenced and
    are printed straight to an analyst's terminal. Left alone, a crafted name
    can emit CSI sequences that scroll a finding out of view, or use U+202E to
    render a malicious device as a benign one.
    """
    return _UNSAFE_DISPLAY_RE.sub("", _LAYOUT_BREAKING_WS_RE.sub(" ", text))


def _display_width(text: str) -> int:
    """Rendered column count, counting East Asian wide forms as two columns."""
    width = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


_SID_RE = re.compile(r"\bS-1-(?:\d+-){2,}(\d+)\b")
# Certificate subjects and issuers carry UPNs, email addresses and personal
# names. A redacted report is meant to be safe to paste into a public issue.
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_CN_RE = re.compile(r"(?i)\b(CN|E|EMAIL|UPN)=([^,/]+)")


def _hash_token(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:length]


def _redact_instance_id(value: str) -> str:
    """Keep the enumerator and hardware ID, hash the per-unit serial tail."""
    parts = value.split("\\")
    if len(parts) < 3:
        return value
    return "\\".join(parts[:2] + [f"redacted-{_hash_token(parts[-1], 8)}"])


_MIN_REDACTABLE_HOSTNAME = 3


def _redact_text(value: str, hostname: str) -> str:
    # Whole-token match only, and never for a hostname so short that it would
    # collide with ordinary words: a 1-character hostname would otherwise
    # rewrite the letters inside every string in the report.
    if hostname and len(hostname) >= _MIN_REDACTABLE_HOSTNAME:
        pattern = re.compile(rf"\b{re.escape(hostname)}\b", re.IGNORECASE)
        value = pattern.sub(f"host-{_hash_token(hostname)}", value)
    value = _SID_RE.sub(lambda m: f"S-1-…-{m.group(1)}", value)
    value = _EMAIL_RE.sub(lambda m: f"redacted-{_hash_token(m.group(0), 8)}@…", value)
    value = _CN_RE.sub(
        lambda m: f"{m.group(1)}=redacted-{_hash_token(m.group(2).strip(), 8)}", value
    )
    if "\\" in value and value.count("\\") >= 2:
        value = _redact_instance_id(value)
    return value


# Fields redacted by key rather than by pattern: these are hardware identifiers
# that would let a pasted report be tied back to a specific machine.
REDACT_BY_KEY = {
    "hostname", "serial_number", "uuid", "baseboard_serial", "chassis_serial",
    "asset_tag",
}


def _redact_in_place(obj: Any, hostname: str) -> Any:
    """Recursively redact a dataclass tree. Mutates; call on a copy."""
    if isinstance(obj, str):
        return _redact_text(obj, hostname)
    if isinstance(obj, list):
        return [_redact_in_place(v, hostname) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_in_place(v, hostname) for v in obj)
    if isinstance(obj, dict):
        return {
            k: (
                (f"host-{_hash_token(v)}" if k == "hostname" else f"redacted-{_hash_token(v, 10)}")
                if k in REDACT_BY_KEY and isinstance(v, str) and v
                else _redact_in_place(v, hostname)
            )
            for k, v in obj.items()
        }
    if is_dataclass(obj) and not isinstance(obj, type):
        for f in fields(obj):
            current = getattr(obj, f.name)
            if f.name in REDACT_BY_KEY and isinstance(current, str) and current:
                setattr(
                    obj,
                    f.name,
                    f"host-{_hash_token(current)}"
                    if f.name == "hostname"
                    else f"redacted-{_hash_token(current, 10)}",
                )
            else:
                setattr(obj, f.name, _redact_in_place(current, hostname))
        return obj
    return obj


def redact_result(result: "AssessmentResult") -> "AssessmentResult":
    """A redacted deep copy of a whole assessment.

    Applied before rendering rather than after serializing, so every output
    format gets the same treatment. Redacting only the JSON left the format
    people actually paste into issues completely unredacted.
    """
    return _redact_in_place(copy.deepcopy(result), result.hostname)


def redact_payload(payload: Any, hostname: str) -> Any:
    """Strip host-identifying detail from a serialized report.

    Hostname becomes a stable hash, SIDs keep only their RID, and instance IDs
    keep the enumerator and hardware ID while the per-unit serial is hashed.
    Structure and finding IDs are preserved so a redacted report is still
    diffable and still pasteable into a public issue.
    """
    if isinstance(payload, dict):
        out: dict[str, Any] = {}
        for key, value in payload.items():
            # Redacted by key, not by text match. A short host name ("vm")
            # falls below the token-matching threshold, and a serial number or
            # UUID has no pattern to match on at all - but the field name says
            # exactly what it holds.
            if key in REDACT_BY_KEY and isinstance(value, str) and value:
                out[key] = (
                    f"host-{_hash_token(value)}"
                    if key == "hostname"
                    else f"redacted-{_hash_token(value, 10)}"
                )
            else:
                out[key] = redact_payload(value, hostname)
        return out
    if isinstance(payload, list):
        return [redact_payload(v, hostname) for v in payload]
    if isinstance(payload, str):
        return _redact_text(payload, hostname)
    return payload


def _plain(text: Any) -> str:
    if text is None or text == "":
        return "-"
    if isinstance(text, bool):
        return "yes" if text else "no"
    return sanitize_display(str(text).replace("\r", "")).strip()


def _wrap_text(text: Any, width: int) -> list[str]:
    """Word-wrap without ellipsis. Long tokens are split only if they exceed width."""
    value = _plain(text).replace("\n", " ")
    if width <= 0:
        return [value]
    words = value.split(" ")
    lines: list[str] = []
    current = ""
    for word in words:
        pieces = [word]
        if _display_width(word) > width:
            pieces = [word[i : i + width] for i in range(0, len(word), width)]
        for piece in pieces:
            if not current:
                current = piece
            elif _display_width(current) + 1 + _display_width(piece) <= width:
                current = f"{current} {piece}"
            else:
                lines.append(current)
                current = piece
    if current:
        lines.append(current)
    return lines or ["-"]


def _short_ts(value: Any) -> str:
    """Trim a UTC ISO timestamp to minute resolution for dense tables."""
    text = str(value or "").strip()
    if len(text) == 20 and text.endswith("Z") and text[10] == "T":
        return text[:16] + "Z"
    return text or "-"


def _pad(text: str, width: int) -> str:
    """Left-align to a rendered width without substituting a placeholder.

    _cell turns an empty value into "-", which is correct for a data cell and
    wrong for the blank continuation rows of a wrapped table cell.
    """
    trimmed = sanitize_display(str(text))
    pad = width - _display_width(trimmed)
    return trimmed + (" " * pad) if pad > 0 else trimmed


def _cell(text: Any, width: int, align: str = "left") -> str:
    value = _plain(text)
    pad = width - _display_width(value)
    if pad <= 0:
        return value
    if align == "right":
        return (" " * pad) + value
    if align == "center":
        left = pad // 2
        return (" " * left) + value + (" " * (pad - left))
    return value + (" " * pad)


REPORT_WIDTH = 120
SECTION_RULE_CHAR = ":"


# Ordered most to least actionable, so a grouped list leads with what matters.
RELEVANCE_ORDER = ("direct", "absence_risk", "enabling", "hypothetical_abuse")


def format_mitre(indicators: list[MitreIndicator]) -> str:
    """Group technique IDs by relevance so the qualifier is written once.

    "T1553 (absence_risk), T1542.001 (absence_risk), T1556 (absence_risk)"
    becomes "absence_risk: T1553, T1542.001, T1556" — same information, half
    the width, and the shared qualifier is obvious at a glance.
    """
    if not indicators:
        return "-"
    groups: dict[str, list[str]] = {}
    for ind in indicators:
        ids = groups.setdefault(ind.relevance, [])
        if ind.display_id() not in ids:
            ids.append(ind.display_id())
    ordered = sorted(
        groups,
        key=lambda r: (
            RELEVANCE_ORDER.index(r) if r in RELEVANCE_ORDER else len(RELEVANCE_ORDER),
            r,
        ),
    )
    return "; ".join(f"{rel}: {', '.join(groups[rel])}" for rel in ordered)


def format_mitre_ids(indicators: list[MitreIndicator], limit: int = 2) -> str:
    """Deduplicated technique IDs for a table cell, capped with an overflow count."""
    seen: list[str] = []
    for ind in indicators:
        if ind.display_id() not in seen:
            seen.append(ind.display_id())
    if not seen:
        return "-"
    if len(seen) <= limit:
        return ", ".join(seen)
    return ", ".join(seen[:limit]) + f" +{len(seen) - limit}"


def _rule(width: int = REPORT_WIDTH, char: str = "-") -> str:
    return char * width


def _section(title: str, width: int = REPORT_WIDTH) -> list[str]:
    return ["", title.upper(), _rule(width, SECTION_RULE_CHAR)]


def _count_phrase(n: int, one: str, many: str) -> str:
    """A count and its noun, agreeing in number.

    "2 orphaned key" disagreed with itself in the hardware-access block.
    """
    return f"{n} {one if n == 1 else many}"


def _kv_block(pairs: list[tuple[str, Any]], key_width: int = 18, value_width: int = 98) -> list[str]:
    """Render key/value rows with one value column for the whole block.

    key_width was applied as a fixed 18 and _cell does not truncate, so a label
    longer than 18 pushed its own value right while its neighbours stayed at
    column 22. Round 5 added "Signature unverifiable" (22) and "Removal residue
    (device node)" (29) to the hardware-access block and the values landed in
    three different columns in one block - visible in Diagnostic Data 3.
    key_width is now a floor, not a fixed width: short blocks keep the 18-char
    column so they do not jump around between hosts, and a block containing a
    long label widens uniformly.
    """
    if pairs:
        key_width = max(key_width, max(len(_plain(k)) for k, _ in pairs))
        # The value column has to give back what the key column took, or a
        # widened block simply runs past the report edge - 135 chars against a
        # 120 width, which is how the anti-cheat row came to wrap mid-phrase.
        value_width = min(value_width, REPORT_WIDTH - key_width - 4)
    lines = []
    for key, value in pairs:
        wrapped = _wrap_text(value, value_width)
        lines.append(f"  {_cell(key, key_width)}  {wrapped[0]}")
        for extra in wrapped[1:]:
            lines.append(f"  {'':<{key_width}}  {extra}")
    return lines


def _column_widths(headers: list[str], rows: list[list[Any]], mins: list[int], caps: list[int]) -> list[int]:
    mins = [min(lo, hi) for lo, hi in zip(mins, caps, strict=True)]
    widths: list[int] = []
    for index, header in enumerate(headers):
        longest = len(header)
        for row in rows:
            if index < len(row):
                longest = max(longest, len(_plain(row[index]).split("\n")[0]))
        lo = mins[index] if index < len(mins) else 4
        hi = caps[index] if index < len(caps) else 48
        widths.append(max(lo, min(longest, hi)))
    return widths


def _table(headers: list[str], rows: list[list[Any]], widths: list[int] | None = None,
           mins: list[int] | None = None, caps: list[int] | None = None) -> list[str]:
    if widths is None:
        widths = _column_widths(headers, rows, mins or [4] * len(headers), caps or [40] * len(headers))
    header_line = "  " + "  ".join(_pad(h, w) for h, w in zip(headers, widths, strict=True))
    sep = "  " + "  ".join(_rule(w, "-") for w in widths)
    lines = [header_line, sep]
    if not rows:
        lines.append("  (none)")
        return lines
    for row in rows:
        wrapped_cols = [_wrap_text(row[i] if i < len(row) else "", widths[i]) for i in range(len(widths))]
        height = max(len(col) for col in wrapped_cols)
        for line_no in range(height):
            parts = []
            for col_lines, width in zip(wrapped_cols, widths, strict=True):
                piece = col_lines[line_no] if line_no < len(col_lines) else ""
                parts.append(_pad(piece, width))
            lines.append("  " + "  ".join(parts))
    return lines


def _render_host(lines: list[str], width: int, ctx: dict[str, Any], result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the Host section."""
    lines.extend(_section("Host", width))
    lines.extend(
        _kv_block(
            [
                ("Hostname", result.hostname),
                ("Collected", result.collected_at_utc),
                ("Windows", ctx.get("windows_version")),
                ("Admin", ctx.get("is_admin")),
                ("Python", ctx.get("python")),
                # Keyed "Collectors" in both modes - _sources_row keys its
                # output "Sources", which is right for a section row and wrong
                # for the global one.
                ("Collectors", _sources_row(ctx.get("collectors") or [], collectors_detail)[1]
                 if collectors_detail or not (ctx.get("collectors") or [])
                 else f"{len(provenance_list(ctx.get('collectors') or []))} "
                      "(run with --collectors for the full list)"),
            ]
        )
    )



def _render_tpm(lines: list[str], width: int, result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the TPM section."""
    tpm_dev = next((d for d in result.devices if d.category == "TPM"), None)
    tpm_find = next(
        (f for f in result.findings if f.category == "TPM" and not f.id.endswith("HEALTHY")),
        None,
    )
    lines.extend(_section("TPM", width))
    lines.extend(
        _kv_block(
            [
                ("Name", tpm_dev.name if tpm_dev else "-"),
                ("Present", result.tpm.present),
                ("Enabled", result.tpm.enabled),
                ("Ready", result.tpm.ready),
                ("Activated", result.tpm.activated),
                ("Owned", result.tpm.owned),
                ("Status", tpm_dev.status if tpm_dev else result.tpm.status_label()),
                ("Spec", result.tpm.spec_version),
                ("Manufacturer", result.tpm.manufacturer_id_text or result.tpm.manufacturer_id),
                ("Lockout", result.tpm.locked_out),
                ("Lockout count", result.tpm.lockout_count),
                ("Owner auth", result.tpm.owner_auth_status or "-"),
                ("Auth policy", result.tpm.os_managed_auth_label or "-"),
                _sources_row(result.tpm.sources, collectors_detail),
                ("Query error", result.tpm.query_error if result.tpm.query_failed else None),
                ("Finding", f"{tpm_find.id} [{tpm_find.severity}]" if tpm_find else "-"),
            ]
        )
    )
    if tpm_dev:
        lines.append(f"  {_cell('MITRE', 18)}  " + format_mitre(tpm_dev.mitre))
        for note in tpm_dev.risk_notes:
            wrapped = _wrap_text(note, width - 24)
            lines.append(f"  {_cell('Note', 18)}  {wrapped[0]}")
            for extra in wrapped[1:]:
                lines.append(f"  {'':<18}  {extra}")



def _render_bitlocker(lines: list[str], width: int, result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the BitLocker section."""
    lines.extend(_section("BitLocker", width))
    bl = result.bitlocker
    if bl.query_failed:
        lines.extend(
            _kv_block(
                [
                    ("Query", "failed"),
                    ("Error", bl.query_error),
                ]
            )
        )
    else:
        lines.extend(
            _kv_block(
                [
                    ("Volumes", len(bl.volumes)),
                    ("Any protected", bl.any_protected),
                    ("All protected", bl.all_protected),
                    _sources_row(bl.sources, collectors_detail),
                ]
            )
        )
        bl_rows = [
            [
                vol.mount_point,
                vol.protection_status,
                vol.volume_status or "-",
                vol.encryption_method or "-",
                "-" if vol.encryption_percentage is None else f"{vol.encryption_percentage:.0f}%",
                ", ".join(vol.key_protectors) or "-",
            ]
            for vol in bl.volumes
        ]
        lines.append("")
        lines.extend(
            _table(
                ["Mount", "Protection", "Volume status", "Method", "Pct", "Key protectors"],
                bl_rows,
                mins=[8, 12, 16, 12, 5, 24],
                caps=[10, 14, 22, 18, 6, 38],
            )
        )
        bl_mitre = indicators_for_bitlocker(
            protected=bl.any_protected,
            uses_tpm_protector=any(v.uses_tpm_protector for v in bl.volumes),
            tpm_present=bool(result.tpm.present),
        )
        lines.append(
            f"  {_cell('MITRE', 18)}  " + format_mitre(bl_mitre)
        )



def _render_dma_thunderbolt(lines: list[str], width: int, result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the DMA / Thunderbolt section."""
    lines.extend(_section("DMA / Thunderbolt", width))
    dma = result.dma
    if dma.query_failed and not dma.controllers and dma.dma_guard_policy is None:
        lines.extend(
            _kv_block(
                [
                    ("Query", "failed"),
                    ("Error", dma.query_error),
                ]
            )
        )
    else:
        lines.extend(
            _kv_block(
                [
                    ("Kernel DMA", dma.kernel_dma_protection or "Unknown"),
                    ("DMA capability", dma.dma_protection_available),
                    ("IOMMU table (firmware)", dma.iommu_table or ("absent" if dma.iommu_present is False else "unknown")),
                    ("ACPI tables (registry)", f"{dma.acpi_status or '-'} ({len(dma.acpi_tables)} tables)"),
                    ("DeviceGuard props", ", ".join(dma.device_guard_properties) or "-"),
                    ("VBS services", ", ".join(dma.device_guard_services_running) or "-"),
                    ("DmaGuard GPO", dma.dma_guard_policy_label),
                    ("GPO DWORD", "-" if dma.dma_guard_policy is None else dma.dma_guard_policy),
                    ("Name-filter hits", len(dma.controllers)),
                    ("Present now", dma.thunderbolt_present),
                    ("Present=false", len(dma.thunderbolt_historical)),
                    ("AllowedBuses", len(dma.allowed_buses)),
                    _sources_row(dma.sources, collectors_detail),
                ]
            )
        )
        dma_rows = [
            [
                rec.name,
                "yes" if rec.present else "no",
                rec.status or "-",
                rec.source,
                rec.last_write_utc or "-",
            ]
            for rec in dma.controllers
        ]
        lines.append("")
        lines.extend(
            _table(
                ["Name", "Present", "Status", "Source", "Last write UTC"],
                dma_rows,
                mins=[28, 7, 10, 10, 20],
                caps=[48, 7, 14, 16, 24],
            )
        )
        if not dma.controllers:
            lines.append("  (no name-filter hits — live or leftover)")
        if dma.allowed_buses:
            lines.append("")
            lines.append("  DmaSecurity AllowedBuses (BitLocker auto-encrypt OEM exceptions, not attach history)")
            bus_rows = [[b.name, b.hardware_id or "-"] for b in dma.allowed_buses]
            lines.extend(
                _table(
                    ["Name", "Hardware ID"],
                    bus_rows,
                    mins=[28, 28],
                    caps=[48, 48],
                )
            )
        dma_mitre = indicators_for_dma(
            kernel_state=dma.kernel_dma_protection,
            policy=dma.dma_guard_policy,
            controller_present=dma.thunderbolt_present,
        )
        lines.append(
            f"  {_cell('MITRE', 18)}  " + format_mitre(dma_mitre)
        )



def _render_source_trust(lines: list[str], width: int, result: AssessmentResult) -> None:
    """Render the Source trust section."""
    lines.extend(_section("Source trust", width))
    trust_rows = result.scanner_context.get("source_trust") or {}
    if trust_rows:
        lines.extend(
            _table(
                ["Collector", "Layer", "Reads", "Who could alter it"],
                [
                    [
                        name,
                        info.get("trust"),
                        info.get("reads"),
                        SOURCE_TRUST.get(info.get("trust", ""), "-").split(";")[-1].strip(),
                    ]
                    for name, info in sorted(
                        trust_rows.items(),
                        key=lambda kv: (
                            SOURCE_TRUST_ORDER.index(kv[1].get("trust", "os"))
                            if kv[1].get("trust") in SOURCE_TRUST_ORDER
                            else 9,
                            kv[0],
                        ),
                    )
                ],
                mins=[15, 9, 40, 30],
                caps=[16, 9, 44, 33],
            )
        )
    lines.append("")



def _render_interception_surface(lines: list[str], width: int, result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the Interception surface section."""
    lines.extend(_section("Interception surface", width))
    ic = result.interception
    if ic.query_failed and not ic.filters:
        lines.extend(_kv_block([("Query", "failed"), ("Error", ic.query_error)]))
    else:
        lines.extend(
            _kv_block(
                [
                    ("Verdict", ic.verdict),
                    # P-8: the collector reads BOTH positions, but the absence of
                    # Lower rows was indistinguishable from not checking Lower.
                    ("Classes checked",
                     (", ".join(ic.classes_checked) or "-")
                     + "  |  positions: UpperFilters, LowerFilters"),
                    ("Filters found",
                     f"{len(ic.filters)} "
                     f"({sum(1 for f in ic.filters if 'upper' in (f.position or '').lower())} upper, "
                     f"{sum(1 for f in ic.filters if 'lower' in (f.position or '').lower())} lower)"),
                    ("Additional", len(ic.additional_filters)),
                    ("Biometric adapters", len(ic.adapters)),
                    ("Third-party", len(ic.third_party_adapters)),
                    _sources_row(ic.sources, collectors_detail),
                ]
            )
        )
        if ic.filters:
            lines.append("")
            lines.append("  What sits in each device class stack")
            lines.extend(
                _table(
                    ["Class", "Position", "Driver", "Origin", "Sees", "Start"],
                    [
                        [
                            f.device_class,
                            f.position.replace("Filters", ""),
                            f.driver,
                            "inbox" if f.inbox else "additional",
                            f.sees or "-",
                            f.start_label or "-",
                        ]
                        for f in ic.filters
                    ],
                    mins=[15, 7, 16, 11, 18, 9],
                    # caps[1] was 7 and the header "Position" is 8, so the
                    # header rendered one character wider than its own
                    # separator. A cap must never be narrower than its header.
                    caps=[16, 8, 20, 11, 20, 10],
                )
            )
        if ic.adapters:
            lines.append("")
            lines.append("  Biometric framework adapters (engine sees the raw sample)")
            lines.extend(
                _table(
                    ["Slot", "Binary", "Origin", "Device"],
                    [
                        [a.slot, a.binary, "inbox" if a.inbox else "third-party", a.device_name]
                        for a in ic.adapters
                    ],
                    mins=[9, 28, 12, 26],
                    caps=[9, 34, 12, 40],
                )
            )
        lines.append("")



def _render_boot_integrity(lines: list[str], width: int, result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the Boot integrity section."""
    lines.extend(_section("Boot integrity", width))
    bi = result.boot_integrity
    if bi.query_failed:
        lines.extend(_kv_block([("Query", "failed"), ("Error", bi.query_error)]))
    else:
        lines.extend(
            _kv_block(
                [
                    ("Verdict", bi.verdict),
                    ("Test signing", bi.test_signing),
                    ("Code integrity", bi.code_integrity_enabled),
                    ("Kernel debug", bi.debug_mode),
                    ("HVCI", bi.hvci_enabled),
                    ("Driver blocklist", tri_bool(bi.blocklist_enabled)),
                    ("Blocklist source", bi.blocklist_status),
                    ("Kernel flags", ", ".join(bi.ci_flags) or "-"),
                    ("Kernel source", bi.ci_status),
                    ("Boot store", bi.bcd_status),
                    _sources_row(bi.sources, collectors_detail),
                ]
            )
        )
        if bi.bcd_flags:
            lines.append("")
            # Rows are settings that are BOTH in BCD_FLAGS_OF_INTEREST and
            # actually set, so a reader could not tell an unset flag from one
            # this tool never asks about. Name the queried set.
            # 188 characters in a 120-character report. W1 missed it because the
            # adversarial fixture carried no boot_integrity data, so this branch
            # never ran under test; the fixture now populates the section.
            for _i, _part in enumerate(_wrap_text(
                "Queried: " + ", ".join(BCD_FLAGS_OF_INTEREST)
                + "  |  rows are those actually set; anything absent is unset",
                REPORT_WIDTH - 4,
            )):
                lines.append(("  " if _i == 0 else "    ") + _part)
            lines.extend(
                _table(
                    ["Boot setting", "Value"],
                    [[k, v] for k, v in sorted(bi.bcd_flags.items())],
                    mins=[24, 20],
                    caps=[30, 40],
                )
            )
        lines.append("")



def _render_anticheat_drivers(lines: list[str], hw: HardwareAccessAssessment,
                              *, detail: bool = False) -> None:
    """Render the anti-cheat sub-block of the hardware access section.

    This exists because the section above it cannot carry the finding. In the
    generic driver table an anti-cheat driver is one more row whose Capabilities
    cell reads "arbitrary kernel read/write", sorted in among fan controllers
    and RGB utilities, with nothing to say which game put it there, whether it
    is loaded, or why it is on the list at all. The vendor, the state and the
    documented abuse are the answer an operator is looking for, so they get
    their own block and their own columns.

    Absence is rendered too. A section that prints nothing when it finds nothing
    is indistinguishable from a section that did not run.
    """
    found = hw.anticheat_present
    by_name = {d.driver for d in found}
    lines.append("")
    lines.append("  Anti-cheat kernel drivers")
    lines.append("")
    lines.append(f"  Checking {len(ANTICHEAT_ENTRIES)} services. '>' marks one found on this host.")
    lines.extend(
        _table(
            ["", "Service", "Vendor", "Ships with", "Reference"],
            [
                [
                    ">" if e.name in by_name else "-",
                    e.service,
                    e.vendor,
                    e.titles,
                    e.ref,
                ]
                for e in ANTICHEAT_ENTRIES
            ],
            # Summed with separators the previous caps made a 135-character
            # table inside a 120-character report, so the roster wrapped in the
            # terminal from the day it was added. 1+27+22+34+26 plus separators
            # and the leading indent lands exactly on the report width.
            mins=[1, 26, 20, 26, 22],
            caps=[1, 27, 22, 34, 26],
        )
    )
    if detail:
        # basis was populated on all 15 entries and read by nothing for five
        # rounds: the roster prints `ref`, the citation, and no column carried
        # the claim being made about it. Concatenating the two truncated at the
        # column cap, so the taxonomy prints once as a legend - reference
        # material, behind --collectors, where the rest of it lives.
        tally: dict[str, int] = {}
        for entry in ANTICHEAT_ENTRIES:
            tally[entry.basis] = tally.get(entry.basis, 0) + 1
        legend = "; ".join(
            f"{_count_phrase(tally[b], 'entry', 'entries')} "
            f"- {ANTICHEAT_BASIS_LABELS.get(b, b)}"
            for b in ("cve", "incident", "footprint") if b in tally
        )
        # Wrapped. The unwrapped form was 132 characters and test_render.py
        # caught it on the first run after this line was added, which is what
        # the harness is for.
        wrapped = _wrap_text("Tracked because: " + legend, REPORT_WIDTH - 4)
        lines.append(f"  {wrapped[0]}")
        for extra in wrapped[1:]:
            lines.append(f"    {extra}")
    lines.append("")
    if not found:
        lines.append(
            "  None of them is installed and none left a device node behind."
        )
        return
    lines.extend(
        _table(
            ["Driver", "Vendor / product", "State", "Signature", "Installed (UTC)", "Capabilities"],
            [
                [
                    d.driver,
                    d.shipped_by or "-",
                    d.state,
                    signature_cell(d),
                    (
                        d.installed_utc
                        or (f"node {d.legacy_last_write_utc}" if d.legacy_last_write_utc else "-")
                    ),
                    ", ".join(d.capability_labels) or "-",
                ]
                for d in found
            ],
            # 27+30+14+14+24+28 plus five separators and the indent is 128 in a
            # 120-character report. The found-drivers table was added in round 3
            # and has overrun the width ever since; the roster above it had the
            # same fault. Capabilities is the column that can afford to lose
            # room - its values are short labels, not identifiers.
            mins=[14, 20, 13, 12, 18, 16],
            caps=[20, 21, 14, 13, 20, 20],
        )
    )
    # The citation for each entry lives in Key.md. What belongs on a terminal is
    # the reference itself - a CVE number is shorter than the sentence
    # explaining it and tells an operator more.
    orphaned = [d for d in found if d.binary_missing]
    if orphaned:
        lines.append("")
        lines.append(
            "  Orphaned service key: "
            + ", ".join(d.driver for d in orphaned)
            + " - the registration survived, the .sys did not."
        )


def _render_low_level_hardware_access(lines: list[str], width: int, result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the Low-level hardware access section."""
    lines.extend(_section("Low-level hardware access", width))
    hw = result.hardware_access
    if hw.query_failed and not hw.drivers:
        lines.extend(_kv_block([("Query", "failed"), ("Error", hw.query_error)]))
    else:
        lines.extend(
            _kv_block(
                [
                    ("Verdict", hw.verdict),
                    ("Drivers installed", len(hw.installed_drivers)),
                    ("User-mode components", len(hw.installed_usermode)),
                    ("MSR capable", len(hw.msr_capable)),
                    ("Loaded now", len(hw.running_drivers)),
                    ("Unattributed", len(hw.unattributed_drivers)),
                    ("Bad signature", len(hw.untrusted_signature)),
                    # "Bad signature 0" and "Removal residue 0" both printed on
                    # a host with two orphaned keys. Neither counter was wrong;
                    # both were read as saying more than they said.
                    ("Signature unverifiable", len(hw.signature_unverifiable)),
                    ("Orphaned keys", len(hw.orphaned_keys)),
                    ("Removal residue (device node)", len(hw.removal_residue)),
                    (
                        # "installed not loaded" was
                        # len(anticheat_installed) - len(anticheat_running),
                        # which lumped three findings round 3 built fields to
                        # separate: an orphaned key whose .sys is gone, a
                        # stopped driver whose .sys is present and startable,
                        # and a user-mode component with no kernel interface.
                        # A host with two orphaned keys and one user-mode
                        # service read as "3 installed not loaded".
                        "Anti-cheat",
                        # Listing all five states unconditionally made a row of
                        # 135 characters that wrapped mid-phrase ("0 removal /
                        # residue"). "loaded" always prints because zero loaded
                        # is the security-relevant statement; the rest appear
                        # only when non-zero, and the total above them is what
                        # makes the omissions recoverable. "2 orphaned key" also
                        # disagreed in number with itself.
                        f"{len(hw.anticheat_present)} of {len(ANTICHEAT_DRIVER_NAMES)} tracked: "
                        + _count_phrase(len(hw.anticheat_running), "loaded", "loaded")
                        + (
                            "; " + ", ".join(
                                part for part in (
                                    _count_phrase(len(hw.anticheat_startable),
                                                  "stopped but startable",
                                                  "stopped but startable"),
                                    _count_phrase(len(hw.anticheat_orphaned),
                                                  "orphaned key", "orphaned keys"),
                                    _count_phrase(len(hw.anticheat_usermode),
                                                  "user-mode component",
                                                  "user-mode components"),
                                    _count_phrase(len(hw.anticheat_residue),
                                                  "removal residue", "removal residue"),
                                ) if not part.startswith("0 ")
                            )
                            if hw.anticheat_present else ""
                        ),
                    ),
                    ("Tracked drivers", len(hw.drivers)),
                    ("Signature check", hw.signature_check),
                    ("Client lookup", hw.process_attribution),
                    ("Physical memory", len(hw.physmem_capable)),
                    _sources_row(hw.sources, collectors_detail),
                ]
            )
        )
        # Only drivers that are actually present or left residue. Listing every
        # tracked name as "not installed" is noise that buries the real rows.
        shown = [d for d in hw.drivers if d.present or d.legacy_node]
        if shown:
            lines.append("")
            lines.extend(
                _table(
                    ["Driver", "State", "Location", "Signature", "Client process", "Capabilities"],
                    [
                        [
                            d.driver,
                            # state already says "residue only"; no second label
                            d.state,
                            d.location_class or "-",
                            signature_cell(d),
                            ", ".join(d.client_processes) or (d.attributed_to or "-"),
                            ", ".join(d.capability_labels),
                        ]
                        for d in shown
                    ],
                    mins=[13, 13, 14, 12, 20, 18],
                    caps=[22, 14, 14, 13, 22, 23],
                )
            )
        else:
            lines.append("")
            lines.append(
                f"  None of the {len(hw.drivers)} tracked drivers is installed and none left "
                "a device node behind."
            )
        _render_anticheat_drivers(lines, hw, detail=collectors_detail)
        lines.append("")



def _render_firmware_surface(lines: list[str], width: int, result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the Firmware surface section."""
    lines.extend(_section("Firmware surface", width))
    fw = result.firmware
    if fw.query_failed and not fw.tables:
        lines.extend(_kv_block([("Query", "failed"), ("Error", fw.query_error)]))
    else:
        lines.extend(
            _kv_block(
                [
                    # Registry-sourced count, sitting two rows above a
                    # firmware-sourced IOMMU result. DMAR is not among these,
                    # and a reader took the adjacency for a relationship.
                    ("ACPI tables (registry)", f"{len(fw.tables)} ({fw.acpi_status or '-'})"),
                    ("WPBT", fw.wpbt_present),
                    (
                        "WPBT binary",
                        # P-7: 0 is a measurement, not an absent one.
                        tri_measure(fw.wpbt_binary_size, "bytes",
                                    unavailable=fw.wpbt_read_status,
                                    not_applicable=(fw.wpbt_present is False)),
                    ),
                    (
                        "WPBT cmdline",
                        tri_measure(fw.wpbt_command_line,
                                    not_applicable=(fw.wpbt_present is False)),
                    ),
                    # P-7: "ok" is a COLLECTION status - the table was retrieved
                    # and parsed. Not "Validated" or "Authentic": SMBIOS carries
                    # no signature this tool can check, and Key.md §0 says
                    # nothing here is hardware-anchored.
                    ("SMBIOS read",
                     (f"{fw.smbios_status}"
                      + (f" ({fw.smbios.version}, "
                         f"{fw.smbios.structure_count} structures parsed; "
                         "contents not validated)"
                         if fw.smbios_status == "ok" and fw.smbios else ""))
                     if fw.smbios_status else "not read"),
                    (
                        "WSMT claims",
                        f"0x{fw.wsmt_flags:02x}: " + (", ".join(fw.wsmt_protections) or "none")
                        if fw.wsmt_flags is not None
                        else (fw.wsmt_read_status or "-"),
                    ),
                    # `or "none declared"` turned an undetermined probe into an
                    # affirmative negative - the same defect A-4 fixed for
                    # tpm_interface, still live here.
                    ("IOMMU table (firmware)", tri_state(fw.iommu_table)),
                    ("TPM interface", tri_state(fw.tpm_interface)),
                    ("SMM mitigations", fw.smm_mitigations_declared),
                    ("Debug port", tri_bool(fw.debug_port_declared, "declared", "none declared")),
                    _sources_row(fw.sources, collectors_detail),
                ]
            )
        )
        lines.append("")
        lines.append("  Platform firmware")
        lines.extend(
            _table(
                ["Field", "Value"],
                [
                    ["BIOS vendor", fw.bios_vendor],
                    ["BIOS version", fw.bios_version],
                    [
                        "Released",
                        (fw.bios_release_date or "-")
                        + (" *" if fw.predates_mitigations else ""),
                    ],
                    ["System", " ".join(x for x in (fw.system_manufacturer, fw.system_product) if x) or "-"],
                    ["CPU", fw.cpu_identifier],
                    ["Microcode", fw.microcode_revision],
                    ["Previous microcode", fw.previous_microcode_revision],
                    # TPM interface and IOMMU table were printed here and again
                    # in the section KV block. Both came from one field, so it
                    # was redundancy rather than divergence - but the KV rows
                    # now carry the provenance marker ("(firmware)") and these
                    # did not, so the unlabelled copy was the weaker of the two.
                ],
                mins=[19, 40],
                # The cap, not the min, was the cause: caps[0] was 16 and
                # "Previous microcode" is 18, so the label wrapped mid-phrase in
                # every capture and a one-row field looked like a row plus an
                # orphaned word. mins was raised first and changed nothing,
                # because the cap is applied after it.
                caps=[20, 60],
            )
        )
        if fw.predates_mitigations:
            lines.append(f"  * firmware predates {FIRMWARE_MITIGATION_ERA}")
        if fw.smbios:
            sm = fw.smbios
            lines.append("")
            lines.append(f"  SMBIOS {sm.version or '?'} — what the firmware says about itself")
            lines.extend(
                _table(
                    ["Field", "Value"],
                    [
                        # A partial walk used to report as a complete
                        # inventory; round 4b added the flag and nothing printed
                        # it, which is a warning nobody can see.
                        ["Structures", f"{sm.structure_count} ({len(sm.types_present)} types)"
                         + (" - WALK TRUNCATED, inventory is partial" if sm.truncated else "")],
                        ["BIOS", " ".join(x for x in (sm.bios_vendor, sm.bios_version) if x) or "-"],
                        ["BIOS date", sm.bios_release_date],
                        ["BIOS release", tri_state(sm.bios_release)],
                        # Printed with its MB equivalent because the field the
                        # host uses is expressed in MB and a bare KB figure is
                        # what made a 2x error look plausible for four rounds.
                        ["ROM size", (f"{sm.bios_rom_size_kb} KB ({sm.bios_rom_size_kb // 1024} MB)"
                                      if sm.bios_rom_size_kb else tri_state(sm.bios_rom_size_kb))],
                        ["System", " ".join(x for x in (sm.system_manufacturer, sm.system_product) if x) or "-"],
                        ["Serial", sm.serial_number],
                        ["UUID", sm.uuid],
                        ["Baseboard", " ".join(x for x in (sm.baseboard_manufacturer, sm.baseboard_product) if x) or "-"],
                        ["Chassis", sm.chassis_type],
                        ["Asset tag", sm.asset_tag],
                        ["Security status", sm.security_status],
                    ],
                    mins=[18, 40],
                    caps=[18, 58],
                )
            )
        if fw.resources:
            lines.append("")
            lines.append("  Capsule-updatable firmware components (ESRT)")
            lines.extend(
                _table(
                    ["Component", "Version", "Lowest supported", "Last attempt", "Status"],
                    [
                        [
                            r.resource_id,
                            r.version,
                            r.lowest_supported_version,
                            r.last_attempt_version,
                            "ok" if r.last_attempt_status == 0 else str(r.last_attempt_status),
                        ]
                        for r in fw.resources
                    ],
                    mins=[38, 10, 16, 13, 8],
                    caps=[40, 12, 16, 14, 10],
                )
            )
        if fw.acpi_wmi_instances:
            lines.append("")
            for wrapped in _wrap_text(
                "Firmware WMI interfaces (ACPI\\PNP0C14): " + "; ".join(fw.acpi_wmi_instances),
                112,
            ):
                lines.append(f"  {wrapped}")
        if fw.tables:
            lines.append("")
            annotated = [t for t in fw.tables if t.note or t.notable]
            lines.extend(
                _table(
                    ["Table", "Meaning", "Notable"],
                    [[t.signature, t.note or "-", "yes" if t.notable else "-"] for t in annotated],
                    mins=[8, 40, 8],
                    caps=[8, 60, 8],
                )
            )
            plain = [t.signature for t in fw.tables if not (t.note or t.notable)]
            if plain:
                lines.append("")
                for wrapped in _wrap_text("Other tables declared: " + ", ".join(plain), 112):
                    lines.append(f"  {wrapped}")
        lines.append("")



def _render_smart_card_certificates(lines: list[str], width: int, result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the Smart-card certificates section."""
    lines.extend(_section("Smart-card certificates", width))
    certs = result.certificates
    if certs.query_failed and not certs.certificates:
        lines.extend(_kv_block([("Query", "failed"), ("Error", certs.query_error)]))
    else:
        lines.extend(
            _kv_block(
                [
                    ("Certificates", len(certs.certificates)),
                    ("Smart-card", len(certs.smartcard_certificates)),
                    ("Confirmed", len(certs.confirmed)),
                    ("Expired", len(certs.expired_smartcard)),
                    ("CertProp policy", certs.cert_prop_status or "-"),
                    ("CertPropSvc", certs.service_start_label or "-"),
                    _sources_row(certs.sources, collectors_detail),
                ]
            )
        )
        shown = certs.smartcard_certificates or certs.certificates
        if shown:
            lines.append("")
            lines.extend(
                _table(
                    ["Subject", "Issuer", "Thumbprint", "Valid to", "Origin", "Store"],
                    [
                        [
                            c.subject,
                            c.issuer,
                            (c.thumbprint or "-")[:16],
                            _short_ts(c.not_after_utc),
                            c.origin + (" (expired)" if c.expired else ""),
                            (c.store or "-").replace("Cert:\\", ""),
                        ]
                        for c in shown
                    ],
                    mins=[20, 18, 16, 17, 10, 12],
                    caps=[26, 22, 16, 17, 11, 16],
                )
            )
        lines.append("")



def _render_zadig_indicators(lines: list[str], width: int, result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the generic-driver Indicators section."""
    lines.extend(_section("Generic driver & INF audit", width))
    drv = result.drivers
    if drv.query_failed and not drv.services:
        lines.extend(_kv_block([("Query", "failed"), ("Error", drv.query_error)]))
    else:
        lines.extend(
            _kv_block(
                [
                    ("Verdict", drv.verdict),
                    ("Drivers installed", len(drv.installed_services)),
                    ("Bound devices", len(drv.bindings)),
                    ("Deliberate", len(drv.strong_bindings)),
                    ("SDR matches", len(drv.sdr_bindings)),
                    # This counted deliberate_inf_hits - INFs naming something
                    # other than WinUSB - while the table below renders every
                    # inf_hit. A host with one WinUSB-only OEM INF therefore
                    # printed "INF packages 0" directly above a table with a
                    # row in it. Both numbers now print, each labelled for what
                    # it counts.
                    ("INF packages (any)", len(drv.inf_hits) if drv.inf_scan_performed else "not scanned"),
                    ("INF packages (deliberate)",
                     len(drv.deliberate_inf_hits) if drv.inf_scan_performed else "not scanned"),
                    _sources_row(drv.sources, collectors_detail),
                ]
            )
        )
        lines.append("")
        lines.extend(
            _table(
                ["Indicator", "Observed", "Signal", "Detail"],
                [[i.indicator, i.observed, i.signal, i.detail] for i in zadig_indicators(drv)],
                mins=[36, 10, 14, 40],
                caps=[38, 10, 14, 50],
            )
        )
        if drv.bindings:
            lines.append("")
            lines.append("  Devices detached from their class driver (raw endpoint access)")
            lines.extend(
                _table(
                    ["Name", "VID:PID", "Driver", "Enum", "Allowlist hit", "Signal"],
                    [
                        [
                            b.name,
                            b.vid_pid or "-",
                            b.driver,
                            b.enumerator,
                            b.allowlist_hit or "-",
                            b.confidence,
                        ]
                        for b in drv.bindings
                    ],
                    mins=[24, 9, 12, 8, 16, 6],
                    caps=[38, 11, 14, 10, 26, 8],
                )
            )
        if drv.inf_hits:
            lines.append("")
            lines.append(
                "  OEM INF packages referencing a generic driver (outlive the device)"
                " - WinUSB-only entries are ordinary vendor packaging"
            )
            lines.extend(
                _table(
                    ["INF", "Markers", "Modified UTC"],
                    [[h.inf_file, ", ".join(h.markers), h.mtime_utc or "-"] for h in drv.inf_hits],
                    mins=[14, 24, 20],
                    caps=[18, 40, 24],
                )
            )
        lines.append("")
        zadig_mitre = indicators_for_driver_substitution(
            bound=bool(drv.bindings),
            strong=bool(drv.strong_bindings or drv.strong_services),
            sdr_match=bool(drv.sdr_bindings),
        )
        lines.extend(
            _kv_block(
                [
                    (
                        "MITRE",
                        format_mitre(zadig_mitre),
                    )
                ]
            )
        )
        lines.append("")



def _render_sdr_tv_tuner(lines: list[str], width: int, result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the SDR / TV tuner section."""
    lines.extend(_section("SDR / TV tuner", width))
    sdr = result.sdr
    if sdr.query_failed and not sdr.devices:
        lines.extend(
            _kv_block(
                [
                    ("Query", "failed"),
                    ("Error", sdr.query_error),
                ]
            )
        )
    else:
        lines.extend(
            _kv_block(
                [
                    ("Allowlist hits", len(sdr.devices)),
                    ("Present now", len(sdr.present_devices)),
                    ("Historical", len(sdr.historical_devices)),
                    _sources_row(sdr.sources, collectors_detail),
                ]
            )
        )
        sdr_rows = [
            [
                rec.name,
                rec.vid_pid or "-",
                "yes" if rec.present else "no",
                rec.allowlist_hit or "-",
                rec.source,
                rec.last_write_utc or "-",
            ]
            for rec in sdr.devices
        ]
        lines.append("")
        lines.append("  Allowlisted SDR / DVB-T nodes only (no USB root walk)")
        lines.extend(
            _table(
                ["Name", "VID:PID", "Present", "Allowlist hit", "Source", "Last write UTC"],
                sdr_rows,
                mins=[22, 9, 7, 16, 14, 20],
                caps=[30, 11, 7, 22, 18, 20],
            )
        )
        sdr_mitre = indicators_for_sdr(present=bool(sdr.present_devices))
        lines.append(
            f"  {_cell('MITRE', 18)}  " + format_mitre(sdr_mitre)
        )



def _render_historical(lines: list[str], width: int, result: AssessmentResult, *, collectors_detail: bool = False) -> None:
    """Render the Historical section."""
    lines.extend(_section("Historical", width))
    hist = result.historical
    if hist.query_failed and not hist.records:
        lines.extend(
            _kv_block(
                [
                    ("Query", "failed"),
                    ("Error", hist.query_error),
                ]
            )
        )
    else:
        hardware = hist.hardware_records()
        context = hist.context_records()
        lines.extend(
            _kv_block(
                [
                    ("Hardware rows", len(hardware)),
                    ("Context omitted", len(context)),
                    ("Absent now", len(hist.absent_identity_devices)),
                    ("Policy hive", (hist.policy or {}).get("path") or "not present"),
                    ("Policy Enabled", (hist.policy or {}).get("enabled")),
                    _sources_row(hist.sources, collectors_detail),
                ]
            )
        )
        hist_rows = [
            [
                rec.category,
                rec.name,
                "yes" if rec.present else "no",
                rec.source,
                _short_ts(rec.first_seen_utc),
                _short_ts(rec.last_write_utc or rec.last_seen_utc),
                _short_ts(rec.last_removal),
            ]
            for rec in hardware
            if rec.category in {"Biometric", "SmartCardReader", "Infrared", "Sensor"}
        ]
        lines.append("")
        lines.append("  Hardware / phantom identity devices (inbox WinBio DBs and Calais card types omitted)")
        lines.extend(
            _table(
                ["Category", "Name", "Present", "Source", "First seen UTC", "Last write UTC", "Last out UTC"],
                hist_rows,
                mins=[10, 20, 7, 10, 17, 17, 17],
                caps=[11, 26, 7, 11, 17, 17, 17],
            )
        )
        enrollments = [
            r for r in hardware
            if r.source == "winbio-account"
        ]
        if enrollments:
            lines.append("")
            lines.append("  Hello enrollment remnants (no templates)")
            for rec in enrollments:
                lines.append(
                    f"    {rec.name}    sid={rec.instance_id}    last_write={rec.last_write_utc or '-'}"
                )
        if context:
            lines.append("")
            lines.append(
                f"  Omitted context: {sum(1 for r in context if r.source=='wbio-database')} WinBio DB key(s), "
                f"{sum(1 for r in context if r.source=='calais-smartcards')} inbox card type(s), "
                f"{sum(1 for r in context if r.source=='biometrics-policy')} policy row(s), "
                f"{sum(1 for r in context if r.source=='winbio-account')} empty enrollment(s)."
            )
        policy_notes = [r for r in hist.records if r.source == "biometrics-policy"]
        if policy_notes:
            lines.append("")
            for rec in policy_notes:
                for note in rec.notes:
                    for wrapped in _wrap_text(note, width - 12):
                        lines.append(f"  policy  {wrapped}")



def _render_device_inventory(lines: list[str], width: int, result: AssessmentResult) -> None:
    """Render the Device inventory section."""
    inventory = [d for d in result.devices if d.category != "TPM"]
    lines.extend(_section("Device inventory", width))
    # An empty table rendered as a bare "(none)", which is the one thing this
    # tool is not supposed to do: it read identically whether the PnP collector
    # had run and matched nothing or had failed outright. The findings layer
    # already made that distinction (FIND-NO-IDENTITY-PERIPHERALS is gated on
    # inventory_ok) and the section did not, so the two could disagree about the
    # same host. The scope line below is what the section knows about itself.
    ctx = result.scanner_context
    examined = ctx.get("pnp_rows_examined")
    excluded = ctx.get("pnp_rows_excluded")
    ok = ctx.get("pnp_inventory_ok")
    by_origin = ctx.get("pnp_rows_by_origin") or {}
    scope = f"  Identity scan ({', '.join(PNP_CLASSES)}): "
    if ok is False:
        scope += "COLLECTOR FAILED - an empty table below is not a result"
    elif by_origin:
        # Reported per scan. One combined number attributed the camera scan's
        # rows to the identity classes and read as a false positive for
        # "devices were found and dropped".
        ident = by_origin.get("identity", 0)
        cam = by_origin.get("camera", 0)
        scope += f"{ident} row(s)"
        if cam:
            excl_cam = (ctx.get("pnp_excluded_by_origin") or {}).get("camera", 0)
            scope += (f"  |  Related-camera scan (Camera, Image): {cam} row(s), "
                      f"{excl_cam} not IR/Hello and excluded")
    elif examined is not None:
        scope += f"{examined} row(s) examined"
        if excluded:
            scope += f", {excluded} excluded"
    # 151 characters on a host where both scans report. Same class as the
    # Queried line: added to satisfy an audit finding and never measured.
    for _i, _part in enumerate(_wrap_text(scope.strip(), REPORT_WIDTH - 4)):
        lines.append(("  " if _i == 0 else "    ") + _part)
    inv_rows = [
        [
            dev.category,
            dev.name,
            dev.status,
            dev.extra.get("enumerator") or "-",
            dev.manufacturer or "-",
            "yes" if dev.virtual_or_software else "",
            format_mitre_ids(dev.mitre),
        ]
        for dev in inventory
    ]
    lines.extend(
        _table(
            ["Category", "Name", "Status", "Bus", "Manufacturer", "Virt", "MITRE"],
            inv_rows,
            mins=[11, 22, 8, 6, 12, 4, 14],
            caps=[15, 30, 10, 7, 18, 4, 22],
        )
    )



def _render_device_risk_notes(lines: list[str], width: int, result: AssessmentResult) -> None:
    """Render the Device risk notes section."""
    inventory = [d for d in result.devices if d.category != "TPM"]
    lines.extend(_section("Device risk notes", width))
    # Same defect as the inventory section above: risk notes are per-device, so
    # an empty inventory necessarily empties this too. Saying so stops it
    # reading as "these devices carry no risk".
    if not inventory:
        lines.append("  No devices in the identity classes, so there is nothing to annotate.")
        return
    if not inventory:
        lines.append("  (none)")
    else:
        for dev in inventory:
            # Device names and instance ids are attacker-controlled - a USB
            # descriptor is whatever the device says it is - and were emitted
            # unwrapped, so a 200-character name produced a 254-character line
            # in a 120-character report.
            avail = max(20, width - 22)
            name_lines = _wrap_text(_plain(dev.name), avail)
            lines.append(f"  {dev.category:<16}  {name_lines[0]}")
            for extra in name_lines[1:]:
                lines.append(f"  {'':<16}  {extra}")
            for extra in _wrap_text(_plain(dev.instance_id or "-"), avail):
                lines.append(f"  {'':<16}  {extra}")
            lines.append(
                f"  {'':<16}  MITRE  "
                + _wrap_text(format_mitre(dev.mitre), max(20, width - 29))[0]
            )
            for note in dev.risk_notes:
                wrapped = _wrap_text(note, width - 22)
                lines.append(f"  {'':<16}  • {wrapped[0]}")
                for extra in wrapped[1:]:
                    lines.append(f"  {'':<16}    {extra}")
            lines.append("")



def _render_tiers(lines: list[str], width: int, result: AssessmentResult,
                   *, colour: bool = False, plan: bool = False) -> None:
    """Posture rows, tiered. All three tiers highlight."""
    rows = assess_tiers(result)
    lines.extend(_section("Posture gaps", width))
    if not rows:
        # P-6. This used to assert completeness unconditionally, which is false
        # on any filtered run: a section that never ran has unexamined gaps, not
        # closed ones. The claim now shrinks to what the run supports.
        ctx = result.scanner_context or {}
        registered = set(ctx.get("collectors_registered") or [])
        skipped = set(ctx.get("collectors_skipped") or [])
        failed = set(ctx.get("collectors_failed") or [])
        unrun = (skipped | failed) or (registered - set(ctx.get("collectors") or []))
        if unrun:
            lines.append(
                f"  No gap found among the sections that ran. "
                f"{_count_phrase(len(unrun), 'collector', 'collectors')} did not "
                "run, so")
            lines.append("  their gaps are unexamined rather than closed: "
                         + ", ".join(sorted(unrun)))
        else:
            lines.append("  None. Every gap this report can establish is already "
                         "closed, and nothing")
            lines.append("  undetermined is being reported as a gap.")
        return
    counts = {t: sum(1 for r in rows if r.tier == t) for t in (TIER_A, TIER_B, TIER_C)}
    lines.extend(_kv_block([
        ("Gaps", _count_phrase(len(rows), "gap", "gaps")),
        ("Tier A", f"{counts[TIER_A]} - {TIER_LABELS[TIER_A]}"),
        ("Tier B", f"{counts[TIER_B]} - {TIER_LABELS[TIER_B]}"),
        ("Tier C", f"{counts[TIER_C]} - {TIER_LABELS[TIER_C]}"),
    ]))
    lines.append("")
    for r in sorted(rows, key=lambda x: (x.tier, x.key)):
        head = f"  [{r.tier}] {r.section}: {r.title}"
        lines.append(mark_actionable(head[:width], enabled=colour))
        for part in _wrap_text(r.detail, width - 8):
            lines.append(f"        {part}")
        for part in _wrap_text("Mitigation: " + r.mitigation, width - 8):
            lines.append(f"        {part}")
        if r.blocked_reason:
            for part in _wrap_text("Not from the OS: " + r.blocked_reason, width - 8):
                lines.append(f"        {part}")
        if plan and r.tier == TIER_A and r.command:
            for part in _wrap_text("Proposed change: " + r.command, width - 8):
                lines.append(f"        {part}")
        lines.append("")
    if plan:
        lines.append("  PLAN ONLY. Nothing above has been applied.")
def _render_findings(
    lines: list[str], width: int, result: AssessmentResult, *, detail: bool = False
) -> None:
    """Render the Findings section.

    The table is always printed - it is the answer to "what did this find", and
    it fits on a screen. The per-finding detail paragraphs are the reasoning
    behind each row, which runs to a screen of its own on a host with anything
    interesting on it, so they are opt-in behind --findings.
    """
    lines.extend(_section("Findings", width))
    if not result.findings:
        lines.append("  (none)")
    else:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranked = sorted(result.findings, key=lambda f: order.get(f.severity, 9))
        finding_rows = [
            [
                finding.severity.upper(),
                finding.id,
                finding.category,
                finding.title,
                format_mitre_ids(finding.mitre),
            ]
            for finding in ranked
        ]
        lines.extend(
            _table(
                ["Sev", "ID", "Category", "Title", "MITRE"],
                finding_rows,
                mins=[8, 26, 12, 20, 14],
                caps=[8, 39, 15, 28, 20],
            )
        )
        if detail:
            lines.append("")
            for finding in ranked:
                lines.append(f"  [{finding.severity.upper()}] {finding.id}")
                for wrapped in _wrap_text(finding.detail, width - 8):
                    lines.append(f"      {wrapped}")
        else:
            # Say the detail exists. A reader who does not know the flag is
            # there has no way to discover what the table is leaving out.
            lines.append("")
            lines.append(
                f"  {len(ranked)} finding(s). Re-run with --findings for the reasoning behind "
                "each row."
            )
    if result.collection_errors:
        lines.extend(_section("Collection errors", width))
        for err in result.collection_errors:
            wrapped = _wrap_text(err, width - 6)
            lines.append(f"  - {wrapped[0]}")
            for extra in wrapped[1:]:
                lines.append(f"    {extra}")



def _render_summary(lines: list[str], width: int, result: AssessmentResult) -> None:
    """Render the Summary section."""
    lines.extend(_section("Summary", width))
    lines.extend(
        _kv_block(
            [
                # device_total includes the synthetic TPM record, which the
                # Device inventory section filters out - so the summary said
                # "Devices 1" directly above an inventory reading "(none)".
                ("Identity devices", result.summary.get("identity_device_total")),
                ("Findings", result.summary.get("finding_total")),
                ("TPM", result.summary.get("tpm_status")),
                ("BitLocker on", result.summary.get("bitlocker_protected")),
                ("BL volumes", result.summary.get("bitlocker_volumes")),
                ("Historical", result.summary.get("historical_records")),
                ("Hist. absent", result.summary.get("historical_absent")),
                ("Kernel DMA", result.summary.get("dma_kernel")),
                ("DmaGuard", result.summary.get("dma_policy")),
                ("Thunderbolt", result.summary.get("thunderbolt_present")),
                ("SDR present", result.summary.get("sdr_present")),
                ("SDR historical", result.summary.get("sdr_historical")),
            ]
        )
    )
    histogram = result.summary.get("technique_histogram") or {}
    if histogram:
        tech_row = ", ".join(f"{k}:{v}" for k, v in histogram.items())
        wrapped = _wrap_text(tech_row, width - 24)
        lines.append(f"  {_cell('ATT&CK hist', 18)}  {wrapped[0]}")
        for extra in wrapped[1:]:
            lines.append(f"  {'':<18}  {extra}")
    lines.append("")


def render_pretty(result: AssessmentResult, *, findings_detail: bool = False,
                  collectors_detail: bool = False, colour: bool = False,
                  plan: bool = False) -> str:
    ctx = result.scanner_context
    width = 120
    lines = [
        BANNER.rstrip(),
        "  Windows sensor / biometric / smart-card / IR / TPM / BitLocker / DMA / SDR assessment",
        # The interpretive notes that used to sit under each section live in
        # Key.md now. One pointer, once, so the terminal stays readable and the
        # context is still findable.
        "  How to read each section, and what it cannot tell you: see Key.md",
        "",
    ]
    _render_host(lines, width, ctx, result, collectors_detail=collectors_detail)
    _render_tpm(lines, width, result, collectors_detail=collectors_detail)
    _render_bitlocker(lines, width, result, collectors_detail=collectors_detail)
    _render_dma_thunderbolt(lines, width, result, collectors_detail=collectors_detail)
    _render_source_trust(lines, width, result)
    _render_interception_surface(lines, width, result, collectors_detail=collectors_detail)
    _render_boot_integrity(lines, width, result, collectors_detail=collectors_detail)
    _render_low_level_hardware_access(lines, width, result, collectors_detail=collectors_detail)
    _render_firmware_surface(lines, width, result, collectors_detail=collectors_detail)
    _render_smart_card_certificates(lines, width, result, collectors_detail=collectors_detail)
    _render_zadig_indicators(lines, width, result, collectors_detail=collectors_detail)
    _render_sdr_tv_tuner(lines, width, result, collectors_detail=collectors_detail)
    _render_historical(lines, width, result, collectors_detail=collectors_detail)
    _render_device_inventory(lines, width, result)
    _render_device_risk_notes(lines, width, result)
    _render_tiers(lines, width, result, colour=colour, plan=plan)
    _render_findings(lines, width, result, detail=findings_detail)
    _render_summary(lines, width, result)
    return "\n".join(lines) + "\n"


PS_SCRIPTS: tuple[tuple[str, str], ...] = (
    ("pnp", _PS_PNP_SCRIPT),
    ("camera", _PS_CAMERA_SCRIPT),
    ("tpm.Get-Tpm", _PS_TPM_GET_SCRIPT),
    ("tpm.Win32_Tpm", _PS_TPM_WMI_SCRIPT),
    ("bitlocker.Get-BitLockerVolume", _PS_BITLOCKER_SCRIPT),
    ("bitlocker.Win32_EncryptableVolume", _PS_BITLOCKER_WMI_SCRIPT),
    ("dma.DeviceGuard", _PS_DEVICEGUARD_SCRIPT),
    ("dma.controllers", _PS_DMA_CONTROLLER_SCRIPT),
    ("sdr", _PS_SDR_PNP_SCRIPT),
    ("historical", _PS_HISTORICAL_PNP_SCRIPT),
)


# Query names are prefixed with their collector, except the related-camera
# sweep which belongs to pnp.
PS_SCRIPT_OWNERS = {"camera": "pnp"}


def _script_owner(script_name: str) -> str:
    prefix = script_name.split(".", 1)[0]
    return PS_SCRIPT_OWNERS.get(prefix, prefix)


def diagnose_powershell(
    timeout: int | None = None, active: Sequence[str] | None = None
) -> list[dict[str, Any]]:
    """Run each query alone and report exactly what came back.

    Every collector funnels through one process launch and one JSON parse, so a
    single fault there fails all of them and reads as "the query failed". This
    reports the fault directly instead of leaving it to be inferred.
    """
    probe = "Get-Tpm | Select-Object TpmPresent | ConvertTo-Json -Compress"
    checks: list[tuple[str, str, bool, str | None]] = [
        ("probe.bare (no prologue)", probe, False, None),
        ("probe.with-prologue", probe, True, None),
        # Both delivery paths are probed regardless of which one is active, so a
        # regression in either is visible before it is switched on.
        ("probe.delivery=command", _PS_STDIN_PROBE_SCRIPT, True, "command"),
        ("probe.stdin (script block)", _PS_STDIN_PROBE_SCRIPT, True, "stdin"),
        ("probe.stdin (flat)", _PS_STDIN_PROBE_SCRIPT, True, "stdin-flat"),
    ]
    # Honour --only / --skip: probing a query the run would not have used is
    # noise, and reads as though that collector is part of this run.
    selected = None if active is None else set(active)
    checks.extend(
        (name, script, True, None)
        for name, script in PS_SCRIPTS
        if selected is None or _script_owner(name) in selected
    )

    rows: list[dict[str, Any]] = []
    for name, script, use_prologue, forced in checks:
        row: dict[str, Any] = {"query": name}
        try:
            completed = _run_powershell_raw(
                script,
                timeout,
                prologue=use_prologue,
                delivery="stdin" if forced == "stdin-flat" else forced,
                wrap=forced != "stdin-flat",
            )
        except CollectionError as exc:
            row.update(status="launch failed", error=str(exc))
            rows.append(row)
            continue
        except (OSError, subprocess.TimeoutExpired) as exc:
            row.update(status="timeout/OS error", error=str(exc))
            rows.append(row)
            continue
        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        row.update(
            exit_code=completed.returncode,
            stdout_bytes=len(stdout),
            stderr=(
                (stderr[:_PS_STDERR_CAP] + " [...truncated]")
                if len(stderr) > _PS_STDERR_CAP
                else (stderr or None)
            ),
            stdout_head=stdout[:160].replace("\n", " ") or None,
        )
        if completed.returncode != 0:
            row["status"] = "nonzero exit"
        elif not stdout:
            row["status"] = "empty output"
        else:
            try:
                parsed = _loads_ps_json(stdout)
                row["status"] = "ok"
                row["rows"] = len(parsed)
            except CollectionError as exc:
                row["status"] = "json parse failed"
                row["error"] = str(exc)
        rows.append(row)
    return rows


def render_diagnostics(rows: list[dict[str, Any]]) -> str:
    lines = ["", "POWERSHELL COLLECTION DIAGNOSTICS", _rule(REPORT_WIDTH, SECTION_RULE_CHAR)]
    # Version first: a diagnostic that cannot identify the build it came from
    # turns every follow-up into a guess about which code actually ran.
    lines.append(f"  Version:     Sensor.py {__version__} (schema {SCHEMA_VERSION})")
    lines.append(f"  Host binary: {_POWERSHELL_PATH or 'not resolved'}")
    lines.append(f"  Timeout:     {PS_TIMEOUT_SEC}s")
    lines.append(f"  Delivery:    {active_script_delivery()} (requested: {_SCRIPT_DELIVERY})")
    head = stdin_first_bytes()
    lines.append(
        f"  Stdin bytes: {head.hex(' ')}  ({head.decode('ascii', 'replace')!r})  "
        f"BOM: {'PRESENT' if head.startswith(codecs.BOM_UTF8) else 'none'}"
    )
    lines.append("")
    table_rows = [
        [
            row.get("query"),
            row.get("status"),
            "-" if row.get("exit_code") is None else row.get("exit_code"),
            "-" if row.get("rows") is None else row.get("rows"),
            "-" if row.get("stdout_bytes") is None else row.get("stdout_bytes"),
        ]
        for row in rows
    ]
    lines.extend(
        _table(
            ["Query", "Status", "Exit", "Rows", "Bytes"],
            table_rows,
            mins=[30, 18, 5, 5, 6],
            caps=[36, 20, 6, 6, 8],
        )
    )
    for row in rows:
        detail = row.get("error") or row.get("stderr")
        if not detail and row.get("status") == "ok":
            continue
        lines.append("")
        lines.append(f"  {row['query']}: {row.get('status')}")
        if detail:
            for wrapped in _wrap_text(detail, 110):
                lines.append(f"      {wrapped}")
        if row.get("stdout_head"):
            for wrapped in _wrap_text(f"stdout head: {row['stdout_head']}", 110):
                lines.append(f"      {wrapped}")
    lines.append("")
    return "\n".join(lines) + "\n"


# Exit codes. 2 is reserved: argparse uses it for a usage error, so a caller
# can distinguish "you passed a bad flag" from "collection failed on the host".
EXIT_OK = 0
EXIT_FINDINGS_AT_THRESHOLD = 1
EXIT_USAGE = 2  # argparse only, never returned by main()
EXIT_WRITE_FAILED = 3
EXIT_UNHANDLED = 4
EXIT_COLLECTION_ABORTED = 5
EXIT_INTERRUPTED = 130


def _write_report(path: str, text: str, *, force: bool) -> None:
    """Write the report exclusively, atomically, and owner-readable only.

    The report carries the hostname, user SIDs, enrolled biometric factor
    bitmasks, BitLocker protector composition and a full peripheral inventory,
    so it is not created world-readable and it does not silently clobber an
    existing file.
    """
    body = text if text.endswith("\n") else text + "\n"
    directory = os.path.dirname(os.path.abspath(path)) or "."
    tmp_path = os.path.join(directory, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(tmp_path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
        if not force and os.path.exists(path):
            raise FileExistsError(f"{path} exists; pass --force to overwrite")
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _warn_if_unelevated() -> None:
    """Say plainly that the tool needs administrator.

    HOST-VERIFY V-7: run from a user terminal, the operator saw a console flash
    and close in about three seconds with no output and no scan. Whatever the
    proximate cause, a tool that is elevation-only by design must say so rather
    than exit into silence. This is the prerequisite for the self-elevation
    work, not a substitute for it.
    """
    if not _is_windows() or _is_admin():
        return
    for line in (
        "",
        "  Sensor.py requires administrator.",
        "",
        "  Most collectors read keys and firmware interfaces that a standard user",
        "  cannot open. Run from an elevated terminal, or the report will be mostly",
        "  'could not establish' - which is honest, but not useful.",
        "",
        "  Right-click the terminal and choose Run as administrator, then re-run.",
        "",
    ):
        print(line, file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Windows sensor / biometric / smart-card / IR / TPM ATT&CK assessment"
    )
    parser.add_argument(
        "--format",
        choices=("pretty", "json"),
        default="pretty",
        help="Report format (default: pretty)",
    )
    parser.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--pretty", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--on-error", choices=("collect", "raise"), default="collect")
    parser.add_argument(
        "--no-related-cameras",
        action="store_true",
        help="Do not scan Camera/Image classes for Hello/IR units",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="Hash the hostname, keep only the RID of SIDs, and hash device serials "
        "(applies to every output format)",
    )
    parser.add_argument(
        "--script-delivery",
        choices=("auto", "stdin", "command"),
        default="auto",
        help="How the query body reaches PowerShell. 'stdin' keeps it out of "
        "process-creation telemetry; 'auto' probes and falls back (default)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=PS_TIMEOUT_SEC,
        help=f"Per-query PowerShell timeout in seconds (default: {PS_TIMEOUT_SEC})",
    )
    parser.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "info"),
        help="Exit 1 if any finding is at or above this severity",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Run each PowerShell query alone and report exit code, stderr, and output",
    )
    parser.add_argument(
        "--findings",
        action="store_true",
        help=(
            "Print the reasoning paragraph under each finding. The findings table is "
            "always printed; this adds the detail behind each row"
        ),
    )
    parser.add_argument(
        "--collectors",
        action="store_true",
        help=(
            "List every source and collector by name. Counts are always shown; "
            "this replaces them with the full enumeration"
        ),
    )
    parser.add_argument(
        "--implement",
        action="store_true",
        help=(
            "Print the remediation plan for each actionable weakness: the exact change, "
            "and for anything that cannot be fixed from the OS, why not. PLAN ONLY - "
            "this tool does not modify the system"
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Never highlight actionable weaknesses, even on a terminal",
    )
    parser.add_argument("-o", "--output", help="Write report to this path instead of stdout")
    known_collectors = ", ".join(spec.name for spec in default_collectors())
    parser.add_argument(
        "--skip",
        default="",
        help=f"Comma-separated collectors to skip. Known: {known_collectors}",
    )
    parser.add_argument(
        "--only",
        default="",
        help="Comma-separated collectors to run exclusively",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite an existing --output file")
    parser.add_argument("--version", action="version", version=f"Sensor.py {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    _warn_if_unelevated()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    fmt = args.format
    if args.json and not args.pretty:
        fmt = "json"  # deprecated alias
    elif args.pretty and not args.json:
        fmt = "pretty"
    elif args.json and args.pretty:
        parser.error("--json and --pretty are mutually exclusive; use --format")

    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    set_powershell_timeout(args.timeout)
    set_script_delivery(args.script_delivery)

    if args.diagnose:
        if not _is_windows():
            LOGGER.error("--diagnose requires Windows")
            return EXIT_COLLECTION_ABORTED
        active, _skipped = select_collectors(
            default_collectors(),
            only=[n for n in args.only.split(",") if n.strip()] or None,
            skip=[n for n in args.skip.split(",") if n.strip()] or None,
        )
        sys.stdout.write(
            render_diagnostics(diagnose_powershell(active=[s.name for s in active]))
        )
        return 0

    try:
        result = assess_sensors(
            include_related_ir_cameras=not args.no_related_cameras,
            on_error=args.on_error,  # type: ignore[arg-type]
            only=[n for n in args.only.split(",") if n.strip()] or None,
            skip=[n for n in args.skip.split(",") if n.strip()] or None,
        )
    except ValueError as exc:
        parser.error(str(exc))
    except CollectionError as exc:
        LOGGER.error("Collection aborted: %s", exc)
        return EXIT_COLLECTION_ABORTED
    except KeyboardInterrupt:
        LOGGER.error("Interrupted before collection completed; no report written")
        return EXIT_INTERRUPTED

    if args.redact:
        result = redact_result(result)
    if fmt == "json":
        text = json.dumps(result.to_dict(), indent=2, sort_keys=True, ensure_ascii=True)
    else:
        text = render_pretty(
            result, findings_detail=args.findings,
            collectors_detail=args.collectors,
            # Highlight only on a terminal, and never into a file: the
            # sanitizer exists to keep escape sequences out of captured
            # output, so emitting our own would be that defect inverted.
            colour=(not args.no_color and not args.output
                    and highlight_enabled()),
            plan=args.implement,
        )

    try:
        if args.output:
            _write_report(args.output, text, force=args.force)
        else:
            sys.stdout.write(text if text.endswith("\n") else text + "\n")
    except OSError as exc:
        LOGGER.error("Could not write report: %s", exc)
        return EXIT_WRITE_FAILED

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 99) <= threshold for f in result.findings):
            return EXIT_FINDINGS_AT_THRESHOLD
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERRUPTED)
    except Exception as exc:  # pragma: no cover - last-resort guard
        LOGGER.error("Unhandled error: %s", exc)
        sys.exit(EXIT_UNHANDLED)
