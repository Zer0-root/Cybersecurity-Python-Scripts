"""Bluejack.py — read-only Windows Bluetooth host audit.

Windows-only live scan. MITRE techniques covered: T1120, T1200, T1056.001, T1040.
Does not mutate policy, does not talk to the radio, does not emit secrets.

Dual-mode devices (Classic CoD plus LE name/services) appear in both paired
tables with stack='dual' so they cannot vanish from either view.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import platform
import shutil
import socket
import sys
import time
import textwrap
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Protocol

BT_COD_MAJOR: dict[int, str] = {
    0x00: "Miscellaneous",
    0x01: "Computer",
    0x02: "Phone",
    0x03: "LAN/Network Access Point",
    0x04: "Audio/Video",
    0x05: "Peripheral",
    0x06: "Imaging",
    0x07: "Wearable",
    0x08: "Toy",
    0x09: "Health",
    0x1F: "Uncategorized",
}

BT_COD_PERIPHERAL_KBPTR: dict[int, str | None] = {
    0b00: None,
    0b01: "Keyboard",
    0b10: "Pointing device",
    0b11: "Keyboard/mouse combo",
}

BT_COD_PERIPHERAL_TYPE: dict[int, str | None] = {
    0x0: None,
    0x1: "Joystick",
    0x2: "Gamepad",
    0x3: "Remote control",
    0x4: "Sensing device",
    0x5: "Digitizer tablet",
    0x6: "Card reader",
    0x7: "Digital pen",
    0x8: "Handheld scanner",
    0x9: "Handheld gestural input",
}

UUID_SPP = "00001101-0000-1000-8000-00805f9b34fb"
UUID_DUN = "00001103-0000-1000-8000-00805f9b34fb"
UUID_HID = "00001124-0000-1000-8000-00805f9b34fb"
UUID_A2DP_SOURCE = "0000110a-0000-1000-8000-00805f9b34fb"
UUID_A2DP_SINK = "0000110b-0000-1000-8000-00805f9b34fb"
UUID_PANU = "00001115-0000-1000-8000-00805f9b34fb"
UUID_NAP = "00001116-0000-1000-8000-00805f9b34fb"
UUID_HOGP = "00001812-0000-1000-8000-00805f9b34fb"
UUID_GATT = "00001801-0000-1000-8000-00805f9b34fb"

HID_NAME_RE = re.compile(
    r"keyboard|keybd|mouse|hid|gamepad|controller",
    re.IGNORECASE,
)

BTHPORT_PARAMS = r"HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters"
BTHPORT_DEVICES = BTHPORT_PARAMS + r"\Devices"
BTHSERV_PANEL = r"HKLM\SYSTEM\CurrentControlSet\Services\bthserv\Parameters\BluetoothControlPanelTasks"
POLICY_BT = r"HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth"
KNOB_PATH = r"HKLM\SYSTEM\CurrentControlSet\Policies\Hardware\Bluetooth"
KNOB_NAME = "EnableMinimumEncryptionKeySize"

__version__ = "1.2.0"
SCHEMA_VERSION = "1.4"

IN_USE_WINDOW = timedelta(minutes=15)
DRIVER_STALE_MONTHS = 24

# --- 1.2 timestamp plausibility -----------------------------------------------
# Bond timestamps are decoded by a magnitude heuristic that cannot reliably tell a
# FILETIME from a unix-ms value, and a host may have written a bond while its clock
# was wrong. A decode landing outside this window is recorded as untrusted rather
# than asserted as fact.
MIN_PLAUSIBLE_EVENT = datetime(2000, 1, 1, tzinfo=timezone.utc)
CLOCK_SKEW_GRACE = timedelta(hours=24)

# last_seen_status values on BtPairedDevice
SEEN_OK = "ok"
SEEN_MISSING = "missing"
SEEN_UNPARSEABLE = "unparseable"
SEEN_IMPLAUSIBLE = "implausible"
SEEN_UNTRUSTED = frozenset({SEEN_MISSING, SEEN_UNPARSEABLE, SEEN_IMPLAUSIBLE})

# --- 1.3 collection status ------------------------------------------------------
# A source that could not be read is not a source that is absent. Conflating the two
# lets a non-elevated scan report a clean host and invent configuration findings.
ACCESS_READ = "read"        # source read successfully
ACCESS_ABSENT = "absent"    # source genuinely not present on this host
ACCESS_DENIED = "denied"    # source exists but was not readable (privilege)
ACCESS_ERROR = "error"      # source failed for some other reason
ACCESS_BLIND = frozenset({ACCESS_DENIED, ACCESS_ERROR})

# Findings that describe the scan itself rather than host posture carry no technique.
MITRE_NA = "n/a"

RED = "\033[31m"
GOLD = "\033[93m"
RESET = "\033[0m"
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
# Split a cell into (leading codes, plain text, trailing codes) so wrapping can work
# on the plain text and re-apply the colour to each produced line.
_ANSI_SPLIT_RE = re.compile(r"^((?:\033\[[0-9;]*m)*)(.*?)((?:\033\[[0-9;]*m)*)$", re.DOTALL)

# Table layout. Falls back to 120 columns when stdout is not a TTY (piped to a file
# or a ticket), which keeps output reproducible rather than terminal-dependent.
DEFAULT_TABLE_WIDTH = 120
MIN_COL_WIDTH = 8
# A single very long token must not be allowed to dictate the whole layout.
MAX_TOKEN_FLOOR = 64

BANNER_BLUEJACK = r"""
 ____  _             _            _
| __ )| |_   _  ___ (_) __ _  ___| | __
|  _ \| | | | |/ _ \| |/ _` |/ __| |/ /
| |_) | | |_| |  __/| | (_| | (__|   <
|____/|_|\__,_|\___|/ |\__,_|\___|_|\_\
                  |__/
     Bluejack.py
     Windows Bluetooth host audit  v{version}
     All timestamps are UTC
""".strip("\n").format(version=__version__)


class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


# --- 5.2 stable rule identifiers ------------------------------------------------
# A SIEM needs to dedupe a finding across scans, track when it clears, and let an
# operator suppress one it has accepted. MITRE techniques are too coarse for that
# (four techniques cover every rule here) and the human-readable target is not
# stable — renaming a paired device would otherwise mint a brand new finding.
RULE_ADAPTER_DRIVER_DATE = "BJ-ADP-DRIVER-DATE"
RULE_ADAPTER_DRIVER_STALE = "BJ-ADP-DRIVER-STALE"
RULE_PAIR_TRUSTED_UNAUTH = "BJ-PAIR-TRUSTED-UNAUTH"
RULE_PAIR_HID = "BJ-PAIR-HID-BOND"
RULE_PAIR_INPUT_UNCLASSIFIED = "BJ-PAIR-INPUT-UNCLASSIFIED"
RULE_HYG_STALE_BOND = "BJ-HYG-STALE-BOND"
RULE_HYG_INVENTORY_ROT = "BJ-HYG-INVENTORY-ROT"
RULE_CFG_DISCOVERABLE = "BJ-CFG-DISCOVERABLE"
RULE_CFG_AUTH_DISABLED = "BJ-CFG-AUTH-DISABLED"
RULE_ENC_KNOB_OFF = "BJ-ENC-KNOB-OFF"
RULE_PRF_HID_DISCOVERABLE = "BJ-PRF-HID-DISCOVERABLE"
RULE_PRF_PAN_OFFERED = "BJ-PRF-PAN-OFFERED"
RULE_PRF_SPP_DUN_OFFERED = "BJ-PRF-SPP-DUN-OFFERED"
RULE_POL_ALLOWBT_DRIFT = "BJ-POL-ALLOWBT-DRIFT"
RULE_POL_DISCOVERABLE_DRIFT = "BJ-POL-DISCOVERABLE-DRIFT"
RULE_DATA_BOND_TIMESTAMP = "BJ-DATA-BOND-TIMESTAMP"
RULE_DATA_POLICY_VALUE = "BJ-DATA-POLICY-VALUE"
RULE_SCAN_INCOMPLETE = "BJ-SCAN-INCOMPLETE"

TARGET_KEY_HOST = "host"


@dataclass
class Finding:
    rule_id: str
    phase: str
    target: str
    detail: str
    severity: Severity
    mitre_technique: str
    remediation: str
    # The stable identity of what the finding is about — a MAC, a registry path, an
    # InstanceId — as opposed to `target`, which is for humans and can change.
    target_key: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    finding_id: str = ""

    def __post_init__(self) -> None:
        if not self.finding_id:
            key = (self.target_key or self.target or "").strip().lower()
            digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
            self.finding_id = f"{self.rule_id}-{digest}"


@dataclass
class QuickSummary:
    hardware_present: str
    currently_in_use: str
    # Two independent facts, previously collapsed into one ambiguous "bluetooth_enabled".
    # adapter_enabled_pnp answers "is the device enabled in PnP" and is blind to the
    # Settings toggle; radio_enabled answers "is the software radio on". A soft-off
    # host is Yes / No, which is why the single field read as a contradiction.
    adapter_enabled_pnp: str
    radio_enabled: str
    disable_type: str
    bthserv_status: str
    discoverable: str
    authentication_required: str
    knob_class_mitigation: str
    trusted_without_authenticated: str
    # None (JSON null) when the bond store could not be enumerated. A blind scan must
    # not report 0, which reads as "this host has no pairings".
    classic_paired_count: int | None
    ble_paired_count: int | None
    dual_paired_count: int | None
    high_critical_count: int
    scan_complete: str = "Yes"


@dataclass
class BtAdapter:
    name: str
    instance_id: str | None = None
    status: str | None = None
    manufacturer: str | None = None
    driver_version: str | None = None
    driver_date: str | None = None
    hardware_id: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class BtPairedDevice:
    name: str
    mac: str
    stack: str
    category: str = "Uncategorized"
    cod: int | None = None
    cod_major: int | None = None
    trusted: bool | None = None
    authenticated: bool | None = None
    last_seen: str | None = None
    last_seen_status: str = SEEN_MISSING
    oui: str | None = None
    oui_vendor: str | None = None
    address_kind: str = "unknown"
    services: list[str] = field(default_factory=list)
    extras: dict[str, Any] = field(default_factory=dict)
    trusted_without_authenticated: bool = False


@dataclass
class BthportProfiles:
    hid: str = "Unknown"
    hogp: str = "Unknown"
    spp: str = "Unknown"
    dun: str = "Unknown"
    a2dp: str = "Unknown"
    pan: str = "Unknown"


@dataclass
class DisableState:
    disable_type: str
    why: str
    adapter_pnp_status: str
    radio_powered: str
    bthserv_status: str
    bthserv_start_type: str


@dataclass
class BtConfig:
    name: str
    value: str
    source: str | None = None


@dataclass
class ScanMeta:
    """Provenance for the scan itself.

    host_local_time and host_utc_offset answer "what time did this host think it was
    when the scan ran". Every other timestamp in the report is normalised to UTC,
    which is correct for comparison but useless when correlating against local-time
    Windows event logs, ticket timestamps, or an interview. A host whose clock or
    time zone is wrong is also itself a finding an analyst should be able to see.
    """

    schema_version: str
    tool_version: str
    started_utc: str
    completed_utc: str | None = None
    duration_s: float | None = None
    host_local_time: str | None = None
    host_utc_offset: str | None = None
    host_timezone: str | None = None
    host_name: str | None = None
    os_version: str | None = None
    python_version: str | None = None
    powershell_version: str | None = None
    privilege: str = "unknown"
    invocation: list[str] = field(default_factory=list)
    role: str | None = None
    stale_days: int | None = None


@dataclass
class BluejackReport:
    scan: ScanMeta
    summary: QuickSummary
    disable_state: DisableState
    knob_class_mitigation: dict[str, str]
    profiles: BthportProfiles
    adapters: list[BtAdapter]
    classic_devices: list[BtPairedDevice]
    ble_devices: list[BtPairedDevice]
    dual_devices: list[BtPairedDevice]
    configuration: list[BtConfig]
    findings: list[Finding]
    # ATT&CK context for the techniques this scan actually tagged, so the report
    # explains why a finding matters without anyone leaving the terminal.
    techniques: list[TechniqueProfile] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Diagnostics that are not failures: an alternate collection path succeeded, a
    # filter matched nothing and the fallback took over. Kept apart from errors so a
    # working fallback never marks the scan incomplete.
    notes: list[str] = field(default_factory=list)
    hygiene_rows: list[dict[str, str]] = field(default_factory=list)
    # source label -> ACCESS_READ / ACCESS_ABSENT / ACCESS_DENIED / ACCESS_ERROR.
    # Every Unknown in the report above should be explainable from this map.
    collection: dict[str, str] = field(default_factory=dict)


class PnpLike(Protocol):
    FriendlyName: str | None
    InstanceId: str | None
    Status: str | None
    Properties: dict[str, Any]


class ScanIO(Protocol):
    def enum_pnp_bluetooth(self, present_only: bool = True) -> list[Any]: ...
    def pnp_properties(self, instance_id: str) -> dict[str, Any]: ...
    def registry_key_exists(self, path: str) -> bool: ...
    def registry_list_subkeys(self, path: str) -> list[str]: ...
    def registry_get_values(self, path: str) -> dict[str, Any]: ...
    def registry_get_value(self, path: str, name: str) -> Any: ...
    def service_status(self, name: str) -> dict[str, str]: ...
    def radio_powered(self) -> str: ...
    def live_profile_flags(self) -> dict[str, str]: ...


def _decode_bt_name(raw: object) -> str:
    if raw is None:
        return "Unknown"
    if isinstance(raw, bytes):
        name = _bytes_to_text(raw)
        return name or "Unknown"
    if isinstance(raw, list) and raw and isinstance(raw[0], int):
        name = _bytes_to_text(bytes(raw))
        return name or "Unknown"
    text = str(raw).strip()
    return text or "Unknown"


def _bytes_to_text(raw: bytes) -> str:
    data = raw.strip(b"\x00")
    if len(data) >= 2 and data[1:2] == b"\x00":
        try:
            return data.decode("utf-16-le", errors="replace").strip("\x00").strip()
        except Exception:
            pass
    return data.decode("utf-8", errors="replace").strip("\x00").strip()


# --- 5.5 local OUI / address classification -------------------------------------
# No network, ever. The vendor table is whatever the operator supplies locally; the
# address-type classification below needs no table at all and is often the more
# useful signal, since it distinguishes an IEEE-assigned public address from a
# random or private BLE one.
OUI_FILE_ENV = "BLUEJACK_OUI_FILE"
OUI_FILE_NAME = "bluejack-oui.csv"

# Deliberately empty. Populating this from memory would mean asserting vendor
# attributions in a forensic report that nothing verifies. Supply a CSV instead —
# see load_oui_table() for the format and provenance.
OUI_SEED: dict[str, str] = {}

_ADDRESS_TYPES = {
    0b11: "random-static",
    0b01: "resolvable-private",
    0b00: "non-resolvable-private",
}


def _oui_of(mac: str) -> str | None:
    """First three octets, normalised to aa:bb:cc."""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(cleaned) < 6:
        return None
    return ":".join(cleaned[i : i + 2] for i in range(0, 6, 2)).lower()


def _address_kind(mac: str) -> str:
    """Classify a Bluetooth address without any lookup table.

    A public address is IEEE-assigned and its OUI means something. A BLE random
    address is not, so looking one up in a vendor table is meaningless and an
    unrecognised OUI on one is not suspicious. The top two bits of the most
    significant byte carry the random-address subtype; for public addresses the
    locally-administered bit is what matters.
    """
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(cleaned) < 12:
        return "unknown"
    msb = int(cleaned[0:2], 16)
    if msb & 0b00000010:
        # Locally administered: not drawn from an IEEE OUI assignment.
        return _ADDRESS_TYPES.get((msb >> 6) & 0b11, "locally-administered")
    return "public"


def load_oui_table(path: str | None = None) -> dict[str, str]:
    """Load oui,vendor pairs from a local CSV. Never fetches anything.

    Format: one `aa:bb:cc,Vendor Name` pair per line; `#` comments and blank lines
    are ignored. Separators in the OUI are optional. Resolution order is the
    explicit path, then $BLUEJACK_OUI_FILE, then bluejack-oui.csv beside this module.

    Generate one from the IEEE registry yourself; Bluejack will not do it for you,
    because a scanner that reaches the network is a different product class.
    """
    table = dict(OUI_SEED)
    candidates = [
        path,
        os.environ.get(OUI_FILE_ENV),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), OUI_FILE_NAME),
    ]
    for candidate in candidates:
        if not candidate or not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8-sig", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(",", 1)
                    if len(parts) != 2:
                        continue
                    oui = _oui_of(parts[0])
                    vendor = parts[1].strip().strip('"')
                    if oui and vendor:
                        table[oui] = vendor
        except OSError:
            continue
        break
    return table


# What each collection label actually probed. "absent" against one of these means the
# key was read successfully and the value simply is not present on this host — a
# result, not a collection failure.
COLLECTION_SOURCES: dict[str, str] = {
    "pnp_adapters": "Win32_PnPEntity where PNPClass='Bluetooth'",
    "collector": "batched PowerShell snapshot (PnP, drivers, services, BTHENUM)",
    "bthport_parameters": r"HKLM\...\Services\BTHPORT\Parameters (key)",
    "bthport_devices": r"HKLM\...\BTHPORT\Parameters\Devices (bond store)",
    "knob_policy": r"HKLM\...\Policies\Hardware\Bluetooth\EnableMinimumEncryptionKeySize",
    "policy_manager": r"HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth (key)",
    "authentication": r"BTHPORT\Parameters -> Authentication (value)",
    "discoverability": r"PolicyManager -> AllowDiscoverableMode (documented); BTHPORT\Parameters (local, unconfirmed)",
    "radio_panel": r"bthserv\Parameters\BluetoothControlPanelTasks -> state (value)",
}

ACCESS_LEGEND = {
    ACCESS_READ: "read successfully",
    ACCESS_ABSENT: "readable, but not set on this host",
    ACCESS_DENIED: "exists but could not be read (privilege)",
    ACCESS_ERROR: "failed for another reason",
}

# Value names Bluejack probes locally that Microsoft does not document as living
# there. They are read because they are cheap and harmless, but an "absent" result
# is expected rather than informative. See README > Known limitations.
UNCONFIRMED_LOCAL_VALUES = {"authentication", "discoverability"}


# --- ATT&CK technique context ---------------------------------------------------
# Which known actors are documented as using the techniques Bluejack tags. This is a
# seed list, not an authority: ATT&CK group-technique mappings change between
# releases, and a wrong attribution in a security report is worse than none. Every
# entry carries its ATT&CK group ID and every technique carries its URL so a reader
# can verify in one click. Override the whole thing with a local file rather than
# trusting what ships here — see load_technique_map().
ATTACK_SEED_NOTE = (
    "Seed list — verify against attack.mitre.org before relying on it. "
    "Actor lists are illustrative, not exhaustive."
)
ATTACK_FILE_ENV = "BLUEJACK_ATTACK_FILE"
ATTACK_FILE_NAME = "bluejack-attack.json"


@dataclass
class TechniqueProfile:
    technique: str
    name: str
    url: str
    actors: list[str] = field(default_factory=list)
    note: str = ""


TECHNIQUE_SEED: dict[str, TechniqueProfile] = {
    "T1120": TechniqueProfile(
        technique="T1120",
        name="Peripheral Device Discovery",
        url="https://attack.mitre.org/techniques/T1120/",
        actors=["Equation (G0020)", "Gamaredon Group (G0047)", "APT37 (G0067)", "Turla (G0010)"],
        note="A discoverable radio and a stale bond inventory are both peripheral-enumeration surface.",
    ),
    "T1200": TechniqueProfile(
        technique="T1200",
        name="Hardware Additions",
        url="https://attack.mitre.org/techniques/T1200/",
        actors=["DarkVishnya (G0105)"],
        note="DarkVishnya is the canonical case: physical devices planted on-premises in bank offices.",
    ),
    "T1056.001": TechniqueProfile(
        technique="T1056.001",
        name="Input Capture: Keylogging",
        url="https://attack.mitre.org/techniques/T1056/001/",
        actors=[
            "APT28 (G0007)",
            "Lazarus Group (G0032)",
            "OilRig (G0049)",
            "MuddyWater (G0069)",
            "Darkhotel (G0012)",
        ],
        note="A rogue or unauthenticated HID bond is a keylogging position that needs no malware.",
    ),
    "T1040": TechniqueProfile(
        technique="T1040",
        name="Network Sniffing",
        url="https://attack.mitre.org/techniques/T1040/",
        actors=["APT28 (G0007)", "Sandworm Team (G0034)", "Kimsuky (G0094)"],
        note=(
            "The KNOB-class weakness (CVE-2019-9506) lets an attacker negotiate a 1-byte "
            "encryption key and brute-force the session, turning an encrypted link into a "
            "sniffable one. EnableMinimumEncryptionKeySize is the mitigation."
        ),
    ),
}


def load_technique_map(path: str | None = None) -> dict[str, TechniqueProfile]:
    """Load technique context from a local JSON file, falling back to the seed.

    Format: {"T1040": {"name": ..., "url": ..., "actors": [...], "note": ...}}.
    Resolution order: explicit path, $BLUEJACK_ATTACK_FILE, then bluejack-attack.json
    beside this module. Regenerate from the ATT&CK STIX bundle yourself; Bluejack
    does not fetch anything.
    """
    table = {k: TechniqueProfile(**vars(v)) for k, v in TECHNIQUE_SEED.items()}
    for candidate in (
        path,
        os.environ.get(ATTACK_FILE_ENV),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ATTACK_FILE_NAME),
    ):
        if not candidate or not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8-sig") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            for technique, entry in data.items():
                if not isinstance(entry, dict):
                    continue
                table[technique] = TechniqueProfile(
                    technique=technique,
                    name=str(entry.get("name") or technique),
                    url=str(entry.get("url") or ""),
                    actors=[str(a) for a in (entry.get("actors") or [])],
                    note=str(entry.get("note") or ""),
                )
        break
    return table


def _actor_summary(profile: TechniqueProfile | None, limit: int = 3) -> str:
    if profile is None or not profile.actors:
        return "-"
    shown = [a.split(" (")[0] for a in profile.actors[:limit]]
    extra = len(profile.actors) - len(shown)
    return ", ".join(shown) + (f" +{extra}" if extra > 0 else "")


def _format_mac(mac: str) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(cleaned) == 12:
        return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).lower()
    return mac


def _norm_guid(value: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", value or "").lower()


def _guid_eq(value: str, canonical: str) -> bool:
    return _norm_guid(value) == _norm_guid(canonical)


def _as_guid_list(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, bytes):
        text = _bytes_to_text(raw)
        parts = re.split(r"[;,\s]+", text)
        return [p for p in parts if p]
    if isinstance(raw, list):
        out: list[str] = []
        for item in raw:
            if isinstance(item, int):
                continue
            out.extend(_as_guid_list(item) if not isinstance(item, str) else [item])
        return [str(x) for x in out if str(x).strip()]
    text = str(raw).strip()
    if not text:
        return []
    if text.startswith("{") or "-" in text:
        return [p for p in re.split(r"[;,\s]+", text) if p]
    return [text]


def _policy_flag(raw: Any) -> tuple[bool | None, bool]:
    """Coerce a policy value to (flag, unrecognized).

    The four policy reads used bare `== 1` / `== 0` comparisons while _truthy() sat
    unused, so a value stored as REG_BINARY or REG_SZ read as Unknown and its finding
    never fired. Everything now goes through _truthy(), which understands DWORD,
    REG_SZ, REG_BINARY and bool, while keeping None for genuinely unknown. The second
    element distinguishes "value present but not a recognisable boolean" from
    "value absent", which the caller must not treat as a configured state.
    """
    if raw is None:
        return None, False
    flag = _truthy(raw)
    return flag, flag is None


def _truthy(raw: object) -> bool | None:
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(int(raw))
    if isinstance(raw, bytes):
        if not raw:
            return None
        return raw not in {b"\x00", b"\x00" * len(raw)}
    token = str(raw).strip().lower()
    if token in {"1", "true", "yes", "on"}:
        return True
    if token in {"0", "false", "no", "off", ""}:
        return False
    return None


def _filetime_to_dt(raw: int) -> datetime | None:
    if raw <= 0:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=raw // 10)
    except OverflowError:
        return None


def _parse_timestamp(raw: object) -> tuple[datetime | None, str]:
    if raw is None:
        return None, "missing"
    if isinstance(raw, datetime):
        dt = raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
        return dt, "datetime"
    if isinstance(raw, bytes):
        if len(raw) >= 8:
            raw = int.from_bytes(raw[:8], "little", signed=False)
        else:
            return None, "unparseable"
    if isinstance(raw, list) and raw and all(isinstance(x, int) for x in raw):
        try:
            raw = int.from_bytes(bytes(raw[:8]), "little", signed=False)
        except Exception:
            return None, "unparseable"
    if isinstance(raw, (int, float)):
        num = int(raw)
        if num > 10**16:
            dt = _filetime_to_dt(num)
            return dt, "filetime"
        if num > 10**12:
            dt = datetime.fromtimestamp(num / 1000.0, tz=timezone.utc)
            return dt, "unix_ms"
        if num > 10**8:
            dt = datetime.fromtimestamp(num, tz=timezone.utc)
            return dt, "unix"
        return None, "unparseable"
    text = str(raw).strip()
    if not text:
        return None, "missing"
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%m/%d/%Y"):
        try:
            dt = datetime.strptime(text.replace("Z", ""), fmt.replace("Z", ""))
            return dt.replace(tzinfo=timezone.utc), "string"
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt, "isoformat"
    except ValueError:
        return None, "unparseable"


def _parse_driver_date(raw: object) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw.date().isoformat()
    text = str(raw).strip()
    # CIM_DATETIME (DMTF): yyyymmddHHMMSS.mmmmmmsUUU, e.g. 20250201000000.000000-000.
    # Reaches us when a driver date arrives from a raw WMI property rather than a
    # formatted one; without this it falls through to "unparseable" and produces a
    # spurious "driver date unavailable" Info finding.
    m = re.match(r"^(\d{4})(\d{2})(\d{2})\d{6}\.\d{6}[+-]\d{3}$", text)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    dt, kind = _parse_timestamp(raw)
    if dt and kind != "unparseable":
        return dt.date().isoformat()
    m = re.search(r"(20\d{2}|19\d{2})[-/](\d{1,2})[-/](\d{1,2})", text)
    if m:
        return f"{int(m.group(1)):04d}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    m = re.search(r"(\d{1,2})[-/](\d{1,2})[-/](20\d{2}|19\d{2})", text)
    if m:
        return f"{int(m.group(3)):04d}-{int(m.group(1)):02d}-{int(m.group(2)):02d}"
    return text or None


def _first_hwid(raw: object) -> str | None:
    """First hardware id as a string.

    Defensive against PowerShell's {"value": [...], "Count": n} collection shape. The
    backend unwraps it, but this is the render path for whatever the backend hands
    over, and a dict falling through to str() printed a Python repr in the report.
    """
    if raw is None:
        return None
    if isinstance(raw, dict):
        for key in ("value", "Value"):
            if key in raw:
                return _first_hwid(raw[key])
        return None
    if isinstance(raw, (list, tuple)):
        for item in raw:
            found = _first_hwid(item)
            if found:
                return found
        return None
    text = str(raw).strip()
    return text or None


def _cod_major(cod: object) -> int | None:
    if isinstance(cod, bool) or not isinstance(cod, int):
        if isinstance(cod, bytes) and len(cod) >= 2:
            cod = int.from_bytes(cod[:4].ljust(4, b"\x00"), "little")
        else:
            return None
    return (int(cod) >> 8) & 0x1F


def _cod_minor_peripheral(cod: int) -> str | None:
    """Decode the Peripheral-major minor field.

    For major class 0x05 the 6-bit minor field is two subfields, not one value:
    bits 4-5 are the keyboard / pointing-device flags and bits 0-3 are the device
    type. The previous flat lookup only matched when the device-type nibble was
    zero, so a keyboard reporting any device type at all fell through to the generic
    "Peripheral" label.
    """
    minor = (cod >> 2) & 0x3F
    kbptr = BT_COD_PERIPHERAL_KBPTR.get((minor >> 4) & 0x03)
    dtype = BT_COD_PERIPHERAL_TYPE.get(minor & 0x0F)
    if kbptr and dtype:
        return f"{kbptr} ({dtype})"
    return kbptr or dtype or "Uncategorized peripheral"


def _services_from_values(vals: dict[str, Any]) -> list[str]:
    collected: list[str] = []
    for key in ("Services", "Service", "SupportedServices", "SDP", "UUIDs"):
        collected.extend(_as_guid_list(vals.get(key)))
    out: list[str] = []
    seen: set[str] = set()
    for item in collected:
        n = _norm_guid(item)
        if n and n not in seen:
            seen.add(n)
            out.append(item)
    return out


def _has_uuid(services: list[str], canonical: str) -> bool:
    return any(_guid_eq(s, canonical) for s in services)


def _is_hid_device(dev: BtPairedDevice) -> bool:
    if dev.cod_major == 5:
        return True
    return _has_uuid(dev.services, UUID_HID) or _has_uuid(dev.services, UUID_HOGP)


_LE_MARKER_KEYS = frozenset({"le", "ledevice", "isdevicetypele", "lename", "leaddresstype"})


def _classify_stack(
    vals: dict[str, Any], services: list[str], cod: object
) -> tuple[str, list[str]]:
    """Classify a bond as classic / ble / dual and report the signals that decided it.

    Precedence note: the previous form was

        has_classic = isinstance(cod, int) or bool(vals.get("Name")) and not le_name

    which parses as ``cod or (Name and not le_name)`` because ``and`` binds tighter
    than ``or``. A bond carrying both Name and LEName but no COD — the normal shape
    for a dual-mode peripheral — evaluated False and was filed BLE-only, so it
    disappeared from the Classic table. The ``and not le_name`` clause is gone: a
    classic signal now stands on its own regardless of what LE signals are present.

    This deliberately widens ``dual``. A BLE bond that happens to carry a Name is now
    listed in both tables rather than one. For an audit tool that is the safe
    direction of error, and the returned evidence list plus the ``stack`` field let an
    analyst see exactly which signal fired.
    """
    le_ev: list[str] = []
    for key in vals:
        if key.lower() not in _LE_MARKER_KEYS:
            continue
        raw = vals.get(key)
        # Preserve the original guard: an explicitly false marker is not a marker.
        if raw in (None, 0, "", b"") or _truthy(raw) is False:
            continue
        le_ev.append(f"le:{key}")
    if _has_uuid(services, UUID_HOGP):
        le_ev.append("le:uuid-HOGP")
    if _has_uuid(services, UUID_GATT):
        le_ev.append("le:uuid-GATT")

    classic_ev: list[str] = []
    if isinstance(cod, int):
        classic_ev.append("classic:COD")
    if vals.get("Name"):
        classic_ev.append("classic:Name")
    for uuid, label in (
        (UUID_HID, "HID"),
        (UUID_SPP, "SPP"),
        (UUID_DUN, "DUN"),
        (UUID_A2DP_SINK, "A2DP-sink"),
        (UUID_A2DP_SOURCE, "A2DP-source"),
    ):
        if _has_uuid(services, uuid):
            classic_ev.append(f"classic:uuid-{label}")

    evidence: list[str] = []
    for item in le_ev + classic_ev:
        if item not in evidence:
            evidence.append(item)

    if le_ev and classic_ev:
        return "dual", evidence
    if le_ev:
        return "ble", evidence
    return "classic", evidence


def _plausible_event(dt: datetime | None, now: datetime) -> bool:
    """True if a decoded bond timestamp could describe a real event on this host."""
    if dt is None:
        return False
    return MIN_PLAUSIBLE_EVENT <= dt <= now + CLOCK_SKEW_GRACE


def _seen_status(raw_kind: str, dt: datetime | None, now: datetime) -> str:
    """Map a parse result to a trust status for last-seen driven logic."""
    if dt is None or raw_kind in {"missing", "unparseable"}:
        return SEEN_MISSING if raw_kind == "missing" else SEEN_UNPARSEABLE
    if not _plausible_event(dt, now):
        return SEEN_IMPLAUSIBLE
    return SEEN_OK


_VT_STATE: bool | None = None
_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
_STD_OUTPUT_HANDLE = -11


def _enable_windows_vt() -> bool:
    """Turn on ANSI handling in the console, returning whether colour is usable.

    Legacy conhost (the classic Command Prompt / PowerShell window) does not
    interpret ANSI escapes unless ENABLE_VIRTUAL_TERMINAL_PROCESSING is set on the
    output handle. Without this the escapes are printed literally, which is why the
    gold KNOB row rendered as "<-[93mKNOB-class ... Off<-[0m". Windows Terminal
    enables VT by default; conhost does not. Result is cached per process.
    """
    global _VT_STATE
    if _VT_STATE is not None:
        return _VT_STATE
    if sys.platform != "win32":
        _VT_STATE = True
        return _VT_STATE
    _VT_STATE = False
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel32.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
        kernel32.SetConsoleMode.argtypes = [ctypes.c_void_p, wintypes.DWORD]

        handle = kernel32.GetStdHandle(_STD_OUTPUT_HANDLE)
        if not handle or handle == ctypes.c_void_p(-1).value:
            return _VT_STATE
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return _VT_STATE  # redirected to a file or pipe; no console to configure
        if mode.value & _ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            _VT_STATE = True
        else:
            _VT_STATE = bool(
                kernel32.SetConsoleMode(
                    handle, mode.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING
                )
            )
    except Exception:  # noqa: BLE001 - colour is cosmetic, never fatal
        _VT_STATE = False
    return _VT_STATE


def _color_enabled(force_off: bool = False) -> bool:
    if force_off:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if not bool(getattr(sys.stdout, "isatty", lambda: False)()):
        return False
    # A TTY is not enough on Windows: emit escapes only if the console will honour them.
    return _enable_windows_vt()


def _paint(text: str, color: str, enabled: bool) -> str:
    if not enabled or not text:
        return text
    return f"{color}{text}{RESET}"


def _red(text: str, enabled: bool) -> str:
    return _paint(text, RED, enabled)


def _gold(text: str, enabled: bool) -> str:
    return _paint(text, GOLD, enabled)


def _default_backend() -> ScanIO:
    from _windows_bt import WindowsBackend

    return WindowsBackend()


def _safe(on_error: str, errors: list[str], label: str, fn, default):
    try:
        return fn()
    except Exception as exc:
        if on_error == "raise":
            raise
        errors.append(f"{label}: {exc}")
        return default


def classify_access_error(exc: BaseException) -> str:
    """Map a registry failure to a collection status.

    winreg raises OSError subclasses selected from the Windows error code, so
    ERROR_ACCESS_DENIED (5) arrives as PermissionError and ERROR_FILE_NOT_FOUND (2)
    as FileNotFoundError. The winerror/errno checks are belt-and-braces for backends
    that raise a bare OSError.
    """
    if isinstance(exc, PermissionError):
        return ACCESS_DENIED
    if isinstance(exc, FileNotFoundError):
        return ACCESS_ABSENT
    if isinstance(exc, OSError):
        winerror = getattr(exc, "winerror", None)
        if winerror == 5:
            return ACCESS_DENIED
        if winerror in (2, 3):
            return ACCESS_ABSENT
        import errno as _errno

        if exc.errno == _errno.EACCES:
            return ACCESS_DENIED
        if exc.errno == _errno.ENOENT:
            return ACCESS_ABSENT
    return ACCESS_ERROR


class _RegistrySource:
    """Reads registry keys once each, preserving why a read failed.

    Replaces the ``registry_key_exists()``-then-``registry_get_value()`` pattern. Both
    of those backend methods swallow OSError and answer False/None, which made an
    ACL'd key indistinguishable from an unset one — so a non-elevated scan reported a
    clean host and raised configuration findings from its own blindness.
    ``registry_get_values()`` propagates, so the distinction survives without any
    change to the backend.
    """

    def __init__(
        self,
        backend: ScanIO,
        on_error: str,
        errors: list[str],
        collection: dict[str, str],
    ) -> None:
        self._be = backend
        self._on_error = on_error
        self._errors = errors
        self._collection = collection
        self._cache: dict[str, tuple[dict[str, Any] | None, str]] = {}

    def key(self, path: str, label: str | None = None) -> tuple[dict[str, Any] | None, str]:
        """Read every value under ``path``. Returns (values or None, status)."""
        if path in self._cache:
            values, status = self._cache[path]
        else:
            try:
                raw = self._be.registry_get_values(path)
                values, status = dict(raw or {}), ACCESS_READ
            except Exception as exc:  # noqa: BLE001 - status is derived below
                if self._on_error == "raise":
                    raise
                status = classify_access_error(exc)
                values = None
                if status == ACCESS_DENIED:
                    self._errors.append(f"{path}: access denied ({exc})")
                elif status == ACCESS_ERROR:
                    self._errors.append(f"{path}: {exc}")
            self._cache[path] = (values, status)
        if label:
            self._collection[label] = status
        return values, status

    def value(self, path: str, name: str, label: str | None = None) -> tuple[Any, str]:
        """Read one value. Status distinguishes a missing value from an unreadable key."""
        values, status = self.key(path, label)
        if status != ACCESS_READ or values is None:
            return None, status
        if name not in values or values[name] is None:
            return None, ACCESS_ABSENT
        return values[name], ACCESS_READ


def _profile_state(supported: list[str], unsupported: list[str], *uuids: str) -> str:
    in_un = any(_has_uuid(unsupported, u) for u in uuids)
    in_su = any(_has_uuid(supported, u) for u in uuids)
    if in_un:
        return "No"
    if in_su:
        return "Yes"
    return "Unknown"


def _merge_profile(registry_state: str, live_state: str | None) -> str:
    if registry_state == "No":
        return "No"
    if registry_state == "Yes":
        return "Yes"
    if live_state == "Yes":
        return "Yes"
    return "Unknown"


def _finalize_profile(
    name: str,
    registry_state: str,
    live_state: str | None,
    *,
    radio_powered: str,
    disable_type: str,
) -> str:
    """Offered now. Soft/hard off → No. Missing lists stay Unknown unless a live object exists."""
    if disable_type == "Hard" or radio_powered == "Off":
        return "No"
    return _merge_profile(registry_state, live_state)


def _decide_disable(
    adapter_pnp_status: str,
    radio_powered: str,
    bthserv_status: str,
) -> tuple[str, str]:
    status = adapter_pnp_status
    if status == "Absent":
        return "Hard", "No Bluetooth adapter is present, so the stack is hard-unavailable."
    if status == "Disabled":
        return "Hard", "The Bluetooth adapter is disabled in PnP (hard disable)."
    if status == "Error":
        return "Unknown", "Adapter PnP status is Error; disable type cannot be asserted."
    if status in {"OK", "Present"} and radio_powered == "Off":
        return (
            "Soft",
            "Adapter is present but the software radio is off (Settings toggle / Radio API).",
        )
    if status in {"OK", "Present"} and radio_powered == "On" and bthserv_status == "On":
        return "None", "Adapter is present, radio is on, and bthserv is running."
    if status in {"OK", "Present"} and radio_powered == "On" and bthserv_status == "Off":
        return (
            "Unknown",
            "Adapter and radio look live but bthserv is not running; signals contradict.",
        )
    if status in {"OK", "Present"} and radio_powered == "Unknown":
        return (
            "Unknown",
            "Adapter is present but the Settings/software radio toggle could not be read.",
        )
    return "Unknown", "Adapter, radio, and service signals do not form a clean disable type."


def _panel_state_to_radio(raw: object) -> str | None:
    if raw in (1, True) or str(raw).strip() in {"1", "0x1"}:
        return "On"
    if raw in (0, False) or str(raw).strip() in {"0", "0x0"}:
        return "Off"
    return None


def _resolve_radio_power(reg: "_RegistrySource", hinted: str) -> str:
    if hinted in {"On", "Off"}:
        return hinted
    raw, _status = reg.value(BTHSERV_PANEL, "state", "radio_panel")
    mapped = _panel_state_to_radio(raw)
    if mapped:
        return mapped
    return "Unknown"


def _utc_offset_label(dt: datetime) -> str:
    """Format a UTC offset as +HH:MM / -HH:MM. 'Z' would hide a zero-offset host."""
    offset = dt.utcoffset()
    if offset is None:
        return "unknown"
    total = int(offset.total_seconds())
    sign = "-" if total < 0 else "+"
    total = abs(total)
    return f"{sign}{total // 3600:02d}:{(total % 3600) // 60:02d}"


def _process_privilege() -> str:
    """Best-effort elevation check. Cosmetic only; the collection map is authoritative."""
    if sys.platform != "win32":
        return "n/a (non-Windows)"
    try:
        import ctypes

        return "elevated" if ctypes.windll.shell32.IsUserAnAdmin() else "standard"
    except Exception:  # noqa: BLE001
        return "unknown"


def _build_scan_meta(scan_now: datetime, role: str, stale_days: int) -> ScanMeta:
    local = scan_now.astimezone()
    host_name = None
    try:
        host_name = platform.node() or socket.gethostname()
    except Exception:  # noqa: BLE001
        pass
    os_version = None
    try:
        os_version = f"{platform.system()} {platform.release()} {platform.version()}".strip()
    except Exception:  # noqa: BLE001
        pass
    return ScanMeta(
        schema_version=SCHEMA_VERSION,
        tool_version=__version__,
        started_utc=_format_utc(scan_now) or scan_now.isoformat(),
        host_local_time=local.isoformat(timespec="seconds"),
        host_utc_offset=_utc_offset_label(local),
        host_timezone=local.tzname(),
        host_name=host_name,
        os_version=os_version,
        python_version=platform.python_version(),
        privilege=_process_privilege(),
        invocation=list(sys.argv[1:]),
        role=role,
        stale_days=stale_days,
    )


def get_bluetooth_status(
    *,
    on_error: str = "continue",
    stale_days: int = 90,
    role: str = "workstation",
    backend: ScanIO | None = None,
    now: datetime | None = None,
) -> BluejackReport:
    """Primary entry point. Mirrors the reference function after decoupling."""
    if on_error not in {"raise", "continue"}:
        raise ValueError("on_error must be 'raise' or 'continue'")
    role = (role or "workstation").lower()
    be = backend or _default_backend()
    scan_now = now or datetime.now(timezone.utc)
    if scan_now.tzinfo is None:
        scan_now = scan_now.replace(tzinfo=timezone.utc)

    scan_meta = _build_scan_meta(scan_now, role, stale_days)
    _monotonic_start = time.monotonic()

    errors: list[str] = []
    findings: list[Finding] = []
    adapters: list[BtAdapter] = []
    collection: dict[str, str] = {}
    reg = _RegistrySource(be, on_error, errors, collection)

    _errs_before = len(errors)
    raw_adapters = _safe(
        on_error,
        errors,
        "adapter-enum",
        lambda: [
            d
            for d in be.enum_pnp_bluetooth(present_only=True)
            if getattr(d, "FriendlyName", None)
            and "Enumerator" not in str(getattr(d, "FriendlyName", ""))
        ],
        [],
    )
    collection["pnp_adapters"] = ACCESS_ERROR if len(errors) > _errs_before else ACCESS_READ

    # The backend collects its snapshot lazily, so by now it has run. Its diagnostics
    # were previously written to an attribute nobody read, which made "check
    # snapshot_errors" advice impossible to follow.
    notes: list[str] = list(getattr(be, "snapshot_notes", None) or [])
    _snapshot_errors = list(getattr(be, "snapshot_errors", None) or [])
    if _snapshot_errors:
        errors.extend(_snapshot_errors)
        collection["collector"] = ACCESS_ERROR
    else:
        collection["collector"] = ACCESS_READ
    scan_meta.powershell_version = _safe(
        on_error, errors, "powershell-version",
        lambda: getattr(be, "powershell_version", lambda: None)(), None,
    )

    for adapter in raw_adapters:
        props = dict(getattr(adapter, "Properties", None) or {})
        instance_id = getattr(adapter, "InstanceId", None)
        if instance_id and not props:
            extra = _safe(
                on_error,
                errors,
                f"pnp-props:{instance_id}",
                lambda iid=instance_id: be.pnp_properties(iid),
                {},
            )
            props.update(extra or {})
        driver_date = _parse_driver_date(props.get("DEVPKEY_Device_DriverDate"))
        hardware_id = _first_hwid(props.get("DEVPKEY_Device_HardwareIds"))
        item = BtAdapter(
            name=adapter.FriendlyName,
            instance_id=instance_id,
            status=str(getattr(adapter, "Status", None) or "") or None,
            manufacturer=props.get("DEVPKEY_Device_Manufacturer")
            if props.get("DEVPKEY_Device_Manufacturer") is None
            or isinstance(props.get("DEVPKEY_Device_Manufacturer"), str)
            else str(props.get("DEVPKEY_Device_Manufacturer")),
            driver_version=(
                None
                if props.get("DEVPKEY_Device_DriverVersion") is None
                else str(props.get("DEVPKEY_Device_DriverVersion"))
            ),
            driver_date=driver_date,
            hardware_id=hardware_id,
            extras={},
        )
        adapters.append(item)
        if driver_date is None:
            findings.append(
                Finding(
                    rule_id=RULE_ADAPTER_DRIVER_DATE,
                    phase="Adapter",
                    target=item.name,
                    target_key=instance_id or item.name,
                    detail="driver date unavailable",
                    severity=Severity.INFO,
                    mitre_technique="T1200",
                    remediation="Confirm the Bluetooth driver is signed and current via Device Manager / Windows Update.",
                    evidence={"instance_id": instance_id, "hardware_id": hardware_id},
                )
            )
        else:
            try:
                parsed = datetime.strptime(driver_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                cutoff = scan_now - timedelta(days=int(DRIVER_STALE_MONTHS * 30.44))
                if parsed < cutoff:
                    findings.append(
                        Finding(
                            rule_id=RULE_ADAPTER_DRIVER_STALE,
                            phase="Adapter",
                            target=item.name,
                            target_key=instance_id or item.name,
                            detail=(
                                "Bluetooth adapter driver is older than 24 months "
                                f"(manufacturer={item.manufacturer}, version={item.driver_version}, "
                                f"date={driver_date}, hardware_id={hardware_id})"
                            ),
                            severity=Severity.MEDIUM,
                            mitre_technique="T1200",
                            remediation=(
                                "Update the Bluetooth adapter driver from the OEM or Windows Update; "
                                "replace the dongle if the OEM no longer ships updates."
                            ),
                            evidence={
                                "manufacturer": item.manufacturer,
                                "driver_version": item.driver_version,
                                "driver_date": driver_date,
                                "hardware_id": hardware_id,
                            },
                        )
                    )
            except ValueError:
                findings.append(
                    Finding(
                        rule_id=RULE_ADAPTER_DRIVER_DATE,
                        phase="Adapter",
                        target=item.name,
                        target_key=instance_id or item.name,
                        detail="driver date unavailable",
                        severity=Severity.INFO,
                        mitre_technique="T1200",
                        remediation="Confirm the Bluetooth driver is signed and current via Device Manager / Windows Update.",
                        evidence={"driver_date_raw": driver_date},
                    )
                )

    if not adapters:
        adapters.append(
            BtAdapter(
                name="(No Bluetooth adapters detected)",
                status="Absent",
            )
        )

    # One read of BTHPORT\Parameters serves DID, Authentication and discoverability.
    did_vals, bthport_status = reg.key(BTHPORT_PARAMS, "bthport_parameters")
    did_vals = did_vals or {}
    if did_vals:
        for adapter in adapters:
            if adapter.status == "Absent":
                continue
            adapter.extras.update(
                {
                    k: did_vals.get(k)
                    for k in ("DIDVendorID", "DIDProductID", "DIDVersion", "DIDVendorIDSource")
                    if k in did_vals
                }
            )

    paired: list[BtPairedDevice] = []
    bonds_unreadable = 0
    oui_table = _safe(on_error, errors, "oui-table", load_oui_table, {})

    def _load_paired() -> str:
        """Enumerate bonds. Returns the collection status for the bond store."""
        nonlocal bonds_unreadable
        try:
            key_paths = be.registry_list_subkeys(BTHPORT_DEVICES)
        except Exception as exc:  # noqa: BLE001 - status is derived below
            if on_error == "raise":
                raise
            status = classify_access_error(exc)
            if status == ACCESS_DENIED:
                errors.append(f"{BTHPORT_DEVICES}: access denied ({exc})")
            elif status == ACCESS_ERROR:
                errors.append(f"{BTHPORT_DEVICES}: {exc}")
            return status
        for key_path in key_paths:
            mac = key_path.rsplit("\\", 1)[-1]
            # Isolate per-bond faults. Previously one ACL'd subkey aborted the whole
            # enumeration, silently truncating the bond list at that point.
            try:
                vals = be.registry_get_values(key_path)
            except Exception as exc:  # noqa: BLE001
                if on_error == "raise":
                    raise
                bonds_unreadable += 1
                errors.append(f"{key_path}: {exc}")
                continue
            services = _services_from_values(vals)
            classic_name = _decode_bt_name(vals.get("Name")) if vals.get("Name") is not None else None
            le_name = _decode_bt_name(vals.get("LEName") or vals.get("LeName")) if (
                vals.get("LEName") is not None or vals.get("LeName") is not None
            ) else None
            cod = vals.get("COD")
            if isinstance(cod, bytes) and len(cod) >= 2:
                cod = int.from_bytes(cod[:4].ljust(4, b"\x00"), "little")
            major = _cod_major(cod) if isinstance(cod, int) else None
            category = BT_COD_MAJOR.get(major, "Uncategorized") if major is not None else "Uncategorized"
            if major == 5 and isinstance(cod, int):
                minor_label = _cod_minor_peripheral(cod)
                if minor_label:
                    category = minor_label
            stack, stack_evidence = _classify_stack(
                vals, services, cod if isinstance(cod, int) else None
            )
            if stack == "ble":
                device_name = le_name or classic_name or "Unknown"
            elif stack == "classic":
                device_name = classic_name or le_name or "Unknown"
            else:
                device_name = classic_name or le_name or "Unknown"
            trusted = _truthy(vals.get("Trusted"))
            authenticated = _truthy(vals.get("Authenticated"))
            last_raw = None
            last_field = None
            for field_name in ("LastSeen", "LastConnected", "LastConnect", "LastSeenTime"):
                if vals.get(field_name) is not None:
                    last_raw = vals.get(field_name)
                    last_field = field_name
                    break
            last_dt, last_kind = _parse_timestamp(last_raw)
            seen_status = _seen_status(last_kind, last_dt, scan_now)
            # The decoded value is still reported so an analyst can see it, but
            # last_seen_status governs every decision made from it.
            last_seen_s = _format_utc(last_dt) if last_dt else None
            tw_auth = bool(trusted is True and authenticated is not True)
            formatted = _format_mac(mac)
            extras: dict[str, Any] = {
                "last_seen_field": last_field,
                "last_seen_parse": last_kind,
                "stack_evidence": stack_evidence,
            }
            if last_kind == "missing":
                extras["last_seen_field"] = None
            if seen_status == SEEN_IMPLAUSIBLE:
                extras["last_seen_implausible"] = True
                extras["last_seen_raw"] = repr(last_raw)[:120]
            dev = BtPairedDevice(
                name=device_name,
                mac=formatted,
                stack=stack,
                category=category,
                cod=cod if isinstance(cod, int) else None,
                cod_major=major,
                trusted=trusted,
                authenticated=authenticated,
                last_seen=last_seen_s,
                last_seen_status=seen_status,
                oui=_oui_of(formatted),
                oui_vendor=oui_table.get(_oui_of(formatted) or ""),
                address_kind=_address_kind(formatted),
                services=services,
                extras=extras,
                trusted_without_authenticated=tw_auth,
            )
            paired.append(dev)
        return ACCESS_READ

    bond_status = _load_paired()
    if bonds_unreadable and bond_status == ACCESS_READ:
        bond_status = ACCESS_DENIED
    collection["bthport_devices"] = bond_status
    bonds_enumerated = bond_status not in ACCESS_BLIND

    classic_devices = sorted(
        [d for d in paired if d.stack in {"classic", "dual"}],
        key=lambda d: d.mac,
    )
    ble_devices = sorted(
        [d for d in paired if d.stack in {"ble", "dual"}],
        key=lambda d: d.mac,
    )
    # 5.6: dual-mode devices remain duplicated into the Classic and BLE tables so they
    # cannot vanish from either view, and additionally get a table of their own so the
    # class is obvious in a large inventory.
    dual_devices = sorted([d for d in paired if d.stack == "dual"], key=lambda d: d.mac)
    unique_macs = sorted({d.mac for d in paired})

    for dev in paired:
        if dev.trusted_without_authenticated:
            findings.append(
                Finding(
                    rule_id=RULE_PAIR_TRUSTED_UNAUTH,
                    phase="Pairing",
                    target=f"{dev.name} ({dev.mac})",
                    target_key=dev.mac,
                    detail="Trusted device without Authenticated — pairing ceremony was not completed.",
                    severity=Severity.HIGH,
                    mitre_technique="T1200",
                    remediation="Remove the bond and re-pair with a confirmed pairing ceremony, or remove the device if unused.",
                    evidence={
                        "mac": dev.mac,
                        "trusted": dev.trusted,
                        "authenticated": dev.authenticated,
                        "stack": dev.stack,
                    },
                )
            )
        if _is_hid_device(dev):
            findings.append(
                Finding(
                    rule_id=RULE_PAIR_HID,
                    phase="Bluetooth",
                    target=f"{dev.name} ({dev.mac})",
                    target_key=dev.mac,
                    detail=(
                        "paired HID/HOGP peripheral — remove the bond if the device is not actively used; "
                        "disable Bluetooth when idle"
                    ),
                    severity=Severity.MEDIUM,
                    mitre_technique="T1056.001",
                    remediation="Remove unused HID bonds. Disable Bluetooth when not needed.",
                    evidence={
                        "mac": dev.mac,
                        "cod_major": dev.cod_major,
                        "services": dev.services,
                    },
                )
            )
        if HID_NAME_RE.search(dev.name or "") and (
            dev.cod_major is None or dev.category == "Uncategorized"
        ):
            findings.append(
                Finding(
                    rule_id=RULE_PAIR_INPUT_UNCLASSIFIED,
                    phase="Bluetooth",
                    target=f"{dev.name} ({dev.mac})",
                    target_key=dev.mac,
                    detail="unclassified input device",
                    severity=Severity.MEDIUM,
                    mitre_technique="T1056.001",
                    remediation="Identify the device, confirm it is an intended input peripheral, or remove the bond.",
                    evidence={"mac": dev.mac, "category": dev.category, "cod_major": dev.cod_major},
                )
            )

    hygiene_rows: list[dict[str, str]] = []
    stale_delta = timedelta(days=stale_days)
    for dev in paired:
        last_kind = dev.last_seen_status
        if last_kind == SEEN_OK:
            last_dt, _ = _parse_timestamp(dev.last_seen)
        else:
            last_dt = None
        # A timestamp we do not trust cannot clear a bond of staleness. Previously a
        # future-dated value satisfied `last_dt < scan_now - stale_delta` as False and
        # the bond escaped hygiene entirely.
        stale = last_dt is None or last_dt < scan_now - stale_delta
        if last_kind in {SEEN_UNPARSEABLE, SEEN_IMPLAUSIBLE}:
            findings.append(
                Finding(
                    rule_id=RULE_DATA_BOND_TIMESTAMP,
                    phase="Data",
                    target=f"{dev.name} ({dev.mac})",
                    target_key=dev.mac,
                    detail=(
                        f"bond last-seen value is {last_kind}; the bond is treated as "
                        "stale and cannot support an in-use claim"
                    ),
                    severity=Severity.INFO,
                    mitre_technique=MITRE_NA,
                    remediation=(
                        "No host change required. Treat this bond's last-seen date as "
                        "unreliable when correlating against other evidence."
                    ),
                    evidence={
                        "mac": dev.mac,
                        "decoded": dev.last_seen,
                        "decode_branch": dev.extras.get("last_seen_parse"),
                        "source_field": dev.extras.get("last_seen_field"),
                        "raw": dev.extras.get("last_seen_raw"),
                    },
                )
            )
        if stale:
            hid = _is_hid_device(dev)
            sev = Severity.MEDIUM if hid or stale_days >= 180 else Severity.LOW
            if last_dt is not None and last_dt < scan_now - timedelta(days=180):
                sev = Severity.MEDIUM
            findings.append(
                Finding(
                    rule_id=RULE_HYG_STALE_BOND,
                    phase="Hygiene",
                    target=f"{dev.name} ({dev.mac})",
                    target_key=dev.mac,
                    detail="remove unused pairings",
                    severity=sev,
                    mitre_technique="T1120",
                    remediation="Remove the unused pairing from Windows Bluetooth settings.",
                    evidence={
                        "mac": dev.mac,
                        "last_seen": dev.last_seen,
                        "last_seen_field": dev.extras.get("last_seen_field"),
                        "parse": last_kind,
                        "stale_days": stale_days,
                    },
                )
            )
            hygiene_rows.append(
                {
                    "check": "stale-bond",
                    "target": f"{dev.name} ({dev.mac})",
                    "severity": sev.value,
                    "mitre": "T1120",
                    "message": "remove unused pairings",
                }
            )
        if _is_hid_device(dev):
            hygiene_rows.append(
                {
                    "check": "hid-hogp",
                    "target": f"{dev.name} ({dev.mac})",
                    "severity": Severity.MEDIUM.value,
                    "mitre": "T1056.001",
                    "message": "paired HID/HOGP peripheral",
                }
            )
        if HID_NAME_RE.search(dev.name or "") and (
            dev.cod_major is None or dev.category == "Uncategorized"
        ):
            hygiene_rows.append(
                {
                    "check": "unclassified-input",
                    "target": f"{dev.name} ({dev.mac})",
                    "severity": Severity.MEDIUM.value,
                    "mitre": "T1056.001",
                    "message": "unclassified input device",
                }
            )

    if len(unique_macs) > 15 and role != "conference":
        findings.append(
            Finding(
                rule_id=RULE_HYG_INVENTORY_ROT,
                phase="Hygiene",
                target="Paired device inventory",
                target_key=TARGET_KEY_HOST,
                detail="inventory rot",
                severity=Severity.LOW,
                mitre_technique="T1120",
                remediation="Review and remove bonds that the host no longer uses.",
                evidence={"bond_count": len(unique_macs), "role": role},
            )
        )
        hygiene_rows.append(
            {
                "check": "inventory-rot",
                "target": "host",
                "severity": Severity.LOW.value,
                "mitre": "T1120",
                "message": f"inventory rot ({len(unique_macs)} bonds)",
            }
        )

    # --- 5.3 discoverability: compare both scopes instead of first-wins -----------
    # The old loop read BTHPORT first and broke on the first non-None, so an MDM
    # policy was only consulted when the local value was missing. That is backwards:
    # PolicyManager is the authority, and the interesting case is precisely when the
    # two disagree. Both scopes are read, both are reported, and a mismatch is a
    # finding rather than something one branch silently wins.
    def _read_disc(path: str, label: str | None) -> tuple[str, Any, str]:
        raw, status = reg.value(path, "AllowDiscoverableMode", label)
        if status in ACCESS_BLIND:
            return "Unknown", None, status
        if raw is None:
            return "Absent", None, status
        flag, unrecognized = _policy_flag(raw)
        if unrecognized:
            return "Unknown", raw, ACCESS_READ
        return ("Enabled" if flag else "Disabled"), raw, ACCESS_READ

    local_disc, local_disc_raw, local_disc_status = _read_disc(BTHPORT_PARAMS, None)
    policy_disc, policy_disc_raw, policy_disc_status = _read_disc(POLICY_BT, "policy_manager")

    disc_unrecognized: Any = None
    if local_disc == "Unknown" and local_disc_raw is not None:
        disc_unrecognized = local_disc_raw
    elif policy_disc == "Unknown" and policy_disc_raw is not None:
        disc_unrecognized = policy_disc_raw

    if policy_disc in {"Enabled", "Disabled"}:
        discoverability, disc_source = policy_disc, POLICY_BT
    elif local_disc in {"Enabled", "Disabled"}:
        discoverability, disc_source = local_disc, BTHPORT_PARAMS
    else:
        discoverability, disc_source = "Unknown", None

    disc_status = (
        policy_disc_status
        if policy_disc in {"Enabled", "Disabled"}
        else local_disc_status
        if local_disc in {"Enabled", "Disabled"}
        else (
            policy_disc_status
            if policy_disc_status in ACCESS_BLIND
            else local_disc_status
        )
    )
    collection["discoverability"] = disc_status
    disc_drift = (
        local_disc in {"Enabled", "Disabled"}
        and policy_disc in {"Enabled", "Disabled"}
        and local_disc != policy_disc
    )

    configuration: list[BtConfig] = [
        BtConfig(name="Discoverability", value=discoverability, source=disc_source),
        BtConfig(name="Discoverability (local)", value=local_disc, source=BTHPORT_PARAMS),
        BtConfig(name="Discoverability (policy)", value=policy_disc, source=POLICY_BT),
    ]
    # Anything else PolicyManager holds for Bluetooth is free to surface: the whole key
    # was already read once by the tri-state reader, so these cost no extra registry I/O.
    policy_vals, policy_status = reg.key(POLICY_BT, "policy_manager")
    if policy_status == ACCESS_READ and policy_vals:
        for extra in (
            "AllowAdvertising",
            "AllowPrepairing",
            "AllowPromptedProximalConnections",
            "ServicesAllowedList",
            "LocalDeviceName",
            # Present in the Bluetooth CSP alongside the others; surfaced so an MDM
            # setting is visible even though the local Policies\Hardware DWORD above
            # is what drives the T1040 verdict.
            "SetMinimumEncryptionKeySize",
        ):
            if extra in policy_vals:
                configuration.append(
                    BtConfig(name=f"Policy: {extra}", value=str(policy_vals[extra]), source=POLICY_BT)
                )
    if disc_drift:
        findings.append(
            Finding(
                rule_id=RULE_POL_DISCOVERABLE_DRIFT,
                phase="Policy",
                target="AllowDiscoverableMode",
                target_key=POLICY_BT,
                detail=(
                    f"policy says {policy_disc} but the local BTHPORT value says {local_disc}; "
                    "the policy value is reported as effective"
                ),
                severity=Severity.MEDIUM,
                mitre_technique="T1200",
                remediation=(
                    "Reconcile the MDM/PolicyManager setting with the local BTHPORT value. "
                    "A local value that disagrees with policy usually means the policy is "
                    "not applying to this host."
                ),
                evidence={
                    "policy_path": POLICY_BT,
                    "policy_value": policy_disc,
                    "local_path": BTHPORT_PARAMS,
                    "local_value": local_disc,
                },
            )
        )
    if discoverability == "Enabled":
        findings.append(
            Finding(
                rule_id=RULE_CFG_DISCOVERABLE,
                phase="Bluetooth",
                target="Bluetooth Discoverability",
                target_key=disc_source or BTHPORT_PARAMS,
                detail="Bluetooth is discoverable — enables reconnaissance and forced pairing attempts",
                severity=Severity.MEDIUM,
                mitre_technique="T1120",
                remediation="Disable discoverable mode when not actively pairing devices.",
                evidence={"source": disc_source, "value": discoverability},
            )
        )

    auth_label = "Unknown"
    auth_val, auth_status = reg.value(BTHPORT_PARAMS, "Authentication")
    collection["authentication"] = auth_status
    auth_flag, auth_unrecognized = _policy_flag(auth_val)
    if auth_flag is True:
        auth_label = "Yes"
    elif auth_flag is False:
        auth_label = "No"
    configuration.append(
        BtConfig(name="AuthenticationRequired", value=auth_label, source=BTHPORT_PARAMS)
    )
    if auth_flag is False:
        findings.append(
            Finding(
                rule_id=RULE_CFG_AUTH_DISABLED,
                phase="Bluetooth",
                target="Bluetooth Authentication",
                target_key=BTHPORT_PARAMS,
                detail="Bluetooth authentication is DISABLED — devices can connect without pairing confirmation",
                severity=Severity.HIGH,
                mitre_technique="T1200",
                remediation=(
                    f"Enable authentication: Set-ItemProperty '{BTHPORT_PARAMS}' "
                    "-Name 'Authentication' -Value 1"
                ),
                evidence={"path": BTHPORT_PARAMS, "value": auth_val},
            )
        )

    knob_raw, knob_status = reg.value(KNOB_PATH, KNOB_NAME, "knob_policy")
    knob_flag, knob_unrecognized = _policy_flag(knob_raw)
    if knob_status in ACCESS_BLIND:
        # The old code read "could not open the key" as "the DWORD is not set" and
        # raised a High T1040 from it. An unreadable policy key is Unknown.
        knob_value = "Unreadable"
        knob_in_use = "Unknown"
    elif knob_unrecognized:
        # Present but not a recognisable boolean. We cannot assert enforcement either
        # way, so no finding fires; the unrecognised value is reported instead.
        knob_value = f"Unrecognized ({knob_raw!r})"
        knob_in_use = "Unknown"
    elif knob_flag is True:
        knob_value = "1"
        knob_in_use = "On"
    elif knob_flag is False:
        knob_value = "0"
        knob_in_use = "Off"
    else:
        knob_value = "Missing"
        knob_in_use = "Off"
    knob_class_mitigation = {
        "Mitigation DWORD": KNOB_NAME,
        "Path": KNOB_PATH,
        "Value": knob_value,
        "Mitigation in use": knob_in_use,
        "Source status": knob_status,
    }

    live_statuses = [
        (a.status or "Unknown")
        for a in adapters
        if a.name != "(No Bluetooth adapters detected)"
    ]
    if not live_statuses:
        adapter_pnp_status = "Absent"
    else:
        normalized = []
        for s in live_statuses:
            sl = s.lower()
            if sl in {"ok", "present", "started"}:
                normalized.append("OK")
            elif sl in {"disabled", "devidisabled", "error"}:
                normalized.append("Disabled" if "disable" in sl else "Error" if sl == "error" else s)
            else:
                normalized.append(s)
        if any(s == "OK" for s in normalized):
            adapter_pnp_status = "OK"
        elif all(s == "Disabled" for s in normalized):
            adapter_pnp_status = "Disabled"
        elif all(s == "Absent" for s in normalized):
            adapter_pnp_status = "Absent"
        elif any(s == "Error" for s in normalized):
            adapter_pnp_status = "Error"
        else:
            adapter_pnp_status = normalized[0]

    svc = _safe(
        on_error,
        errors,
        "bthserv",
        lambda: be.service_status("bthserv"),
        {"state": "Unknown", "start_type": "Unknown"},
    )
    svc_state = (svc or {}).get("state") or "Unknown"
    if svc_state == "Running":
        bthserv_onoff = "On"
    elif svc_state == "Stopped":
        bthserv_onoff = "Off"
    else:
        bthserv_onoff = "Unknown"
    bthserv_start = (svc or {}).get("start_type") or "Unknown"

    radio_powered = _safe(on_error, errors, "radio", lambda: be.radio_powered(), "Unknown")
    if radio_powered not in {"On", "Off", "Unknown"}:
        radio_powered = "Unknown"
    radio_powered = _resolve_radio_power(reg, radio_powered)

    disable_type, why = _decide_disable(adapter_pnp_status, radio_powered, bthserv_onoff)
    disable_state = DisableState(
        disable_type=disable_type,
        why=why,
        adapter_pnp_status=adapter_pnp_status,
        radio_powered=radio_powered,
        bthserv_status=bthserv_onoff,
        bthserv_start_type=bthserv_start,
    )

    hardware_present = "Yes" if any(
        a.name != "(No Bluetooth adapters detected)" for a in adapters
    ) else "No"
    adapter_enabled_pnp = "Yes" if adapter_pnp_status in {"OK", "Present"} else "No"
    if adapter_pnp_status in {"Error", "Unknown"}:
        adapter_enabled_pnp = "Unknown"
    radio_enabled = (
        "Yes" if radio_powered == "On" else "No" if radio_powered == "Off" else "Unknown"
    )

    currently_in_use = "Unknown"
    if disable_type == "Hard" or adapter_enabled_pnp == "No" or radio_powered == "Off":
        currently_in_use = "No"
    else:
        recent = False
        for dev in paired:
            if dev.last_seen_status != SEEN_OK:
                continue
            dt, _kind = _parse_timestamp(dev.last_seen)
            # Two-sided. A future-dated value used to make `scan_now - dt` negative,
            # which is trivially <= the window, so garbage produced a confident "Yes".
            if dt and timedelta(0) <= scan_now - dt <= IN_USE_WINDOW:
                recent = True
                break
        if recent:
            currently_in_use = "Yes"

    if knob_in_use == "Off":  # never fires on Unknown; blindness is not a finding
        # Deliberately still gated on the PnP fact, not the radio: a soft-off host with
        # the DWORD unset keeps its High severity, so this relabel moves no exit codes.
        # Whether that is the right policy is an open decision, not a side effect.
        sev = (
            Severity.HIGH
            if adapter_enabled_pnp == "Yes" or currently_in_use == "Yes"
            else Severity.MEDIUM
        )
        findings.append(
            Finding(
                rule_id=RULE_ENC_KNOB_OFF,
                phase="Encryption",
                target="Minimum encryption key length",
                target_key=KNOB_PATH,
                detail=(
                    "minimum link-key length enforcement is not in use "
                    f"(EnableMinimumEncryptionKeySize={knob_value})"
                ),
                severity=sev,
                mitre_technique="T1040",
                remediation=(
                    f"Set-ItemProperty '{KNOB_PATH}' -Name '{KNOB_NAME}' -Value 1; "
                    "then test peripherals. Bluejack will not apply this change."
                ),
                evidence={"path": KNOB_PATH, "value": knob_value},
            )
        )

    supported = _as_guid_list((did_vals or {}).get("SupportedServices"))
    unsupported = _as_guid_list((did_vals or {}).get("UnsupportedServices"))
    live_flags = _safe(
        on_error,
        errors,
        "live-profiles",
        lambda: getattr(be, "live_profile_flags", lambda: {})(),
        {},
    ) or {}
    profile_kwargs = {"radio_powered": radio_powered, "disable_type": disable_type}
    profiles = BthportProfiles(
        hid=_finalize_profile(
            "hid", _profile_state(supported, unsupported, UUID_HID), live_flags.get("hid"), **profile_kwargs
        ),
        hogp=_finalize_profile(
            "hogp", _profile_state(supported, unsupported, UUID_HOGP), live_flags.get("hogp"), **profile_kwargs
        ),
        spp=_finalize_profile(
            "spp", _profile_state(supported, unsupported, UUID_SPP), live_flags.get("spp"), **profile_kwargs
        ),
        dun=_finalize_profile(
            "dun", _profile_state(supported, unsupported, UUID_DUN), live_flags.get("dun"), **profile_kwargs
        ),
        a2dp=_finalize_profile(
            "a2dp",
            _profile_state(supported, unsupported, UUID_A2DP_SOURCE, UUID_A2DP_SINK),
            live_flags.get("a2dp"),
            **profile_kwargs,
        ),
        pan=_finalize_profile(
            "pan",
            _profile_state(supported, unsupported, UUID_PANU, UUID_NAP),
            live_flags.get("pan"),
            **profile_kwargs,
        ),
    )

    if (profiles.hid == "Yes" or profiles.hogp == "Yes") and discoverability == "Enabled":
        findings.append(
            Finding(
                rule_id=RULE_PRF_HID_DISCOVERABLE,
                phase="Profiles",
                target="HID/HOGP + discoverable",
                target_key=TARGET_KEY_HOST,
                detail="HID or HOGP is offered while the host is discoverable",
                severity=Severity.MEDIUM,
                mitre_technique="T1056.001",
                remediation="Disable discoverable mode except while pairing; restrict HID offer if the role does not need it.",
                evidence={"hid": profiles.hid, "hogp": profiles.hogp, "discoverability": discoverability},
            )
        )
    if profiles.pan == "Yes" and role != "conference":
        findings.append(
            Finding(
                rule_id=RULE_PRF_PAN_OFFERED,
                phase="Profiles",
                target="PAN",
                target_key=TARGET_KEY_HOST,
                detail="PAN is offered — the host can become a Bluetooth network hop",
                severity=Severity.MEDIUM,
                mitre_technique="T1200",
                remediation="Disable the Bluetooth PAN profile on workstations and servers that do not need it.",
                evidence={"pan": profiles.pan, "role": role},
            )
        )
    if (profiles.spp == "Yes" or profiles.dun == "Yes") and role == "workstation":
        findings.append(
            Finding(
                rule_id=RULE_PRF_SPP_DUN_OFFERED,
                phase="Profiles",
                target="SPP/DUN",
                target_key=TARGET_KEY_HOST,
                detail="SPP or DUN is offered on a workstation role",
                severity=Severity.LOW,
                mitre_technique="T1200",
                remediation="Disable SPP/DUN unless a line-of-business peripheral requires the serial or dial-up profile.",
                evidence={"spp": profiles.spp, "dun": profiles.dun, "role": role},
            )
        )

    allow_bt, allow_bt_status = reg.value(POLICY_BT, "AllowBluetooth", "policy_manager")
    allow_bt_flag, allow_bt_unrecognized = _policy_flag(allow_bt)
    if (
        allow_bt_status == ACCESS_READ
        and allow_bt_flag is False
        and hardware_present == "Yes"
        and adapter_pnp_status == "OK"
    ):
        findings.append(
            Finding(
                rule_id=RULE_POL_ALLOWBT_DRIFT,
                phase="Policy",
                target="AllowBluetooth",
                target_key=POLICY_BT,
                detail="Policy forbids Bluetooth but the adapter is live — control drift",
                severity=Severity.HIGH,
                mitre_technique="T1200",
                remediation="Enforce the policy (disable or remove the adapter) or correct the policy if Bluetooth is required.",
                evidence={"AllowBluetooth": allow_bt, "adapter_pnp_status": adapter_pnp_status},
            )
        )

    technique_map = _safe(on_error, errors, "attack-map", load_technique_map, {})
    tagged = {f.mitre_technique for f in findings} - {MITRE_NA}
    techniques = [technique_map[t] for t in sorted(tagged) if t in technique_map]

    blind_sources = sorted(k for k, v in collection.items() if v in ACCESS_BLIND)
    if blind_sources:
        detail = "sources unreadable: " + ", ".join(blind_sources)
        if bonds_unreadable:
            detail += f"; {bonds_unreadable} bond subkey(s) unreadable"
        findings.append(
            Finding(
                rule_id=RULE_SCAN_INCOMPLETE,
                phase="Scan",
                target="Collection completeness",
                target_key=TARGET_KEY_HOST,
                detail=(
                    f"scan is incomplete — {detail}. Values derived from these sources "
                    "are reported Unknown, not assumed absent."
                ),
                severity=Severity.MEDIUM,
                mitre_technique=MITRE_NA,
                remediation=(
                    "Re-run from an account that can read HKLM and query PnP/services "
                    "(elevated), then compare. Do not treat this report as a clean "
                    "result for the unreadable sources."
                ),
                evidence={"collection": dict(collection), "bonds_unreadable": bonds_unreadable},
            )
        )

    unrecognized_policies = [
        (name, path, raw)
        for name, path, raw, flagged in (
            ("AllowDiscoverableMode", disc_source or BTHPORT_PARAMS, disc_unrecognized, disc_unrecognized is not None),
            ("Authentication", BTHPORT_PARAMS, auth_val, auth_unrecognized),
            (KNOB_NAME, KNOB_PATH, knob_raw, knob_unrecognized),
            ("AllowBluetooth", POLICY_BT, allow_bt, allow_bt_unrecognized),
        )
        if flagged
    ]
    for name, path, raw in unrecognized_policies:
        findings.append(
            Finding(
                rule_id=RULE_DATA_POLICY_VALUE,
                phase="Data",
                target=f"{name}",
                target_key=f"{path}\\{name}",
                detail=(
                    "policy value is present but is not a recognisable boolean; "
                    "the setting is reported Unknown rather than guessed"
                ),
                severity=Severity.INFO,
                mitre_technique=MITRE_NA,
                remediation=(
                    f"Inspect '{path}' -Name '{name}'. Expected a 0/1 DWORD. "
                    "Correct the value or confirm the non-standard form is intentional."
                ),
                evidence={"path": path, "name": name, "raw": repr(raw)[:120]},
            )
        )

    adapters = sorted(adapters, key=lambda a: a.name.lower())
    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.mitre_technique, f.target))

    if bonds_enumerated:
        trusted_without_label = "Yes" if any(d.trusted_without_authenticated for d in paired) else "No"
        classic_count: int | None = len(classic_devices)
        ble_count: int | None = len(ble_devices)
        dual_count: int | None = len(dual_devices)
    else:
        # The bond store was not readable. "No" and 0 would both be assertions we
        # cannot make; a blind scan reports Unknown / null.
        trusted_without_label = "Unknown"
        classic_count = None
        ble_count = None
        dual_count = None
    high_critical = sum(1 for f in findings if f.severity in {Severity.HIGH, Severity.CRITICAL})

    disc_yes = (
        "Yes" if discoverability == "Enabled" else "No" if discoverability == "Disabled" else "Unknown"
    )
    auth_yes = (
        "Yes" if auth_label == "Yes" else "No" if auth_label == "No" else "Unknown"
    )

    summary = QuickSummary(
        hardware_present=hardware_present,
        currently_in_use=currently_in_use,
        adapter_enabled_pnp=adapter_enabled_pnp,
        radio_enabled=radio_enabled,
        disable_type=disable_type,
        bthserv_status=bthserv_onoff,
        discoverable=disc_yes,
        authentication_required=auth_yes,
        knob_class_mitigation=knob_in_use,
        trusted_without_authenticated=trusted_without_label,
        classic_paired_count=classic_count,
        ble_paired_count=ble_count,
        dual_paired_count=dual_count,
        high_critical_count=high_critical,
        scan_complete="No" if blind_sources else "Yes",
    )

    scan_meta.duration_s = round(time.monotonic() - _monotonic_start, 3)
    # Derived from the scan start rather than a fresh now(), so an injected clock
    # produces a coherent pair instead of a start and end from different eras.
    scan_meta.completed_utc = _format_utc(scan_now + timedelta(seconds=scan_meta.duration_s))

    return BluejackReport(
        scan=scan_meta,
        summary=summary,
        disable_state=disable_state,
        knob_class_mitigation=knob_class_mitigation,
        profiles=profiles,
        adapters=adapters,
        classic_devices=classic_devices,
        ble_devices=ble_devices,
        dual_devices=dual_devices,
        techniques=techniques,
        configuration=configuration,
        findings=findings,
        errors=errors,
        notes=notes,
        hygiene_rows=hygiene_rows,
        collection=collection,
    )


def _format_utc(raw: object) -> str | None:
    """Normalize any parseable timestamp to UTC Zulu. Returns None if invalid."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, datetime):
        dt = raw
        kind = "datetime"
    else:
        dt, kind = _parse_timestamp(raw)
    if dt is None or kind == "unparseable":
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_utc_stamp(value: str | None) -> bool:
    if not value:
        return False
    dt, kind = _parse_timestamp(value)
    if dt is None:
        return False
    return dt.tzinfo is not None and dt.utcoffset() == timedelta(0) and kind != "unparseable"


def _vis_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text or ""))


def _pad_cell(text: str, width: int) -> str:
    # No placeholder substitution here: rows are normalised before wrapping, so an
    # empty string reaching this point is a continuation line and must stay blank.
    token = text or ""
    pad = width - _vis_len(token)
    if pad <= 0:
        return token
    return token + (" " * pad)


def _wrap_cell(text: str, width: int) -> list[str]:
    """Wrap one cell to width, preserving any colour that wraps the whole cell."""
    match = _ANSI_SPLIT_RE.match(text or "")
    prefix, plain, suffix = match.groups() if match else ("", text or "", "")
    if not plain:
        return [text or ""]
    pieces: list[str] = []
    for para in plain.split("\n"):
        pieces.extend(
            textwrap.wrap(
                para,
                width=max(width, 1),
                break_long_words=True,   # a registry path longer than the column must still fit
                break_on_hyphens=False,  # never split HKLM\...\Bluetooth on a hyphen
                drop_whitespace=True,
            )
            or [""]
        )
    if not prefix and not suffix:
        return pieces
    return [f"{prefix}{p}{suffix}" if p else "" for p in pieces]


def _longest_token(cells: list[str]) -> int:
    longest = 0
    for cell in cells:
        for word in _ANSI_RE.sub("", cell or "").split():
            longest = max(longest, len(word))
    return longest


def _fit_widths(widths: list[int], floors: list[int], max_width: int, cols: int) -> list[int]:
    """Shrink columns until the table fits.

    Two passes. The first will not take a column below its floor — the length of its
    longest unbreakable token — so a registry path or an InstanceId is not split
    across lines where another column still has slack to give. Only when every
    column is at its floor and the table still overflows does the second pass break
    below it, because at that point the terminal genuinely cannot hold the table.
    """
    sep = 3 * (cols - 1)
    widths = list(widths)
    for limit in (floors, [MIN_COL_WIDTH] * cols):
        while sum(widths) + sep > max_width:
            candidates = [i for i in range(cols) if widths[i] > limit[i]]
            if not candidates:
                break
            widest = max(candidates, key=lambda i: widths[i])
            widths[widest] -= 1
    return widths


def _format_table(
    headers: list[str], rows: list[list[str]], max_width: int | None = None
) -> list[str]:
    cols = len(headers)
    widths = [_vis_len(h) for h in headers]
    norm_rows: list[list[str]] = []
    for raw in rows:
        row = [(raw[i] if i < len(raw) and raw[i] not in (None, "") else "-") for i in range(cols)]
        norm_rows.append(row)
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], _vis_len(cell))

    if max_width and max_width > 0:
        floors = []
        for i in range(cols):
            column = [headers[i]] + [r[i] for r in norm_rows]
            # Cap the floor so one pathological token cannot dominate the layout.
            floors.append(max(MIN_COL_WIDTH, min(widths[i], _longest_token(column), MAX_TOKEN_FLOOR)))
        widths = _fit_widths(widths, floors, max_width, cols)

    def emit(cells: list[str]) -> list[str]:
        """Render one record, wrapping cells and aligning continuation lines."""
        wrapped = [_wrap_cell(cells[i], widths[i]) for i in range(cols)]
        height = max(len(w) for w in wrapped)
        out: list[str] = []
        for line_no in range(height):
            parts = []
            for i in range(cols):
                piece = wrapped[i][line_no] if line_no < len(wrapped[i]) else ""
                parts.append(_pad_cell(piece, widths[i]))
            out.append(" | ".join(parts).rstrip())
        return out

    out: list[str] = list(emit(headers))
    out.append("-+-".join("-" * w for w in widths))
    if not norm_rows:
        out.append(_pad_cell("(none)", widths[0]).rstrip())
        return out

    rendered = [emit(row) for row in norm_rows]
    multiline = any(len(r) > 1 for r in rendered)
    for idx, record in enumerate(rendered):
        # Blank spacer between records only when records wrap, so a scannable
        # one-line-per-row table stays dense and a wrapped one stays readable.
        if multiline and idx:
            out.append("")
        out.extend(record)
    return out


def _json_default(o: Any) -> Any:
    """Fallback for values json.dumps cannot encode.

    _convert_reg_value returns bytes for REG_BINARY, and those reach adapter.extras
    and Finding.evidence unfiltered. Without this the --json path raised TypeError,
    which escaped main() and exited 1 — the code the README reserves for
    "High/Critical present", so a serialization crash was indistinguishable from a
    finding. Nothing here drops data: unencodable values are rendered, not skipped.
    """
    if isinstance(o, (bytes, bytearray)):
        return {"hex": o.hex(), "len": len(o)}
    if isinstance(o, datetime):
        return _format_utc(o) or o.isoformat()
    if isinstance(o, Enum):
        return o.value
    if isinstance(o, (set, frozenset, tuple)):
        return list(o)
    if isinstance(o, timedelta):
        return o.total_seconds()
    return str(o)


def findings_to_ndjson(report: BluejackReport) -> str:
    """One finding per line, each self-contained.

    NDJSON lines get shipped and indexed independently, so each carries enough scan
    context to stand alone: which host, which tool version, when, and whether the
    scan was complete. A finding from a blind scan must never be read as equivalent
    to one from a full scan.
    """
    context = {
        "tool_version": report.scan.tool_version,
        "schema_version": report.scan.schema_version,
        "started_utc": report.scan.started_utc,
        "host_name": report.scan.host_name,
        "host_utc_offset": report.scan.host_utc_offset,
        "scan_complete": report.summary.scan_complete,
    }
    lines = []
    for finding in report.findings:
        row = {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "mitre_technique": finding.mitre_technique,
            "phase": finding.phase,
            "target": finding.target,
            "target_key": finding.target_key,
            "detail": finding.detail,
            "remediation": finding.remediation,
            "evidence": finding.evidence,
            "scan": context,
        }
        lines.append(json.dumps(row, sort_keys=False, default=_json_default))
    return "\n".join(lines) + ("\n" if lines else "")


def report_to_json(report: BluejackReport) -> str:
    payload = asdict(report)

    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            # default= does not apply to dict keys, so non-str keys are coerced here.
            return {(k if isinstance(k, str) else str(k)): walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        if isinstance(o, Enum):
            return o.value
        return o

    data = walk(payload)
    # Tri-state: null when the bond store was unreadable. Coercing Unknown to false
    # would put back exactly the confident negative the collection map exists to stop.
    label = report.summary.trusted_without_authenticated
    flag: bool | None = True if label == "Yes" else False if label == "No" else None
    data["trusted_without_authenticated"] = flag
    if isinstance(data.get("summary"), dict):
        data["summary"]["trusted_without_authenticated"] = flag
    return json.dumps(data, indent=2, sort_keys=False, default=_json_default)


def _pad(label: str, width: int = 48) -> str:
    return label.ljust(width)


def _resolve_width(width: int | None) -> int:
    """0 or negative disables wrapping entirely."""
    if width is not None:
        return width
    return shutil.get_terminal_size(fallback=(DEFAULT_TABLE_WIDTH, 24)).columns


def render_report(
    report: BluejackReport, *, color: bool | None = None, width: int | None = None
) -> str:
    use_color = _color_enabled() if color is None else color
    table_width = _resolve_width(width)
    s = report.summary
    lines: list[str] = [BANNER_BLUEJACK, ""]
    lines.append("=== Bluejack Quick Summary ===")
    # Completeness qualifies everything below it, so it leads.
    if s.scan_complete == "No":
        blind = sorted(k for k, v in report.collection.items() if v in ACCESS_BLIND)
        lines.append(
            _red(f"{_pad('Scan complete?')}No - unreadable: {', '.join(blind)}", use_color)
        )
    else:
        lines.append(f"{_pad('Scan complete?')}Yes")
    lines.append(f"{_pad('Is Bluetooth hardware present?')}{s.hardware_present}")
    lines.append(f"{_pad('Is Bluetooth currently in use?')}{s.currently_in_use}")
    lines.append(f"{_pad('Adapter enabled (PnP)?')}{s.adapter_enabled_pnp}")
    lines.append(f"{_pad('Radio enabled?')}{s.radio_enabled}")
    lines.append(f"{_pad('Disable type')}{s.disable_type}")
    lines.append(f"{_pad('Bthserv status')}{s.bthserv_status}")
    lines.append(f"{_pad('Discoverable (T1120)?')}{s.discoverable}")
    lines.append(f"{_pad('Authentication required (T1200)?')}{s.authentication_required}")
    # Always gold, On or Off: this is the cheapest mitigation on the list and the one
    # most often skimmed past, so it gets colour regardless of its value.
    lines.append(
        _gold(
            f"{_pad('KNOB-class min encryption key-length mitigation')}{s.knob_class_mitigation}",
            use_color,
        )
    )
    tw = f"{_pad('Trusted device without Authenticated?')}{s.trusted_without_authenticated}"
    if s.trusted_without_authenticated == "Yes":
        tw = _red(tw, use_color)
    lines.append(tw)
    _count = lambda n: "Unknown (bond store unreadable)" if n is None else str(n)
    lines.append(f"{_pad('Classic paired device count')}{_count(s.classic_paired_count)}")
    lines.append(f"{_pad('BLE paired device count')}{_count(s.ble_paired_count)}")
    lines.append(f"{_pad('Dual-mode paired device count')}{_count(s.dual_paired_count)}")
    lines.append(f"{_pad('High/Critical finding count')}{s.high_critical_count}")
    lines.append(f"{_pad('Timestamps')}UTC")
    lines.append("")

    m = report.scan
    lines.append("=== Scan ===")
    lines.append(f"Tool version:           {m.tool_version} (JSON schema {m.schema_version})")
    lines.append(f"Scan started (UTC):     {m.started_utc or '-'}")
    lines.append(f"Scan completed (UTC):   {m.completed_utc or '-'}")
    lines.append(
        f"Duration:               {m.duration_s if m.duration_s is not None else '-'}s"
    )
    # The host's own clock reading. Everything else in this report is UTC; this is the
    # line you need to line the report up against local-time event logs.
    lines.append(f"Host local time:        {m.host_local_time or '-'}   (host clock at scan time)")
    lines.append(
        f"Host UTC offset:        {m.host_utc_offset or '-'}"
        + (f"  ({m.host_timezone})" if m.host_timezone else "")
    )
    lines.append(f"Host name:              {m.host_name or '-'}")
    lines.append(f"OS:                     {m.os_version or '-'}")
    lines.append(f"Python:                 {m.python_version or '-'}")
    lines.append(f"PowerShell:             {m.powershell_version or '-'}")
    lines.append(f"Process privilege:      {m.privilege}")
    lines.append(f"Role / stale-days:      {m.role or '-'} / {m.stale_days if m.stale_days is not None else '-'}")
    lines.append(f"Invocation:             {' '.join(m.invocation) if m.invocation else '(no arguments)'}")
    lines.append("")

    d = report.disable_state
    lines.append("=== Soft disable vs Hard disable ===")
    lines.append(f"Disable type:           {d.disable_type}")
    lines.append(f"Why:                    {d.why}")
    lines.append(f"Adapter PnP status:     {d.adapter_pnp_status}")
    lines.append(f"Radio powered:          {d.radio_powered}")
    lines.append(f"Bthserv status:         {d.bthserv_status}")
    lines.append(f"Bthserv start type:     {d.bthserv_start_type}")
    lines.append("")

    k = report.knob_class_mitigation
    lines.append("=== Encryption key length (KNOB-class) ===")
    lines.append(f"Mitigation DWORD:       {k.get('Mitigation DWORD')}")
    lines.append(f"Path:                   {k.get('Path')}")
    lines.append(f"Value:                  {k.get('Value')}")
    lines.append(f"Mitigation in use:      {k.get('Mitigation in use')}")
    lines.append("")

    p = report.profiles
    lines.append("=== BTHPORT profiles (offered now) ===")
    lines.append(f"Radio powered     = {report.disable_state.radio_powered}")
    lines.append(f"Bluetooth HID     = {p.hid}")
    lines.append(f"HOGP (BLE HID)    = {p.hogp}")
    lines.append(f"SPP               = {p.spp}")
    lines.append(f"DUN               = {p.dun}")
    lines.append(f"A2DP              = {p.a2dp}")
    lines.append(f"PAN               = {p.pan}")
    lines.append("")

    def _auth_cell(dev: BtPairedDevice) -> str:
        if dev.authenticated is True:
            token = "Yes"
        elif dev.authenticated is False:
            token = "No"
        else:
            token = "No" if dev.trusted_without_authenticated else "-"
        if dev.trusted_without_authenticated:
            return _red(token, use_color)
        return token

    def _tr(v: bool | None) -> str:
        if v is True:
            return "Yes"
        if v is False:
            return "No"
        return "-"

    def _vendor_cell(dev: BtPairedDevice) -> str:
        if dev.oui_vendor:
            return dev.oui_vendor
        # An unmatched OUI on a random BLE address is expected, not a gap in the table.
        if dev.address_kind not in ("public", "unknown"):
            return "(random addr)"
        return dev.oui or "-"

    def _last_seen_cell(dev: BtPairedDevice) -> str:
        formatted = _format_utc(dev.last_seen)
        if not formatted:
            return "-"
        if dev.last_seen_status == SEEN_IMPLAUSIBLE:
            # Show what was decoded, but never let it read as an established fact.
            return _red(f"{formatted} (implausible)", use_color)
        if dev.last_seen_status != SEEN_OK:
            return f"{formatted} ({dev.last_seen_status})"
        return formatted

    lines.append("=== Adapters ===")
    lines.extend(
        _format_table(
            ["Name", "Status", "Manufacturer", "Driver version", "Driver date", "Hardware ID", "InstanceId"],
            [
                [
                    a.name or "-",
                    a.status or "-",
                    str(a.manufacturer or "-"),
                    str(a.driver_version or "-"),
                    a.driver_date or "-",
                    a.hardware_id or "-",
                    a.instance_id or "-",
                ]
                for a in report.adapters
            ],
            table_width,
        )
    )
    lines.append("")

    lines.append("=== Classic Bluetooth paired devices ===")
    lines.extend(
        _format_table(
            ["Name", "MAC", "OUI vendor", "Addr", "Category", "CoD major", "Trusted",
             "Authenticated", "Last seen (UTC)"],
            [
                [
                    dev.name,
                    dev.mac,
                    _vendor_cell(dev),
                    dev.address_kind,
                    dev.category,
                    "-" if dev.cod_major is None else str(dev.cod_major),
                    _tr(dev.trusted),
                    _auth_cell(dev),
                    _last_seen_cell(dev),
                ]
                for dev in report.classic_devices
            ],
            table_width,
        )
    )
    lines.append("")

    lines.append("=== BLE paired devices ===")
    lines.extend(
        _format_table(
            ["Name", "MAC", "OUI vendor", "Addr", "Category", "Trusted",
             "Authenticated", "Last seen (UTC)"],
            [
                [
                    dev.name,
                    dev.mac,
                    _vendor_cell(dev),
                    dev.address_kind,
                    dev.category,
                    _tr(dev.trusted),
                    _auth_cell(dev),
                    _last_seen_cell(dev),
                ]
                for dev in report.ble_devices
            ],
            table_width,
        )
    )
    lines.append("")

    lines.append("=== Dual-mode paired devices (also listed above) ===")
    lines.extend(
        _format_table(
            ["Name", "MAC", "OUI vendor", "Category", "Trusted", "Authenticated",
             "Last seen (UTC)", "Classified by"],
            [
                [
                    dev.name,
                    dev.mac,
                    _vendor_cell(dev),
                    dev.category,
                    _tr(dev.trusted),
                    _auth_cell(dev),
                    _last_seen_cell(dev),
                    ", ".join(dev.extras.get("stack_evidence") or []) or "-",
                ]
                for dev in report.dual_devices
            ],
            table_width,
        )
    )
    lines.append("")

    lines.append("=== Stale-bond hygiene ===")
    lines.extend(
        _format_table(
            ["Check", "Target", "Severity", "MITRE", "Message"],
            [
                [
                    row.get("check") or "-",
                    row.get("target") or "-",
                    row.get("severity") or "-",
                    row.get("mitre") or "-",
                    row.get("message") or "-",
                ]
                for row in report.hygiene_rows
            ],
            table_width,
        )
    )
    lines.append("")

    lines.append("=== Configuration ===")
    for cfg in report.configuration:
        src = f" ({cfg.source})" if cfg.source else ""
        lines.append(f"{cfg.name} = {cfg.value}{src}")
    lines.append("")

    _tech_by_id = {t.technique: t for t in report.techniques}

    lines.append("=== Findings ===")
    lines.extend(
        _format_table(
            ["Severity", "Rule", "MITRE", "Target", "Remediation", "Known actors"],
            [
                [
                    f.severity.value,
                    f.rule_id,
                    f.mitre_technique,
                    f.target,
                    f.remediation,
                    _actor_summary(_tech_by_id.get(f.mitre_technique)),
                ]
                for f in report.findings
            ],
            table_width,
        )
    )
    lines.append("")

    lines.append("=== ATT&CK techniques tagged by this scan ===")
    if not report.techniques:
        lines.append("(none)")
    else:
        for tech in report.techniques:
            lines.append(f"{tech.technique}  {tech.name}")
            if tech.note:
                for wrapped in textwrap.wrap(tech.note, width=max(table_width - 4, 40)):
                    lines.append(f"    {wrapped}")
            lines.append(f"    Known actors: {', '.join(tech.actors) if tech.actors else '-'}")
            if tech.url:
                lines.append(f"    Reference:    {tech.url}")
            lines.append("")
        lines.append(f"({ATTACK_SEED_NOTE})")
    lines.append("")

    lines.append("=== Collection completeness ===")
    if not report.collection:
        lines.append("(not recorded)")
    else:
        rows = []
        for source, status in sorted(report.collection.items()):
            note = ACCESS_LEGEND.get(status, status)
            if status == ACCESS_ABSENT and source in UNCONFIRMED_LOCAL_VALUES:
                note += "; local value name is not documented by Microsoft"
            rows.append([source, status, COLLECTION_SOURCES.get(source, "-"), note])
        table = _format_table(
            ["Source", "Status", "What was checked", "Meaning"], rows, table_width
        )
        blind = {k for k, v in report.collection.items() if v in ACCESS_BLIND}
        for line in table:
            painted = any(line.startswith(k) for k in blind)
            lines.append(_red(line, use_color) if painted else line)
    lines.append("")

    lines.append("=== Errors / skipped sources ===")
    if not report.errors:
        lines.append("(none)")
    else:
        for err in report.errors:
            lines.append(f"- {err}")
    lines.append("")

    lines.append("=== Collector notes ===")
    if not report.notes:
        lines.append("(none)")
    else:
        for note in report.notes:
            lines.append(f"- {note}")
    return "\n".join(lines) + "\n"


def _positive_int(raw: str) -> int:
    """--stale-days must be >= 1: a negative made timedelta(days=-n) flag every bond."""
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {raw!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or greater")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="Bluejack.py",
        description=f"Read-only Windows Bluetooth host audit (v{__version__}).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Bluejack.py {__version__} (JSON schema {SCHEMA_VERSION})",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument(
        "--format",
        choices=("human", "json", "ndjson", "quiet"),
        default=None,
        help=(
            "Output format. 'ndjson' emits one self-contained finding per line for "
            "SIEM ingest. Overrides --json / --quiet if both are given."
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "info", "any", "never"),
        default="high",
        help=(
            "Lowest severity that exits 1. 'any' means any finding at all, 'never' "
            "always exits 0 for a successful scan. Default: high."
        ),
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Alias for --fail-on never. Use for pure collection runs.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Never emit ANSI colour. Also honoured via the NO_COLOR environment variable.",
    )
    parser.add_argument("--quiet", action="store_true", help="Findings only")
    parser.add_argument("--raise", dest="raise_errors", action="store_true", help="Abort on first source error")
    parser.add_argument(
        "--width",
        type=int,
        default=None,
        help="Table width in columns. 0 disables wrapping. Default: terminal width.",
    )
    parser.add_argument("--stale-days", type=_positive_int, default=90)
    parser.add_argument("--role", choices=("workstation", "conference"), default="workstation")
    parser.add_argument(
        "--require-admin",
        action="store_true",
        help=(
            "Exit 2 instead of reporting if any source was unreadable "
            "(usually means the scan was not elevated)"
        ),
    )
    args = parser.parse_args(argv)

    if sys.platform != "win32" and not os.environ.get("BLUEJACK_ALLOW_NON_WINDOWS"):
        sys.stderr.write("Bluejack.py live scan requires Windows.\n")
        return 2

    try:
        report = get_bluetooth_status(
            on_error="raise" if args.raise_errors else "continue",
            stale_days=args.stale_days,
            role=args.role,
        )
    except Exception as exc:
        sys.stderr.write(f"audit failed: {exc}\n")
        return 2

    if args.require_admin and report.summary.scan_complete == "No":
        blind = sorted(k for k, v in report.collection.items() if v in ACCESS_BLIND)
        sys.stderr.write(
            "scan incomplete, refusing to report under --require-admin. "
            f"Unreadable sources: {', '.join(blind)}\n"
            "Re-run from an elevated account.\n"
        )
        return 2

    # Rendering and serialization sit outside the scan, so a failure here used to
    # escape as a traceback and exit 1 — colliding with "High/Critical present".
    # Build the output first, then print; any failure is a scan failure, exit 2.
    fmt = args.format or ("json" if args.json else "quiet" if args.quiet else "human")
    try:
        if fmt == "json":
            output = report_to_json(report) + "\n"
        elif fmt == "ndjson":
            output = findings_to_ndjson(report)
        elif fmt == "quiet":
            output = "".join(
                f"[{f.severity.value}] {f.rule_id} | {f.mitre_technique} | "
                f"{f.target} | {f.detail}\n"
                for f in report.findings
            )
        else:
            output = render_report(
                report,
                color=False if args.no_color else None,
                width=args.width,
            )
    except Exception as exc:
        sys.stderr.write(f"report generation failed: {type(exc).__name__}: {exc}\n")
        return 2

    sys.stdout.write(output)

    threshold = "never" if args.exit_zero else args.fail_on
    return 1 if _meets_threshold(report.findings, threshold) else 0


def _meets_threshold(findings: list[Finding], threshold: str) -> bool:
    """Whether any finding is at or above the configured exit-code threshold."""
    if threshold == "never":
        return False
    if threshold == "any":
        return bool(findings)
    limit = _SEV_ORDER[Severity(threshold.capitalize())]
    return any(_SEV_ORDER.get(f.severity, 99) <= limit for f in findings)


if __name__ == "__main__":
    raise SystemExit(main())
