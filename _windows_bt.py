"""Windows I/O helpers for Bluejack.py. Read-only. No product-framework types.

v1.0.3 collector notes
----------------------
Previous versions spent 11 process launches on a single scan (8x sc.exe, 3x
powershell.exe), and the scan was dominated by process startup rather than by the
work itself. Three changes:

3.1  pnp_properties escaped backslashes for a WQL literal and then interpolated the
     result into a PowerShell *single-quoted* string, where backslashes are literal.
     `-eq $id` could therefore never match, so the CIM fast path always fell through
     to a second launch. Driver rows now come out of the batched snapshot and are
     matched in Python, so no instance id is interpolated into PowerShell at all.
     The per-device fallback still exists and escapes correctly for its context.

3.2  One PowerShell invocation returns a JSON envelope covering PnP entities, signed
     drivers, services and BTHENUM/BTHLE ids. Each section is independently guarded
     so a single failing query degrades that section rather than the whole snapshot.
     The WinRT radio query stays a separate, conditional launch: it is the expensive
     one and radio_powered() already short-circuits on the registry panel state.

3.3  sc.exe output is localized, so the STATE/START_TYPE regexes returned nothing on
     a non-English Windows and every service read came back Unknown. Service state
     now comes from advapi32 via ctypes and start type from the registry Start DWORD.
     Both are locale-invariant and neither spawns a process.

3.4  (folded in while _run_ps was being rewritten) System binaries are invoked by
     absolute path rather than resolved through PATH, since this tool is intended to
     run unattended and possibly as SYSTEM.

Expected launches per scan: 1, plus 1 if the radio state needs WinRT and 1 more if
it needs the Get-NetAdapter fallback.

NOT VALIDATED ON WINDOWS. The PowerShell in this module was written without a
Windows host to run it against. Every stage falls back to the previous per-call
behaviour, so a wrong query degrades rather than breaks, but the WQL filters
(DeviceClass='BLUETOOTH', the PNPDeviceID LIKE clauses) need confirming on a real
Win10/11 box.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any

# --- 3.4: resolve system binaries explicitly ---------------------------------
_SYSTEM_ROOT = os.environ.get("SystemRoot") or r"C:\Windows"
_SYS32 = os.path.join(_SYSTEM_ROOT, "System32")
_POWERSHELL = os.path.join(_SYS32, "WindowsPowerShell", "v1.0", "powershell.exe")

_CREATE_NO_WINDOW = 0x08000000  # keeps scheduled-task / Intune runs from flashing a console

SERVICES_OF_INTEREST = ("bthserv", "BthA2dp", "BthPan", "RFCOMM")


def _powershell_path() -> str:
    return _POWERSHELL if os.path.isfile(_POWERSHELL) else "powershell.exe"


def _run_ps(script: str, timeout: int = 30) -> str:
    if sys.platform != "win32":
        raise OSError("PowerShell Bluetooth queries require Windows")
    kwargs: dict[str, Any] = {}
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    else:
        kwargs["creationflags"] = _CREATE_NO_WINDOW
    completed = subprocess.run(
        [
            _powershell_path(),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-InputFormat",
            "None",
            "-OutputFormat",
            "Text",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        stdin=subprocess.DEVNULL,
        **kwargs,
    )
    if completed.returncode != 0:
        err = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(err or f"PowerShell exited {completed.returncode}")
    return (completed.stdout or "").strip()


def wql_escape(value: str) -> str:
    """Escape a value for a WQL string literal.

    WQL uses backslash as its escape character, so a backslash must be doubled here.
    This is correct for -Filter / -Query clauses and WRONG for a PowerShell
    single-quoted string, where backslashes are literal. Conflating the two is what
    broke the pnp_properties fast path.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def ps_single_quote(value: str) -> str:
    """Escape a value for a PowerShell single-quoted string: only the quote doubles."""
    return value.replace("'", "''")


# --- the batched collector ------------------------------------------------------
# Each section is wrapped so one failing query does not empty the whole snapshot.
_COLLECT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$out = [ordered]@{}
$errs = @()
$notes = @()

# Recorded so a bug report answers "which PowerShell?" without anyone having to ask.
# ConvertTo-Json behaviour differs between 5.1 and 7.x in ways that have already
# produced two wrong-looking reports.
try {
  $out['ps_version'] = [string]$PSVersionTable.PSVersion
  $out['ps_edition'] = [string]$PSVersionTable.PSEdition
} catch { $out['ps_version'] = $null; $out['ps_edition'] = $null }

try {
  $out['pnp'] = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='Bluetooth'" |
    Select-Object @{n='FriendlyName';e={$_.Name}},
                  @{n='InstanceId';e={$_.PNPDeviceID}},
                  Status, ConfigManagerErrorCode)
} catch { $out['pnp'] = @(); $errs += "pnp: $($_.Exception.Message)" }

$driverProps = @('DeviceID','Manufacturer','DriverVersion',
                 @{n='DriverDate';e={ if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { $null } }},
                 @{n='HardWareID';e={ @($_.HardWareID) -join '|' }})
try {
  $out['drivers'] = @(Get-CimInstance -ClassName Win32_PnPSignedDriver -Filter "DeviceClass='BLUETOOTH'" |
    Select-Object $driverProps)
  # DeviceClass is not populated consistently across drivers, so fall back to matching
  # the instance ids we already found. Slower (full enumeration) but still in-process,
  # so a miss costs milliseconds rather than another PowerShell launch.
  if (-not $out['drivers'] -or $out['drivers'].Count -eq 0) {
    $btIds = @($out['pnp'] | ForEach-Object { $_.InstanceId } | Where-Object { $_ })
    if ($btIds.Count -gt 0) {
      $out['drivers'] = @(Get-CimInstance -ClassName Win32_PnPSignedDriver |
        Where-Object { $btIds -contains $_.DeviceID } |
        Select-Object $driverProps)
      $notes += 'drivers: DeviceClass filter returned nothing; matched by InstanceId instead'
    }
  }
} catch { $out['drivers'] = @(); $errs += "drivers: $($_.Exception.Message)" }

try {
  $filter = "Name='bthserv' OR Name='BthA2dp' OR Name='BthPan' OR Name='RFCOMM'"
  $out['services'] = @(Get-CimInstance -ClassName Win32_Service -Filter $filter |
    Select-Object Name, State, StartMode)
} catch { $out['services'] = @(); $errs += "services: $($_.Exception.Message)" }

try {
  $q = "PNPDeviceID LIKE 'BTHENUM%' OR PNPDeviceID LIKE 'BTHLE%'"
  $out['bthenum'] = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter $q |
    Select-Object -ExpandProperty PNPDeviceID)
} catch { $out['bthenum'] = @(); $errs += "bthenum: $($_.Exception.Message)" }

$out['errors'] = @($errs)
$out['notes'] = @($notes)
[pscustomobject]$out | ConvertTo-Json -Compress -Depth 6
"""


def _as_rows(value: Any) -> list[Any]:
    """ConvertTo-Json collapses single-element arrays in some PowerShell versions."""
    value = _ps_unwrap(value)
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _ps_unwrap(value: Any) -> Any:
    """Normalise PowerShell's serialized-collection shape.

    ConvertTo-Json renders some collections (notably the string[] returned by
    Get-PnpDeviceProperty) as {"value": [...], "Count": n} rather than a bare array.
    Left alone that dict reaches the report and renders as a Python repr in the
    Hardware ID column. Unwrapping here keeps the shape out of the audit layer
    entirely rather than teaching every consumer about it.
    """
    if isinstance(value, dict):
        keys = {k.lower() for k in value}
        if "value" in keys and keys <= {"value", "count"}:
            inner = value.get("value", value.get("Value"))
            return _ps_unwrap(inner)
        return {k: _ps_unwrap(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_ps_unwrap(v) for v in value]
    return value


def split_registry_path(path: str) -> tuple[Any, str]:
    import winreg

    raw = path.replace("/", "\\")
    if raw.lower().startswith("hklm:\\"):
        raw = "HKLM\\" + raw[6:]
    elif raw.lower().startswith("hklm:"):
        raw = "HKLM\\" + raw[5:]
    raw = raw.replace("HKLM:\\", "HKLM\\")
    hive_name, _, sub = raw.partition("\\")
    hive_name = hive_name.upper()
    hives = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
    }
    if hive_name not in hives:
        raise ValueError(f"Unsupported hive in path: {path}")
    return hives[hive_name], sub.strip("\\")


def _convert_reg_value(value: Any, typ: int) -> Any:
    import winreg

    if typ == winreg.REG_DWORD or typ == getattr(winreg, "REG_QWORD", 11):
        return int(value)
    if typ == winreg.REG_MULTI_SZ:
        return list(value) if value is not None else []
    if typ == winreg.REG_BINARY:
        return bytes(value) if value is not None else b""
    if typ == winreg.REG_SZ or typ == winreg.REG_EXPAND_SZ:
        return value
    return value


# --- 3.3: locale-invariant service state via advapi32 ---------------------------
_SC_MANAGER_CONNECT = 0x0001
_SERVICE_QUERY_STATUS = 0x0004

# Values from SERVICE_STATUS.dwCurrentState. STOP_PENDING is reported as Stopped to
# match the previous sc.exe behaviour.
_SERVICE_STATE_NAMES = {
    1: "Stopped",
    2: "Start Pending",
    3: "Stopped",
    4: "Running",
    5: "Continue Pending",
    6: "Pause Pending",
    7: "Paused",
}

# HKLM\SYSTEM\CurrentControlSet\Services\<name>\Start
_SERVICE_START_NAMES = {
    0: "Automatic",  # boot
    1: "Automatic",  # system
    2: "Automatic",
    3: "Manual",
    4: "Disabled",
}

_SERVICES_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services"


def _query_service_state(name: str) -> str:
    """Service state from the SCM directly. No subprocess, no localized parsing."""
    if sys.platform != "win32":
        return "Unknown"
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return "Unknown"

    class _SERVICE_STATUS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
        ]

    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    except Exception:
        return "Unknown"

    advapi32.OpenSCManagerW.restype = ctypes.c_void_p
    advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.OpenServiceW.restype = ctypes.c_void_p
    advapi32.OpenServiceW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, wintypes.DWORD]
    advapi32.QueryServiceStatus.restype = wintypes.BOOL
    advapi32.QueryServiceStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(_SERVICE_STATUS)]
    advapi32.CloseServiceHandle.restype = wintypes.BOOL
    advapi32.CloseServiceHandle.argtypes = [ctypes.c_void_p]

    scm = advapi32.OpenSCManagerW(None, None, _SC_MANAGER_CONNECT)
    if not scm:
        return "Unknown"
    try:
        handle = advapi32.OpenServiceW(scm, name, _SERVICE_QUERY_STATUS)
        if not handle:
            return "Unknown"
        try:
            status = _SERVICE_STATUS()
            if not advapi32.QueryServiceStatus(handle, ctypes.byref(status)):
                return "Unknown"
            return _SERVICE_STATE_NAMES.get(int(status.dwCurrentState), "Unknown")
        finally:
            advapi32.CloseServiceHandle(handle)
    finally:
        advapi32.CloseServiceHandle(scm)


@dataclass
class PnpDevice:
    FriendlyName: str | None = None
    InstanceId: str | None = None
    Status: str | None = None
    Properties: dict[str, Any] = field(default_factory=dict)


def _devices_from_rows(rows: list[Any]) -> list[PnpDevice]:
    out: list[PnpDevice] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("FriendlyName") or row.get("Name")
        if not name or "Enumerator" in str(name):
            continue
        instance = row.get("InstanceId") or row.get("PNPDeviceID") or row.get("DeviceID")
        out.append(
            PnpDevice(
                FriendlyName=name,
                InstanceId=instance,
                Status=str(row.get("Status") or "") or None,
            )
        )
    return out


def _devices_from_json(raw: str) -> list[PnpDevice]:
    if not raw:
        return []
    data = json.loads(raw)
    return _devices_from_rows(_as_rows(data))


class WindowsBackend:
    """Live Windows backend: one batched CIM snapshot, winreg, ctypes; PS fallbacks."""

    def __init__(self) -> None:
        self._snapshot: dict[str, Any] | None = None
        self.snapshot_errors: list[str] = []
        self.snapshot_notes: list[str] = []

    def powershell_version(self) -> str | None:
        """Which PowerShell answered. Worth recording: ConvertTo-Json differs by version."""
        snapshot = self._collect()
        version = snapshot.get("ps_version")
        edition = snapshot.get("ps_edition")
        if not version:
            return None
        return f"{version} ({edition})" if edition else str(version)

    # --- snapshot ---------------------------------------------------------------
    def _collect(self) -> dict[str, Any]:
        """Run the batched collector once per backend instance."""
        if self._snapshot is not None:
            return self._snapshot
        snapshot: dict[str, Any] = {}
        try:
            raw = _run_ps(_COLLECT_SCRIPT, timeout=60)
            if raw:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    snapshot = parsed
        except Exception as exc:  # noqa: BLE001 - the whole point is to degrade
            self.snapshot_errors.append(f"collector: {exc}")
        for err in _as_rows(snapshot.get("errors")):
            if err:
                self.snapshot_errors.append(str(err))
        for note in _as_rows(snapshot.get("notes")):
            if note:
                self.snapshot_notes.append(str(note))
        self._snapshot = snapshot
        return snapshot

    def _section(self, name: str) -> list[Any]:
        return _as_rows(self._collect().get(name))

    # --- PnP --------------------------------------------------------------------
    def enum_pnp_bluetooth(self, present_only: bool = True) -> list[PnpDevice]:
        if present_only:
            found = _devices_from_rows(self._section("pnp"))
            if found:
                return found
        # Fallback, and the only path that can honour present_only=False: Win32_PnPEntity
        # does not enumerate absent devices, so the snapshot cannot answer that request.
        present = "$true" if present_only else "$false"
        script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$devs = @(Get-PnpDevice -Class Bluetooth -PresentOnly:{present} -ErrorAction SilentlyContinue |
    Where-Object {{ $_.FriendlyName -and ($_.FriendlyName -notmatch 'Enumerator') }} |
    Select-Object FriendlyName, InstanceId, Status)
if (-not $devs) {{ '[]' }} else {{ $devs | ConvertTo-Json -Compress -Depth 3 }}
"""
        try:
            return _devices_from_json(_run_ps(script))
        except Exception:
            return []

    def pnp_properties(self, instance_id: str) -> dict[str, Any]:
        if not instance_id:
            return {}
        props: dict[str, Any] = {}
        wanted = str(instance_id).strip().upper()
        for row in self._section("drivers"):
            if not isinstance(row, dict):
                continue
            if str(row.get("DeviceID") or "").strip().upper() != wanted:
                continue
            candidate = {
                "DEVPKEY_Device_Manufacturer": row.get("Manufacturer"),
                "DEVPKEY_Device_DriverVersion": row.get("DriverVersion"),
                "DEVPKEY_Device_DriverDate": row.get("DriverDate"),
                # Joined in PowerShell to dodge ConvertTo-Json's collection shapes.
                "DEVPKEY_Device_HardwareIds": [
                    p for p in str(row.get("HardWareID") or "").split("|") if p
                ],
            }
            props.update({k: v for k, v in candidate.items() if v not in (None, "", [])})
            break
        if props.get("DEVPKEY_Device_Manufacturer") and props.get("DEVPKEY_Device_DriverVersion"):
            return self._normalize_hwids(props)

        # Per-device fallback. Single-quoted PowerShell literal: only the quote doubles.
        script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$id = '{ps_single_quote(instance_id)}'
$keys = @(
  'DEVPKEY_Device_Manufacturer',
  'DEVPKEY_Device_DriverVersion',
  'DEVPKEY_Device_DriverDate',
  'DEVPKEY_Device_HardwareIds',
  'DEVPKEY_Bluetooth_DeviceAddress'
)
$out = @{{}}
foreach ($k in $keys) {{
  $p = Get-PnpDeviceProperty -InstanceId $id -KeyName $k -ErrorAction SilentlyContinue
  if ($p) {{ $out[$k] = $p.Data }}
}}
$out | ConvertTo-Json -Compress -Depth 5
"""
        try:
            raw = _run_ps(script)
            if raw:
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = _ps_unwrap(data)
                    props.update({k: v for k, v in data.items() if v not in (None, "")})
        except Exception:
            pass
        return self._normalize_hwids(props)

    @staticmethod
    def _normalize_hwids(props: dict[str, Any]) -> dict[str, Any]:
        hid = _ps_unwrap(props.get("DEVPKEY_Device_HardwareIds"))
        if hid is None:
            props.pop("DEVPKEY_Device_HardwareIds", None)
            return props
        if isinstance(hid, str):
            hid = [hid]
        if isinstance(hid, list):
            flat: list[str] = []
            for item in hid:
                item = _ps_unwrap(item)
                if isinstance(item, list):
                    flat.extend(str(x) for x in item if x)
                elif item not in (None, ""):
                    flat.append(str(item))
            hid = flat
        props["DEVPKEY_Device_HardwareIds"] = hid
        return props

    # --- profiles ---------------------------------------------------------------
    def live_profile_flags(self) -> dict[str, str]:
        flags = {k: "Unknown" for k in ("hid", "hogp", "spp", "dun", "a2dp", "pan")}
        for svc, profile in (("BthA2dp", "a2dp"), ("BthPan", "pan"), ("RFCOMM", "spp")):
            if self.service_status(svc).get("state") == "Running":
                flags[profile] = "Yes"
        ids = self._section("bthenum")
        if not ids:
            return flags
        blob = " ".join(str(i) for i in ids).lower()
        mapping = {
            "hid": "00001124",
            "hogp": "00001812",
            "spp": "00001101",
            "dun": "00001103",
            "a2dp": "0000110a",
            "pan": "00001115",
        }
        for profile, token in mapping.items():
            if token in blob:
                flags[profile] = "Yes"
        if "0000110b" in blob:
            flags["a2dp"] = "Yes"
        if "00001116" in blob:
            flags["pan"] = "Yes"
        return flags

    # --- registry ---------------------------------------------------------------
    def registry_key_exists(self, path: str) -> bool:
        import winreg

        try:
            hive, sub = split_registry_path(path)
            winreg.CloseKey(winreg.OpenKey(hive, sub))
            return True
        except OSError:
            return False

    def registry_list_subkeys(self, path: str) -> list[str]:
        import winreg

        hive, sub = split_registry_path(path)
        key = winreg.OpenKey(hive, sub)
        try:
            names: list[str] = []
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(key, i)
                except OSError:
                    break
                names.append(path.rstrip("\\") + "\\" + name)
                i += 1
            return names
        finally:
            winreg.CloseKey(key)

    def registry_get_values(self, path: str) -> dict[str, Any]:
        import winreg

        hive, sub = split_registry_path(path)
        key = winreg.OpenKey(hive, sub)
        try:
            values: dict[str, Any] = {}
            i = 0
            while True:
                try:
                    name, val, typ = winreg.EnumValue(key, i)
                except OSError:
                    break
                values[name] = _convert_reg_value(val, typ)
                i += 1
            return values
        finally:
            winreg.CloseKey(key)

    def registry_get_value(self, path: str, name: str) -> Any:
        import winreg

        try:
            hive, sub = split_registry_path(path)
            key = winreg.OpenKey(hive, sub)
            try:
                val, typ = winreg.QueryValueEx(key, name)
                return _convert_reg_value(val, typ)
            finally:
                winreg.CloseKey(key)
        except OSError:
            return None

    # --- services ---------------------------------------------------------------
    def service_status(self, name: str) -> dict[str, str]:
        """State from the SCM, start type from the registry. No sc.exe, no locale risk."""
        state = _query_service_state(name)
        start_type = "Unknown"
        try:
            raw_start = self.registry_get_value(f"{_SERVICES_KEY}\\{name}", "Start")
        except Exception:  # noqa: BLE001 - a status probe must never raise
            raw_start = None
        if isinstance(raw_start, int) and not isinstance(raw_start, bool):
            start_type = _SERVICE_START_NAMES.get(raw_start, f"Unknown({raw_start})")

        if state == "Unknown" or start_type == "Unknown":
            for row in self._section("services"):
                if not isinstance(row, dict):
                    continue
                if str(row.get("Name") or "").lower() != name.lower():
                    continue
                if state == "Unknown":
                    # Win32_Service.State is an invariant English string, not localized.
                    token = str(row.get("State") or "").strip()
                    if token:
                        state = "Stopped" if token.lower().startswith("stop") else token
                if start_type == "Unknown":
                    mode = str(row.get("StartMode") or "").strip().lower()
                    start_type = {
                        "auto": "Automatic",
                        "manual": "Manual",
                        "disabled": "Disabled",
                        "boot": "Automatic",
                        "system": "Automatic",
                    }.get(mode, start_type)
                break
        return {"state": state, "start_type": start_type}

    # --- radio ------------------------------------------------------------------
    def radio_powered(self) -> str:
        """Settings toggle / software radio power. Does not change radio state."""
        panel = self._control_panel_radio_state()
        if panel in {"On", "Off"}:
            return panel
        winrt = self._winrt_bluetooth_radio_state()
        if winrt in {"On", "Off"}:
            return winrt
        return self._netadapter_radio_state()

    def _control_panel_radio_state(self) -> str:
        raw = self.registry_get_value(
            r"HKLM\SYSTEM\CurrentControlSet\Services\bthserv\Parameters\BluetoothControlPanelTasks",
            "state",
        )
        if raw in (1, True) or raw == "1":
            return "On"
        if raw in (0, False) or raw == "0":
            return "Off"
        return "Unknown"

    def _winrt_bluetooth_radio_state(self) -> str:
        if sys.platform != "win32":
            return "Unknown"
        script = r"""
$ErrorActionPreference = 'SilentlyContinue'
try {
  Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
  $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() |
    Where-Object {
      $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
      $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    })[0]
  function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $null = $netTask.Wait(8000)
    $netTask.Result
  }
  $null = [Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime]
  $radios = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])
  $bt = @($radios | Where-Object { $_.Kind -eq 'Bluetooth' }) | Select-Object -First 1
  if ($bt) { [string]$bt.State } else { 'Unknown' }
} catch { 'Unknown' }
"""
        try:
            raw = _run_ps(script, timeout=20)
            token = (raw.splitlines()[-1] if raw else "").strip()
            if token.lower() == "on":
                return "On"
            if token.lower() == "off":
                return "Off"
        except Exception:
            return "Unknown"
        return "Unknown"

    def _netadapter_radio_state(self) -> str:
        if sys.platform != "win32":
            return "Unknown"
        script = """
$ErrorActionPreference = 'SilentlyContinue'
$n = Get-NetAdapter | Where-Object {
  $_.InterfaceDescription -match 'Bluetooth' -or $_.Name -match 'Bluetooth'
}
if ($n) {
  $up = @($n | Where-Object { $_.Status -eq 'Up' })
  if ($up.Count -gt 0) { 'On' } else { 'Off' }
} else { 'Unknown' }
"""
        try:
            raw = _run_ps(script)
            token = raw.splitlines()[-1].strip() if raw else "Unknown"
            if token in {"On", "Off", "Unknown"}:
                return token
        except Exception:
            return "Unknown"
        return "Unknown"
