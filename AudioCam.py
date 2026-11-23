#!/usr/bin/env python3
"""AudioCam.py — inventory active and historical Windows cameras / microphones.

Read-only audit of:
  * Plug and Play cameras and audio capture endpoints currently attached
  * CapabilityAccessManager ConsentStore usage / consent history
  * MMDevices capture endpoints and Enum hardware remnants

Run:
    python AudioCam.py
    python AudioCam.py --json
    python AudioCam.py --csv

Standard library only (win32com is an optional live-device fallback).
Windows 10/11. Does not write to the registry.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import csv
import ctypes
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, TypedDict, TypeVar

try:
    import winreg  # type: ignore
except ImportError:
    winreg = None  # type: ignore

try:
    from pyfiglet import Figlet as _Figlet  # type: ignore
except ImportError:
    _Figlet = None  # type: ignore


# ---------------------------------------------------------------------------
# Device-classification and scoring heuristics are tuned for consumer hardware.
# ---------------------------------------------------------------------------

# A bare "Input" used to live in _MIC_RE. Every HID keyboard and mouse
# describes itself as "USB Input Device", so it matched them all and their
# VID/PIDs then polluted the capture-hardware catalog. "Audio Input" is the
# only Input that means a microphone.
_MIC_RE = re.compile(
    r"Microphone|Capture|Audio\s*Input|Recording|Line In|Stereo Mix|What U Hear|\bMic\b",
    re.I,
)
_STEREO_RE = re.compile(r"Stereo Mix|What U Hear|Wave Out Mix|Loopback", re.I)
_CAMERA_RE = re.compile(r"Camera|Webcam|UVC|Video Capture", re.I)
_SCANNER_RE = re.compile(r"Scanner|Still.?Image|WIA\\", re.I)
_VIRTUAL_RE = re.compile(r"^SWD\\|^ROOT\\", re.I)
_VIDPID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})")

# A name that only a real capture device would carry. Used to rescue a node
# whose setup class looks like noise (a USB headset sits under HIDClass).
_CAPTURE_STRONG_RE = re.compile(
    r"Microphone|\bMic\b|Webcam|Camera|UVC|Headset|Video Capture|Stereo Mix|What U Hear",
    re.I,
)
# Generic descriptions the PnP stack gives to hubs, composite parents and HID
# collections. On their own they never identify a microphone or a camera.
_GENERIC_DESC_RE = re.compile(
    r"USB Input Device|HID.?compliant|Composite Device|USB Root Hub|Generic USB",
    re.I,
)
# Setup classes that are not capture devices unless the name says otherwise.
_NON_CAPTURE_CLASSES = {
    "hidclass",
    "keyboard",
    "mouse",
    "usb",
    "usbdevice",
    "printer",
    "monitor",
    "net",
    "volume",
    "diskdrive",
    "battery",
    "bluetooth",
    "ports",
    "system",
    "wpd",
    "firmware",
}

__version__ = "1.1.0"

CONSENT_REL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
MMDEVICES_CAPTURE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture"
MMDEVICES_RENDER = r"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
ENUM_ROOT = r"SYSTEM\CurrentControlSet\Enum"

# MMDevices PROPERTYKEY names as they appear under ...\<guid>\Properties
_PKEY_FRIENDLY = "{a45c254e-df1c-4efd-8020-67d146a850e0},14"
_PKEY_DESC = "{a45c254e-df1c-4efd-8020-67d146a850e0},2"
_PKEY_MFG = "{a45c254e-df1c-4efd-8020-67d146a850e0},13"
_PKEY_IFACE_NAME = "{026e516e-b814-414b-83cd-856d6fef4822},2"
_PKEY_INSTANCE_PATH = "{b3f8fa53-0004-438e-9003-51a46e139bfc},2"

RED = "\033[1;31m"
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"

# Fallback FIGlet "standard" rendering of AudioCam.py (used if pyfiglet is absent)
_BANNER_FALLBACK = r"""
    _             _ _        ____
   / \  _   _  __| (_) ___  / ___|__ _ _ __ ___
  / _ \| | | |/ _` | |/ _ \ |   / _` | '_ ` _ \
 / ___ \ |_| | (_| | | (_) | |__| (_| | | | | | |
/_/   \_\__,_|\__,_|_|\___/ \____\__,_|_| |_| |_|
                                            .py
""".lstrip("\n")

FILETIME_ZERO = datetime(1601, 1, 1, tzinfo=timezone.utc)
SKIP_HKU = {".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_windows() -> bool:
    return os.name == "nt" and winreg is not None


def is_elevated() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


_CURRENT_SID: str | None = None


def _sid_from_token() -> str:
    """String SID of this process token, via advapi32."""
    advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    # Explicit signatures: the default ctypes int return truncates HANDLEs on x64.
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetTokenInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]

    TOKEN_QUERY = 0x0008
    TOKEN_USER = 1

    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
    ):
        return ""
    try:
        size = ctypes.c_ulong(0)
        advapi32.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(size))
        if not size.value:
            return ""
        buf = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(
            token, TOKEN_USER, buf, size.value, ctypes.byref(size)
        ):
            return ""
        # TOKEN_USER is a SID_AND_ATTRIBUTES: { PSID Sid; DWORD Attributes; }
        sid_ptr = ctypes.c_void_p.from_buffer(buf)
        out = ctypes.c_wchar_p()
        if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(out)):
            return ""
        try:
            return _safe_str(out.value)
        finally:
            kernel32.LocalFree(out)
    finally:
        kernel32.CloseHandle(token)


def _sid_from_profile_list() -> str:
    """Fallback: match %USERNAME% against ProfileList\\<SID>\\ProfileImagePath."""
    user = (os.environ.get("USERNAME") or "").strip().lower()
    if not user:
        return ""
    root = _try_open(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
    )
    if root is None:
        return ""
    try:
        for sid in _enum_subkeys(root):
            if not sid.startswith("S-1-5-21-"):
                continue
            key = _try_open(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" + "\\" + sid,
            )
            if key is None:
                continue
            try:
                path = _safe_str(_read_values(key).get("ProfileImagePath") or "")
            finally:
                winreg.CloseKey(key)
            if path and Path(path).name.lower() == user:
                return sid
    except OSError:
        return ""
    finally:
        winreg.CloseKey(root)
    return ""


def current_user_sid() -> str:
    """SID of the calling user, cached.

    HKEY_CURRENT_USER is a view of HKU\\<this SID>. Without this, ConsentStore
    is walked once as HKCU and again as HKU\\<SID>, and every access trace for
    the current user is reported twice with identical timestamps.
    """
    global _CURRENT_SID
    if _CURRENT_SID is not None:
        return _CURRENT_SID
    sid = ""
    if is_windows():
        try:
            sid = _sid_from_token()
        except Exception:
            sid = ""
        if not sid:
            try:
                sid = _sid_from_profile_list()
            except Exception:
                sid = ""
    _CURRENT_SID = sid
    return sid


def filetime_to_dt(raw: Any) -> datetime | None:
    """Windows FILETIME (100-ns since 1601-01-01 UTC) → aware datetime, or None."""
    try:
        if raw is None:
            return None
        if isinstance(raw, bytes):
            if len(raw) < 8:
                return None
            raw = int.from_bytes(raw[:8], "little", signed=False)
        value = int(raw)
        if value <= 0:
            return None
        dt = FILETIME_ZERO + timedelta(microseconds=value / 10.0)
        if dt.year < 2000 or dt.year > 2100:
            return None
        return dt
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def filetime_to_str(raw: Any, local: bool = True) -> str:
    dt = filetime_to_dt(raw)
    if dt is None:
        return ""
    if local:
        dt = dt.astimezone()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def filetime_to_iso(raw: Any) -> str:
    """FILETIME -> ISO-8601 with UTC offset, e.g. 2026-08-30T14:03:22-04:00.

    The display strings elsewhere are local time with no zone attached, which
    is fine on a terminal and useless in a CSV that someone is lining up
    against event logs. Machine-readable output carries the offset.
    """
    dt = filetime_to_dt(raw)
    return dt.astimezone().isoformat(timespec="seconds") if dt else ""


def epoch_to_iso(seconds: float) -> str:
    """POSIX seconds -> ISO-8601 with UTC offset."""
    try:
        return (
            datetime.fromtimestamp(seconds, timezone.utc)
            .astimezone()
            .isoformat(timespec="seconds")
        )
    except (OSError, OverflowError, ValueError):
        return ""


def duration_str(start_raw: Any, stop_raw: Any) -> str:
    start = filetime_to_dt(start_raw)
    stop = filetime_to_dt(stop_raw)
    if start is None or stop is None or stop < start:
        return ""
    seconds = int((stop - start).total_seconds())
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def decode_nonpackaged(name: str) -> str:
    """ConsentStore NonPackaged keys store paths with # instead of backslash."""
    return name.replace("#", "\\") if name else name


def classify_capability(name: str) -> str:
    n = (name or "").lower()
    if n == "webcam":
        return "Camera"
    if n == "microphone":
        return "Microphone"
    return name


def is_virtual(instance_id: str) -> bool:
    return bool(_VIRTUAL_RE.search(instance_id or ""))


def classify_audio(name: str) -> str | None:
    """Microphone vs loopback output vs ignore. None = not a capture-relevant endpoint."""
    text = name or ""
    if _STEREO_RE.search(text) and not re.search(r"Microphone|\bMic\b", text, re.I):
        return "AudioOutput"
    if _MIC_RE.search(text):
        return "Microphone"
    return None


def extract_all_vidpids(*blobs: Any) -> list[str]:
    """Return every USB VID/PID or HDAUDIO VEN/DEV found in registry-style strings."""
    found: list[str] = []
    seen: set[str] = set()
    chunks: list[str] = []
    for blob in blobs:
        if blob is None:
            continue
        if isinstance(blob, (list, tuple)):
            chunks.extend(_safe_str(x) for x in blob)
        elif isinstance(blob, bytes):
            chunks.append(_safe_str(blob))
        else:
            chunks.append(str(blob))
    hay = " ".join(chunks)
    for m in _VIDPID_RE.finditer(hay):
        token = f"VID_{m.group(1).upper()}&PID_{m.group(2).upper()}"
        if token not in seen:
            seen.add(token)
            found.append(token)
    for m in re.finditer(r"VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})", hay, re.I):
        token = f"VEN_{m.group(1).upper()}&DEV_{m.group(2).upper()}"
        if token not in seen:
            seen.add(token)
            found.append(token)
    return found


def vid_pid(instance_id: str) -> str:
    """Pull USB VID/PID (or HDAUDIO VEN/DEV) out of a registry path / HardwareID."""
    ids = extract_all_vidpids(instance_id)
    return ids[0] if ids else ""


def format_vidpid_label(vidpid: str, name: str = "") -> str:
    name = _safe_str(name).strip()
    if name and name not in {"Unknown", "n/a (app access record)"}:
        return f"{vidpid} [{name}]"
    return vidpid


def color_allow(value: str) -> str:
    text = _safe_str(value)
    if text == "Allow" and sys.stdout.isatty():
        return f"{RED}{text}{RESET}"
    return text


def enable_ansi() -> None:
    if os.name != "nt":
        return
    try:
        handle = ctypes.windll.kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint()
        if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def print_banner() -> None:
    """File header: AudioCam.py rendered via pyfiglet when installed."""
    banner = ""
    if _Figlet is not None:
        try:
            banner = _Figlet(font="standard", width=120).renderText("AudioCam.py").rstrip()
        except Exception:
            banner = ""
    if not banner:
        banner = _BANNER_FALLBACK.rstrip()
    if sys.stdout.isatty():
        print(f"{BOLD}{banner}{RESET}")
    else:
        print(banner)


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-16le").rstrip("\x00")
        except Exception:
            return value.decode("utf-8", "replace")
    return str(value)


def _clean_reg_desc(text: str) -> str:
    """DeviceDesc / Mfg often look like '@foo.dll,-123;USB Camera' or 'USB Camera;x;y'."""
    if not text:
        return ""
    part = text.split(";")[-1].strip()
    if part.startswith("@"):
        return ""
    return part


# ---------------------------------------------------------------------------
# Source status — an empty table and an unreadable source are not the same
# ---------------------------------------------------------------------------

_SOURCE_STATUS: list[SourceStatusRow] = []

# An audit source can be in one of three states, and collapsing them into a
# boolean was itself a reporting bug: "CapabilityAccessManager.db: not present"
# is the normal condition on Windows 10, not a failure to read anything.
STATE_OK = "ok"
STATE_ABSENT = "absent"
STATE_FAIL = "fail"

# Ceiling on a SQLite sidecar file copied during a snapshot read.
_MAX_SIDECAR_BYTES = 256 * 1024 * 1024


_SOURCE_STATUS_LOCK = threading.Lock()

# Sources are rendered in this order regardless of which worker thread finished
# first. Non-deterministic output from an audit tool is a defect: two runs of
# the same command on an unchanged host must produce the same report.
_SOURCE_ORDER = (
    "ConsentStore (registry)",
    "MMDevices",
    "Enum hardware nodes (registry)",
    "CapabilityAccessManager.db",
    "Live PnP enumeration",
    "Publisher lookup (Authenticode)",
    "Process list (LIVE PID attach)",
    "Firefox permissions.sqlite",
    "Chromium",
)


def record_source_status(name: str, state: str, detail: str = "") -> None:
    with _SOURCE_STATUS_LOCK:
        _SOURCE_STATUS.append({"Source": name, "State": state, "Detail": detail})


def _source_status_sorted() -> list[SourceStatusRow]:
    """Status entries in the declared order, with unlisted sources appended."""

    def rank(entry: SourceStatusRow) -> tuple[int, str]:
        source = entry.get("Source") or ""
        for index, prefix in enumerate(_SOURCE_ORDER):
            if source.startswith(prefix):
                return (index, source)
        return (len(_SOURCE_ORDER), source)

    with _SOURCE_STATUS_LOCK:
        return sorted(_SOURCE_STATUS, key=rank)


def _safe_is_file(path: Path) -> bool:
    """Path.is_file() that answers False instead of raising.

    pathlib swallows only ENOENT, ENOTDIR, EBADF and ELOOP. EACCES propagates,
    so probing for a file inside a directory the caller cannot traverse raises
    PermissionError. C:\\ProgramData\\Microsoft\\Windows\\CapabilityAccessManager
    is exactly such a directory: it is ACL'd to SYSTEM, and an unelevated run
    got WinError 5 from the existence check itself, before any open was
    attempted.
    """
    try:
        return path.is_file()
    except OSError:
        return False


def _access_denied(path: Path) -> bool:
    """True when the path exists but cannot be examined.

    Needed because _safe_is_file answers False for both "no such file" and
    "not allowed to look", and those are different findings.
    """
    try:
        path.stat()
        return False
    except PermissionError:
        return True
    except OSError as exc:
        if getattr(exc, "winerror", None) == 5:
            return True
    except Exception:
        return False
    try:
        next(iter(path.parent.iterdir()), None)
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def _safe_size(path: Path) -> int:
    """File size, or -1 when it cannot be determined."""
    try:
        return path.stat().st_size
    except OSError:
        return -1


@contextlib.contextmanager
def readonly_sqlite(db: Path, timeout: float = 0.5):
    """Yield (connection, state, detail) for a SQLite file, without writing to it.

    A plain mode=ro open fails on a WAL database whose owner still holds it,
    which is the normal state of Firefox's permissions.sqlite and of CAM.db.
    The old code swallowed that and returned no rows, so a locked file looked
    exactly like a browser with no grants. When the direct open fails, take a
    private snapshot of the database and its -wal and read that instead. The
    original is only ever read.

    A file that simply is not there yields STATE_ABSENT, not STATE_FAIL.
    """
    import sqlite3

    if not _safe_is_file(db):
        # Distinguish "no such file" from "cannot even look": on a protected
        # directory the two are indistinguishable to is_file(), so ask.
        try:
            db.parent.iterdir().__next__()
        except PermissionError as exc:
            yield None, STATE_FAIL, f"cannot read {db.parent}: {exc}"
            return
        except (OSError, StopIteration):
            pass
        yield None, STATE_ABSENT, "not present"
        return

    conn = None
    tmpdir = ""
    try:
        try:
            conn = sqlite3.connect(
                db.resolve().as_uri() + "?mode=ro", uri=True, timeout=timeout
            )
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            yield conn, STATE_OK, "read-only open"
            return
        except Exception as exc:
            direct_error = str(exc)
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()
                conn = None

        try:
            tmpdir = tempfile.mkdtemp(prefix="audiocam_")
            skipped_wal = False
            # -shm is deliberately not copied: SQLite rebuilds it from -wal,
            # and a stale copy can make the snapshot unreadable.
            #
            # The -wal is capped. CapabilityAccessManager.db-wal is known to
            # run away to tens of gigabytes on some Windows 11 builds, and
            # copying that to fill the user's disk would be a worse failure
            # than reading a slightly older checkpoint.
            for suffix in ("", "-wal", "-journal"):
                source = db.with_name(db.name + suffix)
                if not _safe_is_file(source):
                    continue
                size = _safe_size(source)
                if suffix and size > _MAX_SIDECAR_BYTES:
                    skipped_wal = True
                    continue
                shutil.copy2(source, Path(tmpdir) / source.name)
            conn = sqlite3.connect(str(Path(tmpdir) / db.name), timeout=timeout)
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            note = "read from private snapshot (source was locked)"
            if skipped_wal:
                note += (
                    "; write-ahead log over "
                    f"{_MAX_SIDECAR_BYTES // (1024 * 1024)} MB was skipped, so the "
                    "newest uncheckpointed entries may be missing"
                )
            yield conn, STATE_OK, note
            return
        except Exception as exc:
            yield None, STATE_FAIL, f"unreadable: {direct_error}; snapshot also failed: {exc}"
            return
    finally:
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Registry primitives
# ---------------------------------------------------------------------------

# The registry view that works on this host, probed once. Trying both views on
# every single open cost up to two OpenKeyEx calls per key, and the Enum walk
# performs thousands of them.
_REG_VIEW: int | None = None
_REG_VIEW_LOCK = threading.Lock()


def _reg_views() -> tuple[int, ...]:
    """Preferred view first, then the other one as a one-time fallback."""
    if _REG_VIEW is not None:
        return (_REG_VIEW, )
    return (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)


def _remember_view(view: int) -> None:
    global _REG_VIEW
    if _REG_VIEW is None:
        with _REG_VIEW_LOCK:
            if _REG_VIEW is None:
                _REG_VIEW = view


def _open_failure_reason(exc: OSError | None) -> str:
    if exc is None:
        return "unknown"
    code = getattr(exc, "winerror", None)
    if code == 2:
        return "key not present"
    if code == 5:
        return "access denied"
    return f"{type(exc).__name__}: {exc}"


def _try_open_ex(hive, path: str):
    """(key or None, reason). reason is '' on success.

    Distinguishing 'key not present' from 'access denied' is what lets the
    source-status block tell a user that an empty table means "run elevated"
    rather than "nothing happened".
    """
    last: OSError | None = None
    for view in _reg_views():
        try:
            key = winreg.OpenKeyEx(hive, path, 0, winreg.KEY_READ | view)
        except OSError as exc:
            last = exc
            continue
        _remember_view(view)
        return key, ""
    if _REG_VIEW is not None and last is not None and getattr(last, "winerror", None) != 2:
        # The cached view failed for a reason other than "no such key"; retry
        # once against the other view before reporting a failure.
        other = (
            winreg.KEY_WOW64_32KEY
            if _REG_VIEW == winreg.KEY_WOW64_64KEY
            else winreg.KEY_WOW64_64KEY
        )
        try:
            return winreg.OpenKeyEx(hive, path, 0, winreg.KEY_READ | other), ""
        except OSError as exc:
            last = exc
    return None, _open_failure_reason(last)


def _try_open(hive, path: str):
    return _try_open_ex(hive, path)[0]


def _open_child(parent, name: str):
    """Open a subkey relative to an already-open handle, or None.

    Opening by full path from the hive root re-parses and re-walks the whole
    path for every device and every instance. Relative opens are what make the
    Enum sweep affordable on a machine with a large USB or HID tree.
    """
    for view in _reg_views():
        try:
            key = winreg.OpenKeyEx(parent, name, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        _remember_view(view)
        return key
    return None


def _enum_subkeys(key) -> list[str]:
    names: list[str] = []
    i = 0
    while True:
        try:
            names.append(winreg.EnumKey(key, i))
            i += 1
        except OSError:
            break
    return names


def _read_values(key) -> dict[str, Any]:
    out: dict[str, Any] = {}
    i = 0
    while True:
        try:
            name, data, _typ = winreg.EnumValue(key, i)
            out[name] = data
            i += 1
        except OSError:
            break
    return out


def iter_loaded_user_sids(exclude: str = "") -> list[str]:
    """Loaded HKU SIDs, minus service accounts and (by default) the caller."""
    key = _try_open(winreg.HKEY_USERS, "")
    if key is None:
        return []
    skip = {s.lower() for s in SKIP_HKU}
    if exclude:
        skip.add(exclude.lower())
    try:
        sids = []
        for name in _enum_subkeys(key):
            if name.endswith("_Classes") or name.lower() in skip:
                continue
            if name.startswith("S-1-"):
                sids.append(name)
        return sids
    finally:
        winreg.CloseKey(key)


def _consent_roots() -> list[tuple[str, Any, str, bool]]:
    """(label, hive, relative path, is_user_hive).

    HKCU is listed once. The matching HKU\\<SID> is suppressed so the current
    user's ConsentStore is not enumerated twice.
    """
    own_sid = current_user_sid()
    label = f"HKCU (S-{own_sid.split('S-', 1)[-1]})" if own_sid else "HKCU"
    roots: list[tuple[str, Any, str, bool]] = [
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, CONSENT_REL, False),
        (label, winreg.HKEY_CURRENT_USER, CONSENT_REL, True),
    ]
    for sid in iter_loaded_user_sids(exclude=own_sid):
        roots.append((f"HKU\\{sid}", winreg.HKEY_USERS, sid + "\\" + CONSENT_REL, True))
    return roots


# ---------------------------------------------------------------------------
# Table 1 sources
# ---------------------------------------------------------------------------

def read_consent_summary() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for label, hive, base, _is_user in _consent_roots():
        for cap in ("microphone", "webcam"):
            key = _try_open(hive, base + "\\" + cap)
            value = "Missing"
            if key is not None:
                try:
                    vals = _read_values(key)
                    value = _safe_str(vals.get("Value") or "Unknown")
                finally:
                    winreg.CloseKey(key)
            rows.append(
                {
                    "Hive": label,
                    "Capability": classify_capability(cap),
                    "GlobalConsent": value,
                }
            )
    return rows


def iter_consentstore() -> list[AccessTraceRow]:
    rows: list[dict[str, str]] = []
    seen: set[tuple] = set()
    # When the SID could not be resolved, HKCU and HKU\<SID> may still overlap.
    # Fall back to deduping user-hive rows on their content instead of the label.
    sid_known = bool(current_user_sid())
    read_hives: list[str] = []
    denied: list[str] = []
    for label, hive, base, is_user in _consent_roots():
        opened_any = False
        for cap in ("microphone", "webcam"):
            cap_path = base + "\\" + cap
            cap_key, reason = _try_open_ex(hive, cap_path)
            if cap_key is None:
                if reason == "access denied" and label not in denied:
                    denied.append(label)
                continue
            opened_any = True
            try:
                _walk_consent_key(
                    hive=hive,
                    hive_label=label,
                    capability=cap,
                    key=cap_key,
                    key_path=cap_path,
                    under_nonpackaged=False,
                    rows=rows,
                    seen=seen,
                    dedupe_on_content=is_user and not sid_known,
                )
            finally:
                winreg.CloseKey(cap_key)
        if opened_any:
            read_hives.append(label)

    detail = f"{len(read_hives)} hive(s) read ({', '.join(read_hives) or 'none'}); {len(rows)} trace row(s)"
    if denied:
        detail += f"; access denied on {', '.join(denied)}"
        if not is_elevated():
            detail += " — run elevated to include"
    record_source_status(
        "ConsentStore (registry)",
        STATE_OK if read_hives else STATE_FAIL,
        detail,
    )
    return rows


def _walk_consent_key(
    *,
    hive,
    hive_label: str,
    capability: str,
    key,
    key_path: str,
    under_nonpackaged: bool,
    rows: list[dict[str, str]],
    seen: set[tuple],
    dedupe_on_content: bool = False,
) -> None:
    values = _read_values(key)
    subkeys = _enum_subkeys(key)
    leaf = key_path.rsplit("\\", 1)[-1]
    is_container = leaf.lower() in {"microphone", "webcam", "nonpackaged"}
    has_times = "LastUsedTimeStart" in values or "LastUsedTimeStop" in values

    if has_times and not is_container:
        app_type = "NonPackaged" if under_nonpackaged else "Packaged"
        app_name = decode_nonpackaged(leaf) if app_type == "NonPackaged" else leaf
        start = values.get("LastUsedTimeStart")
        stop = values.get("LastUsedTimeStop")
        start_dt = filetime_to_dt(start)
        stop_dt = filetime_to_dt(stop)
        notes = ""
        if start_dt and not stop_dt:
            notes = "Possibly still open (no stop time)"
        elif start_dt and stop_dt and stop_dt < start_dt:
            notes = "Possibly still open (stop < start)"

        if dedupe_on_content:
            dedupe = ("USER", capability, app_name.lower(), str(start), str(stop))
        else:
            dedupe = (hive_label, capability, app_name.lower())
        if dedupe not in seen:
            seen.add(dedupe)
            rows.append(
                {
                    "Source": "ConsentStore",
                    "Capability": classify_capability(capability),
                    "Hive": hive_label,
                    "AppType": app_type,
                    "Application": app_name,
                    "Make": "",
                    "Model": "n/a (app access record)",
                    "Consent": _safe_str(values.get("Value") or ""),
                    "LastStart": filetime_to_str(start),
                    "LastStop": filetime_to_str(stop),
                    "LastStartISO": filetime_to_iso(start),
                    "LastStopISO": filetime_to_iso(stop),
                    # A ConsentStore app key stores no hardware ID at all.
                    "VidPidObserved": "",
                    "VidPidCorrelated": "",
                    "VidPidSource": "none",
                    "Duration": duration_str(start, stop),
                    "Notes": notes,
                }
            )

    for sub in subkeys:
        child_path = key_path + "\\" + sub
        child = _try_open(hive, child_path)
        if child is None:
            continue
        try:
            child_np = under_nonpackaged or sub.lower() == "nonpackaged"
            _walk_consent_key(
                hive=hive,
                hive_label=hive_label,
                capability=capability,
                key=child,
                key_path=child_path,
                under_nonpackaged=child_np,
                rows=rows,
                seen=seen,
                dedupe_on_content=dedupe_on_content,
            )
        finally:
            winreg.CloseKey(child)


def _mm_props(prop_key) -> dict[str, str]:
    vals = _read_values(prop_key)
    # Some hosts store the device instance under pid 2, others under 39.
    instance = _safe_str(
        vals.get(_PKEY_INSTANCE_PATH)
        or vals.get("{b3f8fa53-0004-438e-9003-51a46e139bfc},39")
        or ""
    )
    # Sweep every property: HardwareIDs hide in several PROPERTYKEYs.
    scanned = extract_all_vidpids(instance, *vals.values())
    return {
        "friendly": _safe_str(vals.get(_PKEY_FRIENDLY) or vals.get(_PKEY_IFACE_NAME) or ""),
        "desc": _safe_str(vals.get(_PKEY_DESC) or ""),
        "mfg": _safe_str(vals.get(_PKEY_MFG) or ""),
        "instance": instance,
        "vidpid": scanned[0] if scanned else vid_pid(instance),
        "vidpids": "; ".join(scanned),
    }


def iter_mmdevices_capture() -> list[AccessTraceRow]:
    return _iter_mmdevices(MMDEVICES_CAPTURE, kind="Capture")


def iter_mmdevices_render_loopback() -> list[AccessTraceRow]:
    return _iter_mmdevices(MMDEVICES_RENDER, kind="Render")


def _iter_mmdevices(rel: str, kind: str) -> list[AccessTraceRow]:
    label = f"MMDevices\\{kind} (registry)"
    root, reason = _try_open_ex(winreg.HKEY_LOCAL_MACHINE, rel)
    if root is None:
        record_source_status(
            label,
            STATE_ABSENT if reason == "key not present" else STATE_FAIL,
            reason,
        )
        return []
    rows: list[dict[str, str]] = []
    try:
        for guid in _enum_subkeys(root):
            props_key = _try_open(
                winreg.HKEY_LOCAL_MACHINE, rel + "\\" + guid + "\\Properties"
            )
            if props_key is None:
                continue
            try:
                props = _mm_props(props_key)
            finally:
                winreg.CloseKey(props_key)
            name = props["friendly"] or props["desc"] or guid
            if kind == "Render" and not _STEREO_RE.search(name):
                continue
            audio_kind = classify_audio(name)
            if kind == "Capture":
                cap = audio_kind or "Microphone"
            else:
                cap = audio_kind or "AudioOutput"
            notes = []
            if _STEREO_RE.search(name):
                notes.append(
                    "Stereo Mix / loopback — captures system audio output including calls"
                )
            rows.append(
                {
                    "Source": f"MMDevices\\{kind}",
                    "Capability": cap,
                    "Hive": "HKLM",
                    "AppType": "Endpoint",
                    "Application": name,
                    "Make": props["mfg"],
                    "Model": props["desc"] or props["friendly"] or "Unknown",
                    "Consent": "",
                    "LastStart": "",
                    "LastStop": "",
                    "LastStartISO": "",
                    "LastStopISO": "",
                    "VidPidObserved": props.get("vidpids")
                    or props.get("vidpid")
                    or vid_pid(props.get("instance") or ""),
                    "VidPidCorrelated": "",
                    "VidPidSource": "observed",
                    "Duration": "",
                    "Notes": "; ".join(notes),
                }
            )
    finally:
        winreg.CloseKey(root)
    record_source_status(
        label, STATE_OK, f"{len(rows)} endpoint{'s' if len(rows) != 1 else ''}"
    )
    return rows


def iter_enum_cameras() -> list[AccessTraceRow]:
    """Hardware nodes under CurrentControlSet\\Enum that look like cameras or mics.

    These keys often survive after a device is unplugged, which is why they
    belong in the historical table rather than the live PnP table.
    """
    branches = ("USB", "USBVIDEO", "SWD", "HDAUDIO", "BTHENUM", "HID")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    read_branches: list[str] = []
    denied_branches: list[str] = []

    for branch in branches:
        base = ENUM_ROOT + "\\" + branch
        branch_key, reason = _try_open_ex(winreg.HKEY_LOCAL_MACHINE, base)
        if branch_key is None:
            if reason == "access denied":
                denied_branches.append(branch)
            continue
        read_branches.append(branch)
        try:
            for device in _enum_subkeys(branch_key):
                dev_key = _open_child(branch_key, device)
                if dev_key is None:
                    continue
                try:
                    instances = _enum_subkeys(dev_key)
                    for inst in instances:
                        inst_key = _open_child(dev_key, inst)
                        if inst_key is None:
                            continue
                        try:
                            vals = _read_values(inst_key)
                        finally:
                            winreg.CloseKey(inst_key)

                        klass = _safe_str(vals.get("Class") or "")
                        service = _safe_str(vals.get("Service") or "")
                        desc = _clean_reg_desc(_safe_str(vals.get("DeviceDesc") or ""))
                        friendly = _safe_str(vals.get("FriendlyName") or "")
                        mfg = _clean_reg_desc(_safe_str(vals.get("Mfg") or ""))
                        hw = vals.get("HardwareID") or vals.get("HardwareId") or ""
                        if isinstance(hw, (list, tuple)):
                            hw_blob = " ".join(_safe_str(x) for x in hw)
                        else:
                            hw_blob = _safe_str(hw)
                        blob = " ".join([klass, service, desc, friendly, device, hw_blob])

                        if _SCANNER_RE.search(blob) and not _CAMERA_RE.search(blob):
                            continue

                        klass_l = klass.lower()
                        # A node earns a row on its setup class or on a name only a
                        # capture device would carry. Keyboards, mice, hubs and
                        # composite parents satisfy neither.
                        strong = bool(_CAPTURE_STRONG_RE.search(blob))
                        if klass_l in _NON_CAPTURE_CLASSES and not strong:
                            continue
                        if _GENERIC_DESC_RE.search(f"{desc} {friendly}") and not strong:
                            continue

                        is_cam = (
                            klass_l in {"camera", "image"}
                            or service.lower() == "usbvideo"
                            or bool(_CAMERA_RE.search(blob))
                        )
                        is_mic = klass_l in {"media", "audioendpoint"} or bool(
                            _MIC_RE.search(blob)
                        )
                        if not (is_cam or is_mic):
                            continue

                        instance_id = f"{branch}\\{device}\\{inst}"
                        if instance_id in seen:
                            continue
                        seen.add(instance_id)

                        # Only ID-bearing values are swept. *vals.values()
                        # stringified every REG_BINARY blob under the key and
                        # tried to decode it as UTF-16LE: wasted CPU, and a
                        # source of spurious matches.
                        id_values = [
                            vals.get(name)
                            for name in ("HardwareID", "HardwareId", "CompatibleIDs", "ContainerID")
                            if vals.get(name)
                        ]
                        extra_list = extract_all_vidpids(
                            hw_blob, device, instance_id, *id_values
                        )
                        extra = "; ".join(extra_list)
                        notes: list[str] = []
                        if is_virtual(instance_id):
                            notes.append("Virtual / software device node")

                        capability = "Camera" if is_cam else "Microphone"
                        rows.append(
                            {
                                "Source": "Enum\\" + branch,
                                "Capability": capability,
                                "Hive": "HKLM",
                                "AppType": "Hardware",
                                "Application": friendly or desc or device,
                                "Make": mfg,
                                "Model": desc or extra or "Unknown",
                                "Consent": "",
                                "LastStart": "",
                                "LastStop": "",
                                "LastStartISO": "",
                                "LastStopISO": "",
                                "VidPidObserved": extra,
                                "VidPidCorrelated": "",
                                "VidPidSource": "observed" if extra else "none",
                                "Duration": "",
                                "Notes": "; ".join(notes),
                            }
                        )
                finally:
                    winreg.CloseKey(dev_key)
        finally:
            winreg.CloseKey(branch_key)

    detail = f"{len(read_branches)}/{len(branches)} branches read; {len(rows)} hardware node(s)"
    if denied_branches:
        detail += f"; access denied on {', '.join(denied_branches)}"
    record_source_status(
        "Enum hardware nodes (registry)",
        STATE_OK if read_branches else STATE_FAIL,
        detail,
    )
    return rows


def _cam_db_candidates() -> list[Path]:
    """Where CapabilityAccessManager.db actually lives.

    It is a machine-wide artifact under ProgramData, written by camsvc — not a
    per-user file. Looking under %LOCALAPPDATA% found nothing even on Windows
    11, which made the tool report the database as absent on every host. The
    per-user path is kept as a secondary candidate in case a build differs.
    """
    rel = ("Microsoft", "Windows", "CapabilityAccessManager", "CapabilityAccessManager.db")
    candidates: list[Path] = []
    seen: set[str] = set()

    def add(base: str) -> None:
        if not base:
            return
        path = Path(base).joinpath(*rel)
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            candidates.append(path)

    add(os.environ.get("ProgramData") or "")
    add(os.environ.get("ALLUSERSPROFILE") or "")
    add((os.environ.get("SystemDrive") or "C:") + "\\ProgramData")
    add(os.environ.get("LOCALAPPDATA") or "")
    return candidates


def iter_cam_database() -> list[AccessTraceRow]:
    """Windows 11 CapabilityAccessManager.db — skip if missing or unreadable."""
    candidates = _cam_db_candidates()
    db_path = next((p for p in candidates if _safe_is_file(p)), None)
    rows: list[dict[str, str]] = []

    if db_path is None:
        # "Cannot look" is not "not there". The CapabilityAccessManager folder
        # under ProgramData is ACL'd, so an unelevated run gets WinError 5 from
        # the existence check itself and must not report that as absence.
        blocked = [p for p in candidates if _access_denied(p)]
        if blocked:
            record_source_status(
                "CapabilityAccessManager.db",
                STATE_FAIL,
                f"access denied reading {blocked[0].parent} — an elevated shell may "
                "help, though this folder is restricted to SYSTEM on some builds. "
                "ConsentStore already covers access traces either way",
            )
        else:
            record_source_status(
                "CapabilityAccessManager.db",
                STATE_ABSENT,
                "not present at "
                + " or ".join(str(p) for p in candidates[:2])
                + " (Windows 11 only; ConsentStore still covers access traces)",
            )
        return rows

    with readonly_sqlite(db_path) as (conn, state, detail):
        if conn is None:
            if state == STATE_FAIL and not is_elevated():
                detail += " — ProgramData is a protected directory; try an elevated shell"
            record_source_status("CapabilityAccessManager.db", state, detail)
            return rows
        try:
            _read_cam_database(conn, rows)
        except Exception as exc:
            record_source_status(
                "CapabilityAccessManager.db",
                STATE_FAIL,
                f"opened ({detail}); query failed: {exc}",
            )
            return rows
    record_source_status(
        "CapabilityAccessManager.db",
        STATE_OK,
        f"{detail}; {len(rows)} usage row{'s' if len(rows) != 1 else ''}",
    )
    return rows


def _read_cam_database(conn: Any, rows: list[AccessTraceRow]) -> None:
    """Parse the usage-history tables of an already-open CAM.db connection.

    Identifiers are interpolated into the SQL below. Both sources are closed
    sets: table names come from the literal tuple, column names are filtered
    against what PRAGMA table_info actually returned. Nothing user-supplied
    reaches the statement.
    """
    tables = {
        n
        for (n,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    for table in ("PackagedUsageHistory", "NonPackagedUsageHistory"):
        if table not in tables:
            continue
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        wanted = [
            c
            for c in (
                "LastUsedTimeStart",
                "LastUsedTimeStop",
                "AccessBlocked",
                "Capability",
                "PackageFamilyName",
                "BinaryFullPath",
                "ProgramID",
            )
            if c in cols
        ]
        if "LastUsedTimeStart" not in wanted:
            continue
        try:
            cur = conn.execute(f"SELECT {', '.join(wanted)} FROM {table}")
        except Exception:
            continue
        packaged = table == "PackagedUsageHistory"
        for rec in cur.fetchall():
            data = dict(zip(wanted, rec))
            app = (
                _safe_str(data.get("BinaryFullPath"))
                or _safe_str(data.get("PackageFamilyName"))
                or _safe_str(data.get("ProgramID"))
            )
            if not app:
                continue
            notes = "CAM.db " + table
            blocked = data.get("AccessBlocked")
            if blocked not in (None, 0, "0"):
                notes += "; access blocked"
            rows.append(
                {
                    "Source": "CapabilityAccessManager.db",
                    "Capability": _safe_str(data.get("Capability") or "Unknown"),
                    "Hive": "CurrentUser DB",
                    "AppType": "Packaged" if packaged else "NonPackaged",
                    "Application": decode_nonpackaged(app),
                    "Make": "",
                    "Model": "n/a (app access record)",
                    "Consent": "",
                    "LastStart": filetime_to_str(data.get("LastUsedTimeStart")),
                    "LastStop": filetime_to_str(data.get("LastUsedTimeStop")),
                    "LastStartISO": filetime_to_iso(data.get("LastUsedTimeStart")),
                    "LastStopISO": filetime_to_iso(data.get("LastUsedTimeStop")),
                    "VidPidObserved": "",
                    "VidPidCorrelated": "",
                    "VidPidSource": "none",
                    "Duration": duration_str(
                        data.get("LastUsedTimeStart"),
                        data.get("LastUsedTimeStop"),
                    ),
                    "Notes": notes,
                }
            )


# ---------------------------------------------------------------------------
# Table 2 — live PnP
# ---------------------------------------------------------------------------

_PS_ENUM = r"""
$ErrorActionPreference = 'SilentlyContinue'
$classes = @('Camera','Image','AudioEndpoint','MEDIA','CameraExtension')
$rows = @()
try {
  foreach ($d in (Get-PnpDevice -ErrorAction SilentlyContinue)) {
    if ($classes -contains $d.Class -or $d.FriendlyName -match 'Camera|Webcam|Microphone|Stereo Mix|What U Hear|UVC') {
      $rows += [pscustomobject]@{
        Name = $d.FriendlyName
        Class = $d.Class
        Status = $d.Status
        InstanceId = $d.InstanceId
        Manufacturer = $d.Manufacturer
        Description = $d.Description
        Backend = 'Get-PnpDevice'
      }
    }
  }
} catch {}
if (-not $rows -or $rows.Count -eq 0) {
  try {
    foreach ($e in (Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue)) {
      $cls = $e.PNPClass
      $name = $e.Name
      if ($classes -contains $cls -or $name -match 'Camera|Webcam|Microphone|Stereo Mix|What U Hear|UVC') {
        $rows += [pscustomobject]@{
          Name = $name
          Class = $cls
          Status = $e.Status
          InstanceId = $e.PNPDeviceID
          Manufacturer = $e.Manufacturer
          Description = $e.Description
          Backend = 'Win32_PnPEntity'
        }
      }
    }
  } catch {}
}
$rows | ConvertTo-Json -Compress -Depth 3
"""

# Every backend reports a Status string and nothing else. Present is then
# derived here, once, so the column means the same thing whichever enumerator
# happened to answer. Previously Get-PnpDevice returned a real Present,
# Win32_PnPEntity read a property that class does not have (always null, so
# always False), pnputil guessed from its own Status wording, and the win32com
# fallback hardcoded True.
_STATUS_PRESENT = {
    "ok",
    "started",
    "degraded",
    "stressed",
    "pred fail",
    "starting",
    "service",
}
_STATUS_ABSENT = {
    "unknown",
    "error",
    "stopped",
    "disconnected",
    "no contact",
    "lost comm",
    "nonrecover",
    "problem",
}


def present_from_status(status: str) -> str:
    """True / False / Unknown from a PnP Status string, for any backend."""
    key = _safe_str(status).strip().lower()
    if not key:
        return "Unknown"
    if key in _STATUS_PRESENT:
        return "True"
    if key in _STATUS_ABSENT:
        return "False"
    return "Unknown"


def _run_powershell(script: str) -> str:
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=45,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    return (proc.stdout or "").strip()


# Endpoints that only play audio out. These are genuinely not this tool's
# business and are dropped; anything else on a capture-capable class is kept.
_RENDER_ONLY_RE = re.compile(
    r"Speakers?|Headphones?|Earphones?|Digital Output|Optical|HDMI|S/?PDIF|Line Out",
    re.I,
)

AUDIO_UNCLASSIFIED = "Audio (unclassified)"


def _classify_live_device(name: str, klass: str, desc: str) -> str | None:
    """Camera / Microphone / unclassified audio, or None to drop the device.

    AudioEndpoint and MEDIA nodes used to be dropped whenever the name lacked
    a microphone token, which discarded true positives: a codec node called
    "Realtek(R) Audio" hosts the built-in mic but says so nowhere in its name.
    Those are now kept and labelled, because a silently missing capture device
    is the worst outcome for an audit. Render-only endpoints are still dropped.
    """
    blob = f"{name} {klass} {desc}"
    klass_l = (klass or "").lower()
    if _SCANNER_RE.search(blob) and not _CAMERA_RE.search(blob):
        return None
    if klass_l in {"camera", "image", "cameraextension"} or _CAMERA_RE.search(blob):
        return "Camera"
    if klass_l in {"audioendpoint", "media"}:
        resolved = classify_audio(name) or classify_audio(blob)
        if resolved:
            return resolved
        if _RENDER_ONLY_RE.search(blob):
            return None
        return AUDIO_UNCLASSIFIED
    if _MIC_RE.search(blob):
        return "Microphone"
    return None


def _enum_via_pnputil() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cls in ("Camera", "Image", "AudioEndpoint", "MEDIA"):
        try:
            proc = subprocess.run(
                ["pnputil", "/enum-devices", "/connected", "/class", cls],
                capture_output=True,
                text=True,
                timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
        current: dict[str, Any] = {}
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                if current:
                    current.setdefault("Class", cls)
                    current["Backend"] = "pnputil"
                    rows.append(current)
                    current = {}
                continue
            if ":" not in line:
                continue
            field, _, val = line.partition(":")
            field = field.strip().lower()
            val = val.strip()
            mapping = {
                "instance id": "InstanceId",
                "instanceid": "InstanceId",
                "device description": "Name",
                "name": "Name",
                "class name": "Class",
                "manufacturer": "Manufacturer",
                "status": "Status",
            }
            dest = mapping.get(field)
            if dest:
                current[dest] = val
                if dest == "Name":
                    current["Description"] = val
        if current:
            current.setdefault("Class", cls)
            current["Backend"] = "pnputil"
            rows.append(current)
    return rows


def _enum_via_win32com() -> list[dict[str, Any]]:
    try:
        import pythoncom  # type: ignore
        import win32com.client  # type: ignore
    except ImportError:
        return []
    rows: list[dict[str, Any]] = []
    try:
        pythoncom.CoInitialize()
        locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        svc = locator.ConnectServer(".", r"root\cimv2")
        query = (
            "SELECT Name, PNPClass, Status, PNPDeviceID, Manufacturer, Description "
            "FROM Win32_PnPEntity"
        )
        for ent in svc.ExecQuery(query):
            try:
                rows.append(
                    {
                        "Name": ent.Name,
                        "Class": ent.PNPClass,
                        "Status": ent.Status,
                        "InstanceId": ent.PNPDeviceID,
                        "Manufacturer": ent.Manufacturer,
                        "Description": ent.Description,
                        "Backend": "win32com/Win32_PnPEntity",
                    }
                )
            except Exception:
                continue
    except Exception:
        return []
    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass
    return rows


def enum_active_pnp() -> list[ActiveDeviceRow]:
    raw = _run_powershell(_PS_ENUM)
    devices: list[dict[str, Any]] = []
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                devices = [parsed]
            elif isinstance(parsed, list):
                devices = parsed
        except json.JSONDecodeError:
            devices = []
    backend_used = "PowerShell (Get-PnpDevice / Win32_PnPEntity)" if devices else ""
    if not devices:
        devices = _enum_via_pnputil()
        backend_used = "pnputil" if devices else ""
    if not devices:
        devices = _enum_via_win32com()
        backend_used = "win32com/WMI" if devices else ""
    if not devices:
        record_source_status(
            "Live PnP enumeration",
            STATE_FAIL,
            "PowerShell, pnputil and win32com all returned nothing — Table 2 is "
            "empty because enumeration failed, not because no device is attached",
        )

    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for dev in devices:
        name = _safe_str(dev.get("Name") or "")
        klass = _safe_str(dev.get("Class") or "")
        instance = _safe_str(dev.get("InstanceId") or "")
        status = _safe_str(dev.get("Status") or "")
        backend = _safe_str(dev.get("Backend") or "unknown")
        mfg = _safe_str(dev.get("Manufacturer") or "")
        desc = _safe_str(dev.get("Description") or "")
        key = instance or name
        if not key or key in seen:
            continue
        seen.add(key)

        dtype = _classify_live_device(name, klass, desc)
        if dtype is None:
            continue

        virtual = is_virtual(instance)
        notes: list[str] = []
        if virtual and dtype == "Camera":
            notes.append(
                "Virtual camera — could be legitimate (OBS) or covert capture software"
            )
        if virtual and dtype == "Microphone":
            notes.append(
                "Virtual audio input — could be VB-Cable or covert capture software"
            )
        if _STEREO_RE.search(name):
            notes.append(
                "Stereo Mix / loopback — captures ALL system audio output including calls"
            )
            if instance:
                notes.append(
                    f"Informational disable: Disable-PnpDevice -InstanceId '{instance}' -Confirm:$false"
                )
        if dtype == AUDIO_UNCLASSIFIED:
            notes.append(
                "Capture-capable audio class, but the name does not say input or "
                "output — listed rather than dropped so it is not missed"
            )
        extra = vid_pid(instance)
        present = present_from_status(status)
        if present == "False":
            notes.append(
                "Not currently started — PnP still holds the node (ghost or disabled device)"
            )

        rows.append(
            {
                "Type": dtype,
                "Name": name or desc or instance,
                "Make": mfg,
                "Model": desc or extra or name or "Unknown",
                # Read off this device's own instance ID, so it is measured.
                "VidPidObserved": extra,
                "VidPidCorrelated": "",
                "VidPidSource": "observed" if extra else "none",
                "InstanceId": instance,
                "Status": status or "Unknown",
                "Present": present,
                "Backend": backend,
                "Virtual": "Yes" if virtual else "No",
                "Notes": "; ".join(notes),
            }
        )
    if backend_used:
        started = sum(1 for r in rows if r.get("Present") == "True")
        record_source_status(
            "Live PnP enumeration",
            STATE_OK,
            f"via {backend_used}; {len(rows)} capture device(s), {started} started",
        )
    return rows


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _term_width() -> int:
    try:
        return max(80, shutil.get_terminal_size((120, 24)).columns)
    except Exception:
        return 120


def duration_seconds(text: str) -> int:
    """Parse '2h 3m 4s' / '16s' / '0s' into seconds. -1 if empty/unparseable."""
    raw = (text or "").strip()
    if not raw:
        return -1
    m = re.fullmatch(r"(?:(\d+)h\s*)?(?:(\d+)m\s*)?(?:(\d+)s)?", raw)
    if not m or not any(m.groups()):
        return -1
    hours, minutes, secs = (int(p) if p else 0 for p in m.groups())
    return hours * 3600 + minutes * 60 + secs


def row_duration_seconds(row: AccessTraceRow) -> int:
    """Seconds a session ran, or has been running. -1 when unknown.

    Elapsed time is measured from the aware ISO timestamp against an aware
    now(). The previous naive strptime/datetime.now() pair silently drifted by
    an hour across a DST boundary, which matters when the whole point of the
    row is how long something held the microphone.
    """
    parsed = duration_seconds(row.get("Duration") or "")
    if parsed >= 0:
        return parsed
    start = row.get("LastStart") or ""
    stop = row.get("LastStop") or ""
    if not start or stop:
        return -1
    iso = row.get("LastStartISO") or ""
    if iso:
        try:
            started = datetime.fromisoformat(iso)
            if started.tzinfo is None:
                started = started.astimezone()
            return max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
        except ValueError:
            pass
    try:
        # Fallback for a row with no ISO field: treat the display string as
        # local wall-clock time and attach the current local offset.
        started = datetime.strptime(start, "%Y-%m-%d %H:%M:%S").astimezone()
        return max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
    except ValueError:
        return 0


def is_access_trace(row: AccessTraceRow) -> bool:
    """True when Windows recorded an actual mic/camera open (start timestamp)."""
    return bool((row.get("LastStart") or "").strip())


def _start_epoch(row: AccessTraceRow) -> float:
    """POSIX seconds for LastStartISO, or 0.0 when absent or unparseable."""
    iso = row.get("LastStartISO") or ""
    if not iso:
        return 0.0
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return parsed.timestamp()


def trace_sort_key(row: AccessTraceRow) -> tuple[int, int, float]:
    """LIVE first, then longest duration, then most recent start.

    This used to be two passes: sort_by_duration_desc, then a second sort on
    (live, -duration). The second alone looked sufficient, but Python's sort is
    stable, so the first pass's start-descending order survived as the tiebreak.
    Anyone deleting the first line as redundant would have silently changed
    output ordering, so the tiebreak is spelled out here instead.
    """
    return (
        0 if row.get("Live") else 1,
        -row_duration_seconds(row),
        -_start_epoch(row),
    )


def sort_by_duration_desc(rows: list[AccessTraceRow]) -> list[AccessTraceRow]:
    """Kept for callers that want a new list rather than an in-place sort."""
    return sorted(rows, key=trace_sort_key)


# Shared by _visible_len and the wrapper so the two cannot drift.
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _visible_len(text: str) -> int:
    """Length as rendered, ignoring SGR escape sequences."""
    return len(_ANSI_RE.sub("", text))






def _kv(label: str, value: str, width: int) -> None:
    """Print a padded label and a wrapped value.

    Width arithmetic goes through _visible_len, not len(): color_allow feeds
    this function ANSI-coloured values whose escape bytes are invisible on a
    terminal but counted by len(), which made every wrap decision on a
    coloured value wrong. Escape sequences are also kept whole, so one is
    never split across two lines.
    """
    text = _safe_str(value)
    if not text:
        text = "—"
    pad = 12
    prefix = f"  {label:<{pad}}"
    indent = " " * (pad + 2)
    avail = max(24, width - pad - 2)

    first = True
    for line in _wrap_visible(text, avail):
        print((prefix if first else indent) + line)
        first = False
    if first:
        print(prefix + "—")


def _wrap_visible(text: str, avail: int) -> list[str]:
    """Wrap on visible width, preferring word breaks, keeping ANSI intact."""
    if _visible_len(text) <= avail:
        return [text]
    if _ANSI_RE.search(text):
        # Coloured values are short by construction; hard-break on visible
        # width rather than risk splitting an escape sequence.
        return _hard_break_visible(text, avail)
    wrapped = textwrap.wrap(
        text,
        width=avail,
        break_long_words=True,
        break_on_hyphens=False,
        drop_whitespace=True,
    )
    return wrapped or [text]


def _hard_break_visible(text: str, avail: int) -> list[str]:
    out: list[str] = []
    current = ""
    used = 0
    index = 0
    while index < len(text):
        match = _ANSI_RE.match(text, index)
        if match:
            current += match.group(0)
            index = match.end()
            continue
        if used >= avail:
            out.append(current)
            current = ""
            used = 0
        current += text[index]
        used += 1
        index += 1
    if current:
        out.append(current)
    return out



def print_access_records(title: str, rows: list[AccessTraceRow]) -> None:
    """One record per block so VID/PID, paths, and timestamps are never clipped."""
    width = _term_width()
    print()
    print("=" * width)
    print(title)
    print("=" * width)
    if not rows:
        print("No access traces found (no LastUsedTimeStart on ConsentStore / CAM.db).")
        return

    for idx, row in enumerate(rows, 1):
        seconds = row_duration_seconds(row)
        dur = row.get("Duration") or (f"~{seconds}s elapsed (still open?)" if seconds >= 0 else "unknown")
        cap = row.get("Capability") or ""
        consent = color_allow(row.get("Consent") or "") or "—"
        if row.get("Live"):
            exe = (
                row.get("LiveExe")
                or PureWindowsPath(row.get("Application") or "").name
                or "unknown"
            )
            pids = row.get("LivePids") or "not running"
            since = row.get("LastStart") or ""
            live_tag = f"{RED}LIVE{RESET}" if sys.stdout.isatty() else "LIVE"
            print(f"#{idx:<3} {live_tag}   {cap:<12} {exe} ({pids})   since {since}")
        else:
            print(
                f"#{idx:<3} {dur:<18} {cap:<12} "
                f"{row.get('Source') or ''} / {row.get('Hive') or ''} / {row.get('AppType') or ''}"
            )
        # Access-trace rows are keyed by Application; hardware rows go to
        # print_inventory_records, so there is no second schema to fall back to.
        _kv("App", row.get("Application") or "", width)
        developer = row.get("Developer") or row.get("Make") or ""
        if developer and row.get("DeveloperSource") == "Authenticode":
            developer = f"{developer}  (Authenticode: Valid)"
        _kv("Developer", developer, width)
        observed = row.get("VidPidObserved") or ""
        correlated = row.get("VidPidCorrelated") or ""
        if observed:
            _kv("VID/PID", f"{observed}  (observed on the device)", width)
        elif correlated:
            _kv("VID/PID", f"{correlated}  (correlated, not measured)", width)
        else:
            _kv("VID/PID", "", width)
        _kv("Consent", consent, width)
        window = "  →  ".join(
            p for p in (row.get("LastStart") or "", row.get("LastStop") or "") if p
        )
        if row.get("LastStart") and not row.get("LastStop"):
            window = f"{row.get('LastStart')}  →  (no stop time)"
        _kv("Window", window, width)
        _kv("Instance", row.get("InstanceId") or "", width)
        _kv("Notes", row.get("Notes") or "", width)
        if idx != len(rows):
            print("-" * width)
    print(f"({len(rows)} access trace{'s' if len(rows) != 1 else ''}, longest duration first)")


def print_inventory_records(title: str, rows: list[AccessTraceRow]) -> None:
    """Hardware nodes with no access timestamp.

    These are not access traces and must not be counted as such. They say a
    device existed on this box, never that software opened it.
    """
    width = _term_width()
    print()
    print("=" * width)
    print(title)
    print("=" * width)
    if not rows:
        print("No hardware remnants without an access timestamp.")
        return
    for idx, row in enumerate(rows, 1):
        print(
            f"#{idx:<3} {row.get('Capability') or '':<12} "
            f"{row.get('Source') or ''} / {row.get('AppType') or ''}"
        )
        _kv("Device", row.get("Application") or "", width)
        _kv("Make/Model", " / ".join(
            p for p in (_safe_str(row.get("Make")), _safe_str(row.get("Model"))) if p
        ), width)
        _kv("VID/PID", row.get("VidPidObserved") or "", width)
        _kv("Notes", row.get("Notes") or "", width)
        if idx != len(rows):
            print("-" * width)
    print(
        f"({len(rows)} hardware node{'s' if len(rows) != 1 else ''} with no access "
        "timestamp — presence on the box, not evidence of use)"
    )


def print_active_records(title: str, rows: list[ActiveDeviceRow]) -> None:
    width = _term_width()
    print()
    print("=" * width)
    print(title)
    print("=" * width)
    if not rows:
        print("No records found.")
        return
    for idx, row in enumerate(rows, 1):
        print(
            f"#{idx:<3} {row.get('Type') or '':<21} "
            f"status={row.get('Status') or 'Unknown':<10} "
            f"present={row.get('Present') or '?':<6} "
            f"virtual={row.get('Virtual') or 'No'}"
        )
        _kv("Name", row.get("Name") or "", width)
        make_model = " / ".join(
            p for p in (_safe_str(row.get("Make")), _safe_str(row.get("Model"))) if p
        )
        _kv("Make/Model", make_model, width)
        _kv("VID/PID", row.get("VidPidObserved") or "", width)
        _kv("Instance", row.get("InstanceId") or "", width)
        _kv("Enumerator", row.get("Backend") or "", width)
        _kv("Notes", row.get("Notes") or "", width)
        if idx != len(rows):
            print("-" * width)
    listed = len(rows)
    started = sum(1 for r in rows if _safe_str(r.get("Present")) == "True")
    print(
        f"({listed} device{'s' if listed != 1 else ''} enumerated, {started} started; "
        "present is derived from PnP Status)"
    )




_CSV_INJECTION_RE = re.compile(r"^[=+\-@\t\r]")


def _csv_safe(value: Any) -> str:
    """Defuse spreadsheet formula injection.

    Two of the fields written here are attacker-influenced: a USB device
    supplies its own FriendlyName, and a site permission carries an origin
    from the web. Excel and LibreOffice evaluate a cell beginning =, +, -, @,
    tab or CR, which turns an audit report into an execution vector the moment
    someone opens it. Prefixing an apostrophe forces the cell to stay text.
    """
    text = _safe_str(value)
    dangerous = bool(_CSV_INJECTION_RE.match(text))
    text = text.replace("\r", " ").replace("\n", " ")
    return "'" + text if dangerous else text


def write_csv(path: Path, rows: list[dict[str, str]], columns: list[str]) -> None:
    # utf-8-sig: without the BOM, Excel on Windows mangles non-ASCII device names.
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({c: _csv_safe(row.get(c, "")) for c in columns})


class AccessTraceRow(TypedDict, total=False):
    """A row in Table 1 or Table 1b.

    Both kinds share this shape; RecordKind says which one a row is. The
    schema is written down here because it is also the --json and --csv
    contract, which was previously only discoverable by reading main().

    Make and Model are carried by hardware-inventory rows only, and the
    Live* fields are set by mark_live_sessions on open sessions.
    """

    RecordKind: str
    Source: str
    Capability: str
    Hive: str
    AppType: str
    Application: str
    Developer: str
    DeveloperSource: str
    SignatureStatus: str
    VidPidObserved: str
    VidPidCorrelated: str
    VidPidSource: str
    Consent: str
    LastStart: str
    LastStop: str
    LastStartISO: str
    LastStopISO: str
    Duration: str
    Notes: str
    Make: str
    Model: str
    Live: str
    LiveExe: str
    LivePids: str


class ActiveDeviceRow(TypedDict, total=False):
    """A row in Table 2. Present is derived from Status; Backend names the
    enumerator that answered."""

    Type: str
    Name: str
    Make: str
    Model: str
    VidPidObserved: str
    VidPidCorrelated: str
    VidPidSource: str
    InstanceId: str
    Status: str
    Present: str
    Backend: str
    Virtual: str
    Notes: str


class SitePermissionRow(TypedDict, total=False):
    """One origin's mic or camera grant in Table 3."""

    Origin: str
    Capability: str
    Setting: str
    LastModified: str
    LastModifiedISO: str
    Expires: str


class SourceStatusRow(TypedDict):
    """One line of the source-status block. State is STATE_OK / STATE_ABSENT /
    STATE_FAIL."""

    Source: str
    State: str
    Detail: str


# The column lists below stay the single source of truth for CSV order. The
# TypedDicts above document the same fields for type checkers; a field present
# in one and absent from the other is a bug.
HIST_COLS = [
    "RecordKind",
    "Source",
    "Capability",
    "Hive",
    "AppType",
    "Application",
    "Developer",
    "DeveloperSource",
    "SignatureStatus",
    "VidPidObserved",
    "VidPidCorrelated",
    "VidPidSource",
    "Consent",
    "LastStart",
    "LastStop",
    "LastStartISO",
    "LastStopISO",
    "Duration",
    "Notes",
]

SITE_COLS = [
    "Browser",
    "Profile",
    "Origin",
    "Capability",
    "Setting",
    "LastModified",
    "LastModifiedISO",
    "Expires",
    "ExtraProfiles",
]

ACTIVE_COLS = [
    "Type",
    "Name",
    "Make",
    "Model",
    "VidPidObserved",
    "VidPidSource",
    "InstanceId",
    "Status",
    "Present",
    "Backend",
    "Virtual",
    "Notes",
]


_NOISE_DEV_RE = re.compile(
    r"USB Input Device|Internal AUX Jack|Line In|Center\b|Speakers?|Headphone"
    r"|What U Hear|Stereo Mix|Wave Out Mix",
    re.I,
)
_CAPTURE_NAME_RE = re.compile(
    r"Microphone|\bMic\b|Webcam|Camera|Headset|UVC|Capture",
    re.I,
)


def _normalize_cap(cap: str) -> str:
    c = (cap or "").lower()
    if c in {"webcam", "camera", "image"}:
        return "Camera"
    if c in {"microphone", "audioendpoint", "media", "capture", "audiooutput"}:
        return "Microphone"
    if c == AUDIO_UNCLASSIFIED.lower():
        # Deliberately unbucketed: an unclassified endpoint must not become
        # evidence that this host has a microphone with that hardware ID.
        return ""
    if cap in {"Camera", "Microphone"}:
        return cap
    return ""


def score_capture_id(cap: str, token: str, name: str, present: bool) -> int:
    """Rank how useful a hardware ID is for correlating an access trace.

    Most critical: USB VID/PID of a device whose name is actually a microphone
    or camera (headset mic, webcam, UVC). HDAUDIO codec IDs on 'Line In' /
    'AUX Jack' / 'Center' and generic 'USB Input Device' HID nodes are noise.
    """
    name_l = (name or "").lower()
    score = 0
    if token.startswith("VID_"):
        score += 50
    elif token.startswith("VEN_"):
        score += 10
    if cap == "Microphone":
        if re.search(r"microphone|\bmic\b|headset", name_l):
            score += 40
        elif re.search(r"webcam|camera|uvc", name_l):
            score += 22
    elif cap == "Camera":
        if re.search(r"camera|webcam|uvc", name_l):
            score += 40
        if re.search(r"microphone|\bmic\b", name_l):
            score -= 15
    if _CAPTURE_NAME_RE.search(name or ""):
        score += 8
    if present:
        score += 18
    if _NOISE_DEV_RE.search(name or ""):
        score -= 55
    if "virtual" in name_l or name_l.startswith("windows virtual"):
        score -= 12
    return score


def hardware_vidpid_catalog(
    historical: list[dict[str, str]],
    active: list[dict[str, str]],
) -> dict[str, list[dict[str, Any]]]:
    """Camera/Microphone → scored hardware IDs from Enum + MMDevices + live PnP."""
    buckets: dict[str, list[dict[str, Any]]] = {"Camera": [], "Microphone": []}
    seen: dict[str, set[str]] = {"Camera": set(), "Microphone": set()}

    def add(cap: str, vid: str, name: str, present: bool) -> None:
        cap_key = _normalize_cap(cap)
        if cap_key not in buckets:
            return
        for token in extract_all_vidpids(vid):
            if token in seen[cap_key]:
                continue
            seen[cap_key].add(token)
            buckets[cap_key].append(
                {
                    "token": token,
                    "name": name,
                    "present": present,
                    "score": score_capture_id(cap_key, token, name, present),
                    "label": format_vidpid_label(token, name),
                }
            )

    # Only measured IDs seed the catalog. Feeding correlated values back in
    # would let one inference become the evidence for the next.
    for row in historical:
        add(
            row.get("Capability") or "",
            row.get("VidPidObserved") or "",
            row.get("Application") or row.get("Model") or "",
            False,
        )
    for row in active:
        # Present is now derived from Status in one place, so this no longer
        # needs to second-guess whichever backend produced the row.
        present = _safe_str(row.get("Present")).strip().lower() == "true"
        add(
            row.get("Type") or "",
            row.get("VidPidObserved") or "",
            row.get("Name") or row.get("Model") or "",
            present,
        )
    for cap in buckets:
        buckets[cap].sort(key=lambda item: item["score"], reverse=True)
    return buckets


def top_vidpids_for(cap: str, catalog: dict[str, list[dict[str, Any]]], limit: int = 2) -> list[str]:
    """Plausible capture IDs only.

    There used to be a fallback to the unfiltered list when nothing scored
    above zero, which meant a host with no clean capture hardware got its
    keyboard correlated to a microphone session. An empty answer is correct
    there; the caller records why.
    """
    cap_key = _normalize_cap(cap)
    ranked = [item for item in catalog.get(cap_key, []) if item["score"] > 0]
    return [item["label"] for item in ranked[:limit]]


def enrich_traces_with_vidpid(
    traces: list[dict[str, str]],
    catalog: dict[str, list[dict[str, Any]]],
) -> None:
    """Attach the two highest-value capture IDs for that capability.

    This is inference, not measurement: nothing on a ConsentStore app key
    records which adapter the app bound. It is written to VidPidCorrelated so
    a consumer of --json or --csv can tell it apart from VidPidObserved, which
    is read off a device's own instance ID.
    """
    for row in traces:
        # Every trace row carries all three keys, whichever branch it takes.
        row.setdefault("VidPidObserved", "")
        row.setdefault("VidPidCorrelated", "")
        row.setdefault("VidPidSource", "none")
        observed = (row.get("VidPidObserved") or "").strip()
        if observed:
            # Already measured. Trim to the two best tokens and leave it alone.
            rebuilt = []
            for token in extract_all_vidpids(observed):
                rebuilt.append(
                    {
                        "token": token,
                        "score": score_capture_id(
                            row.get("Capability") or "", token, "", False
                        ),
                        "label": token,
                    }
                )
            rebuilt.sort(key=lambda item: item["score"], reverse=True)
            row["VidPidObserved"] = "; ".join(item["label"] for item in rebuilt[:2])
            row["VidPidSource"] = "observed"
            continue

        ids = top_vidpids_for(row.get("Capability") or "", catalog, limit=2)
        note = row.get("Notes") or ""
        if ids:
            row["VidPidCorrelated"] = "; ".join(ids)
            row["VidPidSource"] = "correlated"
            extra = (
                "Correlated, not measured: top 2 capture VID/PIDs on this host "
                "(no hardware ID is stored on the app key)"
            )
        else:
            row["VidPidCorrelated"] = ""
            row["VidPidSource"] = "none"
            extra = "No plausible capture hardware ID on this host to correlate"
        row["Notes"] = f"{note}; {extra}".strip("; ")


# Matched against whole *directory* components only, never the filename and
# never as a substring. The old version searched the raw path, so
# C:\Windows\Temp\evil.exe resolved to "Microsoft Corporation" and
# ...\Temp\DiscordSetup_x.exe resolved to "Discord Inc.".
_PUBLISHER_DIR_HINTS = (
    (re.compile(r"^(?:BraveSoftware|Brave-Browser|Brave)$", re.I), "Brave Software, Inc."),
    (re.compile(r"^Google$", re.I), "Google LLC"),
    (re.compile(r"^(?:Microsoft|Microsoft Edge|Edge)$", re.I), "Microsoft Corporation"),
    (re.compile(r"^Discord$", re.I), "Discord Inc."),
    (re.compile(r"^Slack$", re.I), "Slack Technologies"),
    (re.compile(r"^Zoom$", re.I), "Zoom Video Communications"),
    (re.compile(r"^(?:Teams|Microsoft Teams)$", re.I), "Microsoft Corporation"),
    (re.compile(r"^Steam$", re.I), "Valve Corporation"),
    (re.compile(r"^Spotify$", re.I), "Spotify AB"),
    (re.compile(r"^(?:OBS|obs-studio)$", re.I), "OBS Project"),
)

# Only these Windows subtrees imply Microsoft. C:\Windows\Temp does not.
_SYSTEM_DIR_RE = re.compile(
    r"^[A-Za-z]:[\\/]Windows[\\/](?:System32|SysWOW64|SystemApps|WinSxS|ImmersiveControlPanel)[\\/]",
    re.I,
)


def _publisher_from_path(path: str) -> str:
    """Weakest evidence tier: a vendor guessed from where the file sits.

    An attacker controls the filename and, in user-writable trees, the
    directory name too. A result from here is never rendered as a verified
    publisher; see _resolve_developer.
    """
    text = path or ""
    if not text:
        return ""
    if "\\" not in text and "/" not in text and "_" in text:
        # Packaged family name: Publisher.App_version_nonce
        if text.lower().startswith("microsoft"):
            return "Microsoft Corporation"
        return text.split(".")[0] or ""
    if _SYSTEM_DIR_RE.match(text):
        return "Microsoft Corporation"
    for component in re.split(r"[\\/]+", text)[:-1]:  # drop the executable name
        for pattern, vendor in _PUBLISHER_DIR_HINTS:
            if pattern.match(component):
                return vendor
    return ""


_CN_RE = re.compile(
    r'(?:^|,)\s*CN\s*=\s*(?:"(?P<quoted>(?:[^"]|"")*)"|(?P<plain>.+?))'
    r"(?=\s*,\s*[A-Za-z]+\s*=|$)",
    re.I,
)


def _cn_from_subject(subject: str) -> str:
    """Common Name out of an X.509 subject.

    A naive [^,]+ truncates at the first comma, which turns
    'CN=Brave Software, Inc., O=...' into 'Brave Software'. Most real
    publisher CNs contain a comma, so stop at the next RDN key instead.
    """
    match = _CN_RE.search(subject or "")
    if not match:
        return ""
    value = match.group("quoted")
    if value is not None:
        return value.replace('""', '"').strip()
    return (match.group("plain") or "").strip()


_DEV_BATCH = 40


def _version_string(path: str, field: str = "CompanyName") -> str:
    """Read a VS_VERSIONINFO string with version.dll, no subprocess.

    The tool advertises itself as standard-library only and then shelled out
    to PowerShell for a value the Win32 API returns directly. This is the same
    data Get-Item(...).VersionInfo.CompanyName exposes, without paying ~500 ms
    of interpreter startup for it.
    """
    if not is_windows() or not path:
        return ""
    try:
        version = ctypes.WinDLL("version.dll")  # type: ignore[attr-defined]
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    except Exception:
        return ""

    try:
        version.GetFileVersionInfoSizeW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        version.GetFileVersionInfoSizeW.restype = ctypes.c_ulong
        version.GetFileVersionInfoW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_void_p,
        ]
        version.GetFileVersionInfoW.restype = ctypes.c_int
        version.VerQueryValueW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint),
        ]
        version.VerQueryValueW.restype = ctypes.c_int

        handle = ctypes.c_ulong(0)
        size = version.GetFileVersionInfoSizeW(path, ctypes.byref(handle))
        if not size:
            return ""
        buf = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(path, 0, size, buf):
            return ""

        # Ask the file which language/codepage its strings are under rather
        # than assuming US English; fall back to 040904b0 only if absent.
        block = ctypes.c_void_p()
        length = ctypes.c_uint(0)
        codepages: list[str] = []
        if version.VerQueryValueW(
            buf, "\\VarFileInfo\\Translation", ctypes.byref(block), ctypes.byref(length)
        ) and length.value >= 4:
            count = length.value // 4
            words = ctypes.cast(block, ctypes.POINTER(ctypes.c_ushort * (count * 2))).contents
            for i in range(count):
                codepages.append(f"{words[i * 2]:04x}{words[i * 2 + 1]:04x}")
        codepages.extend(["040904b0", "040904e4", "000004b0"])

        for cp in codepages:
            value = ctypes.c_void_p()
            chars = ctypes.c_uint(0)
            query = f"\\StringFileInfo\\{cp}\\{field}"
            if version.VerQueryValueW(
                buf, query, ctypes.byref(value), ctypes.byref(chars)
            ) and chars.value:
                text = ctypes.wstring_at(value, chars.value).strip("\x00").strip()
                if text:
                    return text
        return ""
    except Exception:
        return ""
    finally:
        del kernel32


def lookup_developers(paths: list[str]) -> dict[str, dict[str, str]]:
    """Publisher evidence per exe, kept separate rather than collapsed.

    Returns hint / company / signer / status / exists so the caller can decide
    how much each tier is worth. Authenticode Status matters: a revoked,
    expired or tampered binary still carries a signer CN, and the old code
    reported that CN as though the signature were good.
    """
    result: dict[str, dict[str, str]] = {}
    unique: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if not path or path in seen:
            continue
        seen.add(path)
        unique.append(path)
        result[path] = {
            "hint": _publisher_from_path(path),
            "company": "",
            "signer": "",
            "status": "",
            "exists": "",
        }

    file_paths = [p for p in unique if re.search(r"[\\/].+\.exe$", p, re.I)]
    if not file_paths or not is_windows():
        record_source_status(
            "Publisher lookup (Authenticode)",
            STATE_ABSENT,
            "no on-disk executables among the access traces",
        )
        return result

    # Existence and CompanyName without a subprocess. This also means a file
    # that has been deleted is identified before any PowerShell runs.
    present_paths: list[str] = []
    for path in file_paths:
        exists = _safe_is_file(Path(path))
        result[path]["exists"] = "True" if exists else "False"
        if exists:
            result[path]["company"] = _version_string(path, "CompanyName")
            present_paths.append(path)
        else:
            result[path]["status"] = "FileMissing"
    file_paths = present_paths
    if not file_paths:
        record_source_status(
            "Publisher lookup (Authenticode)",
            STATE_OK,
            "no access-trace binary is still on disk; nothing to verify",
        )
        return result

    failures = 0
    batches = 0

    # Batched: the previous [:80] slice silently dropped everything past the
    # 80th path and pushed the -Command line toward its length limit.
    for start in range(0, len(file_paths), _DEV_BATCH):
        batches += 1
        batch = file_paths[start : start + _DEV_BATCH]
        escaped = ",".join("'" + p.replace("'", "''") + "'" for p in batch)
        # Signature only. Existence and CompanyName are read locally above, so
        # this batch no longer pays for Test-Path or Get-Item per file.
        script = (
            f"$paths = @({escaped}); "
            "$out = foreach ($p in $paths) { "
            "  $signer = ''; $status = 'NotChecked'; "
            "  try { $s = Get-AuthenticodeSignature -LiteralPath $p; "
            "        $status = [string]$s.Status; "
            "        if ($s.SignerCertificate) { $signer = [string]$s.SignerCertificate.Subject } } "
            "  catch { $status = 'CheckFailed' } "
            "  [pscustomobject]@{ Path=$p; Signer=$signer; Status=$status } "
            "}; $out | ConvertTo-Json -Compress"
        )
        raw = _run_powershell(script)
        if not raw:
            failures += 1
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            failures += 1
            continue
        if isinstance(parsed, dict):
            parsed = [parsed]
        for item in parsed or []:
            path = _safe_str(item.get("Path") or "")
            if path not in result:
                continue
            result[path].update(
                {
                    "signer": _safe_str(item.get("Signer") or "").strip(),
                    "status": _safe_str(item.get("Status") or "").strip(),
                }
            )

    signed = sum(1 for v in result.values() if (v.get("status") or "").lower() == "valid")
    if failures >= batches:
        record_source_status(
            "Publisher lookup (Authenticode)",
            STATE_FAIL,
            f"all {batches} PowerShell batch(es) failed — the Developer column has "
            "fallen back to path heuristics and no signature was verified",
        )
    else:
        detail = f"{len(file_paths)} binary/binaries checked, {signed} validly signed"
        if failures:
            detail += f"; {failures} of {batches} batch(es) failed"
        record_source_status(
            "Publisher lookup (Authenticode)",
            STATE_FAIL if failures else STATE_OK,
            detail,
        )
    return result


def _resolve_developer(info: dict[str, str]) -> tuple[str, str, str]:
    """(display, evidence tier, signature status) from the collected evidence.

    Ordering is by strength of evidence, and every tier below a valid
    signature says so in the string itself. The point is that a reader can
    never mistake a directory-name guess for a verified publisher.
    """
    signer = _cn_from_subject(info.get("signer") or "")
    status = (info.get("status") or "").strip()
    company = (info.get("company") or "").strip()
    hint = (info.get("hint") or "").strip()

    if signer and status.lower() == "valid":
        return signer, "Authenticode", status
    if signer:
        return (
            f"{signer} [signature: {status or 'Unknown'}]",
            "Authenticode (not valid)",
            status or "Unknown",
        )
    if company:
        qualifier = "unsigned" if status.lower() in {"", "notsigned"} else status
        return f"{company} (VersionInfo, {qualifier})", "VersionInfo", status or "NotSigned"
    if hint:
        return f"{hint} (path heuristic, unverified)", "path heuristic", status or "Unknown"
    if status == "FileMissing":
        return "Unknown (binary no longer present)", "none", status
    return "Unknown", "none", status or "Unknown"


def enrich_traces_with_developer(traces: list[AccessTraceRow]) -> None:
    paths = [row.get("Application") or "" for row in traces]
    found = lookup_developers(paths)
    for row in traces:
        app = row.get("Application") or ""
        info = found.get(app) or {"hint": _publisher_from_path(app)}
        display, source, status = _resolve_developer(info)
        row["Developer"] = display
        row["DeveloperSource"] = source
        row["SignatureStatus"] = status
        # A binary sitting in a vendor-looking directory without a valid
        # signature is the case this tool exists to surface.
        if info.get("hint") and info.get("exists") == "True" and source != "Authenticode":
            note = row.get("Notes") or ""
            warn = (
                f"Path resembles {info['hint']} but the binary carries no valid "
                "Authenticode signature"
            )
            row["Notes"] = f"{note}; {warn}".strip("; ")


# ---------------------------------------------------------------------------
# LIVE sessions + browser site permissions
# ---------------------------------------------------------------------------

def running_image_pids(record_status: bool = True) -> dict[str, list[int]]:
    """Map lowercase image name (with .exe) -> PIDs.

    tasklist replaces the previous PowerShell round-trip. Get-CimInstance
    Win32_Process serialised every process on the box to JSON through a fresh
    PowerShell interpreter just to build a name/PID index; tasklist emits the
    same information as CSV with no interpreter startup.

    The key keeps the .exe suffix, matching PureWindowsPath(app).name from the
    ConsentStore application path. Dropping it would break the LIVE attach.
    """
    mapping: dict[str, list[int]] = {}

    def note(state: str, detail: str) -> None:
        if record_status:
            record_source_status("Process list (LIVE PID attach)", state, detail)

    if not is_windows():
        note(STATE_ABSENT, "not Windows")
        return mapping

    try:
        proc = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        note(STATE_FAIL, f"tasklist failed ({exc}) — LIVE rows cannot be confirmed")
        return mapping

    if proc.returncode != 0 or not (proc.stdout or "").strip():
        note(
            STATE_FAIL,
            "tasklist returned nothing — LIVE rows cannot be confirmed against a "
            "running image",
        )
        return mapping

    try:
        reader = csv.reader(io.StringIO(proc.stdout))
        for record in reader:
            if len(record) < 2:
                continue
            name = _safe_str(record[0]).strip().lower()
            if not name:
                continue
            try:
                pid = int(_safe_str(record[1]).strip())
            except (TypeError, ValueError):
                continue
            mapping.setdefault(name, []).append(pid)
    except csv.Error as exc:
        note(STATE_FAIL, f"unparseable process list: {exc}")
        return mapping

    if not mapping:
        note(STATE_FAIL, "process list parsed but empty")
        return mapping
    note(STATE_OK, f"{len(mapping)} distinct image name(s) via tasklist")
    return mapping



def mark_live_sessions(
    traces: list[AccessTraceRow], running: dict[str, list[int]] | None = None
) -> None:
    """ConsentStore start-without-stop + matching running process → LIVE.

    The PID attach only applies to NonPackaged rows. A packaged row is keyed
    by Package Family Name, which is not an image name and can never match
    Win32_Process.Name, so the old code reported every packaged LIVE session
    as "process not running — stop time may be stale". That read as a finding
    when it was an artefact of the lookup.
    """
    used = False
    for row in traces:
        start = (row.get("LastStart") or "").strip()
        stop = (row.get("LastStop") or "").strip()
        notes = row.get("Notes") or ""
        open_hint = (not stop and bool(start)) or "possibly still open" in notes.lower()
        if not open_hint:
            continue

        row["Live"] = "1"
        app = row.get("Application") or ""
        packaged = (row.get("AppType") or "").strip().lower() == "packaged"

        if packaged:
            row["LiveExe"] = app or "unknown"
            row["LivePids"] = "packaged app — PFN does not map to a process image name"
            extra = "LIVE capability session (no LastUsedTimeStop); PID attach not applicable"
            row["Notes"] = f"{notes}; {extra}".strip("; ")
            continue

        if running is None:
            running = running_image_pids()
        used = True
        # PureWindowsPath, not Path: the value is a Windows path regardless of
        # what flavour the interpreter defaults to, which also makes this
        # testable off-platform.
        exe = PureWindowsPath(app).name
        key = exe.lower()
        pids = running.get(key, []) if key else []
        row["LiveExe"] = exe or "unknown"
        if pids:
            shown = ", ".join(f"PID {p}" for p in pids[:8])
            if len(pids) > 8:
                shown += f" +{len(pids) - 8} more"
            row["LivePids"] = shown
        else:
            row["LivePids"] = "process not running — stop time may be stale"
        extra = "LIVE capability session (no LastUsedTimeStop)"
        row["Notes"] = f"{notes}; {extra}".strip("; ")

    if used and running is not None:
        record_source_status(
            "Process list (LIVE PID attach)",
            STATE_OK if running else STATE_FAIL,
            f"{len(running)} distinct image name(s) via tasklist"
            if running
            else "no process list available — LIVE rows are unconfirmed",
        )


def _chrome_time_to_dt(raw: Any) -> datetime | None:
    """Decode a browser timestamp of unknown encoding into an aware datetime.

    One ladder, two formatters. The previous pair of independent ladders had
    to agree and did not: Unix milliseconds (~1.79e12 today) fell into the
    >10**12 rung and were divided by 1e6, yielding 1970 dates, and the >10**14
    rung swallowed Unix microseconds that its own comment placed lower.

    Chromium writes WebKit microseconds since 1601, so the lower rungs are
    unreachable with real data. They are still correct now, because a silently
    wrong date is worse than a blank one.

    Boundaries, against magnitudes as of the mid-2020s:
        FILETIME, 100 ns since 1601   ~1.34e17   > 5e16
        WebKit microseconds since 1601 ~1.34e16   > 5e15
        Unix microseconds              ~1.79e15   > 1e14
        Unix milliseconds              ~1.79e12   > 1e11
        Unix seconds                   ~1.79e9    else
    """
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None

    if value > 5 * 10**16:
        return filetime_to_dt(value)
    if value > 5 * 10**15:
        return filetime_to_dt(value * 10)
    if value > 10**14:
        seconds = value / 1_000_000.0
    elif value > 10**11:
        seconds = value / 1000.0
    else:
        seconds = float(value)
    try:
        return datetime.fromtimestamp(seconds, timezone.utc).astimezone()
    except (OSError, OverflowError, ValueError):
        return None


def _chrome_time_to_iso(raw: Any) -> str:
    """Browser timestamp as ISO-8601 with a UTC offset."""
    dt = _chrome_time_to_dt(raw)
    return dt.astimezone().isoformat(timespec="seconds") if dt else ""


def _chrome_time_to_str(raw: Any) -> str:
    """Browser timestamp as a local display string."""
    dt = _chrome_time_to_dt(raw)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S") if dt else ""



def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clean_content_origin(key: str) -> str:
    text = (key or "").strip()
    text = text.split(",")[0]
    text = re.sub(r":\d+$", "", text)
    return text


_CHROMIUM_SETTING = {0: "Default", 1: "Allow", 2: "Block", 3: "Ask", 4: "Session", 5: "Detect"}


def _iter_chromium_exceptions(blob: Any) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    if not isinstance(blob, dict):
        return rows
    for origin, meta in blob.items():
        setting = ""
        modified = ""
        modified_iso = ""
        if isinstance(meta, dict):
            raw_set = meta.get("setting")
            if isinstance(raw_set, dict):
                raw_set = raw_set.get("setting", raw_set.get("value"))
            try:
                setting = _CHROMIUM_SETTING.get(int(raw_set), str(raw_set))
            except (TypeError, ValueError):
                setting = _safe_str(raw_set)
            stamp = meta.get("last_modified") or meta.get("expiration")
            modified = _chrome_time_to_str(stamp)
            modified_iso = _chrome_time_to_iso(stamp)
        else:
            setting = _safe_str(meta)
        rows.append(
            (_clean_content_origin(origin), setting or "Unknown", modified, modified_iso)
        )
    return rows


def _load_json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return {}


def _chromium_user_data_roots() -> list[tuple[str, Path]]:
    local = os.environ.get("LOCALAPPDATA") or ""
    roaming = os.environ.get("APPDATA") or ""
    candidates = [
        ("Brave", Path(local) / "BraveSoftware" / "Brave-Browser" / "User Data"),
        ("Chrome", Path(local) / "Google" / "Chrome" / "User Data"),
        ("Edge", Path(local) / "Microsoft" / "Edge" / "User Data"),
        ("Chromium", Path(local) / "Chromium" / "User Data"),
        ("Vivaldi", Path(local) / "Vivaldi" / "User Data"),
        ("Opera", Path(roaming) / "Opera Software" / "Opera Stable"),
    ]
    return [(name, path) for name, path in candidates if path.is_dir()]


def _chromium_profile_dirs(user_data: Path) -> list[tuple[str, Path, bool]]:
    """Return (label, path, is_default)."""
    names: dict[str, str] = {}
    state = user_data / "Local State"
    if _safe_is_file(state):
        cache = (_load_json_file(state).get("profile") or {}).get("info_cache") or {}
        if isinstance(cache, dict):
            for folder, meta in cache.items():
                display = ""
                if isinstance(meta, dict):
                    display = _safe_str(meta.get("name") or meta.get("gaia_name") or "")
                names[folder] = display or folder
    found: list[tuple[str, Path, bool]] = []
    # Opera Stable is itself the default profile directory.
    prefs_here = user_data / "Preferences"
    if _safe_is_file(prefs_here) and not (user_data / "Default").is_dir():
        found.append((names.get("Default") or "Default", user_data, True))
        return found
    for child in sorted(user_data.iterdir(), key=lambda p: p.name.lower()):
        if not child.is_dir():
            continue
        if not _safe_is_file(child / "Preferences"):
            continue
        folder = child.name
        if folder in {"System Profile", "Guest Profile"}:
            continue
        is_default = folder.lower() == "default"
        # Default keeps its display name alone; any other folder renders as
        # "folder (display)" when the two differ. The previous form spelled
        # this out in three branches, two of which could never change anything.
        display = names.get(folder) or folder
        label = (
            display
            if folder == "Default" or display == folder
            else f"{folder} ({display})"
        )
        found.append((label, child, is_default))
    return found


def _permissions_from_chromium_profile(pref_dir: Path) -> list[SitePermissionRow]:
    prefs = _load_json_file(pref_dir / "Preferences")
    exceptions = (
        (prefs.get("profile") or {}).get("content_settings") or {}
    ).get("exceptions") or {}
    rows: list[dict[str, str]] = []
    if not isinstance(exceptions, dict):
        return rows
    for cap_key, cap_label in (
        ("media_stream_mic", "Microphone"),
        ("media_stream_camera", "Camera"),
    ):
        for origin, setting, modified, modified_iso in _iter_chromium_exceptions(
            exceptions.get(cap_key)
        ):
            if setting.lower() in {"default", "ask", "detect", ""}:
                continue
            rows.append(
                {
                    "Origin": origin,
                    "Capability": cap_label,
                    "Setting": setting,
                    "LastModified": modified,
                    "LastModifiedISO": modified_iso,
                    "Expires": "",
                }
            )
    return rows


def _parse_ini_sections(path: Path) -> list[tuple[str, dict[str, str]]]:
    """profiles.ini as ordered (section name, key/value) pairs."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    sections: list[tuple[str, dict[str, str]]] = []
    name = ""
    body: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            if name or body:
                sections.append((name, body))
            name = line[1:-1].strip()
            body = {}
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            body[key.strip()] = value.strip()
    if name or body:
        sections.append((name, body))
    return sections


def _firefox_roots() -> list[tuple[str, Path, bool]]:
    """(display name, profile path, is_default) for every Firefox profile.

    The default is recorded in an [InstallXXXXXXXX] section as
    Default=Profiles/xxxxxxxx.default-release, not as Default=1 on the
    [ProfileN] section. The old parser required a Path= key, so it skipped
    Install sections entirely and fell back to matching "default" in the
    profile name. On a normal install that picks the legacy xxxxxxxx.default
    stub, which Firefox has not written to since the release-profile split
    and which usually has no permissions.sqlite at all.
    """
    roaming = os.environ.get("APPDATA") or ""
    ini = Path(roaming) / "Mozilla" / "Firefox" / "profiles.ini"
    if not _safe_is_file(ini):
        return []
    root = ini.parent
    sections = _parse_ini_sections(ini)

    def resolve(rel_or_abs: str, relative: bool) -> Path:
        # profiles.ini writes forward slashes even on Windows. Split on both
        # separators and rejoin, rather than substituting into a string, so
        # the result is correct regardless of the interpreter's path flavour.
        raw = (rel_or_abs or "").strip()
        if not relative:
            return Path(raw)
        parts = [part for part in re.split(r"[\\/]+", raw) if part]
        return root.joinpath(*parts) if parts else root

    profiles: list[tuple[str, Path]] = []
    for name, body in sections:
        if not name.lower().startswith("profile"):
            continue
        path = body.get("Path") or ""
        if not path:
            continue
        prof = resolve(path, body.get("IsRelative", "1") != "0")
        profiles.append((body.get("Name") or prof.name, prof))

    # Preference order for which profile Firefox actually uses.
    install_defaults = [
        resolve(body["Default"], True)
        for name, body in sections
        if name.lower().startswith("install") and body.get("Default")
    ]
    flagged = [
        resolve(body.get("Path") or "", body.get("IsRelative", "1") != "0")
        for name, body in sections
        if name.lower().startswith("profile") and body.get("Default") == "1"
    ]

    def norm(path: Path) -> str:
        return str(path).rstrip("\\/").lower()

    default_path = ""
    for candidate in install_defaults + flagged:
        match = next((pr for _n, pr in profiles if norm(pr) == norm(candidate)), None)
        if match is not None:
            default_path = norm(match)
            break
    if not default_path:
        # Last resorts, in order: a release profile, then the first listed.
        release = next(
            (pr for _n, pr in profiles if pr.name.lower().endswith(".default-release")),
            None,
        )
        if release is not None:
            default_path = norm(release)
        elif profiles:
            default_path = norm(profiles[0][1])

    # Exactly one profile is flagged, so the caller cannot pick the wrong one.
    return [(name, prof, norm(prof) == default_path) for name, prof in profiles]



def _permissions_from_firefox_profile(prof: Path) -> list[SitePermissionRow]:
    db = prof / "permissions.sqlite"
    label = f"Firefox permissions.sqlite ({prof.name})"
    rows: list[dict[str, str]] = []
    if not prof.is_dir():
        record_source_status(
            label,
            STATE_FAIL,
            f"profile directory listed in profiles.ini does not exist: {prof}",
        )
        return rows
    with readonly_sqlite(db) as (conn, state, detail):
        if conn is None:
            if state == STATE_ABSENT:
                detail = (
                    "no permissions.sqlite in this profile — Firefox writes the file "
                    "on the first site permission decision, so none has been stored here"
                )
            record_source_status(label, state, detail)
            return rows
        try:
            _read_firefox_permissions(conn, rows)
        except Exception as exc:
            record_source_status(
                label, STATE_FAIL, f"opened ({detail}); query failed: {exc}"
            )
            return rows
    record_source_status(
        label,
        STATE_OK,
        f"{detail}; {len(rows)} mic/camera grant{'s' if len(rows) != 1 else ''}",
    )
    return rows


def _read_firefox_permissions(conn: Any, rows: list[SitePermissionRow]) -> None:
    """Parse an open permissions.sqlite.

    Table and column identifiers are interpolated, but each is chosen from a
    literal whitelist after being confirmed present in PRAGMA table_info.

    Firefox permissions carry an expiry: expireType 0 never expires, 1 lasts
    for the session, 2 expires at expireTime (ms since the epoch). A grant
    whose expireTime has passed is no longer in force, so reporting it as a
    live Allow overstates what the browser will actually do.
    """
    tables = {n for (n,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    table = "moz_perms" if "moz_perms" in tables else ("moz_hosts" if "moz_hosts" in tables else "")
    if not table:
        return
    cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    if "type" not in cols:
        return
    origin_col = "origin" if "origin" in cols else ("host" if "host" in cols else "")
    if not origin_col:
        return

    optional = [c for c in ("permission", "modificationTime", "expireType", "expireTime") if c in cols]
    wanted = [origin_col, "type"] + optional
    cur = conn.execute(
        f"SELECT {', '.join(wanted)} FROM {table} WHERE type IN ('microphone','camera')"
    )

    now_ms = datetime.now(timezone.utc).timestamp() * 1000.0
    for rec in cur.fetchall():
        data = dict(zip(wanted, rec))
        kind = _safe_str(data.get("type"))
        if kind not in {"microphone", "camera"}:
            continue

        perm = data.get("permission") if "permission" in optional else 1
        try:
            setting = {1: "Allow", 2: "Block", 0: "Unknown"}.get(int(perm), str(perm))
        except (TypeError, ValueError):
            setting = str(perm)
        if setting not in {"Allow", "Block"}:
            continue

        expire_type = _as_int(data.get("expireType"))
        expire_time = _as_int(data.get("expireTime"))
        expires = ""
        if expire_type == 1:
            expires = "session only"
            setting = f"{setting} (session)"
        elif expire_type == 2 and expire_time > 0:
            if expire_time <= now_ms:
                # Already lapsed. Firefox will prompt again, so this is not a
                # standing grant and does not belong in the report.
                continue
            expires = epoch_to_iso(expire_time / 1000.0)

        modified = ""
        modified_iso = ""
        raw_t = data.get("modificationTime")
        if raw_t:
            try:
                stamp = int(raw_t) / 1000.0
                modified = datetime.fromtimestamp(stamp).strftime("%Y-%m-%d %H:%M:%S")
                modified_iso = epoch_to_iso(stamp)
            except (OSError, OverflowError, ValueError, TypeError):
                modified = ""
        rows.append(
            {
                "Origin": _safe_str(data.get(origin_col)),
                "Capability": "Microphone" if kind == "microphone" else "Camera",
                "Setting": setting,
                "LastModified": modified,
                "LastModifiedISO": modified_iso,
                "Expires": expires,
            }
        )



def get_browser_media_permissions() -> dict[str, Any]:
    """Default-profile mic/camera site permissions + names of extra profiles."""
    browsers: list[dict[str, Any]] = []

    for product, root in _chromium_user_data_roots():
        profiles = _chromium_profile_dirs(root)
        if not profiles:
            continue
        extra = [label for label, _path, is_def in profiles if not is_def]
        default_rows: list[dict[str, str]] = []
        default_name = "Default"
        for label, path, is_def in profiles:
            if is_def:
                default_name = label
                default_rows = _permissions_from_chromium_profile(path)
                break
        browsers.append(
            {
                "Browser": product,
                "DefaultProfile": default_name,
                "ExtraProfiles": extra,
                "Permissions": default_rows,
            }
        )

    fx = _firefox_roots()
    if fx:
        # Existence check only. The README's contract is that extra profiles
        # are named, not expanded; but naming one that holds stored grants is
        # what tells the reader the default may not be the profile they use.
        extra = []
        for label, path, is_def in fx:
            if is_def:
                continue
            if _safe_is_file(path / "permissions.sqlite"):
                extra.append(f"{label} (has stored permissions, not read)")
            else:
                extra.append(label)
        default_rows: list[dict[str, str]] = []
        default_name = "default"
        for label, path, is_def in fx:
            if is_def:
                default_name = label
                default_rows = _permissions_from_firefox_profile(path)
                break
        browsers.append(
            {
                "Browser": "Firefox",
                "DefaultProfile": default_name,
                "ExtraProfiles": extra,
                "Permissions": default_rows,
            }
        )

    return {"browsers": browsers}


def print_site_permissions(report: dict[str, Any]) -> None:
    width = _term_width()
    print()
    print("=" * width)
    print("TABLE 3 — Browser site permissions (mic / camera only, default profile)")
    print("=" * width)
    browsers = report.get("browsers") or []
    if not browsers:
        print("No Chromium/Firefox user-data directories found.")
        return
    for i, browser in enumerate(browsers):
        extra = browser.get("ExtraProfiles") or []
        extra_txt = ", ".join(extra) if extra else "(none)"
        print(
            f"{browser.get('Browser')}  default={browser.get('DefaultProfile') or 'Default'}"
            f"  other_profiles={extra_txt}"
        )
        if extra:
            print("  Note: extra profiles exist (possible alternate-identity vector); permissions not dumped.")
        perms = browser.get("Permissions") or []
        if not perms:
            print("  No Allow/Block mic or camera site entries in the default profile.")
        else:
            perms = sorted(
                perms,
                key=lambda r: (r.get("Capability") or "", r.get("Origin") or ""),
            )
            for row in perms:
                setting = row.get("Setting") or ""
                shown = color_allow(setting) if setting == "Allow" else setting
                modified = row.get("LastModified") or ""
                tail = f"  last_modified={modified}" if modified else ""
                print(
                    f"  {row.get('Capability') or '':<12} {shown:<8} "
                    f"{row.get('Origin') or ''}{tail}"
                )
        if i != len(browsers) - 1:
            print("-" * width)
    total = sum(len(b.get("Permissions") or []) for b in browsers)
    print(
        f"({total} default-profile site permission "
        f"{'row' if total == 1 else 'rows'}; expired grants are omitted)"
    )


_T = TypeVar("_T")


def _guarded(label: str, fn: Callable[[], _T], default: _T) -> _T:
    """Run one source and convert any failure into a status line.

    No single artifact may abort the audit. A protected directory, a locked
    hive, a missing console tool -- each is one source failing, and the rest of
    the report is still worth printing. The tool's whole premise is that an
    empty table and an unreadable source are different claims, which it cannot
    make if an exception takes the process down before anything is rendered.
    """
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - deliberate isolation boundary
        detail = f"{type(exc).__name__}: {exc}"
        if isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5:
            detail += " — access denied; try an elevated shell"
        record_source_status(label, STATE_FAIL, detail)
        return default


def collect() -> tuple[
    list[dict[str, str]],
    list[AccessTraceRow],
    list[ActiveDeviceRow],
    dict[str, list[int]],
]:
    """Gather every source, overlapping the ones that do not depend on each other.

    Three of these paths each start a fresh PowerShell or console process and
    spend most of their wall time waiting on it. They touch disjoint data --
    the registry walk reads HKLM/HKCU, the PnP enumeration shells out, the
    process list shells out -- so they are safe to run together. Only
    _SOURCE_STATUS is shared, and record_source_status takes a lock and renders
    through a fixed order, so interleaving cannot reorder the report.

    Every source is individually guarded. One unreadable artifact degrades to a
    FAIL line; it never costs the caller the other tables.

    Returns the process map as well: it is fetched speculatively here in
    parallel with everything else, and mark_live_sessions consumes it rather
    than paying for its own call afterwards.
    """
    _SOURCE_STATUS.clear()
    # Resolve before any worker starts: current_user_sid caches into a module
    # global and the consent walk on another thread would otherwise race it.
    _guarded("Current user SID", current_user_sid, "")

    def registry_pass() -> tuple[list[dict[str, str]], list[AccessTraceRow]]:
        consent = _guarded("Privacy consent summary", read_consent_summary, [])
        historical: list[AccessTraceRow] = []
        for label, source in (
            ("ConsentStore (registry)", iter_consentstore),
            ("MMDevices\\Capture (registry)", iter_mmdevices_capture),
            ("MMDevices\\Render (registry)", iter_mmdevices_render_loopback),
            ("Enum hardware nodes (registry)", iter_enum_cameras),
            ("CapabilityAccessManager.db", iter_cam_database),
        ):
            historical.extend(_guarded(label, source, []))
        return consent, historical

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        registry_future = pool.submit(registry_pass)
        pnp_future = pool.submit(
            _guarded, "Live PnP enumeration", enum_active_pnp, []
        )
        # record_status=False: this may turn out to be unnecessary, and a
        # status line should describe work that mattered to the report.
        procs_future = pool.submit(
            _guarded,
            "Process list (LIVE PID attach)",
            lambda: running_image_pids(False),
            {},
        )

        consent, historical = _guarded(
            "Registry pass", registry_future.result, ([], [])
        )
        active = pnp_future.result()
        running = procs_future.result()

    return consent, historical, active, running



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit active and historical Windows cameras and microphones."
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of tables")
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Write audiocam_historical.csv and audiocam_active.csv in the current directory",
    )
    parser.add_argument(
        "--inventory",
        action="store_true",
        help=(
            "Also list Enum/MMDevices hardware nodes that have no access timestamp. "
            "Default output is access traces only (ConsentStore / CAM.db with LastUsedTimeStart)."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"AudioCam.py {__version__}",
        help="Print the version and exit",
    )
    args = parser.parse_args(argv)

    if not is_windows():
        print(
            "AudioCam.py must run on Windows (winreg is unavailable on this host).",
            file=sys.stderr,
        )
        return 2

    now = datetime.now().astimezone()
    generated = now.strftime("%Y-%m-%d %H:%M:%S %Z")
    generated_iso = now.isoformat(timespec="seconds")
    host = socket.gethostname()
    elevated = is_elevated()

    try:
        consent, historical, active, running = collect()
    except Exception as exc:
        # collect() guards every source individually, so reaching here means
        # something structural broke rather than one artifact being unreadable.
        # Print whatever status was recorded before the failure: telling the
        # user which sources did read is more useful than a bare error.
        print(f"Fatal collection error: {type(exc).__name__}: {exc}", file=sys.stderr)
        for entry in _source_status_sorted():
            print(
                f"  [{entry['State']}] {entry['Source']}: {entry['Detail']}",
                file=sys.stderr,
            )
        if isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5:
            print(
                "  Access was denied. Re-run from an elevated shell to include "
                "machine-wide artifacts.",
                file=sys.stderr,
            )
        return 2

    inventory_rows = [r for r in historical if not is_access_trace(r)]
    traces = [r for r in historical if is_access_trace(r)]
    for row in traces:
        row["RecordKind"] = "access-trace"
    for row in inventory_rows:
        row["RecordKind"] = "hardware-inventory"
    catalog = hardware_vidpid_catalog(historical, active)
    enrich_traces_with_vidpid(traces, catalog)
    enrich_traces_with_developer(traces)
    mark_live_sessions(traces, running)
    traces.sort(key=trace_sort_key)
    site_perms = get_browser_media_permissions()
    # Every later use site wrote "table1 if args.inventory else traces", which
    # is the same expression three times over: table1 already is traces here.
    table1 = traces + inventory_rows if args.inventory else traces

    if args.json:
        payload = {
            "generated_at": generated,
            "generated_at_iso": generated_iso,
            "host": host,
            "elevated": elevated,
            "consent_summary": consent,
            "historical": table1,
            "access_traces": traces,
            "hardware_inventory": inventory_rows,
            "active": active,
            "site_permissions": site_perms,
            "source_status": _source_status_sorted(),
        }
        json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
        print()
        return 0

    enable_ansi()
    print_banner()
    print(f"host={host}  generated={generated}  elevated={elevated}")
    print(
        "Table 1 = apps that actually opened the mic/camera (LastUsedTimeStart present), "
        "sorted longest session first."
    )
    print(
        "Table 1b = hardware nodes with no access timestamp (--inventory only). "
        "Presence on the box, not evidence of use."
    )
    print("Table 2 = devices plugged in / enumerated right now.")
    print(
        "Table 3 = default-profile site mic/camera permissions (Chromium Preferences / "
        "Firefox permissions.sqlite). Extra profiles are named only."
    )
    if not elevated:
        print("Note: not elevated — HKLM / other-user HKU keys may be incomplete.")
    if _Figlet is None:
        print("Tip: pip install pyfiglet  — uses the figlet module for the AudioCam.py banner.")

    print()
    print("Privacy consent (capability root Value)")
    print("-" * 40)
    for row in consent:
        value = row["GlobalConsent"]
        shown = color_allow(value)
        flag = ""
        if value == "Allow":
            flag = (
                "  [desktop apps may activate without per-use consent — "
                "Settings → Privacy & security → "
                f"{row['Capability']}]"
            )
        print(f"  {row['Hive']:28}  {row['Capability']:12}  {shown}{flag}")

    # Only artifacts that were actually found get a line here. A source that
    # simply does not exist on this host is recorded for --json but says
    # nothing on the console: this module is about microphones and cameras,
    # not about narrating which databases are missing.
    reportable = [e for e in _source_status_sorted() if e["State"] != STATE_ABSENT]
    if reportable:
        failed = [e for e in reportable if e["State"] == STATE_FAIL]
        print()
        print("Source status")
        print("-" * 40)
        marks = {STATE_OK: " ok ", STATE_FAIL: "FAIL"}
        for entry in reportable:
            mark = marks.get(entry["State"], "  ? ")
            print(f"  [{mark}] {entry['Source']}: {entry['Detail']}")
        if failed:
            print(
                "  A FAIL means the artifact exists but could not be read, so an empty "
                "table below is not evidence of absence."
            )

    print_access_records(
        "TABLE 1 — Historical access traces (longest duration first)",
        traces,
    )
    if args.inventory:
        print_inventory_records(
            "TABLE 1b — Hardware inventory (no access timestamp)",
            inventory_rows,
        )
    print_active_records(
        "TABLE 2 — Active / currently connected cameras and microphones",
        active,
    )
    print_site_permissions(site_perms)

    if args.csv:
        hist_path = Path.cwd() / "audiocam_historical.csv"
        act_path = Path.cwd() / "audiocam_active.csv"
        write_csv(hist_path, table1, HIST_COLS)
        write_csv(act_path, active, ACTIVE_COLS)
        site_path = Path.cwd() / "audiocam_site_permissions.csv"
        site_rows: list[dict[str, str]] = []
        for browser in site_perms.get("browsers") or []:
            if not (browser.get("Permissions") or []):
                site_rows.append(
                    {
                        "Browser": browser.get("Browser") or "",
                        "Profile": browser.get("DefaultProfile") or "Default",
                        "Origin": "",
                        "Capability": "",
                        "Setting": "",
                        "LastModified": "",
                        "ExtraProfiles": ", ".join(browser.get("ExtraProfiles") or []),
                    }
                )
            for perm in browser.get("Permissions") or []:
                site_rows.append(
                    {
                        "Browser": browser.get("Browser") or "",
                        "Profile": browser.get("DefaultProfile") or "Default",
                        "Origin": perm.get("Origin") or "",
                        "Capability": perm.get("Capability") or "",
                        "Setting": perm.get("Setting") or "",
                        "LastModified": perm.get("LastModified") or "",
                        "LastModifiedISO": perm.get("LastModifiedISO") or "",
                        "Expires": perm.get("Expires") or "",
                        "ExtraProfiles": ", ".join(browser.get("ExtraProfiles") or []),
                    }
                )
        write_csv(site_path, site_rows, SITE_COLS)
        print()
        print(f"Wrote {hist_path}")
        print(f"Wrote {act_path}")
        print(f"Wrote {site_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
