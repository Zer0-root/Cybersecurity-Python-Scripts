#!/usr/bin/env python3
# Intention.py
# Read-only collector of INTERACTIVE COMMAND-LINE HISTORY on a Windows host.
#
# Scope: strings a human typed, pasted, or entered at an interactive shell
# prompt - on Windows itself and in the POSIX environments that live beside it.
#
# Artifacts (default run):
#   CMD family
#     cmd.exe /c doskey /history                       (live session buffer only)
#     %LOCALAPPDATA%\clink\{.history,clink_history}    (GNU readline + "# epoch")
#     %APPDATA%\clink\*history*
#     %CMDER_ROOT%\config\.history                     (Cmder)
#     ConEmu install dirs - only a sibling Clink history file, never the XML
#     Windows Terminal LocalState - only files clearly named as history
#   PowerShell
#     %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\*history*.txt
#       (ConsoleHost, Visual Studio Code Host, Windows PowerShell ISE Host,
#        pwsh 7+ hosts - one table per $Host.Name)
#   POSIX-on-Windows ports
#     Git for Windows / MSYS2 / Cygwin / MinGW:
#       .bash_history, .bash_history-<host>, .zsh_history, .zhistory,
#       .fish_history, .ash_history
#   WSL
#     HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss  (distro inventory)
#     WSL1 rootfs on NTFS; WSL2 via \\wsl$ only when the share already answers
#     ext4.vhdx is INVENTORIED, never mounted read-write
#   Esoteric shells
#     nushell, xonsh, elvish, oil/ysh, ion - plaintext history only
#
# Explicitly NOT collected (by design, not by omission):
#   Explorer MRU (RunMRU/TypedPaths/ComDlg32/WordWheelQuery) unless
#   --legacy-explorer; ShellBags, UserAssist, Jump Lists, LNK; Prefetch,
#   BAM/DAM, AmCache, Shimcache, SRUM; Event Log 4688/4103/4104, script-block
#   logging, transcripts; browser or Office MRU; clipboard; any hooking,
#   keylogging, or process memory access.
#
# Timestamp caveat: history-file MTIME applies at most to the LAST appended
# line. Older lines are ordered, not individually timed. Per-command times
# exist only where the shell wrote them (Clink "# epoch", bash HISTTIMEFORMAT,
# zsh EXTENDED_HISTORY, fish "when"). This tool never invents a time.
"""
Intention.py - authorized-use-only collector of interactive command-line
history on Windows.

Purpose
    Reconstruct the commands a human typed or pasted at a shell prompt: cmd.exe
    stand-ins (Clink/Cmder/ConEmu), PowerShell and pwsh PSReadLine hosts, and
    the bash/zsh/fish/ash histories of WSL, Git Bash, MSYS2 and Cygwin. It is
    not an execution timeline, not evidence of execution, and not a keylogger.
    It only reads files and registry keys the operating system already wrote.

What this tool cannot see
    Non-interactive, service, scheduled-task, WinRM, and in-process runspace
    activity leave no shell-history artifact. Native cmd.exe history is
    session-volatile. bash typically flushes its history only on a clean
    `exit`, so a WSL window closed with the X button can lose an entire
    session. Absence of rows is not evidence that no shell ran.

Timestamp limitations
    Every row carries timestamp_provenance. Read it. A populated
    utc_timestamp with provenance file_mtime_last_append_only describes when
    the file was last appended to - not when that command was typed.

Authorized use
    Incident response, insider-threat review, and triage of hosts you are
    authorized to examine. Shell history routinely contains credentials,
    connection strings, and tokens; treat the output as sensitive.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import datetime as dt
import json
import logging
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import tempfile
import traceback
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

LOG = logging.getLogger("intention")

VERSION = "1.4.1"

# ---------------------------------------------------------------------------
# Provenance vocabulary (closed set)
#
#   key_lastwrite_most_recent_only  registry key LastWrite; only the MRU head
#   file_mtime_last_append_only     file MTIME; only the LAST line of the file
#   file_ctime                      file creation/change time of the artifact
#   mru_index_only_no_time          position in an MRU list, no time at all
#   order_only                      file order only, no time at all
#   clink_embedded_epoch            Clink / GNU readline "# <unix_epoch>" line
#   db_recorded_epoch               per-command epoch read from a history
#                                   DATABASE (nushell SQLite, atuin) together
#                                   with cwd / exit status / session context
#   histtimeformat_epoch            per-command epoch the SHELL itself wrote:
#                                   bash HISTTIMEFORMAT "# <epoch>",
#                                   zsh EXTENDED_HISTORY ": <epoch>:<dur>;cmd",
#                                   fish "when: <epoch>"
#   collection_time_only            observed at collection time (live doskey)
#   unavailable                     artifact known to exist, contents not read
#
# clink_embedded_epoch and histtimeformat_epoch are both real per-command
# times. They are kept distinct so an examiner can tell which writer produced
# them. Nothing else in this file is ever a per-command time.
# ---------------------------------------------------------------------------
PROV_KEY_LASTWRITE_MR0 = "key_lastwrite_most_recent_only"
PROV_FILE_MTIME_LAST = "file_mtime_last_append_only"
PROV_FILE_CTIME = "file_ctime"
PROV_MRU_NO_TIME = "mru_index_only_no_time"
PROV_CLINK_EPOCH = "clink_embedded_epoch"
PROV_HISTTIME_EPOCH = "histtimeformat_epoch"
PROV_DB_EPOCH = "db_recorded_epoch"
PROV_COLLECTION = "collection_time_only"
PROV_UNAVAILABLE = "unavailable"
PROV_ORDER_ONLY = "order_only"

EXACT_PROVENANCE = (PROV_CLINK_EPOCH, PROV_HISTTIME_EPOCH, PROV_DB_EPOCH)

PROVENANCE_VOCABULARY = [
    PROV_KEY_LASTWRITE_MR0,
    PROV_FILE_MTIME_LAST,
    PROV_FILE_CTIME,
    PROV_MRU_NO_TIME,
    PROV_ORDER_ONLY,
    PROV_CLINK_EPOCH,
    PROV_HISTTIME_EPOCH,
    PROV_DB_EPOCH,
    PROV_COLLECTION,
    PROV_UNAVAILABLE,
]

# History-file basenames -> shell label, used by every POSIX-family collector.
POSIX_HISTORY_FILES = {
    ".bash_history": "bash",
    ".sh_history": "sh",
    ".ash_history": "ash",
    ".zsh_history": "zsh",
    ".zhistory": "zsh",
    ".histfile": "zsh",
    ".fish_history": "fish",
    ".local/share/fish/fish_history": "fish",
}

# REPL histories - only with --include-repls (these are not shells).
REPL_HISTORY_FILES = {
    ".python_history": "python-repl",
    ".node_repl_history": "node-repl",
    ".irb_history": "irb-repl",
    ".psql_history": "psql-repl",
    ".sqlite_history": "sqlite-repl",
}

LXSS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Lxss"

# history_access vocabulary for WSL-Inventory rows
# ---------------------------------------------------------------------------
# Privilege context of a collected profile (closed set).
#
# Derived from the profile SID, and factual: history under the SYSTEM profile
# could only have been written by a process running as SYSTEM.
#
# There is deliberately NO "elevated" value. Windows UAC uses a split token,
# so for an administrator account the elevated and non-elevated shells write
# to the SAME history file - clink_history and the PSReadLine files are
# per-user, not per-integrity-level. Whether a given session was elevated is
# not recoverable from these artifacts, and inventing a value for it would be
# a guess wearing the clothes of a finding.
# ---------------------------------------------------------------------------
PRIV_SYSTEM = "system"
PRIV_SERVICE = "service"
PRIV_BUILTIN_ADMIN = "builtin-administrator"
PRIV_USER = "user"
PRIV_UNKNOWN = "unknown"

PRIVILEGE_CONTEXTS = (PRIV_SYSTEM, PRIV_SERVICE, PRIV_BUILTIN_ADMIN, PRIV_USER, PRIV_UNKNOWN)

PRIVILEGE_CAVEAT = (
    "Privilege context is derived from the profile SID and identifies an ACCOUNT, never a "
    "person - anyone may be using an account. Windows UAC uses a split token, so an "
    "administrator's elevated and non-elevated shells write to the same history file: "
    "whether a session was elevated is NOT recoverable from these artifacts."
)

# What a single candidate path probe returned (closed set). This is what turns
# "None detected" from an assertion into a demonstrated negative.
ABSENCE_READ_OK = "read_ok"
ABSENCE_PATH_ABSENT = "path_absent"
ABSENCE_PRESENT_EMPTY = "present_but_empty"
ABSENCE_PRESENT_UNREADABLE = "present_unreadable"
ABSENCE_PERMISSION_DENIED = "permission_denied"

ABSENCE_OUTCOMES = (
    ABSENCE_READ_OK,
    ABSENCE_PATH_ABSENT,
    ABSENCE_PRESENT_EMPTY,
    ABSENCE_PRESENT_UNREADABLE,
    ABSENCE_PERMISSION_DENIED,
)

# Outcomes that mean the question was NOT answered. These must never be
# rendered as absence.
ABSENCE_UNANSWERED = (ABSENCE_PRESENT_UNREADABLE, ABSENCE_PERMISSION_DENIED)

# Whether a package-manager directory represents a live install or leftovers.
INSTALL_STATE_INSTALLED = "installed"
INSTALL_STATE_REMNANT = "remnant"
INSTALL_STATE_AMBIGUOUS = "ambiguous"

INSTALL_STATES = (INSTALL_STATE_INSTALLED, INSTALL_STATE_REMNANT, INSTALL_STATE_AMBIGUOUS)

# Whether a WSL distro's history was actually found - not whether we could
# reach it. "existence_not_determined" is the honest answer when the VHDX was
# inventoried but never opened: the distro is registered and the image is
# present, and that is all the tool knows. WSL is a documented AV-evasion
# route, so an examiner must not read "unreachable" as "there is history in
# there."
WSL_HIST_CONFIRMED_READ = "history_confirmed_read"
WSL_HIST_CONFIRMED_ABSENT = "history_confirmed_absent"
WSL_HIST_PRESENT_UNREADABLE = "history_present_unreadable"
WSL_HIST_NOT_DETERMINED = "existence_not_determined"

WSL_HISTORY_STATES = (
    WSL_HIST_CONFIRMED_READ,
    WSL_HIST_CONFIRMED_ABSENT,
    WSL_HIST_PRESENT_UNREADABLE,
    WSL_HIST_NOT_DETERMINED,
)

SKIP_PROFILES = {
    "default",
    "default user",
    "defaultuser0",
    "public",
    "all users",
    "wdagutilityaccount",
}

RUNMRU_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
TYPEDPATHS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
COMDLG32_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"
WORDWHEEL_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
PROFILELIST_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

DEFAULT_SOURCES = {"cmd", "powershell", "bash", "wsl", "esoteric", "config"}

SOURCE_ALIASES = {
    "cmd": "cmd",
    "clink": "cmd",
    "doskey": "cmd",
    "powershell": "powershell",
    "ps": "powershell",
    "pwsh": "powershell",
    "psreadline": "powershell",
    "bash": "bash",
    "posix": "bash",
    "zsh": "bash",
    "fish": "bash",
    "wsl": "wsl",
    "lxss": "wsl",
    "esoteric": "esoteric",
    "nushell": "esoteric",
    "atuin": "esoteric",
    "config": "config",
    "policy": "config",
    "histfile": "config",
    "xonsh": "esoteric",
    "legacy-explorer": "legacy-explorer",
    "legacy_explorer": "legacy-explorer",
    "explorer": "legacy-explorer",
    # v1 spellings kept so old command lines still resolve
    "runmru": "legacy-explorer",
    "typedpaths": "legacy-explorer",
    "comdlg32": "legacy-explorer",
    "wordwheel": "legacy-explorer",
    "wordwheelquery": "legacy-explorer",
    "repls": "repls",
    "repl": "repls",
}

# Tables that are printed even when they hold nothing, so the examiner can see
# the surface was checked rather than skipped.
REQUIRED_BLOCKS: list[tuple[str, str]] = [
    ("CMD-LiveDoskey", "cmd"),
    ("CMD-Clink", "cmd"),
    ("Powershell", "powershell"),
    ("Bash-Git", "bash"),
    ("Bash-MSYS2", "bash"),
    ("Bash-Cygwin", "bash"),
    ("WSL-Inventory", "wsl"),
    ("WSL-Bash", "wsl"),
    ("Atuin", "esoteric"),
    ("History-Location", "config"),
    ("History-Policy", "config"),
]

# Display order for merged tables; anything unlisted keeps discovery order.
BLOCK_ORDER = [
    "CMD-LiveDoskey",
    "CMD-Clink",
    "CMD-Cmder",
    "CMD-ConEmu",
    "CMD-WindowsTerminal",
    "CMD",
    "Powershell",
    "Powershell-Pwsh",
    "Powershell-VSCodeHost",
    "Powershell-ISE",
    "Powershell-WindowsTerminal",
    "Bash-Git",
    "Bash-MSYS2",
    "Bash-Cygwin",
    "Zsh-Git",
    "Zsh-MSYS2",
    "Zsh-Cygwin",
    "Fish-Git",
    "Fish-MSYS2",
    "Fish-Cygwin",
    "WSL-Inventory",
    "WSL-Bash",
    "WSL-Zsh",
    "WSL-Fish",
    "WSL-Ash",
    "Nushell",
    "Xonsh",
    "Elvish",
    "Oil",
    "Ion",
    "Atuin",
    "History-Location",
    "History-Policy",
    "REPL",
]

# ---------------------------------------------------------------------------
# Terminal catalog - drives the presence inventory table.
#
# Every entry is printed on every run, present or not, so an examiner can see
# what was looked for rather than only what was found. "None detected" is a
# result, not a gap.
#
#   (display type, source family, contributing block names)
# ---------------------------------------------------------------------------
BUILTIN_INSTALL = "*builtin*"  # ships with Windows; no Uninstall entry exists

# (display type, source family, contributing blocks, ARP/display-name regex,
#  exact package-manager names for scoop / winget / chocolatey / cargo)
#
# Registry patterns are regexes matched against the ARP DisplayName or
# Publisher. Package names are matched EXACTLY, because scoop calls nushell
# "nu" and a regex that short would match unrelated software.
TERMINAL_CATALOG: list[tuple[str, str, tuple[str, ...], str, tuple[str, ...]]] = [
    ("CMD (native cmd.exe)", "cmd", ("CMD",), BUILTIN_INSTALL, ()),
    ("CMD live session (doskey)", "cmd", ("CMD-LiveDoskey",), BUILTIN_INSTALL, ()),
    ("CMD + Clink", "cmd", ("CMD-Clink",), r"\bclink\b", ("clink",)),
    ("Cmder", "cmd", ("CMD-Cmder",), r"\bcmder\b", ("cmder", "cmder-full")),
    ("ConEmu", "cmd", ("CMD-ConEmu",), r"\bconemu\b", ("conemu",)),
    ("Windows Terminal", "cmd", ("CMD-WindowsTerminal",), r"windows\s*terminal",
     ("windows-terminal", "windowsterminal")),
    ("PowerShell (ConsoleHost)", "powershell", ("Powershell",), BUILTIN_INSTALL, ()),
    ("PowerShell (VS Code host)", "powershell", ("Powershell-VSCodeHost",),
     r"visual\s*studio\s*code", ("vscode",)),
    ("PowerShell ISE", "powershell", ("Powershell-ISE",), BUILTIN_INSTALL, ()),
    ("PowerShell 7 / pwsh", "powershell", ("Powershell-Pwsh",),
     r"powershell\s*7|\bpwsh\b", ("pwsh", "powershell-core")),
    ("PowerShell (Windows Terminal host)", "powershell", ("Powershell-WindowsTerminal",),
     r"windows\s*terminal", ("windows-terminal", "windowsterminal")),
    ("Bash (Git for Windows)", "bash", ("Bash-Git",),
     r"^git(\s|$)|git\s+version|git\s+for\s+windows|git\s+development\s+community",
     ("git", "git-with-openssh")),
    ("Bash (MSYS2)", "bash", ("Bash-MSYS2",), r"\bmsys2?\b", ("msys2",)),
    ("Bash (Cygwin)", "bash", ("Bash-Cygwin",), r"\bcygwin\b", ("cygwin",)),
    ("Zsh (POSIX ports)", "bash", ("Zsh-Git", "Zsh-MSYS2", "Zsh-Cygwin"), "", ()),
    ("Fish (POSIX ports)", "bash", ("Fish-Git", "Fish-MSYS2", "Fish-Cygwin"), "", ()),
    ("Ash / sh (POSIX ports)", "bash",
     ("Ash-Git", "Ash-MSYS2", "Ash-Cygwin", "Sh-Git", "Sh-MSYS2", "Sh-Cygwin"), "", ()),
    ("WSL distros registered", "wsl", ("WSL-Inventory",),
     r"windows\s+subsystem\s+for\s+linux", ()),
    ("WSL shell history", "wsl", ("WSL-Bash", "WSL-Zsh", "WSL-Fish", "WSL-Ash"), "", ()),
    ("Nushell", "esoteric", ("Nushell",), r"\bnushell\b|\bnu\s+shell\b", ("nu", "nushell")),
    ("Xonsh", "esoteric", ("Xonsh",), r"\bxonsh\b", ("xonsh",)),
    ("Elvish", "esoteric", ("Elvish",), r"\belvish\b", ("elvish",)),
    ("Oils (OSH / YSH)", "esoteric", ("Oil",), r"\boils\b|\boil\s*shell\b|\bysh\b",
     ("oils", "oil", "ysh")),
    ("Ion", "esoteric", ("Ion",), r"\bion\s*shell\b", ("ion",)),
    ("Atuin (history database)", "esoteric", ("Atuin",), r"\batuin\b", ("atuin",)),
    ("History location (config)", "config", ("History-Location",), "", ()),
    ("History policy (config)", "config", ("History-Policy",), "", ()),
    ("Language REPLs", "repls", ("REPL",), "", ()),
    (
        "Explorer MRU (legacy)",
        "legacy-explorer",
        (
            "RunMRU",
            "TypedPaths",
            "ComDlg32-OpenSave",
            "ComDlg32-LastVisited",
            "ComDlg32-CIDSize",
            "WordWheelQuery",
        ),
        BUILTIN_INSTALL,
        (),
    ),
]

# Presence vocabulary (closed set, so the column can be parsed downstream)
PRESENCE_PRESENT = "Present"
PRESENCE_ABSENT = "None detected"
PRESENCE_NOT_CHECKED = "Not checked"
PRESENCE_VOLATILE = "Volatile - not persisted"
# A path existed but could not be read. NOT the same as absence.
PRESENCE_UNANSWERED = "Unreadable - not answered"

INSTALLED_CAVEAT = (
    "Installed (LEAD, not fact) = an installation record: registry (HKLM/HKCU Uninstall,\n"
    "WOW6432Node, MSI InstallProperties) or a package manager (scoop, winget, chocolatey,\n"
    "cargo, pip/conda). Package-manager entries are additionally marked installed / remnant /\n"
    "ambiguous from what the directory actually contains.\n"
    "TREAT THE DATES AS LEADS. Install dates and file MTIMEs shift with servicing stacks and\n"
    "updates and are trivially settable; confirming one requires a Volume Shadow Copy or\n"
    "windows.old differential, which this tool does not acquire.\n"
    "A dash is NOT proof the software was never installed: a clean uninstall usually removes\n"
    "the Uninstall key, and portable or extracted builds register nothing anywhere.\n"
    "Registry sources need live access and stay blank against an offline hive or off-Windows."
)

REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(password\s*[=:]\s*)(\S+)"), r"\1***REDACTED***"),
    (re.compile(r"(?i)(-p(?:assword)?\s+)(\S+)"), r"\1***REDACTED***"),
    (re.compile(r"(?i)(convertto-securestring\s+)(\S+)"), r"\1***REDACTED***"),
    (re.compile(r"(?i)(bearer\s+)([a-z0-9._\-+=/]+)"), r"\1***REDACTED***"),
    (re.compile(r"(AKIA[0-9A-Z]{16})"), "***REDACTED_AWS_KEY***"),
    (re.compile(r"(?i)(aws_secret_access_key\s*[=:]\s*)(\S+)"), r"\1***REDACTED***"),
    (re.compile(r"(?i)(net\s+use\s+\S+\s+/user:\S+\s+)(\S+)"), r"\1***REDACTED***"),
    (re.compile(r"(?i)(/user:\S+\s+)(\S+)$"), r"\1***REDACTED***"),
]


# ===========================================================================
# Data model
# ===========================================================================
@dataclass
class IntentRow:
    source: str
    user: str
    sid: str
    profile_path: str
    value_name: str
    typed_value: str
    raw_value: str
    mru_pos: Optional[int]
    utc_timestamp: str
    timestamp_provenance: str
    collected_utc: str
    key_lastwrite_utc: str
    extra: str
    local_timestamp: str = ""
    # v1.1 additions - appended so existing v1 JSON/CSV consumers keep working.
    shell: str = ""
    distro: str = ""
    artifact: str = ""

    def as_export(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SourceBlock:
    name: str
    rows: list[IntentRow] = field(default_factory=list)
    header_meta: dict[str, Any] = field(default_factory=dict)
    checked: bool = True
    empty_reason: str = ""


@dataclass
class CollectionError:
    scope: str
    message: str


@dataclass
class UserContext:
    user: str
    sid: str
    profile_path: str
    appdata: str
    localappdata: str
    live_root: Any = None  # Windows live key handle factory
    hive_view: Optional["HiveView"] = None
    privilege: str = "unknown"


# ===========================================================================
# Time helpers
# ===========================================================================
def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_utc(ts: Optional[dt.datetime]) -> str:
    if ts is None:
        return ""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    else:
        ts = ts.astimezone(dt.timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def to_local_iso(utc_iso: str) -> str:
    if not utc_iso:
        return ""
    try:
        ts = dt.datetime.strptime(utc_iso, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
        return ts.astimezone().isoformat(timespec="seconds")
    except ValueError:
        return ""


def filetime_to_dt(low: int, high: int) -> Optional[dt.datetime]:
    value = (int(high) << 32) | int(low)
    if value == 0:
        return None
    try:
        # FILETIME: 100-ns intervals since 1601-01-01 UTC
        epoch = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
        return epoch + dt.timedelta(microseconds=value / 10)
    except OverflowError:
        return None


def unix_to_dt(epoch: int | float) -> Optional[dt.datetime]:
    try:
        return dt.datetime.fromtimestamp(float(epoch), tz=dt.timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def file_times(path: Path) -> dict[str, str]:
    out = {"mtime_utc": "", "ctime_utc": "", "atime_utc": ""}
    try:
        st = path.stat()
        out["mtime_utc"] = iso_utc(dt.datetime.fromtimestamp(st.st_mtime, tz=dt.timezone.utc))
        out["ctime_utc"] = iso_utc(dt.datetime.fromtimestamp(st.st_ctime, tz=dt.timezone.utc))
        out["atime_utc"] = iso_utc(dt.datetime.fromtimestamp(st.st_atime, tz=dt.timezone.utc))
    except OSError as exc:
        out["stat_error"] = str(exc)
    return out


# ===========================================================================
# Redaction
# ===========================================================================
def redact_text(text: str) -> str:
    out = text
    for pat, repl in REDACT_PATTERNS:
        out = pat.sub(repl, out)
    return out


def maybe_redact(text: str, enabled: bool) -> str:
    return redact_text(text) if enabled else text


# ===========================================================================
# Windows live registry (optional)
# ===========================================================================
try:
    import winreg  # type: ignore
except ImportError:
    winreg = None  # type: ignore


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


def _advapi32() -> Optional[Any]:
    if os.name != "nt":
        return None
    try:
        return ctypes.WinDLL("advapi32", use_last_error=True)
    except OSError:
        return None


def _shell32() -> Optional[Any]:
    if os.name != "nt":
        return None
    try:
        return ctypes.WinDLL("shell32", use_last_error=True)
    except OSError:
        return None


def live_key_lastwrite(hkey: Any) -> Optional[dt.datetime]:
    """RegQueryInfoKey last-write; winreg itself does not expose this."""
    adv = _advapi32()
    if adv is None:
        return None
    try:
        handle = int(hkey.handle) if hasattr(hkey, "handle") else int(hkey)
    except (TypeError, ValueError, AttributeError):
        return None
    adv.RegQueryInfoKeyW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(FILETIME),
    ]
    adv.RegQueryInfoKeyW.restype = ctypes.c_long
    ft = FILETIME()
    status = adv.RegQueryInfoKeyW(
        handle,
        None,
        None,
        None,
        ctypes.byref(ctypes.c_uint32()),
        ctypes.byref(ctypes.c_uint32()),
        ctypes.byref(ctypes.c_uint32()),
        ctypes.byref(ctypes.c_uint32()),
        ctypes.byref(ctypes.c_uint32()),
        ctypes.byref(ctypes.c_uint32()),
        ctypes.byref(ctypes.c_uint32()),
        ctypes.byref(ft),
    )
    if status != 0:
        return None
    return filetime_to_dt(ft.dwLowDateTime, ft.dwHighDateTime)


def is_admin() -> Optional[bool]:
    if os.name != "nt":
        return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return None


def lookup_account_sid(sid: str) -> str:
    if os.name != "nt" or not sid:
        return ""
    try:
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        ConvertStringSidToSid = adv.ConvertStringSidToSidW
        ConvertStringSidToSid.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
        ConvertStringSidToSid.restype = ctypes.c_int
        LookupAccountSidW = adv.LookupAccountSidW
        psid = ctypes.c_void_p()
        if not ConvertStringSidToSid(sid, ctypes.byref(psid)):
            return ""
        name = ctypes.create_unicode_buffer(256)
        domain = ctypes.create_unicode_buffer(256)
        name_sz = ctypes.c_uint32(256)
        domain_sz = ctypes.c_uint32(256)
        use = ctypes.c_uint32()
        ok = LookupAccountSidW(
            None, psid, name, ctypes.byref(name_sz), domain, ctypes.byref(domain_sz), ctypes.byref(use)
        )
        ctypes.windll.kernel32.LocalFree(psid)
        if ok:
            return name.value
    except Exception:
        return ""
    return ""


# ===========================================================================
# Hive view abstraction (live winreg / RegLoadAppKey / python-registry / mock)
# ===========================================================================
@dataclass
class RegValue:
    name: str
    data: Any
    vtype: int  # 1=SZ, 2=EXPAND_SZ, 3=BINARY, 4=DWORD, 7=MULTI_SZ, 11=QWORD


@dataclass
class RegKeySnap:
    path: str
    last_write: Optional[dt.datetime]
    values: dict[str, RegValue]
    subkeys: list[str]


class HiveView:
    """Read-only view of a user hive rooted at the NTUSER equivalent of HKCU."""

    def open_key(self, relative_path: str) -> Optional[RegKeySnap]:
        raise NotImplementedError

    def open_subkey(self, relative_path: str, sub: str) -> Optional[RegKeySnap]:
        child = f"{relative_path}\\{sub}" if relative_path else sub
        return self.open_key(child)

    def close(self) -> None:
        return None


def _norm_rel(path: str) -> str:
    return path.strip("\\")


class LiveHiveView(HiveView):
    """HKCU or HKU\\SID via winreg."""

    def __init__(self, root: Any):
        self.root = root

    def open_key(self, relative_path: str) -> Optional[RegKeySnap]:
        if winreg is None:
            return None
        rel = _norm_rel(relative_path)
        try:
            key = winreg.OpenKey(self.root, rel) if rel else self.root
        except OSError:
            return None
        try:
            last = live_key_lastwrite(key)
            values: dict[str, RegValue] = {}
            i = 0
            while True:
                try:
                    name, data, vtype = winreg.EnumValue(key, i)
                except OSError:
                    break
                values[name] = RegValue(name=name, data=data, vtype=vtype)
                i += 1
            subkeys: list[str] = []
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
            return RegKeySnap(path=rel, last_write=last, values=values, subkeys=subkeys)
        finally:
            try:
                if rel:
                    winreg.CloseKey(key)
            except Exception:
                pass


class AppKeyHiveView(HiveView):
    """Private hive loaded with RegLoadAppKeyW (no admin required; fails if locked)."""

    def __init__(self, hive_path: str):
        self.hive_path = hive_path
        self._hkey = None
        self._loaded = False
        adv = _advapi32()
        if adv is None:
            raise OSError("advapi32 unavailable")
        handle = ctypes.c_void_p()
        adv.RegLoadAppKeyW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        adv.RegLoadAppKeyW.restype = ctypes.c_long
        KEY_READ = 0x20019
        status = adv.RegLoadAppKeyW(hive_path, ctypes.byref(handle), KEY_READ, 0, 0)
        if status != 0:
            raise OSError(f"RegLoadAppKeyW failed status={status} path={hive_path}")
        self._hkey = handle
        self._loaded = True

    def _open_rel(self, relative_path: str) -> Optional[Any]:
        if winreg is None or self._hkey is None:
            return None
        rel = _norm_rel(relative_path)
        # Wrap raw handle as PyHKEY via winreg by using OpenKey from a dummy?
        # winreg cannot wrap an arbitrary handle portably. Use advapi32 RegOpenKeyEx.
        adv = _advapi32()
        if adv is None:
            return None
        if not rel:
            return self._hkey
        result = ctypes.c_void_p()
        adv.RegOpenKeyExW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        adv.RegOpenKeyExW.restype = ctypes.c_long
        KEY_READ = 0x20019
        status = adv.RegOpenKeyExW(self._hkey, rel, 0, KEY_READ, ctypes.byref(result))
        if status != 0:
            return None
        return result

    def open_key(self, relative_path: str) -> Optional[RegKeySnap]:
        handle = self._open_rel(relative_path)
        if handle is None:
            return None
        adv = _advapi32()
        if adv is None:
            return None
        last = None
        try:
            # last write
            ft = FILETIME()
            adv.RegQueryInfoKeyW.restype = ctypes.c_long
            class_sz = ctypes.c_uint32(0)
            subkeys_c = ctypes.c_uint32()
            values_c = ctypes.c_uint32()
            status = adv.RegQueryInfoKeyW(
                handle.value if hasattr(handle, "value") else handle,
                None,
                ctypes.byref(class_sz) if False else None,
                None,
                ctypes.byref(subkeys_c),
                ctypes.byref(ctypes.c_uint32()),
                ctypes.byref(ctypes.c_uint32()),
                ctypes.byref(values_c),
                ctypes.byref(ctypes.c_uint32()),
                ctypes.byref(ctypes.c_uint32()),
                ctypes.byref(ctypes.c_uint32()),
                ctypes.byref(ft),
            )
            if status == 0:
                last = filetime_to_dt(ft.dwLowDateTime, ft.dwHighDateTime)
        except Exception:
            last = None

        values: dict[str, RegValue] = {}
        subkeys: list[str] = []
        try:
            adv.RegEnumValueW.restype = ctypes.c_long
            i = 0
            while True:
                name_buf = ctypes.create_unicode_buffer(16384)
                name_sz = ctypes.c_uint32(16384)
                vtype = ctypes.c_uint32()
                data_sz = ctypes.c_uint32(0)
                h = handle.value if hasattr(handle, "value") else handle
                # size probe
                st = adv.RegEnumValueW(
                    h,
                    i,
                    name_buf,
                    ctypes.byref(name_sz),
                    None,
                    ctypes.byref(vtype),
                    None,
                    ctypes.byref(data_sz),
                )
                if st == 259:  # ERROR_NO_MORE_ITEMS
                    break
                if st not in (0, 234):  # SUCCESS / MORE_DATA
                    break
                data_buf = (ctypes.c_ubyte * max(data_sz.value, 1))()
                name_sz = ctypes.c_uint32(16384)
                st = adv.RegEnumValueW(
                    h,
                    i,
                    name_buf,
                    ctypes.byref(name_sz),
                    None,
                    ctypes.byref(vtype),
                    ctypes.cast(data_buf, ctypes.POINTER(ctypes.c_ubyte)),
                    ctypes.byref(data_sz),
                )
                if st != 0:
                    i += 1
                    continue
                raw = bytes(data_buf[: data_sz.value])
                values[name_buf.value] = RegValue(
                    name=name_buf.value,
                    data=_decode_reg_bytes(vtype.value, raw),
                    vtype=vtype.value,
                )
                i += 1
            adv.RegEnumKeyExW.restype = ctypes.c_long
            i = 0
            while True:
                name_buf = ctypes.create_unicode_buffer(256)
                name_sz = ctypes.c_uint32(256)
                h = handle.value if hasattr(handle, "value") else handle
                st = adv.RegEnumKeyExW(h, i, name_buf, ctypes.byref(name_sz), None, None, None, None)
                if st != 0:
                    break
                subkeys.append(name_buf.value)
                i += 1
        finally:
            rel = _norm_rel(relative_path)
            if rel and adv is not None:
                try:
                    adv.RegCloseKey(handle.value if hasattr(handle, "value") else handle)
                except Exception:
                    pass
        return RegKeySnap(path=_norm_rel(relative_path), last_write=last, values=values, subkeys=subkeys)

    def close(self) -> None:
        adv = _advapi32()
        if adv is not None and self._hkey is not None:
            try:
                adv.RegCloseKey(self._hkey)
            except Exception:
                pass
        self._hkey = None


def _decode_reg_bytes(vtype: int, raw: bytes) -> Any:
    if vtype in (1, 2):  # SZ, EXPAND_SZ
        try:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            return raw
    if vtype == 4 and len(raw) >= 4:
        return struct.unpack("<I", raw[:4])[0]
    if vtype == 11 and len(raw) >= 8:
        return struct.unpack("<Q", raw[:8])[0]
    if vtype == 7:
        try:
            text = raw.decode("utf-16-le", errors="replace")
            return [p for p in text.split("\x00") if p]
        except Exception:
            return raw
    return raw


class PythonRegistryHiveView(HiveView):
    """Offline NTUSER.DAT via python-registry (optional dependency)."""

    def __init__(self, hive_path: str):
        try:
            from Registry import Registry as _Registry  # type: ignore
        except ImportError as exc:
            raise OSError("python-registry is not installed") from exc
        self._reg = _Registry.Registry(hive_path)

    def open_key(self, relative_path: str) -> Optional[RegKeySnap]:
        rel = _norm_rel(relative_path)
        try:
            key = self._reg.open(rel) if rel else self._reg.root()
        except Exception:
            return None
        last = None
        try:
            ts = key.timestamp()
            if ts.tzinfo is None:
                last = ts.replace(tzinfo=dt.timezone.utc)
            else:
                last = ts.astimezone(dt.timezone.utc)
        except Exception:
            last = None
        values: dict[str, RegValue] = {}
        for v in key.values():
            try:
                values[v.name()] = RegValue(name=v.name(), data=v.value(), vtype=int(v.value_type()))
            except Exception:
                try:
                    values[v.name()] = RegValue(name=v.name(), data=v.raw_data(), vtype=3)
                except Exception:
                    continue
        subkeys = []
        try:
            subkeys = [s.name() for s in key.subkeys()]
        except Exception:
            pass
        return RegKeySnap(path=rel, last_write=last, values=values, subkeys=subkeys)


class DictHiveView(HiveView):
    """In-memory hive for --selftest."""

    def __init__(self, tree: dict[str, Any]):
        # tree[path] = {"last_write": datetime|None, "values": {name: (data, type)}, "subkeys": []}
        self.tree = tree

    def open_key(self, relative_path: str) -> Optional[RegKeySnap]:
        rel = _norm_rel(relative_path)
        node = self.tree.get(rel)
        if node is None:
            return None
        values = {
            n: RegValue(name=n, data=d, vtype=t) for n, (d, t) in node.get("values", {}).items()
        }
        return RegKeySnap(
            path=rel,
            last_write=node.get("last_write"),
            values=values,
            subkeys=list(node.get("subkeys", [])),
        )


def open_offline_hive(hive_path: str) -> HiveView:
    errors: list[str] = []
    if os.name == "nt":
        try:
            return AppKeyHiveView(hive_path)
        except OSError as exc:
            errors.append(str(exc))
    try:
        return PythonRegistryHiveView(hive_path)
    except OSError as exc:
        errors.append(str(exc))
    raise OSError("Unable to open hive {0}: {1}".format(hive_path, " | ".join(errors)))


# ===========================================================================
# PIDL / shell-item decode
# ===========================================================================
def sh_get_path_from_idlist(pidl_bytes: bytes) -> Optional[str]:
    shell = _shell32()
    if shell is None or not pidl_bytes:
        return None
    # ITEMIDLIST must be double-null terminated (cb == 0)
    blob = pidl_bytes if pidl_bytes.endswith(b"\x00\x00") else pidl_bytes + b"\x00\x00"
    buf = ctypes.create_string_buffer(blob)
    out = ctypes.create_unicode_buffer(520)
    try:
        shell.SHGetPathFromIDListW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        shell.SHGetPathFromIDListW.restype = ctypes.c_int
        ok = shell.SHGetPathFromIDListW(ctypes.addressof(buf), out)
        if ok and out.value:
            return out.value
    except Exception:
        return None
    return None


def _utf16_strings(data: bytes, min_chars: int = 2) -> list[str]:
    found: list[str] = []
    i = 0
    n = len(data)
    while i + 4 <= n:
        if data[i + 1:i + 2] == b"\x00" and 32 <= data[i] < 127:
            chars: list[str] = []
            j = i
            while j + 2 <= n:
                lo, hi = data[j], data[j + 1]
                if lo == 0 and hi == 0:
                    break
                if hi != 0 or lo < 32:
                    chars = []
                    break
                chars.append(chr(lo))
                j += 2
            if len(chars) >= min_chars:
                found.append("".join(chars))
                i = j + 2
                continue
        i += 1
    return found


def _ascii_strings(data: bytes, min_chars: int = 3) -> list[str]:
    found: list[str] = []
    cur: list[str] = []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_chars:
                found.append("".join(cur))
            cur = []
    if len(cur) >= min_chars:
        found.append("".join(cur))
    return found


def walk_shell_items(data: bytes) -> list[bytes]:
    items: list[bytes] = []
    index = 0
    n = len(data)
    while index + 2 <= n:
        size = struct.unpack_from("<H", data, index)[0]
        if size == 0:
            break
        if size < 2 or index + size > n:
            break
        items.append(data[index : index + size])
        index += size
    return items


def fallback_pidl_path(data: bytes) -> str:
    """Best-effort reconstruction from UTF-16 / ASCII names inside shell items."""
    names: list[str] = []
    items = walk_shell_items(data)
    scan = items if items else [data]
    junk = {
        "",
        ".",
        "..",
        "desktop",
        "desktop.ini",
    }
    for item in scan:
        u16 = _utf16_strings(item, min_chars=1)
        picked = ""
        for cand in reversed(u16):
            low = cand.lower()
            if low in junk:
                continue
            if cand.startswith("{") and cand.endswith("}"):
                continue
            picked = cand
            break
        if not picked:
            for cand in _ascii_strings(item, min_chars=2):
                if cand.lower() in junk or cand.startswith("SH"):
                    continue
                picked = cand
                break
        if picked:
            names.append(picked)
    if not names:
        u16 = _utf16_strings(data, min_chars=2)
        names = [s for s in u16 if s.lower() not in junk][:8]
    for cand in _utf16_strings(data, min_chars=3):
        if cand.lower() in junk or cand.startswith("{"):
            continue
        if cand not in names:
            names.append(cand)
    # Drive letters often appear as 'C:'
    path = ""
    for part in names:
        if re.match(r"^[A-Za-z]:$", part) or re.match(r"^[A-Za-z]:\\$", part):
            path = part.rstrip("\\") + "\\"
        elif part.startswith("\\\\"):
            path = part
        elif path.endswith("\\") or path == "":
            path = (path + part) if path.endswith("\\") or not path else path + "\\" + part
        else:
            path = path + "\\" + part
    return path


def split_lastvisited_blob(data: bytes) -> tuple[str, bytes]:
    """LastVisitedPidlMRU: UTF-16 exe name, then PIDL."""
    exe = ""
    if isinstance(data, str):
        return data, b""
    # find first UTF-16 NUL
    i = 0
    chars: list[str] = []
    while i + 2 <= len(data):
        lo, hi = data[i], data[i + 1]
        if lo == 0 and hi == 0:
            i += 2
            break
        if hi == 0 and lo >= 32:
            chars.append(chr(lo))
            i += 2
            continue
        # not a clean string; abandon exe parse
        return "", data
    exe = "".join(chars)
    return exe, data[i:]


def _as_bytes(data: Any) -> bytes:
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-16-le", errors="replace")
    if isinstance(data, int):
        return struct.pack("<I", data & 0xFFFFFFFF)
    return b""


def decode_pidl(data: Any) -> tuple[str, str]:
    """
    Returns (path_or_text, note).
    note includes DECODE_FAILED when nothing usable was recovered.
    """
    raw = _as_bytes(data)
    if not raw:
        if isinstance(data, str) and data:
            return data, "legacy_string"
        return "", "DECODE_FAILED empty"
    live = sh_get_path_from_idlist(raw)
    if live:
        return live, "SHGetPathFromIDListW"
    fb = fallback_pidl_path(raw)
    if fb:
        return fb, "shell_item_fallback"
    preview = raw[:24].hex()
    return f"DECODE_FAILED hex={preview}", "DECODE_FAILED"




def decode_utf16_reg(data: Any) -> str:
    if isinstance(data, str):
        return data.rstrip("\x00")
    raw = _as_bytes(data)
    if not raw:
        return ""
    # WordWheelQuery often stores UTF-16LE including trailing NUL
    try:
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return raw.decode("latin-1", errors="replace")


def parse_mrulistex(data: Any) -> list[int]:
    raw = _as_bytes(data)
    out: list[int] = []
    for i in range(0, len(raw) - 3, 4):
        val = struct.unpack_from("<I", raw, i)[0]
        if val == 0xFFFFFFFF:
            break
        out.append(val)
    return out


def hex_preview(data: Any, n: int = 16) -> str:
    raw = _as_bytes(data)
    if not raw and isinstance(data, str):
        return data[:40]
    return raw[:n].hex()


# ===========================================================================
# Value helpers
# ===========================================================================
def strip_runmru_suffix(value: str) -> tuple[str, str]:
    raw = value if isinstance(value, str) else str(value)
    cleaned = raw
    if cleaned.endswith("\\1"):
        cleaned = cleaned[:-2]
    elif cleaned.endswith("\x01"):
        cleaned = cleaned[:-1]
    return cleaned, raw


# ===========================================================================
# Source collectors
# ===========================================================================
def collect_runmru(ctx: UserContext, collected: str, redact: bool) -> SourceBlock:
    block = SourceBlock(name="RunMRU", header_meta={"registry_path": RUNMRU_PATH})
    snap = ctx.hive_view.open_key(RUNMRU_PATH) if ctx.hive_view else None
    if snap is None:
        block.empty_reason = "No artifacts found (key missing or unreadable)"
        return block
    block.header_meta["key_lastwrite_utc"] = iso_utc(snap.last_write)
    order = ""
    mru = snap.values.get("MRUList")
    if mru and isinstance(mru.data, str):
        order = mru.data
    else:
        order = "".join(sorted(k for k in snap.values if len(k) == 1))
    lastwrite = iso_utc(snap.last_write)
    for pos, letter in enumerate(order):
        val = snap.values.get(letter)
        if val is None:
            continue
        text = val.data if isinstance(val.data, str) else decode_utf16_reg(val.data)
        cleaned, raw = strip_runmru_suffix(text)
        is_first = pos == 0
        block.rows.append(
            IntentRow(
                source="RunMRU",
                user=ctx.user,
                sid=ctx.sid,
                profile_path=ctx.profile_path,
                value_name=letter,
                typed_value=maybe_redact(cleaned, redact),
                raw_value=maybe_redact(raw, redact),
                mru_pos=pos,
                utc_timestamp=lastwrite if is_first else "",
                timestamp_provenance=PROV_KEY_LASTWRITE_MR0 if is_first else PROV_MRU_NO_TIME,
                collected_utc=collected,
                key_lastwrite_utc=lastwrite,
                extra=f"value={letter}",
            )
        )
    if not block.rows:
        block.empty_reason = "No artifacts found (empty MRU)"
    return block


def collect_typedpaths(ctx: UserContext, collected: str, redact: bool) -> SourceBlock:
    block = SourceBlock(name="TypedPaths", header_meta={"registry_path": TYPEDPATHS_PATH})
    snap = ctx.hive_view.open_key(TYPEDPATHS_PATH) if ctx.hive_view else None
    if snap is None:
        block.empty_reason = "No artifacts found (key missing or unreadable)"
        return block
    lastwrite = iso_utc(snap.last_write)
    block.header_meta["key_lastwrite_utc"] = lastwrite
    url_keys = []
    for name in snap.values:
        m = re.fullmatch(r"url(\d+)", name, flags=re.I)
        if m:
            url_keys.append((int(m.group(1)), name))
    url_keys.sort(key=lambda x: x[0])  # url1 is most recent
    for pos, (_, name) in enumerate(url_keys):
        val = snap.values[name]
        text = val.data if isinstance(val.data, str) else decode_utf16_reg(val.data)
        is_first = pos == 0
        block.rows.append(
            IntentRow(
                source="TypedPaths",
                user=ctx.user,
                sid=ctx.sid,
                profile_path=ctx.profile_path,
                value_name=name,
                typed_value=maybe_redact(str(text), redact),
                raw_value=maybe_redact(str(text), redact),
                mru_pos=pos,
                utc_timestamp=lastwrite if is_first else "",
                timestamp_provenance=PROV_KEY_LASTWRITE_MR0 if is_first else PROV_MRU_NO_TIME,
                collected_utc=collected,
                key_lastwrite_utc=lastwrite,
                extra=f"value={name}",
            )
        )
    if not block.rows:
        block.empty_reason = "No artifacts found (empty TypedPaths)"
    return block


def _mru_order_from_snap(snap: RegKeySnap) -> list[str]:
    if "MRUListEx" in snap.values:
        idxs = parse_mrulistex(snap.values["MRUListEx"].data)
        return [str(i) for i in idxs]
    if "MRUList" in snap.values:
        data = snap.values["MRUList"].data
        if isinstance(data, str):
            return list(data)
    numeric = [k for k in snap.values if k.isdigit()]
    numeric.sort(key=lambda x: int(x))
    return numeric


def collect_comdlg32(ctx: UserContext, collected: str, redact: bool) -> list[SourceBlock]:
    blocks: list[SourceBlock] = []
    root = ctx.hive_view.open_key(COMDLG32_PATH) if ctx.hive_view else None
    if root is None:
        for name in ("ComDlg32-OpenSave", "ComDlg32-LastVisited", "ComDlg32-CIDSize"):
            blocks.append(
                SourceBlock(
                    name=name,
                    empty_reason="No artifacts found (ComDlg32 key missing or unreadable)",
                    header_meta={"registry_path": COMDLG32_PATH},
                )
            )
        return blocks

    # OpenSave (modern + legacy)
    open_block = SourceBlock(
        name="ComDlg32-OpenSave",
        header_meta={"registry_path": COMDLG32_PATH + r"\OpenSavePidlMRU"},
    )
    found_open = False
    for subname in ("OpenSavePidlMRU", "OpenSaveMRU"):
        parent = ctx.hive_view.open_key(f"{COMDLG32_PATH}\\{subname}") if ctx.hive_view else None
        if parent is None:
            continue
        found_open = True
        open_block.header_meta["key_variant"] = subname
        open_block.header_meta["key_lastwrite_utc"] = iso_utc(parent.last_write)
        ext_keys = [s for s in parent.subkeys]
        # also values directly under parent (rare)
        targets = ext_keys or [""]
        for ext in targets:
            snap = (
                ctx.hive_view.open_key(f"{COMDLG32_PATH}\\{subname}\\{ext}")
                if ext
                else parent
            )
            if snap is None:
                continue
            lastwrite = iso_utc(snap.last_write)
            order = _mru_order_from_snap(snap)
            for pos, vname in enumerate(order):
                val = snap.values.get(vname)
                if val is None:
                    continue
                if subname == "OpenSaveMRU" and isinstance(val.data, str):
                    path, note = val.data, "legacy_string"
                else:
                    path, note = decode_pidl(val.data)
                is_first = pos == 0
                open_block.rows.append(
                    IntentRow(
                        source="ComDlg32-OpenSave",
                        user=ctx.user,
                        sid=ctx.sid,
                        profile_path=ctx.profile_path,
                        value_name=vname,
                        typed_value=maybe_redact(path, redact),
                        raw_value=hex_preview(val.data),
                        mru_pos=pos,
                        utc_timestamp=lastwrite if is_first else "",
                        timestamp_provenance=PROV_KEY_LASTWRITE_MR0 if is_first else PROV_MRU_NO_TIME,
                        collected_utc=collected,
                        key_lastwrite_utc=lastwrite,
                        extra=f"ext={ext or '*'}; {note}; value={vname}",
                    )
                )
    if not found_open:
        open_block.empty_reason = "No artifacts found (OpenSavePidlMRU/OpenSaveMRU missing)"
    elif not open_block.rows:
        open_block.empty_reason = "No artifacts found (empty OpenSave MRU)"
    blocks.append(open_block)

    # LastVisited
    lv_block = SourceBlock(
        name="ComDlg32-LastVisited",
        header_meta={"registry_path": COMDLG32_PATH + r"\LastVisitedPidlMRU"},
    )
    found_lv = False
    for subname in ("LastVisitedPidlMRU", "LastVisitedMRU", "LastVisitedPidlMRULegacy"):
        snap = ctx.hive_view.open_key(f"{COMDLG32_PATH}\\{subname}") if ctx.hive_view else None
        if snap is None:
            continue
        found_lv = True
        lv_block.header_meta["key_variant"] = subname
        lastwrite = iso_utc(snap.last_write)
        lv_block.header_meta["key_lastwrite_utc"] = lastwrite
        order = _mru_order_from_snap(snap)
        for pos, vname in enumerate(order):
            val = snap.values.get(vname)
            if val is None:
                continue
            raw = _as_bytes(val.data)
            if subname == "LastVisitedMRU" and isinstance(val.data, str):
                exe, path, note = val.data, "", "legacy_string"
            else:
                exe, pidl = split_lastvisited_blob(raw)
                path, note = decode_pidl(pidl if pidl else raw)
            is_first = pos == 0
            typed = path if path and not path.startswith("DECODE_FAILED") else (exe or path)
            extra_bits = [f"exe={exe}" if exe else "", note, f"value={vname}"]
            lv_block.rows.append(
                IntentRow(
                    source="ComDlg32-LastVisited",
                    user=ctx.user,
                    sid=ctx.sid,
                    profile_path=ctx.profile_path,
                    value_name=vname,
                    typed_value=maybe_redact(typed, redact),
                    raw_value=hex_preview(val.data),
                    mru_pos=pos,
                    utc_timestamp=lastwrite if is_first else "",
                    timestamp_provenance=PROV_KEY_LASTWRITE_MR0 if is_first else PROV_MRU_NO_TIME,
                    collected_utc=collected,
                    key_lastwrite_utc=lastwrite,
                    extra="; ".join(b for b in extra_bits if b),
                )
            )
    if not found_lv:
        lv_block.empty_reason = "No artifacts found (LastVisitedPidlMRU missing)"
    elif not lv_block.rows:
        lv_block.empty_reason = "No artifacts found (empty LastVisited MRU)"
    blocks.append(lv_block)

    # CIDSizeMRU
    cid = SourceBlock(
        name="ComDlg32-CIDSize",
        header_meta={"registry_path": COMDLG32_PATH + r"\CIDSizeMRU"},
    )
    snap = ctx.hive_view.open_key(f"{COMDLG32_PATH}\\CIDSizeMRU") if ctx.hive_view else None
    if snap is None:
        cid.empty_reason = "No artifacts found (CIDSizeMRU missing)"
    else:
        lastwrite = iso_utc(snap.last_write)
        cid.header_meta["key_lastwrite_utc"] = lastwrite
        order = _mru_order_from_snap(snap)
        for pos, vname in enumerate(order):
            val = snap.values.get(vname)
            if val is None:
                continue
            raw = _as_bytes(val.data)
            exe, _rest = split_lastvisited_blob(raw)
            if not exe:
                exe = decode_utf16_reg(val.data)
            is_first = pos == 0
            cid.rows.append(
                IntentRow(
                    source="ComDlg32-CIDSize",
                    user=ctx.user,
                    sid=ctx.sid,
                    profile_path=ctx.profile_path,
                    value_name=vname,
                    typed_value=maybe_redact(exe, redact),
                    raw_value=hex_preview(val.data),
                    mru_pos=pos,
                    utc_timestamp=lastwrite if is_first else "",
                    timestamp_provenance=PROV_KEY_LASTWRITE_MR0 if is_first else PROV_MRU_NO_TIME,
                    collected_utc=collected,
                    key_lastwrite_utc=lastwrite,
                    extra=f"value={vname}",
                )
            )
        if not cid.rows:
            cid.empty_reason = "No artifacts found (empty CIDSizeMRU)"
    blocks.append(cid)
    return blocks


def collect_wordwheel(ctx: UserContext, collected: str, redact: bool) -> SourceBlock:
    block = SourceBlock(name="WordWheelQuery", header_meta={"registry_path": WORDWHEEL_PATH})
    snap = ctx.hive_view.open_key(WORDWHEEL_PATH) if ctx.hive_view else None
    if snap is None:
        block.empty_reason = "No artifacts found (key missing or unreadable)"
        return block
    lastwrite = iso_utc(snap.last_write)
    block.header_meta["key_lastwrite_utc"] = lastwrite
    order = _mru_order_from_snap(snap)
    if not order:
        order = [n for n in snap.values if n not in ("MRUListEx", "MRUList")]
    for pos, vname in enumerate(order):
        val = snap.values.get(vname)
        if val is None:
            continue
        text = decode_utf16_reg(val.data)
        is_first = pos == 0
        block.rows.append(
            IntentRow(
                source="WordWheelQuery",
                user=ctx.user,
                sid=ctx.sid,
                profile_path=ctx.profile_path,
                value_name=str(vname),
                typed_value=maybe_redact(text, redact),
                raw_value=hex_preview(val.data),
                mru_pos=pos,
                utc_timestamp=lastwrite if is_first else "",
                timestamp_provenance=PROV_KEY_LASTWRITE_MR0 if is_first else PROV_MRU_NO_TIME,
                collected_utc=collected,
                key_lastwrite_utc=lastwrite,
                extra=f"value={vname}",
            )
        )
    if not block.rows:
        block.empty_reason = "No artifacts found (empty WordWheelQuery)"
    return block


# ----- PowerShell history -----
PS_HISTORY_DIR_REL = Path("Microsoft") / "Windows" / "PowerShell" / "PSReadLine"

HOST_LABELS = {
    "consolehost_history.txt": "Powershell",
    "visual studio code host_history.txt": "Powershell-VSCodeHost",
    "windows powershell ise host_history.txt": "Powershell-ISE",
    "windows terminal_history.txt": "Powershell-WindowsTerminal",
}


def ps_source_name(filename: str) -> str:
    low = filename.lower()
    if low in HOST_LABELS:
        return HOST_LABELS[low]
    if "vscode" in low or "visual studio code" in low:
        return "Powershell-VSCodeHost"
    if "ise" in low:
        return "Powershell-ISE"
    if "pwsh" in low:
        return "Powershell-Pwsh"
    if "terminal" in low:
        return "Powershell-WindowsTerminal"
    stem = Path(filename).stem
    return f"Powershell-{stem}"


# Largest artifact this tool will read into memory. Enforced inside
# read_text_guess so every caller inherits it.
MAX_HISTORY_BYTES = 32 * 1024 * 1024


def read_text_guess(path: Path, max_bytes: int = MAX_HISTORY_BYTES) -> tuple[str, str]:
    """Read a text artifact, guessing its encoding.

    The size cap lives here rather than only at the call sites. Several
    callers guarded it and several did not - the diagnostics probe would
    happily slurp a multi-gigabyte history file to look at its first twelve
    lines. Reading is capped, not refused, so an oversized artifact still
    yields what fits instead of nothing at all.
    """
    with path.open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    truncated = len(raw) > max_bytes
    if truncated:
        raw = raw[:max_bytes]
    for enc in ("utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            return raw.decode(enc), (enc + "+truncated" if truncated else enc)
        except UnicodeDecodeError:
            continue
    decoded = raw.decode("latin-1", errors="replace")
    return decoded, ("latin-1+truncated" if truncated else "latin-1")


def coalesce_backtick_lines(lines: list[str]) -> list[str]:
    out: list[str] = []
    buf = ""
    for line in lines:
        stripped = line.rstrip("\r\n")
        if stripped.endswith("`"):
            buf += stripped[:-1] + "\n"
            continue
        if buf:
            out.append(buf + stripped)
            buf = ""
        else:
            out.append(stripped)
    if buf:
        out.append(buf)
    return out


def collect_powershell_for_user(ctx: UserContext, collected: str, redact: bool) -> list[SourceBlock]:
    blocks: list[SourceBlock] = []
    seen_files: set[str] = set()
    candidates: list[Path] = []
    if ctx.appdata:
        candidates.append(Path(ctx.appdata) / PS_HISTORY_DIR_REL)
    # PowerShell 7 sometimes uses the same roaming path; also check documents/local
    if ctx.localappdata:
        candidates.append(Path(ctx.localappdata) / PS_HISTORY_DIR_REL)
    if ctx.profile_path:
        candidates.append(
            Path(ctx.profile_path) / "AppData" / "Roaming" / PS_HISTORY_DIR_REL
        )

    files: list[Path] = []
    for folder in candidates:
        try:
            if folder.is_dir():
                for p in sorted(folder.iterdir()):
                    if p.is_file() and "history" in p.name.lower():
                        key = str(p.resolve()) if p.exists() else str(p)
                        if key not in seen_files:
                            seen_files.add(key)
                            files.append(p)
        except OSError as exc:
            blocks.append(
                SourceBlock(
                    name="Powershell",
                    empty_reason=f"Unreadable directory {folder}: {exc}",
                )
            )

    if not files:
        blocks.append(
            SourceBlock(
                name="Powershell",
                empty_reason="No artifacts found (no PSReadLine history files)",
                header_meta={"search_roots": [str(c) for c in candidates]},
            )
        )
        return blocks

    for path in files:
        name = ps_source_name(path.name)
        meta = {"path": str(path)}
        meta.update(file_times(path))
        block = SourceBlock(name=name, header_meta=meta)
        try:
            text, enc = read_text_guess(path)
            block.header_meta["encoding"] = enc
        except OSError as exc:
            block.empty_reason = f"Unreadable file: {exc}"
            blocks.append(block)
            continue
        raw_lines = text.splitlines()
        commands = [c for c in coalesce_backtick_lines(raw_lines) if c.strip() != ""]
        last_idx = len(commands) - 1
        mtime = block.header_meta.get("mtime_utc", "")
        for i, cmd in enumerate(commands):
            is_last = i == last_idx
            # file order is oldest-first; display most-recent first later
            block.rows.append(
                IntentRow(
                    source=name,
                    user=ctx.user,
                    sid=ctx.sid,
                    profile_path=ctx.profile_path,
                    value_name=str(i + 1),
                    typed_value=maybe_redact(cmd, redact),
                    raw_value=maybe_redact(cmd, redact),
                    mru_pos=last_idx - i,  # 0 = most recent after we reverse
                    utc_timestamp=mtime if is_last else "",
                    timestamp_provenance=PROV_FILE_MTIME_LAST if is_last else PROV_ORDER_ONLY,
                    collected_utc=collected,
                    key_lastwrite_utc="",
                    extra=f"file_index={i + 1}; encoding={enc}",
                    shell="powershell",
                    artifact=str(path),
                )
            )
        # Present most recent first
        block.rows.reverse()
        for pos, row in enumerate(block.rows):
            row.mru_pos = pos
        if not block.rows:
            block.empty_reason = "No artifacts found (empty history file)"
        blocks.append(block)
    return blocks


# ===========================================================================
# Shared history parsing (one reader for every readline-format shell)
# ===========================================================================

SHELL_LABELS = {
    "bash": "Bash",
    "sh": "Sh",
    "ash": "Ash",
    "zsh": "Zsh",
    "fish": "Fish",
    "nushell": "Nushell",
    "xonsh": "Xonsh",
    "elvish": "Elvish",
    "oil": "Oil",
    "ion": "Ion",
}


@dataclass
class HistEntry:
    """One command recovered from a history file."""

    command: str
    ts: Optional[dt.datetime] = None
    prov: str = ""
    note: str = ""
    deleted: bool = False
    raw: str = ""


CLINK_CTAG_PREFIX = "|CTAG"


def parse_readline_history(
    text: str,
    epoch_prov: str = PROV_HISTTIME_EPOCH,
    tombstones: bool = False,
) -> list[HistEntry]:
    """GNU readline history: bash, ash, Clink, Cmder, oil.

    Handles the optional '# <unix_epoch>' comment that bash writes when
    HISTTIMEFORMAT is set and that Clink writes for its own entries. The
    comment applies to the command that FOLLOWS it. Backslash continuation
    joins into one entry.

    With tombstones=True (Clink family), two Clink-specific rules apply:
      * the leading '|CTAG' line is a file header, not a command;
      * a deleted entry is not removed, it is marked by OVERWRITING its
        first character with '|'. Those lines survive until Clink compacts
        the file, so they are recoverable deleted history. The original
        first character is destroyed by the overwrite and cannot be
        recovered, so it is reported as '?' rather than guessed.
    """
    entries: list[HistEntry] = []
    pending: Optional[dt.datetime] = None
    buf = ""
    for lineno, line in enumerate(text.splitlines()):
        if tombstones and lineno == 0 and line.startswith(CLINK_CTAG_PREFIX):
            continue
        if buf == "" and line.startswith("#") and re.fullmatch(r"#\s*\d{6,}(?:\.\d+)?", line.strip()):
            pending = unix_to_dt(float(line.strip().lstrip("#").strip()))
            continue
        if tombstones and line.startswith("|"):
            if line[1:].strip():
                entries.append(
                    HistEntry(
                        command="?" + line[1:],
                        ts=pending,
                        prov=epoch_prov if pending else "",
                        note="clink_deleted_entry; first_char_overwritten_by_tombstone",
                        deleted=True,
                        raw=line,
                    )
                )
            pending = None
            continue
        if line.endswith("\\") and not line.endswith("\\\\"):
            buf += line[:-1] + "\n"
            continue
        cmd = buf + line
        buf = ""
        if cmd.strip() == "":
            continue
        entries.append(HistEntry(command=cmd, ts=pending, prov=epoch_prov if pending else ""))
        pending = None
    if buf.strip():
        entries.append(HistEntry(command=buf, ts=pending, prov=epoch_prov if pending else ""))
    return entries


ZSH_EXTENDED_RE = re.compile(r"^:\s*(\d+):(\d+);(.*)$", re.DOTALL)


def parse_zsh_history(text: str) -> list[HistEntry]:
    """zsh: plain lines, or EXTENDED_HISTORY ': <epoch>:<elapsed>;<command>'."""
    entries: list[HistEntry] = []
    buf = ""
    for line in text.splitlines():
        if line.endswith("\\") and not line.endswith("\\\\"):
            buf += line[:-1] + "\n"
            continue
        raw = buf + line
        buf = ""
        if raw.strip() == "":
            continue
        m = ZSH_EXTENDED_RE.match(raw)
        if m:
            ts = unix_to_dt(int(m.group(1)))
            cmd = m.group(3)
            entries.append(
                HistEntry(
                    command=cmd,
                    ts=ts,
                    prov=PROV_HISTTIME_EPOCH if ts else "",
                    note=f"elapsed_s={m.group(2)}",
                )
            )
        else:
            entries.append(HistEntry(command=raw))
    if buf.strip():
        entries.append(HistEntry(command=buf))
    return entries


def parse_fish_history(text: str) -> list[HistEntry]:
    """fish_history is YAML-ish: '- cmd: ...' followed by '  when: <epoch>'."""
    entries: list[HistEntry] = []
    cur: Optional[HistEntry] = None
    for line in text.splitlines():
        if line.startswith("- cmd:"):
            if cur is not None:
                entries.append(cur)
            cur = HistEntry(command=line[len("- cmd:") :].strip())
            continue
        stripped = line.strip()
        if cur is not None and stripped.startswith("when:"):
            val = stripped[len("when:") :].strip()
            try:
                cur.ts = unix_to_dt(int(float(val)))
                cur.prov = PROV_HISTTIME_EPOCH if cur.ts else ""
            except ValueError:
                pass
            continue
        if cur is not None and (stripped.startswith("paths:") or stripped.startswith("- ")):
            continue
        if cur is None and stripped and not stripped.startswith("#"):
            # Not YAML-ish after all - treat as a plain line.
            entries.append(HistEntry(command=stripped))
    if cur is not None:
        entries.append(cur)
    return entries


def parse_plain_history(text: str) -> list[HistEntry]:
    return [HistEntry(command=ln) for ln in text.splitlines() if ln.strip()]


def parse_xonsh_json(text: str) -> Optional[list[HistEntry]]:
    """xonsh JSON history: {'data': {'cmds': [{'inp': ..., 'ts': [start, end]}]}}."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return None
    cmds = None
    if isinstance(doc, dict):
        data = doc.get("data")
        if isinstance(data, dict):
            cmds = data.get("cmds")
        if cmds is None:
            cmds = doc.get("cmds")
    if not isinstance(cmds, list):
        return None
    entries: list[HistEntry] = []
    for item in cmds:
        if not isinstance(item, dict):
            continue
        inp = str(item.get("inp", "")).rstrip("\n")
        if not inp.strip():
            continue
        ts = None
        raw_ts = item.get("ts")
        if isinstance(raw_ts, list) and raw_ts:
            ts = unix_to_dt(raw_ts[0])
        entries.append(HistEntry(command=inp, ts=ts, prov=PROV_HISTTIME_EPOCH if ts else ""))
    return entries


PARSERS = {
    "readline": parse_readline_history,
    "zsh": parse_zsh_history,
    "fish": parse_fish_history,
    "plain": parse_plain_history,
}


def shell_from_filename(name: str) -> str:
    """Infer the shell from a history filename.

    Order matters: 'bash' must be tested before 'ash', because the string
    'ash' is a substring of 'bash'.
    """
    low = name.lower()
    for token, shell in (
        ("bash", "bash"),
        ("zsh", "zsh"),
        ("zhistory", "zsh"),
        ("fish", "fish"),
        ("ash", "ash"),
        ("sh_history", "sh"),
    ):
        if token in low:
            return shell
    return "bash"


def parser_for_shell(shell: str) -> str:
    if shell == "zsh":
        return "zsh"
    if shell == "fish":
        return "fish"
    if shell in {"bash", "sh", "ash", "oil", "cmd"}:
        return "readline"
    return "plain"


def entries_to_rows(
    entries: list[HistEntry],
    *,
    source: str,
    ctx: UserContext,
    collected: str,
    redact: bool,
    mtime_utc: str,
    shell: str,
    distro: str = "",
    value_name: str = "",
    extra_prefix: str = "",
    artifact: str = "",
) -> list[IntentRow]:
    """Apply the timestamp policy, then present most-recent-first.

    Only an entry the shell itself timestamped gets a per-command time. The
    final line of the file may carry file MTIME (last append). Everything
    else is order_only with an empty timestamp - never an invented one.
    """
    rows: list[IntentRow] = []
    last_idx = len(entries) - 1
    for i, ent in enumerate(entries):
        if ent.ts is not None:
            utc = iso_utc(ent.ts)
            prov = ent.prov or PROV_HISTTIME_EPOCH
        elif i == last_idx and mtime_utc:
            utc = mtime_utc
            prov = PROV_FILE_MTIME_LAST
        else:
            utc = ""
            prov = PROV_ORDER_ONLY
        bits = [b for b in (extra_prefix, f"file_index={i + 1}", ent.note) if b]
        if ent.deleted:
            bits.append("deleted_entry=1")
        rows.append(
            IntentRow(
                source=source,
                user=ctx.user,
                sid=ctx.sid,
                profile_path=ctx.profile_path,
                value_name=value_name or str(i + 1),
                typed_value=maybe_redact(ent.command, redact),
                raw_value=maybe_redact(ent.raw or ent.command, redact),
                mru_pos=None,
                utc_timestamp=utc,
                timestamp_provenance=prov,
                collected_utc=collected,
                key_lastwrite_utc="",
                extra="; ".join(bits),
                shell=shell,
                distro=distro,
                artifact=artifact,
            )
        )
    rows.reverse()  # file order is oldest-first; examiners read newest-first
    for pos, row in enumerate(rows):
        row.mru_pos = pos
    return rows


LINK_ESCAPE_NOTE = "link_target_outside_search_root"


def _has_reparse_point(path: Path) -> bool:
    """Windows junctions are not symlinks to pathlib; detect them separately."""
    if os.name != "nt":
        return False
    try:
        attrs = getattr(path.lstat(), "st_file_attributes", 0)
    except (OSError, AttributeError):
        return False
    return bool(attrs & getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def link_escapes_root(path: Path, root: Optional[Path]) -> Optional[str]:
    """Reason string if `path` resolves outside `root`, else None.

    An attacker who can write a user profile can replace a history file with a
    symlink or junction. Following it lets an elevated collector read any file
    the account can reach - and on Windows a link to \\\\attacker\\share
    triggers outbound SMB authentication, leaking the account's NTLM hash.

    Containment is judged against the root the artifact was DISCOVERED under,
    not against a blanket UNC ban: \\\\wsl$ and \\\\wsl.localhost are legitimate
    roots the WSL collector uses on purpose.

    Fails CLOSED. When no root is supplied the file's own parent directory is
    used, so a caller that forgets to pass one still gets protection: a link
    pointing elsewhere inside its own directory is allowed, a link escaping to
    /etc, another profile, or a UNC share is not.
    """
    if root is None:
        root = path.parent
    try:
        if not path.is_symlink() and not _has_reparse_point(path):
            return None
    except OSError:
        return None
    try:
        target = path.resolve(strict=False)
        base = root.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        return f"{LINK_ESCAPE_NOTE}: unresolvable ({exc})"
    try:
        target.relative_to(base)
    except ValueError:
        return f"{LINK_ESCAPE_NOTE}: {path} -> {target} (root {base})"
    return None




def probe_path(path: Path) -> tuple[str, str]:
    """Probe one candidate artifact path. Returns (outcome, detail).

    Turns "None detected" from an assertion into a demonstrated negative, and
    keeps apart three things the tool used to collapse:

      * the file was never there              -> path_absent
      * the file is there and holds nothing   -> present_but_empty
      * the file is there and could not be read -> the question is UNANSWERED

    A zero-byte .bash_history means something truncated or cleared it, which
    is the opposite claim from the file never existing. And a permission
    failure is never absence: it means nobody looked successfully.
    """
    try:
        if not path.exists():
            return ABSENCE_PATH_ABSENT, ""
    except PermissionError as exc:
        return ABSENCE_PERMISSION_DENIED, str(exc)
    except OSError as exc:
        return ABSENCE_PRESENT_UNREADABLE, str(exc)
    try:
        size = path.stat().st_size
    except PermissionError as exc:
        return ABSENCE_PERMISSION_DENIED, str(exc)
    except OSError as exc:
        return ABSENCE_PRESENT_UNREADABLE, str(exc)
    if size == 0:
        return ABSENCE_PRESENT_EMPTY, "zero bytes - truncated or cleared"
    try:
        with path.open("rb") as handle:
            handle.read(1)
    except PermissionError as exc:
        return ABSENCE_PERMISSION_DENIED, str(exc)
    except OSError as exc:
        return ABSENCE_PRESENT_UNREADABLE, str(exc)
    return ABSENCE_READ_OK, f"{size} bytes"


def record_probe(block: SourceBlock, path: Path) -> str:
    """Probe a path and file the outcome on the block. Returns the outcome."""
    outcome, detail = probe_path(path)
    entry = {"path": str(path), "outcome": outcome}
    if detail:
        entry["detail"] = detail
    block.header_meta.setdefault("probed_paths", []).append(entry)
    return outcome


def block_absence_summary(block: SourceBlock) -> dict[str, int]:
    """Count each probe outcome recorded on a block."""
    counts: dict[str, int] = {}
    for entry in block.header_meta.get("probed_paths", []) or []:
        if isinstance(entry, dict):
            outcome = entry.get("outcome", "")
            if outcome:
                counts[outcome] = counts.get(outcome, 0) + 1
    return counts


def rows_from_history_file(
    path: Path,
    *,
    source: str,
    shell: str,
    ctx: UserContext,
    collected: str,
    redact: bool,
    parser: Optional[str] = None,
    distro: str = "",
    epoch_prov: str = PROV_HISTTIME_EPOCH,
    tombstones: bool = False,
    search_root: Optional[Path] = None,
    text_override: Optional[str] = None,
    display_path: str = "",
) -> tuple[list[IntentRow], dict[str, Any]]:
    """Read one history file and turn it into rows. Never raises."""
    shown = display_path or str(path)
    meta: dict[str, Any] = {"path": shown, "shell": shell}
    if distro:
        meta["distro"] = distro
    text = text_override
    if text is None:
        escape = link_escapes_root(path, search_root)
        if escape is not None:
            # A planted link is itself a finding, so it is recorded, not
            # silently skipped - but its target is never read.
            meta["error"] = escape
            meta["rejected"] = LINK_ESCAPE_NOTE
            return [], meta
        try:
            size = path.stat().st_size
            meta["size_bytes"] = size
            if size > MAX_HISTORY_BYTES:
                meta["skipped"] = f"file larger than {MAX_HISTORY_BYTES} bytes"
                return [], meta
            text, enc = read_text_guess(path)
            meta["encoding"] = enc
        except OSError as exc:
            meta["error"] = str(exc)
            return [], meta
    times = file_times(path) if text_override is None else {}
    meta.update(times)
    kind = parser or parser_for_shell(shell)
    meta["parser"] = kind
    if kind == "readline":
        entries = parse_readline_history(text, epoch_prov=epoch_prov, tombstones=tombstones)
    else:
        entries = PARSERS[kind](text)
    rows = entries_to_rows(
        entries,
        source=source,
        ctx=ctx,
        collected=collected,
        redact=redact,
        mtime_utc=times.get("mtime_utc", ""),
        shell=shell,
        distro=distro,
        extra_prefix=f"path={shown}",
        artifact=shown,
    )
    meta["rows"] = len(rows)
    meta["timed_rows"] = sum(1 for r in rows if r.timestamp_provenance in EXACT_PROVENANCE)
    deleted = sum(1 for e in entries if e.deleted)
    if deleted:
        meta["recoverable_deleted_rows"] = deleted
    return rows, meta


def unparsed_row(
    path: Path,
    *,
    source: str,
    shell: str,
    ctx: UserContext,
    collected: str,
    reason: str = "present_unparsed",
) -> IntentRow:
    """Inventory a history store we can see but will not decode.

    Binary stores (SQLite, bolt) are recorded as present, never hex-dumped.
    """
    times = file_times(path)
    size = ""
    try:
        size = str(path.stat().st_size)
    except OSError:
        pass
    return IntentRow(
        source=source,
        user=ctx.user,
        sid=ctx.sid,
        profile_path=ctx.profile_path,
        value_name=path.name,
        typed_value=f"[{reason}] {path}",
        raw_value=str(path),
        mru_pos=None,
        utc_timestamp="",
        timestamp_provenance=PROV_UNAVAILABLE,
        collected_utc=collected,
        key_lastwrite_utc="",
        extra=f"reason={reason}; size_bytes={size}; mtime_utc={times.get('mtime_utc', '')}",
        shell=shell,
        artifact=str(path),
    )


# ----- CMD / Clink / WT / doskey -----
def system32_binary(name: str) -> str:
    """Absolute path to a Windows system binary, falling back to the bare name.

    Intention.py may be run on a host that is already compromised. Resolving
    'cmd.exe' or 'wsl.exe' through PATH would let an attacker-planted binary
    earlier in PATH execute instead. Prefer the known System32 location and
    only fall back to PATH resolution if it is genuinely absent.
    """
    system_root = os.environ.get("SystemRoot") or os.environ.get("windir")
    if system_root:
        candidate = Path(system_root) / "System32" / name
        try:
            if candidate.is_file():
                return str(candidate)
        except OSError:
            pass
    return name


def collect_live_doskey(ctx: UserContext, collected: str, redact: bool) -> SourceBlock:
    block = SourceBlock(name="CMD-LiveDoskey", header_meta={"method": "cmd.exe /c doskey /history"})
    if os.name != "nt":
        block.empty_reason = "Live doskey skipped (not Windows)"
        return block
    try:
        proc = subprocess.run(
            [system32_binary("cmd.exe"), "/c", "doskey /history"],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        block.empty_reason = f"doskey spawn failed: {exc}"
        return block
    text = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    lines = [ln.rstrip("\r") for ln in text.splitlines() if ln.strip()]
    # drop the collector invocation if it appears
    lines = [ln for ln in lines if not re.search(r"doskey\s+/history", ln, flags=re.I)]
    for i, ln in enumerate(lines):
        block.rows.append(
            IntentRow(
                source="CMD-LiveDoskey",
                user=ctx.user,
                sid=ctx.sid,
                profile_path=ctx.profile_path,
                value_name=str(i + 1),
                typed_value=maybe_redact(ln, redact),
                raw_value=maybe_redact(ln, redact),
                mru_pos=i,
                utc_timestamp=collected,
                timestamp_provenance=PROV_COLLECTION,
                collected_utc=collected,
                key_lastwrite_utc="",
                extra="live_session_only",
                shell="cmd",
            )
        )
    if not block.rows:
        block.empty_reason = "No artifacts found (empty live doskey buffer or no console history)"
    return block


def collect_clink(ctx: UserContext, collected: str, redact: bool) -> SourceBlock:
    block = SourceBlock(name="CMD-Clink")
    roots: list[Path] = []
    if ctx.localappdata:
        roots.append(Path(ctx.localappdata) / "clink")
    if ctx.appdata:
        roots.append(Path(ctx.appdata) / "clink")
    if ctx.profile_path:
        roots.append(Path(ctx.profile_path) / "AppData" / "Local" / "clink")
        roots.append(Path(ctx.profile_path) / "AppData" / "Roaming" / "clink")
    files: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        try:
            if not root.exists():
                continue
            for p in root.rglob("*"):
                if not p.is_file():
                    continue
                n = p.name.lower()
                if "history" in n or n in {".history", "clink_history"}:
                    key = str(p)
                    if key not in seen:
                        seen.add(key)
                        files.append(p)
        except OSError:
            continue
    block.header_meta["files"] = [str(f) for f in files]
    block.header_meta["format_note"] = (
        "Clink marks a deleted entry by overwriting its first character with '|' rather than "
        "removing the line; such rows are reported with deleted_entry=1 and a leading '?' for "
        "the destroyed character, and survive until 'clink history compact' runs"
    )
    block.header_meta["UNVERIFIED_timestamp_format"] = (
        "Clink timestamps are parsed on the ASSUMPTION that history.time_stamp writes "
        "readline-style '# <unix_epoch>' comment lines. Clink's documentation describes "
        "the setting but not the on-disk encoding, and no sample with timestamps enabled "
        "has been examined. Rows tagged clink_embedded_epoch therefore rest on an "
        "unverified format assumption; rows without it are unaffected."
    )
    block.header_meta["suppression_note"] = (
        "Clink's history.ignore_space defaults to on: a command typed with a leading space is "
        "never written to this file"
    )
    for path in files:
        rows, meta = rows_from_history_file(
            path,
            source="CMD-Clink",
            shell="cmd",
            parser="readline",
            ctx=ctx,
            collected=collected,
            redact=redact,
            epoch_prov=PROV_CLINK_EPOCH,
            tombstones=True,
        )
        block.rows.extend(rows)
        block.header_meta.setdefault("per_file", []).append(meta)
    if block.rows:
        for i, row in enumerate(block.rows):
            row.mru_pos = i
    else:
        block.empty_reason = "No artifacts found (no Clink history files)"
    return block


def collect_windows_terminal_history(ctx: UserContext, collected: str, redact: bool) -> SourceBlock:
    block = SourceBlock(name="CMD-WindowsTerminal")
    roots: list[Path] = []
    bases = []
    if ctx.localappdata:
        bases.append(Path(ctx.localappdata))
    if ctx.profile_path:
        bases.append(Path(ctx.profile_path) / "AppData" / "Local")
    for base in bases:
        roots.append(base / "Microsoft" / "Windows Terminal")
        pkg = base / "Packages"
        try:
            if pkg.is_dir():
                for child in pkg.iterdir():
                    if child.name.startswith("Microsoft.WindowsTerminal"):
                        roots.append(child / "LocalState")
        except OSError:
            pass
    files: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        try:
            if not root.exists():
                continue
            for p in root.rglob("*"):
                if p.is_file() and "history" in p.name.lower() and p.suffix.lower() in {
                    ".txt",
                    ".log",
                    "",
                    ".history",
                }:
                    if str(p) not in seen:
                        seen.add(str(p))
                        files.append(p)
        except OSError:
            continue
    block.header_meta["search_roots"] = [str(r) for r in roots]
    block.header_meta["files"] = [str(f) for f in files]
    for path in files:
        rows, meta = rows_from_history_file(
            path,
            source="CMD-WindowsTerminal",
            shell="cmd",
            parser="plain",
            ctx=ctx,
            collected=collected,
            redact=redact,
        )
        block.rows.extend(rows)
        block.header_meta.setdefault("per_file", []).append(meta)
    if block.rows:
        for i, row in enumerate(block.rows):
            row.mru_pos = i
    else:
        block.empty_reason = (
            "No artifacts found (Windows Terminal does not persist cmd.exe history by default)"
        )
    return block


def collect_cmder(ctx: UserContext, collected: str, redact: bool) -> SourceBlock:
    """Cmder keeps a Clink-format history at <CMDER_ROOT>\\config\\.history."""
    block = SourceBlock(name="CMD-Cmder")
    roots: list[Path] = []
    env_root = os.environ.get("CMDER_ROOT")
    if env_root:
        roots.append(Path(env_root))
    bases = [p for p in (ctx.profile_path, ctx.localappdata, ctx.appdata) if p]
    for base in bases:
        roots.append(Path(base) / "cmder")
        roots.append(Path(base) / "Cmder")
    for pf in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if pf:
            roots.append(Path(pf) / "cmder")
            roots.append(Path(pf) / "Cmder")

    files: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        for rel in ("config/.history", "config/history", "vendor/clink/.history"):
            cand = root / rel
            try:
                if cand.is_file() and str(cand) not in seen:
                    seen.add(str(cand))
                    files.append(cand)
            except OSError:
                continue
    block.header_meta["search_roots"] = [str(r) for r in roots]
    block.header_meta["files"] = [str(f) for f in files]
    for path in files:
        rows, meta = rows_from_history_file(
            path,
            source="CMD-Cmder",
            shell="cmd",
            parser="readline",
            ctx=ctx,
            collected=collected,
            redact=redact,
            epoch_prov=PROV_CLINK_EPOCH,
        )
        block.rows.extend(rows)
        block.header_meta.setdefault("per_file", []).append(meta)
    if not block.rows:
        block.empty_reason = "No artifacts found (no Cmder config\\.history)"
    return block


def collect_conemu(ctx: UserContext, collected: str, redact: bool) -> SourceBlock:
    """ConEmu.xml holds settings, not typed commands.

    The XML is never dumped. A ConEmu row appears only when a Clink-style
    history file lives beside the settings file.
    """
    block = SourceBlock(
        name="CMD-ConEmu",
        header_meta={
            "policy": "ConEmu.xml/user-ConEmu.xml are settings only; not parsed for commands",
        },
    )
    xml_locations: list[Path] = []
    for base in (ctx.appdata, ctx.profile_path, ctx.localappdata):
        if base:
            xml_locations.append(Path(base) / "ConEmu.xml")
            xml_locations.append(Path(base) / "user-ConEmu.xml")
    for pf in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if pf:
            for name in ("ConEmu", "ConEmuPack"):
                xml_locations.append(Path(pf) / name / "ConEmu.xml")
                xml_locations.append(Path(pf) / name / "user-ConEmu.xml")

    found_xml: list[Path] = []
    siblings: list[Path] = []
    for xml in xml_locations:
        try:
            if not xml.is_file():
                continue
        except OSError:
            continue
        found_xml.append(xml)
        parent = xml.parent
        for cand in (parent, parent / "clink", parent / "config"):
            try:
                if not cand.is_dir():
                    continue
                for p in cand.iterdir():
                    n = p.name.lower()
                    if p.is_file() and ("history" in n or n == ".history"):
                        if p not in siblings:
                            siblings.append(p)
            except OSError:
                continue
    block.header_meta["settings_files_seen"] = [str(x) for x in found_xml]
    block.header_meta["sibling_history_files"] = [str(s) for s in siblings]
    for path in siblings:
        rows, meta = rows_from_history_file(
            path,
            source="CMD-ConEmu",
            shell="cmd",
            parser="readline",
            ctx=ctx,
            collected=collected,
            redact=redact,
            epoch_prov=PROV_CLINK_EPOCH,
        )
        block.rows.extend(rows)
        block.header_meta.setdefault("per_file", []).append(meta)
    if not block.rows:
        block.empty_reason = (
            "No artifacts found (ConEmu stores settings, not typed commands; "
            "no sibling Clink history file present)"
        )
    return block


def collect_cmd_bundle(ctx: UserContext, collected: str, redact: bool, want_live: bool) -> list[SourceBlock]:
    blocks = [
        collect_clink(ctx, collected, redact),
        collect_cmder(ctx, collected, redact),
        collect_conemu(ctx, collected, redact),
        collect_windows_terminal_history(ctx, collected, redact),
    ]
    if want_live:
        blocks.insert(0, collect_live_doskey(ctx, collected, redact))
    any_rows = any(b.rows for b in blocks)
    if not any_rows:
        blocks.append(
            SourceBlock(
                name="CMD",
                empty_reason=(
                    "No persistent CMD history artifact present on this host. "
                    "Native cmd.exe history lives in the conhost session buffer and is "
                    "destroyed when the window closes; it persists only when Clink, "
                    "Cmder, or an incidental history file is in use."
                ),
            )
        )
    return blocks


# ===========================================================================
# POSIX-on-Windows ports (Git for Windows, MSYS2, Cygwin) - not WSL
# ===========================================================================
def _dedup_paths(paths: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for p in paths:
        key = os.path.normcase(str(p))
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def git_bash_homes(ctx: UserContext) -> list[Path]:
    """Git for Windows uses the Windows profile as $HOME in the common case."""
    homes: list[Path] = []
    if ctx.profile_path:
        homes.append(Path(ctx.profile_path))
    for pf in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if not pf:
            continue
        for name in ("Git", "Git for Windows"):
            root = Path(pf) / name / "home"
            try:
                if root.is_dir():
                    homes.extend(c for c in root.iterdir() if c.is_dir())
            except OSError:
                continue
    if ctx.localappdata:
        # Portable / user-scope Git installs
        for rel in ("Programs/Git/home", "Git/home"):
            root = Path(ctx.localappdata) / rel
            try:
                if root.is_dir():
                    homes.extend(c for c in root.iterdir() if c.is_dir())
            except OSError:
                continue
    return _dedup_paths(homes)


def _posix_root_homes(roots: Iterable[Path]) -> list[Path]:
    homes: list[Path] = []
    for root in roots:
        try:
            if not root.is_dir():
                continue
        except OSError:
            continue
        home = root / "home"
        try:
            if home.is_dir():
                homes.extend(c for c in home.iterdir() if c.is_dir())
        except OSError:
            pass
        rootuser = root / "root"
        try:
            if rootuser.is_dir():
                homes.append(rootuser)
        except OSError:
            pass
    return _dedup_paths(homes)


def msys2_homes() -> list[Path]:
    drive = os.environ.get("SystemDrive", "C:")
    roots = [Path(f"{drive}\\msys64"), Path(f"{drive}\\msys32"), Path(f"{drive}\\msys")]
    for entry in (os.environ.get("PATH") or "").split(os.pathsep):
        low = entry.lower().replace("/", "\\")
        if "msys" in low:
            part = Path(entry)
            for _ in range(3):
                if part.name.lower() in {"bin", "usr", "mingw64", "mingw32", "ucrt64"}:
                    part = part.parent
            roots.append(part)
    return _posix_root_homes(_dedup_paths(roots))


def cygwin_homes() -> list[Path]:
    drive = os.environ.get("SystemDrive", "C:")
    roots = [Path(f"{drive}\\cygwin64"), Path(f"{drive}\\cygwin")]
    for entry in (os.environ.get("PATH") or "").split(os.pathsep):
        if "cygwin" in entry.lower():
            part = Path(entry)
            for _ in range(2):
                if part.name.lower() in {"bin", "usr"}:
                    part = part.parent
            roots.append(part)
    return _posix_root_homes(_dedup_paths(roots))


def history_files_in_home(home: Path, include_repls: bool) -> list[tuple[Path, str]]:
    """Return (path, shell) for every history file directly under a home dir."""
    found: list[tuple[Path, str]] = []
    table = dict(POSIX_HISTORY_FILES)
    if include_repls:
        table.update(REPL_HISTORY_FILES)
    for rel, shell in table.items():
        cand = home / rel
        try:
            if cand.is_file():
                found.append((cand, shell))
        except OSError:
            continue
    # .bash_history-<hostname> variants written by some ports
    try:
        for p in home.glob(".bash_history-*"):
            if p.is_file():
                found.append((p, "bash"))
        for p in home.glob(".zsh_history.*"):
            if p.is_file():
                found.append((p, "zsh"))
    except OSError:
        pass
    return found


def collect_posix_ports(
    ctx: UserContext, collected: str, redact: bool, include_repls: bool
) -> list[SourceBlock]:
    """Bash-Git / Bash-MSYS2 / Bash-Cygwin (and zsh/fish/ash siblings)."""
    families: list[tuple[str, list[Path]]] = [
        ("Git", git_bash_homes(ctx)),
        ("MSYS2", msys2_homes()),
        ("Cygwin", cygwin_homes()),
    ]
    blocks: dict[str, SourceBlock] = {}
    ports: dict[str, str] = {}

    def block_for(name: str, port: str) -> SourceBlock:
        if name not in blocks:
            ports[name] = port
            blocks[name] = SourceBlock(
                name=name,
                header_meta={
                    "port": port,
                    "note": (
                        "bash usually flushes history on a clean `exit`; a window closed "
                        "with the X button can lose the whole session"
                    ),
                },
            )
        return blocks[name]

    for port, homes in families:
        searched = [str(h) for h in homes]
        # Always create the Bash-<port> table so an empty one still prints.
        block_for(f"Bash-{port}", port).header_meta.setdefault("homes_searched", searched)
        for home in homes:
            # Probe every candidate so absence is demonstrated, not asserted.
            # Each probe is filed against the block for ITS OWN shell: routing
            # them all to Bash made a zsh directory turn the Bash table
            # "unreadable" while the Zsh table showed no evidence at all.
            for rel, probe_shell in POSIX_HISTORY_FILES.items():
                probe_label = SHELL_LABELS.get(probe_shell, probe_shell.title())
                record_probe(
                    block_for(f"{probe_label}-{port}", port),
                    home.joinpath(*rel.split("/")),
                )
            for path, shell in history_files_in_home(home, include_repls):
                if shell.endswith("-repl"):
                    name = "REPL"
                else:
                    name = f"{SHELL_LABELS.get(shell, shell.title())}-{port}"
                block = block_for(name, port)
                rows, meta = rows_from_history_file(
                    path,
                    source=name,
                    shell=shell,
                    ctx=ctx,
                    collected=collected,
                    redact=redact,
                    search_root=home,
                )
                block.rows.extend(rows)
                block.header_meta.setdefault("per_file", []).append(meta)
    for name, block in blocks.items():
        if not block.rows and not block.empty_reason:
            port = ports.get(name, "")
            where = f"any {port} home directory" if port else "any searched home directory"
            block.empty_reason = f"No artifacts found (no history files under {where})"
    return list(blocks.values())


# ===========================================================================
# WSL
# ===========================================================================
def _reg_str(vals: dict[str, RegValue], name: str) -> str:
    """Read a REG_SZ-ish value, decoding raw UTF-16LE bytes when needed."""
    v = vals.get(name)
    if v is None:
        return ""
    data = v.data
    if isinstance(data, bytes):
        try:
            return data.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            return ""
    return str(data)


def _reg_int(vals: dict[str, RegValue], name: str) -> Optional[int]:
    v = vals.get(name)
    if v is None:
        return None
    try:
        return int(v.data)
    except (TypeError, ValueError):
        return None


def read_lxss_inventory(ctx: UserContext) -> list[dict[str, Any]]:
    """Read HKCU\\...\\Lxss read-only. Returns one dict per registered distro."""
    out: list[dict[str, Any]] = []
    if ctx.hive_view is None:
        return out
    root = ctx.hive_view.open_key(LXSS_PATH)
    if root is None:
        return out
    for guid in root.subkeys:
        if not guid.startswith("{"):
            continue
        snap = ctx.hive_view.open_subkey(LXSS_PATH, guid)
        if snap is None:
            continue
        vals = snap.values
        out.append(
            {
                "guid": guid,
                "name": _reg_str(vals, "DistributionName"),
                "base_path": os.path.expandvars(_reg_str(vals, "BasePath")),
                "version": _reg_int(vals, "Version"),
                "default_uid": _reg_int(vals, "DefaultUid"),
                "flags": _reg_int(vals, "Flags"),
                "package_family": _reg_str(vals, "PackageFamilyName"),
                "key_lastwrite": snap.last_write,
            }
        )
    return out


def find_vhdx(base_path: str) -> tuple[str, int]:
    """Locate ext4.vhdx under BasePath without descending into it."""
    if not base_path:
        return "", 0
    base = Path(base_path)
    for name in ("ext4.vhdx", "ext4.vhd"):
        cand = base / name
        try:
            if cand.is_file():
                return str(cand), cand.stat().st_size
        except OSError:
            continue
    try:
        for p in base.glob("*.vhdx"):
            if p.is_file():
                return str(p), p.stat().st_size
    except OSError:
        pass
    return "", 0


def _dedup_str(items: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for i in items:
        k = i.lower()
        if k not in seen:
            seen.add(k)
            out.append(i)
    return out


def list_wsl_shares() -> list[str]:
    """Names visible under \\\\wsl$ - this lists running distros only.

    Listing the share root does not start a stopped distro. We never touch
    \\\\wsl$\\<name> unless the name already appears here or --wsl-online was
    passed explicitly.
    """
    if os.name != "nt":
        return []
    names: list[str] = []
    for root in (r"\\wsl$", r"\\wsl.localhost"):
        try:
            names.extend(os.listdir(root))
        except OSError:
            continue
    return _dedup_str(names)




def wsl1_home_candidates(distro: dict[str, Any], ctx: UserContext) -> list[Path]:
    """WSL1 keeps the rootfs as ordinary NTFS files."""
    homes: list[Path] = []
    base = distro.get("base_path") or ""
    if base:
        rootfs = Path(base) / "rootfs"
        try:
            home = rootfs / "home"
            if home.is_dir():
                homes.extend(c for c in home.iterdir() if c.is_dir())
            if (rootfs / "root").is_dir():
                homes.append(rootfs / "root")
        except OSError:
            pass
    if ctx.localappdata:
        legacy = Path(ctx.localappdata) / "lxss"
        try:
            home = legacy / "home"
            if home.is_dir():
                homes.extend(c for c in home.iterdir() if c.is_dir())
            if (legacy / "root").is_dir():
                homes.append(legacy / "root")
        except OSError:
            pass
    return _dedup_paths(homes)


def wsl_unc_home_candidates(distro_name: str) -> list[Path]:
    """Home directories under \\\\wsl$ for a distro that is already up."""
    out: list[Path] = []
    for prefix in (r"\\wsl$", r"\\wsl.localhost"):
        root = Path(f"{prefix}\\{distro_name}")
        try:
            if not root.exists():
                continue
        except OSError:
            continue
        try:
            home = root / "home"
            if home.is_dir():
                for c in home.iterdir():
                    if c.is_dir():
                        out.append(c)
            if (root / "root").is_dir():
                out.append(root / "root")
        except OSError:
            continue
        break  # one working prefix is enough
    return out


def vhdx_extraction_tool() -> tuple[str, str]:
    """Return (tool_name, path) for a local read-only image reader, if any."""
    import shutil

    for name in ("virt-copy-out", "7z", "7zz", "7za", "guestfish", "guestmount"):
        found = shutil.which(name)
        if found:
            return name, found
    return "", ""


def safe_cli_argument(value: str) -> bool:
    """Reject a value that an external tool would parse as a switch.

    7z, virt-copy-out and wsl.exe all take these as positional arguments. A
    path or distro name beginning with '-' is read as an option instead -
    argument injection. Everything here is already list-form with no shell, so
    this closes the remaining gap rather than a command-injection hole.
    """
    text = str(value or "")
    return bool(text) and not text.startswith("-") and "\x00" not in text


def try_vhdx_extract(
    vhdx: str, tool: tuple[str, str], timeout: int = 60
) -> tuple[list[tuple[str, str]], str]:
    """Best-effort READ-ONLY extraction of history files from an ext4 image.

    Returns ([(inner_path, text)], note). The image is never opened for
    write, never mounted read-write, and never optimized/compacted.
    """
    name, exe = tool
    if not name:
        return [], "no_local_tool"
    if not safe_cli_argument(vhdx) or not os.path.isabs(vhdx):
        return [], "refused_unsafe_image_path"
    targets = [
        "/root/.bash_history",
        "/root/.zsh_history",
        "/root/.ash_history",
    ]
    try:
        if name == "virt-copy-out":
            with tempfile.TemporaryDirectory() as tmp:
                out: list[tuple[str, str]] = []
                for target in targets:
                    proc = subprocess.run(
                        [exe, "-a", vhdx, "--", target, tmp],
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )
                    if proc.returncode != 0:
                        continue
                    got = Path(tmp) / Path(target).name
                    if got.is_file():
                        out.append((target, got.read_text(errors="replace")))
                if out:
                    return out, "virt-copy-out(read-only)"
                return [], "virt-copy-out_found_no_history_at_known_paths"
        if name in {"7z", "7zz", "7za"}:
            proc = subprocess.run(
                [exe, "l", "-ba", "--", vhdx],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            listing = proc.stdout or ""
            if "_history" not in listing:
                # 7-Zip commonly exposes the VHDX as a nested image that must
                # be opened a second time; do not chain that automatically.
                return [], "7z_listing_shows_nested_image_or_no_history"
            out = []
            for line in listing.splitlines():
                m = re.search(r"(\S*(?:home|root)\S*_history\S*)$", line)
                if not m:
                    continue
                inner = m.group(1)
                if not safe_cli_argument(inner):
                    continue  # archive-controlled name that 7z would read as a switch
                got = subprocess.run(
                    [exe, "e", "-so", "--", vhdx, inner],
                    capture_output=True,
                    timeout=timeout,
                )
                if got.returncode == 0 and got.stdout:
                    out.append((inner, got.stdout.decode("utf-8", errors="replace")))
            return out, "7z(read-only listing/extract)"
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f"extract_failed:{exc}"
    return [], f"{name}_present_but_not_used_automatically"


def wsl_exec_read(distro: str, timeout: int = 20) -> Optional[str]:
    """--wsl-exec only. This STARTS a stopped distro and changes VM state."""
    if not safe_cli_argument(distro):
        return None  # registry-supplied name that wsl.exe would read as a switch
    try:
        proc = subprocess.run(
            [system32_binary("wsl.exe"), "-d", distro, "-e", "cat", "/root/.bash_history"],
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    return proc.stdout.decode("utf-8", errors="replace")


def collect_wsl(
    ctx: UserContext,
    collected: str,
    redact: bool,
    *,
    online: bool,
    offline: bool,
    allow_exec: bool,
) -> list[SourceBlock]:
    inv = SourceBlock(
        name="WSL-Inventory",
        header_meta={
            "registry_key": f"HKCU\\{LXSS_PATH}",
            "row_semantics": (
                "each row is a registered distro, not a command; "
                "timestamp_provenance=unavailable because an inventory row has no event time"
            ),
            "history_state_values": [
                WSL_HIST_CONFIRMED_READ,
                WSL_HIST_CONFIRMED_ABSENT,
                WSL_HIST_PRESENT_UNREADABLE,
                WSL_HIST_NOT_DETERMINED,
            ],
        },
    )
    hist_blocks: dict[str, SourceBlock] = {}

    def hist_block(shell: str) -> SourceBlock:
        label = SHELL_LABELS.get(shell, shell.title())
        name = f"WSL-{label}"
        if name not in hist_blocks:
            hist_blocks[name] = SourceBlock(
                name=name,
                header_meta={
                    "note": (
                        "WSL bash flushes history on clean `exit`; closing the terminal "
                        "window can discard the session's commands entirely"
                    )
                },
            )
        return hist_blocks[name]

    distros = read_lxss_inventory(ctx)
    if not distros:
        inv.empty_reason = "No artifacts found (no Lxss key - WSL not registered for this user)"
        blocks: list[SourceBlock] = [inv]
        blocks.extend(hist_blocks.values())
        return blocks

    running = list_wsl_shares() if os.name == "nt" else []
    inv.header_meta["shares_visible"] = running
    tool = vhdx_extraction_tool() if offline else ("", "")
    if offline:
        inv.header_meta["offline_tool"] = tool[0] or "none_found"

    for d in distros:
        name = d.get("name") or d.get("guid", "")
        version = d.get("version")
        vhdx, vhdx_size = find_vhdx(d.get("base_path", ""))
        # Start from "not determined": nothing has been opened yet.
        access = WSL_HIST_NOT_DETERMINED
        detail = ""
        looked_somewhere = False

        # --- WSL1: plain NTFS files -------------------------------------
        wsl1_homes = wsl1_home_candidates(d, ctx) if version != 2 else []
        collected_any = False
        for home in wsl1_homes:
            for path, shell in history_files_in_home(home, include_repls=False):
                block = hist_block(shell)
                rows, meta = rows_from_history_file(
                    path,
                    source=block.name,
                    shell=shell,
                    ctx=ctx,
                    collected=collected,
                    redact=redact,
                    distro=name,
                    search_root=home,
                )
                block.rows.extend(rows)
                block.header_meta.setdefault("per_file", []).append(meta)
                collected_any = collected_any or bool(rows)
        if wsl1_homes:
            looked_somewhere = True
        if collected_any:
            access = WSL_HIST_CONFIRMED_READ
            detail = "read directly from the WSL1 rootfs on NTFS"

        # --- WSL2 live share: only if it is already answering ------------
        share_up = any(s.lower() == str(name).lower() for s in running)
        if access == WSL_HIST_NOT_DETERMINED and (share_up or online):
            for home in wsl_unc_home_candidates(str(name)):
                for path, shell in history_files_in_home(home, include_repls=False):
                    block = hist_block(shell)
                    rows, meta = rows_from_history_file(
                        path,
                        source=block.name,
                        shell=shell,
                        ctx=ctx,
                        collected=collected,
                        redact=redact,
                        distro=str(name),
                        display_path=str(path),
                    )
                    block.rows.extend(rows)
                    block.header_meta.setdefault("per_file", []).append(meta)
                    if rows:
                        access = WSL_HIST_CONFIRMED_READ
            looked_somewhere = True
            if access == WSL_HIST_CONFIRMED_READ:
                detail = "read via \\\\wsl$ (share already active)" if share_up else "read via \\\\wsl$ (--wsl-online)"

        # --- Offline VHDX: inventory first, extraction only if a tool exists
        if access == WSL_HIST_NOT_DETERMINED and vhdx:
            # The VHDX was inventoried, not opened. Whether it holds history
            # is unknown, and saying otherwise would be a guess.
            detail = "vhdx present but not opened; history existence not determined"
            if offline and tool[0]:
                extracted, note = try_vhdx_extract(vhdx, tool)
                detail = f"offline_attempt={note}"
                for inner, text in extracted:
                    shell = shell_from_filename(inner)
                    block = hist_block(shell)
                    rows, meta = rows_from_history_file(
                        Path(inner),
                        source=block.name,
                        shell=shell,
                        ctx=ctx,
                        collected=collected,
                        redact=redact,
                        distro=str(name),
                        text_override=text,
                        display_path=f"{vhdx}!{inner}",
                    )
                    block.rows.extend(rows)
                    block.header_meta.setdefault("per_file", []).append(meta)
                    if rows:
                        access = WSL_HIST_CONFIRMED_READ
                        detail = f"read by offline extraction ({note})"
                if not extracted:
                    detail = (
                        f"offline extraction attempted and recovered nothing ({note}); "
                        "history existence still not determined"
                    )

        # --- Optional, loud, off by default -----------------------------
        if access == WSL_HIST_NOT_DETERMINED and allow_exec and os.name == "nt":
            text = wsl_exec_read(str(name))
            if text is not None:
                block = hist_block("bash")
                rows, meta = rows_from_history_file(
                    Path(f"wsl:{name}:~/.bash_history"),
                    source=block.name,
                    shell="bash",
                    ctx=ctx,
                    collected=collected,
                    redact=redact,
                    distro=str(name),
                    text_override=text,
                    display_path=f"\\\\wsl-exec\\{name}\\~/.bash_history",
                )
                block.rows.extend(rows)
                meta["warning"] = "distro was started by --wsl-exec; VM state changed"
                block.header_meta.setdefault("per_file", []).append(meta)
                if rows:
                    access = WSL_HIST_CONFIRMED_READ
                    detail = "read via --wsl-exec (STARTED THE DISTRO)"

        # Windows-side copies (bind-mounted home, manual export). BasePath is
        # scanned one level only - we never descend into the VHDX.
        side: list[str] = []
        base = d.get("base_path") or ""
        if base:
            try:
                for p in sorted(Path(base).glob("*_history")):
                    if not p.is_file():
                        continue
                    side.append(str(p))
                    shell = shell_from_filename(p.name)
                    block = hist_block(shell)
                    rows, meta = rows_from_history_file(
                        p,
                        source=block.name,
                        shell=shell,
                        ctx=ctx,
                        collected=collected,
                        redact=redact,
                        distro=str(name),
                    )
                    meta["origin"] = "ntfs_side_copy_under_basepath"
                    block.rows.extend(rows)
                    block.header_meta.setdefault("per_file", []).append(meta)
            except OSError:
                pass

        if access == WSL_HIST_NOT_DETERMINED and looked_somewhere and not vhdx:
            # Reachable locations were searched and held nothing. That is a
            # confirmed absence, not an open question.
            access = WSL_HIST_CONFIRMED_ABSENT
            detail = detail or "reachable rootfs searched; no history file present"
        extra_bits = [
            f"version={version if version is not None else 'unknown'}",
            f"base_path={d.get('base_path', '')}",
            f"vhdx={vhdx or 'none'}",
            f"vhdx_size_bytes={vhdx_size}",
            f"default_uid={d.get('default_uid')}",
            f"history_state={access}",
            f"guid={d.get('guid', '')}",
        ]
        if detail:
            extra_bits.append(f"detail={detail}")
        if side:
            extra_bits.append(f"ntfs_side_copies={';'.join(side)}")
        inv.rows.append(
            IntentRow(
                source="WSL-Inventory",
                user=ctx.user,
                sid=ctx.sid,
                profile_path=ctx.profile_path,
                value_name=str(d.get("guid", "")),
                typed_value=str(name),
                raw_value=d.get("base_path", ""),
                mru_pos=None,
                utc_timestamp="",
                timestamp_provenance=PROV_UNAVAILABLE,
                collected_utc=collected,
                key_lastwrite_utc=iso_utc(d.get("key_lastwrite")),
                extra="; ".join(extra_bits),
                shell="",
                distro=str(name),
            )
        )

    for block in hist_blocks.values():
        if not block.rows:
            block.empty_reason = "No artifacts found (no readable WSL shell history)"
    out_blocks = [inv]
    out_blocks.extend(hist_blocks.values())
    return out_blocks




# ===========================================================================
# Esoteric shells - plaintext only, binary stores inventoried not dumped
# ===========================================================================
def _sqlite_epoch(value: Any) -> Optional[dt.datetime]:
    """Normalise an integer epoch of unknown unit to UTC.

    Nushell stores milliseconds, Atuin nanoseconds. Rather than hard-code a
    unit per tool, detect it by magnitude so a schema change cannot silently
    produce timestamps in the wrong millennium.
    """
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    if v > 1e16:
        v /= 1e9  # nanoseconds
    elif v > 1e13:
        v /= 1e6  # microseconds
    elif v > 1e10:
        v /= 1e3  # milliseconds
    return unix_to_dt(v)


def open_sqlite_readonly(path: Path) -> tuple[Any, str, Optional[Any]]:
    """Open a history database without modifying it.

    Two strategies, both read-only with respect to the evidence:
      * no journal alongside it -> open the file itself with mode=ro and
        immutable=1, which cannot create -wal/-shm or take a lock;
      * a -wal/-shm present -> copy the database AND its journal to a temp
        directory and open the copy, so recent entries still in the WAL are
        not missed. The original is only ever read.
    """
    import shutil
    import sqlite3

    wal = path.with_name(path.name + "-wal")
    shm = path.with_name(path.name + "-shm")
    if wal.exists() or shm.exists():
        tmp = tempfile.TemporaryDirectory()
        target = Path(tmp.name) / path.name
        shutil.copy2(path, target)
        for side in (wal, shm):
            if side.exists():
                shutil.copy2(side, Path(tmp.name) / side.name)
        conn = sqlite3.connect(f"file:{target.as_posix()}?mode=ro", uri=True)
        return conn, "copied with journal to temp, original untouched", tmp
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    return conn, "opened in-place read-only (mode=ro, immutable=1)", None


def _table_columns(conn: Any, table: str) -> list[str]:
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return [r[1] for r in cur.fetchall()]
    except Exception:
        return []


def read_sqlite_history(
    path: Path,
    *,
    table: str,
    cmd_col: str,
    ts_col: str,
    context_cols: tuple[str, ...] = (),
    deleted_col: str = "",
) -> tuple[list[HistEntry], dict[str, Any]]:
    """Generic reader for a shell-history SQLite table.

    Columns are resolved against PRAGMA table_info rather than assumed, so a
    renamed or missing column degrades to less context instead of an
    exception.
    """
    meta: dict[str, Any] = {"path": str(path), "format": "sqlite", "table": table}
    holder = None
    try:
        conn, how, holder = open_sqlite_readonly(path)
    except Exception as exc:
        meta["error"] = f"sqlite open failed: {exc}"
        return [], meta
    meta["access"] = how
    entries: list[HistEntry] = []
    try:
        cols = _table_columns(conn, table)
        if not cols:
            meta["error"] = f"table '{table}' not present"
            return [], meta
        if cmd_col not in cols:
            meta["error"] = f"command column '{cmd_col}' not present (have: {','.join(cols)})"
            return [], meta
        wanted = [cmd_col]
        has_ts = ts_col in cols
        if has_ts:
            wanted.append(ts_col)
        ctx = [c for c in context_cols if c in cols]
        wanted.extend(ctx)
        has_deleted = bool(deleted_col) and deleted_col in cols
        if has_deleted:
            wanted.append(deleted_col)
        meta["columns_used"] = wanted
        order = f" ORDER BY {ts_col}" if has_ts else ""
        # Identifiers come from module constants filtered through PRAGMA
        # table_info, never from user input, so interpolation is safe here.
        sql = f"SELECT {', '.join(wanted)} FROM {table}{order}"
        for row in conn.execute(sql):
            record = dict(zip(wanted, row, strict=False))
            command = record.get(cmd_col)
            if command is None or not str(command).strip():
                continue
            ts = _sqlite_epoch(record.get(ts_col)) if has_ts else None
            bits = []
            for c in ctx:
                value = record.get(c)
                if value not in (None, ""):
                    bits.append(f"{c}={value}")
            deleted = False
            if has_deleted and record.get(deleted_col) not in (None, "", 0):
                deleted = True
                bits.append("db_soft_deleted=1")
            entries.append(
                HistEntry(
                    command=str(command),
                    ts=ts,
                    prov=PROV_DB_EPOCH if ts else "",
                    note="; ".join(bits),
                    deleted=deleted,
                )
            )
    except Exception as exc:
        meta["error"] = f"sqlite read failed: {exc}"
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if holder is not None:
            try:
                holder.cleanup()
            except Exception:
                pass
    meta["rows"] = len(entries)
    meta["timed_rows"] = sum(1 for e in entries if e.ts is not None)
    deleted_n = sum(1 for e in entries if e.deleted)
    if deleted_n:
        meta["recoverable_deleted_rows"] = deleted_n
    return entries, meta


def rows_from_sqlite_history(
    path: Path,
    *,
    source: str,
    shell: str,
    ctx: UserContext,
    collected: str,
    redact: bool,
    table: str,
    cmd_col: str,
    ts_col: str,
    context_cols: tuple[str, ...] = (),
    deleted_col: str = "",
    search_root: Optional[Path] = None,
) -> tuple[list[IntentRow], dict[str, Any]]:
    escape = link_escapes_root(path, search_root)
    if escape is not None:
        # A history database reached through a planted link is never opened.
        return [], {"path": str(path), "shell": shell, "error": escape,
                    "rejected": LINK_ESCAPE_NOTE}
    entries, meta = read_sqlite_history(
        path,
        table=table,
        cmd_col=cmd_col,
        ts_col=ts_col,
        context_cols=context_cols,
        deleted_col=deleted_col,
    )
    meta.update(file_times(path))
    if not entries:
        return [], meta
    rows = entries_to_rows(
        entries,
        source=source,
        ctx=ctx,
        collected=collected,
        redact=redact,
        mtime_utc="",  # every DB row carries its own time; no mtime fallback
        shell=shell,
        extra_prefix=f"path={path}",
        artifact=str(path),
    )
    return rows, meta


NUSHELL_SQLITE = {
    "table": "history",
    "cmd_col": "command_line",
    "ts_col": "start_timestamp",
    "context_cols": ("cwd", "exit_status", "duration_ms", "session_id", "hostname"),
}

ATUIN_SQLITE = {
    "table": "history",
    "cmd_col": "command",
    "ts_col": "timestamp",
    "context_cols": ("cwd", "exit", "duration", "session", "hostname", "shell"),
    "deleted_col": "deleted_at",
}


def atuin_search_roots(ctx: UserContext) -> list[Path]:
    """Atuin data directories reachable from this Windows profile.

    Includes POSIX-port homes because Git Bash, MSYS2 and Cygwin are how
    atuin normally ends up on a Windows host.
    """
    roots: list[Path] = []
    homes: list[Path] = []
    if ctx.profile_path:
        homes.append(Path(ctx.profile_path))
    homes.extend(git_bash_homes(ctx))
    homes.extend(msys2_homes())
    homes.extend(cygwin_homes())
    for home in _dedup_paths(homes):
        roots.append(home / ".local" / "share" / "atuin")
    for base in (ctx.localappdata, ctx.appdata):
        if base:
            roots.append(Path(base) / "atuin")
    return _dedup_paths(roots)


def collect_atuin(ctx: UserContext, collected: str, redact: bool) -> SourceBlock:
    """Atuin is not a shell; it is a history store that replaces Ctrl-R.

    Where it is installed it is the authoritative record, and the shell's own
    history file may be near-empty by comparison.
    """
    roots = atuin_search_roots(ctx)
    block = SourceBlock(
        name="Atuin",
        header_meta={
            "searched": [str(r) for r in roots],
            "note": (
                "atuin records cwd, exit status, duration, session and hostname per command "
                "and does not replace the shell's own history file; both should be compared"
            ),
            "sync_note": (
                "atuin can sync history to a remote server, so this database may hold commands "
                "typed on other hosts, and commands typed here may exist off this host"
            ),
        },
    )
    for root in roots:
        try:
            if not root.is_dir():
                continue
            candidates = [
                p
                for p in root.iterdir()
                if p.is_file()
                and p.suffix in (".db", ".sqlite", ".sqlite3")
                and "history" in p.name.lower()
            ]
        except OSError:
            continue
        for path in candidates:
            rows, meta = rows_from_sqlite_history(
                path,
                source="Atuin",
                shell="atuin",
                ctx=ctx,
                collected=collected,
                redact=redact,
                **ATUIN_SQLITE,
            )
            block.rows.extend(rows)
            block.header_meta.setdefault("per_file", []).append(meta)
    if block.rows:
        for i, row in enumerate(block.rows):
            row.mru_pos = i
    else:
        block.empty_reason = "No artifacts found (no atuin history database)"
    return block


def collect_esoteric(ctx: UserContext, collected: str, redact: bool) -> list[SourceBlock]:
    profile = Path(ctx.profile_path) if ctx.profile_path else None
    appdata = Path(ctx.appdata) if ctx.appdata else None
    localapp = Path(ctx.localappdata) if ctx.localappdata else None
    blocks: list[SourceBlock] = []

    def add(name: str, searched: list[Path]) -> SourceBlock:
        b = SourceBlock(name=name, header_meta={"searched": [str(s) for s in searched]})
        blocks.append(b)
        return b

    # --- nushell ------------------------------------------------------
    nu_roots = [p / "nushell" for p in (appdata, localapp) if p]
    if profile:
        nu_roots.append(profile / ".config" / "nushell")
    nu = add("Nushell", nu_roots)
    for root in nu_roots:
        try:
            if not root.is_dir():
                continue
            for p in sorted(root.iterdir()):
                if not p.is_file() or "history" not in p.name.lower():
                    continue
                if p.suffix.lower() in {".txt", ".xml", ""}:
                    if p.suffix.lower() == ".xml":
                        nu.rows.append(
                            unparsed_row(p, source="Nushell", shell="nushell", ctx=ctx,
                                         collected=collected, reason="present_unparsed_xml")
                        )
                        continue
                    rows, meta = rows_from_history_file(
                        p, source="Nushell", shell="nushell", parser="plain",
                        ctx=ctx, collected=collected, redact=redact,
                    )
                    nu.rows.extend(rows)
                    nu.header_meta.setdefault("per_file", []).append(meta)
                elif p.suffix.lower() in {".sqlite3", ".sqlite", ".db"}:
                    # The SQLite backend carries a per-command timestamp, the
                    # working directory and the exit status - far richer than
                    # the plaintext backend, which stores bare command lines.
                    rows, meta = rows_from_sqlite_history(
                        p, source="Nushell", shell="nushell",
                        ctx=ctx, collected=collected, redact=redact,
                        **NUSHELL_SQLITE,
                    )
                    if rows:
                        nu.rows.extend(rows)
                    elif meta.get("error"):
                        nu.rows.append(
                            unparsed_row(p, source="Nushell", shell="nushell", ctx=ctx,
                                         collected=collected, reason="present_unparsed_sqlite")
                        )
                    nu.header_meta.setdefault("per_file", []).append(meta)
                else:
                    nu.rows.append(
                        unparsed_row(p, source="Nushell", shell="nushell", ctx=ctx,
                                     collected=collected)
                    )
        except OSError:
            continue

    # --- xonsh --------------------------------------------------------
    xo_roots = [p for p in (profile,) if p]
    if profile:
        xo_roots.append(profile / ".local" / "share" / "xonsh")
        xo_roots.append(profile / ".local" / "share" / "xonsh" / "history_json")
    xo = add("Xonsh", xo_roots)
    xo_files: list[Path] = []
    if profile:
        try:
            xo_files.extend(p for p in profile.glob(".xonsh_history*") if p.is_file())
        except OSError:
            pass
        # Newer xonsh keeps per-session JSON under a history_json/ subdirectory.
        for rel in (("xonsh",), ("xonsh", "history_json")):
            share = profile.joinpath(".local", "share", *rel)
            try:
                if share.is_dir():
                    xo_files.extend(p for p in share.iterdir() if p.is_file())
            except OSError:
                continue
    for p in _dedup_paths(xo_files):
        if p.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
            xo.rows.append(unparsed_row(p, source="Xonsh", shell="xonsh", ctx=ctx,
                                        collected=collected, reason="present_unparsed_sqlite"))
            continue
        try:
            text, enc = read_text_guess(p)
        except OSError:
            continue
        entries = parse_xonsh_json(text)
        if entries is None:
            rows, meta = rows_from_history_file(
                p, source="Xonsh", shell="xonsh", parser="plain",
                ctx=ctx, collected=collected, redact=redact,
            )
            xo.rows.extend(rows)
            xo.header_meta.setdefault("per_file", []).append(meta)
            continue
        times = file_times(p)
        xo.rows.extend(
            entries_to_rows(
                entries, source="Xonsh", ctx=ctx, collected=collected, redact=redact,
                mtime_utc=times.get("mtime_utc", ""), shell="xonsh",
                extra_prefix=f"path={p}; format=json; encoding={enc}",
            )
        )
        xo.header_meta.setdefault("per_file", []).append({"path": str(p), "format": "json", **times})

    # --- elvish -------------------------------------------------------
    el_roots = [p / "elvish" for p in (appdata, localapp) if p]
    if profile:
        el_roots.append(profile / ".local" / "state" / "elvish")
        el_roots.append(profile / ".elvish")
    el = add("Elvish", el_roots)
    for root in el_roots:
        try:
            if not root.is_dir():
                continue
            for p in sorted(root.iterdir()):
                if not p.is_file():
                    continue
                low = p.name.lower()
                if low.startswith("db"):
                    el.rows.append(unparsed_row(p, source="Elvish", shell="elvish", ctx=ctx,
                                                collected=collected, reason="present_unparsed_boltdb"))
                elif "history" in low:
                    rows, meta = rows_from_history_file(
                        p, source="Elvish", shell="elvish", parser="plain",
                        ctx=ctx, collected=collected, redact=redact,
                    )
                    el.rows.extend(rows)
                    el.header_meta.setdefault("per_file", []).append(meta)
        except OSError:
            continue

    # --- oil / ysh and ion -------------------------------------------
    if profile:
        oil_paths = [
            profile / ".local" / "share" / "oil" / "history",
            profile / ".config" / "oil" / "history",
            profile / ".osh_history",
            profile / ".ysh_history",
        ]
        oil = add("Oil", oil_paths)
        oil.header_meta["port_note"] = (
            "Oils (OSH/YSH) has no native Windows build; these paths are reached only when a "
            "POSIX port such as Git Bash or Cygwin uses this profile as $HOME"
        )
        for p in oil_paths:
            try:
                if not p.is_file():
                    continue
            except OSError:
                continue
            rows, meta = rows_from_history_file(
                p, source="Oil", shell="oil", parser="readline",
                ctx=ctx, collected=collected, redact=redact,
            )
            oil.rows.extend(rows)
            oil.header_meta.setdefault("per_file", []).append(meta)

        ion_paths = [
            profile / ".local" / "share" / "ion" / "history",
            profile / ".ion_history",
        ]
        ion = add("Ion", ion_paths)
        ion.header_meta["port_note"] = (
            "Ion has no Windows support by design (the maintainers cite NT passing a single "
            "command string rather than an argv array); reachable only via a POSIX port or WSL"
        )
        for p in ion_paths:
            try:
                if not p.is_file():
                    continue
            except OSError:
                continue
            rows, meta = rows_from_history_file(
                p, source="Ion", shell="ion", parser="plain",
                ctx=ctx, collected=collected, redact=redact,
            )
            ion.rows.extend(rows)
            ion.header_meta.setdefault("per_file", []).append(meta)

    for b in blocks:
        if not b.rows:
            b.empty_reason = f"No artifacts found (no {b.name} history files present)"
    return blocks


# ===========================================================================
# History-policy configuration scanner
#
# Reads shell configuration for two questions only:
#   1. where the history artifact is declared to be written (and on what kind
#      of volume - is it going to a USB stick or a network share?)
#   2. whether history is suppressed, filtered, or destroyed on exit
#
# It is not a dotfile dumper. $PATH, aliases, functions, prompts and exported
# credentials are out of scope and are never collected. Only lines matching the
# table below are read out, so a .bashrc full of API keys does not end up in
# the report.
#
# Nothing here evaluates a config file. Lines are reported verbatim with their
# file and line number. Shell precedence (.bashrc vs .bash_profile vs
# /etc/profile) and conditional guards such as `if [[ $- == *i* ]]` make any
# claim about the EFFECTIVE value confidently wrong, so no such claim is made.
# ===========================================================================
EFFECT_RELOCATES = "relocates"
EFFECT_SUPPRESSES = "suppresses"
EFFECT_CLEARS_ON_EXIT = "clears-on-exit"
EFFECT_FILTERS = "filters"
EFFECT_LIMITS = "limits"
EFFECT_PRESERVES = "preserves"
EFFECT_DEFAULT = "default"

POLICY_EFFECTS = (
    EFFECT_RELOCATES,
    EFFECT_SUPPRESSES,
    EFFECT_CLEARS_ON_EXIT,
    EFFECT_FILTERS,
    EFFECT_LIMITS,
    EFFECT_PRESERVES,
    EFFECT_DEFAULT,
)

VOLUME_FIXED = "fixed"
VOLUME_REMOVABLE = "removable"
VOLUME_REMOTE = "remote"
VOLUME_CLOUD = "cloud-sync"
VOLUME_NULL = "null-device"
VOLUME_ABSENT = "absent/unmounted"
VOLUME_UNKNOWN = "unknown"

VOLUME_KINDS = (
    VOLUME_FIXED,
    VOLUME_REMOVABLE,
    VOLUME_REMOTE,
    VOLUME_CLOUD,
    VOLUME_NULL,
    VOLUME_ABSENT,
    VOLUME_UNKNOWN,
)

# Config files per shell family. Logout files matter: they are where
# "clear history on exit" actually lives.
CONFIG_FILES: dict[str, tuple[str, ...]] = {
    "bash": (".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout"),
    "zsh": (".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout"),
    "fish": (".config/fish/config.fish", ".config/fish/fish_variables"),
    "xonsh": (".xonshrc",),
}

# (family, effect, capture-group-is-a-path, compiled pattern)
# One table drives every shell family; there is no per-shell parser.
CONFIG_MATCHERS: list[tuple[str, str, str, bool]] = [
    # --- Goal 1: where the history is written -------------------------
    ("bash", EFFECT_RELOCATES, r"^\s*(?:export\s+)?HISTFILE\s*=\s*(.+?)\s*(?:#.*)?$", True),
    ("zsh", EFFECT_RELOCATES, r"^\s*(?:export\s+)?HISTFILE\s*=\s*(.+?)\s*(?:#.*)?$", True),
    ("fish", EFFECT_RELOCATES, r"^\s*set\s+(?:-U\s+|--universal\s+)?fish_history\s+(.+?)\s*$", False),
    ("powershell", EFFECT_RELOCATES, r"-HistorySavePath\s+(\S+)", True),
    ("xonsh", EFFECT_RELOCATES, r"^\s*\$XONSH_HISTORY_FILE\s*=\s*(.+?)\s*$", True),
    ("atuin", EFFECT_RELOCATES, r"^\s*db_path\s*=\s*(.+?)\s*$", True),
    ("nushell", EFFECT_RELOCATES,
     r"^\s*\$env\.config\.history\.file_format\s*=\s*(.+?)\s*$", False),
    # Nushell configs commonly use a nested record rather than flat assignment:
    #   $env.config = { history: { file_format: "sqlite" max_size: 100_000 } }
    # Matched line-by-line; the file is never parsed or evaluated as a whole,
    # so a bare `key: value` is reported as written without claiming context.
    ("nushell", EFFECT_RELOCATES, r"^\s*file_format\s*:\s*(.+?)\s*,?\s*$", False),
    # --- Goal 2: suppression, filtering, destruction -------------------
    ("bash", EFFECT_SUPPRESSES, r"^\s*(?:export\s+)?HISTSIZE\s*=\s*[\"']?0[\"']?\s*$", False),
    ("bash", EFFECT_SUPPRESSES, r"^\s*(?:export\s+)?HISTFILESIZE\s*=\s*[\"']?0[\"']?\s*$", False),
    ("bash", EFFECT_SUPPRESSES, r"^\s*unset\s+HISTFILE\b", False),
    ("bash", EFFECT_SUPPRESSES, r"^\s*set\s+\+o\s+history\b", False),
    ("bash", EFFECT_SUPPRESSES, r"^\s*shopt\s+-u\s+histappend\b", False),
    ("bash", EFFECT_FILTERS, r"^\s*(?:export\s+)?HISTCONTROL\s*=\s*(.+?)\s*$", False),
    ("bash", EFFECT_FILTERS, r"^\s*(?:export\s+)?HISTIGNORE\s*=\s*(.+?)\s*$", False),
    ("bash", EFFECT_PRESERVES, r"^\s*(?:export\s+)?HISTTIMEFORMAT\s*=\s*(.+?)\s*$", False),
    ("zsh", EFFECT_SUPPRESSES, r"^\s*(?:export\s+)?SAVEHIST\s*=\s*[\"']?0[\"']?\s*$", False),
    ("zsh", EFFECT_SUPPRESSES, r"^\s*setopt\s+(?:HIST_NO_STORE|hist_no_store)\b", False),
    ("zsh", EFFECT_SUPPRESSES, r"^\s*unsetopt\s+(?:INC_APPEND_HISTORY|inc_append_history|SHARE_HISTORY|share_history)\b", False),
    ("zsh", EFFECT_FILTERS, r"^\s*setopt\s+(?:HIST_IGNORE_SPACE|hist_ignore_space)\b", False),
    ("zsh", EFFECT_PRESERVES, r"^\s*setopt\s+(?:EXTENDED_HISTORY|extended_history)\b", False),
    ("zsh", EFFECT_LIMITS, r"^\s*(?:export\s+)?SAVEHIST\s*=\s*[\"']?([1-9]\d*)[\"']?\s*$", False),
    ("powershell", EFFECT_SUPPRESSES, r"-HistorySaveStyle\s+SaveNothing\b", False),
    ("powershell", EFFECT_SUPPRESSES, r"-MaximumHistoryCount\s+0\b", False),
    ("powershell", EFFECT_FILTERS, r"-AddToHistoryHandler\b", False),
    ("powershell", EFFECT_CLEARS_ON_EXIT, r"^\s*Clear-History\b", False),
    ("powershell", EFFECT_CLEARS_ON_EXIT,
     r"Remove-Item[^\n]*HistorySavePath", False),
    ("clink", EFFECT_SUPPRESSES, r"^\s*history\.save\s*=\s*[Ff]alse\s*$", False),
    ("clink", EFFECT_FILTERS, r"^\s*history\.ignore_space\s*=\s*[Tt]rue\s*$", False),
    ("clink", EFFECT_LIMITS, r"^\s*history\.max_lines\s*=\s*(\d+)\s*$", False),
    ("clink", EFFECT_PRESERVES, r"^\s*history\.time_stamp\s*=\s*(?!off)(\S+)\s*$", False),
    ("atuin", EFFECT_FILTERS, r"^\s*history_filter\s*=\s*(.+?)\s*$", False),
    ("atuin", EFFECT_FILTERS, r"^\s*cwd_filter\s*=\s*(.+?)\s*$", False),
    ("atuin", EFFECT_FILTERS, r"^\s*store_failed\s*=\s*false\s*$", False),
    ("atuin", EFFECT_RELOCATES, r"^\s*sync_address\s*=\s*(.+?)\s*$", False),
    ("atuin", EFFECT_RELOCATES, r"^\s*auto_sync\s*=\s*true\s*$", False),
    ("nushell", EFFECT_LIMITS, r"^\s*\$env\.config\.history\.max_size\s*=\s*(\d+)\s*$", False),
    ("nushell", EFFECT_FILTERS, r"^\s*\$env\.config\.history\.isolation\s*=\s*(.+?)\s*$", False),
    ("nushell", EFFECT_LIMITS, r"^\s*max_size\s*:\s*([\d_]+)\s*,?\s*$", False),
    ("nushell", EFFECT_FILTERS, r"^\s*isolation\s*:\s*(true|false)\s*,?\s*$", False),
    ("xonsh", EFFECT_SUPPRESSES, r"^\s*\$XONSH_HISTORY_SIZE\s*=\s*\(?0\b", False),
    # --- clear-on-exit, any POSIX family ------------------------------
    ("posix", EFFECT_CLEARS_ON_EXIT, r"\bhistory\s+-c\b", False),
    ("posix", EFFECT_CLEARS_ON_EXIT, r"\bhistory\s+-w\s+/dev/null\b", False),
    ("posix", EFFECT_CLEARS_ON_EXIT, r"\b(?:rm|shred|del)\b[^\n]*_history\b", False),
    ("posix", EFFECT_CLEARS_ON_EXIT, r"\bcat\s+/dev/null\s*>[^\n]*_history\b", False),
    ("posix", EFFECT_CLEARS_ON_EXIT, r"\btrap\b[^\n]*\bhistory\s+-c\b", False),
]

_COMPILED_MATCHERS = [
    (family, effect, re.compile(pattern), is_path)
    for family, effect, pattern, is_path in CONFIG_MATCHERS
]

# Cheap substring that MUST be present for a pattern to have any chance of
# matching. Only the patterns with an unanchored `[^\n]*` between two
# literals need one; those are the ones that backtrack quadratically on a
# long line with many candidate start positions.
_MATCHER_GATES: dict[int, str] = {}
for _f, _e, _rx, _p in _COMPILED_MATCHERS:
    _src = _rx.pattern
    if "_history" in _src and "[^\\n]*" in _src:
        _MATCHER_GATES[id(_rx)] = "_history"
    elif "HistorySavePath" in _src and "[^\\n]*" in _src:
        _MATCHER_GATES[id(_rx)] = "HistorySavePath"

# A config directive is never this long. Lines beyond it are counted as an
# anomaly rather than matched - see scan_config_file for why.
MAX_CONFIG_LINE = 4096

# Shell families that share the POSIX clear-on-exit patterns.
POSIX_CONFIG_FAMILIES = {"bash", "zsh", "fish"}

NULL_DEVICE_NAMES = {"/dev/null", "nul", "nul:", "$null", "/dev/zero"}
CLOUD_MARKERS = ("onedrive", "dropbox", "google drive", "googledrive", "icloud", "box sync")


# Win32 GetDriveTypeW return codes. The mapping is asserted by --selftest; the
# Win32 call itself cannot be executed off-Windows, so the seam below is what
# the tests substitute. Treat this as mapping-verified, not execution-verified.
DRIVE_TYPE_MAP = {
    0: VOLUME_UNKNOWN,   # DRIVE_UNKNOWN
    1: VOLUME_ABSENT,    # DRIVE_NO_ROOT_DIR - the drive letter has no volume
    2: VOLUME_REMOVABLE,  # DRIVE_REMOVABLE - USB stick, SD card, floppy
    3: VOLUME_FIXED,     # DRIVE_FIXED
    4: VOLUME_REMOTE,    # DRIVE_REMOTE - mapped network drive
    5: VOLUME_UNKNOWN,   # DRIVE_CDROM
    6: VOLUME_UNKNOWN,   # DRIVE_RAMDISK
}


def query_drive_type(drive: str) -> Optional[int]:
    """Raw GetDriveTypeW result for a drive root, or None if unavailable.

    Isolated so classify_volume() can be tested off-Windows by substituting
    this function. Never raises: a failed lookup degrades to None, which the
    caller treats as `unknown`.
    """
    if os.name != "nt":
        return None
    try:
        return int(ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive)))
    except (AttributeError, OSError, ValueError):
        return None


def classify_volume(raw: str) -> str:
    """Classify a declared history path by the kind of volume it names.

    Answers "is this history being written to a USB stick or a share?".
    A UNC path is remote without any API call; a drive letter needs
    GetDriveTypeW, which is guarded and substitutable.
    """
    text = (raw or "").strip().strip("\"'")
    if not text:
        return VOLUME_UNKNOWN
    lowered = text.lower()
    if lowered in NULL_DEVICE_NAMES:
        return VOLUME_NULL
    if any(marker in lowered for marker in CLOUD_MARKERS):
        return VOLUME_CLOUD
    if text.startswith("\\\\") or text.startswith("//"):
        return VOLUME_REMOTE
    # Unexpanded variables cannot be resolved without evaluating the config.
    if "$" in text or "%" in text:
        return VOLUME_UNKNOWN
    drive = ""
    if len(text) >= 2 and text[1] == ":":
        drive = text[0].upper() + ":\\"
    if drive:
        code = query_drive_type(drive)
        if code is not None:
            return DRIVE_TYPE_MAP.get(code, VOLUME_UNKNOWN)
    try:
        if Path(text).exists():
            return VOLUME_FIXED if drive or text.startswith("/") else VOLUME_UNKNOWN
    except OSError:
        pass
    if drive:
        return VOLUME_ABSENT
    return VOLUME_UNKNOWN


@dataclass
class ConfigFinding:
    """One matched configuration line."""

    family: str
    effect: str
    path: str
    lineno: int
    line: str
    declared_path: str = ""
    volume: str = ""


def scan_config_file(
    path: Path, families: tuple[str, ...]
) -> tuple[list[ConfigFinding], dict[str, Any]]:
    """Match one config file against the table. Never evaluates the file.

    Returns (findings, anomalies). Lines longer than MAX_CONFIG_LINE are not
    matched: a config directive is never that long, and scanning one is a
    denial-of-service vector. The clear-on-exit patterns contain `[^\\n]*`
    between two anchors, so on a long line with many candidate starts the
    regex engine backtracks quadratically - a planted `.bashrc` holding one
    long line of repeated `rm ` tokens made collection take hours. An
    over-long line is itself anomalous, so it is counted and reported rather
    than silently dropped.
    """
    findings: list[ConfigFinding] = []
    anomalies: dict[str, Any] = {}
    try:
        if path.stat().st_size > MAX_HISTORY_BYTES:
            anomalies["skipped"] = f"file larger than {MAX_HISTORY_BYTES} bytes"
            return findings, anomalies
        text, _enc = read_text_guess(path)
    except OSError:
        return findings, anomalies

    # POSIX shells share the clear-on-exit patterns; other families do not.
    wanted_families = set(families)
    if wanted_families & POSIX_CONFIG_FAMILIES:
        wanted_families.add("posix")

    oversize = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if len(line) > MAX_CONFIG_LINE:
            oversize += 1
            continue
        for family, effect, rx, is_path in _COMPILED_MATCHERS:
            if family not in wanted_families:
                continue
            # Cheap substring gate before the backtracking-prone patterns.
            gate = _MATCHER_GATES.get(id(rx))
            if gate and gate not in line:
                continue
            match = rx.search(line)
            if not match:
                continue
            declared = ""
            volume = ""
            if is_path and match.groups():
                declared = match.group(1).strip().strip("\"'")
                volume = classify_volume(declared)
                if volume == VOLUME_NULL:
                    # Relocation to a null device is destruction, not storage.
                    findings.append(
                        ConfigFinding(family, EFFECT_SUPPRESSES, str(path), lineno,
                                      stripped, declared, volume)
                    )
            findings.append(
                ConfigFinding(family, effect, str(path), lineno, stripped, declared, volume)
            )
    if oversize:
        anomalies["oversize_lines_skipped"] = oversize
        anomalies["oversize_note"] = (
            f"{oversize} line(s) exceeded {MAX_CONFIG_LINE} chars and were not matched; "
            "a config directive is never that long, so treat such a line as suspicious"
        )
    return findings, anomalies


def powershell_machine_profiles() -> list[tuple[Path, tuple[str, ...], Path]]:
    """AllUsers $PROFILE locations under $PSHOME.

    Machine-scope: a SaveNothing or -HistorySavePath here applies to EVERY
    user on the host, not just the profile being examined. Read once per run,
    like HKLM and the machine-scope package roots.
    """
    out: list[tuple[Path, tuple[str, ...], Path]] = []
    roots: list[Path] = []
    system_root = os.environ.get("SystemRoot") or os.environ.get("windir")
    if system_root:
        roots.append(Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0")
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_name)
        if not base:
            continue
        pwsh_root = Path(base) / "PowerShell"
        try:
            if pwsh_root.is_dir():
                # 7, 8, ... - take whatever major-version dirs exist
                roots.extend(child for child in pwsh_root.iterdir() if child.is_dir())
        except OSError:
            continue
    for root in _dedup_paths(roots):
        for name in ("profile.ps1", "Microsoft.PowerShell_profile.ps1"):
            out.append((root / name, ("powershell",), root))
    return out


def config_file_candidates(
    ctx: UserContext, include_machine_scope: bool = True
) -> list[tuple[Path, tuple[str, ...], Path]]:
    """(config file, families it belongs to, discovery root).

    Reuses the existing root discovery - no new search logic. The discovery
    root is returned so link containment can be enforced per artifact.
    """
    out: list[tuple[Path, tuple[str, ...], Path]] = []
    if include_machine_scope:
        out.extend(powershell_machine_profiles())
    homes: list[Path] = []
    homes.extend(git_bash_homes(ctx))
    homes.extend(msys2_homes())
    homes.extend(cygwin_homes())
    for home in _dedup_paths(homes):
        for family, names in CONFIG_FILES.items():
            for name in names:
                out.append((home.joinpath(*name.split("/")), (family,), home))
    profile = Path(ctx.profile_path) if ctx.profile_path else None
    appdata = Path(ctx.appdata) if ctx.appdata else None
    localapp = Path(ctx.localappdata) if ctx.localappdata else None
    if appdata is not None:
        ps_dir = appdata / "Microsoft" / "Windows" / "PowerShell"
        for name in ("Microsoft.PowerShell_profile.ps1", "profile.ps1"):
            out.append((ps_dir / name, ("powershell",), ps_dir))
        pwsh_dir = appdata / "Microsoft" / "PowerShell"
        for name in ("Microsoft.PowerShell_profile.ps1", "profile.ps1"):
            out.append((pwsh_dir / name, ("powershell",), pwsh_dir))
        for base in (appdata, localapp):
            if base is not None:
                out.append((base / "clink" / "clink_settings", ("clink",), base / "clink"))
                out.append((base / "nushell" / "config.nu", ("nushell",), base / "nushell"))
                out.append((base / "nushell" / "env.nu", ("nushell",), base / "nushell"))
    if profile is not None:
        for rel, fam in (
            ((".config", "atuin", "config.toml"), "atuin"),
            ((".atuin", "config.toml"), "atuin"),
            ((".config", "nushell", "config.nu"), "nushell"),
        ):
            out.append((profile.joinpath(*rel), (fam,), profile))
    seen: set[str] = set()
    unique: list[tuple[Path, tuple[str, ...], Path]] = []
    for path, fams, root in out:
        key = os.path.normcase(str(path))
        if key not in seen:
            seen.add(key)
            unique.append((path, fams, root))
    return unique


def collect_config_policy(
    ctx: UserContext,
    collected: str,
    redact: bool,
    blocks: list[SourceBlock],
    include_machine_scope: bool = True,
) -> list[SourceBlock]:
    """Build the History-Location and History-Policy tables."""
    location = SourceBlock(
        name="History-Location",
        header_meta={
            "goal": "where each shell declares its history artifact is written",
            "volume_kinds": list(VOLUME_KINDS),
            "volume_caveat": (
                "the volume kind is read AT COLLECTION TIME and drive letters get reassigned; "
                "this states two facts at two moments - what the config declares, and what that "
                "drive is now - not that history was written to a USB"
            ),
            "caveat": (
                "declared, not effective: shell precedence and conditional guards are "
                "not evaluated, and a path is reported exactly as written"
            ),
        },
    )
    policy = SourceBlock(
        name="History-Policy",
        header_meta={
            "goal": "configuration that suppresses, filters or destroys history",
            "effects": list(POLICY_EFFECTS),
            "caveat": (
                "absence of suppression config is NOT evidence of absence: an interactive "
                "`unset HISTFILE` or a leading space leaves no trace in any file"
            ),
        },
    )
    collected_paths = {
        os.path.normcase(r.artifact)
        for b in blocks
        for r in b.rows
        if r.artifact
    }
    checked = 0
    machine_paths = {
        os.path.normcase(str(p)) for p, _f, _r in powershell_machine_profiles()
    }
    for path, families, root in config_file_candidates(ctx, include_machine_scope):
        escape = link_escapes_root(path, root)
        if escape is not None:
            policy.header_meta.setdefault("per_file", []).append(
                {"path": str(path), "error": escape, "rejected": LINK_ESCAPE_NOTE}
            )
            continue
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        checked += 1
        times = file_times(path)
        file_findings, file_anomalies = scan_config_file(path, families)
        if file_anomalies:
            policy.header_meta.setdefault("per_file", []).append(
                {"path": str(path), **file_anomalies}
            )
        for finding in file_findings:
            scope = (
                "machine (applies to every user)"
                if os.path.normcase(finding.path) in machine_paths
                else "user"
            )
            extra_bits = [
                f"config={finding.path}",
                f"line={finding.lineno}",
                f"family={finding.family}",
                f"scope={scope}",
                f"config_mtime_utc={times.get('mtime_utc', '')}",
            ]
            if finding.effect == EFFECT_RELOCATES and finding.declared_path:
                cross = ""
                declared_norm = os.path.normcase(finding.declared_path)
                if collected_paths and declared_norm not in collected_paths:
                    cross = "declared_path_not_among_collected_artifacts"
                if finding.volume in (VOLUME_REMOVABLE, VOLUME_REMOTE, VOLUME_ABSENT):
                    cross = (cross + "; " if cross else "") + "artifact_may_be_off_this_machine"
                bits = [*extra_bits, f"volume={finding.volume}"]
                if cross:
                    bits.append(f"cross_check={cross}")
                location.rows.append(
                    IntentRow(
                        source="History-Location",
                        user=ctx.user,
                        sid=ctx.sid,
                        profile_path=ctx.profile_path,
                        value_name=f"{Path(finding.path).name}:{finding.lineno}",
                        typed_value=maybe_redact(finding.line, redact),
                        raw_value=maybe_redact(finding.line, redact),
                        mru_pos=None,
                        utc_timestamp="",
                        timestamp_provenance=PROV_UNAVAILABLE,
                        collected_utc=collected,
                        key_lastwrite_utc="",
                        extra="; ".join(bits),
                        shell=finding.family,
                        artifact=finding.path,
                    )
                )
            policy.rows.append(
                IntentRow(
                    source="History-Policy",
                    user=ctx.user,
                    sid=ctx.sid,
                    profile_path=ctx.profile_path,
                    value_name=f"{Path(finding.path).name}:{finding.lineno}",
                    typed_value=maybe_redact(finding.line, redact),
                    raw_value=maybe_redact(finding.line, redact),
                    mru_pos=None,
                    utc_timestamp="",
                    timestamp_provenance=PROV_UNAVAILABLE,
                    collected_utc=collected,
                    key_lastwrite_utc="",
                    extra="; ".join([*extra_bits, f"effect={finding.effect}"]),
                    shell=finding.family,
                    artifact=finding.path,
                )
            )
    location.header_meta["config_files_read"] = checked
    policy.header_meta["config_files_read"] = checked
    if not location.rows:
        location.empty_reason = (
            f"Checked {checked} config file(s); no shell declares a relocated history path"
        )
    if not policy.rows:
        policy.empty_reason = (
            f"Checked {checked} config file(s); no history-altering configuration found. "
            "This is not evidence that history was never suppressed."
        )
    return [location, policy]


def collect_repls(ctx: UserContext, collected: str, redact: bool) -> SourceBlock:
    """--include-repls only. These are language REPLs, not shells."""
    block = SourceBlock(
        name="REPL",
        header_meta={"note": "language REPL histories; not interactive shells (--include-repls)"},
    )
    if not ctx.profile_path:
        block.empty_reason = "No artifacts found (no profile path)"
        return block
    home = Path(ctx.profile_path)
    for rel, shell in REPL_HISTORY_FILES.items():
        p = home / rel
        try:
            if not p.is_file():
                continue
        except OSError:
            continue
        rows, meta = rows_from_history_file(
            p, source="REPL", shell=shell, parser="plain",
            ctx=ctx, collected=collected, redact=redact,
        )
        block.rows.extend(rows)
        block.header_meta.setdefault("per_file", []).append(meta)
    ipy = home / ".ipython"
    try:
        if ipy.is_dir():
            for p in ipy.rglob("history.sqlite"):
                block.rows.append(
                    unparsed_row(p, source="REPL", shell="ipython", ctx=ctx,
                                 collected=collected, reason="present_unparsed_sqlite")
                )
    except OSError:
        pass
    if not block.rows:
        block.empty_reason = "No artifacts found (no REPL history files)"
    return block


# ===========================================================================
# User discovery
# ===========================================================================
def windows_os_build() -> str:
    if os.name == "nt":
        try:
            v = sys.getwindowsversion()  # type: ignore[attr-defined]
            return f"Windows {v.major}.{v.minor} build {v.build}"
        except Exception:
            return platform.platform()
    return platform.platform()


def current_username() -> str:
    for key in ("USERNAME", "USER", "LOGNAME"):
        if os.environ.get(key):
            return os.environ[key]
    try:
        import getpass

        return getpass.getuser() or ""
    except Exception:
        return ""


def profile_list_map() -> dict[str, str]:
    """SID -> ProfileImagePath from HKLM ProfileList."""
    mapping: dict[str, str] = {}
    if winreg is None:
        return mapping
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, PROFILELIST_PATH)
    except OSError:
        return mapping
    i = 0
    while True:
        try:
            sid = winreg.EnumKey(root, i)
        except OSError:
            break
        i += 1
        try:
            k = winreg.OpenKey(root, sid)
            path, _ = winreg.QueryValueEx(k, "ProfileImagePath")
            winreg.CloseKey(k)
            mapping[sid] = os.path.expandvars(str(path))
        except OSError:
            continue
    try:
        winreg.CloseKey(root)
    except OSError:
        pass
    return mapping


def sid_for_profile(profile_path: str, plist: dict[str, str]) -> str:
    norm = os.path.normcase(os.path.normpath(profile_path))
    for sid, p in plist.items():
        if os.path.normcase(os.path.normpath(os.path.expandvars(p))) == norm:
            return sid
    return ""


def privilege_for_sid(sid: str) -> str:
    """Privilege context of an account, from its SID alone.

    Well-known SIDs are decidable without touching the SAM or a live query:
    S-1-5-18 is SYSTEM, S-1-5-19/20 are the service accounts, and a RID of
    500 is the built-in Administrator. Everything else is `user` - membership
    of the Administrators group needs the SAM hive or a live lookup, and this
    tool reads neither, so claiming it would be a guess.
    """
    text = (sid or "").strip().upper()
    if not text.startswith("S-1-"):
        return PRIV_UNKNOWN
    if text == "S-1-5-18":
        return PRIV_SYSTEM
    if text in ("S-1-5-19", "S-1-5-20"):
        return PRIV_SERVICE
    if text.startswith("S-1-5-21-") and text.rsplit("-", 1)[-1] == "500":
        return PRIV_BUILTIN_ADMIN
    return PRIV_USER


def build_user_context_from_profile(
    profile_path: str,
    user: str = "",
    sid: str = "",
    hive_view: Optional[HiveView] = None,
    errors: Optional[list[CollectionError]] = None,
) -> UserContext:
    profile = str(Path(profile_path))
    name = user or Path(profile).name
    appdata = str(Path(profile) / "AppData" / "Roaming")
    localappdata = str(Path(profile) / "AppData" / "Local")
    view = hive_view
    hive_file = Path(profile) / "NTUSER.DAT"
    if view is None and hive_file.is_file():
        try:
            view = open_offline_hive(str(hive_file))
        except OSError as exc:
            if errors is not None:
                errors.append(CollectionError(scope=profile, message=str(exc)))
    return UserContext(
        user=name,
        sid=sid,
        profile_path=profile,
        appdata=appdata,
        localappdata=localappdata,
        hive_view=view,
        privilege=privilege_for_sid(sid),
    )




def live_current_user_context(errors: list[CollectionError]) -> UserContext:
    user = current_username()
    profile = os.environ.get("USERPROFILE") or str(Path.home())
    appdata = os.environ.get("APPDATA") or str(Path(profile) / "AppData" / "Roaming")
    localappdata = os.environ.get("LOCALAPPDATA") or str(Path(profile) / "AppData" / "Local")
    plist = profile_list_map()
    sid = sid_for_profile(profile, plist)
    if not sid:
        sid = os.environ.get("USERDOMAIN", "") + "\\" + user if user else ""
    view: Optional[HiveView] = None
    if winreg is not None:
        try:
            view = LiveHiveView(winreg.HKEY_CURRENT_USER)
        except OSError as exc:
            errors.append(CollectionError(scope="HKCU", message=str(exc)))
    return UserContext(
        user=user,
        sid=sid,
        profile_path=profile,
        appdata=appdata,
        localappdata=localappdata,
        hive_view=view,
        privilege=privilege_for_sid(sid),
    )


def _profilelist_contexts(
    plist: dict[str, str],
    loaded_hku: dict[str, Any],
    seen_paths: set[str],
    errors: list[CollectionError],
) -> list[UserContext]:
    """Profiles named by HKLM ProfileList that the C:\\Users walk cannot reach.

    SYSTEM lives at %SystemRoot%\\System32\\config\\systemprofile and the
    service accounts under %SystemRoot%\\ServiceProfiles - neither is under
    C:\\Users, so enumerating that directory misses them entirely. A
    ConsoleHost_history.txt under the SYSTEM profile is PowerShell that ran as
    SYSTEM, which is the post-escalation artifact an examiner most wants.

    These are collected regardless of --include-system-profiles: that flag
    exists to include Public and Default, which are noise. SYSTEM is not.
    """
    out: list[UserContext] = []
    for sid, profile in sorted(plist.items()):
        if not profile:
            continue
        key = os.path.normcase(profile)
        if key in seen_paths:
            continue
        try:
            if not Path(profile).is_dir():
                continue
        except OSError:
            continue
        seen_paths.add(key)
        view: Optional[HiveView] = None
        if sid in loaded_hku and winreg is not None:
            view = LiveHiveView(loaded_hku[sid])
        else:
            hive = Path(profile) / "NTUSER.DAT"
            try:
                if hive.is_file():
                    view = open_offline_hive(str(hive))
            except OSError as exc:
                errors.append(CollectionError(scope=str(hive), message=str(exc)))
        out.append(
            UserContext(
                user=lookup_account_sid(sid) or Path(profile).name,
                sid=sid,
                profile_path=profile,
                appdata=str(Path(profile) / "AppData" / "Roaming"),
                localappdata=str(Path(profile) / "AppData" / "Local"),
                hive_view=view,
                privilege=privilege_for_sid(sid),
            )
        )
    return out


def iter_all_users(include_system: bool, errors: list[CollectionError]) -> list[UserContext]:
    users_root = Path(os.environ.get("SystemDrive", "C:") + r"\Users")
    plist = profile_list_map()
    if not users_root.is_dir():
        errors.append(CollectionError(scope=str(users_root), message="Users directory not found"))
        # ProfileList may still name SYSTEM and the service accounts, whose
        # profiles are NOT under C:\Users.
        return _profilelist_contexts(plist, {}, set(), errors)
    loaded_hku: dict[str, Any] = {}
    if winreg is not None:
        try:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(winreg.HKEY_USERS, i)
                except OSError:
                    break
                i += 1
                if name.startswith("S-1-5-") and "_Classes" not in name:
                    try:
                        loaded_hku[name] = winreg.OpenKey(winreg.HKEY_USERS, name)
                    except OSError:
                        continue
        except OSError as exc:
            errors.append(CollectionError(scope="HKU", message=str(exc)))

    contexts: list[UserContext] = []
    seen_paths: set[str] = set()
    try:
        entries = list(users_root.iterdir())
    except OSError as exc:
        errors.append(CollectionError(scope=str(users_root), message=str(exc)))
        return []
    for entry in entries:
        if not entry.is_dir():
            continue
        if not include_system and entry.name.lower() in SKIP_PROFILES:
            continue
        profile = str(entry)
        seen_paths.add(os.path.normcase(profile))
        sid = sid_for_profile(profile, plist)
        name = lookup_account_sid(sid) or entry.name
        view: Optional[HiveView] = None
        if sid and sid in loaded_hku and winreg is not None:
            view = LiveHiveView(loaded_hku[sid])
        else:
            hive = entry / "NTUSER.DAT"
            if hive.is_file():
                try:
                    view = open_offline_hive(str(hive))
                except OSError as exc:
                    errors.append(CollectionError(scope=str(hive), message=str(exc)))
        contexts.append(
            UserContext(
                user=name,
                sid=sid,
                profile_path=profile,
                appdata=str(entry / "AppData" / "Roaming"),
                localappdata=str(entry / "AppData" / "Local"),
                hive_view=view,
                privilege=privilege_for_sid(sid),
            )
        )
    contexts.extend(_profilelist_contexts(plist, loaded_hku, seen_paths, errors))
    return contexts


# ===========================================================================
# Related notes (static - no event-log dump)
# ===========================================================================
RELATED_NOTES = [
    "Scope is interactive command-line history only: what a human typed at a shell prompt.",
    "Intention.py does not record non-interactive, service, scheduled-task, WinRM, or in-process runspace activity.",
    "Absence of rows is not evidence that no shell ran.",
    "Native cmd.exe history is session-volatile (conhost/doskey buffer). Persistent CMD rows appear only with Clink, Cmder, or an incidental history file.",
    "PSReadLine history has no per-command timestamp. File MTIME is applied to the last line only; every earlier line is order_only.",
    "bash normally flushes its history on a clean `exit`. A WSL or Git Bash window closed with the X button can lose that session's commands entirely.",
    "Per-command times exist only where the shell wrote them: Clink '# epoch', bash HISTTIMEFORMAT, zsh EXTENDED_HISTORY, fish 'when'. Nothing here is inferred.",
    "WSL2 history lives inside ext4.vhdx. This tool inventories the VHDX and reads \\\\wsl$ only when the share is already answering; it never mounts read-write.",
    "Related execution telemetry (NOT collected here, by design): Security 4688 command-line auditing, Sysmon 1, PowerShell 4103/4104 script-block logging, transcripts, Prefetch, BAM/DAM, AmCache, SRUM.",
    "Explorer MRU surfaces (RunMRU, TypedPaths, ComDlg32, WordWheelQuery) are not command-line history; they are available only under --legacy-explorer.",
]


# ===========================================================================
# Rendering
# ===========================================================================
def harden_console_encoding() -> None:
    """Make console writes degrade instead of aborting the run.

    On Windows a real console is written as UTF-16 via WriteConsoleW, but a
    REDIRECTED stdout (`> out.txt`, a pipe) uses the ANSI code page - normally
    cp1252 - with errors="strict". Any character outside that page then raises
    UnicodeEncodeError.

    The source's own literals are ASCII (enforced by --selftest), but the data
    is not: a recovered command line can hold an accented path, Cyrillic, or
    CJK. Collection has already finished by the time anything is printed, so an
    unencodable character must never destroy the run - it degrades to the
    stream's replacement character instead.

    This affects console streams only. The report file is opened separately and
    explicitly as UTF-8, so it still carries the exact characters.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError, ValueError):
            pass  # not a reconfigurable TextIOWrapper; nothing to harden


def try_rich():
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text

        return Console, Table, Panel, Text
    except ImportError:
        return None


BANNER_SCOPE = (
    "Intention.py records interactive command-line histories (CMD/Clink, "
    "PSReadLine, bash/zsh/fish on WSL and POSIX-on-Windows ports). It does "
    "not record non-interactive, service, scheduled-task, WinRM, or "
    "in-process runspace activity. Absence of rows is not evidence that no "
    "shell ran."
)


def banner_text(meta: dict[str, Any], redact: bool) -> str:
    lines = [
        f"Intention.py {VERSION}",
        f"Hostname        : {meta.get('hostname', '')}",
        f"Collection UTC  : {meta.get('collected_utc', '')}",
        f"Current user    : {meta.get('current_user', '')}",
        f"OS              : {meta.get('os', '')}",
        f"Collector elevated: {meta.get('elevated', '')}   (this tool's own token, NOT a property of any collected session)",
        f"Scope           : {meta.get('scope', 'cli_history')}",
        f"Sources         : {', '.join(meta.get('sources', []))}",
        f"Redaction       : {'ON' if redact else 'OFF (forensic default)'}",
        "",
        BANNER_SCOPE,
        "",
        "Timestamp caveat: history-file MTIME applies to the last appended line only. "
        "Read timestamp_provenance on every row; a blank timestamp means the artifact "
        "carried no time and none was invented.",
    ]
    if meta.get("wsl_exec"):
        lines.extend(
            [
                "",
                "WARNING: --wsl-exec is enabled. Reading history through `wsl.exe -d "
                "<distro> -e cat` STARTS A STOPPED DISTRO and changes VM state, "
                "filesystem access times, and boot artifacts inside the guest.",
            ]
        )
    if meta.get("legacy_explorer"):
        lines.extend(
            [
                "",
                "NOTE: --legacy-explorer is enabled. Explorer MRU tables are shown; "
                "these are UI intent, not command-line history.",
            ]
        )
    return "\n".join(lines)


@dataclass
class InstallRecord:
    """One software installation registration found on the host."""

    display_name: str
    version: str = ""
    install_date: str = ""      # normalised to YYYY-MM-DD where parseable
    install_location: str = ""
    publisher: str = ""
    source: str = ""            # where the record came from
    key_lastwrite: str = ""
    # Package-manager records only: is this a live install or leftovers?
    install_state: str = ""
    state_evidence: str = ""

    def summary(self) -> str:
        bits = [self.display_name or "(unnamed)"]
        if self.install_state and self.install_state != INSTALL_STATE_INSTALLED:
            bits.append(f"[{self.install_state}: {self.state_evidence}]")
        if self.version:
            bits.append(f"v{self.version}")
        if self.install_date:
            bits.append(f"installed {self.install_date}")
        if self.publisher:
            bits.append(f"publisher={self.publisher}")
        if self.install_location:
            bits.append(f"location={self.install_location}")
        bits.append(f"via {self.source}")
        return "  ".join(bits)


UNINSTALL_REL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
UNINSTALL_REL_WOW = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
MSI_USERDATA_REL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData"

def _norm_install_date(raw: str) -> str:
    """ARP InstallDate is usually YYYYMMDD; leave anything else alone."""
    text = str(raw or "").strip()
    if re.fullmatch(r"\d{8}", text):
        return f"{text[0:4]}-{text[4:6]}-{text[6:8]}"
    return text


def _record_from_values(vals: dict[str, RegValue], source: str, lastwrite: Any) -> Optional[InstallRecord]:
    name = _reg_str(vals, "DisplayName")
    if not name.strip():
        return None
    return InstallRecord(
        display_name=name.strip(),
        version=_reg_str(vals, "DisplayVersion").strip(),
        install_date=_norm_install_date(_reg_str(vals, "InstallDate")),
        install_location=_reg_str(vals, "InstallLocation").strip(),
        publisher=_reg_str(vals, "Publisher").strip(),
        source=source,
        key_lastwrite=iso_utc(lastwrite),
    )


def scan_uninstall_keys(view: Optional[HiveView], rel: str, source: str) -> list[InstallRecord]:
    """Enumerate an Uninstall hive. Read-only; never opens for write."""
    out: list[InstallRecord] = []
    if view is None:
        return out
    root = view.open_key(rel)
    if root is None:
        return out
    for sub in root.subkeys:
        snap = view.open_subkey(rel, sub)
        if snap is None:
            continue
        record = _record_from_values(snap.values, source, snap.last_write)
        if record is not None:
            out.append(record)
    return out


def scan_msi_userdata(view: Optional[HiveView]) -> list[InstallRecord]:
    """MSI InstallProperties under Installer\\UserData.

    Worth reading separately from the ARP list: these product records can
    outlive a clean uninstall, so they sometimes evidence software that is no
    longer present.
    """
    out: list[InstallRecord] = []
    if view is None:
        return out
    root = view.open_key(MSI_USERDATA_REL)
    if root is None:
        return out
    for sid in root.subkeys:
        products_rel = f"{MSI_USERDATA_REL}\\{sid}\\Products"
        products = view.open_key(products_rel)
        if products is None:
            continue
        for code in products.subkeys:
            props = view.open_key(f"{products_rel}\\{code}\\InstallProperties")
            if props is None:
                continue
            record = _record_from_values(props.values, "MSI InstallProperties", props.last_write)
            if record is not None:
                out.append(record)
    return out


def _python_scripts_dirs(ctx: UserContext) -> list[Path]:
    """Scripts directories of Python installs that could hold a shell entry point.

    Covers the per-user installer layout, the Store/py-launcher layout,
    virtualenvs are out of scope (unbounded), and conda environments.
    Directories are returned whether or not they exist; the caller filters.
    """
    profile = Path(ctx.profile_path) if ctx.profile_path else None
    localapp = Path(ctx.localappdata) if ctx.localappdata else None
    out: list[Path] = []
    if localapp is not None:
        programs = localapp / "Programs" / "Python"
        try:
            if programs.is_dir():
                out.extend(child / "Scripts" for child in programs.iterdir() if child.is_dir())
        except OSError:
            pass
        # pip --user installs
        pkgs = localapp / "Packages"
        try:
            if pkgs.is_dir():
                for child in pkgs.iterdir():
                    if child.is_dir() and child.name.lower().startswith("pythonsoftwarefoundation"):
                        out.append(child / "LocalCache" / "local-packages" / "Scripts")
        except OSError:
            pass
    if profile is not None:
        out.append(profile / "AppData" / "Roaming" / "Python" / "Scripts")
        for conda in ("anaconda3", "miniconda3", "miniforge3"):
            out.append(profile / conda / "Scripts")
            out.append(profile / conda / "condabin")
    for drive_root in ("ProgramFiles",):
        base = os.environ.get(drive_root)
        if base:
            out.append(Path(base) / "Python" / "Scripts")
    return _dedup_paths(out)


def package_manager_roots(
    ctx: UserContext, include_machine_scope: bool = True
) -> list[tuple[str, Path, str]]:
    """(source label, directory holding one entry per package, entry kind).

    Every path is built with pathlib joins rather than embedded separators, so
    the discovery logic is testable off-Windows. Each manager's environment
    override is honoured, because a relocated scoop or cargo root is exactly
    the kind of thing a portable setup uses.

    kind is "dir" when each child directory is one package, or "file" when
    each child file is one installed binary (cargo, winget Links).
    """
    profile = Path(ctx.profile_path) if ctx.profile_path else None
    localapp = Path(ctx.localappdata) if ctx.localappdata else None
    programdata = Path(os.environ.get("ProgramData", "C:\\ProgramData"))
    program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")

    roots: list[tuple[str, Path, str]] = []

    # scoop - user scope, then global, honouring SCOOP / SCOOP_GLOBAL
    scoop_home = os.environ.get("SCOOP")
    if scoop_home:
        roots.append(("scoop", Path(scoop_home) / "apps", "dir"))
    elif profile is not None:
        roots.append(("scoop", profile / "scoop" / "apps", "dir"))
    if include_machine_scope:
        scoop_global = os.environ.get("SCOOP_GLOBAL")
        roots.append(
            ("scoop (global)", Path(scoop_global) / "apps" if scoop_global
             else programdata / "scoop" / "apps", "dir")
        )

    # chocolatey
    if include_machine_scope:
        choco = os.environ.get("ChocolateyInstall")
        roots.append(
            ("chocolatey", Path(choco) / "lib" if choco else programdata / "chocolatey" / "lib", "dir")
        )

    # winget portable packages: <PackageId>_<Source>_<hash> per directory
    if localapp is not None:
        roots.append(("winget (portable)", localapp / "Microsoft" / "WinGet" / "Packages", "dir"))
    if include_machine_scope:
        roots.append(("winget (portable)", Path(program_files) / "WinGet" / "Packages", "dir"))
        roots.append(("winget (portable)", Path(program_files_x86) / "WinGet" / "Packages", "dir"))

    # cargo install drops binaries straight into bin/ and registers nothing
    cargo_home = os.environ.get("CARGO_HOME")
    if cargo_home:
        roots.append(("cargo", Path(cargo_home) / "bin", "file"))
    elif profile is not None:
        roots.append(("cargo", profile / ".cargo" / "bin", "file"))

    # pip / conda: xonsh is a Python package first and a scoop/winget package
    # second, so `pip install xonsh` is a realistic - arguably the dominant -
    # install route for it. Entry-point executables land in a Scripts dir.
    for base in _python_scripts_dirs(ctx):
        roots.append(("pip/conda", base, "file"))
    return roots




def _winget_package_id(dir_name: str) -> str:
    """'Nushell.Nushell_Microsoft.Winget.Source_8wekyb3d8bbwe' -> 'Nushell.Nushell'."""
    return dir_name.split("_", 1)[0]


def _scoop_version(app_dir: Path) -> str:
    """Newest version directory under a scoop app ('current' is a junction)."""
    try:
        versions = sorted(
            d.name for d in app_dir.iterdir() if d.is_dir() and d.name.lower() != "current"
        )
    except OSError:
        return ""
    return versions[-1] if versions else ""


def classify_install_state(entry: Path, label: str, kind: str) -> tuple[str, str]:
    """Is this a live install or leftovers? Returns (state, evidence).

    Verified against each manager's documented uninstall behaviour:
      * chocolatey tracks a package as the files in lib\\<pkg>; uninstall
        removes them, but empty lib folders left behind are a documented
        outcome, so an empty lib\\<pkg> is a remnant, not an install.
      * scoop keeps user data in scoop\\persist\\<app> across uninstall, so
        persist without a live app directory is positive remnant evidence.
        A live app has a version directory holding the binary.
      * cargo, pip and winget-portable ARE the executable: the entry point is
        the evidence, and its absence makes the directory leftovers.
    """
    try:
        if kind == "file":
            return (INSTALL_STATE_INSTALLED, "entry-point executable present") if entry.is_file() \
                else (INSTALL_STATE_REMNANT, "entry point missing")
        children = list(entry.iterdir())
    except OSError as exc:
        return INSTALL_STATE_AMBIGUOUS, f"directory unreadable ({exc.__class__.__name__})"
    if not children:
        return INSTALL_STATE_REMNANT, "package directory is empty"
    names = {c.name.lower() for c in children}
    if label.startswith("chocolatey"):
        if any(n.endswith(".nuspec") for n in names):
            return INSTALL_STATE_INSTALLED, "nuspec install receipt present"
        return INSTALL_STATE_REMNANT, "no nuspec receipt in the package directory"
    if label.startswith("scoop"):
        versions = [c for c in children if c.is_dir() and c.name.lower() != "current"]
        for version_dir in versions:
            try:
                inner = {c.name.lower() for c in version_dir.iterdir()}
            except OSError:
                continue
            if any(n.endswith(".exe") for n in inner):
                return INSTALL_STATE_INSTALLED, f"binary present in {version_dir.name}"
            if "manifest.json" in inner:
                return INSTALL_STATE_AMBIGUOUS, "manifest present but no binary found"
        return INSTALL_STATE_REMNANT, "no version directory holds a binary"
    if label.startswith("winget"):
        if any(n.endswith(".exe") for n in names):
            return INSTALL_STATE_INSTALLED, "portable executable present"
        return INSTALL_STATE_REMNANT, "no executable in the portable package directory"
    return INSTALL_STATE_AMBIGUOUS, "no differential rule for this source"


def scan_package_managers(
    ctx: UserContext, include_machine_scope: bool = True
) -> list[InstallRecord]:
    """Installs from scoop, winget portables, chocolatey and cargo.

    These leave no Uninstall key, and they are how nushell, elvish, xonsh and
    atuin normally arrive on Windows - so registry-only detection is blind to
    exactly the shells this tool exists to find.

    The date is the package directory's creation time, which is the install
    time on Windows (st_ctime). It is evidence of installation, not an
    installer-reported InstallDate.
    """
    out: list[InstallRecord] = []
    for label, root, kind in package_manager_roots(ctx, include_machine_scope):
        try:
            if not root.is_dir():
                continue
            entries = sorted(root.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if kind == "dir" and not entry.is_dir():
                    continue
                if kind == "file" and not entry.is_file():
                    continue
            except OSError:
                continue
            if label.startswith("winget"):
                name = _winget_package_id(entry.name)
            elif kind == "file":
                name = entry.stem
            else:
                name = entry.name
            version = _scoop_version(entry) if label.startswith("scoop") else ""
            state, evidence = classify_install_state(entry, label, kind)
            times = file_times(entry)
            out.append(
                InstallRecord(
                    display_name=name,
                    version=version,
                    install_date=(times.get("ctime_utc") or "")[:10],
                    install_location=str(entry),
                    source=label,
                    install_state=state,
                    state_evidence=evidence,
                    key_lastwrite=times.get("mtime_utc", ""),
                )
            )
    return out


PACKAGE_SOURCES = (
    "scoop",
    "scoop (global)",
    "chocolatey",
    "winget (portable)",
    "cargo",
    "pip/conda",
)


def collect_installations(
    ctx: UserContext,
    machine_view: Optional[HiveView] = None,
    include_machine_scope: bool = True,
) -> list[InstallRecord]:
    """Every installation registration we can read, deduplicated."""
    records: list[InstallRecord] = []
    records.extend(scan_uninstall_keys(machine_view, UNINSTALL_REL, "HKLM Uninstall"))
    records.extend(scan_uninstall_keys(machine_view, UNINSTALL_REL_WOW, "HKLM Uninstall (WOW6432)"))
    records.extend(scan_uninstall_keys(ctx.hive_view, UNINSTALL_REL, "HKCU Uninstall"))
    records.extend(scan_msi_userdata(machine_view))
    records.extend(scan_package_managers(ctx, include_machine_scope))
    seen: set[tuple[str, str, str]] = set()
    unique: list[InstallRecord] = []
    for r in records:
        key = (r.display_name.lower(), r.version, r.source)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def match_installation(
    records: list[InstallRecord], pattern: str, pkg_names: tuple[str, ...] = ()
) -> Optional[InstallRecord]:
    """Best installation record for one catalogued terminal.

    Registry records match the ARP display name or the publisher by regex.
    Package-manager records match the package name EXACTLY: scoop calls
    nushell 'nu', which is far too short to regex safely against arbitrary
    software ('Nuance PDF Reader' would match). winget package directories
    are '<PackageId>_<Source>_<hash>', so 'Nushell.Nushell' is also tried on
    its last dotted component.
    """
    if not pattern and not pkg_names:
        return None
    rx = re.compile(pattern, re.I) if pattern else None
    wanted = {n.lower() for n in pkg_names}
    hits: list[InstallRecord] = []
    for record in records:
        if record.source in PACKAGE_SOURCES:
            name = record.display_name.lower()
            if name in wanted or name.rsplit(".", 1)[-1] in wanted:
                hits.append(record)
            continue
        if rx is not None and (
            rx.search(record.display_name)
            or (record.publisher and rx.search(record.publisher))
        ):
            hits.append(record)
    if not hits:
        return None
    dated = [h for h in hits if h.install_date]
    return sorted(dated or hits, key=lambda r: r.install_date, reverse=True)[0]


@dataclass
class PresenceRow:
    """One line of the inventory table: Type | Presence | LastWrite."""

    type_name: str
    presence: str
    last_write: str
    installed: str = ""
    install_detail: str = ""
    commands: int = 0
    unparsed: int = 0
    deleted: int = 0
    noun: str = "entries"
    unanswered: int = 0
    empty_artifacts: int = 0

    @property
    def detail(self) -> str:
        """Presence cell text, with counts folded in."""
        if self.presence == PRESENCE_UNANSWERED:
            return f"{PRESENCE_UNANSWERED} ({self.unanswered} path(s))"
        if self.presence == PRESENCE_ABSENT and self.empty_artifacts:
            # An empty history file is evidence of clearing, not of absence.
            return f"None recovered ({self.empty_artifacts} empty artifact(s) present)"
        if self.presence != PRESENCE_PRESENT:
            return self.presence
        bits: list[str] = []
        if self.commands:
            noun = self.noun
            if self.commands == 1 and noun == "entries":
                noun = "entry"
            bits.append(f"{self.commands} {noun}")
        if self.deleted:
            bits.append(f"{self.deleted} recoverable deleted")
        if self.unparsed:
            bits.append(f"{self.unparsed} unreadable store{'s' if self.unparsed > 1 else ''}")
        return f"{PRESENCE_PRESENT} ({', '.join(bits)})" if bits else PRESENCE_PRESENT


def _iter_meta_paths(node: Any) -> Iterator[str]:
    """Walk a header_meta structure yielding artifact paths and registry keys.

    merge_blocks nests per-user metadata, so this has to recurse rather than
    read the top level only.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("path", "registry_key") and isinstance(value, str) and value:
                yield value
            elif key == "files" and isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item:
                        yield item
            else:
                yield from _iter_meta_paths(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_meta_paths(item)


def collected_source_paths(blocks: list[SourceBlock]) -> list[str]:
    """Artifact paths that actually contributed rows, in stable order."""
    seen: set[str] = set()
    out: list[str] = []
    for block in blocks:
        if not block.rows or block.name == "CollectionErrors":
            continue
        for path in _iter_meta_paths(block.header_meta):
            key = path.lower()
            if key not in seen:
                seen.add(key)
                out.append(path)
    return out


def _newest_timestamp(block: SourceBlock) -> str:
    """Most recent instant associated with a block, for the LastWrite column."""
    candidates: list[str] = []
    for row in block.rows:
        if row.utc_timestamp:
            candidates.append(row.utc_timestamp)
        if row.key_lastwrite_utc:
            candidates.append(row.key_lastwrite_utc)
    for key in ("mtime_utc", "ctime_utc"):
        value = block.header_meta.get(key)
        if isinstance(value, str) and value:
            candidates.append(value)
    for meta in block.header_meta.get("per_file", []) or []:
        if isinstance(meta, dict):
            value = meta.get("mtime_utc")
            if isinstance(value, str) and value:
                candidates.append(value)
    return max(candidates) if candidates else ""


def build_presence(
    blocks: list[SourceBlock],
    sources: set[str],
    installs: Optional[list[InstallRecord]] = None,
) -> list[PresenceRow]:
    """One row per catalogued terminal type, whether or not it was found."""
    installs = installs or []
    by_name = {b.name: b for b in blocks}
    catalogued: set[str] = set()
    out: list[PresenceRow] = []

    def tally(present: list[SourceBlock]) -> tuple[int, int, int, str]:
        unparsed = sum(
            1
            for b in present
            for r in b.rows
            if r.timestamp_provenance == PROV_UNAVAILABLE
        )
        deleted = sum(
            1 for b in present for r in b.rows if "deleted_entry=1" in r.extra
        )
        commands = sum(len(b.rows) for b in present) - unparsed
        stamps = [s for s in (_newest_timestamp(b) for b in present) if s]
        return commands, unparsed, deleted, (max(stamps) if stamps else "")

    for type_name, family, block_names, pattern, pkg_names in TERMINAL_CATALOG:
        catalogued.update(block_names)
        present = [by_name[n] for n in block_names if n in by_name]
        commands, unparsed, deleted, last_write = tally(present)
        if pattern == BUILTIN_INSTALL:
            installed, install_detail = "built-in", "ships with Windows; no Uninstall entry"
        else:
            record = match_installation(installs, pattern, pkg_names)
            if record is None:
                installed, install_detail = "", ""
            else:
                installed = record.install_date or "yes"
                install_detail = record.summary()

        # WSL-Inventory rows are registered distros, not typed commands.
        # Some tables hold records rather than typed commands: WSL distros and
        # config findings both carry provenance "unavailable" by design, which
        # must not be reported as an unreadable store.
        if block_names == ("WSL-Inventory",):
            noun = "distros registered"
        elif block_names == ("History-Location",):
            noun = "declared paths"
        elif block_names == ("History-Policy",):
            noun = "settings"
        else:
            noun = "entries"
        if noun != "entries":
            commands, unparsed = commands + unparsed, 0

        unanswered = sum(
            block_absence_summary(b).get(outcome, 0)
            for b in present
            for outcome in ABSENCE_UNANSWERED
        )
        empties = sum(block_absence_summary(b).get(ABSENCE_PRESENT_EMPTY, 0) for b in present)
        if type_name.startswith("CMD (native"):
            # cmd.exe history lives in the conhost session buffer and never
            # reaches disk. Absence here is a property of Windows, not a finding.
            presence = PRESENCE_VOLATILE
        elif family not in sources:
            presence = PRESENCE_NOT_CHECKED
        elif commands or unparsed:
            presence = PRESENCE_PRESENT
        elif unanswered:
            # A path that could not be read is an open question, never absence.
            presence = PRESENCE_UNANSWERED
        else:
            presence = PRESENCE_ABSENT
        out.append(
            PresenceRow(
                type_name=type_name,
                presence=presence,
                last_write=last_write,
                installed=installed,
                install_detail=install_detail,
                commands=commands,
                unparsed=unparsed,
                deleted=deleted,
                noun=noun,
                unanswered=unanswered,
                empty_artifacts=empties,
            )
        )

    # Anything collected but not catalogued (custom PSReadLine hosts, new
    # ports) still has to appear, or the inventory would understate the host.
    leftovers = [
        b
        for b in blocks
        if b.name not in catalogued and b.name != "CollectionErrors" and b.rows
    ]
    if leftovers:
        commands, unparsed, deleted, last_write = tally(leftovers)
        out.append(
            PresenceRow(
                type_name=f"Other hosts ({', '.join(b.name for b in leftovers)})",
                presence=PRESENCE_PRESENT,
                last_write=last_write,
                commands=commands,
                unparsed=unparsed,
                deleted=deleted,
            )
        )
    return out


def catalog_label(block_name: str) -> str:
    """Map a source block back to its catalogued display type, for report headers."""
    for type_name, _family, block_names, _pattern, _pkgs in TERMINAL_CATALOG:
        if block_name in block_names:
            return type_name
    return block_name




def display_safe(value: str) -> str:
    """Escape terminal control characters in anything shown to a human.

    A recovered command can contain raw ESC. Printed to a terminal - or read
    back with `cat`/`type` - an OSC or CSI sequence can retitle the window,
    clear the screen, or hide text from the examiner. Escaping renders the
    bytes visible instead of letting the terminal act on them.

    Applies to DISPLAYED values only: terminal output and the .txt report.
    raw_value in the JSON export keeps the original bytes, so nothing is lost.
    """
    if not value:
        return value
    out: list[str] = []
    for ch in value:
        code = ord(ch)
        if ch in _CONTROL_KEEP:
            out.append(ch)
        elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


# ===========================================================================
# ATT&CK technique mapping
#
# Ties what this run actually observed to MITRE ATT&CK techniques.
#
# TECHNIQUES ONLY. No threat-group data of any kind - no group names, no
# G#### identifiers, no campaign names, no "commonly associated with" prose.
# Two reasons, both settled after reviewing ATT&CK and the literature:
#
#   1. It would carry no information. ATT&CK has no sub-technique for zsh,
#      fish, nushell, xonsh or elvish; they collapse into T1059.004 or the
#      T1059 parent. A group list attached to those techniques describes the
#      whole bucket, not the shell that was found.
#   2. It invites fabricated specificity. Group-to-technique listings read as
#      group-to-artifact claims, and the gap gets filled with invented case
#      studies. Techniques are stable and evidence-backed; groups are neither
#      at this resolution.
#
# The table is static and in-file. Nothing here touches the network: this tool
# runs on evidence machines and offline images.
# ===========================================================================
ATTACK_VERSION = "v19.2"

TACTIC_EXECUTION = "Execution"
TACTIC_DEFENSE_EVASION = "Defense Evasion"
TACTIC_CREDENTIAL_ACCESS = "Credential Access"

ATTACK_TACTICS = (TACTIC_EXECUTION, TACTIC_DEFENSE_EVASION, TACTIC_CREDENTIAL_ACCESS)

ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# technique id -> (name, tactic)
ATTACK_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1059": ("Command and Scripting Interpreter", TACTIC_EXECUTION),
    "T1059.001": ("PowerShell", TACTIC_EXECUTION),
    "T1059.003": ("Windows Command Shell", TACTIC_EXECUTION),
    "T1059.004": ("Unix Shell", TACTIC_EXECUTION),
    "T1202": ("Indirect Command Execution", TACTIC_DEFENSE_EVASION),
    "T1070.003": ("Clear Command History", TACTIC_DEFENSE_EVASION),
    "T1552.003": ("Shell History", TACTIC_CREDENTIAL_ACCESS),
}

# Which collected blocks imply which technique. Recovered history only - a
# table that was checked and found empty implies nothing.
ATTACK_BLOCK_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("T1059.003", ("CMD-LiveDoskey", "CMD-Clink", "CMD-Cmder", "CMD-ConEmu",
                   "CMD-WindowsTerminal", "CMD")),
    ("T1059.001", ("Powershell", "Powershell-Pwsh", "Powershell-VSCodeHost",
                   "Powershell-ISE", "Powershell-WindowsTerminal")),
    ("T1059.004", ("Bash-Git", "Bash-MSYS2", "Bash-Cygwin",
                   "Zsh-Git", "Zsh-MSYS2", "Zsh-Cygwin",
                   "Fish-Git", "Fish-MSYS2", "Fish-Cygwin",
                   "Ash-Git", "Ash-MSYS2", "Ash-Cygwin",
                   "Sh-Git", "Sh-MSYS2", "Sh-Cygwin",
                   "WSL-Bash", "WSL-Zsh", "WSL-Fish", "WSL-Ash")),
    # xonsh is a Python-based shell, so T1059.006 Python is arguable. It is
    # mapped to the T1059 parent instead: what the tool observes is a history
    # file belonging to an interpreter ATT&CK does not enumerate, and the
    # Python sub-technique describes executing Python payloads, which is a
    # different claim from "this user's interactive shell was xonsh".
    ("T1059", ("Nushell", "Xonsh", "Elvish", "Oil", "Ion")),
    ("T1202", ("WSL-Inventory",)),
    ("T1552.003", ()),  # handled separately: any recovered shell history
]

# Config effects that indicate history destruction rather than mere policy.
ATTACK_POLICY_EFFECTS = (EFFECT_CLEARS_ON_EXIT, EFFECT_SUPPRESSES)

ATTACK_CAVEAT = (
    "These techniques describe what the observed artifacts COULD support, not that an "
    "intrusion occurred. Most hosts running Git Bash are running Git Bash. Techniques "
    "only: this tool makes no threat-group or attribution claims."
)

OBSCURE_SHELL_NOTE = (
    "nushell, xonsh, elvish, oils and ion have no ATT&CK sub-technique and map to the "
    "T1059 parent. They are a DETECTION GAP, not a documented adversary tool: shell "
    "built-ins spawn no process, so a cd, loop or redirect inside them produces no "
    "process-creation event (4688 / Sysmon 1) at all, and their history formats are not "
    "parsed by standard tooling. Their presence indicates a developer or power user."
)


@dataclass
class AttackFinding:
    """One technique, and the concrete evidence that produced it."""

    technique: str
    name: str
    tactic: str
    basis: str


def map_attack_techniques(blocks: list[SourceBlock]) -> list[AttackFinding]:
    """Derive technique rows from what this run collected.

    A row is emitted only when an observation actually fired; an empty result
    is the correct outcome on a clean host. Every row carries a traceable
    basis - a technique without one is a bug, not a finding.
    """
    by_name = {b.name: b for b in blocks}

    def rows_in(names: tuple[str, ...]) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        for name in names:
            block = by_name.get(name)
            if block is not None and block.rows:
                out.append((name, len(block.rows)))
        return out

    findings: list[AttackFinding] = []
    history_total = 0
    history_sources: list[str] = []

    for technique, block_names in ATTACK_BLOCK_RULES:
        if not block_names:
            continue
        hits = rows_in(block_names)
        if not hits:
            continue
        if technique == "T1202":
            distros = sum(count for _n, count in hits)
            basis = f"WSL-Inventory: {distros} distro(s) registered"
        else:
            detail = ", ".join(f"{name} ({count})" for name, count in hits)
            total = sum(count for _n, count in hits)
            basis = f"{total} recovered entr{'y' if total == 1 else 'ies'} from {detail}"
            history_total += total
            history_sources.extend(name for name, _c in hits)
        name, tactic = ATTACK_TECHNIQUES[technique]
        findings.append(AttackFinding(technique, name, tactic, basis))

    # Atuin is a history store rather than a shell: it contributes to the
    # credential-access mapping but implies no interpreter of its own.
    atuin = by_name.get("Atuin")
    if atuin is not None and atuin.rows:
        history_total += len(atuin.rows)
        history_sources.append("Atuin")

    # Recovered history of any kind is where credentials sit.
    if history_total:
        name, tactic = ATTACK_TECHNIQUES["T1552.003"]
        findings.append(
            AttackFinding(
                "T1552.003", name, tactic,
                f"{history_total} recovered entries across "
                f"{len(set(history_sources))} source(s); recovered history may contain "
                "credentials, tokens or connection strings",
            )
        )

    # Declared history destruction, from the config scanner.
    policy = by_name.get("History-Policy")
    if policy is not None and policy.rows:
        destructive: list[str] = []
        for row in policy.rows:
            for part in row.extra.split("; "):
                if part.startswith("effect=") and part[len("effect="):] in ATTACK_POLICY_EFFECTS:
                    destructive.append(row.value_name)
        if destructive:
            name, tactic = ATTACK_TECHNIQUES["T1070.003"]
            shown = ", ".join(sorted(set(destructive))[:4])
            more = len(set(destructive)) - 4
            findings.append(
                AttackFinding(
                    "T1070.003", name, tactic,
                    f"config declares history destruction at {shown}"
                    + (f" (+{more} more)" if more > 0 else ""),
                )
            )
    return findings


def attack_summary_lines(findings: list[AttackFinding]) -> list[str]:
    """Terminal table: Technique | Tactic | Observed because."""
    out = ["", f"ATT&CK TECHNIQUES OBSERVED (mapping authored against ATT&CK {ATTACK_VERSION})"]
    if not findings:
        out.append("  none - no observation in this run supports a technique mapping")
        return out
    w_id = max(len("Technique"), max(len(f"{f.technique} {f.name}") for f in findings))
    w_tac = max(len("Tactic"), max(len(f.tactic) for f in findings))
    out.append(f"  {'Technique':<{w_id}}  {'Tactic':<{w_tac}}  Observed because")
    for f in findings:
        label = f"{f.technique} {f.name}"
        out.append(f"  {label:<{w_id}}  {f.tactic:<{w_tac}}  {f.basis}")
    out.append(f"  {ATTACK_CAVEAT}")
    if any(f.technique == "T1059" for f in findings):
        out.append(f"  {OBSCURE_SHELL_NOTE}")
    return out


def config_summary_lines(blocks: list[SourceBlock], limit: int = 12) -> list[str]:
    """Compact HISTORY LOCATION / HISTORY POLICY tables for the terminal.

    Only populated rows are shown, with an explicit "none found" line when a
    table is empty - because "checked and found nothing" is a result and must
    be distinguishable from "never looked". Full per-line detail, with file and
    line number, lives in the report.
    """
    by_name = {b.name: b for b in blocks}
    out: list[str] = []

    def field(row: IntentRow, key: str) -> str:
        for part in row.extra.split("; "):
            if part.startswith(key + "="):
                return part[len(key) + 1:]
        return ""

    loc = by_name.get("History-Location")
    if loc is not None:
        out.append("")
        out.append("HISTORY LOCATION (declared in configuration; volume read at collection time)")
        if not loc.rows:
            out.append(f"  {loc.empty_reason or 'none found'}")
        else:
            w_sh = max(len("Shell"), max(len(r.shell) for r in loc.rows))
            out.append(f"  {'Shell':<{w_sh}}  {'Volume':<16}  Setting")
            for row in loc.rows[:limit]:
                flag = " (*)" if field(row, "cross_check") else ""
                out.append(
                    f"  {row.shell:<{w_sh}}  {field(row, 'volume'):<16}  "
                    f"{display_safe(row.typed_value)[:60]}{flag}"
                )
            if len(loc.rows) > limit:
                out.append(f"  ... {len(loc.rows) - limit} more in the report")
            if any(field(r, "cross_check") for r in loc.rows):
                out.append("  (*) declared path was not among the artifacts collected on this host")

    pol = by_name.get("History-Policy")
    if pol is not None:
        out.append("")
        out.append("HISTORY POLICY (suppression / filtering / destruction)")
        if not pol.rows:
            out.append(f"  {pol.empty_reason or 'none found'}")
        else:
            notable = [r for r in pol.rows
                       if field(r, "effect") not in (EFFECT_PRESERVES, EFFECT_DEFAULT)]
            counts: dict[str, int] = {}
            for row in pol.rows:
                counts[field(row, "effect")] = counts.get(field(row, "effect"), 0) + 1
            out.append("  " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items()) if k))
            w_sh = max(len("Shell"), max(len(r.shell) for r in pol.rows))
            for row in (notable or pol.rows)[:limit]:
                out.append(
                    f"  {row.shell:<{w_sh}}  {field(row, 'effect'):<15}  "
                    f"{display_safe(row.typed_value)[:60]}"
                )
            if len(notable or pol.rows) > limit:
                out.append(f"  ... {len(notable or pol.rows) - limit} more in the report")
            out.append("  Absence of suppression config is not evidence of absence.")
    return out


def render_summary_plain(
    blocks: list[SourceBlock],
    meta: dict[str, Any],
    presence: list[PresenceRow],
    errors: list[CollectionError],
    report_path: Optional[Path],
    redact: bool,
) -> None:
    print(banner_text(meta, redact))
    print()
    print("TERMINAL / SHELL INVENTORY")
    w_type = max([len("Type")] + [len(p.type_name) for p in presence])
    w_pres = max([len("Presence")] + [len(p.detail) for p in presence])
    header = f"{'Type':<{w_type}}  {'Presence':<{w_pres}}  {'LastWrite (lead)':<20}  Installed (lead)"
    print(header)
    print("-" * len(header))
    for row in presence:
        print(
            f"{row.type_name:<{w_type}}  {row.detail:<{w_pres}}  "
            f"{(row.last_write or '-'):<20}  {row.installed or '-'}"
        )
    print()
    print(INSTALLED_CAVEAT)

    for line in attack_summary_lines(map_attack_techniques(blocks)):
        print(line)

    for line in config_summary_lines(blocks):
        print(line)

    paths = collected_source_paths(blocks)
    print()
    print(f"SOURCES COLLECTED ({len(paths)})")
    if paths:
        for path in paths:
            print(f"  - {path}")
    else:
        print("  (none - no command-line history artifacts were readable on this host)")

    if errors:
        print()
        print(f"COLLECTION ERRORS ({len(errors)}) - detail in the report")
        for err in errors[:5]:
            print(f"  ! {err.scope}: {err.message}")
        if len(errors) > 5:
            print(f"  ... and {len(errors) - 5} more")

    # Future: ATT&CK technique / APT mapping per terminal renders here,
    # between the sources list and the report path.

    print()
    total = sum(len(b.rows) for b in blocks if b.name != "CollectionErrors")
    if report_path is not None:
        print(f"{total} history entries written to:")
        print(f"  {report_path}")
    else:
        print(f"{total} history entries collected; report file was NOT written.")


def render_summary_rich(
    blocks: list[SourceBlock],
    meta: dict[str, Any],
    presence: list[PresenceRow],
    errors: list[CollectionError],
    report_path: Optional[Path],
    redact: bool,
    no_color: bool,
) -> None:
    rich_mod = try_rich()
    if rich_mod is None:
        render_summary_plain(blocks, meta, presence, errors, report_path, redact)
        return
    Console, Table, Panel, _Text = rich_mod
    console = Console(no_color=no_color, highlight=False)
    console.print(Panel(banner_text(meta, redact), title="Intention.py", expand=False))

    table = Table(title="Terminal / Shell Inventory", expand=False)
    table.add_column("Type", no_wrap=True)
    table.add_column("Presence")
    table.add_column("LastWrite (lead)", no_wrap=True)
    table.add_column("Installed", no_wrap=True)
    for row in presence:
        if row.presence == PRESENCE_PRESENT:
            style = "green"
        elif row.presence == PRESENCE_VOLATILE:
            style = "yellow"
        elif row.presence == PRESENCE_NOT_CHECKED:
            style = "dim"
        else:
            style = None
        table.add_row(
            row.type_name,
            row.detail,
            row.last_write or "-",
            row.installed or "-",
            style=style,
        )
    console.print(table)
    console.print(f"[dim]{INSTALLED_CAVEAT}[/dim]")

    for line in attack_summary_lines(map_attack_techniques(blocks)):
        console.print(line)

    for line in config_summary_lines(blocks):
        console.print(line)

    paths = collected_source_paths(blocks)
    console.print(f"\n[bold]Sources collected ({len(paths)})[/bold]")
    if paths:
        for path in paths:
            console.print(f"  - {path}")
    else:
        console.print(
            "  [yellow](none - no command-line history artifacts were readable)[/yellow]"
        )

    if errors:
        console.print(f"\n[bold]Collection errors ({len(errors)})[/bold] - detail in the report")
        for err in errors[:5]:
            console.print(f"  [red]![/red] {err.scope}: {err.message}")
        if len(errors) > 5:
            console.print(f"  [dim]... and {len(errors) - 5} more[/dim]")

    # Future: ATT&CK technique / APT mapping per terminal renders here.

    total = sum(len(b.rows) for b in blocks if b.name != "CollectionErrors")
    if report_path is not None:
        console.print(f"\n{total} history entries written to:")
        console.print(f"  [bold]{report_path}[/bold]")
    else:
        console.print(f"\n[red]{total} history entries collected; report file was NOT written.[/red]")






def print_plain_table(block: SourceBlock, localtime: bool, max_rows: Optional[int]) -> None:
    print()
    print("=" * 78)
    print(f" {block.name}")
    print("=" * 78)
    if block.header_meta:
        for k, v in block.header_meta.items():
            print(f"  {k}: {v}")
    if not block.rows:
        print(f"  {block.empty_reason or 'No artifacts found'}")
        return
    rows = block.rows[: max_rows if max_rows else None]
    headers = ["#", "utc_timestamp", "provenance", "mru", "user", "typed_value", "extra"]
    if localtime:
        headers.insert(2, "local_timestamp")
    print("  " + " | ".join(headers))
    print("  " + "-+-".join("-" * len(h) for h in headers))
    for row in rows:
        cols = [
            str(row.mru_pos if row.mru_pos is not None else ""),
            row.utc_timestamp,
            row.timestamp_provenance,
            str(row.mru_pos if row.mru_pos is not None else ""),
            row.user,
            display_safe(row.typed_value).replace("\n", " \\n "),
            row.extra,
        ]
        # first # is display index = mru_pos
        if localtime:
            cols.insert(2, row.local_timestamp)
        print("  " + " | ".join(cols))
    if max_rows and len(block.rows) > max_rows:
        print(f"  ... truncated {len(block.rows) - max_rows} rows (--max-rows {max_rows})")


def print_rich_tables(
    blocks: list[SourceBlock],
    meta: dict[str, Any],
    redact: bool,
    localtime: bool,
    max_rows: Optional[int],
    no_color: bool,
) -> None:
    rich_mod = try_rich()
    if rich_mod is None:
        print(banner_text(meta, redact))
        for b in blocks:
            print_plain_table(b, localtime, max_rows)
        print()
        print("Notes / Related")
        for n in RELATED_NOTES:
            print(f"  - {n}")
        return
    Console, Table, Panel, _Text = rich_mod
    console = Console(no_color=no_color, highlight=False)
    console.print(Panel(banner_text(meta, redact), title="Intention.py", expand=False))
    for block in blocks:
        title = block.name
        table = Table(title=title, show_lines=False, expand=True)
        table.add_column("#", style="dim", no_wrap=True)
        table.add_column("utc_timestamp", no_wrap=True)
        if localtime:
            table.add_column("local_timestamp", no_wrap=True)
        table.add_column("provenance")
        table.add_column("user", no_wrap=True)
        table.add_column("typed_value")
        table.add_column("extra")
        if block.header_meta:
            meta_bits = " | ".join(f"{k}={v}" for k, v in block.header_meta.items() if not isinstance(v, (list, dict)))
            console.print(f"[dim]{meta_bits}[/dim]")
        if not block.rows:
            console.print(f"[yellow]{block.empty_reason or 'No artifacts found'}[/yellow]")
            continue
        shown = block.rows[: max_rows if max_rows else None]
        for row in shown:
            vals = [
                str(row.mru_pos if row.mru_pos is not None else ""),
                row.utc_timestamp,
            ]
            if localtime:
                vals.append(row.local_timestamp)
            vals.extend(
                [
                    row.timestamp_provenance,
                    row.user,
                    display_safe(row.typed_value).replace("\n", " \\n "),
                    row.extra,
                ]
            )
            table.add_row(*vals)
        console.print(table)
        if max_rows and len(block.rows) > max_rows:
            console.print(f"[dim]truncated {len(block.rows) - max_rows} rows[/dim]")
    console.print(Panel("\n".join(RELATED_NOTES), title="Notes / Related"))


_CONTROL_KEEP = {"\n", "\t"}




def open_exclusive(path: Path, newline: Optional[str] = None, encoding: str = "utf-8"):
    """Create an output file, refusing to write through anything that exists.

    Report names are predictable (host + UTC second), so an attacker on the
    box can pre-plant a symlink at the expected path. A plain open("w") follows
    it and truncates the target - and this tool is normally run elevated, which
    turns that into an arbitrary file write as administrator.

    O_EXCL fails on ANY existing path, symlink included, so the link is never
    followed. O_NOFOLLOW is added where the platform provides it.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "w", newline=newline, encoding=encoding)

def write_text_exclusive(path: Path, text: str, encoding: str = "utf-8") -> None:
    with open_exclusive(path, encoding=encoding) as fh:
        fh.write(text)

def free_output_path(base: Path, suffix: str, limit: int = 50) -> Path:
    """First unused <base><suffix>, or <base>_<n><suffix>. Never reuses a path.

    Returning a fresh name rather than overwriting keeps the O_EXCL guarantee
    meaningful: a pre-planted path is stepped over, not written through.
    """
    candidate = Path(str(base) + suffix)
    if not candidate.exists() and not candidate.is_symlink():
        return candidate
    for n in range(1, limit):
        candidate = Path(f"{base}_{n}{suffix}")
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    raise OSError(f"no free output path for {base}{suffix} after {limit} attempts")

def csv_safe(value: Any) -> Any:
    """Defuse a spreadsheet formula trigger without losing the character."""
    if not isinstance(value, str) or not value:
        return value
    if value[0] in CSV_FORMULA_LEADERS:
        return "'" + value
    return value


def export_json(path: Path, meta: dict[str, Any], blocks: list[SourceBlock], errors: list[CollectionError]) -> None:
    payload = {
        "meta": meta,
        "notes": RELATED_NOTES,
        "errors": [asdict(e) for e in errors],
        "attack": {
            "attack_version": ATTACK_VERSION,
            "caveat": ATTACK_CAVEAT,
            "techniques": [asdict(f) for f in map_attack_techniques(blocks)],
        },
        "sources": {
            b.name: {
                "header_meta": b.header_meta,
                "checked": b.checked,
                "empty_reason": b.empty_reason,
                "rows": [r.as_export() for r in b.rows],
            }
            for b in blocks
        },
    }
    write_text_exclusive(path, json.dumps(payload, indent=2, default=str))








# Characters that make a spreadsheet treat a cell as a formula. Shell history
# is attacker-influenced: anyone with shell access chooses what lands in it, so
# a command typed as =cmd|'/c calc'!A0 would execute when the examiner opens
# the CSV. Neutralised in the CSV writer ONLY - JSON, the .txt report and
# raw_value keep the byte-exact original.
CSV_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")
CSV_SANITISE_NOTE = (
    "CSV cells beginning with = + - @ TAB or CR are prefixed with an apostrophe "
    "to stop spreadsheets executing them as formulas. The JSON export and the "
    ".txt report carry the unmodified value."
)




# CSV column order. Must stay identical to the IntentRow field order - the
# selftest asserts parity, because these two lists have drifted apart before.
CSV_FIELDNAMES = [
    "source",
    "user",
    "sid",
    "profile_path",
    "value_name",
    "typed_value",
    "raw_value",
    "mru_pos",
    "utc_timestamp",
    "timestamp_provenance",
    "collected_utc",
    "key_lastwrite_utc",
    "extra",
    "local_timestamp",
    # v1.1 columns appended so v1 column positions are unchanged
    "shell",
    "distro",
    "artifact",
]


def export_csv(path: Path, blocks: list[SourceBlock]) -> None:
    fieldnames = CSV_FIELDNAMES
    with open_exclusive(path, newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for b in blocks:
            for r in b.rows:
                w.writerow({k: csv_safe(v) for k, v in r.as_export().items()})


REPORT_WIDTH = 118
WHO_COL = 16  # width of the who column: "<privilege>:<account>"
CMD_COL = 54  # width of the gutter before the command text

PROV_TAG = {
    PROV_CLINK_EPOCH: "exact",
    PROV_HISTTIME_EPOCH: "exact",
    PROV_DB_EPOCH: "exact",
    PROV_FILE_MTIME_LAST: "~last",
    PROV_ORDER_ONLY: "order",
    PROV_COLLECTION: "live",
    PROV_KEY_LASTWRITE_MR0: "~key",
    PROV_MRU_NO_TIME: "order",
    PROV_FILE_CTIME: "~ctime",
    PROV_UNAVAILABLE: "n/a",
}

REPORT_LEGEND = [
    "when   the instant shown for that entry, or a dash when the artifact carried none",
    "t      exact = per-command time written by the shell or its database",
    "       ~last = file MTIME; applies ONLY to the final appended line of that file",
    "       ~key  = registry key LastWrite; applies only to the most recent MRU entry",
    "       order = position in the file only, no time was recorded",
    "       live  = observed at collection time (live doskey buffer)",
    "       n/a   = inventory row, not a typed command",
    "flag   !     = recoverable deleted entry (see the source's format note)",
    "       ?     = artifact present but its contents could not be parsed",
]


def _fmt_when(row: IntentRow, localtime: bool) -> str:
    stamp = row.local_timestamp if (localtime and row.local_timestamp) else row.utc_timestamp
    if not stamp:
        return "-"
    return stamp.replace("T", " ").replace("Z", "")


PRIV_ABBREV = {
    PRIV_SYSTEM: "system",
    PRIV_SERVICE: "service",
    PRIV_BUILTIN_ADMIN: "adm",
    PRIV_USER: "usr",
    PRIV_UNKNOWN: "unk",
}


def who_label(row: IntentRow, width: int = WHO_COL) -> str:
    """"<privilege>:<account>" for a row, trimmed to the column width.

    Most history artifacts carry no per-command time, so identity is the axis
    that remains usable. The privilege comes from the SID; the full SID is not
    repeated here because it is constant per artifact and is printed once in
    the section header.
    """
    priv = PRIV_ABBREV.get(privilege_for_sid(row.sid), "unk")
    account = row.user or "?"
    label = f"{priv}:{account}"
    if len(label) <= width:
        return label
    keep = max(1, width - len(priv) - 2)
    return f"{priv}:{account[:keep]}"


def _row_flag(row: IntentRow) -> str:
    if "deleted_entry=1" in row.extra or "db_soft_deleted=1" in row.extra:
        return "!"
    if row.timestamp_provenance == PROV_UNAVAILABLE:
        return "?"
    return " "


def _row_context(row: IntentRow) -> str:
    """Useful per-row context, minus the parts repeated in the section header.

    Database-backed sources carry cwd / exit status / session per command;
    that is the reason for parsing them and it belongs next to the command.
    The artifact path and file index are already in the header, so they are
    dropped here rather than repeated on every line.
    """
    keep = [
        display_safe(part)
        for part in row.extra.split("; ")
        if part and not part.startswith(("path=", "file_index=", "encoding="))
    ]
    if row.distro:
        keep.insert(0, f"distro={row.distro}")
    return "  ".join(keep)


def _wrap_text(text: str, width: int, indent: str) -> list[str]:
    """Wrap text for reading without losing its literal content.

    The continuation indent is applied only when the lines are emitted. It is
    deliberately NOT part of the string being measured: an earlier version
    prepended two spaces to the remainder before re-measuring, so rfind()
    kept finding that injected space at index 1, cut there, emitted a single
    space and lstrip()'d the body back to its original length. Any command
    holding an unbroken run of `width` characters with no space - a long
    path, a URL, a base64 blob, an -EncodedCommand payload - looped forever
    and grew the output list until the process was killed.

    Every iteration below must consume at least one character of `body`.
    """
    width = max(20, width)
    pieces: list[str] = []
    for lineno, physical in enumerate(text.split("\n")):
        body = physical if lineno == 0 else "| " + physical
        if not body:
            pieces.append("")
            continue
        guard = 0
        while len(body) > width:
            guard += 1
            if guard > 10000:  # cannot happen; a hang here must never be silent
                pieces.append(body[:width] + "  [wrap-guard: truncated]")
                body = ""
                break
            cut = body.rfind(" ", 0, width)
            if cut <= 0:
                cut = width  # unbroken token: hard-cut it rather than stall
            chunk = body[:cut].rstrip()
            remainder = body[cut:].lstrip()
            if not chunk or len(remainder) >= len(body):
                # No forward progress available at that cut point.
                chunk, remainder = body[:width], body[width:]
            pieces.append(chunk)
            body = remainder
        if body:
            pieces.append(body)
    if not pieces:
        return [""]
    return [pieces[0]] + [indent + piece for piece in pieces[1:]]


def _section_rows_by_artifact(block: SourceBlock) -> list[tuple[str, list[IntentRow]]]:
    """Group a block's rows by the file they came from, oldest entry first."""
    groups: dict[str, list[IntentRow]] = {}
    order: list[str] = []
    for row in block.rows:
        key = row.artifact or "(source not recorded)"
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(row)
    # collectors emit newest-first; a transcript reads better oldest-first
    return [(k, list(reversed(groups[k]))) for k in order]


def _artifact_meta(block: SourceBlock, artifact: str) -> dict[str, Any]:
    for meta in block.header_meta.get("per_file", []) or []:
        if isinstance(meta, dict) and meta.get("path") == artifact:
            return meta
    for user_meta in block.header_meta.get("per_user_meta", []) or []:
        if not isinstance(user_meta, dict):
            continue
        if user_meta.get("path") == artifact:
            return user_meta
        for meta in user_meta.get("per_file", []) or []:
            if isinstance(meta, dict) and meta.get("path") == artifact:
                return meta
    if block.header_meta.get("path") == artifact:
        return block.header_meta
    return {}


def build_timeline(blocks: list[SourceBlock]) -> tuple[list[IntentRow], int]:
    """Rows carrying a real per-command time, merged across sources, ascending.

    Returns (rows, excluded_count). Rows whose time is order_only or file
    MTIME are excluded BY CONSTRUCTION - that exclusion is the point. A
    timeline assembled from order_only rows would present a sequence the
    artifact never recorded, and the reader's eye would supply a chronology
    that does not exist.
    """
    timed: list[IntentRow] = []
    excluded = 0
    record_blocks = {"WSL-Inventory", "History-Location", "History-Policy", "CollectionErrors"}
    for block in blocks:
        if block.name in record_blocks:
            continue  # inventory and config rows are records, not commands
        for row in block.rows:
            if row.timestamp_provenance in EXACT_PROVENANCE and row.utc_timestamp:
                timed.append(row)
            else:
                excluded += 1
    timed.sort(key=lambda r: (r.utc_timestamp, r.source))
    return timed, excluded


def timestamp_coverage(blocks: list[SourceBlock]) -> list[tuple[str, int, int]]:
    """(source, timed rows, total rows) per block that holds any rows."""
    out: list[tuple[str, int, int]] = []
    record_blocks = {"WSL-Inventory", "History-Location", "History-Policy", "CollectionErrors"}
    for block in blocks:
        if block.name in record_blocks or not block.rows:
            continue
        timed = sum(
            1
            for r in block.rows
            if r.timestamp_provenance in EXACT_PROVENANCE and r.utc_timestamp
        )
        out.append((block.name, timed, len(block.rows)))
    return out


def export_txt(
    path: Path,
    meta: dict[str, Any],
    blocks: list[SourceBlock],
    errors: list[CollectionError],
    redact: bool,
    localtime: bool,
    presence: Optional[list[PresenceRow]] = None,
) -> None:
    """Full plaintext report - every row, no --max-rows truncation.

    Organised for reading top to bottom: one line per command, aligned
    columns, repeated per-file metadata hoisted into a section header, and
    a date rule wherever the day changes. The console shows the inventory;
    this file is the record.
    """
    out: list[str] = [banner_text(meta, redact), ""]

    def _block(text: str, prefix: str, indent: str) -> None:
        """Append wrapped prose, prefixing only the first line."""
        wrapped = _wrap_text(text, REPORT_WIDTH - len(indent), indent)
        out.append(f"{prefix}{wrapped[0]}")
        out.extend(wrapped[1:])


    if presence:
        out.append("=" * REPORT_WIDTH)
        out.append(" TERMINAL / SHELL INVENTORY")
        out.append("=" * REPORT_WIDTH)
        w_type = max([len("Type")] + [len(p.type_name) for p in presence])
        w_pres = max([len("Presence")] + [len(p.detail) for p in presence])
        out.append(
            f"  {'Type':<{w_type}}  {'Presence':<{w_pres}}  {'LastWrite (lead)':<20}  Installed (lead)"
        )
        out.append(f"  {'-' * w_type}  {'-' * w_pres}  {'-' * 20}  {'-' * 20}")
        for row in presence:
            out.append(
                f"  {row.type_name:<{w_type}}  {row.detail:<{w_pres}}  "
                f"{(row.last_write or '-'):<20}  {row.installed or '-'}"
            )
        out.append("")
        for line in INSTALLED_CAVEAT.split("\n"):
            out.append(f"  {line}")
        out.append("")
        detailed = [p for p in presence if p.install_detail and p.installed != "built-in"]
        if detailed:
            out.append("=" * REPORT_WIDTH)
            out.append(" INSTALLATION RECORDS")
            out.append("=" * REPORT_WIDTH)
            w = max(len(p.type_name) for p in detailed)
            for row in detailed:
                lines = _wrap_text(row.install_detail, REPORT_WIDTH - w - 6, " " * (w + 6))
                out.append(f"  {row.type_name:<{w}}  {lines[0]}")
                out.extend(lines[1:])
            out.append("")

    populated = [b for b in blocks if b.rows and b.name != "CollectionErrors"]
    empty = [b for b in blocks if not b.rows and b.name != "CollectionErrors"]

    timed, excluded = build_timeline(blocks)
    out.append("=" * REPORT_WIDTH)
    out.append(" TIMELINE (only entries the shell itself timestamped)")
    out.append("=" * REPORT_WIDTH)
    _block(
        f"{len(timed)} entr{'y carries' if len(timed) == 1 else 'ies carry'} a real per-command time. "
        f"{excluded} row(s) are EXCLUDED because their artifact recorded no time - a timeline "
        "built from those would invent a sequence that was never recorded. Read the per-source "
        "coverage below before drawing conclusions from what is here.",
        "  ", "  ",
    )
    out.append("")
    coverage = timestamp_coverage(blocks)
    if coverage:
        out.append("  Timestamp coverage by source")
        w_src = max(len(name) for name, _t, _n in coverage)
        for name, t_count, total in coverage:
            out.append(f"    {name:<{w_src}}  {t_count} of {total} entries carry exact times")
        out.append("")
    if timed:
        out.append(f"   {'when (UTC)':<20}  {'privilege':<22}  {'source':<18}  command")
        out.append(f"  {'-' * (REPORT_WIDTH - 2)}")
        for row in timed:
            when = row.utc_timestamp.replace("T", " ").replace("Z", "")
            priv = privilege_for_sid(row.sid)
            label = f"{priv}/{row.user}" if row.user else priv
            wrapped = _wrap_text(display_safe(row.typed_value), REPORT_WIDTH - 66, " " * 66)
            out.append(f"   {when:<20}  {label[:22]:<22}  {row.source[:18]:<18}  {wrapped[0]}")
            out.extend(wrapped[1:])
    else:
        out.append("  (no entry in this collection carries a shell-recorded timestamp)")
    out.append("")
    _block(PRIVILEGE_CAVEAT, "  ", "  ")
    out.append("")

    attack = map_attack_techniques(blocks)
    out.append("=" * REPORT_WIDTH)
    out.append(f" ATT&CK TECHNIQUES OBSERVED (authored against ATT&CK {ATTACK_VERSION})")
    out.append("=" * REPORT_WIDTH)
    if not attack:
        out.append("  none - no observation in this run supports a technique mapping")
    else:
        for finding in attack:
            out.append(f"  {finding.technique}  {finding.name}  [{finding.tactic}]")
            _block(finding.basis, "      ", "      ")
        out.append("")
        _block(ATTACK_CAVEAT, "  ", "  ")
        if any(f.technique == "T1059" for f in attack):
            out.append("")
            _block(OBSCURE_SHELL_NOTE, "  ", "  ")
    out.append("")

    out.append("=" * REPORT_WIDTH)
    out.append(" CONTENTS")
    out.append("=" * REPORT_WIDTH)
    if populated:
        w_name = max(len(b.name) for b in populated)
        for i, b in enumerate(populated, 1):
            label = catalog_label(b.name)
            suffix = "" if label == b.name else f"  ({label})"
            noun = "entry " if len(b.rows) == 1 else "entries"
            out.append(f"  [{i:>2}]  {b.name:<{w_name}}  {len(b.rows):>6} {noun}{suffix}")
    else:
        out.append("  (no command-line history recovered on this host)")
    if empty:
        out.append("")
        out.append(f"  Checked and empty: {', '.join(b.name for b in empty)}")
    out.append("")
    out.append("=" * REPORT_WIDTH)
    out.append(" LEGEND")
    out.append("=" * REPORT_WIDTH)
    for line in REPORT_LEGEND:
        out.append(f"  {line}")
    out.append("")

    for index, block in enumerate(populated, 1):
        label = catalog_label(block.name)
        title = block.name if label == block.name else f"{block.name} - {label}"
        out.append("")
        out.append("=" * REPORT_WIDTH)
        out.append(f" [{index}] {title}")
        out.append("=" * REPORT_WIDTH)

        for note_key in ("note", "format_note", "suppression_note", "sync_note",
                         "port_note", "policy", "row_semantics", "goal", "caveat",
                         "UNVERIFIED_timestamp_format"):
            value = block.header_meta.get(note_key)
            if isinstance(value, str) and value:
                note_lines = _wrap_text(value, REPORT_WIDTH - 6, "    ")
                out.append(f"  * {note_lines[0]}")
                out.extend(note_lines[1:])

        for artifact, rows in _section_rows_by_artifact(block):
            file_meta = _artifact_meta(block, artifact)
            out.append("")
            out.append(f"  source: {artifact}")
            owners = sorted({(r.user, r.sid) for r in rows})
            for owner, sid in owners:
                out.append(
                    f"          account: {owner or '(unknown)'}  sid={sid or '(none)'}  "
                    f"privilege={privilege_for_sid(sid)}"
                )
            bits = []
            for key, tag in (("ctime_utc", "created"), ("mtime_utc", "modified"),
                             ("encoding", "encoding"), ("size_bytes", "bytes"),
                             ("format", "format"), ("access", "access")):
                value = file_meta.get(key)
                if value not in (None, ""):
                    bits.append(f"{tag}={value}")
            if bits:
                for line in _wrap_text("  ".join(bits), REPORT_WIDTH - 10, "          "):
                    out.append(f"          {line}")
            exact = sum(1 for r in rows if r.timestamp_provenance in EXACT_PROVENANCE)
            flagged = sum(1 for r in rows if _row_flag(r) == "!")
            summary = f"          entries={len(rows)}  exact_times={exact}"
            if flagged:
                summary += f"  deleted={flagged}"
            # A span may only be drawn from times the shell itself recorded.
            # Deriving one from a file MTIME renders a single last-append
            # instant as though it were a range of command times.
            exact_stamps = sorted(
                r.utc_timestamp
                for r in rows
                if r.utc_timestamp and r.timestamp_provenance in EXACT_PROVENANCE
            )
            if exact_stamps:
                summary += f"  span={exact_stamps[0][:10]}..{exact_stamps[-1][:10]}"
            else:
                mtimes = [
                    r.utc_timestamp
                    for r in rows
                    if r.utc_timestamp and r.timestamp_provenance == PROV_FILE_MTIME_LAST
                ]
                if mtimes:
                    summary += f"  no span (only a file MTIME: {max(mtimes)[:10]})"
            out.append(summary)
            out.append("          order: oldest -> newest")
            out.append("")
            out.append(f"   {'#':>4}  {'when':<19}  {'who':<{WHO_COL}}  {'t':<6}  command")
            out.append(f"  {'-' * (REPORT_WIDTH - 2)}")

            last_day = ""
            for i, row in enumerate(rows, 1):
                day = row.utc_timestamp[:10] if row.utc_timestamp else ""
                if day and day != last_day:
                    if last_day:
                        out.append("")
                    out.append(f"        -- {day} " + "-" * (REPORT_WIDTH - 14 - len(day)))
                    last_day = day
                flag = _row_flag(row)
                tag = PROV_TAG.get(row.timestamp_provenance, "?")
                indent = " " * CMD_COL
                wrapped = _wrap_text(
                    display_safe(row.typed_value), REPORT_WIDTH - CMD_COL, indent
                )
                out.append(
                    f" {flag} {i:>4}  {_fmt_when(row, localtime):<19}  "
                    f"{who_label(row):<{WHO_COL}}  {tag:<6}  {wrapped[0]}"
                )
                for cont in wrapped[1:]:
                    out.append(cont)
                context = _row_context(row)
                if context:
                    ctx_lines = _wrap_text(
                        context, REPORT_WIDTH - CMD_COL - 3, indent + "   "
                    )
                    out.append(f"{indent}`- {ctx_lines[0]}")
                    out.extend(ctx_lines[1:])
        out.append("")

    if errors:
        out.append("=" * REPORT_WIDTH)
        out.append(" COLLECTION ERRORS")
        out.append("=" * REPORT_WIDTH)
        for e in errors:
            out.append(f"  {e.scope}: {e.message}")
        out.append("")

    out.append("=" * REPORT_WIDTH)
    out.append(" NOTES / RELATED")
    out.append("=" * REPORT_WIDTH)
    for n in RELATED_NOTES:
        note_lines = _wrap_text(n, REPORT_WIDTH - 6, "    ")
        out.append(f"  - {note_lines[0]}")
        out.extend(note_lines[1:])
    out.append("")
    out.append("Provenance vocabulary: " + ", ".join(PROVENANCE_VOCABULARY))
    write_text_exclusive(path, "\n".join(out))


def _html_esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def export_html(path: Path, meta: dict[str, Any], blocks: list[SourceBlock], redact: bool) -> None:
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Intention.py</title>",
        "<style>",
        "body{font-family:Segoe UI,Calibri,sans-serif;background:#111;color:#eee;margin:24px}",
        "h1,h2{color:#9cf} table{border-collapse:collapse;width:100%;margin:12px 0 28px}",
        "th,td{border:1px solid #444;padding:4px 8px;vertical-align:top;font-size:13px}",
        "th{background:#1c1c1c} .empty{color:#c90} pre{white-space:pre-wrap}",
        "</style></head><body>",
        f"<h1>Intention.py {VERSION}</h1>",
        f"<pre>{banner_text(meta, redact)}</pre>",
    ]
    for b in blocks:
        parts.append(f"<h2>{_html_esc(b.name)}</h2>")
        if b.header_meta:
            parts.append("<pre>" + _html_esc(json.dumps(b.header_meta, default=str, indent=2)) + "</pre>")
        if not b.rows:
            parts.append(f"<p class='empty'>{_html_esc(b.empty_reason or 'No artifacts found')}</p>")
            continue
        parts.append(
            "<table><tr><th>#</th><th>utc_timestamp</th><th>provenance</th>"
            "<th>user</th><th>sid</th><th>typed_value</th><th>extra</th></tr>"
        )
        for r in b.rows:
            parts.append(
                "<tr>"
                f"<td>{r.mru_pos if r.mru_pos is not None else ''}</td>"
                f"<td>{_html_esc(r.utc_timestamp)}</td>"
                f"<td>{_html_esc(r.timestamp_provenance)}</td>"
                f"<td>{_html_esc(r.user)}</td>"
                f"<td>{_html_esc(r.sid)}</td>"
                f"<td>{_html_esc(display_safe(r.typed_value))}</td>"
                f"<td>{_html_esc(r.extra)}</td>"
                "</tr>"
            )
        parts.append("</table>")
    parts.append("<h2>Notes / Related</h2><ul>")
    for n in RELATED_NOTES:
        parts.append(f"<li>{_html_esc(n)}</li>")
    parts.append("</ul></body></html>")
    write_text_exclusive(path, "".join(parts))




# ===========================================================================
# Orchestration
# ===========================================================================
def wanted(sources: set[str], name: str) -> bool:
    return name in sources


def collect_for_context(
    ctx: UserContext,
    sources: set[str],
    collected: str,
    redact: bool,
    live_doskey: bool,
    opts: "RunOptions",
) -> list[SourceBlock]:
    out: list[SourceBlock] = []
    if wanted(sources, "cmd"):
        out.extend(collect_cmd_bundle(ctx, collected, redact, want_live=live_doskey))
    if wanted(sources, "powershell"):
        out.extend(collect_powershell_for_user(ctx, collected, redact))
    if wanted(sources, "bash"):
        out.extend(collect_posix_ports(ctx, collected, redact, opts.include_repls))
    if wanted(sources, "wsl"):
        out.extend(
            collect_wsl(
                ctx,
                collected,
                redact,
                online=opts.wsl_online,
                offline=opts.wsl_offline,
                allow_exec=opts.wsl_exec,
            )
        )
    if wanted(sources, "esoteric"):
        out.extend(collect_esoteric(ctx, collected, redact))
        out.append(collect_atuin(ctx, collected, redact))
    if wanted(sources, "repls"):
        out.append(collect_repls(ctx, collected, redact))
    if wanted(sources, "config"):
        # last, so the cross-check can compare declared paths
        # against the artifacts actually collected above
        out.extend(
            collect_config_policy(
                ctx, collected, redact, out,
                include_machine_scope=opts.config_machine_scope,
            )
        )
    # Explorer UI MRU is not command-line history. Opt-in only.
    if wanted(sources, "legacy-explorer"):
        out.append(collect_runmru(ctx, collected, redact))
        out.append(collect_typedpaths(ctx, collected, redact))
        out.extend(collect_comdlg32(ctx, collected, redact))
        out.append(collect_wordwheel(ctx, collected, redact))
    return out


@dataclass
class RunOptions:
    include_repls: bool = False
    # machine-scope config (AllUsers $PROFILE) is host-wide: read once, then
    # cleared for subsequent profiles under --all-users
    config_machine_scope: bool = True
    wsl_online: bool = False
    wsl_offline: bool = False
    wsl_exec: bool = False
    legacy_explorer: bool = False


def ensure_required_blocks(blocks: list[SourceBlock], sources: set[str]) -> list[SourceBlock]:
    """Print the core tables even when nothing was found, so the examiner can
    tell 'checked and empty' apart from 'never looked'."""
    have = {b.name for b in blocks}
    for name, family in REQUIRED_BLOCKS:
        if family not in sources or name in have:
            continue
        blocks.append(
            SourceBlock(
                name=name,
                checked=True,
                empty_reason="Checked; no artifacts found on this host",
            )
        )
    return blocks


def order_blocks(blocks: list[SourceBlock]) -> list[SourceBlock]:
    """Stable sort into BLOCK_ORDER; unlisted tables keep discovery order at
    the end, and CollectionErrors is always last."""
    index = {name: i for i, name in enumerate(BLOCK_ORDER)}
    tail = len(BLOCK_ORDER)

    def key(pair: tuple[int, SourceBlock]) -> tuple[int, int]:
        i, block = pair
        if block.name == "CollectionErrors":
            return (tail + len(blocks) + 1, i)
        return (index.get(block.name, tail + i), i)

    return [b for _, b in sorted(enumerate(blocks), key=key)]


def collect_rejections(node: Any) -> list[str]:
    """Every containment rejection recorded anywhere in a block's metadata.

    Recurses because merge_blocks nests per-user metadata a level down.
    """
    out: list[str] = []
    if isinstance(node, dict):
        if node.get("rejected") == LINK_ESCAPE_NOTE and node.get("error"):
            out.append(str(node["error"]))
        for value in node.values():
            out.extend(collect_rejections(value))
    elif isinstance(node, list):
        for item in node:
            out.extend(collect_rejections(item))
    return out


def merge_blocks(blocks: list[SourceBlock]) -> list[SourceBlock]:
    """Keep separate tables; if same name from multiple users, suffix or combine rows."""
    grouped: dict[str, SourceBlock] = {}
    order: list[str] = []
    for b in blocks:
        if b.name not in grouped:
            grouped[b.name] = SourceBlock(name=b.name, header_meta=dict(b.header_meta))
            order.append(b.name)
        target = grouped[b.name]
        target.rows.extend(b.rows)
        if b.header_meta:
            target.header_meta.setdefault("per_user_meta", []).append(b.header_meta)
        if b.empty_reason and not target.rows:
            if target.empty_reason:
                target.empty_reason += " | " + b.empty_reason
            else:
                target.empty_reason = b.empty_reason
        if target.rows:
            target.empty_reason = ""
    return [grouped[n] for n in order]


def apply_localtime(blocks: list[SourceBlock]) -> None:
    for b in blocks:
        for r in b.rows:
            r.local_timestamp = to_local_iso(r.utc_timestamp) if r.utc_timestamp else ""


def sort_blocks(blocks: list[SourceBlock], chronological: bool) -> None:
    for b in blocks:
        if not chronological:
            continue
        # Stable: rows with timestamps first by time desc, others keep relative order
        indexed = list(enumerate(b.rows))

        def key(item: tuple[int, IntentRow]) -> tuple[int, str, int]:
            i, row = item
            if row.utc_timestamp:
                return (0, row.utc_timestamp, i)
            return (1, "", i)

        indexed.sort(key=key, reverse=False)
        # timestamps should be newest first among timed rows
        timed = [(i, r) for i, r in indexed if r.utc_timestamp]
        untimed = [(i, r) for i, r in indexed if not r.utc_timestamp]
        timed.sort(key=lambda x: x[1].utc_timestamp, reverse=True)
        b.rows = [r for _, r in timed + untimed]


def parse_sources(arg: Optional[str]) -> set[str]:
    """cmd,powershell,bash,wsl,esoteric[,legacy-explorer][,repls]"""
    if not arg:
        return set(DEFAULT_SOURCES)
    out: set[str] = set()
    for part in arg.split(","):
        key = part.strip().lower()
        if not key:
            continue
        if key not in SOURCE_ALIASES:
            raise argparse.ArgumentTypeError(f"unknown source '{part}'")
        out.add(SOURCE_ALIASES[key])
    if not out:
        raise argparse.ArgumentTypeError("no sources selected")
    return out


# ===========================================================================
# Self-test
# ===========================================================================
# ===========================================================================
# --diagnose: evidence for the Windows execution gap
#
# Every code path in this tool has been verified on Linux. Several cannot be:
# they call Win32 APIs, read the live registry, or depend on NTFS semantics
# that have no POSIX equivalent. This mode exercises exactly those paths and
# reports what they actually did, so the gap is closed with observation rather
# than assumption.
#
# It collects no history and writes no report. It is read-only, like the rest
# of the tool, and it prints no command text and no file contents - only the
# SHAPE of what it found.
#
# It IS host-identifying: the output carries the hostname, profile paths (which
# contain the account name on Windows), which shells and package managers are
# installed, and drive letters. That is the point - the paths are the finding -
# but it means the output is safe to share with someone you would already tell
# those things, not safe to publish.
# ===========================================================================
DIAG_OK = "OK"
DIAG_FAIL = "FAIL"
DIAG_SKIP = "SKIP"
DIAG_INFO = "INFO"

DIAG_STATUSES = (DIAG_OK, DIAG_FAIL, DIAG_SKIP, DIAG_INFO)


@dataclass
class DiagnosticResult:
    """One probe: what was tested, what happened, and whether it worked."""

    probe: str
    status: str
    detail: str


def _diag(probe: str, status: str, detail: str) -> DiagnosticResult:
    return DiagnosticResult(probe=probe, status=status, detail=detail)


def diagnose_console() -> list[DiagnosticResult]:
    """Console encoding - the path that crashed a redirected Windows run."""
    out = [
        _diag("console.platform", DIAG_INFO,
              f"os.name={os.name} platform={platform.platform()} python={sys.version.split()[0]}"),
        _diag("console.stdout", DIAG_INFO,
              f"encoding={getattr(sys.stdout, 'encoding', '?')} "
              f"errors={getattr(sys.stdout, 'errors', '?')} "
              f"isatty={getattr(sys.stdout, 'isatty', lambda: '?')()}"),
    ]
    hardened = getattr(sys.stdout, "errors", "") == "replace"
    out.append(
        _diag("console.hardened", DIAG_OK if hardened else DIAG_FAIL,
              f"stdout errors={getattr(sys.stdout, 'errors', '?')} "
              "(expected 'replace' so undecodable output degrades instead of aborting)")
    )
    if os.name == "nt":
        try:
            k32 = ctypes.windll.kernel32
            out.append(_diag("console.codepage", DIAG_INFO,
                             f"GetConsoleOutputCP={k32.GetConsoleOutputCP()} GetACP={k32.GetACP()}"))
        except (AttributeError, OSError) as exc:
            out.append(_diag("console.codepage", DIAG_FAIL, f"{type(exc).__name__}: {exc}"))
    else:
        out.append(_diag("console.codepage", DIAG_SKIP, "Windows only"))
    # a non-ASCII round trip through the current stdout encoding
    sample = "jos" + chr(0xE9) + "".join(chr(c) for c in (0x43F, 0x430, 0x440))
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        sample.encode(enc)
        out.append(_diag("console.non_ascii", DIAG_OK, f"{enc} encodes non-ASCII directly"))
    except (UnicodeEncodeError, LookupError):
        degraded = sample.encode(enc, errors="replace").decode(enc, errors="replace")
        out.append(_diag("console.non_ascii", DIAG_OK if hardened else DIAG_FAIL,
                         f"{enc} cannot encode non-ASCII; with errors=replace it degrades to "
                         f"{degraded!r} (this is the redirected-Windows case)"))
    return out


def diagnose_system32() -> list[DiagnosticResult]:
    """system32_binary() - never executed against a real %SystemRoot%."""
    out: list[DiagnosticResult] = []
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or ""
    out.append(_diag("system32.root", DIAG_INFO if root else DIAG_SKIP,
                     f"SystemRoot={root or '(unset - not Windows)'}"))
    for name in ("cmd.exe", "wsl.exe"):
        resolved = system32_binary(name)
        absolute = os.path.isabs(resolved)
        if os.name != "nt":
            out.append(_diag(f"system32.{name}", DIAG_SKIP, f"resolved={resolved} (not Windows)"))
        else:
            out.append(_diag(f"system32.{name}", DIAG_OK if absolute else DIAG_FAIL,
                             f"resolved={resolved} absolute={absolute} "
                             "(FAIL means it fell back to PATH lookup)"))
    return out


def diagnose_drive_types() -> list[DiagnosticResult]:
    """GetDriveTypeW - the removable/USB answer has never executed."""
    if os.name != "nt":
        return [_diag("drives", DIAG_SKIP,
                      "GetDriveTypeW is Windows only; the code->volume mapping is asserted "
                      "by --selftest but the Win32 call has never run")]
    out: list[DiagnosticResult] = []
    seen = 0
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:\\"
        code = query_drive_type(drive)
        if code in (None, 0, 1):
            continue
        seen += 1
        mapped = DRIVE_TYPE_MAP.get(code, VOLUME_UNKNOWN)
        out.append(_diag(f"drives.{letter}", DIAG_OK,
                         f"GetDriveTypeW={code} -> classify_volume={mapped}"))
    if not seen:
        out.append(_diag("drives", DIAG_FAIL, "no drives returned a usable type code"))
    out.append(_diag("drives.usb_hint", DIAG_INFO,
                     "attach a USB stick and re-run: a removable volume should report "
                     f"code 2 -> {VOLUME_REMOVABLE}"))
    return out


def diagnose_reparse_points() -> list[DiagnosticResult]:
    """_has_reparse_point() - Windows junctions are not POSIX symlinks.

    Probes directories Windows itself creates as junctions, so no junction has
    to be created to test the detector.
    """
    if os.name != "nt":
        return [_diag("reparse", DIAG_SKIP,
                      "Windows junctions have no POSIX equivalent; detector unexercised")]
    out: list[DiagnosticResult] = []
    drive = os.environ.get("SystemDrive", "C:")
    known = [
        Path(f"{drive}\\Users\\All Users"),
        Path(f"{drive}\\Users\\Default User"),
        Path(f"{drive}\\ProgramData\\Application Data"),
        Path(f"{drive}\\Documents and Settings"),
    ]
    detected = 0
    for candidate in known:
        try:
            exists = candidate.exists() or candidate.is_symlink()
        except OSError:
            exists = False
        if not exists:
            continue
        flagged = _has_reparse_point(candidate)
        detected += 1 if flagged else 0
        out.append(_diag(f"reparse.{candidate.name}", DIAG_OK if flagged else DIAG_FAIL,
                         f"{candidate} detected_as_reparse_point={flagged} "
                         "(these are junctions on a stock Windows install)"))
    if not out:
        out.append(_diag("reparse", DIAG_FAIL, "no known junction paths were present to test"))
    elif detected == 0:
        out.append(_diag("reparse.verdict", DIAG_FAIL,
                         "no junction was detected - link containment would not fail closed "
                         "against a planted junction"))
    else:
        out.append(_diag("reparse.verdict", DIAG_OK,
                         f"{detected} junction(s) correctly detected"))
    return out


def diagnose_registry() -> list[DiagnosticResult]:
    """Live winreg enumeration - only ever exercised through DictHiveView."""
    if winreg is None:
        return [_diag("registry", DIAG_SKIP, "winreg unavailable (not Windows)")]
    out: list[DiagnosticResult] = []
    probes = [
        ("HKCU", winreg.HKEY_CURRENT_USER, LXSS_PATH, "WSL distro inventory"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, UNINSTALL_REL, "installed software"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, UNINSTALL_REL_WOW, "32-bit installed software"),
        ("HKCU", winreg.HKEY_CURRENT_USER, UNINSTALL_REL, "per-user installed software"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, MSI_USERDATA_REL, "MSI install records"),
    ]
    for hive_name, hive, path, what in probes:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError as exc:
            out.append(_diag(f"registry.{hive_name}:{path.rsplit(chr(92), 1)[-1]}",
                             DIAG_INFO, f"{what}: not present or unreadable ({exc.__class__.__name__})"))
            continue
        try:
            count = winreg.QueryInfoKey(key)[0]
            out.append(_diag(f"registry.{hive_name}:{path.rsplit(chr(92), 1)[-1]}",
                             DIAG_OK, f"{what}: {count} subkey(s) enumerable"))
        except OSError as exc:
            out.append(_diag(f"registry.{hive_name}:{path.rsplit(chr(92), 1)[-1]}",
                             DIAG_FAIL, f"{what}: open succeeded but enumeration failed ({exc})"))
        finally:
            try:
                winreg.CloseKey(key)
            except OSError:
                pass
    out.append(_diag("registry.elevation", DIAG_INFO,
                     f"elevated={is_admin()} (HKLM reads generally work unelevated; "
                     "other users' hives do not)"))
    return out


def diagnose_wsl() -> list[DiagnosticResult]:
    """\\\\wsl$ share access - probed without starting any distro."""
    if os.name != "nt":
        return [_diag("wsl", DIAG_SKIP, "\\\\wsl$ is Windows only")]
    out: list[DiagnosticResult] = []
    for root in (r"\\wsl$", r"\\wsl.localhost"):
        try:
            names = os.listdir(root)
            out.append(_diag(f"wsl.share {root}", DIAG_OK,
                             f"{len(names)} distro(s) visible: {', '.join(sorted(names)) or '(none)'}"))
        except OSError as exc:
            out.append(_diag(f"wsl.share {root}", DIAG_INFO,
                             f"not enumerable ({exc.__class__.__name__}) - normal when no distro is running"))
    exe = system32_binary("wsl.exe")
    out.append(_diag("wsl.binary", DIAG_INFO,
                     f"wsl.exe resolves to {exe}; NOT executed (--wsl-exec would start a distro)"))
    return out


def diagnose_clink() -> list[DiagnosticResult]:
    """The standing unknown: how Clink encodes timestamps on disk.

    Reports the SHAPE of each of the first lines - never the command text - so
    the output can be shared. If history.time_stamp is enabled and epoch
    comment lines appear, the parser's assumption is confirmed.
    """
    out: list[DiagnosticResult] = []
    roots: list[Path] = []
    for env_name in ("CLINK_PROFILE", "CLINK_SETTINGS", "LOCALAPPDATA", "APPDATA"):
        value = os.environ.get(env_name)
        if value:
            roots.append(Path(value) if env_name.startswith("CLINK") else Path(value) / "clink")
    settings_seen = False
    for root in _dedup_paths(roots):
        settings = root / "clink_settings"
        try:
            if not settings.is_file():
                continue
        except OSError:
            continue
        settings_seen = True
        try:
            text, _enc = read_text_guess(settings)
        except OSError as exc:
            out.append(_diag("clink.settings", DIAG_FAIL, f"{settings}: {exc}"))
            continue
        stamp = "(not set - defaults to off)"
        for line in text.splitlines():
            if line.strip().startswith("history.time_stamp"):
                stamp = line.strip()
        out.append(_diag("clink.settings", DIAG_OK, f"{settings}: {stamp}"))

        history = root / "clink_history"
        if not history.is_file():
            history = root / ".history"
        try:
            if not history.is_file():
                out.append(_diag("clink.history", DIAG_INFO, f"no history file under {root}"))
                continue
            htext, _e = read_text_guess(history)
        except OSError as exc:
            out.append(_diag("clink.history", DIAG_FAIL, f"{history}: {exc}"))
            continue
        shapes: list[str] = []
        for lineno, line in enumerate(htext.splitlines()[:12], 1):
            if line.startswith(CLINK_CTAG_PREFIX):
                shape = "CTAG header"
            elif re.fullmatch(r"#\s*\d{6,}(?:\.\d+)?", line.strip()):
                shape = "EPOCH COMMENT <- confirms the parser's assumption"
            elif line.startswith("#"):
                shape = f"comment, non-epoch: {line[:20]!r}"
            elif line.startswith("|"):
                shape = "tombstoned (deleted) entry"
            else:
                shape = f"command text ({len(line)} chars, not shown)"
            shapes.append(f"    line {lineno}: {shape}")
        verdict = DIAG_OK if any("EPOCH COMMENT" in s for s in shapes) else DIAG_INFO
        out.append(_diag("clink.history_shape", verdict,
                         f"{history}\n" + "\n".join(shapes)))
    if not settings_seen:
        out.append(_diag("clink.settings", DIAG_SKIP,
                         "no clink_settings found; install Clink and enable "
                         "'clink set history.time_stamp save' to resolve this unknown"))
    return out


def _safe_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def diagnose_profiles() -> list[DiagnosticResult]:
    """ProfileList discovery and privilege labelling - Windows-only, unproven.

    v1.4.0 began discovering profiles through HKLM ProfileList so SYSTEM and
    the service accounts, which do not live under C:\\Users, are collected at
    all. None of that has executed against a real registry. This reports what
    it found without printing any command text.
    """
    out: list[DiagnosticResult] = []
    if winreg is None:
        return [_diag("profiles", DIAG_SKIP,
                      "ProfileList needs the live registry; SYSTEM discovery unexercised")]
    plist = profile_list_map()
    if not plist:
        return [_diag("profiles.list", DIAG_FAIL,
                      "ProfileList returned nothing - SYSTEM and service profiles cannot be found")]
    out.append(_diag("profiles.list", DIAG_OK, f"{len(plist)} SID(s) in ProfileList"))
    users_root = os.path.normcase(os.environ.get("SystemDrive", "C:") + "\\Users")
    outside = 0
    for sid, path in sorted(plist.items()):
        priv = privilege_for_sid(sid)
        try:
            exists = bool(path) and Path(path).is_dir()
        except OSError:
            exists = False
        beyond = bool(path) and not os.path.normcase(path).startswith(users_root)
        if beyond and exists:
            outside += 1
        if priv in (PRIV_SYSTEM, PRIV_SERVICE, PRIV_BUILTIN_ADMIN) or beyond:
            status = DIAG_OK if exists else DIAG_INFO
            out.append(_diag(f"profiles.{priv}", status,
                             f"{sid} -> {path or '(no path)'} exists={exists} "
                             f"outside_C:\\Users={beyond}"))
    out.append(_diag("profiles.privileges", DIAG_INFO,
                     "assigned: " + ", ".join(
                         f"{p}={sum(1 for s in plist if privilege_for_sid(s) == p)}"
                         for p in PRIVILEGE_CONTEXTS)))
    verdict = DIAG_OK if outside else DIAG_INFO
    out.append(_diag("profiles.outside_users", verdict,
                     f"{outside} profile(s) exist outside C:\\Users and would be INVISIBLE to a "
                     "C:\\Users walk alone - this is what ProfileList discovery exists for"))
    sys_hit = [s for s in plist if privilege_for_sid(s) == PRIV_SYSTEM]
    if sys_hit:
        sys_path = plist[sys_hit[0]]
        ps_dir = Path(sys_path) / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell"
        try:
            present = ps_dir.is_dir()
        except OSError:
            present = False
        out.append(_diag("profiles.system_psreadline", DIAG_OK if present else DIAG_INFO,
                         f"SYSTEM PowerShell profile dir {'present' if present else 'absent'}: "
                         f"{ps_dir} (present means PowerShell has run as SYSTEM on this host)"))
    return out


def diagnose_paths() -> list[DiagnosticResult]:
    """Which discovery roots actually exist on this host."""
    ctx = live_current_user_context([])
    out = [
        _diag("paths.profile", DIAG_INFO,
              f"profile={ctx.profile_path or '?'} appdata={ctx.appdata or '?'} "
              f"localappdata={ctx.localappdata or '?'}"),
    ]
    homes = {
        "git-bash": git_bash_homes(ctx),
        "msys2": msys2_homes(),
        "cygwin": cygwin_homes(),
    }
    for label, found in homes.items():
        out.append(_diag(f"paths.{label}", DIAG_OK if found else DIAG_INFO,
                         f"{len(found)} home(s): {', '.join(str(h) for h in found[:3]) or '(none)'}"))
    present = []
    for label, root, _kind in package_manager_roots(ctx):
        try:
            if root.is_dir():
                present.append(f"{label}={root}")
        except OSError:
            continue
    out.append(_diag("paths.package_managers", DIAG_OK if present else DIAG_INFO,
                     "; ".join(present) or "(no package-manager roots present)"))
    cfg = [str(p) for p, _f, _r in config_file_candidates(ctx) if _safe_is_file(p)]
    out.append(_diag("paths.config_files", DIAG_OK if cfg else DIAG_INFO,
                     f"{len(cfg)} shell config file(s) readable"))
    return out




def run_diagnostics(no_color: bool = False) -> int:
    """Exercise the paths that Linux testing cannot reach, and report.

    Collects no history, writes no report, prints no command text.
    """
    sections = [
        ("CONSOLE ENCODING", diagnose_console),
        ("SYSTEM32 BINARY RESOLUTION", diagnose_system32),
        ("DRIVE TYPE (GetDriveTypeW)", diagnose_drive_types),
        ("REPARSE POINTS / JUNCTIONS", diagnose_reparse_points),
        ("LIVE REGISTRY", diagnose_registry),
        ("WSL SHARE ACCESS", diagnose_wsl),
        ("CLINK TIMESTAMP FORMAT", diagnose_clink),
        ("PROFILES AND PRIVILEGE", diagnose_profiles),
        ("DISCOVERY ROOTS", diagnose_paths),
    ]
    print(f"Intention.py {VERSION} - diagnostics")
    print(f"Collected UTC : {iso_utc(dt.datetime.now(dt.timezone.utc))}")
    print(f"Host          : {socket.gethostname()}")
    print()
    print("This mode exercises the code paths that cannot be verified off-Windows.")
    print("It reads only; it collects no history and prints no command text.")
    print("It DOES print the hostname, profile paths (with the account name) and")
    print("which software is installed. Share accordingly.")
    print()
    totals: dict[str, int] = {s: 0 for s in DIAG_STATUSES}
    for title, probe in sections:
        print("=" * 78)
        print(f" {title}")
        print("=" * 78)
        try:
            results = probe()
        except Exception as exc:  # a probe must never take the run down
            results = [_diag(title.lower().replace(" ", "."), DIAG_FAIL,
                             f"probe raised {type(exc).__name__}: {exc}")]
            LOG.debug("diagnostic probe failed", exc_info=True)
        for item in results:
            totals[item.status] = totals.get(item.status, 0) + 1
            first, _, rest = item.detail.partition("\n")
            print(f"  [{item.status:<4}] {item.probe:<28} {display_safe(first)}")
            for line in rest.splitlines():
                print(f"         {display_safe(line)}")
        print()
    print("=" * 78)
    print(" SUMMARY")
    print("=" * 78)
    print("  " + "  ".join(f"{k}={totals.get(k, 0)}" for k in DIAG_STATUSES))
    if totals.get(DIAG_SKIP):
        print("  SKIP means the probe needs Windows; run this on the target host.")
    if totals.get(DIAG_FAIL):
        print("  FAIL means a path this tool depends on did not behave as designed.")
        return 1
    return 0


def run_selftest() -> int:
    import ast as _ast
    import hashlib
    import io as _io
    import sqlite3 as _sq
    from dataclasses import fields as dataclass_fields

    source_text = Path(__file__).read_text(encoding="utf-8")

    failures: list[str] = []

    def check(cond: bool, msg: str) -> None:
        if not cond:
            failures.append(msg)

    collected = iso_utc(utc_now())
    lw = dt.datetime(2024, 6, 1, 12, 0, tzinfo=dt.timezone.utc)
    tree = {
        RUNMRU_PATH: {
            "last_write": lw,
            "values": {
                "MRUList": ("ba", 1),
                "a": ("notepad.exe\\1", 1),
                "b": ("\\\\fileserver\\share\\tool.exe\\1", 1),
            },
            "subkeys": [],
        },
        TYPEDPATHS_PATH: {
            "last_write": lw,
            "values": {
                "url1": ("C:\\Temp\\staging", 1),
                "url2": ("\\\\dc01\\sysvol", 1),
            },
            "subkeys": [],
        },
        WORDWHEEL_PATH: {
            "last_write": lw,
            "values": {
                "MRUListEx": (struct.pack("<III", 1, 0, 0xFFFFFFFF), 3),
                "0": ("password policy".encode("utf-16-le") + b"\x00\x00", 3),
                "1": ("confidential".encode("utf-16-le") + b"\x00\x00", 3),
            },
            "subkeys": [],
        },
        COMDLG32_PATH: {"last_write": lw, "values": {}, "subkeys": ["OpenSavePidlMRU", "LastVisitedPidlMRU", "CIDSizeMRU"]},
        COMDLG32_PATH + r"\OpenSavePidlMRU": {
            "last_write": lw,
            "values": {},
            "subkeys": ["txt"],
        },
        COMDLG32_PATH + r"\OpenSavePidlMRU\txt": {
            "last_write": lw,
            "values": {
                "MRUListEx": (struct.pack("<II", 0, 0xFFFFFFFF), 3),
                "0": (b"\x14\x00" + "notes.txt".encode("utf-16-le") + b"\x00\x00\x00\x00", 3),
            },
            "subkeys": [],
        },
        COMDLG32_PATH + r"\LastVisitedPidlMRU": {
            "last_write": lw,
            "values": {
                "MRUListEx": (struct.pack("<II", 0, 0xFFFFFFFF), 3),
                "0": ("notepad.exe".encode("utf-16-le") + b"\x00\x00" + b"\x14\x00C:\x00\\\x00T\x00e\x00m\x00p\x00\x00\x00\x00\x00", 3),
            },
            "subkeys": [],
        },
        COMDLG32_PATH + r"\CIDSizeMRU": {
            "last_write": lw,
            "values": {
                "MRUListEx": (struct.pack("<II", 0, 0xFFFFFFFF), 3),
                "0": ("powershell.exe".encode("utf-16-le") + b"\x00\x00", 3),
            },
            "subkeys": [],
        },
    }
    ctx = UserContext(
        user="analyst",
        sid="S-1-5-21-1000-1000-1000-1001",
        profile_path=r"C:\Users\analyst",
        appdata="",
        localappdata="",
        hive_view=DictHiveView(tree),
    )
    run = collect_runmru(ctx, collected, False)
    check(len(run.rows) == 2, f"RunMRU count {len(run.rows)}")
    check(run.rows[0].typed_value.endswith("tool.exe"), f"RunMRU order {run.rows[0].typed_value}")
    check(run.rows[0].timestamp_provenance == PROV_KEY_LASTWRITE_MR0, "RunMRU pos0 provenance")
    check(run.rows[1].timestamp_provenance == PROV_MRU_NO_TIME, "RunMRU pos1 provenance")
    check(run.rows[1].utc_timestamp == "", "RunMRU older has no timestamp")
    check("\\1" not in run.rows[0].typed_value, "RunMRU suffix stripped")

    tp = collect_typedpaths(ctx, collected, False)
    check(tp.rows[0].typed_value.endswith("staging"), "TypedPaths url1 first")
    check(tp.rows[0].value_name.lower() == "url1", "TypedPaths value name")

    ww = collect_wordwheel(ctx, collected, False)
    check(len(ww.rows) == 2, "WordWheel count")
    check(ww.rows[0].typed_value == "confidential", f"WordWheel MRU order {ww.rows[0].typed_value!r}")

    com = collect_comdlg32(ctx, collected, False)
    names = [b.name for b in com]
    check("ComDlg32-OpenSave" in names, "OpenSave block")
    check("ComDlg32-LastVisited" in names, "LastVisited block")
    check(any(b.rows and "notepad.exe" in (b.rows[0].extra + b.rows[0].typed_value) for b in com), "LastVisited exe")
    check(any(b.rows and "powershell.exe" in b.rows[0].typed_value for b in com), "CIDSize exe")

    # PowerShell backtick coalesce + last-line mtime only
    with tempfile.TemporaryDirectory() as tmp:
        hist_dir = Path(tmp) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
        hist_dir.mkdir(parents=True)
        hist = hist_dir / "ConsoleHost_history.txt"
        hist.write_text("Get-ChildItem `\nC:\\Temp\nwhoami\n", encoding="utf-8")
        pctx = UserContext(
            user="analyst",
            sid="S-1-5-21-1",
            profile_path=tmp,
            appdata=tmp,
            localappdata=tmp,
            hive_view=DictHiveView({}),
        )
        ps_blocks = collect_powershell_for_user(pctx, collected, False)
        ps = next((b for b in ps_blocks if b.name == "Powershell"), None)
        check(ps is not None, "Powershell block exists")
        assert ps is not None
        check(len(ps.rows) == 2, f"PS row count {len(ps.rows)} { [r.typed_value for r in ps.rows] }")
        # reversed: whoami is most recent
        check(ps.rows[0].typed_value == "whoami", f"PS most recent {ps.rows[0].typed_value!r}")
        check(ps.rows[0].timestamp_provenance == PROV_FILE_MTIME_LAST, "PS last line mtime")
        check(ps.rows[1].timestamp_provenance == PROV_ORDER_ONLY, "PS older order_only")
        check(ps.rows[1].utc_timestamp == "", "PS older no invented time")
        check("Get-ChildItem" in ps.rows[1].typed_value and "C:\\Temp" in ps.rows[1].typed_value, "backtick join")

        clink_dir = Path(tmp) / "clink"
        clink_dir.mkdir()
        (clink_dir / ".history").write_text("# 1700000000\nnet user\nwhoami\n", encoding="utf-8")
        cctx = UserContext(
            user="analyst",
            sid="S-1-5-21-1",
            profile_path=tmp,
            appdata=tmp,
            localappdata=tmp,
            hive_view=DictHiveView({}),
        )
        cl = collect_clink(cctx, collected, False)
        check(len(cl.rows) == 2, f"Clink rows {len(cl.rows)}")
        # reversed most recent first
        check(cl.rows[0].typed_value == "whoami", "Clink order")
        check(any(r.timestamp_provenance == PROV_CLINK_EPOCH for r in cl.rows), "Clink epoch parsed")

    # ---- v1.1: Clink file format (CTAG header + deleted-entry tombstones) ----
    clink_txt = (
        "|CTAG_1_9\n"
        "# 1700000000\n"
        "whoami /priv\n"
        "|onda install graphviz\n"
        "net user\n"
    )
    plain = parse_readline_history(clink_txt, epoch_prov=PROV_CLINK_EPOCH)
    check(len(plain) == 4, f"without tombstones every line is a command: {len(plain)}")
    tomb = parse_readline_history(clink_txt, epoch_prov=PROV_CLINK_EPOCH, tombstones=True)
    check(len(tomb) == 3, f"CTAG header dropped, 3 entries: {[e.command for e in tomb]}")
    check(not any(e.command.startswith("|CTAG") for e in tomb), "CTAG never becomes a command")
    check(tomb[0].command == "whoami /priv", f"live entry {tomb[0].command!r}")
    check(tomb[0].prov == PROV_CLINK_EPOCH and tomb[0].ts is not None, "clink epoch attached")
    dead = [e for e in tomb if e.deleted]
    check(len(dead) == 1, f"one tombstoned entry, got {len(dead)}")
    check(dead[0].command == "?onda install graphviz", f"lost char marked: {dead[0].command!r}")
    check(dead[0].raw == "|onda install graphviz", "raw on-disk line preserved verbatim")
    check(tomb[2].command == "net user" and not tomb[2].deleted, "entry after tombstone is live")

    with tempfile.TemporaryDirectory() as tmp:
        cdir = Path(tmp) / "clink"
        cdir.mkdir()
        (cdir / "clink_history").write_text(clink_txt, encoding="utf-8")
        cctx2 = UserContext(
            user="analyst", sid="S-1-5-21-9", profile_path=tmp,
            appdata=tmp, localappdata=tmp, hive_view=DictHiveView({}),
        )
        cb = collect_clink(cctx2, collected, False)
        check(len(cb.rows) == 3, f"collect_clink rows {len(cb.rows)}")
        check(not any("CTAG" in r.typed_value for r in cb.rows), "CTAG absent from rows")
        drow = [r for r in cb.rows if "deleted_entry=1" in r.extra]
        check(len(drow) == 1, "deleted row flagged in extra")
        check(drow[0].typed_value.startswith("?onda"), f"deleted row value {drow[0].typed_value!r}")
        per_file = cb.header_meta.get("per_file", [{}])[0]
        check(per_file.get("recoverable_deleted_rows") == 1, "deleted count reported in meta")
        check(cb.rows[0].mru_pos == 0, "clink rows renumbered")

    # ---- v1.1: POSIX shell parsers -----------------------------------
    bash_txt = "#1700000000\nwhoami\nls -la\n#1700000600\nsudo cat /etc/shadow\n"
    bents = parse_readline_history(bash_txt)
    check(len(bents) == 3, f"bash entry count {len(bents)}")
    check(bents[0].command == "whoami", f"bash first {bents[0].command!r}")
    check(bents[0].ts is not None and bents[0].prov == PROV_HISTTIME_EPOCH, "bash epoch attached")
    check(bents[1].ts is None, "bash untimed line stays untimed")
    check(bents[2].command.startswith("sudo cat"), "bash second epoch applies to next command")
    check(iso_utc(bents[0].ts) == "2023-11-14T22:13:20Z", f"bash epoch value {iso_utc(bents[0].ts)}")

    cont = parse_readline_history("echo one \\\ntwo\nwhoami\n")
    check(len(cont) == 2, f"readline continuation count {len(cont)}")
    check("one" in cont[0].command and "two" in cont[0].command, "readline continuation joined")

    zsh_txt = (
        ": 1700000000:0;git status\n"
        ": 1700000005:12;ssh admin@10.0.0.5\n"
        "plain-line-without-extended-format\n"
    )
    zents = parse_zsh_history(zsh_txt)
    check(len(zents) == 3, f"zsh entry count {len(zents)}")
    check(zents[0].command == "git status", f"zsh cmd {zents[0].command!r}")
    check(zents[0].prov == PROV_HISTTIME_EPOCH, "zsh extended epoch")
    check("elapsed_s=12" in zents[1].note, f"zsh elapsed {zents[1].note!r}")
    check(zents[2].ts is None and zents[2].prov == "", "zsh plain line has no invented time")

    fish_txt = (
        "- cmd: sudo pacman -Syu\n  when: 1700000000\n  paths:\n    - /etc\n"
        "- cmd: curl http://198.51.100.7/x.sh\n  when: 1700000060\n"
    )
    fents = parse_fish_history(fish_txt)
    check(len(fents) == 2, f"fish entry count {len(fents)}")
    check(fents[0].command == "sudo pacman -Syu", f"fish cmd {fents[0].command!r}")
    check(fents[1].prov == PROV_HISTTIME_EPOCH and fents[1].ts is not None, "fish when parsed")

    # 'ash' is a substring of 'bash' - precedence must not misfile bash rows
    check(shell_from_filename("backup.bash_history") == "bash", "bash beats ash")
    check(shell_from_filename(".bash_history-DESKTOP1") == "bash", "hostname-suffixed bash")
    check(shell_from_filename(".ash_history") == "ash", "ash detected")
    check(shell_from_filename(".zhistory") == "zsh", "zhistory is zsh")
    check(shell_from_filename("fish_history") == "fish", "fish detected")

    xo = parse_xonsh_json('{"data": {"cmds": [{"inp": "ls\\n", "ts": [1700000000, 1700000001]}]}}')
    check(xo is not None and len(xo) == 1 and xo[0].command == "ls", "xonsh json parse")
    check(parse_xonsh_json("not json at all") is None, "xonsh non-json rejected")

    # ---- v1.1: Git Bash / MSYS2-style home collection ------------------
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        (home / ".bash_history").write_text("#1700000000\nnetstat -ano\nipconfig /all\n", encoding="utf-8")
        (home / ".zsh_history").write_text(": 1700000000:0;kubectl get pods\n", encoding="utf-8")
        (home / ".fish_history").write_text("- cmd: nmap -sS 10.0.0.0/24\n  when: 1700000000\n", encoding="utf-8")
        (home / ".python_history").write_text("import os\n", encoding="utf-8")
        gctx = UserContext(
            user="analyst", sid="S-1-5-21-2", profile_path=str(home),
            appdata=str(home), localappdata=str(home), hive_view=DictHiveView({}),
        )
        pblocks = collect_posix_ports(gctx, collected, False, include_repls=False)
        names = {b.name for b in pblocks}
        check("Bash-Git" in names, f"Bash-Git block missing: {names}")
        check("Zsh-Git" in names, f"Zsh-Git block missing: {names}")
        check("Fish-Git" in names, f"Fish-Git block missing: {names}")
        check("REPL" not in names, "REPL must stay off without --include-repls")
        bg = next(b for b in pblocks if b.name == "Bash-Git")
        check(len(bg.rows) == 2, f"Bash-Git rows {len(bg.rows)}")
        # newest first
        check(bg.rows[0].typed_value == "ipconfig /all", f"Bash-Git order {bg.rows[0].typed_value!r}")
        check(bg.rows[0].timestamp_provenance == PROV_FILE_MTIME_LAST, "Bash-Git last line mtime")
        check(bg.rows[1].timestamp_provenance == PROV_HISTTIME_EPOCH, "Bash-Git epoch row")
        check(bg.rows[1].shell == "bash", "Bash-Git shell field")
        zg = next(b for b in pblocks if b.name == "Zsh-Git")
        check(zg.rows[0].timestamp_provenance == PROV_HISTTIME_EPOCH, "Zsh-Git epoch row")

        rblocks = collect_posix_ports(gctx, collected, False, include_repls=True)
        check(any(b.name == "REPL" and b.rows for b in rblocks), "REPL appears with --include-repls")

    # ---- v1.1: WSL inventory without a live WSL ------------------------
    with tempfile.TemporaryDirectory() as tmp:
        base2 = Path(tmp) / "Ubuntu2"
        (base2).mkdir(parents=True)
        (base2 / "ext4.vhdx").write_bytes(b"\x00" * 4096)
        base1 = Path(tmp) / "Legacy1"
        wsl1_home = base1 / "rootfs" / "home" / "opsuser"
        wsl1_home.mkdir(parents=True)
        (wsl1_home / ".bash_history").write_text("uname -a\ncat /etc/passwd\n", encoding="utf-8")
        lw2 = dt.datetime(2025, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
        g1 = "{11111111-1111-1111-1111-111111111111}"
        g2 = "{22222222-2222-2222-2222-222222222222}"
        lxss_tree = {
            LXSS_PATH: {"last_write": lw2, "values": {}, "subkeys": [g1, g2]},
            LXSS_PATH + "\\" + g1: {
                "last_write": lw2,
                "values": {
                    "DistributionName": ("Ubuntu-22.04", 1),
                    "BasePath": (str(base2), 1),
                    "Version": (2, 4),
                    "DefaultUid": (1000, 4),
                },
                "subkeys": [],
            },
            LXSS_PATH + "\\" + g2: {
                "last_write": lw2,
                "values": {
                    "DistributionName": ("Legacy-WSL1", 1),
                    "BasePath": (str(base1), 1),
                    "Version": (1, 4),
                    "DefaultUid": (0, 4),
                },
                "subkeys": [],
            },
        }
        wctx = UserContext(
            user="analyst", sid="S-1-5-21-3", profile_path=tmp,
            appdata=tmp, localappdata=tmp, hive_view=DictHiveView(lxss_tree),
        )
        wblocks = collect_wsl(wctx, collected, False, online=False, offline=False, allow_exec=False)
        winv = next((b for b in wblocks if b.name == "WSL-Inventory"), None)
        check(winv is not None, "WSL-Inventory block emitted")
        assert winv is not None
        check(len(winv.rows) == 2, f"WSL-Inventory rows {len(winv.rows)}")
        by_name = {r.typed_value: r for r in winv.rows}
        check("Ubuntu-22.04" in by_name and "Legacy-WSL1" in by_name, "WSL distro names")
        u = by_name["Ubuntu-22.04"]
        check(f"history_state={WSL_HIST_NOT_DETERMINED}" in u.extra, f"WSL2 state marker: {u.extra}")
        check("ext4.vhdx" in u.extra and "vhdx_size_bytes=4096" in u.extra, f"vhdx inventory: {u.extra}")
        check("not determined" in u.extra, f"VHDX existence must not be asserted: {u.extra}")
        check(u.timestamp_provenance == PROV_UNAVAILABLE, "inventory row has no invented time")
        check(u.key_lastwrite_utc == "2025-01-02T03:04:05Z", f"Lxss lastwrite {u.key_lastwrite_utc}")
        legacy = by_name["Legacy-WSL1"]
        check(f"history_state={WSL_HIST_CONFIRMED_READ}" in legacy.extra, f"WSL1 state marker: {legacy.extra}")
        wbash = next((b for b in wblocks if b.name == "WSL-Bash"), None)
        check(wbash is not None and len(wbash.rows) == 2, "WSL1 bash history collected")
        assert wbash is not None
        check(wbash.rows[0].distro == "Legacy-WSL1", f"WSL distro tag {wbash.rows[0].distro!r}")
        check(wbash.rows[1].utc_timestamp == "", "older WSL line carries no time")

        # Empty Lxss must still produce the inventory table
        eblocks = collect_wsl(
            UserContext(user="u", sid="", profile_path=tmp, appdata=tmp, localappdata=tmp,
                        hive_view=DictHiveView({})),
            collected, False, online=False, offline=False, allow_exec=False,
        )
        check(any(b.name == "WSL-Inventory" for b in eblocks), "WSL-Inventory present with no Lxss")

    # ---- v1.1: scope gating and required tables ------------------------
    check("legacy-explorer" not in parse_sources(None), "Explorer MRU off by default")
    check(parse_sources(None) == DEFAULT_SOURCES, "default source set")
    check(parse_sources("legacy-explorer") == {"legacy-explorer"}, "explorer selectable")
    req = ensure_required_blocks([], DEFAULT_SOURCES)
    req_names = {b.name for b in req}
    for must in ("CMD-LiveDoskey", "CMD-Clink", "Powershell", "Bash-Git", "Bash-MSYS2",
                 "Bash-Cygwin", "WSL-Inventory", "WSL-Bash"):
        check(must in req_names, f"required table missing: {must}")
    check(all(b.checked and b.empty_reason for b in req), "required tables marked checked")
    ordered = order_blocks(
        [SourceBlock(name="CollectionErrors"), SourceBlock(name="Powershell"), SourceBlock(name="CMD-Clink")]
    )
    check([b.name for b in ordered][-1] == "CollectionErrors", "errors table sorts last")
    check(next(b.name for b in ordered) == "CMD-Clink", "block order applied")
    check(BANNER_SCOPE in banner_text({"sources": []}, False), "banner carries scope statement")

    # ---- v1.4.1: defects found by reading real output, not by tests ------
    # All three shipped with a green selftest. They were visible the moment a
    # report from a real host was read.
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        psdir = home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
        psdir.mkdir(parents=True)
        ps_file = psdir / "ConsoleHost_history.txt"
        ps_file.write_text("whoami /priv\nnet user\n", encoding="utf-8")
        pctx = UserContext(user="jdoe", sid="S-1-5-21-1-2-3-1001", profile_path=str(home),
                           appdata=str(home / "AppData" / "Roaming"),
                           localappdata=str(home / "AppData" / "Local"),
                           hive_view=DictHiveView({}))
        psblocks = collect_powershell_for_user(pctx, collected, False)
        psrows = [r for b in psblocks for r in b.rows]
        check(psrows, "PowerShell fixture produced rows")
        # DEFECT 1: every file-backed row must name the file it came from.
        check(all(r.artifact for r in psrows),
              "PowerShell rows must carry their artifact path, or the report says "
              "'(source not recorded)' for thousands of commands")
        check(all(str(ps_file) == r.artifact for r in psrows), "artifact is the history file")

        # DEFECT 2: a span may only be drawn from shell-recorded times. With
        # exact_times=0 the only stamp is a file MTIME, and rendering that as
        # a range presents one instant as a period.
        rp = Path(tmp) / "r.txt"
        export_txt(rp, {"hostname": "h", "sources": [], "sources_checked": []},
                   psblocks, [], False, False, presence=None)
        report = rp.read_text()
        check("(source not recorded)" not in report, "the report names the source file")
        check("exact_times=0" in report, "coverage reports zero exact times for PSReadLine")
        for line in report.splitlines():
            if "exact_times=0" in line:
                check("span=" not in line,
                      f"no span may be drawn without exact times: {line.strip()}")
        # ... and a source that DOES have exact times still gets one
        eblk = SourceBlock(name="CMD-Clink", header_meta={"per_file": [{"path": "C:\\h"}]})
        eblk.rows = [
            IntentRow(source="CMD-Clink", user="u", sid="", profile_path="", value_name="1",
                      typed_value="a", raw_value="a", mru_pos=0,
                      utc_timestamp="2026-01-01T00:00:00Z",
                      timestamp_provenance=PROV_CLINK_EPOCH, collected_utc=collected,
                      key_lastwrite_utc="", extra="", shell="cmd", artifact="C:\\h"),
        ]
        rp2 = Path(tmp) / "r2.txt"
        export_txt(rp2, {"hostname": "h", "sources": [], "sources_checked": []},
                   [eblk], [], False, False, presence=None)
        check("span=2026-01-01" in rp2.read_text(), "a real span is still drawn from exact times")

    # DEFECT 3: probes must be filed against the block for their own shell.
    # Routing them all to Bash let a zsh directory mark the Bash table
    # unreadable while the Zsh table showed no evidence at all.
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        (home / ".bash_history").write_text("", encoding="utf-8")
        (home / ".zsh_history").mkdir()
        rctx = UserContext(user="a", sid="S-1-5-21-1-2-3-1001", profile_path=str(home),
                           appdata=str(home), localappdata=str(home),
                           hive_view=DictHiveView({}))
        rblocks = collect_posix_ports(rctx, collected, False, include_repls=False)
        rpres = {p.type_name: p for p in build_presence(rblocks, DEFAULT_SOURCES, [])}
        check("empty artifact" in rpres["Bash (Git for Windows)"].detail,
              f"the empty bash history must be the Bash finding: "
              f"{rpres['Bash (Git for Windows)'].detail}")
        check(rpres["Zsh (POSIX ports)"].presence == PRESENCE_UNANSWERED,
              f"the unreadable zsh path must be the Zsh finding: "
              f"{rpres['Zsh (POSIX ports)'].presence}")
        bash_blk = next(b for b in rblocks if b.name == "Bash-Git")
        bash_probes = {e["path"] for e in bash_blk.header_meta.get("probed_paths", [])}
        check(not any("zsh" in pth for pth in bash_probes),
              f"zsh candidates must not be probed onto the Bash block: {bash_probes}")

    # the banner's elevation field is about THIS TOOL, never a collected session
    _banner = banner_text({"sources": [], "elevated": True}, False)
    check("Collector elevated" in _banner,
          "the banner must scope its elevation field to the collector")
    check("NOT a property of any collected session" in _banner,
          "the banner must say whose elevation it is reporting")

    # ---- v1.4.1: who column ---------------------------------------------
    _who_sys = IntentRow(source="Powershell", user="SYSTEM", sid="S-1-5-18", profile_path="",
                         value_name="1", typed_value="whoami", raw_value="x", mru_pos=0,
                         utc_timestamp="", timestamp_provenance=PROV_ORDER_ONLY,
                         collected_utc=collected, key_lastwrite_utc="", extra="",
                         shell="powershell", artifact="C:\\h")
    check(who_label(_who_sys) == "system:SYSTEM", f"who label: {who_label(_who_sys)}")
    _who_user = IntentRow(**{**asdict(_who_sys), "user": "jdoe", "sid": "S-1-5-21-1-2-3-1001"})
    check(who_label(_who_user) == "usr:jdoe", f"who label: {who_label(_who_user)}")
    _who_long = IntentRow(**{**asdict(_who_sys), "user": "a" * 40, "sid": "S-1-5-18"})
    check(len(who_label(_who_long)) <= WHO_COL, "who label is trimmed to the column width")
    check(CMD_COL > WHO_COL, "the command gutter accounts for the who column")
    # the column must actually reach the rendered report, not merely exist
    with tempfile.TemporaryDirectory() as tmp:
        wblk = SourceBlock(name="Powershell", header_meta={"per_file": [{"path": "C:\\h"}]})
        wblk.rows = [_who_sys, IntentRow(**{**asdict(_who_sys), "user": "jdoe",
                                            "sid": "S-1-5-21-1-2-3-1001", "value_name": "2"})]
        wp = Path(tmp) / "w.txt"
        export_txt(wp, {"hostname": "h", "sources": [], "sources_checked": []},
                   [wblk], [], False, False, presence=None)
        wtext = wp.read_text()
        check("system:SYSTEM" in wtext, "the who column must render a SYSTEM row")
        check("usr:jdoe" in wtext, "the who column must render an ordinary user row")
        check("sid=S-1-5-18" in wtext, "the full SID belongs in the artifact header")
        for line in wtext.splitlines():
            if "whoami" in line:
                check("system:SYSTEM" in line or "usr:jdoe" in line,
                      f"every command line carries its who label: {line.strip()}")

    # ---- v1.4.0: privilege context --------------------------------------
    for sid, expected in (
        ("S-1-5-18", PRIV_SYSTEM), ("S-1-5-19", PRIV_SERVICE), ("S-1-5-20", PRIV_SERVICE),
        ("S-1-5-21-1-2-3-500", PRIV_BUILTIN_ADMIN), ("S-1-5-21-1-2-3-1001", PRIV_USER),
        ("", PRIV_UNKNOWN), ("garbage", PRIV_UNKNOWN), ("S-1-5-21-1-2-3-501", PRIV_USER),
    ):
        got = privilege_for_sid(sid)
        check(got == expected, f"privilege_for_sid({sid!r}) = {got}, expected {expected}")
    check(all(p in PRIVILEGE_CONTEXTS for p in
              (PRIV_SYSTEM, PRIV_SERVICE, PRIV_BUILTIN_ADMIN, PRIV_USER, PRIV_UNKNOWN)),
          "privilege vocabulary is closed")
    # There must be no "elevated" value: UAC's split token means an admin's
    # elevated and non-elevated shells share one history file.
    _priv_consts = {
        n: v for n, v in globals().items() if n.startswith("PRIV_") and isinstance(v, str)
    }
    _unregistered_priv = {n: v for n, v in _priv_consts.items() if v not in PRIVILEGE_CONTEXTS}
    check(not _unregistered_priv, f"privilege constants outside the vocabulary: {_unregistered_priv}")
    check(not any("elevat" in v.lower() for v in _priv_consts.values()),
          f"no elevated value may enter the privilege vocabulary: {_priv_consts}")
    check("split token" in PRIVILEGE_CAVEAT and "not recoverable" in PRIVILEGE_CAVEAT.lower(),
          "the UAC limit must be stated in the caveat")

    # SYSTEM/service profiles are not under C:\\Users, so ProfileList must find them
    with tempfile.TemporaryDirectory() as tmp:
        sysprof = Path(tmp) / "Windows" / "System32" / "config" / "systemprofile"
        (sysprof / "AppData" / "Roaming").mkdir(parents=True)
        svc = Path(tmp) / "Windows" / "ServiceProfiles" / "LocalService"
        svc.mkdir(parents=True)
        plist = {"S-1-5-18": str(sysprof), "S-1-5-19": str(svc),
                 "S-1-5-21-1-2-3-1001": str(Path(tmp) / "gone")}
        ctxs = _profilelist_contexts(plist, {}, set(), [])
        by_priv = {c.privilege: c for c in ctxs}
        check(PRIV_SYSTEM in by_priv, f"SYSTEM profile discovered: {[c.privilege for c in ctxs]}")
        check(PRIV_SERVICE in by_priv, "service profile discovered")
        check(len(ctxs) == 2, f"a ProfileList path that does not exist is skipped: {len(ctxs)}")
        check(by_priv[PRIV_SYSTEM].profile_path == str(sysprof), "SYSTEM profile path carried")
        # a path already walked under C:\\Users must not be duplicated
        check(len(_profilelist_contexts(plist, {}, {os.path.normcase(str(sysprof))}, [])) == 1,
              "already-seen profile paths are not duplicated")
    # Behavioural: iter_all_users must UNION the ProfileList profiles with the
    # C:\Users walk. An AST check is not enough - there is a second call site
    # on the no-Users-directory fallback, so removing the union still leaves a
    # reference behind while SYSTEM silently disappears.
    with tempfile.TemporaryDirectory() as tmp:
        fake_users = Path(str(Path(tmp) / "drive") + "\\Users")
        (fake_users / "alice").mkdir(parents=True)
        sysprof2 = Path(tmp) / "sysprofile"
        sysprof2.mkdir()
        _real_plist = globals()["profile_list_map"]
        _old_drive = os.environ.get("SystemDrive")
        os.environ["SystemDrive"] = str(Path(tmp) / "drive")
        globals()["profile_list_map"] = lambda: {"S-1-5-18": str(sysprof2)}
        try:
            merged = iter_all_users(False, [])
        finally:
            globals()["profile_list_map"] = _real_plist
            if _old_drive is None:
                os.environ.pop("SystemDrive", None)
            else:
                os.environ["SystemDrive"] = _old_drive
        privs = {c.privilege for c in merged}
        paths = {os.path.normcase(c.profile_path) for c in merged}
        check(PRIV_SYSTEM in privs,
              f"iter_all_users must union in ProfileList profiles or SYSTEM stays invisible: {privs}")
        check(os.path.normcase(str(fake_users / "alice")) in paths,
              f"the C:\\Users walk must still contribute: {paths}")

    # ---- v1.4.0: prove absence ------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "empty.txt").write_text("", encoding="utf-8")
        (root / "full.txt").write_text("whoami\n", encoding="utf-8")
        check(probe_path(root / "nothere.txt")[0] == ABSENCE_PATH_ABSENT, "absent path")
        check(probe_path(root / "empty.txt")[0] == ABSENCE_PRESENT_EMPTY,
              "a zero-byte artifact is empty, NOT absent")
        check(probe_path(root / "full.txt")[0] == ABSENCE_READ_OK, "readable artifact")
        check(ABSENCE_PRESENT_EMPTY != ABSENCE_PATH_ABSENT,
              "empty and absent must never be the same outcome")
        check(set(ABSENCE_UNANSWERED) <= set(ABSENCE_OUTCOMES), "unanswered outcomes are outcomes")
        check(ABSENCE_PATH_ABSENT not in ABSENCE_UNANSWERED,
              "an absent path IS answered; only unreadable ones are not")

        # a cleared history file must not read as 'never existed'
        home = root / "prof"
        home.mkdir()
        (home / ".bash_history").write_text("", encoding="utf-8")
        actx = UserContext(user="a", sid="S-1-5-21-1-2-3-1001", profile_path=str(home),
                           appdata=str(root), localappdata=str(root),
                           hive_view=DictHiveView({}))
        ablocks = collect_posix_ports(actx, collected, False, include_repls=False)
        apres = {p.type_name: p for p in build_presence(ablocks, DEFAULT_SOURCES, [])}
        detail = apres["Bash (Git for Windows)"].detail
        check("empty artifact" in detail, f"a cleared history file must be reported: {detail}")
        bg = next(b for b in ablocks if b.name == "Bash-Git")
        outcomes = block_absence_summary(bg)
        check(outcomes.get(ABSENCE_PRESENT_EMPTY) == 1, f"empty recorded: {outcomes}")
        # each shell's probes are filed on its own block now
        all_outcomes: dict[str, int] = {}
        for blk in ablocks:
            for k, v in block_absence_summary(blk).items():
                all_outcomes[k] = all_outcomes.get(k, 0) + v
        check(all_outcomes.get(ABSENCE_PATH_ABSENT, 0) > 0,
              f"absent paths recorded across the shell blocks: {all_outcomes}")
        zsh_blk = next((b for b in ablocks if b.name == "Zsh-Git"), None)
        check(zsh_blk is not None and block_absence_summary(zsh_blk),
              "a zsh candidate path must be probed on the Zsh block, not the Bash one")
        check(all(e["outcome"] in ABSENCE_OUTCOMES for e in bg.header_meta["probed_paths"]),
              "probe outcomes stay in the closed vocabulary")

        # A path that exists but cannot be opened is an UNANSWERED question.
        # A directory standing where a history file is expected reproduces
        # that without depending on filesystem permissions (root ignores them).
        blocked = root / "blocked"
        blocked.mkdir()
        (blocked / ".bash_history").mkdir()
        check(probe_path(blocked / ".bash_history")[0] == ABSENCE_PRESENT_UNREADABLE,
              "an unopenable path is unreadable, not absent")
        uctx = UserContext(user="a", sid="S-1-5-21-1-2-3-1001", profile_path=str(blocked),
                           appdata=str(root), localappdata=str(root),
                           hive_view=DictHiveView({}))
        ublocks = collect_posix_ports(uctx, collected, False, include_repls=False)
        upres = {p.type_name: p for p in build_presence(ublocks, DEFAULT_SOURCES, [])}
        ugit = upres["Bash (Git for Windows)"]
        check(ugit.presence == PRESENCE_UNANSWERED,
              f"an unreadable path must not be reported as absence: {ugit.presence}")
        check(ugit.presence != PRESENCE_ABSENT, "unreadable is never None detected")

    # ---- v1.4.0: install vs remnant --------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        live = root / "nu"
        (live / "0.99.1").mkdir(parents=True)
        (live / "0.99.1" / "nu.exe").write_text("x")
        (live / "current").mkdir()
        dead = root / "elvish"
        (dead / "0.21.0").mkdir(parents=True)
        state, why = classify_install_state(live, "scoop", "dir")
        check(state == INSTALL_STATE_INSTALLED, f"scoop live app: {state} ({why})")
        state, why = classify_install_state(dead, "scoop", "dir")
        check(state == INSTALL_STATE_REMNANT, f"scoop remnant: {state} ({why})")
        choco_live = root / "xonsh"
        choco_live.mkdir()
        (choco_live / "xonsh.nuspec").write_text("x")
        check(classify_install_state(choco_live, "chocolatey", "dir")[0] == INSTALL_STATE_INSTALLED,
              "chocolatey nuspec receipt means installed")
        choco_dead = root / "empty_pkg"
        choco_dead.mkdir()
        check(classify_install_state(choco_dead, "chocolatey", "dir")[0] == INSTALL_STATE_REMNANT,
              "an empty chocolatey lib folder is a documented remnant, not an install")
        binary = root / "atuin.exe"
        binary.write_text("x")
        check(classify_install_state(binary, "cargo", "file")[0] == INSTALL_STATE_INSTALLED,
              "a cargo entry point is the install evidence")
        check(classify_install_state(root / "gone.exe", "cargo", "file")[0] == INSTALL_STATE_REMNANT,
              "a missing entry point is a remnant")
        check(all(classify_install_state(live, lbl, "dir")[0] in INSTALL_STATES
                  for lbl in ("scoop", "chocolatey", "winget (portable)", "pip/conda")),
              "install states stay in the closed vocabulary")

    # ---- v1.4.0: WSL existence is never assumed --------------------------
    check(not any("unreachable" in v for v in WSL_HISTORY_STATES),
          f"no state may imply history exists but is unreachable: {WSL_HISTORY_STATES}")
    check(WSL_HIST_NOT_DETERMINED in WSL_HISTORY_STATES, "not-determined is a first-class state")

    # ---- v1.4.0: timeline ------------------------------------------------
    def _trow(name: str, when: str, prov: str, sid: str = "S-1-5-21-1-2-3-1001") -> IntentRow:
        return IntentRow(
            source=name, user="op", sid=sid, profile_path="", value_name="1",
            typed_value=f"cmd-{when or 'none'}", raw_value="x", mru_pos=0,
            utc_timestamp=when, timestamp_provenance=prov, collected_utc=collected,
            key_lastwrite_utc="", extra="", shell="bash",
        )

    tblk = SourceBlock(name="Bash-Git")
    tblk.rows = [
        _trow("Bash-Git", "2026-01-02T03:04:05Z", PROV_HISTTIME_EPOCH),
        _trow("Bash-Git", "", PROV_ORDER_ONLY),
        _trow("Bash-Git", "2026-01-01T00:00:00Z", PROV_DB_EPOCH),
        _trow("Bash-Git", "2026-05-05T00:00:00Z", PROV_FILE_MTIME_LAST),
    ]
    sysblk = SourceBlock(name="Powershell")
    sysblk.rows = [_trow("Powershell", "2026-01-01T12:00:00Z", PROV_CLINK_EPOCH, "S-1-5-18")]
    timed, excluded = build_timeline([tblk, sysblk])
    check([r.utc_timestamp for r in timed] ==
          ["2026-01-01T00:00:00Z", "2026-01-01T12:00:00Z", "2026-01-02T03:04:05Z"],
          f"timeline is ascending and exact-only: {[r.utc_timestamp for r in timed]}")
    check(excluded == 2, f"order_only and file-MTIME rows are excluded, got {excluded}")
    check(all(r.timestamp_provenance in EXACT_PROVENANCE for r in timed),
          "a timeline row must carry a shell-recorded time")
    cov = dict((name, (t, n)) for name, t, n in timestamp_coverage([tblk, sysblk]))
    check(cov["Bash-Git"] == (2, 4), f"coverage counts exact times only: {cov}")
    check(privilege_for_sid(timed[1].sid) == PRIV_SYSTEM,
          "a SYSTEM-context row is identifiable in the timeline")
    # inventory and config records are not commands and must not skew coverage
    cfgblk = SourceBlock(name="History-Policy")
    cfgblk.rows = [_trow("History-Policy", "", PROV_UNAVAILABLE)]
    _, excl2 = build_timeline([tblk, sysblk, cfgblk])
    check(excl2 == excluded, "config records are not counted as excluded commands")

    # ---- v1.4.0: --diagnose and collection are mutually exclusive --------
    _mode_src = _ast.parse(source_text)
    _main_fn = next(n for n in _ast.walk(_mode_src)
                    if isinstance(n, _ast.FunctionDef) and n.name == "main")
    _diag_guard = [
        n for n in _ast.walk(_main_fn)
        if isinstance(n, _ast.If)
        and any(getattr(a, "attr", "") == "diagnose" for a in _ast.walk(n.test))
    ]
    check(_diag_guard, "main() must gate diagnostics behind args.diagnose")
    check(any(isinstance(x, _ast.Return) for n in _diag_guard for x in _ast.walk(n)),
          "the diagnose branch must return before any collection happens")
    _buf3 = _io.StringIO()
    _saved_stdout = sys.stdout
    try:
        sys.stdout = _buf3
        run_diagnostics()
    finally:
        sys.stdout = _saved_stdout
    _diag_out = _buf3.getvalue()
    for table in ("TERMINAL / SHELL INVENTORY", "ATT&CK TECHNIQUES OBSERVED",
                  "HISTORY LOCATION", "HISTORY POLICY"):
        check(table not in _diag_out, f"--diagnose must not render the {table} table")
    check("history entries written to" not in _diag_out,
          "--diagnose must not announce a report file")
    _summary_out = "\n".join(
        attack_summary_lines(map_attack_techniques([tblk]))
        + config_summary_lines([cfgblk])
    )
    check("ATT&CK TECHNIQUES OBSERVED" in _summary_out and "HISTORY POLICY" in _summary_out,
          "a collection run still renders its tables")

    # ---- regression: unbounded reads ------------------------------------
    # The size cap now lives inside read_text_guess, because several callers
    # guarded it and several did not - the diagnostics probe would slurp a
    # multi-gigabyte history file to inspect twelve lines.
    with tempfile.TemporaryDirectory() as tmp:
        oversized = Path(tmp) / "big.txt"
        with oversized.open("wb") as fh:
            fh.write(b"echo hello\n")
            fh.write(b"A" * (MAX_HISTORY_BYTES + 4096))
        _text, _enc = read_text_guess(oversized)
        check(len(_text) <= MAX_HISTORY_BYTES, "read_text_guess must cap what it loads")
        check("truncated" in _enc, f"truncation must be visible to the caller: {_enc}")
        ordinary = Path(tmp) / "s.txt"
        ordinary.write_text("echo hi\n", encoding="utf-8")
        check(read_text_guess(ordinary) == ("echo hi\n", "utf-8-sig"),
              "an ordinary file is read unchanged")

    # ---- regression: config matcher denial-of-service -------------------
    # The clear-on-exit patterns hold `[^\n]*` between two literals. On a long
    # line with many candidate starts the engine backtracks quadratically: a
    # planted .bashrc of repeated `rm ` tokens took ~8.6s at 200KB and hours
    # at the file-size cap, producing no output and no report - the same
    # silent-hang class as the _wrap_text bug.
    import time as _time

    with tempfile.TemporaryDirectory() as tmp:
        adversarial = Path(tmp) / ".bashrc"
        adversarial.write_text("rm " * 300_000 + "\n", encoding="utf-8")
        _t0 = _time.monotonic()
        _found, _anom = scan_config_file(adversarial, ("bash",))
        _elapsed = _time.monotonic() - _t0
        check(_elapsed < 5.0, f"adversarial config line must not stall the scan ({_elapsed:.1f}s)")
        check(_anom.get("oversize_lines_skipped") == 1,
              f"the over-long line must be reported as an anomaly: {_anom}")
        check(_found == [], "an unmatchable over-long line yields no findings")

        # the cap must not break legitimate directives of ordinary length
        normal = Path(tmp) / ".bash_logout"
        normal.write_text("rm -f ~/.bash_history\nhistory -c\n", encoding="utf-8")
        _nf, _na = scan_config_file(normal, ("bash",))
        check(len(_nf) == 2 and all(f.effect == EFFECT_CLEARS_ON_EXIT for f in _nf),
              f"ordinary clear-on-exit lines still match: {[(f.effect, f.line) for f in _nf]}")
        check(not _na, "a clean file reports no anomaly")

        # the substring gate must not suppress a real match
        gated = Path(tmp) / ".zlogout"
        gated.write_text("shred -u /home/u/.zsh_history\n", encoding="utf-8")
        _gf, _ = scan_config_file(gated, ("zsh",))
        check(any(f.effect == EFFECT_CLEARS_ON_EXIT for f in _gf),
              f"gated pattern still matches when the literal is present: {_gf}")

    # ---- v1.3.1: --diagnose --------------------------------------------
    # The mode exists to close the Windows execution gap with observation.
    # What it must never do is leak evidence into a paste-able report.
    _clink_secret = "net user attacker P@ssw0rd123 /add"
    with tempfile.TemporaryDirectory() as tmp:
        cdir = Path(tmp) / "clink"
        cdir.mkdir()
        (cdir / "clink_settings").write_text(
            "history.save = True\nhistory.time_stamp = save\n", encoding="utf-8")
        (cdir / "clink_history").write_text(
            f"|CTAG_1_9\n# 1757000000\n{_clink_secret}\n|eleted entry\n", encoding="utf-8")
        _old_profile = os.environ.get("CLINK_PROFILE")
        os.environ["CLINK_PROFILE"] = str(cdir)
        try:
            results = diagnose_clink()
            blob = " ".join(f"{r.probe} {r.detail}" for r in results)
            check(_clink_secret not in blob and "P@ssw0rd123" not in blob,
                  "diagnose must never print command text")
            check("EPOCH COMMENT" in blob,
                  f"epoch-comment shape must be reported: {blob[:200]}")
            check("history.time_stamp = save" in blob,
                  "the time_stamp setting must be surfaced")
            check("tombstoned" in blob, "tombstone shape reported")
            check("not shown" in blob, "command lines are reported by length only")
        finally:
            if _old_profile is None:
                os.environ.pop("CLINK_PROFILE", None)
            else:
                os.environ["CLINK_PROFILE"] = _old_profile

    for _probe in (diagnose_console, diagnose_system32, diagnose_drive_types,
                   diagnose_reparse_points, diagnose_registry, diagnose_wsl,
                   diagnose_paths):
        _res = _probe()
        check(isinstance(_res, list) and _res, f"{_probe.__name__} returns results")
        check(all(r.status in DIAG_STATUSES for r in _res),
              f"{_probe.__name__} statuses stay in vocabulary: {[r.status for r in _res]}")
        check(all(r.probe and r.detail for r in _res),
              f"{_probe.__name__} rows are fully populated")

    # off-Windows, the Windows-only probes must SKIP rather than FAIL - a
    # skipped probe is an unanswered question, not a defect
    if os.name != "nt":
        for _probe in (diagnose_drive_types, diagnose_reparse_points, diagnose_wsl):
            check(all(r.status != DIAG_FAIL for r in _probe()),
                  f"{_probe.__name__} must SKIP off-Windows, not FAIL")

    # a probe that raises must be reported, not take the run down
    _real_probe = globals()["diagnose_registry"]

    def _exploding_probe() -> list[DiagnosticResult]:
        raise RuntimeError("simulated probe failure")

    _buf = _io.StringIO()
    _real_stdout = sys.stdout
    try:
        globals()["diagnose_registry"] = _exploding_probe
        sys.stdout = _buf
        rc = run_diagnostics()
    finally:
        sys.stdout = _real_stdout
        globals()["diagnose_registry"] = _real_probe
    _out = _buf.getvalue()
    check(rc == 1, "a failing probe must set a non-zero exit code")
    check("simulated probe failure" in _out, "a raising probe is reported, not swallowed")
    check("SUMMARY" in _out, "the report still completes after a probe failure")

    # a normal run reports and collects nothing
    _buf2 = _io.StringIO()
    try:
        sys.stdout = _buf2
        run_diagnostics()
    finally:
        sys.stdout = _real_stdout
    _clean = _buf2.getvalue()
    check("diagnostics" in _clean and "SUMMARY" in _clean, "diagnostics render end to end")
    check("collects no history" in _clean, "the mode states that it collects nothing")

    # ---- v1.3.0: ATT&CK technique mapping --------------------------------
    # Techniques only. The group-exclusion assertions below are the guard:
    # group listings read as artifact claims and get filled with invented
    # case studies, so no group data may exist anywhere in the module.
    check(all(ATTACK_ID_RE.match(tid) for tid in ATTACK_TECHNIQUES),
          f"technique ids must match T####[.###]: {list(ATTACK_TECHNIQUES)}")
    check(all(tac in ATTACK_TACTICS for _n, tac in ATTACK_TECHNIQUES.values()),
          "tactics stay in the closed vocabulary")
    _rule_ids = {tid for tid, _b in ATTACK_BLOCK_RULES}
    check(_rule_ids <= set(ATTACK_TECHNIQUES),
          f"every mapped id exists in the static table: {_rule_ids - set(ATTACK_TECHNIQUES)}")
    check(not re.search(r"\bG\d{4}\b", source_text),
          "no ATT&CK group identifier may appear anywhere in the module")

    check(map_attack_techniques([]) == [], "clean host produces an empty mapping")
    _empty_block = SourceBlock(name="Bash-Git", empty_reason="Checked; no artifacts found")
    check(map_attack_techniques([_empty_block]) == [],
          "a checked-but-empty table implies no technique")

    def _arow(name: str, n: int) -> IntentRow:
        return IntentRow(
            source=name, user="u", sid="", profile_path="", value_name=str(n),
            typed_value=f"cmd{n}", raw_value=f"cmd{n}", mru_pos=n, utc_timestamp="",
            timestamp_provenance=PROV_ORDER_ONLY, collected_utc=collected,
            key_lastwrite_utc="", extra="", shell="",
        )

    def _afix(name: str, count: int = 1) -> SourceBlock:
        blk = SourceBlock(name=name)
        blk.rows = [_arow(name, i) for i in range(count)]
        return blk

    # the fixture the spec names: Clink history + a .bash_logout with
    # history -c + a registered WSL distro
    _pol = SourceBlock(name="History-Policy")
    _pol.rows = [
        IntentRow(source="History-Policy", user="u", sid="", profile_path="",
                  value_name=".bash_logout:1", typed_value="history -c", raw_value="history -c",
                  mru_pos=None, utc_timestamp="", timestamp_provenance=PROV_UNAVAILABLE,
                  collected_utc=collected, key_lastwrite_utc="",
                  extra=f"config=.bash_logout; line=1; effect={EFFECT_CLEARS_ON_EXIT}",
                  shell="bash"),
    ]
    _scenario = [
        _afix("CMD-Clink", 2), _afix("Bash-Git", 3), _afix("WSL-Inventory", 1), _pol,
    ]
    _got = {f.technique for f in map_attack_techniques(_scenario)}
    check(_got == {"T1059.003", "T1059.004", "T1202", "T1070.003", "T1552.003"},
          f"scenario must produce exactly the five expected techniques, got {sorted(_got)}")

    _findings = map_attack_techniques(_scenario)
    check(all(f.basis.strip() for f in _findings),
          "every technique row must carry a traceable evidence basis")
    check(all(f.name == ATTACK_TECHNIQUES[f.technique][0] for f in _findings),
          "names come from the static table, never generated prose")
    check(all(f.tactic == ATTACK_TECHNIQUES[f.technique][1] for f in _findings),
          "tactics come from the static table")
    _clink = next(f for f in _findings if f.technique == "T1059.003")
    check("CMD-Clink" in _clink.basis and "2" in _clink.basis,
          f"basis names the block and count: {_clink.basis}")
    _clear = next(f for f in _findings if f.technique == "T1070.003")
    check(".bash_logout:1" in _clear.basis, f"basis names config file and line: {_clear.basis}")

    # a config table holding only NON-destructive effects must not fire
    # T1070.003 - HISTTIMEFORMAT preserves history, it does not clear it
    _benign = SourceBlock(name="History-Policy")
    _benign.rows = [
        IntentRow(source="History-Policy", user="u", sid="", profile_path="",
                  value_name=".bashrc:3", typed_value="export HISTTIMEFORMAT='%F %T '",
                  raw_value="x", mru_pos=None, utc_timestamp="",
                  timestamp_provenance=PROV_UNAVAILABLE, collected_utc=collected,
                  key_lastwrite_utc="",
                  extra=f"config=.bashrc; line=3; effect={EFFECT_PRESERVES}", shell="bash"),
        IntentRow(source="History-Policy", user="u", sid="", profile_path="",
                  value_name=".bashrc:4", typed_value="HISTIGNORE='ls*'",
                  raw_value="x", mru_pos=None, utc_timestamp="",
                  timestamp_provenance=PROV_UNAVAILABLE, collected_utc=collected,
                  key_lastwrite_utc="",
                  extra=f"config=.bashrc; line=4; effect={EFFECT_FILTERS}", shell="bash"),
    ]
    check(map_attack_techniques([_benign]) == [],
          "preserves/filters effects must not be read as history destruction")

    # obscure shells map to the parent, never to an invented sub-technique
    _obscure = map_attack_techniques([_afix("Nushell", 1), _afix("Elvish", 1)])
    _oids = {f.technique for f in _obscure}
    check("T1059" in _oids, f"obscure shells map to the T1059 parent: {_oids}")
    check(not any(t.startswith("T1059.") for t in _oids if t != "T1552.003"),
          f"no sub-technique may be invented for obscure shells: {_oids}")

    # relocation to removable media must NOT be mapped to exfiltration
    _loc = SourceBlock(name="History-Location")
    _loc.rows = [
        IntentRow(source="History-Location", user="u", sid="", profile_path="",
                  value_name=".bashrc:2", typed_value="export HISTFILE=E:\\h",
                  raw_value="x", mru_pos=None, utc_timestamp="",
                  timestamp_provenance=PROV_UNAVAILABLE, collected_utc=collected,
                  key_lastwrite_utc="", extra=f"volume={VOLUME_REMOVABLE}", shell="bash"),
    ]
    check(map_attack_techniques([_loc]) == [],
          "a relocated HISTFILE is a lead, not an exfiltration technique")

    # WSL registration alone implies indirect execution but no shell history
    _wsl_only = {f.technique for f in map_attack_techniques([_afix("WSL-Inventory", 2)])}
    check(_wsl_only == {"T1202"}, f"WSL registration alone maps to T1202 only: {_wsl_only}")

    # renderings carry the caveat and never leak group data
    _summary = "\n".join(attack_summary_lines(_findings))
    check(ATTACK_VERSION in _summary, "terminal table states the ATT&CK version")
    check("no threat-group or attribution claims" in _summary,
          "terminal table states the non-attribution caveat")
    check(not re.search(r"\bG\d{4}\b", _summary), "no group id in the terminal table")
    check("none" in "\n".join(attack_summary_lines([])).lower(),
          "empty mapping renders an explicit 'none' rather than a blank table")
    with tempfile.TemporaryDirectory() as tmp:
        jp = Path(tmp) / "a.json"
        export_json(jp, {"hostname": "h"}, _scenario, [])
        doc = json.loads(jp.read_text())
        check(doc["attack"]["attack_version"] == ATTACK_VERSION, "JSON carries ATT&CK version")
        check({t["technique"] for t in doc["attack"]["techniques"]} == _got,
              "JSON mapping matches the derived findings")
        check(not re.search(r"\bG\d{4}\b", jp.read_text()), "no group id in the JSON export")
        rp = Path(tmp) / "a.txt"
        export_txt(rp, {"hostname": "h", "sources": [], "sources_checked": []},
                   _scenario, [], False, False, presence=None)
        flat = " ".join(rp.read_text().split())
        check("ATT&CK TECHNIQUES OBSERVED" in flat, "report carries the mapping section")
        check("makes no threat-group or attribution claims" in flat,
              "report carries the non-attribution caveat")
        check(not re.search(r"\bG\d{4}\b", rp.read_text()), "no group id in the report")

    # ---- v1.2.1: drive-type mapping (mapping-verified, not execution-verified)
    # GetDriveTypeW cannot run off-Windows, so query_drive_type is the seam the
    # test substitutes. This asserts the MAPPING; the Win32 call itself remains
    # unexecuted anywhere in this project.
    _real_query = globals()["query_drive_type"]
    try:
        for code, expected in (
            (0, VOLUME_UNKNOWN), (1, VOLUME_ABSENT), (2, VOLUME_REMOVABLE),
            (3, VOLUME_FIXED), (4, VOLUME_REMOTE), (5, VOLUME_UNKNOWN),
            (6, VOLUME_UNKNOWN), (99, VOLUME_UNKNOWN),
        ):
            globals()["query_drive_type"] = lambda _d, _c=code: _c
            got = classify_volume(r"E:\hist\bash_history")
            check(got == expected, f"DRIVE code {code} should map to {expected}, got {got}")
        # the USB answer Goal 1 exists for
        globals()["query_drive_type"] = lambda _d: 2
        check(classify_volume(r"E:\h") == VOLUME_REMOVABLE, "removable drive detected")
        # a failed lookup degrades, never raises
        globals()["query_drive_type"] = lambda _d: None
        check(classify_volume(r"E:\nope\h") in VOLUME_KINDS, "failed lookup stays in vocabulary")

        def _boom(_d):
            raise OSError("simulated Win32 failure")

        globals()["query_drive_type"] = _boom
        raised = False
        try:
            classify_volume(r"E:\h")
        except OSError:
            raised = True
        check(raised, "seam propagates only because the real one swallows errors")
    finally:
        globals()["query_drive_type"] = _real_query
    check(query_drive_type("E:\\") is None or isinstance(query_drive_type("E:\\"), int),
          "real query_drive_type never raises")
    check(set(DRIVE_TYPE_MAP.values()) <= set(VOLUME_KINDS), "drive map stays in vocabulary")

    # ---- v1.2.1: nushell nested record form ------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        nested = Path(tmp) / "config.nu"
        nested.write_text(
            "$env.config = {\n"
            "    history: {\n"
            '        file_format: "sqlite"\n'
            "        max_size: 100_000\n"
            "        isolation: true\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        nf, _ = scan_config_file(nested, ("nushell",))
        effects = {f.effect for f in nf}
        check(EFFECT_RELOCATES in effects, f"nested file_format matched: {effects}")
        check(EFFECT_LIMITS in effects, f"nested max_size matched: {effects}")
        check(EFFECT_FILTERS in effects, f"nested isolation matched: {effects}")
        flat = Path(tmp) / "flat.nu"
        flat.write_text("$env.config.history.max_size = 1000\n", encoding="utf-8")
        check(any(f.effect == EFFECT_LIMITS for f in scan_config_file(flat, ("nushell",))[0]),
              "flat assignment form still matched")
        neither = Path(tmp) / "plain.nu"
        neither.write_text("$env.PROMPT_INDICATOR = '> '\nalias ll = ls -l\n", encoding="utf-8")
        check(scan_config_file(neither, ("nushell",))[0] == [],
              "a nushell config with no history settings yields nothing")

    # ---- v1.2.1: machine-scope PowerShell profiles -----------------------
    with tempfile.TemporaryDirectory() as tmp:
        fake_root = Path(tmp) / "Windows"
        ps5 = fake_root / "System32" / "WindowsPowerShell" / "v1.0"
        ps5.mkdir(parents=True)
        (ps5 / "profile.ps1").write_text(
            "Set-PSReadLineOption -HistorySaveStyle SaveNothing\n", encoding="utf-8")
        _old_sr = os.environ.get("SystemRoot")
        os.environ["SystemRoot"] = str(fake_root)
        try:
            machine = powershell_machine_profiles()
            check(any(p.name == "profile.ps1" for p, _f, _r in machine),
                  f"AllUsersAllHosts profile discovered: {[str(p) for p, _f, _r in machine]}")
            check(any(p.name == "Microsoft.PowerShell_profile.ps1" for p, _f, _r in machine),
                  "AllUsersCurrentHost profile discovered")
            mctx = UserContext(user="a", sid="S-1", profile_path=tmp, appdata=tmp,
                               localappdata=tmp, hive_view=DictHiveView({}))
            with_m = collect_config_policy(mctx, collected, False, [], include_machine_scope=True)
            pol = next(b for b in with_m if b.name == "History-Policy")
            check(any("SaveNothing" in r.typed_value for r in pol.rows),
                  "machine-scope profile is actually read")
            check(any("scope=machine" in r.extra for r in pol.rows),
                  f"machine scope recorded: {[r.extra for r in pol.rows][:1]}")
            without = collect_config_policy(mctx, collected, False, [],
                                            include_machine_scope=False)
            pol2 = next(b for b in without if b.name == "History-Policy")
            check(not any("SaveNothing" in r.typed_value for r in pol2.rows),
                  "machine scope skipped on subsequent profiles")
        finally:
            if _old_sr is None:
                os.environ.pop("SystemRoot", None)
            else:
                os.environ["SystemRoot"] = _old_sr

    # ---- v1.2.1: the Clink format assumption must be stated in the output --
    with tempfile.TemporaryDirectory() as tmp:
        cdir = Path(tmp) / "clink"
        cdir.mkdir()
        (cdir / "clink_history").write_text("|CTAG_1\n# 1700000000\nnet user\n", encoding="utf-8")
        actx = UserContext(user="a", sid="S-1", profile_path=tmp, appdata=tmp,
                           localappdata=tmp, hive_view=DictHiveView({}))
        cblk = collect_clink(actx, collected, False)
        note = cblk.header_meta.get("UNVERIFIED_timestamp_format", "")
        check("ASSUMPTION" in note and "clink_embedded_epoch" in note,
              "Clink block must declare its unverified timestamp assumption")
        rp = Path(tmp) / "r.txt"
        export_txt(rp, {"hostname": "h", "sources": [], "sources_checked": ["CMD-Clink"]},
                   [cblk], [], False, False, presence=None)
        # the note is wrapped for readability, so compare on normalised whitespace
        flat_report = " ".join(rp.read_text().split())
        check("unverified format assumption" in flat_report,
              "the assumption must reach the report an examiner reads")

    # ---- v1.2.0: history-policy configuration scanner --------------------
    check(classify_volume("/dev/null") == VOLUME_NULL, "null device classified")
    check(classify_volume("NUL") == VOLUME_NULL, "windows null device classified")
    check(classify_volume(r"\\\\server\\share\\h.txt") == VOLUME_REMOTE, "UNC is remote")
    check(classify_volume("//server/share/h") == VOLUME_REMOTE, "posix UNC is remote")
    check(classify_volume(r"C:\\Users\\a\\OneDrive\\h.txt") == VOLUME_CLOUD, "cloud-sync detected")
    check(classify_volume("$HOME/.bash_history") == VOLUME_UNKNOWN,
          "unexpanded variable is not guessed at")
    # a drive letter WITH a variable must stay unknown rather than be resolved
    check(classify_volume(r"C:\%USERNAME%\hist") == VOLUME_UNKNOWN,
          "a path holding an unexpanded variable is never classified by drive")
    check(classify_volume("") == VOLUME_UNKNOWN, "empty path is unknown")
    check(classify_volume(r"Z:\\nope\\h") in VOLUME_KINDS, "classification stays in vocabulary")

    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        (home / ".bashrc").write_text(
            "export PATH=/usr/local/bin:$PATH\n"
            "export HISTFILE=E:\\\\hist\\\\bash_history\n"
            "export HISTTIMEFORMAT='%F %T '\n"
            "HISTIGNORE='curl*:ssh*'\n"
            "export API_KEY=sk-MUST-NOT-APPEAR\n"
            "# HISTSIZE=0\n",
            encoding="utf-8",
        )
        (home / ".bash_logout").write_text("history -c\nrm -f ~/.bash_history\n", encoding="utf-8")
        (home / ".zshrc").write_text("SAVEHIST=0\nsetopt EXTENDED_HISTORY\n", encoding="utf-8")
        (home / ".profile").write_text("export EDITOR=vim\n", encoding="utf-8")

        bash_f, _ = scan_config_file(home / ".bashrc", ("bash",))
        effects = {(f.effect, f.line) for f in bash_f}
        check(any(e == EFFECT_RELOCATES for e, _ in effects), "HISTFILE relocation matched")
        check(any(e == EFFECT_FILTERS and "HISTIGNORE" in ln for e, ln in effects),
              "HISTIGNORE recorded verbatim as a filter")
        check(any(e == EFFECT_PRESERVES for e, _ in effects), "HISTTIMEFORMAT recorded as preserving")
        # scope: nothing outside the two goals may be captured
        blob = " ".join(f.line for f in bash_f)
        check("API_KEY" not in blob and "SUPERSECRET" not in blob and "sk-MUST-NOT-APPEAR" not in blob,
              f"secret leaked out of a config file: {blob}")
        check("PATH=" not in blob.replace("HISTFILE=", ""), "$PATH must never be collected")
        check(all("HISTSIZE" not in f.line for f in bash_f), "commented-out settings are ignored")
        loc = [f for f in bash_f if f.effect == EFFECT_RELOCATES]
        check(loc and loc[0].declared_path.startswith("E:"), f"declared path captured: {loc}")
        check(loc[0].lineno == 2, f"line number recorded: {loc[0].lineno}")

        logout, _ = scan_config_file(home / ".bash_logout", ("bash",))
        check(sum(1 for f in logout if f.effect == EFFECT_CLEARS_ON_EXIT) == 2,
              f"clear-on-exit found in .bash_logout: {[f.effect for f in logout]}")

        zsh_f, _ = scan_config_file(home / ".zshrc", ("zsh",))
        check(any(f.effect == EFFECT_SUPPRESSES for f in zsh_f), "SAVEHIST=0 suppresses")
        check(any(f.effect == EFFECT_PRESERVES for f in zsh_f), "EXTENDED_HISTORY preserves")

        # a clean config must yield nothing at all - no false positives
        check(scan_config_file(home / ".profile", ("bash",))[0] == [],
              "clean config produced a false positive")

        # HISTFILE=/dev/null is both relocation and destruction
        (home / ".zshenv").write_text("HISTFILE=/dev/null\n", encoding="utf-8")
        dual, _ = scan_config_file(home / ".zshenv", ("zsh",))
        check({f.effect for f in dual} == {EFFECT_RELOCATES, EFFECT_SUPPRESSES},
              f"/dev/null must be classified as both: {[f.effect for f in dual]}")

        # every emitted effect and volume stays inside the closed vocabularies
        allf = bash_f + logout + zsh_f + dual
        check(all(f.effect in POLICY_EFFECTS for f in allf), "effects stay in vocabulary")
        check(all(f.volume in VOLUME_KINDS or f.volume == "" for f in allf),
              "volumes stay in vocabulary")

        # cross-check: declared path differs from the artifact actually collected
        (home / ".bash_history").write_text("whoami\n", encoding="utf-8")
        cctx = UserContext(user="a", sid="S-1", profile_path=str(home), appdata=str(home),
                           localappdata=str(home), hive_view=DictHiveView({}))
        hist_blocks = collect_posix_ports(cctx, collected, False, include_repls=False)
        cfg_blocks = collect_config_policy(cctx, collected, False, hist_blocks)
        names = {b.name for b in cfg_blocks}
        check(names == {"History-Location", "History-Policy"}, f"config blocks: {names}")
        cloc = next(b for b in cfg_blocks if b.name == "History-Location")
        check(any("declared_path_not_among_collected_artifacts" in r.extra for r in cloc.rows),
              "declared path not among collected artifacts must be flagged")
        check(any("artifact_may_be_off_this_machine" in r.extra for r in cloc.rows),
              "removable/absent declared path must be called out")
        cpol = next(b for b in cfg_blocks if b.name == "History-Policy")
        check(all(r.timestamp_provenance == PROV_UNAVAILABLE for r in cpol.rows),
              "config rows carry no invented event time")
        check(all("config_mtime_utc=" in r.extra for r in cpol.rows),
              "config file mtime recorded on every finding")
        check(any("line=" in r.extra for r in cpol.rows), "line numbers recorded on rows")
        # redaction must reach config lines
        red_blocks = collect_config_policy(cctx, collected, True, hist_blocks)
        check(red_blocks is not None, "redacted config scan runs")

        # a commented-out directive must not be reported as active policy
        (home / ".bash_logout").write_text(
            "# history -c\n#rm -f ~/.bash_history\nhistory -c\n", encoding="utf-8")
        commented, _ = scan_config_file(home / ".bash_logout", ("bash",))
        check(len(commented) == 1 and commented[0].lineno == 3,
              f"commented directives must be ignored: {[(f.lineno, f.line) for f in commented]}")

        # a config file reached through a planted link is never read
        outside = Path(tmp) / "outside_cfg"
        outside.write_text("export HISTFILE=E:\\planted\nSECRET-VIA-LINK\n", encoding="utf-8")
        linked_home = Path(tmp) / "linkhome"
        linked_home.mkdir()
        try:
            os.symlink(outside, linked_home / ".bashrc")
            can_link = True
        except (OSError, NotImplementedError):
            can_link = False
        if can_link:
            lctx = UserContext(user="a", sid="S-1", profile_path=str(linked_home),
                               appdata=str(linked_home), localappdata=str(linked_home),
                               hive_view=DictHiveView({}))
            lblocks = collect_config_policy(lctx, collected, False, [])
            ltext = " ".join(r.typed_value for b in lblocks for r in b.rows)
            check("SECRET-VIA-LINK" not in ltext and "planted" not in ltext,
                  "config scanner followed a planted link out of the profile")
            check([m for b in lblocks for m in collect_rejections(b.header_meta)],
                  "config link rejection must be recorded")

        # empty-but-checked must be distinguishable from never-looked
        with tempfile.TemporaryDirectory() as empty_tmp:
            ectx = UserContext(user="a", sid="S-1", profile_path=empty_tmp, appdata=empty_tmp,
                               localappdata=empty_tmp, hive_view=DictHiveView({}))
            eblocks = collect_config_policy(ectx, collected, False, [])
            epol = next(b for b in eblocks if b.name == "History-Policy")
            check(not epol.rows and "not evidence" in epol.empty_reason,
                  f"empty policy table must state the symmetry: {epol.empty_reason}")

        # terminal tables render and state the caveat
        summary = "\n".join(config_summary_lines(cfg_blocks))
        check("HISTORY LOCATION" in summary and "HISTORY POLICY" in summary,
              "both config tables render in the terminal")
        check("Absence of suppression config is not evidence" in summary,
              "terminal states the absence caveat")

    # ---- v1.1.2: security fixes (A-F) -----------------------------------
    def _secrow(v: str) -> IntentRow:
        return IntentRow(
            source="Bash-Git", user="u", sid="", profile_path="", value_name="1",
            typed_value=v, raw_value=v, mru_pos=0, utc_timestamp="",
            timestamp_provenance=PROV_ORDER_ONLY, collected_utc=collected,
            key_lastwrite_utc="", extra="", shell="bash",
        )

    # A. CSV formula injection - neutralised in the CSV writer ONLY.
    for leader in CSV_FORMULA_LEADERS:
        check(csv_safe(leader + "calc") [0] not in CSV_FORMULA_LEADERS,
              f"csv_safe leaves a formula trigger for {leader!r}")
    check(csv_safe("ls -la") == "ls -la", "ordinary command unchanged in CSV")
    check(csv_safe(5) == 5, "non-strings pass through csv_safe")
    with tempfile.TemporaryDirectory() as tmp:
        ablk = SourceBlock(name="Bash-Git")
        payloads = ["=cmd|'/c calc'!A0", "+1+1", "-1+1", "@SUM(1)", "\tx", "\rx"]
        ablk.rows = [_secrow(p) for p in payloads]
        csv_path = Path(tmp) / "a.csv"
        export_csv(csv_path, [ablk])
        import csv as _csv
        cells = [r[5] for r in list(_csv.reader(csv_path.read_text().splitlines()))[1:]]
        check(all(c[:1] not in CSV_FORMULA_LEADERS for c in cells),
              f"CSV still carries formula triggers: {cells}")
        # evidence integrity: JSON keeps the byte-exact original
        json_path = Path(tmp) / "a.json"
        export_json(json_path, {"hostname": "h"}, [ablk], [])
        got = json.loads(json_path.read_text())["sources"]["Bash-Git"]["rows"]
        check([r["typed_value"] for r in got] == payloads,
              "JSON export must not be sanitised - it is the evidence copy")

    # B. Output files are created exclusively; a planted link is not followed.
    with tempfile.TemporaryDirectory() as tmp:
        victim = Path(tmp) / "victim.txt"
        victim.write_text("ORIGINAL")
        trap = Path(tmp) / "report.txt"
        try:
            os.symlink(victim, trap)
            linked = True
        except (OSError, NotImplementedError):
            linked = False
        bblk = SourceBlock(name="Bash-Git")
        bblk.rows = [_secrow("ls")]
        if linked:
            raised = False
            try:
                export_txt(trap, {"hostname": "h", "sources": [], "sources_checked": []},
                           [bblk], [], False, False, presence=None)
            except FileExistsError:
                raised = True
            check(raised, "exclusive create must refuse an existing path")
            check(victim.read_text() == "ORIGINAL", "symlink target must be untouched")
        plain = Path(tmp) / "plain.txt"
        plain.write_text("KEEP")
        raised = False
        try:
            export_txt(plain, {"hostname": "h", "sources": [], "sources_checked": []},
                       [bblk], [], False, False, presence=None)
        except FileExistsError:
            raised = True
        check(raised and plain.read_text() == "KEEP", "existing regular file is not truncated")
        # a free name is still found so a run never silently loses its report
        base = Path(tmp) / "intention_h_2026"
        Path(str(base) + ".txt").write_text("taken")
        alt = free_output_path(base, ".txt")
        check(alt != Path(str(base) + ".txt") and not alt.exists(), "free_output_path avoids collision")

    # C. Terminal control sequences are escaped in displayed values only.
    ansi = "ls \x1b]0;PWNED\x07 \x1b[2J\x7f"
    safe = display_safe(ansi)
    check("\x1b" not in safe and "\x07" not in safe and "\x7f" not in safe,
          f"display_safe left control characters: {safe!r}")
    check("\\x1b" in safe, "escaped form is visible to the examiner")
    check(display_safe("a\nb\tc") == "a\nb\tc", "newline and tab are preserved")
    with tempfile.TemporaryDirectory() as tmp:
        cblk = SourceBlock(name="Bash-Git")
        cblk.rows = [_secrow(ansi)]
        rp = Path(tmp) / "c.txt"
        export_txt(rp, {"hostname": "h", "sources": [], "sources_checked": []},
                   [cblk], [], False, False, presence=None)
        check("\x1b" not in rp.read_text(), "report must not carry raw ESC")
        jp = Path(tmp) / "c.json"
        export_json(jp, {"hostname": "h"}, [cblk], [])
        check("\u001b" in json.loads(jp.read_text())["sources"]["Bash-Git"]["rows"][0]["raw_value"],
              "raw_value keeps the original bytes so nothing is lost")

    # D. Link containment - fails CLOSED when no root is supplied.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        home = root / "prof"
        home.mkdir()
        outside = root / "outside.txt"
        outside.write_text("SENSITIVE-OUTSIDE-SCOPE\n")
        inside = home / "real_hist"
        inside.write_text("- cmd: inside link ok\n  when: 1700000000\n")
        (home / ".zsh_history").write_text(": 1700000000:0;legit command\n")
        try:
            os.symlink(outside, home / ".bash_history")
            os.symlink(inside, home / ".fish_history")
            links = True
        except (OSError, NotImplementedError):
            links = False
        if links:
            check(link_escapes_root(home / ".bash_history", home) is not None,
                  "escaping link detected against an explicit root")
            check(link_escapes_root(home / ".bash_history", None) is not None,
                  "containment fails CLOSED when no root is passed")
            check(link_escapes_root(home / ".fish_history", home) is None,
                  "a link staying inside the root is allowed")
            check(link_escapes_root(home / ".zsh_history", home) is None,
                  "an ordinary file is never rejected")
            dctx = UserContext(user="a", sid="S-1", profile_path=str(home),
                               appdata=str(root), localappdata=str(root),
                               hive_view=DictHiveView({}))
            dblocks = collect_posix_ports(dctx, collected, False, include_repls=False)
            dvals = [r.typed_value for b in dblocks for r in b.rows]
            check(not any("SENSITIVE-OUTSIDE-SCOPE" in v for v in dvals),
                  "collector followed a link out of the profile")
            check(any("legit command" in v for v in dvals), "ordinary file still collected")
            rejections = [m for b in dblocks for m in collect_rejections(b.header_meta)]
            check(rejections, "a rejected link must be recorded, not silently skipped")

            # the SQLite reader needs the same guard: a linked history DB
            # must never be opened.
            real_db = root / "real.db"
            con = _sq.connect(real_db)
            con.execute("CREATE TABLE history (id text primary key, timestamp integer not null,"
                        " duration integer not null, exit integer not null, command text not null,"
                        " cwd text not null, session text not null, hostname text not null,"
                        " deleted_at integer)")
            con.execute("INSERT INTO history VALUES"
                        " ('a',1700000000000000000,1,0,'SECRET-DB-COMMAND','/h','s','n',NULL)")
            con.commit(); con.close()
            db_home = root / "dbhome"
            db_home.mkdir()
            os.symlink(real_db, db_home / "history.db")
            db_rows, db_meta = rows_from_sqlite_history(
                db_home / "history.db", source="Atuin", shell="atuin", ctx=dctx,
                collected=collected, redact=False, search_root=db_home, **ATUIN_SQLITE,
            )
            check(db_rows == [], "linked history database must not be opened")
            check(db_meta.get("rejected") == LINK_ESCAPE_NOTE, "database rejection recorded")

    # E. Argument injection into 7z / virt-copy-out / wsl.exe.
    check(not safe_cli_argument("-t7z"), "leading dash rejected")
    check(not safe_cli_argument(""), "empty argument rejected")
    check(safe_cli_argument("C:\\\\images\\\\ext4.vhdx"), "ordinary path accepted")
    check(try_vhdx_extract("-evil.vhdx", ("7z", "/usr/bin/7z"))[1]
          == "refused_unsafe_image_path", "switch-like image path refused before exec")
    # wsl.exe is absent on CI, so a return of None proves nothing on its own;
    # assert the guard is actually present in the function body.
    _wsl_fn = next(
        (n for n in _ast.walk(_ast.parse(source_text))
         if isinstance(n, _ast.FunctionDef) and n.name == "wsl_exec_read"), None
    )
    check(_wsl_fn is not None, "wsl_exec_read found")
    check(
        any(isinstance(c, _ast.Call) and getattr(c.func, "id", "") == "safe_cli_argument"
            for c in _ast.walk(_wsl_fn)),
        "wsl_exec_read must vet the registry-supplied distro name before exec",
    )
    check(wsl_exec_read("-e") is None, "switch-like distro name refused before exec")

    # F. Machine-scope package roots are walked once, not once per profile.
    _mctx = UserContext(user="a", sid="S-1", profile_path="/p", appdata="/p",
                        localappdata="/p", hive_view=DictHiveView({}))
    _all_roots = {lbl for lbl, _p, _k in package_manager_roots(_mctx, True)}
    _user_roots = {lbl for lbl, _p, _k in package_manager_roots(_mctx, False)}
    check("chocolatey" in _all_roots and "chocolatey" not in _user_roots,
          "machine-scope roots are separable from user-scope roots")
    check({"cargo", "pip/conda", "scoop"} <= _user_roots, "user-scope roots always scanned")
    # and the flag must be honoured by the scanner, not just the root builder
    with tempfile.TemporaryDirectory() as tmp:
        froot = Path(tmp)
        (froot / "choco" / "lib" / "nushell").mkdir(parents=True)
        (froot / "prof" / ".cargo" / "bin").mkdir(parents=True)
        (froot / "prof" / ".cargo" / "bin" / "atuin.exe").write_text("x")
        _old_choco = os.environ.get("ChocolateyInstall")
        os.environ["ChocolateyInstall"] = str(froot / "choco")
        try:
            fctx = UserContext(user="a", sid="S-1", profile_path=str(froot / "prof"),
                               appdata=str(froot), localappdata=str(froot),
                               hive_view=DictHiveView({}))
            with_machine = {r.source for r in scan_package_managers(fctx, True)}
            without = {r.source for r in scan_package_managers(fctx, False)}
            check("chocolatey" in with_machine, f"machine scope scanned when asked: {with_machine}")
            check("chocolatey" not in without,
                  f"machine scope must be skipped on later profiles: {without}")
            check("cargo" in without, "user-scope roots still scanned for every profile")
        finally:
            if _old_choco is None:
                os.environ.pop("ChocolateyInstall", None)
            else:
                os.environ["ChocolateyInstall"] = _old_choco

    # ---- structural invariants (v1.1.1) ---------------------------------
    # These assert properties of the module itself, so a future edit cannot
    # quietly break them.
    _mod_tree = _ast.parse(source_text)
    _top_defs = [n for n in _mod_tree.body if isinstance(n, (_ast.FunctionDef, _ast.ClassDef))]
    _def_order = {n.name: i for i, n in enumerate(_top_defs)}

    # 1. Provenance closure: nothing may emit a label outside the vocabulary.
    _prov_consts = {
        name: value
        for name, value in globals().items()
        if name.startswith("PROV_") and isinstance(value, str)
    }
    _unregistered = {n: v for n, v in _prov_consts.items() if v not in PROVENANCE_VOCABULARY}
    check(not _unregistered, f"provenance constants outside the vocabulary: {_unregistered}")
    check(set(PROV_TAG) == set(PROVENANCE_VOCABULARY),
          f"every provenance needs a report tag; diff="
          f"{set(PROV_TAG) ^ set(PROVENANCE_VOCABULARY)}")
    check(set(EXACT_PROVENANCE) <= set(PROVENANCE_VOCABULARY), "EXACT_PROVENANCE within vocabulary")

    # 2. Catalog completeness: no source may vanish from the inventory.
    _catalogued = {b for _t, _f, blocks_, _p, _pk in TERMINAL_CATALOG for b in blocks_}
    _known = _catalogued | set(BLOCK_ORDER) | {"CollectionErrors"}
    _selftest_node = next(
        (n for n in _ast.walk(_mod_tree)
         if isinstance(n, _ast.FunctionDef) and n.name == "run_selftest"), None
    )
    _test_span = range(_selftest_node.lineno, (_selftest_node.end_lineno or 0) + 1) \
        if _selftest_node else range(0)
    _literal_blocks = {
        kw.value.value
        for node in _ast.walk(_mod_tree)
        if isinstance(node, _ast.Call) and getattr(node.func, "id", "") == "SourceBlock"
        and node.lineno not in _test_span  # fixtures may name uncatalogued hosts on purpose
        for kw in node.keywords
        if kw.arg == "name" and isinstance(kw.value, _ast.Constant)
        and isinstance(kw.value.value, str)
    }
    check(_literal_blocks <= _known,
          f"block names not catalogued: {sorted(_literal_blocks - _known)}")
    # names built at runtime by the POSIX/WSL collectors must also be covered
    _generated = {f"{SHELL_LABELS[sh]}-{port}"
                  for sh in ("bash", "zsh", "fish", "ash")
                  for port in ("Git", "MSYS2", "Cygwin")}
    _generated |= {f"WSL-{SHELL_LABELS[sh]}" for sh in ("bash", "zsh", "fish", "ash")}
    check(_generated <= _known,
          f"generated block names not catalogued: {sorted(_generated - _known)}")

    # 3. Schema parity: CSV columns track the dataclass exactly.
    check(CSV_FIELDNAMES == [f.name for f in dataclass_fields(IntentRow)],
          f"CSV/IntentRow drift: {CSV_FIELDNAMES} vs {[f.name for f in dataclass_fields(IntentRow)]}")

    # 4. Loop convergence: every while must be able to stop. A loop qualifies
    #    if it can break, return/raise out, or assigns a name used in its test.
    _nonconverging = []
    for _node in _ast.walk(_mod_tree):
        if not isinstance(_node, _ast.While):
            continue
        _body = list(_ast.walk(_node))
        _exits = any(isinstance(x, (_ast.Break, _ast.Return, _ast.Raise)) for x in _body)
        _test_names = {x.id for x in _ast.walk(_node.test) if isinstance(x, _ast.Name)}
        _assigned = {
            t.id
            for x in _body
            if isinstance(x, (_ast.Assign, _ast.AugAssign))
            for t in _ast.walk(x.targets[0] if isinstance(x, _ast.Assign) else x.target)
            if isinstance(t, _ast.Name)
        }
        if not _exits and not (_test_names & _assigned):
            _nonconverging.append(_node.lineno)
    check(not _nonconverging, f"while loops with no visible progress: {_nonconverging}")

    # 5. Definition order: helpers precede their callers.
    _forward = []
    for _node in _mod_tree.body:
        if not isinstance(_node, _ast.FunctionDef):
            continue
        for _sub in _ast.walk(_node):
            if isinstance(_sub, _ast.Call) and isinstance(_sub.func, _ast.Name):
                _t = _sub.func.id
                if _t in _def_order and _def_order[_t] > _def_order[_node.name]:
                    _forward.append(f"{_node.name}->{_t}")
    check(not _forward, f"forward references: {sorted(set(_forward))}")

    # 6. No dead code: every top-level def is referenced somewhere.
    _entry_points = {"main", "run_selftest"}
    _used = {
        n.id for n in _ast.walk(_mod_tree) if isinstance(n, _ast.Name)
    } | {
        n.attr for n in _ast.walk(_mod_tree) if isinstance(n, _ast.Attribute)
    }
    _orphans = sorted(
        d.name for d in _top_defs
        if d.name not in _entry_points and d.name not in _used
        and not d.name.startswith("__")
    )
    check(not _orphans, f"unreferenced top-level definitions: {_orphans}")

    # 7. Read-only proof: a full pass over a fixture profile must not alter it.
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Path(tmp) / "profile"
        (fixture / "AppData" / "Local" / "clink").mkdir(parents=True)
        (fixture / "AppData" / "Roaming" / "nushell").mkdir(parents=True)
        (fixture / ".local" / "share" / "atuin").mkdir(parents=True)
        (fixture / ".bash_history").write_text("#1700000000\nwhoami\nls -la\n", encoding="utf-8")
        (fixture / "AppData" / "Local" / "clink" / "clink_history").write_text(
            "|CTAG_1\nnet user\n|eleted entry\n", encoding="utf-8")
        con = _sq.connect(fixture / "AppData" / "Roaming" / "nushell" / "history.sqlite3")
        con.execute("CREATE TABLE history (id INTEGER PRIMARY KEY, start_timestamp INTEGER,"
                    " command_line TEXT, cwd TEXT, exit_status INTEGER)")
        con.execute("INSERT INTO history (start_timestamp,command_line,cwd,exit_status)"
                    " VALUES (1700000000000,'ls','C:\\\\w',0)")
        con.commit(); con.close()
        con = _sq.connect(fixture / ".local" / "share" / "atuin" / "history.db")
        con.execute("CREATE TABLE history (id text primary key, timestamp integer not null,"
                    " duration integer not null, exit integer not null, command text not null,"
                    " cwd text not null, session text not null, hostname text not null,"
                    " deleted_at integer)")
        con.execute("INSERT INTO history VALUES ('a',1700000000000000000,1,0,'ssh h','/h','s','n',NULL)")
        con.commit(); con.close()

        def _snapshot() -> dict[str, str]:
            out: dict[str, str] = {}
            for item in sorted(fixture.rglob("*")):
                if item.is_file():
                    st = item.stat()
                    # content AND mtime: a read-only tool must not restamp
                    # evidence either. (atime is expected to move on read and
                    # is deliberately excluded.)
                    out[str(item.relative_to(fixture))] = (
                        f"{hashlib.sha256(item.read_bytes()).hexdigest()}"
                        f":{st.st_mtime_ns}:{st.st_size}"
                    )
            return out

        _before = _snapshot()
        _ro_ctx = build_user_context_from_profile(str(fixture))
        _ro_blocks = collect_for_context(
            _ro_ctx, DEFAULT_SOURCES, collected, False, False, RunOptions()
        )
        _after = _snapshot()
        check(_before == _after, "READ-ONLY: fixture artifacts altered by a collection pass")
        _strays = [k for k in _after if k.endswith(("-wal", "-shm", "-journal"))]
        check(not _strays, f"READ-ONLY: journal/sidecar files created: {_strays}")
        check(any(b.rows for b in _ro_blocks), "read-only fixture still produced rows")

    # ---- Task 3: system binaries must not resolve through PATH -----------
    check(system32_binary("cmd.exe").endswith("cmd.exe"), "resolver returns the binary name")
    with tempfile.TemporaryDirectory() as tmp:
        sysroot = Path(tmp) / "Windows"
        (sysroot / "System32").mkdir(parents=True)
        (sysroot / "System32" / "cmd.exe").write_text("stub")
        _old_root = os.environ.get("SystemRoot")
        os.environ["SystemRoot"] = str(sysroot)
        try:
            check(system32_binary("cmd.exe") == str(sysroot / "System32" / "cmd.exe"),
                  "System32 path preferred when the binary exists there")
            check(system32_binary("nosuch.exe") == "nosuch.exe",
                  "falls back to bare name when absent from System32")
        finally:
            if _old_root is None:
                del os.environ["SystemRoot"]
            else:
                os.environ["SystemRoot"] = _old_root
    _bare = [
        node.lineno
        for node in _ast.walk(_mod_tree)
        if isinstance(node, _ast.Call)
        and getattr(node.func, "attr", "") == "run"
        and node.args
        and isinstance(node.args[0], _ast.List)
        and node.args[0].elts
        and isinstance(node.args[0].elts[0], _ast.Constant)
        and str(node.args[0].elts[0].value).lower().endswith(".exe")
    ]
    check(not _bare, f"subprocess called with a bare .exe name at lines {_bare}")

    # ---- regression: console encoding on Windows -------------------------
    # `Intention.py --tables > out.txt` on Windows writes through the ANSI code
    # page (cp1252), not UTF-8, with errors="strict". Two separate hazards:
    # non-ASCII in our own literals, and non-ASCII in the recovered data.
    literal_offenders = [
        (node.lineno, node.value[:40])
        for node in _ast.walk(_ast.parse(source_text))
        if isinstance(node, _ast.Constant)
        and isinstance(node.value, str)
        and any(ord(ch) > 127 for ch in node.value)
    ]
    check(not literal_offenders, f"non-ASCII string literals: {literal_offenders[:3]}")

    # the helper must actually be wired into main(), not merely exist
    _tree = _ast.parse(source_text)
    _main = next(
        (n for n in _ast.walk(_tree)
         if isinstance(n, _ast.FunctionDef) and n.name == "main"), None
    )
    check(_main is not None, "main() found for wiring check")
    check(
        any(
            isinstance(c, _ast.Call) and getattr(c.func, "id", "") == "harden_console_encoding"
            for c in _ast.walk(_main)
        ),
        "main() must call harden_console_encoding() before it prints anything",
    )

    # Non-ASCII DATA, built at runtime so no source literal is itself non-ASCII.
    accented = "jos" + chr(0xE9)
    cyrillic = "".join(chr(c) for c in (0x43F, 0x430, 0x440, 0x43E, 0x43B, 0x44C))
    cp1252_block = SourceBlock(name="Bash-Git", header_meta={"path": "C:\\u.txt"})
    cp1252_block.rows = [
        IntentRow(
            source="Bash-Git", user="operator", sid="", profile_path="", value_name="1",
            typed_value=f"cat /home/{accented}/{cyrillic}.txt\nsecond line",
            raw_value="x", mru_pos=0, utc_timestamp="", timestamp_provenance=PROV_ORDER_ONLY,
            collected_utc=collected, key_lastwrite_utc="", extra="", shell="bash",
        )
    ]
    stream = _io.TextIOWrapper(_io.BytesIO(), encoding="cp1252", errors="strict", newline="")
    real_stdout = sys.stdout
    try:
        sys.stdout = stream
        harden_console_encoding()  # must flip the strict stream to replace
        print_plain_table(cp1252_block, False, None)
        rendered = True
    except UnicodeEncodeError:
        rendered = False
    finally:
        sys.stdout = real_stdout
    check(rendered, "cp1252 console must not raise UnicodeEncodeError on non-ASCII data")
    check(stream.errors == "replace", f"console hardened to errors=replace, got {stream.errors}")

    # the report keeps the real characters: it is opened UTF-8 regardless
    with tempfile.TemporaryDirectory() as tmp:
        rp = Path(tmp) / "u.txt"
        export_txt(rp, {"hostname": "h", "sources": [], "sources_checked": ["Bash-Git"]},
                   [cp1252_block], [], False, False, presence=None)
        recovered = rp.read_text(encoding="utf-8")
        check(accented in recovered, "UTF-8 report preserves accented characters")
        check(cyrillic in recovered, "UTF-8 report preserves Cyrillic")

    # ---- regression: _wrap_text must always consume input ---------------
    # An earlier build folded the continuation indent into the string being
    # measured, so any unbroken run of >= width characters looped forever and
    # grew the output list until the process was killed. That produced no
    # terminal output and no report file at all, because the report is written
    # before the summary is printed. Long paths, URLs, base64 and
    # -EncodedCommand payloads all hit it on a real host.
    for label, sample in (
        ("unbroken", "A" * 500),
        ("long path", "C:\\Users\\op\\AppData\\Local\\Temp\\" + "sub\\" * 40 + "p.exe"),
        ("encodedcommand", "powershell -EncodedCommand " + "aQBlAHgA" * 60),
        ("leading spaces", "    " + "B" * 300),
        ("multiline", "Get-Process `\n  -Name " + "C" * 200),
        ("exact width", "X" * 82),
        ("empty", ""),
        ("spaces only", "     "),
    ):
        wrapped = _wrap_text(sample, 82, " " * 36)
        check(len(wrapped) < 200, f"wrap did not converge for {label}: {len(wrapped)} lines")
        check(
            not any("wrap-guard" in line for line in wrapped),
            f"wrap needed its emergency guard for {label} - the loop is wrong again",
        )
        stripped = "".join(line.strip().lstrip("| ").strip() for line in wrapped)
        source = sample.replace("\n", "").replace(" ", "")
        check(
            len(stripped.replace(" ", "")) == len(source),
            f"wrap lost characters for {label}",
        )
    # a degenerate width must not stall either
    check(len(_wrap_text("A" * 200, 0, "  ")) < 200, "zero width clamped")
    check(len(_wrap_text("A" * 200, -5, "  ")) < 200, "negative width clamped")

    # ---- v1.1: presence inventory table --------------------------------
    def _row(name: str, n: int = 0, prov: str = PROV_ORDER_ONLY, extra: str = "") -> IntentRow:
        return IntentRow(
            source=name, user="analyst", sid="", profile_path="", value_name=str(n),
            typed_value=f"cmd{n}", raw_value=f"cmd{n}", mru_pos=n, utc_timestamp="",
            timestamp_provenance=prov, collected_utc=collected, key_lastwrite_utc="",
            extra=extra,
        )

    clink_blk = SourceBlock(name="CMD-Clink", header_meta={"per_file": [
        {"path": "C:\\Users\\a\\AppData\\Local\\clink\\clink_history", "mtime_utc": "2026-02-02T00:00:00Z"}
    ]})
    clink_blk.rows = [_row("CMD-Clink", 1), _row("CMD-Clink", 2, extra="deleted_entry=1")]
    nu_blk = SourceBlock(name="Nushell")
    nu_blk.rows = [_row("Nushell", 1), _row("Nushell", 2, prov=PROV_UNAVAILABLE)]
    empty_bash = SourceBlock(name="Bash-Git", empty_reason="Checked; no artifacts found")
    odd = SourceBlock(name="Powershell-CustomHost")
    odd.rows = [_row("Powershell-CustomHost", 1)]
    pres = build_presence([clink_blk, nu_blk, empty_bash, odd], DEFAULT_SOURCES)
    by_type = {p.type_name: p for p in pres}

    check(len(pres) >= len(TERMINAL_CATALOG), "every catalogued type is listed")
    for must in ("CMD + Clink", "Bash (Git for Windows)", "Bash (MSYS2)", "Bash (Cygwin)",
                 "WSL distros registered", "Ion", "Elvish", "Nushell", "Xonsh"):
        check(must in by_type, f"inventory missing type: {must}")
    check(by_type["Bash (Git for Windows)"].presence == PRESENCE_ABSENT, "empty block -> None detected")
    check(by_type["Bash (MSYS2)"].detail == PRESENCE_ABSENT, "never-seen block still listed as absent")
    check(by_type["Ion"].detail == PRESENCE_ABSENT, "absent esoteric shell retained in table")
    check(by_type["CMD (native cmd.exe)"].presence == PRESENCE_VOLATILE, "native cmd is volatile")
    check(by_type["Language REPLs"].presence == PRESENCE_NOT_CHECKED, "unselected family -> Not checked")
    ck = by_type["CMD + Clink"]
    check(ck.presence == PRESENCE_PRESENT and ck.commands == 2, f"clink count {ck.commands}")
    check("recoverable deleted" in ck.detail, f"deleted surfaced in presence: {ck.detail}")
    check(ck.last_write == "2026-02-02T00:00:00Z", f"LastWrite from file mtime: {ck.last_write}")
    nu = by_type["Nushell"]
    check(nu.commands == 1 and nu.unparsed == 1, f"unparsed split out: {nu.detail}")
    check("unreadable store" in nu.detail, f"unreadable store shown: {nu.detail}")
    other = [p for p in pres if p.type_name.startswith("Other hosts")]
    check(len(other) == 1 and "Powershell-CustomHost" in other[0].type_name,
          "uncatalogued host still appears in the inventory")

    # WSL inventory rows are distros, not commands
    wsl_blk = SourceBlock(name="WSL-Inventory")
    wsl_blk.rows = [_row("WSL-Inventory", 1, prov=PROV_UNAVAILABLE)]
    wpres = {p.type_name: p for p in build_presence([wsl_blk], DEFAULT_SOURCES)}
    check("distros registered" in wpres["WSL distros registered"].detail,
          f"WSL noun: {wpres['WSL distros registered'].detail}")

    # source paths must survive merge_blocks nesting them under per_user_meta
    merged = merge_blocks([clink_blk])
    check("clink_history" in " ".join(collected_source_paths(merged)),
          "artifact paths recovered from merged per-user metadata")
    check(collected_source_paths([empty_bash]) == [], "empty blocks contribute no sources")
    check(catalog_label("CMD-Clink") == "CMD + Clink", "block maps to catalog label")
    check(catalog_label("Nushell") == "Nushell", "unmapped label falls back to block name")

    # ---- v1.1: SQLite-backed history (nushell + atuin) -----------------

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        nu_db = root / "history.sqlite3"
        con = _sq.connect(nu_db)
        con.execute(
            "CREATE TABLE history (id INTEGER PRIMARY KEY, start_timestamp INTEGER,"
            " command_line TEXT, session_id INTEGER, hostname TEXT, cwd TEXT,"
            " duration_ms INTEGER, exit_status INTEGER, more_info TEXT)"
        )
        con.executemany(
            "INSERT INTO history (start_timestamp,command_line,cwd,exit_status) VALUES (?,?,?,?)",
            [(1700000000000, "ls | where size > 1kb", "C:\\work", 0),
             (1700000060000, "sudo -i", "C:\\work", 1)],
        )
        con.commit(); con.close()

        at_db = root / "history.db"
        con = _sq.connect(at_db)
        con.execute(
            "CREATE TABLE history (id text primary key, timestamp integer not null,"
            " duration integer not null, exit integer not null, command text not null,"
            " cwd text not null, session text not null, hostname text not null,"
            " deleted_at integer, author text, intent text, shell text)"
        )
        con.executemany(
            "INSERT INTO history VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [("a", 1700000000000000000, 1, 0, "ssh admin@10.0.0.5", "/h", "s1", "lab0",
              None, None, None, "zsh"),
             ("b", 1700000120000000000, 2, 1, "rm -rf /var/log", "/h", "s1", "lab0",
              1700000200000000000, None, None, "zsh")],
        )
        con.commit(); con.close()

        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (nu_db, at_db)}

        nu_entries, nu_meta = read_sqlite_history(nu_db, **NUSHELL_SQLITE)
        check(len(nu_entries) == 2, f"nushell sqlite rows {len(nu_entries)} err={nu_meta.get('error')}")
        # milliseconds must not be read as seconds (that would land in 1970)
        check(iso_utc(nu_entries[0].ts) == "2023-11-14T22:13:20Z",
              f"nushell ms epoch: {iso_utc(nu_entries[0].ts)}")
        check(nu_entries[0].prov == PROV_DB_EPOCH, "nushell rows are db_recorded_epoch")
        check("cwd=C:\\work" in nu_entries[0].note, f"nushell cwd captured: {nu_entries[0].note}")
        check("exit_status=1" in nu_entries[1].note, "nushell exit status captured")

        at_entries, at_meta = read_sqlite_history(at_db, **ATUIN_SQLITE)
        check(len(at_entries) == 2, f"atuin rows {len(at_entries)} err={at_meta.get('error')}")
        # nanoseconds must not be read as seconds (that would land in the year 55000)
        check(iso_utc(at_entries[0].ts) == "2023-11-14T22:13:20Z",
              f"atuin ns epoch: {iso_utc(at_entries[0].ts)}")
        check(not at_entries[0].deleted and at_entries[1].deleted, "atuin soft-delete detected")
        check(at_meta.get("recoverable_deleted_rows") == 1, "atuin deleted count in meta")

        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (nu_db, at_db)}
        check(before == after, "READ-ONLY: history databases unchanged after parsing")
        strays = [p.name for p in root.iterdir() if p.name.endswith(("-wal", "-shm", "-journal"))]
        check(not strays, f"READ-ONLY: no journal files created ({strays})")

        # a database with no history table degrades, it does not raise
        junk = root / "records.db"
        con = _sq.connect(junk); con.execute("CREATE TABLE other (x INTEGER)"); con.commit(); con.close()
        j_entries, j_meta = read_sqlite_history(junk, **ATUIN_SQLITE)
        check(j_entries == [] and "error" in j_meta, "missing table degrades gracefully")

        actx = UserContext(user="analyst", sid="S-1-5-21-4", profile_path=tmp,
                           appdata=tmp, localappdata=tmp, hive_view=DictHiveView({}))
        adir = root / ".local" / "share" / "atuin"
        adir.mkdir(parents=True)
        (adir / "history.db").write_bytes(at_db.read_bytes())
        (adir / "records.db").write_bytes(junk.read_bytes())
        ablock = collect_atuin(actx, collected, False)
        check(len(ablock.rows) == 2, f"collect_atuin rows {len(ablock.rows)}")
        check(all("records.db" not in (m.get("path") or "")
                  for m in ablock.header_meta.get("per_file", [])),
              "atuin records.db is not probed as a history table")
        check(ablock.rows[0].artifact.endswith("history.db"), "artifact path recorded on row")

    check(_sqlite_epoch(1700000000) == unix_to_dt(1700000000), "second epochs pass through")
    check(_sqlite_epoch(0) is None and _sqlite_epoch("x") is None, "bad epochs rejected")

    # ---- v1.1: Installed column + report layout ------------------------
    inst_blk = SourceBlock(name="Bash-Git", header_meta={"per_file": [
        {"path": "C:\\Users\\a\\.bash_history", "ctime_utc": "2024-01-01T00:00:00Z",
         "mtime_utc": "2026-05-05T00:00:00Z"},
        {"path": "C:\\Users\\a\\.bash_history-OLD", "ctime_utc": "2023-02-02T00:00:00Z",
         "mtime_utc": "2023-03-03T00:00:00Z"},
    ]})
    inst_blk.rows = [_row("Bash-Git", 1)]
    ip = {p.type_name: p for p in build_presence([inst_blk], DEFAULT_SOURCES)}
    git_row = ip["Bash (Git for Windows)"]
    check(git_row.last_write == "2026-05-05T00:00:00Z", f"LastWrite = newest mtime: {git_row.last_write}")
    check(git_row.installed == "", "Installed is empty without an installation record")

    rep_blk = SourceBlock(name="Atuin", header_meta={"per_file": [
        {"path": "C:\\atuin\\history.db", "format": "sqlite", "ctime_utc": "2026-01-01T00:00:00Z"}
    ]})
    rep_blk.rows = [
        IntentRow(source="Atuin", user="a", sid="", profile_path="", value_name="1",
                  typed_value="ssh admin@10.0.0.5", raw_value="ssh admin@10.0.0.5", mru_pos=0,
                  utc_timestamp="2026-01-02T03:04:05Z", timestamp_provenance=PROV_DB_EPOCH,
                  collected_utc=collected, key_lastwrite_utc="",
                  extra="path=C:\\atuin\\history.db; file_index=1; cwd=/h; exit=0",
                  shell="atuin", artifact="C:\\atuin\\history.db"),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        rp = Path(tmp) / "r.txt"
        export_txt(rp, {"hostname": "h", "sources": [], "sources_checked": ["Atuin"]},
                   [rep_blk], [], False, False, presence=pres)
        text = rp.read_text()
        check("CONTENTS" in text and "LEGEND" in text, "report has contents and legend")
        check("TERMINAL / SHELL INVENTORY" in text, "report carries the inventory table")
        check("source: C:\\atuin\\history.db" in text, "report groups rows under their artifact")
        check("order: oldest -> newest" in text, "report states its ordering")
        check("-- 2026-01-02 " in text, "report rules off each date")
        # the command now appears twice by design: once in the TIMELINE and
        # once in its source section. Scope the per-source assertion to the
        # section body, after CONTENTS.
        body = text.split(" CONTENTS", 1)[1]
        cmd_lines = [ln for ln in body.splitlines() if "ssh admin@10.0.0.5" in ln]
        check(len(cmd_lines) == 1, f"one line per command in its section, got {len(cmd_lines)}")
        check("exact" in cmd_lines[0], "provenance tag on the command line")
        timeline_part = text.split(" CONTENTS", 1)[0]
        check("ssh admin@10.0.0.5" in timeline_part, "timed command also appears in the timeline")
        check("`- cwd=/h  exit=0" in text, "db context kept beside the command")
        check("path=C:" not in text.split("source:")[2] if text.count("source:") > 2 else True,
              "artifact path not repeated on every row")
    check(_row_context(rep_blk.rows[0]) == "cwd=/h  exit=0", "row context drops path and index")

    # ---- v1.1: real installation detection -----------------------------
    lw = dt.datetime(2026, 4, 5, 6, 7, 8, tzinfo=dt.timezone.utc)
    uninstall_tree = {
        UNINSTALL_REL: {"last_write": lw, "values": {}, "subkeys": ["Git_is1", "Clink_is1", "Junk"]},
        UNINSTALL_REL + "\\Git_is1": {
            "last_write": lw,
            "values": {
                "DisplayName": ("Git", 1),
                "DisplayVersion": ("2.45.1", 1),
                "InstallDate": ("20240311", 1),
                "InstallLocation": ("C:\\Program Files\\Git\\", 1),
                "Publisher": ("The Git Development Community", 1),
            },
            "subkeys": [],
        },
        UNINSTALL_REL + "\\Clink_is1": {
            "last_write": lw,
            "values": {
                "DisplayName": ("clink v1.6.5", 1),
                "InstallLocation": ("C:\\Program Files (x86)\\clink\\", 1),
            },
            "subkeys": [],
        },
        # no DisplayName -> must be skipped, not emitted as "(unnamed)"
        UNINSTALL_REL + "\\Junk": {"last_write": lw, "values": {"NoName": ("x", 1)}, "subkeys": []},
        MSI_USERDATA_REL: {"last_write": lw, "values": {}, "subkeys": ["S-1-5-18"]},
        MSI_USERDATA_REL + "\\S-1-5-18\\Products": {
            "last_write": lw, "values": {}, "subkeys": ["ABC123"],
        },
        MSI_USERDATA_REL + "\\S-1-5-18\\Products\\ABC123\\InstallProperties": {
            "last_write": lw,
            "values": {
                "DisplayName": ("MSYS2 64bit", 1),
                "InstallDate": ("20250102", 1),
                "InstallLocation": ("C:\\msys64", 1),
            },
            "subkeys": [],
        },
    }
    mview = DictHiveView(uninstall_tree)
    recs = scan_uninstall_keys(mview, UNINSTALL_REL, "HKLM Uninstall")
    check(len(recs) == 2, f"uninstall records {len(recs)} (entry without DisplayName must be skipped)")
    git = next(r for r in recs if r.display_name == "Git")
    check(git.install_date == "2024-03-11", f"InstallDate normalised: {git.install_date}")
    check(git.install_location.endswith("Git\\"), "InstallLocation captured")
    check(git.publisher.startswith("The Git"), "Publisher captured")
    msi = scan_msi_userdata(mview)
    check(len(msi) == 1 and msi[0].display_name.startswith("MSYS2"), f"MSI record {msi}")
    check(msi[0].install_date == "2025-01-02", "MSI InstallDate normalised")

    # A record whose DisplayName does not match but whose Publisher does.
    pub_only = [InstallRecord(display_name="Portable Toolchain", publisher="Cygwin Project",
                              source="HKLM Uninstall")]
    check(match_installation(pub_only, r"\bcygwin\b") is not None,
          "publisher is matched as well as display name")

    # collect_installations must aggregate all three registry sources: a 32-bit
    # install under WOW6432Node and an MSI remnant are both real evidence.
    wow_tree = {
        UNINSTALL_REL_WOW: {"last_write": lw, "values": {}, "subkeys": ["ConEmu"]},
        UNINSTALL_REL_WOW + "\\ConEmu": {
            "last_write": lw,
            "values": {"DisplayName": ("ConEmu 240115", 1), "InstallDate": ("20240115", 1)},
            "subkeys": [],
        },
    }
    merged_view = DictHiveView({**uninstall_tree, **wow_tree})
    empty_ctx = UserContext(user="a", sid="S-1", profile_path="", appdata="",
                            localappdata="", hive_view=DictHiveView({}))
    every = collect_installations(empty_ctx, merged_view)
    sources_seen = {r.source for r in every}
    check("HKLM Uninstall (WOW6432)" in sources_seen,
          f"32-bit WOW6432Node installs are scanned: {sources_seen}")
    check("MSI InstallProperties" in sources_seen,
          f"MSI InstallProperties remnants are scanned: {sources_seen}")
    check(any(r.display_name.startswith("ConEmu") for r in every), "WOW6432Node record surfaced")
    check(any(r.display_name.startswith("MSYS2") for r in every), "MSI record surfaced")

    # Per-user installs live in the user's own hive, not HKLM.
    hkcu_ctx = UserContext(
        user="a", sid="S-1", profile_path="", appdata="", localappdata="",
        hive_view=DictHiveView({
            UNINSTALL_REL: {"last_write": lw, "values": {}, "subkeys": ["Nushell"]},
            UNINSTALL_REL + "\\Nushell": {
                "last_write": lw,
                "values": {"DisplayName": ("nushell", 1), "InstallDate": ("20260301", 1)},
                "subkeys": [],
            },
        }),
    )
    per_user = collect_installations(hkcu_ctx, None)
    check(any(r.source == "HKCU Uninstall" for r in per_user),
          f"per-user HKCU installs are scanned: {[r.source for r in per_user]}")
    check(any(r.display_name == "nushell" for r in per_user), "HKCU record surfaced")

    # ---- package managers: scoop / winget / chocolatey / cargo ----------
    # Built with pathlib joins so the discovery logic is exercised off-Windows;
    # an earlier build embedded "\\" separators and silently found nothing here.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        prof, local = root / "profile", root / "local"
        (prof / "scoop" / "apps" / "nu" / "0.99.1").mkdir(parents=True)
        (prof / "scoop" / "apps" / "nu" / "current").mkdir()
        (prof / "scoop" / "apps" / "elvish" / "0.21.0").mkdir(parents=True)
        (local / "Microsoft" / "WinGet" / "Packages"
         / "xonsh.xonsh_Microsoft.Winget.Source_8wekyb3d8bbwe").mkdir(parents=True)
        (prof / ".cargo" / "bin").mkdir(parents=True)
        (prof / ".cargo" / "bin" / "atuin.exe").write_text("x")
        (prof / ".cargo" / "bin" / "ripgrep.exe").write_text("x")
        pctx = UserContext(user="a", sid="S-1", profile_path=str(prof),
                           appdata=str(local), localappdata=str(local),
                           hive_view=DictHiveView({}))
        pkgs = scan_package_managers(pctx)
        names = {r.display_name.lower() for r in pkgs}
        check({"nu", "elvish", "atuin"} <= names, f"scoop and cargo installs found: {names}")
        check(any(r.display_name == "xonsh.xonsh" for r in pkgs),
              f"winget portable package found: {names}")
        check(_winget_package_id("Nushell.Nushell_Microsoft.Winget.Source_8wekyb3d8bbwe")
              == "Nushell.Nushell", "winget directory name reduced to its package id")
        nu_rec = next(r for r in pkgs if r.display_name == "nu")
        check(nu_rec.version == "0.99.1", f"scoop version read, 'current' ignored: {nu_rec.version}")
        check(nu_rec.install_date and nu_rec.install_date[:2] == "20",
              f"package install date from directory ctime: {nu_rec.install_date}")
        check(all(r.source in PACKAGE_SOURCES for r in pkgs), "package records carry a package source")

        # the aggregate must include them, not just the standalone scanner
        aggregated = collect_installations(pctx, None)
        agg_sources = {r.source for r in aggregated}
        check(bool(agg_sources & set(PACKAGE_SOURCES)),
              f"collect_installations must include package managers: {agg_sources}")
        check(any(r.display_name == "nu" for r in aggregated), "scoop record reaches the aggregate")

    # pip/conda: xonsh is normally a Python package, so a Scripts-dir entry
    # point is a realistic - often the only - install record. Isolated tree so
    # the scoop/winget records above cannot satisfy these assertions.
    with tempfile.TemporaryDirectory() as pip_tmp:
        pip_root = Path(pip_tmp)
        pip_prof, pip_local = pip_root / "prof", pip_root / "local"
        pip_scripts = pip_local / "Programs" / "Python" / "Python312" / "Scripts"
        pip_scripts.mkdir(parents=True)
        (pip_scripts / "xonsh.exe").write_text("x")
        (pip_scripts / "pip.exe").write_text("x")
        conda_scripts = pip_prof / "miniconda3" / "Scripts"
        conda_scripts.mkdir(parents=True)
        (conda_scripts / "elvish.exe").write_text("x")
        pip_ctx = UserContext(user="a", sid="S-1", profile_path=str(pip_prof),
                              appdata=str(pip_local), localappdata=str(pip_local),
                              hive_view=DictHiveView({}))
        pip_recs = scan_package_managers(pip_ctx)
        got = {(r.display_name, r.source) for r in pip_recs}
        check(("xonsh", "pip/conda") in got, f"pip-installed xonsh detected: {got}")
        check(("elvish", "pip/conda") in got, f"conda Scripts directory scanned: {got}")
        pip_rows = {p.type_name: p for p in build_presence([], DEFAULT_SOURCES, pip_recs)}
        check(pip_rows["Xonsh"].installed != "", "Xonsh resolves from a pip install alone")
        check("pip/conda" in pip_rows["Xonsh"].install_detail,
              f"pip source attributed: {pip_rows['Xonsh'].install_detail}")
        check(pip_rows["Elvish"].installed != "", "Elvish resolves from a conda install alone")
        # pip.exe itself must not be mistaken for a shell
        check(match_installation(pip_recs, r"\bnushell\b", ("nu", "nushell")) is None,
              "unrelated Scripts entry points do not match a shell")

        # the four shells this capability exists for must now resolve
        prows = {p.type_name: p for p in build_presence([], DEFAULT_SOURCES, pkgs)}
        for shell in ("Nushell", "Elvish", "Xonsh", "Atuin (history database)"):
            check(prows[shell].installed != "",
                  f"{shell} not detected via package manager: {prows[shell].installed!r}")
        check(prows["Bash (Cygwin)"].installed == "", "unrelated shell stays blank")
        check(prows["Ion"].installed == "", "cargo binaries do not match every shell")

        # exact-name matching: a short package name must not regex unrelated software
        check(
            match_installation(
                [InstallRecord(display_name="Nuance PDF Reader", source="HKLM Uninstall")],
                r"\bnushell\b|\bnu\s+shell\b", ("nu", "nushell"),
            )
            is None,
            "short package name must not match unrelated ARP software",
        )
        # ... and a package record must not be regex-matched either
        check(
            match_installation(
                [InstallRecord(display_name="nuget", source="scoop")],
                r"\bnushell\b", ("nu", "nushell"),
            )
            is None,
            "package names match exactly, not by substring",
        )
        # winget ids resolve on their last dotted component
        check(
            match_installation(
                [InstallRecord(display_name="Nushell.Nushell", source="winget (portable)")],
                r"\bnushell\b", ("nu", "nushell"),
            )
            is not None,
            "winget package id matches on its last dotted component",
        )
        # env overrides are honoured
        os.environ["CARGO_HOME"] = str(root / "altcargo")
        (root / "altcargo" / "bin").mkdir(parents=True)
        (root / "altcargo" / "bin" / "elvish.exe").write_text("x")
        try:
            labels = {(lbl, str(p)) for lbl, p, _k in package_manager_roots(pctx)}
            check(any(lbl == "cargo" and "altcargo" in path for lbl, path in labels),
                  "CARGO_HOME override honoured")
        finally:
            del os.environ["CARGO_HOME"]

    all_recs = recs + msi

    # A generic pattern must not sweep up unrelated software.
    check(
        match_installation(
            [InstallRecord(display_name="Nuance PDF Reader", source="HKLM Uninstall")],
            r"\bnushell\b",
        )
        is None,
        "unrelated ARP entry must not match a shell pattern",
    )
    check(match_installation(all_recs, r"\bcygwin\b") is None, "absent software yields no record")
    gm = match_installation(all_recs, r"^git(\s|$)|git\s+for\s+windows")
    check(gm is not None and gm.install_date == "2024-03-11", "git matched with its date")
    check(match_installation(all_recs, "") is None, "empty pattern never matches")

    # end-to-end: the column reflects registration, not history
    blk = SourceBlock(name="Bash-Git")
    blk.rows = [_row("Bash-Git", 1)]
    rows = {p.type_name: p for p in build_presence([blk], DEFAULT_SOURCES, all_recs)}
    check(rows["Bash (Git for Windows)"].installed == "2024-03-11",
          f"Installed column: {rows['Bash (Git for Windows)'].installed}")
    check(rows["Bash (Cygwin)"].installed == "", "no record -> empty Installed cell")
    check(rows["CMD (native cmd.exe)"].installed == "built-in", "OS components marked built-in")
    # THE case this feature exists for: registered but no history recovered
    check(rows["Bash (MSYS2)"].presence == PRESENCE_ABSENT
          and rows["Bash (MSYS2)"].installed == "2025-01-02",
          "installed with no history is visible in the table")
    check("MSYS2" in rows["Bash (MSYS2)"].install_detail, "install detail retained for report")
    # a record with no InstallDate still proves installation
    dateless = [InstallRecord(display_name="ConEmu", source="HKLM Uninstall")]
    drow = {p.type_name: p for p in build_presence([], DEFAULT_SOURCES, dateless)}
    check(drow["ConEmu"].installed == "yes", f"dateless record -> yes: {drow['ConEmu'].installed}")
    # no install data at all (non-Windows / offline hive) must not claim absence
    nrow = {p.type_name: p for p in build_presence([], DEFAULT_SOURCES, [])}
    check(nrow["ConEmu"].installed == "", "no registry access -> blank, not a negative claim")

    # PIDL fallback should recover a name from a synthetic shell item
    name = "secret.docx".encode("utf-16-le") + b"\x00\x00"
    payload = b"xxxx" + name
    blob = struct.pack("<H", 2 + len(payload)) + payload + b"\x00\x00"
    path = fallback_pidl_path(blob)
    check("secret.docx" in path, f"fallback pidl {path!r}")

    red = redact_text("net use z: \\\\s\\c /user:admin hunter2")
    check("***REDACTED***" in red, f"redact net use {red}")

    if failures:
        print("SELFTEST FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("SELFTEST OK")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="Intention.py",
        description=(
            "Read-only collector of interactive command-line history on Windows "
            "(CMD/Clink, PSReadLine, bash/zsh/fish on WSL and POSIX-on-Windows ports)."
        ),
        epilog=(
            "The terminal shows an inventory of which shells are present. The full "
            "command history is always written to a .txt report in the current "
            "directory (or --outdir), whose path is printed at the end of the run."
        ),
    )
    p.add_argument("--all-users", action="store_true", help="Examine each profile under C:\\Users")
    p.add_argument("--hive", metavar="PATH", help="Parse a single NTUSER.DAT")
    p.add_argument("--profile", metavar="PATH", help="Treat PATH as a user profile root")
    p.add_argument(
        "--sources",
        help=(
            "Comma list: cmd,powershell,bash,wsl,esoteric,config[,legacy-explorer][,repls] "
            "(default: cmd,powershell,bash,wsl,esoteric,config)"
        ),
    )
    p.add_argument("--outdir", help="Directory for JSON/CSV/TXT/HTML exports")
    p.add_argument("--json", action="store_true", help="Write JSON export")
    p.add_argument("--csv", action="store_true", help="Write CSV export")
    p.add_argument(
        "--txt",
        action="store_true",
        help="Deprecated: the .txt report is always written (flag kept for compatibility)",
    )
    p.add_argument(
        "--tables",
        action="store_true",
        help="Also print the full per-source tables to the terminal (v1 behaviour)",
    )
    p.add_argument("--html", action="store_true", help="Write HTML report")
    p.add_argument(
        "--legacy-explorer",
        action="store_true",
        help="Also collect v1 Explorer MRU tables (RunMRU/TypedPaths/ComDlg32/WordWheelQuery). Not CLI history.",
    )
    p.add_argument(
        "--include-repls",
        action="store_true",
        help="Also collect language REPL histories (.python_history, node, IPython). Not shells.",
    )
    p.add_argument(
        "--wsl-online",
        action="store_true",
        help="Probe \\\\wsl$\\<distro> even when the share is not already listed",
    )
    p.add_argument(
        "--wsl-offline",
        action="store_true",
        help="Attempt read-only history extraction from ext4.vhdx if 7z/libguestfs is installed",
    )
    p.add_argument(
        "--wsl-exec",
        action="store_true",
        help="Read WSL history via `wsl.exe -d <distro> -e cat`. WARNING: this STARTS a stopped distro.",
    )
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--localtime", action="store_true", help="Add local-time column")
    p.add_argument("--max-rows", type=int, default=None)
    p.add_argument("--include-system-profiles", action="store_true")
    p.add_argument("--redact-secrets", action="store_true")
    p.add_argument("--chronological", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--selftest", action="store_true", help="Run parser unit checks and exit")
    p.add_argument(
        "--diagnose",
        action="store_true",
        help="Probe the Windows-only code paths and report what they did, then exit. "
             "Collects no history and prints no command text.",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    harden_console_encoding()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        sources = parse_sources(args.sources)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
        return 2

    # Flags and --sources are additive for the opt-in families.
    if args.legacy_explorer:
        sources.add("legacy-explorer")
    if args.include_repls:
        sources.add("repls")
    opts = RunOptions(
        include_repls=args.include_repls,
        wsl_online=args.wsl_online,
        wsl_offline=args.wsl_offline,
        wsl_exec=args.wsl_exec,
        legacy_explorer="legacy-explorer" in sources,
    )
    if args.wsl_exec:
        print(
            "WARNING: --wsl-exec will start any stopped distro it reads from, "
            "changing guest VM state. Ctrl-C now if that is not acceptable.",
            file=sys.stderr,
        )

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )

    if args.selftest:
        return run_selftest()

    if args.diagnose:
        return run_diagnostics(no_color=args.no_color)

    collected_dt = utc_now()
    collected = iso_utc(collected_dt)
    errors: list[CollectionError] = []
    contexts: list[UserContext] = []

    try:
        if args.hive and args.profile:
            view = None
            try:
                view = open_offline_hive(args.hive)
            except OSError as exc:
                errors.append(CollectionError(scope=args.hive, message=str(exc)))
            contexts.append(
                build_user_context_from_profile(
                    args.profile, hive_view=view, errors=errors
                )
            )
        elif args.hive:
            view = None
            try:
                view = open_offline_hive(args.hive)
            except OSError as exc:
                errors.append(CollectionError(scope=args.hive, message=str(exc)))
            contexts.append(
                UserContext(
                    user=Path(args.hive).parent.name,
                    sid="",
                    profile_path=str(Path(args.hive).parent),
                    appdata=str(Path(args.hive).parent / "AppData" / "Roaming"),
                    localappdata=str(Path(args.hive).parent / "AppData" / "Local"),
                    hive_view=view,
                )
            )
        elif args.profile:
            contexts.append(build_user_context_from_profile(args.profile, errors=errors))
        elif args.all_users:
            contexts.extend(iter_all_users(args.include_system_profiles, errors))
            if not contexts:
                # still try current user so the run is not empty on non-Windows
                contexts.append(live_current_user_context(errors))
        else:
            contexts.append(live_current_user_context(errors))

        all_blocks: list[SourceBlock] = []
        for i, ctx in enumerate(contexts):
            live_doskey = (not args.all_users) and i == 0
            try:
                all_blocks.extend(
                    collect_for_context(
                        ctx, sources, collected, args.redact_secrets, live_doskey, opts
                    )
                )
            except Exception as exc:
                errors.append(CollectionError(scope=ctx.user or ctx.profile_path, message=str(exc)))
                LOG.debug("context failed", exc_info=True)
            finally:
                # AllUsers $PROFILE is host-wide; read it on the first context
                # only, so --all-users does not rescan it per profile.
                opts.config_machine_scope = False
                if ctx.hive_view is not None:
                    try:
                        ctx.hive_view.close()
                    except Exception:
                        pass

        blocks = merge_blocks(all_blocks)
        blocks = ensure_required_blocks(blocks, sources)
        # A planted link is itself a finding, so promote every containment
        # rejection from per-file metadata into the errors table where an
        # examiner will actually see it.
        for _blk in blocks:
            for _meta in collect_rejections(_blk.header_meta):
                errors.append(
                    CollectionError(scope=_blk.name, message=str(_meta))
                )
        blocks = order_blocks(blocks)
        if args.localtime:
            apply_localtime(blocks)
        sort_blocks(blocks, args.chronological)

        if errors:
            err_block = SourceBlock(name="CollectionErrors")
            for e in errors:
                err_block.rows.append(
                    IntentRow(
                        source="CollectionErrors",
                        user="",
                        sid="",
                        profile_path=e.scope,
                        value_name="",
                        typed_value=e.message,
                        raw_value=e.message,
                        mru_pos=None,
                        utc_timestamp=collected,
                        timestamp_provenance=PROV_COLLECTION,
                        collected_utc=collected,
                        key_lastwrite_utc="",
                        extra="error",
                    )
                )
            blocks.append(err_block)

        meta = {
            "tool": "Intention.py",
            "version": VERSION,
            "scope": "cli_history",
            "hostname": socket.gethostname(),
            "collected_utc": collected,
            "current_user": current_username(),
            "os": windows_os_build(),
            "elevated": is_admin(),
            "sources": sorted(sources),
            "sources_checked": [b.name for b in blocks if b.name != "CollectionErrors"],
            "provenance_vocabulary": PROVENANCE_VOCABULARY,
            "legacy_explorer": opts.legacy_explorer,
            "include_repls": opts.include_repls,
            "wsl_online": opts.wsl_online,
            "wsl_offline": opts.wsl_offline,
            "wsl_exec": opts.wsl_exec,
            "read_only": True,
            "platform": platform.platform(),
            "python": sys.version.split()[0],
        }

        machine_view: Optional[HiveView] = None
        if winreg is not None:
            try:
                machine_view = LiveHiveView(winreg.HKEY_LOCAL_MACHINE)
            except Exception as exc:  # HKLM unreadable is not fatal
                errors.append(CollectionError(scope="installations", message=str(exc)))
        installs: list[InstallRecord] = []
        machine_scope = True
        for ctx in contexts:
            try:
                installs.extend(
                    collect_installations(ctx, machine_view, include_machine_scope=machine_scope)
                )
            except Exception as exc:
                errors.append(CollectionError(scope="installations", message=str(exc)))
            # HKLM and the machine-scope package roots are machine-wide:
            # read them once, not once per profile.
            machine_view = None
            machine_scope = False
        meta["installations_found"] = len(installs)
        presence = build_presence(blocks, sources, installs)

        # The .txt report is the deliverable and is always written: to --outdir
        # when given, otherwise the directory the tool was run from.
        outdir = Path(args.outdir) if args.outdir else Path.cwd()
        stamp = collected_dt.strftime("%Y%m%dT%H%M%SZ")
        host = re.sub(r"[^A-Za-z0-9._-]", "_", meta["hostname"])
        base = outdir / f"intention_{host}_{stamp}"
        report_path: Optional[Path] = None
        try:
            outdir.mkdir(parents=True, exist_ok=True)
            txt_path = free_output_path(base, ".txt")
            export_txt(
                txt_path,
                meta,
                blocks,
                errors,
                args.redact_secrets,
                args.localtime,
                presence=presence,
            )
            report_path = txt_path
        except OSError as exc:
            print(f"ERROR writing report: {exc}", file=sys.stderr)

        # Old v1 behaviour: full per-source tables in the terminal, on request.
        # Rendered before the summary so the report path stays the last line.
        if args.tables:
            print_rich_tables(
                blocks,
                meta,
                args.redact_secrets,
                args.localtime,
                args.max_rows,
                args.no_color,
            )

        # Optional machine-readable exports alongside the report.
        write_json = args.json or bool(args.outdir)
        write_csv = args.csv or bool(args.outdir)
        write_html = args.html
        if write_json or write_csv or write_html:
            try:
                outdir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                print(f"ERROR creating outdir: {exc}", file=sys.stderr)
                return 1
            if write_json:
                json_path = free_output_path(base, ".json")
                export_json(json_path, meta, blocks, errors)
                print(f"Wrote {json_path}", file=sys.stderr)
            if write_csv:
                csv_path = free_output_path(base, ".csv")
                export_csv(csv_path, blocks)
                print(f"Wrote {csv_path}", file=sys.stderr)
            if write_html:
                html_path = free_output_path(base, ".html")
                export_html(html_path, meta, blocks, args.redact_secrets)
                print(f"Wrote {html_path}", file=sys.stderr)

        render_summary_rich(
            blocks,
            meta,
            presence,
            errors,
            report_path,
            args.redact_secrets,
            args.no_color,
        )
        return 0
    except BrokenPipeError:
        return 0
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
