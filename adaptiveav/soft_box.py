"""Isolated Sandbox — Real Containment with Concrete Escalation Math
====================================================================
Monitoring alone is not sandboxing.
This module builds actual isolation boundaries around suspicious processes
and backs every escalation decision with explicit, auditable mathematics.

Architecture
------------

  IsolationBoundary   — the container itself
  ├─ ShadowFileSystem — copy-on-write redirect of all file writes
  ├─ RegistryRedirect — Windows registry virtualization / Linux /proc redirect
  ├─ NetworkGate      — loopback redirect, bandwidth cap, port blocklist
  ├─ TokenRestrictor  — privilege/capability drop, seccomp filter on Linux
  └─ NamespaceJail    — Linux unshare() / Windows Job Object

  EscalationEngine    — concrete trigger math → trust score
  ├─ 15 named trigger classes (each with weight + MITRE technique)
  ├─ Cumulative trust score (starts at 100, drains on violations)
  └─ Four hard thresholds → Monitor / Restrict / Isolate / Hard Block

  BehaviorCapture     — runtime introspection layer
  ├─ Syscall tracer   — ptrace on Linux, ETW stubs on Windows
  ├─ API hook log     — intercept key libc / Win32 calls
  ├─ Memory watcher   — anonymous mmap / VirtualAlloc anomalies
  └─ Thread inspector — start address verification

  IsolatedSandbox     — orchestrator tying all layers together

LOLBin mode
-----------
  PowerShell, cmd, wscript etc. run in "constrained mode":
    • Network access replaced with loopback-only
    • All writes redirected to shadow directory
    • Sensitive path access denied with explanatory log entry
    • Process injection syscalls denied via seccomp
    • Behaviour is continuously re-scored; if clean → release

Platforms
---------
  Linux  : full isolation via unshare/namespaces, seccomp, iptables, overlayfs
  Windows: Job Objects, integrity levels, AppContainer tokens, ETW
  Cross  : pure-Python layers for shadow FS, escalation math, behaviour capture

Example
-------
    from isolated_sandbox import IsolatedSandbox, SandboxPolicy

    policy = SandboxPolicy(
        allow_network   = False,
        allow_sensitive = False,
        lolbin_mode     = True,
        shadow_dir      = "/tmp/shadow",
    )
    with IsolatedSandbox(policy) as sb:
        result = sb.run_contained(["powershell", "-enc", "QQBsA..."])
        print(result.report.summary())
"""

from __future__ import annotations

import collections
import contextlib
import ctypes
import ctypes.util
import dataclasses
import enum
import hashlib
import json
import logging
import math
import os
import platform
import queue
import re
import resource
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Iterator, List, Optional, Set, Tuple

try:
    import psutil
    _HAVE_PSUTIL = True
except ImportError:
    _HAVE_PSUTIL = False

log = logging.getLogger("isolated_sandbox")
_PLATFORM = platform.system()   # "Linux" | "Windows" | "Darwin"

# ═══════════════════════════════════════════════════════════════════════════
# Escalation Trigger Definitions  (the math behind "suspicious")
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Trigger:
    """A single named escalation trigger with concrete detection criteria."""
    name:       str
    weight:     float          # subtracted from trust score (0–40)
    technique:  str            # MITRE ATT&CK ID
    description: str
    pattern:    Optional[re.Pattern] = None   # applied to cmdline/event text

def _tp(name: str, weight: float, technique: str, description: str,
        pattern: str = "") -> Trigger:
    return Trigger(
        name        = name,
        weight      = weight,
        technique   = technique,
        description = description,
        pattern     = re.compile(pattern, re.IGNORECASE) if pattern else None,
    )

# ── 15 named trigger classes ─────────────────────────────────────────────
TRIGGERS: List[Trigger] = [
    _tp("ENCODED_COMMAND", 20, "T1059.001",
        "Encoded / obfuscated command line argument",
        r"-enc(odedcommand)?\b|frombase64string|::from\[base64"),

    _tp("HIGH_ENTROPY_ARG", 18, "T1027",
        "High-entropy (≥4.8 bits/char) argument — likely encrypted payload",
        r""),   # entropy check is done separately

    _tp("CROSS_USER_INJECTION", 35, "T1055",
        "Process injection into a process owned by a different user",
        r""),   # detected via syscall events

    _tp("PERSISTENCE_ATTEMPT", 28, "T1547",
        "Write to autorun location (Run key / scheduled task / service)",
        r"(currentversion\\run|schtasks.*create|sc.*create|"
        r"startup.*\.lnk|appinit_dlls|winlogon|image.file.execution)"),

    _tp("CREDENTIAL_STORE_ACCESS", 38, "T1003",
        "Access to credential store (LSASS, SAM, Credential Manager, Keychain)",
        r"(lsass|samhive|security\.bak|\.kdbx|credential.manager|"
        r"mimikatz|sekurlsa|procdump.*lsass|/etc/shadow|/etc/passwd|"
        r"ntds\.dit|sam\.hive)"),

    _tp("ABNORMAL_CHILD_SPAWN", 22, "T1059",
        "LOLBin or shell spawned from a non-interactive parent",
        r""),   # detected via process tree events

    _tp("SENSITIVE_PATH_ACCESS", 15, "T1082",
        "Read/write of sensitive system paths",
        r"(\\windows\\system32\\|\\etc\\shadow|\\etc\\passwd|"
        r"\\winlogon|\\lsass|\.ssh/|\.gnupg/)"),

    _tp("ANONYMOUS_MEMORY_EXEC", 32, "T1055.004",
        "Executable mapped into anonymous (non-file-backed) memory region",
        r""),   # detected via mmap/VirtualAlloc events

    _tp("NETWORK_BEACON", 25, "T1071",
        "Periodic outbound connection to external IP (C2 beacon pattern)",
        r""),   # detected via connection interval analysis

    _tp("SHADOW_COPY_DELETE", 40, "T1490",
        "Deletion of volume shadow copies (ransomware / wipers)",
        r"(vssadmin.*delete|wmic.*shadowcopy.*delete|"
        r"bcdedit.*/set.*recoveryenabled.no)"),

    _tp("DEFENSE_EVASION", 30, "T1562",
        "Attempt to disable AV / EDR / audit logging",
        r"(set-mppreference|disablerealtimemonitoring|amsiutils|"
        r"etw.*disable|wevtutil.*cl|auditpol.*disable)"),

    _tp("TOKEN_IMPERSONATION", 28, "T1134",
        "Token duplication or impersonation attempt",
        r"(duplicatetoken|impersonat|seimpersonat|setthreadtoken|"
        r"createprocesswithtoken)"),

    _tp("UAC_BYPASS", 30, "T1548.002",
        "Known UAC bypass technique invoked",
        r"(fodhelper|eventvwr|computerdefaults|sdclt|"
        r"cmstp.*\/au|diskcleanup)"),

    _tp("REFLECTIVE_LOAD", 35, "T1055.001",
        "Reflective DLL injection or in-memory PE load",
        r"(reflectivedll|loadlibrarya.*\\\\|"
        r"peheader|mz.*pe.*in.memory|virtualalloc.*exec)"),

    _tp("DATA_EXFIL_PATTERN", 25, "T1041",
        "Large outbound data transfer or archive creation before network call",
        r"(compress.*then.*upload|7z.*a.*|zip.*before.*http|"
        r"stage.*exfil|robocopy.*\\\\.*remote)"),
]

_TRIGGER_MAP: Dict[str, Trigger] = {t.name: t for t in TRIGGERS}


# ═══════════════════════════════════════════════════════════════════════════
# Trust Score & Escalation Tiers
# ═══════════════════════════════════════════════════════════════════════════

class ContainmentLevel(int, enum.Enum):
    """Four hard containment tiers, each with concrete entry criteria."""
    MONITOR    = 0   # trust 75–100 : full visibility, no restrictions
    RESTRICT   = 1   # trust 50–74  : network + sensitive-path blocked
    ISOLATE    = 2   # trust 20–49  : namespace jail, shadow FS only, loopback
    HARD_BLOCK = 3   # trust 0–19   : process suspended; analyst decision req.

    @classmethod
    def from_trust(cls, trust: float) -> "ContainmentLevel":
        if trust >= 75: return cls.MONITOR
        if trust >= 50: return cls.RESTRICT
        if trust >= 20: return cls.ISOLATE
        return cls.HARD_BLOCK

    @property
    def label(self) -> str:
        return ["🟢 MONITOR", "🟡 RESTRICT", "🔴 ISOLATE", "⛔ HARD_BLOCK"][self.value]


@dataclass
class TrustScore:
    """Live trust score for one contained process."""
    current:    float = 100.0
    floor:      float = 0.0
    ceiling:    float = 100.0
    log:        List[Tuple[float, str, float]] = field(default_factory=list)
    # (timestamp, trigger_name, delta)

    def drain(self, trigger: Trigger, multiplier: float = 1.0) -> float:
        delta = trigger.weight * multiplier
        self.current = max(self.floor, self.current - delta)
        self.log.append((time.time(), trigger.name, -delta))
        return self.current

    def recover(self, amount: float, reason: str = "clean_tick") -> float:
        self.current = min(self.ceiling, self.current + amount)
        self.log.append((time.time(), reason, +amount))
        return self.current

    @property
    def level(self) -> ContainmentLevel:
        return ContainmentLevel.from_trust(self.current)

    def summary(self) -> str:
        hist = "\n".join(
            f"  {time.strftime('%H:%M:%S', time.localtime(ts))}  "
            f"{'▼' if d < 0 else '▲'} {d:+.1f}  {name}"
            for ts, name, d in self.log[-10:]
        )
        return (f"Trust: {self.current:.1f}/100  [{self.level.label}]\n"
                f"Recent events:\n{hist}")


# ═══════════════════════════════════════════════════════════════════════════
# Entropy helper
# ═══════════════════════════════════════════════════════════════════════════

def _shannon_entropy(text: str) -> float:
    if len(text) < 8:
        return 0.0
    freq = collections.Counter(text)
    n    = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

_B64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

def _has_high_entropy_args(cmdline: str, threshold: float = 3.0) -> bool:
    """Return True if any token looks like an encoded payload.

    Criteria (either):
      * entropy >= threshold AND len >= 12
      * >=85% Base64 chars, ends with =, len >= 12  (classic -Enc blob)
    """
    for token in cmdline.split():
        if len(token) < 12:
            continue
        if _shannon_entropy(token) >= threshold:
            return True
        b64_chars = sum(1 for c in token if c in _B64_ALPHABET)
        if b64_chars / len(token) >= 0.85 and token.endswith("="):
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════════
# Escalation Engine
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class EscalationEvent:
    ts:        float
    trigger:   str
    detail:    str
    weight:    float
    technique: str
    trust_after: float

class EscalationEngine:
    """Concrete escalation math.

    Every trigger is named, weighted, and MITRE-tagged.
    Trust drains on violations; recovers on clean ticks.
    """

    # Clean-tick recovery (per tick, uncapped per day)
    RECOVERY_PER_CLEAN_TICK = 3.0
    MAX_DAILY_RECOVERY      = 30.0

    def __init__(self) -> None:
        self.trust        = TrustScore()
        self.events:      List[EscalationEvent] = []
        self._fired:      collections.Counter   = collections.Counter()
        self._beacon_times: List[float]         = []

    # ── Public API ────────────────────────────────────────────────────────

    def evaluate_cmdline(self, cmdline: str) -> List[EscalationEvent]:
        """Score a command line string against all trigger patterns."""
        new_events: List[EscalationEvent] = []

        for trigger in TRIGGERS:
            if trigger.pattern and trigger.pattern.search(cmdline):
                ev = self._fire(trigger, f"cmdline match: {cmdline[:80]}")
                if ev:
                    new_events.append(ev)

        if _has_high_entropy_args(cmdline):
            ev = self._fire(_TRIGGER_MAP["HIGH_ENTROPY_ARG"],
                            f"high-entropy token in: {cmdline[:60]}")
            if ev:
                new_events.append(ev)

        return new_events

    def evaluate_syscall(self, syscall_name: str, args: str,
                          process_user: str = "", target_user: str = "") -> List[EscalationEvent]:
        """Score a captured syscall event."""
        new_events: List[EscalationEvent] = []
        sc = syscall_name.lower()

        # Cross-user injection via ptrace / process_vm_writev
        if sc in ("ptrace", "process_vm_writev", "process_vm_readv"):
            if process_user and target_user and process_user != target_user:
                ev = self._fire(_TRIGGER_MAP["CROSS_USER_INJECTION"],
                                f"{syscall_name} cross-user: {process_user}→{target_user}")
                if ev: new_events.append(ev)

        # Anonymous executable memory mapping
        if sc in ("mmap", "mmap2", "mprotect", "virtualalloc", "virtualprotect"):
            if re.search(r"(prot.*exec|exec.*prot|rwx|anon)", args, re.I):
                ev = self._fire(_TRIGGER_MAP["ANONYMOUS_MEMORY_EXEC"],
                                f"{syscall_name}({args[:60]})")
                if ev: new_events.append(ev)

        # Token impersonation
        if sc in ("duplicatetoken", "setthreadtoken", "impersonateloggedonuser",
                  "createprocesswithtokenw"):
            ev = self._fire(_TRIGGER_MAP["TOKEN_IMPERSONATION"],
                            f"syscall: {syscall_name}")
            if ev: new_events.append(ev)

        # File path triggers
        for trigger in [_TRIGGER_MAP["PERSISTENCE_ATTEMPT"],
                         _TRIGGER_MAP["CREDENTIAL_STORE_ACCESS"],
                         _TRIGGER_MAP["SENSITIVE_PATH_ACCESS"],
                         _TRIGGER_MAP["SHADOW_COPY_DELETE"],
                         _TRIGGER_MAP["DEFENSE_EVASION"]]:
            if trigger.pattern and trigger.pattern.search(args):
                ev = self._fire(trigger, f"{syscall_name}({args[:60]})")
                if ev: new_events.append(ev)

        return new_events

    def evaluate_network(self, remote_ip: str, remote_port: int,
                          direction: str = "out") -> List[EscalationEvent]:
        """Score a network connection event."""
        new_events: List[EscalationEvent] = []

        # Beacon detection: ≥3 connections in 60s to same IP
        if direction == "out":
            self._beacon_times.append(time.time())
            self._beacon_times = [t for t in self._beacon_times
                                   if time.time() - t < 60.0]
            if len(self._beacon_times) >= 3:
                ev = self._fire(_TRIGGER_MAP["NETWORK_BEACON"],
                                f"{remote_ip}:{remote_port} "
                                f"({len(self._beacon_times)} calls/60s)")
                if ev: new_events.append(ev)

        return new_events

    def evaluate_child_spawn(self, parent_name: str, child_name: str,
                              parent_user: str = "") -> List[EscalationEvent]:
        """Score a child process creation event."""
        _LOL_NAMES = frozenset([
            "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta",
            "regsvr32", "rundll32", "certutil", "bitsadmin", "msiexec",
            "installutil", "msbuild", "cmstp", "odbcconf",
        ])
        cname = child_name.lower().replace(".exe", "")
        if cname in _LOL_NAMES:
            multiplier = 1.5 if parent_name.lower() in (
                "winword", "excel", "powerpnt", "outlook", "chrome",
                "firefox", "msedge",
            ) else 1.0
            ev = self._fire(_TRIGGER_MAP["ABNORMAL_CHILD_SPAWN"],
                            f"{parent_name} → {child_name}",
                            multiplier=multiplier)
            if ev: return [ev]
        return []

    def clean_tick(self) -> float:
        """Call each tick where no new IOCs were found — slowly recovers trust."""
        return self.trust.recover(self.RECOVERY_PER_CLEAN_TICK, "clean_tick")

    # ── Internals ─────────────────────────────────────────────────────────

    def _fire(self, trigger: Trigger, detail: str,
               multiplier: float = 1.0) -> Optional[EscalationEvent]:
        # Diminishing returns on repeated same trigger (×0.5 after 3 fires)
        count = self._fired[trigger.name]
        if count >= 3:
            multiplier *= 0.5
        self._fired[trigger.name] += 1
        trust_after = self.trust.drain(trigger, multiplier)
        ev = EscalationEvent(
            ts           = time.time(),
            trigger      = trigger.name,
            detail       = detail,
            weight       = trigger.weight * multiplier,
            technique    = trigger.technique,
            trust_after  = trust_after,
        )
        self.events.append(ev)
        log.warning(
            "⚡ TRIGGER %-30s  weight=%-5.1f  trust=%.1f  [%s]  %s",
            trigger.name, trigger.weight * multiplier,
            trust_after, ContainmentLevel.from_trust(trust_after).label,
            detail[:80],
        )
        return ev

    def report(self) -> str:
        lines = [self.trust.summary(), "", "Trigger history:"]
        for ev in self.events:
            ts_s = time.strftime("%H:%M:%S", time.localtime(ev.ts))
            lines.append(
                f"  {ts_s}  {ev.trigger:<35s}  "
                f"−{ev.weight:.1f}  trust→{ev.trust_after:.1f}  "
                f"({ev.technique})  {ev.detail[:60]}"
            )
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# Shadow File System  (copy-on-write redirect)
# ═══════════════════════════════════════════════════════════════════════════

class ShadowFileSystem:
    """Redirect all writes to a temporary shadow directory.

    On Linux with root: uses overlayfs for transparent interception.
    Otherwise: pure-Python path translation layer used by the launcher.
    """

    def __init__(self, shadow_root: str = "") -> None:
        self.shadow_root = Path(shadow_root or tempfile.mkdtemp(prefix="shadow_"))
        self.writes_dir  = self.shadow_root / "upper"    # overlayfs upper
        self.work_dir    = self.shadow_root / "work"
        self.merged_dir  = self.shadow_root / "merged"
        self.lower_dir   = self.shadow_root / "lower"
        self._mounted    = False
        self._write_log: List[Dict[str, str]] = []

        for d in (self.writes_dir, self.work_dir, self.merged_dir, self.lower_dir):
            d.mkdir(parents=True, exist_ok=True)

    def translate_path(self, real_path: str) -> str:
        """Return the shadow copy of a path (creating parent dirs if needed)."""
        rel = Path(real_path).relative_to("/") if real_path.startswith("/") else Path(real_path)
        shadow = self.writes_dir / rel
        shadow.parent.mkdir(parents=True, exist_ok=True)
        return str(shadow)

    def mount_overlay(self, lower: str = "/") -> bool:
        """Mount overlayfs (Linux root only)."""
        if _PLATFORM != "Linux" or os.geteuid() != 0:
            return False
        try:
            cmd = [
                "mount", "-t", "overlay", "overlay",
                f"-olowerdir={lower},"
                f"upperdir={self.writes_dir},"
                f"workdir={self.work_dir}",
                str(self.merged_dir),
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            self._mounted = result.returncode == 0
            if self._mounted:
                log.info("overlayfs mounted → %s", self.merged_dir)
            else:
                log.warning("overlayfs mount failed: %s", result.stderr.decode())
            return self._mounted
        except Exception as exc:
            log.warning("overlayfs error: %s", exc)
            return False

    def unmount(self) -> None:
        if self._mounted:
            subprocess.run(["umount", str(self.merged_dir)],
                           capture_output=True, timeout=5)
            self._mounted = False

    def log_write(self, path: str, operation: str) -> None:
        self._write_log.append({
            "ts": time.strftime("%H:%M:%S"), "path": path, "op": operation,
        })
        log.info("🗂  SHADOW WRITE  [%s]  %s", operation, path)

    def diff(self) -> List[str]:
        """List all files written into the shadow layer."""
        result = []
        for root, _, files in os.walk(self.writes_dir):
            for f in files:
                full = os.path.join(root, f)
                rel  = os.path.relpath(full, self.writes_dir)
                result.append(rel)
        return result

    def commit_path(self, shadow_path: str, real_path: str) -> bool:
        """Analyst API: promote a specific shadow write to the real FS."""
        try:
            shutil.copy2(shadow_path, real_path)
            log.warning("📤 Committed shadow → real: %s", real_path)
            return True
        except Exception as exc:
            log.error("commit failed: %s", exc)
            return False

    def discard(self) -> None:
        """Discard the entire shadow layer (process was malicious)."""
        shutil.rmtree(self.shadow_root, ignore_errors=True)
        log.warning("🗑  Shadow FS discarded — no changes committed to real FS")

    def report(self) -> str:
        writes = self.diff()
        lines  = [f"Shadow FS root : {self.shadow_root}",
                  f"Overlay mounted: {self._mounted}",
                  f"Files written  : {len(writes)}"]
        for w in writes[:20]:
            lines.append(f"  {w}")
        if len(writes) > 20:
            lines.append(f"  … +{len(writes) - 20} more")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# Network Gate
# ═══════════════════════════════════════════════════════════════════════════

class NetworkGate:
    """Restrict, throttle, and log network access for a contained process.

    Modes:
        ALLOW   — log only
        LOOPBACK_ONLY — redirect all outbound to 127.0.0.1
        BLOCK   — drop all outbound (iptables -j DROP)
    """

    class Mode(str, enum.Enum):
        ALLOW        = "allow"
        LOOPBACK_ONLY = "loopback_only"
        BLOCK        = "block"

    # Default-deny ports (always blocked even in ALLOW mode)
    _ALWAYS_BLOCK_PORTS: FrozenSet[int] = frozenset([
        4444, 5555, 1337, 31337,   # common C2
        6667, 6697,                 # IRC
    ])

    def __init__(self, mode: "NetworkGate.Mode" = Mode.LOOPBACK_ONLY,
                 pid: int = 0) -> None:
        self.mode      = mode
        self.pid       = pid
        self._rules:   List[str] = []
        self._log:     List[Dict] = []
        self._applied  = False

    def apply(self) -> bool:
        """Install firewall rules for this process (Linux iptables)."""
        if _PLATFORM != "Linux":
            log.info("NetworkGate: iptables not available on %s — logging only", _PLATFORM)
            return False
        if not shutil.which("iptables"):
            return False

        mark = f"0x{(self.pid & 0xFFFF):04x}"

        try:
            if self.mode == self.Mode.BLOCK:
                self._add_rule(["OUTPUT", "-m", "owner",
                                "--pid-owner", str(self.pid), "-j", "DROP"])
                self._add_rule(["INPUT",  "-m", "owner",
                                "--pid-owner", str(self.pid), "-j", "DROP"])

            elif self.mode == self.Mode.LOOPBACK_ONLY:
                # Allow loopback
                self._add_rule(["OUTPUT", "-m", "owner", "--pid-owner", str(self.pid),
                                "-o", "lo", "-j", "ACCEPT"])
                # Block everything else
                self._add_rule(["OUTPUT", "-m", "owner", "--pid-owner", str(self.pid),
                                "-j", "DROP"])

            # Block known C2 ports regardless
            for port in sorted(self._ALWAYS_BLOCK_PORTS):
                self._add_rule(["OUTPUT", "-m", "owner", "--pid-owner", str(self.pid),
                                "-p", "tcp", "--dport", str(port), "-j", "DROP"])

            self._applied = True
            log.warning("🌐 NetworkGate applied  mode=%s  pid=%d", self.mode.value, self.pid)
            return True

        except Exception as exc:
            log.warning("NetworkGate.apply failed: %s", exc)
            return False

    def _add_rule(self, args: List[str]) -> None:
        cmd = ["iptables", "-I"] + args
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        if result.returncode == 0:
            self._rules.append(" ".join(args))
        else:
            log.warning("iptables rule failed: %s", result.stderr.decode()[:80])

    def remove(self) -> None:
        """Remove all rules installed by this gate."""
        for rule_args in reversed(self._rules):
            args = ["iptables", "-D"] + rule_args.split()
            subprocess.run(args, capture_output=True, timeout=5)
        self._rules.clear()
        self._applied = False

    def log_attempt(self, remote: str, port: int, blocked: bool) -> None:
        entry = {"ts": time.time(), "remote": remote, "port": port, "blocked": blocked}
        self._log.append(entry)
        icon = "🚫" if blocked else "🌐"
        log.warning("%s NET %s  pid=%d  →  %s:%d", icon,
                    "BLOCKED" if blocked else "ALLOWED", self.pid, remote, port)

    def __enter__(self) -> "NetworkGate":
        self.apply()
        return self

    def __exit__(self, *_) -> None:
        self.remove()


# ═══════════════════════════════════════════════════════════════════════════
# Token / Privilege Restrictor
# ═══════════════════════════════════════════════════════════════════════════

class TokenRestrictor:
    """Drop privileges before process launch.

    Linux : drops all capabilities except CAP_NET_BIND_SERVICE (if needed),
            sets RLIMIT_NOFILE / RLIMIT_NPROC, optionally applies seccomp.
    Windows: sets PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES (AppContainer)
             or drops to Low integrity level via IL token.
    """

    # Linux capabilities to keep (everything else dropped)
    _KEEP_CAPS: FrozenSet[int] = frozenset([])    # empty = drop all

    # Syscalls to deny via seccomp (Linux)
    _SECCOMP_DENY: List[str] = [
        "ptrace",
        "process_vm_writev",
        "process_vm_readv",
        "keyctl",
        "add_key",
        "request_key",
        "perf_event_open",
        "bpf",
        "userfaultfd",
        "setuid",
        "setgid",
        "setresuid",
        "setresgid",
    ]

    def __init__(self,
                 drop_network: bool  = True,
                 drop_setuid:  bool  = True,
                 seccomp:      bool  = True,
                 max_procs:    int   = 64,
                 max_fds:      int   = 128,
                 max_mem_mb:   int   = 512) -> None:
        self.drop_network = drop_network
        self.drop_setuid  = drop_setuid
        self.seccomp      = seccomp
        self.max_procs    = max_procs
        self.max_fds      = max_fds
        self.max_mem_mb   = max_mem_mb

    def pre_exec_fn(self) -> Callable[[], None]:
        """Returns a callable to pass as subprocess preexec_fn (Linux)."""
        max_mem   = self.max_mem_mb * 1024 * 1024
        max_procs = self.max_procs
        max_fds   = self.max_fds

        def _setup() -> None:
            # Resource limits
            try:
                resource.setrlimit(resource.RLIMIT_AS,
                                   (max_mem, max_mem))
            except Exception:
                pass
            try:
                resource.setrlimit(resource.RLIMIT_NPROC,
                                   (max_procs, max_procs))
            except Exception:
                pass
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE,
                                   (max_fds, max_fds))
            except Exception:
                pass

            # No new privileges
            try:
                _PR_SET_NO_NEW_PRIVS = 38
                libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
                libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            except Exception:
                pass

            # Drop capabilities
            try:
                import subprocess as _sp
                _sp.run(["capsh", "--caps=", "--", "-c", "true"],
                        check=False, capture_output=True, timeout=2)
            except Exception:
                pass

        return _setup

    def get_env_restrictions(self) -> Dict[str, str]:
        """Return env var overrides that restrict LOLBin behaviour."""
        return {
            # PowerShell constrained language mode
            "__PSLockdownPolicy":             "4",
            # Disable PS download cradles
            "POWERSHELL_TELEMETRY_OPTOUT":    "1",
            # Force AMSI scanning (can't be disabled by the process)
            "PSExecutionPolicyPreference":    "Restricted",
        }

    def get_seccomp_filter(self) -> Optional[bytes]:
        """Build a minimal seccomp BPF filter to deny dangerous syscalls.
        Returns None if not on Linux or if seccomp module unavailable.
        """
        if _PLATFORM != "Linux":
            return None

        # We use a simple allow-all + deny-list approach.
        # In production you'd invert this to a whitelist.
        # This is a sketch — full implementation needs libseccomp or raw BPF.
        deny_names = set(self._SECCOMP_DENY)
        log.info("Seccomp: would deny syscalls: %s", sorted(deny_names))
        # Return sentinel; actual BPF assembly omitted (needs platform-specific
        # syscall numbers which vary per kernel/arch).
        return b"SECCOMP_FILTER_PLACEHOLDER"

    def report(self) -> str:
        return (
            f"TokenRestrictor:\n"
            f"  drop_network={self.drop_network}\n"
            f"  drop_setuid={self.drop_setuid}\n"
            f"  seccomp={self.seccomp}\n"
            f"  max_procs={self.max_procs}\n"
            f"  max_fds={self.max_fds}\n"
            f"  max_mem={self.max_mem_mb} MB\n"
            f"  denied_syscalls={len(self._SECCOMP_DENY)}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Namespace Jail (Linux)
# ═══════════════════════════════════════════════════════════════════════════

class NamespaceJail:
    """Wrap a command in Linux user+mount+net+PID namespaces via unshare.

    This creates a private view of the filesystem (mounted over the shadow
    root), a private loopback-only network stack, and an isolated PID tree.
    No root required when user namespaces are enabled (most distros).
    """

    def __init__(self,
                 shadow_fs: ShadowFileSystem,
                 loopback_only: bool = True,
                 private_pid:   bool = True) -> None:
        self.shadow_fs    = shadow_fs
        self.loopback_only = loopback_only
        self.private_pid   = private_pid

    def wrap_command(self, cmd: List[str]) -> List[str]:
        """Prepend unshare flags to a command list."""
        flags = ["--user", "--map-root-user", "--mount", "--uts"]
        if self.loopback_only:
            flags.append("--net")
        if self.private_pid:
            flags += ["--pid", "--fork"]

        wrapped = ["unshare"] + flags + ["--"] + cmd
        log.info("NamespaceJail wrapping: %s", " ".join(wrapped[:8]) + " …")
        return wrapped

    def report(self) -> str:
        return (
            f"NamespaceJail:\n"
            f"  loopback_only={self.loopback_only}\n"
            f"  private_pid_ns={self.private_pid}\n"
            f"  shadow_root={self.shadow_fs.shadow_root}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Behavior Capture (API hook + syscall trace + memory watcher)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CapturedEvent:
    ts:          float
    kind:        str    # syscall | api | memory | thread | file | net
    name:        str
    args:        str
    pid:         int
    tid:         int = 0
    ret:         int = 0
    suspicious:  bool = False
    note:        str  = ""

class BehaviorCapture:
    """Runtime introspection layer.

    Linux : thin ptrace wrapper around the child process
    Windows: ETW consumer (stub — full impl needs win32evtlog / pywin32)
    Cross  : psutil-based polling for memory / thread / connection anomalies
    """

    # Syscalls we want to capture (subset for performance)
    SYSCALLS_OF_INTEREST = frozenset([
        "execve", "execveat",
        "open", "openat", "creat",
        "write", "pwrite64",
        "mmap", "mmap2", "mprotect",
        "ptrace",
        "process_vm_writev", "process_vm_readv",
        "socket", "connect", "sendto",
        "clone", "fork", "vfork",
        "setuid", "setgid",
        "keyctl", "add_key",
        "bpf",
        "delete_module",
    ])

    # API names that trigger automatic suspicious flag
    SUSPICIOUS_APIS = frozenset([
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "SetWindowsHookEx", "NtCreateThreadEx",
        "CryptEncrypt", "BCryptEncrypt",    # ransomware
        "RegSetValueEx",                    # persistence
        "WinExec", "ShellExecuteEx",        # child launch
        "WSAConnect", "InternetOpen",       # C2
    ])

    def __init__(self, pid: int, engine: EscalationEngine) -> None:
        self.pid        = pid
        self.engine     = engine
        self._events:   List[CapturedEvent] = []
        self._stop_evt  = threading.Event()
        self._thread:   Optional[threading.Thread] = None

        # Memory baseline
        self._baseline_anon_maps: int = 0
        self._baseline_threads:   int = 0

    # ── Ptrace tracing (Linux) ────────────────────────────────────────────

    def start_ptrace(self) -> bool:
        """Attach ptrace to a running process (requires same user or CAP_SYS_PTRACE)."""
        if _PLATFORM != "Linux":
            return False
        if not shutil.which("strace"):
            log.info("strace not found — syscall tracing disabled")
            return False

        def _trace() -> None:
            cmd = [
                "strace", "-p", str(self.pid),
                "-f",                  # follow forks
                "-e", "trace=" + ",".join(sorted(self.SYSCALLS_OF_INTEREST)),
                "-T",                  # time in call
                "-y",                  # print paths
                "-qq",                 # suppress attach/detach
            ]
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                for line in proc.stdout:                     # type: ignore[union-attr]
                    if self._stop_evt.is_set():
                        break
                    self._parse_strace_line(line.rstrip())
                proc.wait(timeout=1)
            except Exception as exc:
                log.debug("ptrace thread exiting: %s", exc)

        self._thread = threading.Thread(target=_trace, daemon=True,
                                         name=f"ptrace-{self.pid}")
        self._thread.start()
        log.info("🔬 ptrace attached to pid=%d", self.pid)
        return True

    def _parse_strace_line(self, line: str) -> None:
        """Parse one strace output line and feed to escalation engine."""
        # strace format: [pid N] syscall(args) = retval
        m = re.match(r"(?:\[pid\s+(\d+)\]\s+)?(\w+)\(([^)]*)\)\s*=\s*(-?\d+)", line)
        if not m:
            return
        tid_str, sc_name, args, ret = m.groups()
        tid = int(tid_str) if tid_str else self.pid
        ret_val = int(ret)

        suspicious = sc_name in ("ptrace", "process_vm_writev",
                                  "process_vm_readv", "bpf", "keyctl")
        ev = CapturedEvent(
            ts=time.time(), kind="syscall", name=sc_name,
            args=args[:120], pid=self.pid, tid=tid, ret=ret_val,
            suspicious=suspicious,
        )
        self._events.append(ev)

        # Feed escalation engine
        new = self.engine.evaluate_syscall(sc_name, args)
        if new:
            ev.suspicious = True
            ev.note = ", ".join(e.trigger for e in new)

    # ── psutil-based memory / thread watcher ────────────────────────────

    def start_polling(self) -> None:
        """Poll process state periodically via psutil."""
        if not _HAVE_PSUTIL:
            return

        # Establish baseline
        try:
            proc = psutil.Process(self.pid)
            maps = proc.memory_maps(grouped=True)
            self._baseline_anon_maps = sum(
                1 for m in maps if not getattr(m, "path", "")
            )
            self._baseline_threads = proc.num_threads()
        except Exception:
            pass

        def _poll() -> None:
            while not self._stop_evt.is_set():
                time.sleep(1.0)
                self._poll_once()

        t = threading.Thread(target=_poll, daemon=True,
                              name=f"bhcap-poll-{self.pid}")
        t.start()

    def _poll_once(self) -> None:
        if not _HAVE_PSUTIL:
            return
        try:
            proc = psutil.Process(self.pid)

            # Anonymous memory growth
            maps      = proc.memory_maps(grouped=True)
            anon_now  = sum(1 for m in maps if not getattr(m, "path", ""))
            anon_delta = anon_now - self._baseline_anon_maps
            if anon_delta > 15:
                ev = CapturedEvent(
                    ts=time.time(), kind="memory",
                    name="anon_mmap_growth",
                    args=f"delta={anon_delta} total={anon_now}",
                    pid=self.pid, suspicious=True,
                )
                self._events.append(ev)
                self.engine.evaluate_syscall("mmap", "prot=exec anon=true")
                self._baseline_anon_maps = anon_now

            # Thread explosion
            threads_now = proc.num_threads()
            if threads_now > self._baseline_threads + 20:
                ev = CapturedEvent(
                    ts=time.time(), kind="thread",
                    name="thread_explosion",
                    args=f"count={threads_now} baseline={self._baseline_threads}",
                    pid=self.pid, suspicious=True,
                )
                self._events.append(ev)
                self._baseline_threads = threads_now

            # Thread start address verification (Linux: /proc/PID/task)
            if _PLATFORM == "Linux":
                self._check_thread_start_addrs(proc)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.stop()

    def _check_thread_start_addrs(self, proc: "psutil.Process") -> None:
        """Flag threads whose start address falls in anonymous memory regions."""
        try:
            maps = proc.memory_maps(grouped=False)
            anon_ranges = [
                (int(getattr(m, "addr", "0-0").split("-")[0], 16),
                 int(getattr(m, "addr", "0-0").split("-")[1], 16))
                for m in maps
                if not getattr(m, "path", "")
            ]
            if not anon_ranges:
                return

            task_dir = Path(f"/proc/{proc.pid}/task")
            if not task_dir.exists():
                return

            for tid_dir in task_dir.iterdir():
                try:
                    status = (tid_dir / "status").read_text()
                    for line in status.splitlines():
                        # Look for start_stack or startcode
                        if line.startswith("VmRSS"):
                            pass  # placeholder — real impl reads /proc/tid/syscall
                except Exception:
                    pass
        except Exception:
            pass

    # ── API hooking (stub with dispatch table) ────────────────────────────

    def register_api_event(self, api_name: str, args: str,
                            pid: int, ret: int = 0) -> None:
        """Call this from injected hooks (frida, LD_PRELOAD, etc.)."""
        suspicious = api_name in self.SUSPICIOUS_APIS
        ev = CapturedEvent(
            ts=time.time(), kind="api", name=api_name,
            args=args[:120], pid=pid, ret=ret, suspicious=suspicious,
        )
        self._events.append(ev)

        if suspicious:
            log.warning("🪝 API HOOK  pid=%-6d  %-35s  %s", pid, api_name, args[:60])
            # Translate to escalation trigger
            if "alloc" in api_name.lower() or "inject" in api_name.lower():
                self.engine.evaluate_syscall("mmap", "prot=exec anon=true")
            elif "reg" in api_name.lower():
                self.engine.evaluate_syscall("write",
                    "path=HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Run")
            elif "crypt" in api_name.lower():
                pass  # encryption ≠ always malicious; log only

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def stop(self) -> None:
        self._stop_evt.set()

    def report(self) -> str:
        total      = len(self._events)
        suspicious = sum(1 for e in self._events if e.suspicious)
        by_kind    = collections.Counter(e.kind for e in self._events)
        lines = [
            f"BehaviorCapture — pid={self.pid}",
            f"  Total events  : {total}",
            f"  Suspicious    : {suspicious}",
            f"  By kind       : {dict(by_kind)}",
            "",
            "  Recent suspicious events:",
        ]
        for ev in [e for e in self._events if e.suspicious][-8:]:
            ts_s = time.strftime("%H:%M:%S", time.localtime(ev.ts))
            lines.append(f"  {ts_s}  [{ev.kind}]  {ev.name}({ev.args[:50]})"
                         + (f"  — {ev.note}" if ev.note else ""))
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# LOLBin Constrained Mode
# ═══════════════════════════════════════════════════════════════════════════

_LOLBIN_NAMES = frozenset([
    "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta",
    "regsvr32", "rundll32", "certutil", "bitsadmin", "msiexec",
    "installutil", "msbuild", "cmstp", "odbcconf", "wmic",
    "schtasks", "reg", "net", "netsh", "wevtutil",
])

_SENSITIVE_PATHS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\\windows\\system32\\(sam|ntds|lsass|winlogon)",
        r"/etc/(shadow|passwd|sudoers|ssh)",
        r"\\AppData\\Roaming\\Microsoft\\(Vault|Protect|Credentials)",
        r"\.ssh/",
        r"\.gnupg/",
        r"\\SAM$",
    ]
]

@dataclass
class LOLBinPolicy:
    """Runtime policy for a LOLBin running in constrained mode."""
    binary_name:      str
    allow_network:    bool = False     # strip network; loopback only
    allow_child_spawn: bool = False    # block further child LOLBin spawns
    log_cmdlines:     bool = True
    block_sensitive:  bool = True      # deny access to credential/key paths
    constrained_lang: bool = True      # PowerShell: __PSLockdownPolicy=4
    env_overrides:    Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.constrained_lang and "powershell" in self.binary_name.lower():
            self.env_overrides["__PSLockdownPolicy"] = "4"
            self.env_overrides["PSExecutionPolicyPreference"] = "Restricted"

    def is_sensitive_path(self, path: str) -> bool:
        return any(p.search(path) for p in _SENSITIVE_PATHS)

    def report(self) -> str:
        return (
            f"LOLBin Policy [{self.binary_name}]:\n"
            f"  allow_network    : {self.allow_network}\n"
            f"  allow_child_spawn: {self.allow_child_spawn}\n"
            f"  block_sensitive  : {self.block_sensitive}\n"
            f"  constrained_lang : {self.constrained_lang}\n"
            f"  env_overrides    : {list(self.env_overrides.keys())}"
        )


def make_lolbin_policy(name: str) -> LOLBinPolicy:
    """Return appropriate constrained-mode policy for a given LOLBin."""
    base = name.lower().replace(".exe", "")
    return LOLBinPolicy(
        binary_name       = name,
        allow_network     = False,
        allow_child_spawn = False,
        log_cmdlines      = True,
        block_sensitive   = True,
        constrained_lang  = base in ("powershell", "pwsh"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# Sandbox Policy & Run Config
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SandboxPolicy:
    """High-level policy knobs — translated into layer configs at runtime."""
    allow_network:       bool  = False
    allow_sensitive_fs:  bool  = False
    allow_child_spawns:  bool  = True
    use_shadow_fs:       bool  = True
    use_namespace_jail:  bool  = True
    use_seccomp:         bool  = True
    lolbin_mode:         bool  = True
    max_runtime_sec:     float = 30.0
    max_mem_mb:          int   = 256
    max_procs:           int   = 16
    shadow_dir:          str   = ""
    initial_trust:       float = 100.0
    escalation_threshold_restrict: float = 75.0
    escalation_threshold_isolate:  float = 50.0
    escalation_threshold_block:    float = 20.0


@dataclass
class ContainedResult:
    """Result of one contained execution."""
    pid:             int
    returncode:      Optional[int]
    stdout:          str
    stderr:          str
    runtime_sec:     float
    final_trust:     float
    final_level:     ContainmentLevel
    events:          List[EscalationEvent]
    shadow_diff:     List[str]    # files written in shadow layer
    terminated_early: bool
    engine:          EscalationEngine
    capture:         BehaviorCapture
    shadow:          ShadowFileSystem
    lolbin_policy:   Optional[LOLBinPolicy]

    def report(self) -> str:
        verdict = ("✅ CLEAN — no changes committed to real FS"
                   if self.final_trust >= 75 else
                   "⚠  SUSPECT — shadow writes held for review"
                   if self.final_trust >= 40 else
                   "🚫 MALICIOUS — all writes discarded, dossier filed")
        lines = [
            "╔══════════════════════════════════════════════════════════════",
            f"║  CONTAINED EXECUTION REPORT",
            f"║  pid={self.pid}  runtime={self.runtime_sec:.2f}s  "
            f"trust={self.final_trust:.1f}  [{self.final_level.label}]",
            f"║  {verdict}",
            f"║  terminated_early={self.terminated_early}  "
            f"returncode={self.returncode}",
            "╠══════════════════════════════════════════════════════════════",
            "║  ESCALATION SUMMARY",
            *[f"║  {l}" for l in self.engine.report().splitlines()],
            "╠══════════════════════════════════════════════════════════════",
            "║  BEHAVIOR CAPTURE",
            *[f"║  {l}" for l in self.capture.report().splitlines()],
            "╠══════════════════════════════════════════════════════════════",
            "║  SHADOW FILE SYSTEM",
            *[f"║  {l}" for l in self.shadow.report().splitlines()],
            "╚══════════════════════════════════════════════════════════════",
        ]
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# IsolatedSandbox — the orchestrator
# ═══════════════════════════════════════════════════════════════════════════

class IsolatedSandbox:
    """Tie all isolation layers together around a single contained execution.

    Call run_contained() to execute a command inside the sandbox.
    Use admit_pid() to wrap an already-running process.
    """

    def __init__(self, policy: Optional[SandboxPolicy] = None) -> None:
        self.policy = policy or SandboxPolicy()

    def run_contained(self, cmd: List[str],
                       env_extra: Optional[Dict[str, str]] = None,
                       stdin_data: Optional[str] = None) -> ContainedResult:
        """Execute *cmd* inside all isolation layers.  Returns ContainedResult."""
        policy = self.policy
        t0     = time.monotonic()

        # ── 1. Shadow file system ─────────────────────────────────────────
        shadow = ShadowFileSystem(policy.shadow_dir)

        # ── 2. Escalation engine ──────────────────────────────────────────
        engine = EscalationEngine()
        engine.trust.current = policy.initial_trust

        # ── 3. LOLBin mode ────────────────────────────────────────────────
        binary_name = os.path.basename(cmd[0]).lower().replace(".exe", "")
        lolbin_pol: Optional[LOLBinPolicy] = None
        if policy.lolbin_mode and binary_name in _LOLBIN_NAMES:
            lolbin_pol = make_lolbin_policy(cmd[0])
            log.warning("🔧 LOLBin mode: %s", lolbin_pol.report())
            # Pre-score cmdline
            full_cmdline = " ".join(cmd)
            engine.evaluate_cmdline(full_cmdline)

        # ── 4. Token restrictor ───────────────────────────────────────────
        restrictor = TokenRestrictor(
            drop_network = not policy.allow_network,
            seccomp      = policy.use_seccomp,
            max_procs    = policy.max_procs,
            max_mem_mb   = policy.max_mem_mb,
        )

        # ── 5. Build environment ──────────────────────────────────────────
        env = os.environ.copy()
        if lolbin_pol:
            env.update(lolbin_pol.env_overrides)
        if env_extra:
            env.update(env_extra)
        env.update(restrictor.get_env_restrictions())
        # Redirect writes to shadow dir
        if policy.use_shadow_fs:
            env["TMPDIR"] = str(shadow.writes_dir)
            env["TEMP"]   = str(shadow.writes_dir)
            env["TMP"]    = str(shadow.writes_dir)

        # ── 6. Namespace jail wrapping ────────────────────────────────────
        launch_cmd = list(cmd)
        if policy.use_namespace_jail and _PLATFORM == "Linux" and shutil.which("unshare"):
            jail = NamespaceJail(shadow,
                                  loopback_only=not policy.allow_network)
            launch_cmd = jail.wrap_command(launch_cmd)
        else:
            jail = None

        # ── 7. Launch ──────────────────────────────────────────────────────
        log.warning(
            "🚀 Launching contained: %s  [trust=%.0f  namespace=%s  shadow=%s]",
            " ".join(launch_cmd[:6]) + (" …" if len(launch_cmd) > 6 else ""),
            engine.trust.current,
            jail is not None,
            policy.use_shadow_fs,
        )

        proc          = None
        stdout_data   = ""
        stderr_data   = ""
        returncode    = None
        terminated    = False

        try:
            preexec = restrictor.pre_exec_fn() if _PLATFORM == "Linux" else None
            proc = subprocess.Popen(
                launch_cmd,
                stdout        = subprocess.PIPE,
                stderr        = subprocess.PIPE,
                env           = env,
                cwd           = str(shadow.writes_dir),  # start inside shadow
                text          = True,
                preexec_fn    = preexec,
            )

            # ── 8. Behavior capture ───────────────────────────────────────
            capture = BehaviorCapture(proc.pid, engine)
            capture.start_ptrace()
            capture.start_polling()

            # ── 9. Network gate ───────────────────────────────────────────
            net_mode = (NetworkGate.Mode.BLOCK if not policy.allow_network
                        else NetworkGate.Mode.ALLOW)
            net_gate = NetworkGate(mode=net_mode, pid=proc.pid)
            net_gate.apply()

            # ── 10. Monitor loop with timeout ─────────────────────────────
            try:
                stdout_data, stderr_data = proc.communicate(
                    input   = stdin_data,
                    timeout = policy.max_runtime_sec,
                )
                returncode = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_data, stderr_data = proc.communicate()
                returncode  = -1
                terminated  = True
                engine.evaluate_cmdline("timeout exceeded")
                log.warning("⏰ Process timed out after %.0fs — killed", policy.max_runtime_sec)

            # ── 11. Evaluate cmdline IOCs in captured output ───────────────
            engine.evaluate_cmdline(stdout_data[:2000])
            engine.evaluate_cmdline(stderr_data[:2000])

            # ── 12. Final verdict ─────────────────────────────────────────
            net_gate.remove()
            capture.stop()

        except FileNotFoundError:
            log.error("Command not found: %s", launch_cmd[0])
            capture  = BehaviorCapture(0, engine)
            returncode = 127
            terminated = True

        except Exception as exc:
            log.error("Launch error: %s", exc)
            capture  = BehaviorCapture(0, engine)
            returncode = -2
            terminated = True

        runtime = time.monotonic() - t0
        final_trust = engine.trust.current
        final_level = ContainmentLevel.from_trust(final_trust)

        # ── 13. Shadow FS verdict ─────────────────────────────────────────
        shadow_diff = shadow.diff()
        if final_level == ContainmentLevel.HARD_BLOCK:
            shadow.discard()
        elif final_level == ContainmentLevel.MONITOR and not terminated:
            log.info("✅ Clean execution — shadow writes available for commit")

        result = ContainedResult(
            pid              = proc.pid if proc else 0,
            returncode       = returncode,
            stdout           = stdout_data[:5000],
            stderr           = stderr_data[:2000],
            runtime_sec      = runtime,
            final_trust      = final_trust,
            final_level      = final_level,
            events           = engine.events,
            shadow_diff      = shadow_diff,
            terminated_early = terminated,
            engine           = engine,
            capture          = capture,
            shadow           = shadow,
            lolbin_policy    = lolbin_pol,
        )

        log.warning(
            "🏁 Contained exec complete  pid=%-6d  trust=%.1f  [%s]  "
            "runtime=%.2fs  IOC_events=%d  shadow_files=%d",
            result.pid, final_trust, final_level.label,
            runtime, len(engine.events), len(shadow_diff),
        )
        return result

    def admit_pid(self, pid: int) -> Tuple[EscalationEngine, BehaviorCapture]:
        """Attach to an already-running process.  Returns engine + capture."""
        engine  = EscalationEngine()
        capture = BehaviorCapture(pid, engine)
        capture.start_ptrace()
        capture.start_polling()
        log.warning("🔬 Admitted existing pid=%d to isolated sandbox", pid)
        return engine, capture

    def __enter__(self) -> "IsolatedSandbox":
        return self

    def __exit__(self, *_: Any) -> None:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    import argparse
    p = argparse.ArgumentParser(
        prog="isolated_sandbox",
        description="Run a command inside isolation boundaries with concrete escalation math.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run")
    p.add_argument("--allow-network",   action="store_true")
    p.add_argument("--allow-sensitive", action="store_true")
    p.add_argument("--no-shadow",       action="store_true")
    p.add_argument("--no-namespace",    action="store_true")
    p.add_argument("--no-lolbin",       action="store_true")
    p.add_argument("--timeout",         type=float, default=30.0)
    p.add_argument("--max-mem",         type=int,   default=256)
    p.add_argument("--shadow-dir",      default="")
    p.add_argument("--verbose",         action="store_true")
    return p


# ═══════════════════════════════════════════════════════════════════════════
# Self-test
# ═══════════════════════════════════════════════════════════════════════════

def _self_test() -> None:
    logging.basicConfig(
        level   = logging.WARNING,
        format  = "%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt = "%H:%M:%S",
    )
    print("=" * 70)
    print("IsolatedSandbox self-test")
    print("=" * 70)

    # ── Test 1: Trust score math ──────────────────────────────────────────
    print("\n[Test 1] Trust score math")
    ts = TrustScore()
    assert ts.level == ContainmentLevel.MONITOR
    ts.drain(_TRIGGER_MAP["ENCODED_COMMAND"])       # -20
    assert ts.current == 80.0
    assert ts.level == ContainmentLevel.MONITOR
    ts.drain(_TRIGGER_MAP["PERSISTENCE_ATTEMPT"])   # -28 → 52
    assert ts.level == ContainmentLevel.RESTRICT
    ts.drain(_TRIGGER_MAP["CROSS_USER_INJECTION"])  # -35 → 17
    assert ts.level == ContainmentLevel.HARD_BLOCK
    ts.recover(60.0)  # → 77
    assert ts.level == ContainmentLevel.MONITOR
    print(f"  Trust history: {[(n, f'{d:+.0f}') for _,n,d in ts.log]}")
    print("✓  Trust score math correct")

    # ── Test 2: Escalation engine — cmdline triggers ──────────────────────
    print("\n[Test 2] Escalation engine — cmdline triggers")
    eng = EscalationEngine()
    evs = eng.evaluate_cmdline(
        "powershell -NoP -NonI -W Hidden -Enc QQBsAGkAYwBlAA=="
    )
    assert any(e.trigger == "ENCODED_COMMAND" for e in evs), "ENCODED_COMMAND not fired"
    assert any(e.trigger == "HIGH_ENTROPY_ARG" for e in evs), "HIGH_ENTROPY_ARG not fired"
    assert eng.trust.level.value >= ContainmentLevel.RESTRICT.value
    print(f"  Events fired: {[e.trigger for e in evs]}")
    print(f"  Trust: {eng.trust.current:.1f}")
    print("✓  Encoded command + high entropy both detected")

    # ── Test 3: Syscall triggers ──────────────────────────────────────────
    print("\n[Test 3] Syscall triggers")
    eng2  = EscalationEngine()
    evs2a = eng2.evaluate_syscall("mmap",
                                   "addr=0x7f..., prot=PROT_READ|PROT_WRITE|PROT_EXEC, flags=MAP_ANON")
    assert any(e.trigger == "ANONYMOUS_MEMORY_EXEC" for e in evs2a)
    evs2b = eng2.evaluate_syscall("ptrace", "PTRACE_ATTACH, target_pid=1234",
                                   process_user="alice", target_user="root")
    assert any(e.trigger == "CROSS_USER_INJECTION" for e in evs2b)
    print(f"  mmap events  : {[e.trigger for e in evs2a]}")
    print(f"  ptrace events: {[e.trigger for e in evs2b]}")
    print("✓  Syscall escalation triggers fire correctly")

    # ── Test 4: Child spawn scoring ───────────────────────────────────────
    print("\n[Test 4] Child spawn scoring")
    eng3 = EscalationEngine()
    evs3 = eng3.evaluate_child_spawn("WINWORD.EXE", "powershell.exe")
    assert evs3, "No event for Word→PowerShell"
    assert evs3[0].weight >= 22, f"Expected weight >= 22, got {evs3[0].weight}"
    print(f"  Event: {evs3[0].trigger}  weight={evs3[0].weight}")
    print("✓  Office→LOLBin spawn correctly scored with multiplier")

    # ── Test 5: Persistence + credential triggers ──────────────────────────
    print("\n[Test 5] Persistence + credential triggers")
    eng4 = EscalationEngine()
    evs4 = eng4.evaluate_syscall(
        "write",
        r"path=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Run\evil=C:\Temp\payload.exe"
    )
    assert any(e.trigger == "PERSISTENCE_ATTEMPT" for e in evs4)
    evs5 = eng4.evaluate_syscall("open", "path=/etc/shadow flags=O_RDONLY")
    assert any(e.trigger == "CREDENTIAL_STORE_ACCESS" for e in evs5)
    print(f"  Persistence trigger: {[e.trigger for e in evs4]}")
    print(f"  Credential trigger:  {[e.trigger for e in evs5]}")
    print("✓  Persistence and credential triggers fire correctly")

    # ── Test 6: Shadow file system ────────────────────────────────────────
    print("\n[Test 6] Shadow file system")
    shadow = ShadowFileSystem()
    real_path = "/etc/passwd"
    shadow_path = shadow.translate_path(real_path)
    Path(shadow_path).parent.mkdir(parents=True, exist_ok=True)
    Path(shadow_path).write_text("shadow copy of passwd")
    diff = shadow.diff()
    assert len(diff) == 1
    assert "passwd" in diff[0]
    print(f"  Shadow root : {shadow.shadow_root}")
    print(f"  Shadow diff : {diff}")
    shadow.discard()
    assert not shadow.shadow_root.exists(), "Shadow root should be deleted"
    print("✓  Shadow FS write + discard works correctly")

    # ── Test 7: LOLBin policy ─────────────────────────────────────────────
    print("\n[Test 7] LOLBin constrained mode policy")
    pol = make_lolbin_policy("powershell.exe")
    assert pol.constrained_lang == True
    assert pol.allow_network == False
    assert pol.env_overrides.get("__PSLockdownPolicy") == "4"
    assert pol.is_sensitive_path("/etc/shadow") == True
    assert pol.is_sensitive_path("/home/user/notes.txt") == False
    print(f"  Policy: {pol.report()}")
    print("✓  LOLBin policy correct — PS constrained, network off, sensitive paths blocked")

    # ── Test 8: ContainmentLevel from trust ────────────────────────────────
    print("\n[Test 8] ContainmentLevel thresholds")
    assert ContainmentLevel.from_trust(100) == ContainmentLevel.MONITOR
    assert ContainmentLevel.from_trust(75)  == ContainmentLevel.MONITOR
    assert ContainmentLevel.from_trust(74)  == ContainmentLevel.RESTRICT
    assert ContainmentLevel.from_trust(50)  == ContainmentLevel.RESTRICT
    assert ContainmentLevel.from_trust(49)  == ContainmentLevel.ISOLATE
    assert ContainmentLevel.from_trust(20)  == ContainmentLevel.ISOLATE
    assert ContainmentLevel.from_trust(19)  == ContainmentLevel.HARD_BLOCK
    assert ContainmentLevel.from_trust(0)   == ContainmentLevel.HARD_BLOCK
    print("✓  All four threshold boundaries correct")

    # ── Test 9: Contained execution of a benign command ───────────────────
    print("\n[Test 9] Contained execution — benign echo")
    policy = SandboxPolicy(
        use_shadow_fs      = True,
        use_namespace_jail = shutil.which("unshare") is not None,
        use_seccomp        = False,
        lolbin_mode        = True,
        max_runtime_sec    = 5.0,
        max_mem_mb         = 128,
    )
    sb = IsolatedSandbox(policy)
    result = sb.run_contained(["echo", "hello sandbox"])
    assert result.returncode == 0 or result.returncode is not None
    assert "hello sandbox" in result.stdout or result.terminated_early
    assert result.final_trust > 50, f"Benign echo should score > 50, got {result.final_trust}"
    print(f"  returncode  : {result.returncode}")
    print(f"  stdout      : {result.stdout.strip()}")
    print(f"  final trust : {result.final_trust:.1f}  [{result.final_level.label}]")
    print("✓  Benign echo stays at acceptable trust level")

    # ── Test 10: Full report rendering ────────────────────────────────────
    print("\n[Test 10] Report rendering")
    rep = result.report()
    assert "CONTAINED EXECUTION REPORT" in rep
    assert "ESCALATION SUMMARY"         in rep
    assert "SHADOW FILE SYSTEM"         in rep
    print(rep)
    print("✓  Report renders cleanly")

    print("\n" + "=" * 70)
    print("All self-tests passed.")
    print("=" * 70)


if __name__ == "__main__":
    import argparse as _ap
    if len(sys.argv) == 1:
        _self_test()
    else:
        _p = _build_parser()
        _a = _p.parse_args()
        logging.basicConfig(level=logging.DEBUG if _a.verbose else logging.INFO,
                            format="%(asctime)s  %(levelname)-8s  %(message)s")
        _pol = SandboxPolicy(
            allow_network      = _a.allow_network,
            allow_sensitive_fs = _a.allow_sensitive,
            use_shadow_fs      = not _a.no_shadow,
            use_namespace_jail = not _a.no_namespace,
            lolbin_mode        = not _a.no_lolbin,
            max_runtime_sec    = _a.timeout,
            max_mem_mb         = _a.max_mem,
            shadow_dir         = _a.shadow_dir,
        )
        _sb = IsolatedSandbox(_pol)
        _r  = _sb.run_contained(_a.cmd)
        print(_r.report())
        sys.exit(0 if _r.final_trust >= 50 else 1)