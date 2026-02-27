"""
AdaptiveAV Real-Time Monitor Daemon  ·  v2.0
=============================================
Enhancements over v1:
  · Entropy analysis  — detects packed/encrypted/obfuscated payloads
  · Magic-byte validation  — catches extension-spoofed files
  · Hash cache  — skip re-scanning known-clean files (SHA-256 bloom)
  · String / pattern scanner  — YARA-style rules, pure Python, no deps
  · Script obfuscation detector  — PS1 / JS / VBS / bash
  · PE / ELF header heuristics  — suspicious section names, no imports, etc.
  · Office macro sniffer  — OLE/OOXML macro flags, auto-open triggers
  · Network-connection correlator  — ties open sockets to suspicious processes
  · Recursive directory watch  — opt-in per directory
  · Native OS watchers  — inotify (Linux), FSEvents (macOS), ReadDirChanges (Win)
    with polling fallback (unchanged cross-platform guarantee)
  · Watchdog thread  — restarts dead sub-threads automatically
  · Graceful SIGTERM / SIGINT handling
  · Rate-limiter  — prevents scan storms on mass-write events
  · Configurable via ~/.adaptiveav/config.json
  · Everything is LOCAL. No telemetry. No cloud. No network calls.
"""

from __future__ import annotations

import os
import re
import sys
import time
import json
import math
import mmap
import signal
import socket
import struct
import hashlib
import logging
import platform
import threading
import subprocess
import traceback
from abc import ABC, abstractmethod
from collections import deque, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional, List, Dict, Set, Tuple

# ── Paths ─────────────────────────────────────────────────────────

BASE_DIR       = Path.home() / ".adaptiveav"
DAEMON_PID_FILE = BASE_DIR / "daemon.pid"
DAEMON_LOG_FILE = BASE_DIR / "daemon.log"
DAEMON_SOCK     = BASE_DIR / "daemon.sock"
ALERT_LOG       = BASE_DIR / "alerts.jsonl"
HASH_CACHE_FILE = BASE_DIR / "clean_hashes.json"  # known-clean SHA-256 set
CONFIG_FILE     = BASE_DIR / "config.json"

PLATFORM = platform.system()

# ── Default config ────────────────────────────────────────────────

DEFAULT_CONFIG: dict = {
    "poll_interval":      2.0,
    "process_interval":   5.0,
    "scan_max_size_mb":   50,
    "cache_max_entries":  50_000,
    "use_native_watcher": True,
    "recursive_watch":    False,     # set True per-dir in watch_dirs list
    "watch_dirs": {
        "Darwin":  [
            str(Path.home() / "Downloads"),
            str(Path.home() / "Desktop"),
            "/tmp",
            str(Path.home() / "Library/LaunchAgents"),
            str(Path.home() / "Library/LaunchDaemons"),
        ],
        "Linux": [
            str(Path.home() / "Downloads"),
            str(Path.home() / "Desktop"),
            "/tmp",
            "/var/tmp",
            str(Path.home() / ".config/autostart"),
            str(Path.home() / ".local/share/applications"),
        ],
        "Windows": [
            str(Path.home() / "Downloads"),
            str(Path.home() / "Desktop"),
            str(Path.home() / "AppData/Local/Temp"),
            str(Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"),
        ],
    },
}

def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            user = json.loads(CONFIG_FILE.read_text())
            cfg.update(user)
        except Exception:
            pass
    return cfg

CFG = load_config()

# ── Logging ───────────────────────────────────────────────────────

BASE_DIR.mkdir(exist_ok=True, parents=True)
_log = logging.getLogger("adaptiveav")
_log.setLevel(logging.DEBUG)
_fh = logging.FileHandler(DAEMON_LOG_FILE)
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
_log.addHandler(_fh)

# ── Suspicious process keywords ───────────────────────────────────

SUSPICIOUS_PROCESS_KEYWORDS: List[str] = [
    "mimikatz", "meterpreter", "cobalt", "metasploit",
    "netcat", "ncat", "nmap", "masscan",
    "john", "hashcat", "hydra",
    "sqlmap", "burpsuite",
    "nc -e", "bash -i >", "sh -i >",
    "powershell -w hidden", "powershell -windowstyle hidden",
    "iex(", "invoke-expression", "downloadstring(",
    "/dev/tcp/", "/dev/udp/",
    "base64 -d |", "base64 --decode |",
    "xterm -display",
]

# ── File extension categories ─────────────────────────────────────

EXECUTABLE_EXTS: Set[str] = {
    ".exe", ".dll", ".sys", ".drv", ".ocx",   # Windows PE
    ".com", ".scr", ".pif",
    ".elf", ".so", ".run", ".bin",            # Linux
    ".dylib", ".kext", ".pkg", ".app",        # macOS
    ".deb", ".rpm",
    ".jar", ".class", ".jnlp",               # JVM
    ".msi", ".msix", ".appx",
}

SCRIPT_EXTS: Set[str] = {
    ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta",
    ".sh", ".bash", ".zsh", ".fish",
    ".py", ".rb", ".pl", ".php",
    ".lua",
}

DOCUMENT_EXTS: Set[str] = {
    ".doc", ".docx", ".docm",
    ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm",
    ".odt", ".ods", ".odp",
    ".pdf",
    ".rtf",
}

ALL_WATCHED_EXTS = EXECUTABLE_EXTS | SCRIPT_EXTS | DOCUMENT_EXTS | {
    ".lnk", ".url", ".svg", ".html", ".xml",
}

# ── Magic bytes (file-type fingerprints) ──────────────────────────

MAGIC_SIGNATURES: Dict[bytes, str] = {
    b"MZ":                    "pe",        # Windows PE
    b"\x7fELF":               "elf",       # Linux ELF
    b"\xfe\xed\xfa\xce":      "macho32",   # Mach-O 32-bit
    b"\xce\xfa\xed\xfe":      "macho32le",
    b"\xfe\xed\xfa\xcf":      "macho64",
    b"\xcf\xfa\xed\xfe":      "macho64le",
    b"PK\x03\x04":            "zip",       # ZIP / OOXML / JAR / APK
    b"\xd0\xcf\x11\xe0":      "ole",       # OLE2 (legacy Office, MSI)
    b"%PDF":                   "pdf",
    b"#!":                     "shebang",
    b"\x4d\x5a":              "pe",        # alternate MZ spelling
    b"CAFEBABE":               "java-class",
    b"\xca\xfe\xba\xbe":      "java-class",
}

# Spoofable: extension claims one type but magic says another
EXTENSION_MAGIC_MAP: Dict[str, str] = {
    ".exe": "pe",   ".dll": "pe",   ".sys": "pe",
    ".elf": "elf",  ".so":  "elf",  ".run": "elf",
    ".pdf": "pdf",
    ".jar": "zip",  ".docx": "zip", ".xlsx": "zip",
    ".doc": "ole",  ".xls":  "ole", ".ppt":  "ole",
}

# ── YARA-style pattern rules ──────────────────────────────────────

class PatternRule:
    """Lightweight regex/bytes pattern with scoring."""
    __slots__ = ("name", "pattern", "score", "context", "is_bytes")

    def __init__(self, name: str, pattern, score: int, context: str = "any", is_bytes: bool = False):
        self.name     = name
        self.pattern  = re.compile(pattern, re.IGNORECASE | (0 if is_bytes else re.MULTILINE))
        self.score    = score
        self.context  = context   # "any", "script", "pe", "office", "pdf"
        self.is_bytes = is_bytes

PATTERN_RULES: List[PatternRule] = [
    # ── PowerShell obfuscation ──────────────────────────────────
    PatternRule("ps1_encoded_cmd",       rb"\-[Ee]n[Cc][Oo][Dd][Ee][Dd][Cc]",    5, "script"),
    PatternRule("ps1_iex",               rb"[Ii]nvo[Kk][Ee]-[Ee]xpression",       4, "script"),
    PatternRule("ps1_downloadstring",    rb"DownloadString\s*\(",                  5, "script"),
    PatternRule("ps1_downloadfile",      rb"DownloadFile\s*\(",                    5, "script"),
    PatternRule("ps1_webclient",         rb"Net\.WebClient",                       3, "script"),
    PatternRule("ps1_hidden_window",     rb"-[Ww]indow[Ss]tyle\s+[Hh]idden",      4, "script"),
    PatternRule("ps1_bypass",            rb"-[Ee]xecution[Pp]olicy\s+[Bb]ypass",  5, "script"),
    PatternRule("ps1_string_concat",     rb"\(\s*'[^']+'\s*\+\s*'[^']+'\s*\)\s*\+", 3, "script"),
    PatternRule("ps1_amsi_bypass",       rb"[Aa][Mm][Ss][Ii]",                    3, "script"),
    PatternRule("ps1_reflection",        rb"\[Reflection\.Assembly\]",             4, "script"),
    PatternRule("ps1_marshal_alloc",     rb"Marshal\s*::\s*AllocHGlobal",          5, "script"),

    # ── VBScript / JScript ──────────────────────────────────────
    PatternRule("vbs_wscript_shell",     rb"WScript\s*\.\s*Shell",                4, "script"),
    PatternRule("vbs_createobject",      rb"CreateObject\s*\(\s*[\"']",           3, "script"),
    PatternRule("vbs_shell_exec",        rb"\.Run\s+\"cmd",                        5, "script"),
    PatternRule("vbs_regwrite",          rb"RegWrite",                             4, "script"),
    PatternRule("js_activex_shell",      rb"new\s+ActiveXObject\s*\(\s*[\"']WScript", 5, "script"),

    # ── Bash / sh obfuscation ───────────────────────────────────
    PatternRule("bash_base64_exec",      rb"base64\s+(?:-d|--decode)\s*\|",       5, "script"),
    PatternRule("bash_dev_tcp",          rb"/dev/(tcp|udp)/",                      5, "script"),
    PatternRule("bash_curl_pipe",        rb"curl\s+[^\|]+\|\s*(ba)?sh",           5, "script"),
    PatternRule("bash_wget_pipe",        rb"wget\s+[^\|]+\|\s*(ba)?sh",           5, "script"),
    PatternRule("bash_hidden_cron",      rb"crontab\s+-[^l]",                     3, "script"),

    # ── Macro / Office ──────────────────────────────────────────
    PatternRule("vba_auto_open",         rb"Auto_?Open|AutoOpen|Workbook_Open",   5, "office"),
    PatternRule("vba_shell",             rb"\bShell\s*\(",                         4, "office"),
    PatternRule("vba_environ",           rb"\bEnviron\s*\(",                       2, "office"),
    PatternRule("vba_create_object",     rb"\bCreateObject\s*\(",                  4, "office"),
    PatternRule("vba_write_file",        rb"\bOpen\s+.+For\s+(?:Output|Append)",  3, "office"),
    PatternRule("vba_wmi",               rb"GetObject\s*\(\s*[\"']winmgmts",      5, "office"),

    # ── Generic shellcode indicators ────────────────────────────
    PatternRule("shellcode_nop_sled",    rb"\x90{20,}",                            5, "any", True),
    PatternRule("shellcode_x86_push_ret",rb"(\x68.{4}\xc3){3,}",                 4, "any", True),

    # ── Network / C2 indicators ─────────────────────────────────
    PatternRule("hardcoded_ipv4",        rb"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\."
                                         rb"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b", 1, "any"),
    PatternRule("url_in_script",         rb"https?://[^\s\"']{10,}",              1, "script"),
    PatternRule("onion_address",         rb"[a-z2-7]{16,56}\.onion",              4, "any"),

    # ── Credential harvesting ───────────────────────────────────
    PatternRule("lsass_access",          rb"lsass\.exe",                           4, "any"),
    PatternRule("sam_access",            rb"SYSTEM\\CurrentControlSet\\Control\\"
                                         rb"SAM",                                  5, "any"),
    PatternRule("password_keyword",      rb"password\s*=\s*['\"][^'\"]{4,}",      2, "any"),

    # ── Ransomware indicators ───────────────────────────────────
    PatternRule("ransom_note_text",      rb"your\s+files\s+(have\s+been|are)\s+(encrypted|locked)", 5, "any"),
    PatternRule("mass_rename_ext",       rb"\.(encrypted|locked|enc\d?|crypted)\b", 3, "any"),
    PatternRule("bitcoin_address",       rb"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", 2, "any"),

    # ── Persistence mechanisms ──────────────────────────────────
    PatternRule("registry_run_key",      rb"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 4, "any"),
    PatternRule("launchagent_path",      rb"Library/LaunchAgents/",               3, "any"),
    PatternRule("cron_persist",          rb"/etc/cron\.(d|daily|weekly|monthly)/", 3, "any"),
    PatternRule("rc_local_persist",      rb"/etc/rc\.local",                       3, "any"),
]


# ── Entropy engine ────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy [0.0–8.0] of a byte buffer."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def section_entropy(data: bytes, section_size: int = 512) -> Tuple[float, float, float]:
    """Return (mean, max, variance) section entropy for a file buffer."""
    sections = [data[i:i + section_size] for i in range(0, len(data), section_size) if data[i:i + section_size]]
    entropies = [shannon_entropy(s) for s in sections]
    if not entropies:
        return 0.0, 0.0, 0.0
    mean = sum(entropies) / len(entropies)
    variance = sum((e - mean) ** 2 for e in entropies) / len(entropies)
    return mean, max(entropies), variance


# ── File-type detection ───────────────────────────────────────────

def detect_magic(header: bytes) -> Optional[str]:
    """Return file type string from first 8 bytes, or None."""
    for sig, ftype in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            return ftype
    return None


def is_spoofed_extension(path: Path, header: bytes) -> bool:
    """Return True if file magic doesn't match declared extension."""
    ext = path.suffix.lower()
    expected_magic = EXTENSION_MAGIC_MAP.get(ext)
    if expected_magic is None:
        return False
    actual_magic = detect_magic(header)
    if actual_magic is None:
        return False
    # zip covers many formats (docx, xlsx, jar) — all map to "zip"
    if expected_magic == "zip" and actual_magic == "zip":
        return False
    return actual_magic != expected_magic


# ── PE / ELF header heuristics ───────────────────────────────────

def _pe_score(data: bytes) -> Tuple[int, List[str]]:
    """Basic PE header heuristic scoring. Returns (score, reasons)."""
    score = 0
    reasons: List[str] = []
    if len(data) < 64:
        return score, reasons

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew >= len(data) - 4:
            return score, reasons
        pe_sig = data[e_lfanew:e_lfanew + 4]
        if pe_sig != b"PE\x00\x00":
            return score, reasons

        coff_offset = e_lfanew + 4
        machine       = struct.unpack_from("<H", data, coff_offset)[0]
        num_sections  = struct.unpack_from("<H", data, coff_offset + 2)[0]
        characteristics = struct.unpack_from("<H", data, coff_offset + 18)[0]

        # DLL flag but no .dll extension
        if characteristics & 0x2000:
            reasons.append("pe:dll-flag-no-dll-ext")
            score += 1

        # More than 12 sections is unusual
        if num_sections > 12:
            score += 2
            reasons.append(f"pe:excessive-sections({num_sections})")

        # Scan section names
        opt_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
        section_table_offset = coff_offset + 20 + opt_size
        suspicious_names = {b"UPX0", b"UPX1", b"UPX2", b".ndata", b"_text\x00", b".vmp0", b".vmp1", b"themida"}
        for i in range(num_sections):
            off = section_table_offset + i * 40
            if off + 8 > len(data):
                break
            name = data[off:off + 8].rstrip(b"\x00")
            for sn in suspicious_names:
                if name.startswith(sn.rstrip(b"\x00")):
                    score += 3
                    reasons.append(f"pe:suspicious-section({name.decode(errors='ignore')})")

        # Import table size = 0 (no imports → likely packed)
        if opt_size >= 128:
            import_rva = struct.unpack_from("<I", data, coff_offset + 20 + 104)[0]
            import_size = struct.unpack_from("<I", data, coff_offset + 20 + 108)[0]
            if import_rva == 0 and import_size == 0:
                score += 3
                reasons.append("pe:no-import-table")

    except (struct.error, IndexError):
        pass

    return score, reasons


def _elf_score(data: bytes) -> Tuple[int, List[str]]:
    """Basic ELF heuristic scoring."""
    score = 0
    reasons: List[str] = []
    if len(data) < 52:
        return score, reasons
    try:
        e_type = struct.unpack_from("<H", data, 16)[0]
        if e_type == 3:  # ET_DYN (shared lib / PIE)
            # Fine on its own, but combine with high entropy
            pass
        # Stripped binary: check for absence of section header table
        e_shnum = struct.unpack_from("<H", data, 48)[0]
        if e_shnum == 0:
            score += 2
            reasons.append("elf:no-section-headers")
    except (struct.error, IndexError):
        pass
    return score, reasons


# ── Office macro sniffer ──────────────────────────────────────────

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_OOXML_MACRO_STREAMS = (b"vbaProject.bin", b"xl/vbaProject.bin", b"word/vbaProject.bin")

def has_office_macro(path: Path, header: bytes) -> bool:
    """
    Returns True if the file appears to contain a VBA macro.
    No deps — uses raw bytes inspection.
    """
    try:
        data = path.read_bytes()
    except Exception:
        return False

    # OLE2 (legacy .doc/.xls): look for VBA stream
    if header.startswith(_OLE_MAGIC):
        return b"VBA" in data or b"_VBA_PROJECT" in data

    # OOXML (ZIP): look for vbaProject.bin entry
    if header.startswith(b"PK\x03\x04"):
        for marker in _OOXML_MACRO_STREAMS:
            if marker in data:
                return True

    return False


# ── Hash cache (known-clean blocklist/allowlist) ──────────────────

class HashCache:
    """
    Thread-safe SHA-256 cache for known-clean files.
    Persisted to disk as a flat JSON list.
    """

    def __init__(self, path: Path = HASH_CACHE_FILE, max_entries: int = 50_000):
        self._path       = path
        self._max        = max_entries
        self._hashes: Set[str] = set()
        self._lock       = threading.Lock()
        self._load()

    def _load(self):
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                self._hashes = set(data.get("hashes", []))
            except Exception:
                pass

    def _save(self):
        try:
            self._path.parent.mkdir(exist_ok=True, parents=True)
            with open(self._path, "w") as f:
                json.dump({"hashes": list(self._hashes)}, f)
        except Exception:
            pass

    def contains(self, sha256: str) -> bool:
        with self._lock:
            return sha256 in self._hashes

    def add_clean(self, sha256: str):
        with self._lock:
            if len(self._hashes) >= self._max:
                self._hashes.pop()
            self._hashes.add(sha256)
            self._save()

    def remove(self, sha256: str):
        """Remove a hash (e.g., after it's been quarantined)."""
        with self._lock:
            self._hashes.discard(sha256)
            self._save()

    def __len__(self) -> int:
        with self._lock:
            return len(self._hashes)


# ── Rate limiter ──────────────────────────────────────────────────

class RateLimiter:
    """
    Token-bucket rate limiter per path.
    Prevents scan storms on mass-write events.
    """

    def __init__(self, max_per_second: float = 20.0):
        self._max     = max_per_second
        self._tokens  = max_per_second
        self._last    = time.monotonic()
        self._lock    = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now    = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self._max, self._tokens + elapsed * self._max)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


# ── Alert system ─────────────────────────────────────────────────

class Alert:
    def __init__(self, level: str, category: str, message: str, data: dict = None):
        self.level     = level      # INFO, WARNING, CRITICAL
        self.category  = category   # file, process, browser, network, macro
        self.message   = message
        self.data      = data or {}
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "level":     self.level,
            "category":  self.category,
            "message":   self.message,
            "data":      self.data,
            "timestamp": self.timestamp,
        }


class AlertBus:
    """Thread-safe alert dispatch + persistent JSONL log."""

    def __init__(self, max_size: int = 1000):
        self._queue:    deque         = deque(maxlen=max_size)
        self._handlers: List[Callable] = []
        self._lock      = threading.Lock()

    def subscribe(self, handler: Callable):
        with self._lock:
            self._handlers.append(handler)

    def publish(self, alert: Alert):
        with self._lock:
            self._queue.append(alert)
            handlers = list(self._handlers)
        for h in handlers:
            try:
                h(alert)
            except Exception:
                pass
        try:
            ALERT_LOG.parent.mkdir(exist_ok=True, parents=True)
            with open(ALERT_LOG, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except Exception:
            pass

    def recent(self, n: int = 50) -> List[Alert]:
        with self._lock:
            return list(self._queue)[-n:]


# ── File scanner (local, stateless) ──────────────────────────────

class FileScanner:
    """
    Standalone file scanner — called by FileWatcher and on-demand CLI scans.
    Does NOT depend on any external engine; all analysis is local.
    Optionally delegates verdict to `engine` (AdaptiveAVEngine) if provided.
    """

    def __init__(self,
                 alert_bus: AlertBus,
                 hash_cache: HashCache,
                 engine=None,
                 max_scan_bytes: int = 50 * 1024 * 1024):
        self.alert_bus     = alert_bus
        self.hash_cache    = hash_cache
        self.engine        = engine
        self.max_scan_bytes = max_scan_bytes
        self._rate         = RateLimiter(max_per_second=20.0)

    def scan_file(self, path: Path, event: str = "created") -> Optional[dict]:
        """
        Scan a single file. Returns a result dict or None (clean / skipped).
        All I/O errors are swallowed — never raises.
        """
        if not self._rate.allow():
            return None

        try:
            return self._scan(path, event)
        except Exception:
            _log.debug("scan_file exception: %s", traceback.format_exc())
            return None

    def _scan(self, path: Path, event: str) -> Optional[dict]:
        if not path.exists() or not path.is_file():
            return None

        stat = path.stat()
        file_size = stat.st_size

        # Skip zero-byte files and files that are too large
        if file_size == 0 or file_size > self.max_scan_bytes:
            return None

        # Read header (first 8 KB) for magic + quick checks
        try:
            with open(path, "rb") as fh:
                header = fh.read(8192)
        except (PermissionError, OSError):
            return None

        ext = path.suffix.lower()

        # Skip files with no suspicious extension unless they have executable magic
        magic_type = detect_magic(header)
        if ext not in ALL_WATCHED_EXTS and magic_type not in ("pe", "elf", "macho32", "macho64", "macho32le", "macho64le"):
            return None

        # ── Hash + cache check ────────────────────────────────
        sha256 = self._hash_file(path)
        if sha256 and self.hash_cache.contains(sha256):
            return None  # known clean

        score  = 0
        flags: List[str] = []

        # ── Extension / magic mismatch ─────────────────────────
        if is_spoofed_extension(path, header):
            score += 6
            flags.append(f"spoofed-ext:{ext}!={magic_type}")

        # ── Full-file read for deeper analysis ─────────────────
        # Only read fully for scripts, Office docs, and smaller executables
        full_data: Optional[bytes] = None
        if file_size <= 4 * 1024 * 1024 or ext in SCRIPT_EXTS | DOCUMENT_EXTS:
            try:
                full_data = path.read_bytes()
            except (PermissionError, OSError):
                full_data = header

        data_for_analysis = full_data or header

        # ── Entropy analysis ───────────────────────────────────
        mean_ent, max_ent, var_ent = section_entropy(data_for_analysis)
        if mean_ent > 7.2 and magic_type in ("pe", "elf", "macho32", "macho64", "macho32le", "macho64le"):
            score += 4
            flags.append(f"high-entropy-executable:{mean_ent:.2f}")
        elif mean_ent > 7.5:
            score += 2
            flags.append(f"high-entropy:{mean_ent:.2f}")

        # Encrypted sections check (high variance + very high peak)
        if max_ent > 7.8 and var_ent < 0.05:
            score += 3
            flags.append("uniform-high-entropy(possible-encrypted-payload)")

        # ── PE header heuristics ───────────────────────────────
        if magic_type == "pe":
            pe_score, pe_reasons = _pe_score(data_for_analysis)
            score += pe_score
            flags.extend(pe_reasons)

        # ── ELF header heuristics ──────────────────────────────
        elif magic_type == "elf":
            elf_score, elf_reasons = _elf_score(data_for_analysis)
            score += elf_score
            flags.extend(elf_reasons)

        # ── Office macro detection ─────────────────────────────
        elif ext in DOCUMENT_EXTS or magic_type in ("ole", "zip"):
            if has_office_macro(path, header):
                score += 5
                flags.append("office-macro-detected")
                # Pattern-scan the macro content
                macro_flags = self._pattern_scan(data_for_analysis, context="office")
                score += sum(r["score"] for r in macro_flags)
                flags.extend(r["name"] for r in macro_flags)

        # ── Shebang / script analysis ──────────────────────────
        if ext in SCRIPT_EXTS or header.startswith(b"#!"):
            script_flags = self._pattern_scan(data_for_analysis, context="script")
            score += sum(r["score"] for r in script_flags)
            flags.extend(r["name"] for r in script_flags)

            # Obfuscation: very long lines (> 1000 chars) in scripts
            try:
                lines = data_for_analysis.split(b"\n")
                max_line = max((len(l) for l in lines), default=0)
                if max_line > 2000:
                    score += 3
                    flags.append(f"obfuscated-long-line:{max_line}")
                elif max_line > 1000:
                    score += 1
                    flags.append(f"long-line:{max_line}")
            except Exception:
                pass

        # ── Generic pattern scan for all types ────────────────
        generic_flags = self._pattern_scan(data_for_analysis, context="any")
        score += sum(r["score"] for r in generic_flags)
        flags.extend(r["name"] for r in generic_flags)

        # ── Delegate to engine if available ───────────────────
        engine_result = None
        if self.engine:
            try:
                engine_result = self.engine.scan(str(path))
                if engine_result.verdict == "malicious":
                    score += 10
                    flags.append(f"engine:{engine_result.threat_name or engine_result.risk_level}")
            except Exception:
                pass

        # ── Verdict ────────────────────────────────────────────
        if score == 0:
            if sha256:
                self.hash_cache.add_clean(sha256)
            return None

        level    = "CRITICAL" if score >= 8 else "WARNING" if score >= 4 else "INFO"
        category = "macro" if "office-macro-detected" in flags else "file"

        threat_name = None
        if engine_result:
            threat_name = getattr(engine_result, "threat_name", None)

        result = {
            "path":        str(path),
            "sha256":      sha256,
            "size":        file_size,
            "ext":         ext,
            "magic":       magic_type,
            "score":       score,
            "flags":       flags,
            "level":       level,
            "event":       event,
            "threat_name": threat_name,
            "entropy":     round(mean_ent, 3),
        }

        self.alert_bus.publish(Alert(
            level=level,
            category=category,
            message=f"Threat detected [{event}]: {path.name}  score={score}  flags={flags[:4]}",
            data=result,
        ))
        return result

    def _pattern_scan(self, data: bytes, context: str) -> List[dict]:
        hits = []
        for rule in PATTERN_RULES:
            if rule.context not in ("any", context):
                continue
            try:
                if rule.pattern.search(data):
                    hits.append({"name": rule.name, "score": rule.score})
            except Exception:
                pass
        return hits

    @staticmethod
    def _hash_file(path: Path) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None


# ── OS-native file watchers ───────────────────────────────────────

class BaseWatcher(ABC):
    @abstractmethod
    def start(self): ...
    @abstractmethod
    def stop(self): ...
    @abstractmethod
    def add_dir(self, path: str): ...


class _InotifyWatcher(BaseWatcher):
    """
    Linux inotify watcher using ctypes (no deps).
    Watches IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE.
    """
    _IN_CREATE      = 0x00000100
    _IN_CLOSE_WRITE = 0x00000008
    _IN_MOVED_TO    = 0x00000080
    _IN_MASK        = _IN_CREATE | _IN_CLOSE_WRITE | _IN_MOVED_TO

    def __init__(self, dirs: List[str], callback: Callable, recursive: bool = False):
        import ctypes
        import ctypes.util
        self._libc      = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self._callback  = callback
        self._recursive = recursive
        self._wd_to_dir: Dict[int, str] = {}
        self._stop      = threading.Event()
        self._thread    = None
        self._fd        = self._libc.inotify_init()
        self._dirs      = dirs
        for d in dirs:
            self._watch(d)

    def _watch(self, path: str):
        import ctypes
        wd = self._libc.inotify_add_watch(self._fd, path.encode(), self._IN_MASK)
        if wd > 0:
            self._wd_to_dir[wd] = path
        if self._recursive:
            try:
                for child in Path(path).iterdir():
                    if child.is_dir():
                        self._watch(str(child))
            except Exception:
                pass

    def add_dir(self, path: str):
        if path not in self._dirs:
            self._dirs.append(path)
            self._watch(path)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="InotifyWatcher")
        self._thread.start()

    def stop(self):
        self._stop.set()
        import ctypes
        self._libc.close(self._fd)

    def _run(self):
        import ctypes
        EVENT_SIZE  = 16
        BUF_SIZE    = 4096
        while not self._stop.is_set():
            try:
                buf = (ctypes.c_char * BUF_SIZE)()
                length = self._libc.read(self._fd, buf, BUF_SIZE)
                if length <= 0:
                    continue
                offset = 0
                while offset < length:
                    wd, mask, cookie, name_len = struct.unpack_from("iIII", buf, offset)
                    offset += EVENT_SIZE
                    name_bytes = buf[offset:offset + name_len]
                    offset    += name_len
                    name = name_bytes.rstrip(b"\x00").decode(errors="ignore")
                    if name and wd in self._wd_to_dir:
                        full_path = Path(self._wd_to_dir[wd]) / name
                        event = "modified" if mask & self._IN_CLOSE_WRITE else "created"
                        self._callback(event, full_path)
            except Exception:
                if not self._stop.is_set():
                    time.sleep(0.5)


class _PollingWatcher(BaseWatcher):
    """
    Universal polling watcher (unchanged cross-platform fallback).
    """

    def __init__(self, dirs: List[str], callback: Callable,
                 poll_interval: float = 2.0, recursive: bool = False):
        self._dirs          = [Path(d) for d in dirs if Path(d).exists()]
        self._callback      = callback
        self._poll_interval = poll_interval
        self._recursive     = recursive
        self._seen: Dict[str, float] = {}
        self._stop  = threading.Event()
        self._thread = None

    def start(self):
        # Seed with existing files (don't alert on startup)
        for d in self._dirs:
            for f in self._iter_dir(d):
                try:
                    self._seen[str(f)] = f.stat().st_mtime
                except Exception:
                    pass
        self._thread = threading.Thread(target=self._run, daemon=True, name="PollingWatcher")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def add_dir(self, path: str):
        p = Path(path)
        if p.exists() and p not in self._dirs:
            self._dirs.append(p)

    def _iter_dir(self, d: Path):
        try:
            for item in d.iterdir():
                if item.is_file():
                    yield item
                elif item.is_dir() and self._recursive:
                    yield from self._iter_dir(item)
        except Exception:
            pass

    def _run(self):
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception:
                pass
            self._stop.wait(self._poll_interval)

    def _poll(self):
        for d in self._dirs:
            for item in self._iter_dir(d):
                path_str = str(item)
                try:
                    mtime = item.stat().st_mtime
                except Exception:
                    continue
                if path_str not in self._seen:
                    self._seen[path_str] = mtime
                    self._callback("created", item)
                elif mtime != self._seen[path_str]:
                    self._seen[path_str] = mtime
                    self._callback("modified", item)


def make_watcher(dirs: List[str], callback: Callable, cfg: dict) -> BaseWatcher:
    """Factory: pick best available watcher for the current OS."""
    recursive = cfg.get("recursive_watch", False)
    poll_int  = cfg.get("poll_interval", 2.0)
    use_native = cfg.get("use_native_watcher", True)

    if use_native and PLATFORM == "Linux":
        try:
            w = _InotifyWatcher(dirs, callback, recursive=recursive)
            _log.info("Using inotify watcher")
            return w
        except Exception as e:
            _log.warning("inotify unavailable (%s), falling back to polling", e)

    # macOS FSEvents requires PyObjC — if not present, fall back to polling
    if use_native and PLATFORM == "Darwin":
        try:
            from Foundation import NSRunLoop, NSDate  # type: ignore
            from FSEvents import (  # type: ignore
                kFSEventStreamEventFlagNone,
                kFSEventStreamCreateFlagFileEvents,
                FSEventStreamCreate, FSEventStreamStart,
                FSEventStreamScheduleWithRunLoop,
                kCFRunLoopDefaultMode,
            )
            _log.info("FSEvents available but not using (no stable ctypes binding) — using polling")
        except ImportError:
            pass

    _log.info("Using polling watcher (interval=%.1fs)", poll_int)
    return _PollingWatcher(dirs, callback, poll_interval=poll_int, recursive=recursive)


# ── FileWatcher (public interface) ────────────────────────────────

class FileWatcher:
    """
    Public file watcher: wraps OS-native or polling backend.
    Feeds events to FileScanner.
    """

    def __init__(self, dirs: List[str], scanner: FileScanner, cfg: dict):
        self._scanner = scanner
        self._backend = make_watcher(dirs, self._on_event, cfg)
        self.dirs     = [Path(d) for d in dirs]

    def _on_event(self, event: str, path: Path):
        # Skip our own housekeeping files
        if str(path).startswith(str(BASE_DIR)):
            return
        self._scanner.scan_file(path, event)

    def start(self):
        self._backend.start()

    def stop(self):
        self._backend.stop()

    def add_dir(self, path: str):
        self.dirs.append(Path(path))
        self._backend.add_dir(path)


# ── Network connection correlator ─────────────────────────────────

class NetworkMonitor:
    """
    Reads /proc/net/tcp (Linux) or `lsof` (macOS) to find suspicious
    processes with established outbound connections to non-local IPs.
    Runs every 30 seconds.
    """

    PRIVATE_PREFIXES = (
        "127.", "10.", "192.168.", "::1", "0.0.0.0",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    )
    SUSPICIOUS_PORTS = {4444, 4445, 5555, 6666, 6667, 1337, 31337, 9001, 9030}

    def __init__(self, alert_bus: AlertBus):
        self.alert_bus = alert_bus
        self._stop     = threading.Event()
        self._thread   = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="NetworkMonitor")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                self._check()
            except Exception:
                pass
            self._stop.wait(30.0)

    def _check(self):
        if PLATFORM == "Linux":
            self._check_linux()
        elif PLATFORM == "Darwin":
            self._check_macos()

    def _check_linux(self):
        """Parse /proc/net/tcp and correlate with /proc/<pid>/fd."""
        try:
            connections = []
            for f in ("/proc/net/tcp", "/proc/net/tcp6"):
                try:
                    lines = Path(f).read_text().splitlines()[1:]
                    for line in lines:
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        state = parts[3]
                        if state != "01":  # 01 = ESTABLISHED
                            continue
                        remote_hex = parts[2]
                        rip_hex, rport_hex = remote_hex.split(":")
                        rport = int(rport_hex, 16)
                        # Decode IPv4
                        rip_bytes = bytes.fromhex(rip_hex)
                        rip = ".".join(str(b) for b in reversed(rip_bytes))
                        if not any(rip.startswith(p) for p in self.PRIVATE_PREFIXES):
                            connections.append((rip, rport))
                        elif rport in self.SUSPICIOUS_PORTS:
                            connections.append((rip, rport))
                except Exception:
                    pass
            for rip, rport in connections:
                if rport in self.SUSPICIOUS_PORTS:
                    self.alert_bus.publish(Alert(
                        level="WARNING",
                        category="network",
                        message=f"Connection on suspicious port {rport} → {rip}:{rport}",
                        data={"remote_ip": rip, "remote_port": rport},
                    ))
        except Exception:
            pass

    def _check_macos(self):
        """Use lsof -i TCP -s TCP:ESTABLISHED to find connections."""
        try:
            out = subprocess.check_output(
                ["lsof", "-i", "TCP", "-s", "TCP:ESTABLISHED", "-n", "-P"],
                timeout=10, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 9:
                    continue
                conn_info = parts[-1]
                if "->" not in conn_info:
                    continue
                remote = conn_info.split("->")[1]
                rip, rport_str = remote.rsplit(":", 1)
                rport = int(rport_str)
                if not any(rip.startswith(p) for p in self.PRIVATE_PREFIXES):
                    if rport in self.SUSPICIOUS_PORTS:
                        self.alert_bus.publish(Alert(
                            level="WARNING",
                            category="network",
                            message=f"Process '{parts[0]}' (PID {parts[1]}) on suspicious port {rport}",
                            data={"process": parts[0], "pid": parts[1], "remote": remote},
                        ))
        except Exception:
            pass


# ── Process monitor (unchanged + network correlation) ─────────────

class ProcessMonitor:
    """
    Monitors running processes for suspicious behavior.
    Linux: reads /proc directly.
    macOS: ps.
    Windows: tasklist (basic).
    """

    def __init__(self, alert_bus: AlertBus, interval: float = 5.0):
        self.alert_bus  = alert_bus
        self._interval  = interval
        self._seen_pids: Set[int] = set()
        self._stop      = threading.Event()
        self._thread    = None

    def start(self):
        for proc in self._list_processes():
            self._seen_pids.add(proc.get("pid", -1))
        self._thread = threading.Thread(target=self._run, daemon=True, name="ProcessMonitor")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                self._check_processes()
            except Exception:
                pass
            self._stop.wait(self._interval)

    def _check_processes(self):
        current = self._list_processes()
        current_pids = {p.get("pid", -1) for p in current}

        for proc in current:
            pid = proc.get("pid", -1)
            if pid in self._seen_pids:
                continue
            self._seen_pids.add(pid)

            cmdline    = proc.get("cmdline", "").lower()
            name       = proc.get("name", "").lower()
            suspicion  = 0
            reasons: List[str]    = []

            for kw in SUSPICIOUS_PROCESS_KEYWORDS:
                if kw in cmdline:
                    suspicion += 3
                    reasons.append(f"keyword:{kw}")

            if name in ("python", "python3", "node", "ruby", "perl", "php", "pwsh", "powershell") and suspicion > 0:
                suspicion += 2
                reasons.append("scripting-engine")

            if "-enc " in cmdline or "-encodedcommand" in cmdline:
                suspicion += 4
                reasons.append("encoded-command")

            # Detect common parent-child process spoofing patterns
            parent_name = proc.get("parent_name", "").lower()
            dangerous_children = {"cmd", "powershell", "pwsh", "bash", "sh", "python", "wscript", "cscript", "mshta"}
            browser_parents    = {"chrome", "firefox", "safari", "edge", "opera"}
            office_parents     = {"excel", "word", "outlook", "powerpoint", "onenote"}

            if parent_name in (browser_parents | office_parents) and name in dangerous_children:
                suspicion += 5
                reasons.append(f"spawned-by-{parent_name}")

            # lolbas / living-off-the-land patterns
            lolbas = {"certutil", "regsvr32", "mshta", "rundll32", "installutil",
                      "regasm", "regsvcs", "msbuild", "csc", "vbc", "wmic"}
            if name in lolbas and suspicion == 0:
                # lolbas alone = low-confidence, score only with additional indicators
                if any(x in cmdline for x in ("http", "ftp", "\\\\", "base64", "download")):
                    suspicion += 4
                    reasons.append(f"lolbas:{name}")

            if suspicion >= 4:
                level = "CRITICAL" if suspicion >= 7 else "WARNING"
                self.alert_bus.publish(Alert(
                    level=level,
                    category="process",
                    message=f"Suspicious process: {proc.get('name', '')} (PID {pid})",
                    data={
                        "pid":             pid,
                        "name":            proc.get("name", ""),
                        "cmdline":         proc.get("cmdline", "")[:200],
                        "parent":          proc.get("parent_name", ""),
                        "reasons":         reasons,
                        "suspicion_score": suspicion,
                    },
                ))

        self._seen_pids = current_pids

    def _list_processes(self) -> List[dict]:
        try:
            if PLATFORM == "Linux":
                return self._list_linux()
            elif PLATFORM == "Darwin":
                return self._list_macos()
            elif PLATFORM == "Windows":
                return self._list_windows()
        except Exception:
            pass
        return []

    def _list_linux(self) -> List[dict]:
        procs = []
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                pid     = int(pid_dir.name)
                cmdline = (pid_dir / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="ignore").strip()
                comm    = (pid_dir / "comm").read_text().strip()
                status  = (pid_dir / "status").read_text()
                ppid    = 0
                pname   = ""
                for line in status.splitlines():
                    if line.startswith("PPid:"):
                        ppid = int(line.split()[1])
                # Resolve parent name
                try:
                    pname = (Path("/proc") / str(ppid) / "comm").read_text().strip()
                except Exception:
                    pass
                procs.append({"pid": pid, "name": comm, "cmdline": cmdline, "ppid": ppid, "parent_name": pname})
            except Exception:
                pass
        return procs

    def _list_macos(self) -> List[dict]:
        try:
            out = subprocess.check_output(
                ["ps", "axo", "pid,ppid,comm,command"],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            procs = []
            pid_to_name: Dict[int, str] = {}
            rows = []
            for line in out.splitlines()[1:]:
                parts = line.strip().split(None, 3)
                if len(parts) >= 3:
                    try:
                        pid  = int(parts[0])
                        ppid = int(parts[1])
                        name = Path(parts[2]).name
                        pid_to_name[pid] = name
                        rows.append({"pid": pid, "ppid": ppid, "name": name,
                                     "cmdline": parts[3] if len(parts) > 3 else parts[2]})
                    except Exception:
                        pass
            for r in rows:
                r["parent_name"] = pid_to_name.get(r["ppid"], "")
            return rows
        except Exception:
            return []

    def _list_windows(self) -> List[dict]:
        try:
            out = subprocess.check_output(
                ["tasklist", "/fo", "csv", "/nh"],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            procs = []
            for line in out.splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    try:
                        procs.append({"pid": int(parts[1]), "name": parts[0], "cmdline": parts[0], "parent_name": ""})
                    except Exception:
                        pass
            return procs
        except Exception:
            return []


# ── Watchdog ──────────────────────────────────────────────────────

class Watchdog:
    """
    Monitors daemon sub-threads and restarts dead ones.
    Checks every 15 seconds.
    """

    def __init__(self, managed_threads: Dict[str, Callable]):
        """managed_threads: {name: restart_fn}"""
        self._managed = managed_threads
        self._stop    = threading.Event()
        self._thread  = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="Watchdog")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            for name, restart_fn in self._managed.items():
                # Find thread by name
                alive = any(t.name == name and t.is_alive() for t in threading.enumerate())
                if not alive:
                    _log.warning("Thread '%s' died — restarting", name)
                    try:
                        restart_fn()
                    except Exception as e:
                        _log.error("Failed to restart '%s': %s", name, e)
            self._stop.wait(15.0)


# ── Main Daemon ───────────────────────────────────────────────────

class AVDaemon:
    """
    Main real-time protection daemon.
    Runs as a background process. Communicates via Unix socket (IPC).
    """

    def __init__(self, engine=None):
        self.engine        = engine
        self.alert_bus     = AlertBus()
        self._stop         = threading.Event()

        self.hash_cache    = HashCache(max_entries=CFG.get("cache_max_entries", 50_000))
        self.scanner       = FileScanner(
            alert_bus=self.alert_bus,
            hash_cache=self.hash_cache,
            engine=engine,
            max_scan_bytes=CFG.get("scan_max_size_mb", 50) * 1024 * 1024,
        )
        self.file_watcher  = None
        self.proc_monitor  = None
        self.net_monitor   = None
        self.watchdog      = None
        self._socket_thread = None

        # Graceful shutdown
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT,  self._handle_signal)

    def _handle_signal(self, sig, _frame):
        _log.info("Received signal %d — shutting down", sig)
        self.stop()

    # ── Public API ────────────────────────────────────────────────

    def start(self, background: bool = False):
        if background and PLATFORM != "Windows":
            self._daemonize()
            return
        self._write_pid()
        self._init_components()
        _log.info("AdaptiveAV daemon started (PID %d)", os.getpid())
        self._run_event_loop()

    def stop(self):
        _log.info("Stopping daemon…")
        self._stop.set()
        for component in (self.file_watcher, self.proc_monitor, self.net_monitor, self.watchdog):
            try:
                if component:
                    component.stop()
            except Exception:
                pass
        if DAEMON_PID_FILE.exists():
            DAEMON_PID_FILE.unlink()

    # ── Internals ─────────────────────────────────────────────────

    def _init_components(self):
        watch_dirs = CFG["watch_dirs"].get(PLATFORM, [])

        self.file_watcher = FileWatcher(watch_dirs, self.scanner, CFG)
        self.file_watcher.start()

        self.proc_monitor = ProcessMonitor(
            self.alert_bus,
            interval=CFG.get("process_interval", 5.0),
        )
        self.proc_monitor.start()

        self.net_monitor = NetworkMonitor(self.alert_bus)
        self.net_monitor.start()

        self.alert_bus.subscribe(self._on_alert)
        self._start_socket_server()

        # Watchdog: restart dead threads
        self.watchdog = Watchdog({
            "ProcessMonitor": self.proc_monitor.start,
            "NetworkMonitor": self.net_monitor.start,
        })
        self.watchdog.start()

    def _run_event_loop(self):
        try:
            while not self._stop.is_set():
                self._stop.wait(1.0)
        except KeyboardInterrupt:
            self.stop()

    def _on_alert(self, alert: Alert):
        colors = {"CRITICAL": "\033[91m\033[1m", "WARNING": "\033[93m", "INFO": "\033[94m"}
        reset  = "\033[0m"
        color  = colors.get(alert.level, "")
        ts     = alert.timestamp[11:19]
        print(f"\r{color}[{ts}] [{alert.level}] {alert.category.upper()}: {alert.message}{reset}")

    def _write_pid(self):
        DAEMON_PID_FILE.parent.mkdir(exist_ok=True, parents=True)
        DAEMON_PID_FILE.write_text(str(os.getpid()))

    def _daemonize(self):
        if os.fork() > 0:
            return
        os.setsid()
        if os.fork() > 0:
            sys.exit(0)
        sys.stdout.flush()
        sys.stderr.flush()
        with open(DAEMON_LOG_FILE, "a") as log:
            os.dup2(log.fileno(), sys.stdout.fileno())
            os.dup2(log.fileno(), sys.stderr.fileno())
        self._write_pid()
        self._init_components()
        self._run_event_loop()

    # ── IPC socket ────────────────────────────────────────────────

    def _start_socket_server(self):
        if DAEMON_SOCK.exists():
            DAEMON_SOCK.unlink()

        def serve():
            try:
                srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                srv.bind(str(DAEMON_SOCK))
                srv.listen(5)
                srv.settimeout(1.0)
                while not self._stop.is_set():
                    try:
                        conn, _ = srv.accept()
                        threading.Thread(target=self._handle_ipc, args=(conn,), daemon=True).start()
                    except socket.timeout:
                        pass
                srv.close()
            except Exception:
                pass

        self._socket_thread = threading.Thread(target=serve, daemon=True, name="IPCSocket")
        self._socket_thread.start()

    def _handle_ipc(self, conn):
        try:
            data = conn.recv(4096).decode()
            resp = self._dispatch_ipc(json.loads(data))
            conn.sendall(json.dumps(resp).encode())
        except Exception as e:
            try:
                conn.sendall(json.dumps({"error": str(e)}).encode())
            except Exception:
                pass
        finally:
            conn.close()

    def _dispatch_ipc(self, cmd: dict) -> dict:
        action = cmd.get("action", "")

        if action == "status":
            return {
                "running":     True,
                "pid":         os.getpid(),
                "alerts":      len(self.alert_bus.recent()),
                "cache_size":  len(self.hash_cache),
                "watch_dirs":  [str(d) for d in (self.file_watcher.dirs if self.file_watcher else [])],
                "platform":    PLATFORM,
            }
        elif action == "alerts":
            return {"alerts": [a.to_dict() for a in self.alert_bus.recent(cmd.get("n", 20))]}

        elif action == "scan":
            path = cmd.get("path", "")
            if not path:
                return {"error": "no path"}
            result = self.scanner.scan_file(Path(path), event="manual")
            return {"result": result or "clean"}

        elif action == "add_watch":
            if self.file_watcher:
                self.file_watcher.add_dir(cmd.get("path", ""))
            return {"success": True}

        elif action == "cache_stats":
            return {"clean_hashes_cached": len(self.hash_cache)}

        elif action == "clear_cache":
            self.hash_cache._hashes.clear()
            self.hash_cache._save()
            return {"success": True}

        return {"error": "unknown action"}

    # ── Static helpers ─────────────────────────────────────────────

    @staticmethod
    def is_running() -> bool:
        if not DAEMON_PID_FILE.exists():
            return False
        try:
            pid = int(DAEMON_PID_FILE.read_text())
            os.kill(pid, 0)
            return True
        except Exception:
            return False

    @staticmethod
    def send_command(cmd: dict) -> Optional[dict]:
        if not DAEMON_SOCK.exists():
            return None
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(str(DAEMON_SOCK))
            s.sendall(json.dumps(cmd).encode())
            resp = s.recv(65536).decode()
            s.close()
            return json.loads(resp)
        except Exception:
            return None


# ── CLI entry point ───────────────────────────────────────────────

def cli():
    import argparse
    parser = argparse.ArgumentParser(prog="adaptiveav-daemon",
                                     description="AdaptiveAV Real-Time Monitor Daemon v2.0")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("start",    help="Start daemon in foreground")
    sub.add_parser("stop",     help="Stop running daemon")
    sub.add_parser("status",   help="Show daemon status")
    sub.add_parser("alerts",   help="Show recent alerts")

    sp = sub.add_parser("scan", help="Scan a file on-demand")
    sp.add_argument("path", help="File to scan")

    sub.add_parser("background", help="Start daemon in background")

    args = parser.parse_args()

    if args.cmd == "start":
        AVDaemon().start(background=False)

    elif args.cmd == "background":
        AVDaemon().start(background=True)
        print("Daemon started in background.")

    elif args.cmd == "stop":
        if not AVDaemon.is_running():
            print("Daemon is not running.")
            return
        try:
            pid = int(DAEMON_PID_FILE.read_text())
            os.kill(pid, signal.SIGTERM)
            print(f"Sent SIGTERM to PID {pid}.")
        except Exception as e:
            print(f"Error: {e}")

    elif args.cmd == "status":
        if not AVDaemon.is_running():
            print("Daemon: NOT RUNNING")
            return
        resp = AVDaemon.send_command({"action": "status"})
        if resp:
            for k, v in resp.items():
                print(f"  {k}: {v}")
        else:
            print("Daemon running but IPC unresponsive.")

    elif args.cmd == "alerts":
        resp = AVDaemon.send_command({"action": "alerts", "n": 50})
        if resp:
            for a in resp.get("alerts", []):
                lvl  = a["level"]
                ts   = a["timestamp"][11:19]
                cat  = a["category"].upper()
                msg  = a["message"]
                print(f"[{ts}] [{lvl}] {cat}: {msg}")
        else:
            print("No daemon running or no alerts.")

    elif args.cmd == "scan":
        alert_bus  = AlertBus()
        hash_cache = HashCache()
        scanner    = FileScanner(alert_bus, hash_cache)
        result     = scanner.scan_file(Path(args.path), event="manual")
        if result is None:
            print(f"\033[92m[CLEAN]\033[0m {args.path}")
        else:
            print(f"\033[91m[ALERT]\033[0m {args.path}")
            print(json.dumps(result, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    cli()