


from __future__ import annotations

import contextlib
import gc
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import secrets
import shutil
import sqlite3
import stat
import tempfile
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Generator, Iterator, Optional, Sequence

# ---------------------------------------------------------------------------
# Optional integration with privacy_shield (same package)
# ---------------------------------------------------------------------------
try:
    from .privacy_shield import hash_target, hash_device_id  # type: ignore
    _SHIELD_AVAILABLE = True
except ImportError:
    _SHIELD_AVAILABLE = False

    def hash_target(s: str) -> str:  # type: ignore[misc]
        """Fallback HMAC when privacy_shield is not importable."""
        key = _module_hmac_key()
        return hmac.new(key, s.encode(), "sha256").hexdigest()

logger = logging.getLogger("adaptiveav.browser_scanner")

# ---------------------------------------------------------------------------
# Module-level HMAC key (fallback only — privacy_shield key is preferred)
# ---------------------------------------------------------------------------
_MODULE_KEY: Optional[bytes] = None
_MODULE_KEY_LOCK = threading.Lock()


def _module_hmac_key() -> bytes:
    """Return (or lazily create) a per-process HMAC key for the fallback hasher."""
    global _MODULE_KEY
    with _MODULE_KEY_LOCK:
        if _MODULE_KEY is None:
            _MODULE_KEY = secrets.token_bytes(32)
        return _MODULE_KEY


# ===========================================================================
# Enumerations and constants
# ===========================================================================

class Verdict(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    MALICIOUS_EXTENSION  = "malicious_extension"
    PHISHING_URL         = "phishing_url"
    MALICIOUS_DOWNLOAD   = "malicious_download"
    OBFUSCATED_JS        = "obfuscated_js"
    DATA_EXFIL_JS        = "data_exfil_js"
    SUSPICIOUS_DOMAIN    = "suspicious_domain"
    TYPOSQUAT            = "typosquat"
    IDN_HOMOGRAPH        = "idn_homograph"
    WEBSHELL             = "webshell"
    SUSPICIOUS_PROCESS   = "suspicious_process"


_SYS = platform.system()   # "Darwin" | "Linux" | "Windows"


# ---------------------------------------------------------------------------
# Browser profile paths
# ---------------------------------------------------------------------------
def _home() -> Path:
    return Path.home()


def _localappdata() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", ""))


def _appdata() -> Path:
    return Path(os.environ.get("APPDATA", ""))


BROWSER_PROFILES: dict[str, dict[str, Path]] = {
    "Chrome": {
        "Darwin":  _home() / "Library/Application Support/Google/Chrome",
        "Linux":   _home() / ".config/google-chrome",
        "Windows": _localappdata() / "Google/Chrome/User Data",
    },
    "Chromium": {
        "Darwin":  _home() / "Library/Application Support/Chromium",
        "Linux":   _home() / ".config/chromium",
        "Windows": _localappdata() / "Chromium/User Data",
    },
    "Brave": {
        "Darwin":  _home() / "Library/Application Support/BraveSoftware/Brave-Browser",
        "Linux":   _home() / ".config/BraveSoftware/Brave-Browser",
        "Windows": _localappdata() / "BraveSoftware/Brave-Browser",
    },
    "Edge": {
        "Darwin":  _home() / "Library/Application Support/Microsoft Edge",
        "Linux":   _home() / ".config/microsoft-edge",
        "Windows": _localappdata() / "Microsoft/Edge/User Data",
    },
    "Vivaldi": {
        "Darwin":  _home() / "Library/Application Support/Vivaldi",
        "Linux":   _home() / ".config/vivaldi",
        "Windows": _localappdata() / "Vivaldi/User Data",
    },
    "Opera": {
        "Darwin":  _home() / "Library/Application Support/com.operasoftware.Opera",
        "Linux":   _home() / ".config/opera",
        "Windows": _appdata() / "Opera Software/Opera Stable",
    },
    "Firefox": {
        "Darwin":  _home() / "Library/Application Support/Firefox",
        "Linux":   _home() / ".mozilla/firefox",
        "Windows": _appdata() / "Mozilla/Firefox",
    },
    "LibreWolf": {
        "Darwin":  _home() / "Library/Application Support/LibreWolf",
        "Linux":   _home() / ".librewolf",
        "Windows": _appdata() / "LibreWolf",
    },
    "Waterfox": {
        "Darwin":  _home() / "Library/Application Support/Waterfox",
        "Linux":   _home() / ".waterfox",
        "Windows": _appdata() / "Waterfox",
    },
}

BROWSER_DOWNLOAD_DIRS: dict[str, list[Path]] = {
    "Darwin":  [_home() / "Downloads"],
    "Linux":   [_home() / "Downloads", Path("/tmp")],
    "Windows": [_home() / "Downloads", _home() / "Desktop"],
}

# ===========================================================================
# Threat-intelligence patterns
# ===========================================================================

# --- Domain patterns (compiled once at import) ----------------------------
_RAW_DOMAIN_PATTERNS: list[tuple[str, str, int]] = [
    # (regex, pattern_id, base_risk)
    (r'^(?:[^.]+\.){0,3}(?:tk|ml|ga|cf|gq|pw|buzz|rest|fun|monster)$',
     "DOMAIN_FREE_TLD_ABUSE", 30),
    (r'(?:paypal|apple|microsoft|google|amazon|facebook|instagram|netflix)'
     r'[^.]*\.(?!com$|co\.uk$|co\.jp$)[a-z.]{4,}',
     "DOMAIN_BRAND_IMPERSONATION", 60),
    (r'(?:login|signin|account|verify|secure|update|confirm|reset|wallet|auth)'
     r'\.[^.]+\.(?:xyz|top|club|online|site|info|biz|live|shop|store)',
     "DOMAIN_AUTH_PHISH_COMBO", 70),
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\.(?:exe|dll|bat|ps1|vbs|sh)',
     "DOMAIN_IP_SERVED_EXEC", 90),
    (r'(?:paypai|paypa1|g00gle|g0ogle|amaz0n|m1crosoft|m1cros0ft|arnazon|linkedln)',
     "DOMAIN_TYPOSQUAT_KNOWN", 80),
    (r'xn--[a-z0-9-]{2,}',
     "DOMAIN_IDN_HOMOGRAPH", 50),
    (r'(?:[a-z0-9-]{30,})\.',
     "DOMAIN_VERY_LONG_LABEL", 20),
    (r'(?:[^.]+\.){6,}',
     "DOMAIN_EXCESSIVE_SUBDOMAINS", 25),
]

_DOMAIN_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(p, re.I), pid, risk)
    for p, pid, risk in _RAW_DOMAIN_PATTERNS
]

# --- URL path/query patterns -----------------------------------------------
_RAW_URL_PATH_PATTERNS: list[tuple[str, str, int]] = [
    (r'/(?:shell|c99|r57|b374k|wso|alfa|indoxploit|adminer)\.php',
     "URL_WEBSHELL_PATH", 95),
    (r'[?&](?:download|file|exec|cmd|run|payload)=',
     "URL_EXEC_QUERY_PARAM", 50),
    (r'\.(?:exe|dll|bat|cmd|ps1|vbs|hta|msi|jar)\?',
     "URL_EXEC_VIA_QUERY", 70),
    (r'data:text/html;base64',
     "URL_DATA_URI_HTML", 80),
    (r'javascript:',
     "URL_JAVASCRIPT_SCHEME", 85),
    (r'base64_decode|eval\(atob\(',
     "URL_OBFUSCATED_PAYLOAD", 90),
]

_URL_PATH_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(p, re.I), pid, risk)
    for p, pid, risk in _RAW_URL_PATH_PATTERNS
]

# Shorteners: flag only if combined with other indicators, not standalone
_SHORTENER_HOSTS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "buff.ly",
    "goo.gl", "cutt.ly", "rb.gy", "is.gd", "v.gd",
})

# --- Extension permissions -------------------------------------------------
DANGEROUS_PERMISSIONS = frozenset({
    "tabs", "webRequest", "webRequestBlocking", "cookies",
    "history", "management", "nativeMessaging", "<all_urls>",
    "browsingData", "privacy", "proxy", "contentSettings",
    "debugger", "declarativeNetRequest", "offscreen",
    "scripting", "downloads", "clipboardRead", "clipboardWrite",
})

# Permission combinations that together indicate high risk.
# Using frozensets so membership tests are O(1).
HIGH_RISK_PERMISSION_COMBOS: list[tuple[frozenset, int]] = [
    (frozenset({"tabs", "cookies", "<all_urls>"}),              60),
    (frozenset({"webRequest", "webRequestBlocking", "<all_urls>"}), 70),
    (frozenset({"nativeMessaging", "cookies"}),                 65),
    (frozenset({"history", "<all_urls>", "cookies"}),           70),
    (frozenset({"scripting", "<all_urls>", "cookies"}),         75),
    (frozenset({"debugger", "cookies"}),                        80),
    (frozenset({"downloads", "nativeMessaging"}),               60),
]

# --- JavaScript malware patterns -------------------------------------------
_RAW_JS_PATTERNS: list[tuple[str, str, int, ThreatCategory]] = [
    # (regex, pattern_id, risk, category)
    (r'eval\s*\(\s*atob\s*\(',
     "JS_BASE64_EVAL", 85, ThreatCategory.OBFUSCATED_JS),
    (r'eval\s*\(\s*unescape\s*\(',
     "JS_UNESCAPE_EVAL", 80, ThreatCategory.OBFUSCATED_JS),
    (r'eval\s*\(\s*(?:String\.fromCharCode|decodeURI(?:Component)?)\s*\(',
     "JS_ENCODED_EVAL", 80, ThreatCategory.OBFUSCATED_JS),
    (r'String\.fromCharCode\s*\([\d,\s]{60,}\)',
     "JS_CHARCODE_OBFUSCATION", 75, ThreatCategory.OBFUSCATED_JS),
    (r'\bexec\s*\(["\'].*?powershell',
     "JS_POWERSHELL_EXEC", 95, ThreatCategory.OBFUSCATED_JS),
    (r'document\.cookie\s*[=+].*?window\.location',
     "JS_COOKIE_THEFT_REDIRECT", 90, ThreatCategory.DATA_EXFIL_JS),
    (r'new\s+XMLHttpRequest\b.*?\.open\s*\(["\']POST',
     "JS_XHR_POST_EXFIL", 60, ThreatCategory.DATA_EXFIL_JS),
    (r'localStorage\s*\.\s*getItem\s*\(.*?\bfetch\b',
     "JS_LOCALSTORAGE_EXFIL", 70, ThreatCategory.DATA_EXFIL_JS),
    (r'navigator\.sendBeacon\s*\(',
     "JS_BEACON_EXFIL", 55, ThreatCategory.DATA_EXFIL_JS),
    (r'WebSocket\s*\(\s*["\']wss?://',
     "JS_WEBSOCKET_C2", 65, ThreatCategory.DATA_EXFIL_JS),
    (r'window\[(?:["\'][\\x][^"\']+["\']|\s*(?:atob|unescape)\s*\()',
     "JS_DYNAMIC_PROPERTY_OBFUSC", 80, ThreatCategory.OBFUSCATED_JS),
    (r'(?:document|window)\s*\[.*?\]\s*\(',
     "JS_ARRAY_NOTATION_CALL", 45, ThreatCategory.OBFUSCATED_JS),
    (r'crypto\.subtle\.',
     "JS_SUBTLE_CRYPTO", 35, ThreatCategory.OBFUSCATED_JS),
    (r'new\s+Function\s*\(',
     "JS_NEW_FUNCTION_CONSTRUCTOR", 70, ThreatCategory.OBFUSCATED_JS),
    (r'(?:setTimeout|setInterval)\s*\(\s*["\'][^"\']{50,}',
     "JS_TIMER_STRING_EXEC", 75, ThreatCategory.OBFUSCATED_JS),
    # Clipboard hijacking (common in crypto-theft extensions)
    (r'document\.addEventListener\s*\(\s*["\']copy["\']',
     "JS_CLIPBOARD_COPY_HIJACK", 70, ThreatCategory.DATA_EXFIL_JS),
    (r'clipboardData\.setData\s*\(',
     "JS_CLIPBOARD_SETDATA", 65, ThreatCategory.DATA_EXFIL_JS),
    # Cryptomining
    (r'(?:coinhive|cryptonight|stratum\+tcp|monero\.pool)',
     "JS_CRYPTOMINER", 90, ThreatCategory.SUSPICIOUS_DOMAIN),
]

_JS_PATTERNS: list[tuple[re.Pattern, str, int, ThreatCategory]] = [
    (re.compile(p, re.I | re.DOTALL), pid, risk, cat)
    for p, pid, risk, cat in _RAW_JS_PATTERNS
]

# Suspicious executable file suffixes for download scan
_EXEC_SUFFIXES = frozenset({
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".vbs", ".vbe", ".js", ".jse", ".jar", ".msi", ".msp",
    ".reg", ".scr", ".hta", ".com", ".pif", ".cpl",
    ".sh", ".run", ".bin", ".elf", ".deb", ".rpm",
    ".pkg", ".dmg",
})

# How to size-bucket downloads (preserves privacy, still useful for triage)
_SIZE_BUCKETS: list[tuple[int, str]] = [
    (1_024,           "<1 KB"),
    (10_240,          "1–10 KB"),
    (102_400,         "10–100 KB"),
    (1_048_576,       "100 KB–1 MB"),
    (10_485_760,      "1–10 MB"),
    (104_857_600,     "10–100 MB"),
    (10**18,          ">100 MB"),
]

_AGE_BUCKETS: list[tuple[float, str]] = [
    (3600,          "<1 hour"),
    (86_400,        "1–24 hours"),
    (7 * 86_400,    "1–7 days"),
    (30 * 86_400,   "7–30 days"),
    (10**18,        ">30 days"),
]


def _size_bucket(n: int) -> str:
    for threshold, label in _SIZE_BUCKETS:
        if n < threshold:
            return label
    return ">100 MB"


def _age_bucket(seconds: float) -> str:
    for threshold, label in _AGE_BUCKETS:
        if seconds < threshold:
            return label
    return ">30 days"


# ===========================================================================
# Data model
# ===========================================================================

@dataclass
class ThreatFinding:
    """
    A single privacy-safe threat finding.

    All user-identifying strings (URLs, file paths, extension names from user
    data) are stored as keyed HMAC hashes.  The only human-readable fields are
    verdicts, pattern IDs, risk scores, and bucketed metadata.
    """
    finding_id:   str                # 16-byte random hex — correlates log lines
    browser:      str                # "Chrome", "Firefox", etc.
    profile_hash: str                # HMAC of profile path — no plaintext path
    category:     ThreatCategory
    verdict:      Verdict
    risk_score:   int                # 0–100
    pattern_ids:  list[str]          # opaque identifiers referencing rules above
    # Extension fields (populated when category == MALICIOUS_EXTENSION)
    ext_id_hash:      str = ""       # HMAC of extension ID
    ext_perms_hash:   str = ""       # HMAC of sorted permissions string (for dedup)
    dangerous_perms:  list[str] = field(default_factory=list)  # perm names are fine
    # Download fields (populated when category == MALICIOUS_DOWNLOAD)
    file_suffix:   str = ""          # e.g. ".exe" — not identifying
    file_size_bucket: str = ""       # e.g. "1–10 MB"
    file_age_bucket:  str = ""       # e.g. "1–24 hours"
    # JS / URL fields — only hashes, never raw content
    target_hash:   str = ""          # HMAC of URL or domain
    # Scan metadata
    scan_time:     str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["verdict"]  = self.verdict.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))


@dataclass
class ProfileScanResult:
    """Aggregated findings for one browser + profile pair."""
    browser:         str
    profile_hash:    str        # HMAC — no plaintext path
    findings:        list[ThreatFinding] = field(default_factory=list)
    total_urls_checked:  int = 0
    total_exts_checked:  int = 0
    total_js_checked:    int = 0
    scan_time:       str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def threat_count(self) -> int:
        return len(self.findings)

    def summary(self) -> str:
        cats = defaultdict(int)
        for f in self.findings:
            cats[f.category.value] += 1
        cat_str = ", ".join(f"{v}:{c}" for v, c in sorted(cats.items()))
        return (
            f"[{self.browser}] threats={self.threat_count} "
            f"urls_checked={self.total_urls_checked} "
            f"exts_checked={self.total_exts_checked} "
            f"js_checked={self.total_js_checked} "
            f"({cat_str})"
        )


# ===========================================================================
# Privacy helpers
# ===========================================================================

def _hash(value: str) -> str:
    """
    Hash a privacy-sensitive string.

    Delegates to privacy_shield.hash_target() if available (uses the
    per-install Argon2-derived key).  Falls back to a per-process HMAC key
    so that no plaintext ever appears in results even without the full shield.
    """
    if _SHIELD_AVAILABLE:
        return hash_target(value)
    return hmac.new(_module_hmac_key(), value.encode(), "sha256").hexdigest()


def _new_finding_id() -> str:
    return secrets.token_hex(16)


# ===========================================================================
# SQLite helper — safe temp-copy approach
# ===========================================================================

@contextlib.contextmanager
def _safe_db_copy(db_path: Path) -> Iterator[Optional[sqlite3.Connection]]:
    """
    Copy *db_path* to a secure NamedTemporaryFile and yield a Connection.

    • The temp file is opened with O_CREAT|O_WRONLY|O_TRUNC; the original
      is never opened for writing.
    • The connection is closed and the temp file is unlinked in the
      finally block even if an exception is raised.
    • Yields None if the source does not exist or copy fails.
    """
    if not db_path.exists():
        yield None
        return

    fd, tmp_path_str = tempfile.mkstemp(suffix=".sqlite")
    tmp_path = Path(tmp_path_str)
    conn: Optional[sqlite3.Connection] = None
    try:
        os.close(fd)
        shutil.copy2(db_path, tmp_path)
        # Restrict temp file to owner read/write
        tmp_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        conn = sqlite3.connect(str(tmp_path), timeout=5)
        conn.row_factory = sqlite3.Row
        yield conn
    except Exception as exc:
        logger.debug("DB copy/open failed for %s: %s", db_path.name, exc)
        yield None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        with contextlib.suppress(Exception):
            tmp_path.unlink()


# ===========================================================================
# History cutoff helpers
# ===========================================================================

def _chromium_cutoff_microseconds(days: int = 30) -> int:
    """Chromium stores timestamps as microseconds since 1601-01-01."""
    epoch_delta_us = 11_644_473_600 * 1_000_000  # seconds between 1601 and 1970 in µs
    return int((time.time() - days * 86_400) * 1_000_000 + epoch_delta_us)


def _firefox_cutoff_microseconds(days: int = 30) -> int:
    """Firefox uses microseconds since Unix epoch."""
    return int((time.time() - days * 86_400) * 1_000_000)


# ===========================================================================
# Domain / URL analysis (stateless)
# ===========================================================================

def _analyze_domain(domain: str) -> tuple[list[str], int]:
    """
    Return (pattern_id_list, risk_score) for *domain*.
    The raw domain string is NOT included in the return value.
    """
    pattern_ids: list[str] = []
    risk = 0

    # Shortener standalone — low risk unless combined
    if domain in _SHORTENER_HOSTS:
        pattern_ids.append("DOMAIN_URL_SHORTENER")
        risk += 10

    for compiled, pid, base_risk in _DOMAIN_PATTERNS:
        if compiled.search(domain):
            pattern_ids.append(pid)
            risk += base_risk

    return pattern_ids, min(risk, 100)


def _analyze_url_path(url: str) -> tuple[list[str], int]:
    """
    Return (pattern_id_list, risk_score) for the path+query portion of *url*.
    The URL itself is NOT included in the return value.
    """
    pattern_ids: list[str] = []
    risk = 0
    for compiled, pid, base_risk in _URL_PATH_PATTERNS:
        if compiled.search(url):
            pattern_ids.append(pid)
            risk += base_risk
    return pattern_ids, min(risk, 100)


def _url_to_domain(url: str) -> str:
    """Extract lowercased domain from a URL.  Returns '' on failure."""
    m = re.match(r'https?://([^/?#\s]+)', url, re.I)
    return m.group(1).lower() if m else ""


def _analyze_full_url(url: str) -> tuple[list[str], int]:
    """Combine domain and path analysis.  No plaintext is retained."""
    if not url or not re.match(r'https?://', url, re.I):
        return [], 0

    domain = _url_to_domain(url)
    if not domain:
        return [], 0

    dom_ids, dom_risk = _analyze_domain(domain)
    path_ids, path_risk = _analyze_url_path(url)
    combined_ids = dom_ids + path_ids
    combined_risk = min(dom_risk + path_risk, 100)
    return combined_ids, combined_risk


# ===========================================================================
# JavaScript analysis (stateless)
# ===========================================================================

_MAX_JS_SCAN_BYTES = 1_000_000   # 1 MB — larger files skipped
_JS_MAGIC_BYTES = (b"<script", b"function(", b"eval(", b"=>", b"var ", b"const ",
                   b"let ", b"document.", b"window.")


def _looks_like_js(content: bytes) -> bool:
    """Heuristic: return True if *content* resembles JavaScript or HTML."""
    sample = content[:4096]
    return any(magic in sample for magic in _JS_MAGIC_BYTES)


def _scan_js_bytes(content: bytes) -> list[tuple[str, int, ThreatCategory]]:
    """
    Scan raw bytes for JS malware patterns.

    Returns list of (pattern_id, risk_score, category) tuples.
    No snippet of the original content is retained.
    """
    if len(content) > _MAX_JS_SCAN_BYTES:
        return []
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return []

    results: list[tuple[str, int, ThreatCategory]] = []
    for compiled, pid, risk, cat in _JS_PATTERNS:
        if compiled.search(text):
            results.append((pid, risk, cat))

    # Entropy check: high-entropy string literals suggest obfuscation.
    # We scan for long (>80 char) base64-ish strings.
    entropy_hits = len(re.findall(
        r'["\'][A-Za-z0-9+/=_\-]{80,}["\']', text
    ))
    if entropy_hits >= 3:
        results.append(("JS_HIGH_ENTROPY_STRINGS", 55, ThreatCategory.OBFUSCATED_JS))

    # Explicit reference to suspicious external host in JS
    if re.search(r'(fetch|XMLHttpRequest|sendBeacon|WebSocket)\s*\(.*?http', text, re.I):
        results.append(("JS_REMOTE_FETCH", 40, ThreatCategory.DATA_EXFIL_JS))

    del text  # explicitly release — GC might be delayed otherwise
    gc.collect()
    return results


# ===========================================================================
# Extension analysis (stateless)
# ===========================================================================

def _analyze_chromium_manifest(
    manifest: dict,
    ext_id: str,
) -> tuple[list[str], int, list[str]]:
    """
    Analyse a Chromium extension manifest.

    Returns (pattern_ids, risk_score, dangerous_perm_names).
    All identifying strings are hashed by the caller.
    """
    perms: set[str] = set(
        manifest.get("permissions", [])
        + manifest.get("host_permissions", [])
        + manifest.get("optional_permissions", [])
        + list(manifest.get("optional_host_permissions", []))
    )
    dangerous_found = sorted(perms & DANGEROUS_PERMISSIONS)
    risk = len(dangerous_found) * 8
    pattern_ids: list[str] = []

    if dangerous_found:
        pattern_ids.append("EXT_DANGEROUS_PERMS")

    for combo, combo_risk in HIGH_RISK_PERMISSION_COMBOS:
        if combo.issubset(perms):
            pattern_ids.append(f"EXT_COMBO_{'+'.join(sorted(combo))[:40]}")
            risk += combo_risk

    # CSP weaknesses
    csp = manifest.get("content_security_policy", "")
    if isinstance(csp, dict):
        csp = " ".join(csp.values())
    if "unsafe-eval" in csp:
        pattern_ids.append("EXT_CSP_UNSAFE_EVAL")
        risk += 25
    if "unsafe-inline" in csp:
        pattern_ids.append("EXT_CSP_UNSAFE_INLINE")
        risk += 15

    # Remote resources in manifest
    manifest_json = json.dumps(manifest)
    remote_non_google = re.findall(
        r'https?://(?!clients\d?\.google\.com|'
        r'update\.googleapis\.com|'
        r'chrome\.google\.com)[^\s"\']+',
        manifest_json,
    )
    if remote_non_google:
        pattern_ids.append("EXT_REMOTE_RESOURCE")
        risk += min(len(remote_non_google) * 10, 40)

    # Suspicious host patterns
    for url in remote_non_google:
        dom = _url_to_domain(url)
        if dom:
            _, dom_risk = _analyze_domain(dom)
            risk += dom_risk // 2  # halved — manifest presence is less definitive

    risk = min(risk, 100)
    return pattern_ids, risk, dangerous_found


def _analyze_firefox_addon(addon: dict) -> tuple[list[str], int, list[str]]:
    """Analyse a Firefox add-on entry from addons.json."""
    user_perms = addon.get("userPermissions", {})
    perms: set[str] = set(
        user_perms.get("permissions", [])
        + user_perms.get("origins", [])
    )
    dangerous_found = sorted(perms & DANGEROUS_PERMISSIONS)
    risk = len(dangerous_found) * 8
    pattern_ids: list[str] = []

    if dangerous_found:
        pattern_ids.append("EXT_DANGEROUS_PERMS")

    for combo, combo_risk in HIGH_RISK_PERMISSION_COMBOS:
        if combo.issubset(perms):
            pattern_ids.append(f"EXT_COMBO_{'+'.join(sorted(combo))[:40]}")
            risk += combo_risk

    return pattern_ids, min(risk, 100), dangerous_found


# ===========================================================================
# BrowserScanner
# ===========================================================================

class BrowserScanner:
    """
    Scans all detected browsers for threats, entirely offline.

    Usage
    -----
        scanner = BrowserScanner()
        results = scanner.scan_all()          # list[ProfileScanResult]
        downloads = scanner.scan_downloads()  # list[ThreatFinding]

    Privacy guarantees:
      • Every ThreatFinding contains only HMAC hashes for user-identifying
        strings; no plaintext URLs, domains, paths, or filenames.
      • DB temp copies are cleaned up in finally-blocks.
      • JS content is scanned in-memory and immediately discarded.
    """

    def __init__(
        self,
        max_history_days: int = 30,
        max_history_rows: int = 5000,
        max_js_per_profile: int = 500,
        parallel_profiles: int = 4,
    ) -> None:
        self.max_history_days  = max_history_days
        self.max_history_rows  = max_history_rows
        self.max_js_per_profile = max_js_per_profile
        self.parallel_profiles = parallel_profiles

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_all(self) -> list[ProfileScanResult]:
        """
        Scan all detected browsers in parallel.

        Returns a list of ProfileScanResult, one per detected profile.
        Empty results are excluded.
        """
        tasks: list[tuple[str, Path]] = []
        for browser, paths in BROWSER_PROFILES.items():
            profile_root = paths.get(_SYS)
            if profile_root and profile_root.exists():
                tasks.append((browser, profile_root))

        if not tasks:
            logger.info("No browser profile directories found on this system.")
            return []

        results: list[ProfileScanResult] = []
        with ThreadPoolExecutor(max_workers=self.parallel_profiles,
                                thread_name_prefix="av_browser") as pool:
            futures = {
                pool.submit(self._scan_browser_safe, browser, root): (browser, root)
                for browser, root in tasks
            }
            for future in as_completed(futures):
                browser, root = futures[future]
                try:
                    for r in future.result():
                        results.append(r)
                except Exception as exc:
                    logger.warning("Browser scan failed for %s: %s", browser, exc)

        return results

    def scan_downloads(self) -> list[ThreatFinding]:
        """
        Scan download directories for recently-created executable files.

        Only file extension, size bucket, and age bucket are recorded.
        File paths and names are NEVER stored.
        """
        findings: list[ThreatFinding] = []
        dirs = BROWSER_DOWNLOAD_DIRS.get(_SYS, [])
        now = time.time()

        for dl_dir in dirs:
            if not dl_dir.exists():
                continue
            try:
                entries = list(dl_dir.iterdir())
            except PermissionError:
                continue

            for f in entries:
                if not f.is_file():
                    continue
                suffix = f.suffix.lower()
                if suffix not in _EXEC_SUFFIXES:
                    continue
                try:
                    st = f.stat()
                except OSError:
                    continue

                age_s = now - st.st_mtime
                if age_s > 30 * 86_400:   # only flag files < 30 days old
                    continue

                risk = 40
                pattern_ids = ["DL_EXEC_SUFFIX"]
                # Very new large executables are higher risk
                if age_s < 3600 and st.st_size > 1_048_576:
                    risk = 70
                    pattern_ids.append("DL_LARGE_RECENT_EXEC")

                findings.append(ThreatFinding(
                    finding_id   = _new_finding_id(),
                    browser      = "downloads",
                    profile_hash = _hash(str(dl_dir)),
                    category     = ThreatCategory.MALICIOUS_DOWNLOAD,
                    verdict      = _risk_to_verdict(risk),
                    risk_score   = risk,
                    pattern_ids  = pattern_ids,
                    file_suffix  = suffix,
                    file_size_bucket = _size_bucket(st.st_size),
                    file_age_bucket  = _age_bucket(age_s),
                ))
        return findings

    # ------------------------------------------------------------------
    # Internal — browser dispatch
    # ------------------------------------------------------------------

    def _scan_browser_safe(
        self, browser: str, profile_root: Path
    ) -> list[ProfileScanResult]:
        try:
            if browser in ("Firefox", "LibreWolf", "Waterfox"):
                return list(self._scan_firefox_family(browser, profile_root))
            else:
                return list(self._scan_chromium_family(browser, profile_root))
        except Exception as exc:
            logger.warning("Unhandled error scanning %s: %s", browser, exc)
            return []

    # ------------------------------------------------------------------
    # Chromium family
    # ------------------------------------------------------------------

    def _scan_chromium_family(
        self, browser: str, profile_root: Path
    ) -> Generator[ProfileScanResult, None, None]:
        for prof_name, prof_path in self._find_chromium_profiles(profile_root):
            result = ProfileScanResult(
                browser=browser,
                profile_hash=_hash(str(prof_path)),
            )
            self._chromium_extensions(result, prof_path / "Extensions")
            self._chromium_history(result, prof_path / "History")
            self._chromium_cache_js(result, prof_path)
            if result.threat_count or result.total_urls_checked:
                yield result

    def _find_chromium_profiles(self, root: Path) -> list[tuple[str, Path]]:
        profiles: list[tuple[str, Path]] = []
        default = root / "Default"
        if default.exists():
            profiles.append(("Default", default))
        for p in sorted(root.glob("Profile *")):
            profiles.append((p.name, p))
        if not profiles and root.exists():
            profiles.append(("Default", root))
        return profiles

    def _chromium_extensions(
        self, result: ProfileScanResult, ext_dir: Path
    ) -> None:
        if not ext_dir.exists():
            return

        for ext_id_dir in ext_dir.iterdir():
            if not ext_id_dir.is_dir():
                continue
            for ver_dir in ext_id_dir.iterdir():
                manifest_path = ver_dir / "manifest.json"
                if not manifest_path.exists():
                    continue
                result.total_exts_checked += 1
                try:
                    with manifest_path.open(encoding="utf-8", errors="ignore") as fh:
                        manifest = json.load(fh)
                except Exception:
                    continue

                pattern_ids, risk, dangerous_perms = _analyze_chromium_manifest(
                    manifest, ext_id_dir.name
                )
                if risk >= 35:
                    result.findings.append(ThreatFinding(
                        finding_id    = _new_finding_id(),
                        browser       = result.browser,
                        profile_hash  = result.profile_hash,
                        category      = ThreatCategory.MALICIOUS_EXTENSION,
                        verdict       = _risk_to_verdict(risk),
                        risk_score    = risk,
                        pattern_ids   = pattern_ids,
                        ext_id_hash   = _hash(ext_id_dir.name),
                        ext_perms_hash= _hash(",".join(sorted(dangerous_perms))),
                        dangerous_perms = dangerous_perms,
                    ))

                # Scan JS within the extension
                for js_file in ver_dir.rglob("*.js"):
                    self._process_js_file(result, js_file)

    def _chromium_history(
        self, result: ProfileScanResult, history_db: Path
    ) -> None:
        cutoff = _chromium_cutoff_microseconds(self.max_history_days)
        with _safe_db_copy(history_db) as conn:
            if conn is None:
                return
            try:
                rows = conn.execute(
                    "SELECT url FROM urls "
                    "WHERE last_visit_time > ? "
                    "LIMIT ?",
                    (cutoff, self.max_history_rows),
                ).fetchall()
            except sqlite3.Error as exc:
                logger.debug("Chromium history query failed: %s", exc)
                return

        for row in rows:
            url: str = row[0] or ""
            result.total_urls_checked += 1
            finding = self._finding_from_url(url, result.browser, result.profile_hash)
            if finding:
                result.findings.append(finding)

    def _chromium_cache_js(
        self, result: ProfileScanResult, profile_path: Path
    ) -> None:
        cache_dirs = [profile_path / "Cache", profile_path / "Code Cache"]
        scanned = 0
        for cache_dir in cache_dirs:
            if not cache_dir.exists() or scanned >= self.max_js_per_profile:
                continue
            for f in cache_dir.rglob("*"):
                if scanned >= self.max_js_per_profile:
                    break
                if not f.is_file():
                    continue
                try:
                    sz = f.stat().st_size
                except OSError:
                    continue
                if sz == 0 or sz > _MAX_JS_SCAN_BYTES:
                    continue
                try:
                    content = f.read_bytes()
                except OSError:
                    continue
                if not _looks_like_js(content):
                    del content
                    continue
                hits = _scan_js_bytes(content)
                del content
                result.total_js_checked += 1
                scanned += 1
                for pid, risk, cat in hits:
                    result.findings.append(ThreatFinding(
                        finding_id   = _new_finding_id(),
                        browser      = result.browser,
                        profile_hash = result.profile_hash,
                        category     = cat,
                        verdict      = _risk_to_verdict(risk),
                        risk_score   = risk,
                        pattern_ids  = [pid],
                        target_hash  = _hash(str(f.name)),
                    ))

    # ------------------------------------------------------------------
    # Firefox family
    # ------------------------------------------------------------------

    def _scan_firefox_family(
        self, browser: str, profile_root: Path
    ) -> Generator[ProfileScanResult, None, None]:
        profiles_ini = profile_root / "profiles.ini"
        if not profiles_ini.exists():
            return
        try:
            raw = profiles_ini.read_text(errors="ignore")
            rel_paths = re.findall(r'^Path=(.+)', raw, re.MULTILINE)
        except Exception:
            return

        for rel in rel_paths:
            prof_path = (
                Path(rel) if rel.startswith("/") else profile_root / rel.strip()
            )
            if not prof_path.exists():
                continue
            result = ProfileScanResult(
                browser=browser,
                profile_hash=_hash(str(prof_path)),
            )
            self._firefox_addons(result, prof_path)
            self._firefox_history(result, prof_path / "places.sqlite")
            if result.threat_count or result.total_urls_checked:
                yield result

    def _firefox_addons(
        self, result: ProfileScanResult, prof_path: Path
    ) -> None:
        addons_json = prof_path / "addons.json"
        if not addons_json.exists():
            return
        try:
            with addons_json.open(encoding="utf-8", errors="ignore") as fh:
                data = json.load(fh)
        except Exception:
            return

        for addon in data.get("addons", []):
            result.total_exts_checked += 1
            pattern_ids, risk, dangerous_perms = _analyze_firefox_addon(addon)
            if risk >= 35:
                result.findings.append(ThreatFinding(
                    finding_id   = _new_finding_id(),
                    browser      = result.browser,
                    profile_hash = result.profile_hash,
                    category     = ThreatCategory.MALICIOUS_EXTENSION,
                    verdict      = _risk_to_verdict(risk),
                    risk_score   = risk,
                    pattern_ids  = pattern_ids,
                    ext_id_hash  = _hash(addon.get("id", "")),
                    ext_perms_hash = _hash(",".join(sorted(dangerous_perms))),
                    dangerous_perms = dangerous_perms,
                ))

    def _firefox_history(
        self, result: ProfileScanResult, places_db: Path
    ) -> None:
        cutoff = _firefox_cutoff_microseconds(self.max_history_days)
        with _safe_db_copy(places_db) as conn:
            if conn is None:
                return
            try:
                rows = conn.execute(
                    "SELECT p.url "
                    "FROM moz_places p "
                    "JOIN moz_historyvisits h ON p.id = h.place_id "
                    "WHERE h.visit_date > ? "
                    "LIMIT ?",
                    (cutoff, self.max_history_rows),
                ).fetchall()
            except sqlite3.Error as exc:
                logger.debug("Firefox history query failed: %s", exc)
                return

        for row in rows:
            url: str = row[0] or ""
            result.total_urls_checked += 1
            finding = self._finding_from_url(url, result.browser, result.profile_hash)
            if finding:
                result.findings.append(finding)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _finding_from_url(
        self, url: str, browser: str, profile_hash: str
    ) -> Optional[ThreatFinding]:
        """
        Analyse a URL and, if suspicious, return a ThreatFinding.

        The raw URL is hashed immediately; it is never stored anywhere else.
        """
        pattern_ids, risk = _analyze_full_url(url)
        if risk < 20 or not pattern_ids:
            return None

        # Determine the most specific category from pattern IDs
        if any(pid.startswith("JS_") for pid in pattern_ids):
            cat = ThreatCategory.OBFUSCATED_JS
        elif "IDN_HOMOGRAPH" in " ".join(pattern_ids):
            cat = ThreatCategory.IDN_HOMOGRAPH
        elif any("TYPO" in pid for pid in pattern_ids):
            cat = ThreatCategory.TYPOSQUAT
        elif any("PHISH" in pid or "BRAND" in pid for pid in pattern_ids):
            cat = ThreatCategory.PHISHING_URL
        else:
            cat = ThreatCategory.SUSPICIOUS_DOMAIN

        return ThreatFinding(
            finding_id   = _new_finding_id(),
            browser      = browser,
            profile_hash = profile_hash,
            category     = cat,
            verdict      = _risk_to_verdict(risk),
            risk_score   = risk,
            pattern_ids  = pattern_ids,
            target_hash  = _hash(url),   # one-way hash; original URL discarded
        )

    def _process_js_file(
        self, result: ProfileScanResult, js_path: Path
    ) -> None:
        """Scan a JS file for malware patterns; store only hashes."""
        if result.total_js_checked >= self.max_js_per_profile:
            return
        try:
            sz = js_path.stat().st_size
        except OSError:
            return
        if sz == 0 or sz > _MAX_JS_SCAN_BYTES:
            return
        try:
            content = js_path.read_bytes()
        except OSError:
            return
        hits = _scan_js_bytes(content)
        del content
        result.total_js_checked += 1
        for pid, risk, cat in hits:
            result.findings.append(ThreatFinding(
                finding_id   = _new_finding_id(),
                browser      = result.browser,
                profile_hash = result.profile_hash,
                category     = cat,
                verdict      = _risk_to_verdict(risk),
                risk_score   = risk,
                pattern_ids  = [pid],
                target_hash  = _hash(js_path.name),
            ))


# ===========================================================================
# Utility
# ===========================================================================

def _risk_to_verdict(risk: int) -> Verdict:
    if risk >= 80:
        return Verdict.CRITICAL
    if risk >= 60:
        return Verdict.HIGH
    if risk >= 35:
        return Verdict.MEDIUM
    return Verdict.LOW


# ===========================================================================
# Privacy-safe report serialisation
# ===========================================================================

def export_findings(
    results: Sequence[ProfileScanResult],
    download_findings: Optional[Sequence[ThreatFinding]] = None,
) -> str:
    """
    Serialise all findings to a compact, privacy-safe JSON string.

    The output contains only hashes, verdicts, and pattern IDs — never any
    plaintext URL, domain, file path, or user identifier.
    """
    all_findings: list[dict] = []
    for r in results:
        for f in r.findings:
            all_findings.append(f.to_dict())
    for f in (download_findings or []):
        all_findings.append(f.to_dict())

    return json.dumps(
        {
            "schema_version": "2.0",
            "exported_at":    datetime.now(timezone.utc).isoformat(),
            "finding_count":  len(all_findings),
            "findings":       all_findings,
        },
        separators=(",", ":"),
    )


# ===========================================================================
# Self-test / example
# ===========================================================================

def _run_example() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    scanner = BrowserScanner(max_history_days=7, max_js_per_profile=50)

    print("\n=== Scanning all browsers ===")
    results = scanner.scan_all()
    for r in results:
        print(" ", r.summary())

    print("\n=== Scanning downloads ===")
    dl_findings = scanner.scan_downloads()
    print(f"  Download threats found: {len(dl_findings)}")

    print("\n=== Privacy-safe JSON export (first 500 chars) ===")
    report = export_findings(results, dl_findings)
    print(report[:500] + ("..." if len(report) > 500 else ""))

    print("\n=== URL analysis self-test (no plaintext output) ===")
    test_urls = [
        "https://paypaI.com/login?reset=1",              # brand impersonation
        "https://secure.login.verify.xyz/account",       # auth phish combo
        "https://normal-bank.com/dashboard",             # benign
        "https://192.168.1.5/payload.exe?run=1",         # IP served exec
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ]
    for url in test_urls:
        pids, risk = _analyze_full_url(url)
        url_hash = _hash(url)
        print(f"  hash={url_hash[:16]}…  risk={risk:3d}  patterns={pids}")


if __name__ == "__main__":
    _run_example()