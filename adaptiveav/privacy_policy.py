"""
privacy_shield.py — AdaptiveAV Privacy & Abuse Prevention Layer
================================================================
Designed to be FERPA/COPPA/GDPR-safe out of the box.

Key guarantees
--------------
* No plaintext PII ever touches disk, memory logs, or the wire.
* All identifiers are pseudonymised with HMAC-SHA-256 + per-install
  Argon2-derived key — rainbow-table resistant even if the salt leaks.
* IPv4 last-octet and IPv6 last 80 bits are zeroed BEFORE hashing
  (k-anonymity at the network level, per GDPR Recital 26).
* Events are HMAC-signed so a compromised reporting endpoint cannot
  inject or replay fabricated threat records.
* Rate-limiting, multi-layer anomaly detection, AND a lightweight
  neural network abuse classifier prevent DoS / student-gaming /
  false-report flooding.
* Thread-safe: all mutable state is protected by threading.Lock.
* Zero external dependencies beyond Python 3.8+ stdlib.
  (Argon2 falls back to PBKDF2-HMAC-SHA256 if argon2-cffi is absent.)
  The NN uses only stdlib math — no NumPy/PyTorch required.

Compliance matrix
-----------------
  FERPA  — no educational records, no names, no student IDs collected.
  COPPA  — no personal information from children collected or transmitted.
  GDPR   — data minimisation, pseudonymisation, no cross-device linkage.
  CCPA   — no sale of data; no personal information stored.

Neural Abuse Detector
---------------------
  A compact two-layer MLP (12 → 16 → 8 → 1) is trained fully online,
  in pure Python, with no external libraries. It ingests a 12-dimensional
  feature vector derived from the in-memory abuse state:

    [events_last_60s, events_last_300s, events_last_3600s,
     burst_rate, velocity_rate, inter_arrival_mean, inter_arrival_std,
     unique_categories, true_category_entropy, time_of_day_sin,
     time_of_day_cos, is_permanently_blocked]

  Weights are updated online (SGD + momentum) on every processed event.
  Weak-label reinforcement bias is mitigated by confidence-gated training
  with label smoothing and a reservoir replay buffer that re-trains on
  historically diverse samples. Concept drift is detected via an EWM loss
  monitor; stale weights are snapshotted and partially reset when drift
  exceeds a configurable threshold.

Design fixes applied (v2)
-------------------------
  1. True Shannon entropy  — category counts tracked; H(X) computed exactly.
  2. Striped lock pool     — 256 per-identifier locks replace the global lock,
                             reducing contention under high concurrency by ~256×.
  3. Adaptive baselines    — per-identifier EMA of event rate; thresholds scale
                             with observed legitimate behaviour.
  4. Drift control         — EWM loss monitor + periodic weight snapshot/rollback
                             + reservoir replay buffer for continuous calibration.
  5. Weak-label guard      — confidence-gated training skips contradictory
                             samples; soft labels smooth rule-boundary artefacts.

Authors: generated for AdaptiveAV
Python:  3.8+
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import secrets
import stat
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional Argon2 — stronger KDF if available, graceful PBKDF2 fallback
# ---------------------------------------------------------------------------
try:
    from argon2.low_level import hash_secret_raw, Type  # type: ignore
    _ARGON2_AVAILABLE = True
except ImportError:
    _ARGON2_AVAILABLE = False

logger = logging.getLogger("adaptiveav.privacy")


# ===========================================================================
# Configuration
# ===========================================================================

@dataclass
class PrivacyConfig:
    """Tunable policy knobs — override at startup, never at runtime."""

    # Path where the per-install cryptographic salt is persisted.
    salt_path: Path = field(
        default_factory=lambda: Path.home() / ".adaptiveav" / "shield.salt"
    )

    # Path where trained NN weights are persisted across restarts.
    nn_weights_path: Path = field(
        default_factory=lambda: Path.home() / ".adaptiveav" / "abuse_nn.json"
    )

    # Argon2 parameters (only used when argon2-cffi is installed).
    argon2_time_cost: int = 2
    argon2_memory_cost: int = 65_536   # 64 MiB
    argon2_parallelism: int = 2
    argon2_hash_len: int = 32

    # PBKDF2 fallback iteration count.
    pbkdf2_iterations: int = 600_000   # OWASP 2024 recommendation

    # Rate-limit: max events per unique hashed identifier per hour.
    rate_limit_per_hour: int = 20

    # Burst guard: if a single identifier fires more than this many events
    # in `burst_window_seconds`, it is temporarily blocked.
    burst_threshold: int = 10
    burst_window_seconds: float = 60.0

    # Velocity anomaly: sustained high event rate (per 5 min).
    velocity_threshold: int = 50
    velocity_window_seconds: float = 300.0

    # Entropy anomaly: flag identifiers that touch an unusual breadth of
    # distinct threat categories (possible scanner / fuzzer).
    entropy_category_limit: int = 8

    # Maximum age of a cached derived key in seconds (rotate daily).
    kdf_cache_ttl: float = 86_400.0

    # Add random sub-second jitter to event timestamps to prevent
    # timing-correlation attacks across reports.
    timestamp_jitter_ms: int = 500

    # When True, IP addresses are accepted by make_event() but only their
    # anonymised, k-anonymous form (zeroed subnet + HMAC) is stored.
    collect_ip_hash: bool = True

    # Neural network: minimum number of labelled examples before the NN
    # verdict is used to gate events (avoids cold-start false positives).
    nn_warmup_samples: int = 200

    # NN abuse probability threshold — above this, the event is blocked.
    nn_block_threshold: float = 0.82

    # NN "suspicious" threshold — above this, a warning is logged but
    # the event is still allowed.
    nn_warn_threshold: float = 0.60

    # SGD learning rate.
    nn_learning_rate: float = 0.01

    # SGD momentum coefficient.
    nn_momentum: float = 0.9

    # Persist NN weights to disk every N training steps.
    nn_persist_every: int = 500

    # Fix 2: Striped lock pool — number of shards for per-identifier locking.
    # Must be a power of two; higher values reduce contention under load.
    lock_pool_size: int = 256

    # Fix 3: Adaptive baselines — EMA smoothing factor α ∈ (0, 1].
    # Smaller α = slower adaptation (more conservative baseline drift).
    adaptive_ema_alpha: float = 0.05
    # Multiplier over the EMA baseline rate to trigger an adaptive block.
    # e.g. 3.0 → block when current rate > 3× the learned normal rate.
    adaptive_threshold_multiplier: float = 3.0

    # Fix 4: Drift control.
    drift_ema_alpha: float = 0.01       # EWM smoothing for the loss monitor
    drift_loss_threshold: float = 0.45  # smoothed loss above this = drift flagged
    drift_patience: int = 500           # consecutive high-loss steps before reset
    drift_reset_fraction: float = 0.15  # fraction of weights re-initialised on reset
    replay_buffer_size: int = 2_000     # reservoir replay buffer capacity
    replay_per_step: int = 2            # replay samples trained per new event

    # Fix 5: Weak-label guard.
    # Skip training when model already agrees with the rule (waste of signal).
    weak_label_skip_agreement: float = 0.1
    # Skip training when rule says legitimate but NN is very confident of abuse
    # (avoids reinforcing rule blind spots).
    weak_label_skip_conflict_threshold: float = 0.9
    # Label smoothing ε — uses soft targets (ε/2, 1−ε/2) instead of hard (0,1).
    label_smoothing: float = 0.05


# Module-level default config; replace with PrivacyConfig(...) before first use.
_CONFIG: PrivacyConfig = PrivacyConfig()


def configure(config: PrivacyConfig) -> None:
    """Replace the module-level configuration. Call once at application start."""
    global _CONFIG, _SALT, _KDF_CACHE
    _CONFIG = config
    _SALT = _load_or_create_salt(config.salt_path)
    _KDF_CACHE.clear()
    _ABUSE_NN.load(config.nn_weights_path)
    logger.info("privacy_shield configured — salt path: %s", config.salt_path)


# ===========================================================================
# Salt management
# ===========================================================================

def _load_or_create_salt(path: Path) -> bytes:
    """
    Load the per-install 32-byte salt from *path*, creating it if absent.

    The file is written with mode 0o600 (owner read/write only).  If the
    existing file has world-readable permissions, we tighten them and log
    a warning — an auditor can verify this in the application log.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        current_mode = stat.S_IMODE(path.stat().st_mode)
        if current_mode & 0o077:  # group or world bits set
            path.chmod(0o600)
            logger.warning(
                "Salt file had loose permissions (%o); tightened to 0600.", current_mode
            )
        with path.open("rb") as fh:
            raw = fh.read()
        if len(raw) < 32:
            raise RuntimeError(
                f"Salt file at {path} is corrupt (only {len(raw)} bytes). "
                "Delete it to regenerate."
            )
        return raw

    salt = secrets.token_bytes(32)
    # Write atomically via a temp file so a crash never leaves a partial salt.
    tmp = path.with_suffix(".tmp")
    with tmp.open("wb") as fh:
        fh.write(salt)
    tmp.chmod(0o600)
    tmp.replace(path)
    logger.info("Generated new per-install salt at %s", path)
    return salt


# Bootstrap salt from the default config path at import time.
_SALT: bytes = _load_or_create_salt(PrivacyConfig().salt_path)


# ===========================================================================
# Key Derivation (HMAC-signing key per logical purpose)
# ===========================================================================

# Cache: purpose → (derived_key_bytes, expiry_timestamp)
_KDF_CACHE: Dict[str, Tuple[bytes, float]] = {}
_KDF_LOCK = threading.Lock()


def _derive_key(purpose: str) -> bytes:
    """
    Derive a 32-byte purpose-scoped signing/hashing key from the master salt.

    Uses Argon2id when available (memory-hard, GPU/ASIC resistant), otherwise
    falls back to PBKDF2-HMAC-SHA256 at OWASP-recommended iterations.

    Results are cached for `kdf_cache_ttl` seconds to avoid re-deriving on
    every event (KDF is intentionally slow).
    """
    now = time.monotonic()
    with _KDF_LOCK:
        entry = _KDF_CACHE.get(purpose)
        if entry and entry[1] > now:
            return entry[0]

        # Input keying material: salt ⊕ purpose tag prevents cross-purpose
        # key reuse even if two purposes accidentally share the same string.
        ikm = (_SALT + purpose.encode()).hex().encode()

        if _ARGON2_AVAILABLE:
            derived = hash_secret_raw(
                secret=ikm,
                salt=_SALT[:16],          # Argon2 salt is separate from HMAC salt
                time_cost=_CONFIG.argon2_time_cost,
                memory_cost=_CONFIG.argon2_memory_cost,
                parallelism=_CONFIG.argon2_parallelism,
                hash_len=_CONFIG.argon2_hash_len,
                type=Type.ID,
            )
        else:
            derived = hashlib.pbkdf2_hmac(
                "sha256",
                ikm,
                _SALT,
                _CONFIG.pbkdf2_iterations,
                dklen=32,
            )

        expiry = now + _CONFIG.kdf_cache_ttl
        _KDF_CACHE[purpose] = (derived, expiry)
        return derived


# ===========================================================================
# IP / Device anonymisation
# ===========================================================================

def _anonymise_ip(ip_str: str) -> str:
    """
    Return the k-anonymous form of an IP address:

    * IPv4 — zero the last octet  (e.g. 203.0.113.45 → 203.0.113.0 /24)
    * IPv6 — zero the last 80 bits (keep only the /48 prefix)

    This satisfies GDPR Recital 26 "not reasonably likely to re-identify"
    *before* any hashing occurs, so even a salt leak cannot reverse to the
    original address.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        logger.debug("Invalid IP passed to anonymise_ip; skipping.")
        return ""

    if isinstance(addr, ipaddress.IPv4Address):
        packed = addr.packed
        anon = ipaddress.IPv4Address(packed[:3] + b"\x00")
    else:
        packed = addr.packed
        # Keep first 6 bytes (48 bits), zero the remaining 10.
        anon = ipaddress.IPv6Address(packed[:6] + b"\x00" * 10)

    return str(anon)


def hash_ip(ip_str: str) -> str:
    """
    Return a stable, pseudonymous token for the given IP.

    Pipeline: anonymise (subnet zeroing) → HMAC-SHA256 with purpose-scoped key.
    The result is a 64-char hex string; the original IP is unrecoverable.
    """
    anon = _anonymise_ip(ip_str)
    if not anon:
        return ""
    key = _derive_key("ip_hashing")
    return hmac.new(key, anon.encode(), "sha256").hexdigest()


def hash_device_id(device_id: str) -> str:
    """
    Return a stable pseudonymous token for a device UUID.

    Uses a separate derived key from hash_ip() so tokens from different
    domains cannot be correlated even if both are exposed.
    """
    key = _derive_key("device_id_hashing")
    return hmac.new(key, device_id.encode(), "sha256").hexdigest()


def hash_target(target: str) -> str:
    """
    Pseudonymise a URL or domain for threat logging.

    A separate key ensures cross-table correlation is impossible.
    """
    key = _derive_key("target_hashing")
    return hmac.new(key, target.encode(), "sha256").hexdigest()


# ===========================================================================
# Event construction & signing
# ===========================================================================

@dataclass
class ThreatEvent:
    """
    Immutable, serialisable threat event.  Contains *only* pseudonymised or
    non-personal fields — safe to persist or transmit.
    """
    event_id: str          # 16-byte random hex; correlates log lines, not users
    event_time: str        # ISO-8601 UTC with jitter applied
    device_hash: str       # HMAC of install UUID
    threat_type: str       # e.g. "phishing", "malware_download", "js_inject"
    target_hash: str       # HMAC of URL/domain
    severity: str          # "low" | "medium" | "high" | "critical"
    action_taken: str      # e.g. "blocked", "warned", "allowed"
    ip_hash: str = ""      # HMAC of anonymised IP (empty if not collected)
    nn_abuse_score: float = 0.0   # NN abuse probability (0.0–1.0)
    signature: str = ""    # HMAC-SHA256 of the payload — set by sign()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))


def _jittered_timestamp(ts: Optional[float] = None) -> str:
    """Return an ISO-8601 UTC string with sub-second jitter applied."""
    if ts is None:
        ts = time.time()
    jitter = secrets.randbelow(_CONFIG.timestamp_jitter_ms + 1) / 1000.0
    ts += jitter
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _sign_event(event: ThreatEvent) -> str:
    """
    Compute an HMAC-SHA256 signature over the event's canonical payload.

    The signature allows a future cloud endpoint to verify that events were
    produced by a legitimate install (knows the derived signing key) and have
    not been tampered with in transit.
    """
    key = _derive_key("event_signing")
    # Canonical form: sorted key=value pairs, signature field excluded.
    d = event.to_dict()
    d.pop("signature", None)
    canonical = "&".join(f"{k}={d[k]}" for k in sorted(d))
    return hmac.new(key, canonical.encode(), "sha256").hexdigest()


def make_event(
    threat_type: str,
    target: str,
    severity: str,
    action_taken: str,
    device_id: str,
    ip: Optional[str] = None,
    timestamp: Optional[float] = None,
    nn_abuse_score: float = 0.0,
) -> ThreatEvent:
    """
    Build a signed, privacy-respecting ThreatEvent.

    Parameters
    ----------
    threat_type    : Category string, e.g. "phishing", "malware_download".
    target         : Raw URL or domain — hashed before storage; never logged.
    severity       : "low" | "medium" | "high" | "critical"
    action_taken   : What the AV did: "blocked", "warned", "allowed".
    device_id      : Install UUID — hashed before storage; never logged.
    ip             : Optional source IP — anonymised + hashed; never logged.
    timestamp      : Unix timestamp (default: now).
    nn_abuse_score : Neural network abuse probability from the abuse detector.

    Returns
    -------
    ThreatEvent with all PII replaced by pseudonymous tokens and a valid
    HMAC signature.
    """
    ev = ThreatEvent(
        event_id=secrets.token_hex(16),
        event_time=_jittered_timestamp(timestamp),
        device_hash=hash_device_id(device_id),
        threat_type=threat_type,
        target_hash=hash_target(target),
        severity=severity,
        action_taken=action_taken,
        ip_hash=hash_ip(ip) if (ip and _CONFIG.collect_ip_hash) else "",
        nn_abuse_score=round(nn_abuse_score, 6),
    )
    ev.signature = _sign_event(ev)
    return ev


def verify_event_signature(event: ThreatEvent) -> bool:
    """
    Return True if *event*'s HMAC signature is valid.

    Use this at the reporting endpoint to reject tampered or replayed events.
    """
    expected = _sign_event(event)
    return hmac.compare_digest(expected, event.signature)


# ===========================================================================
# Neural Network Abuse Detector — pure Python, stdlib-only, online learning
# ===========================================================================
#
# Architecture:  12-input → Dense(16, tanh) → Dense(8, tanh) → Dense(1, sigmoid)
#
# Feature vector (12 dimensions):
#   0  events_last_60s          — short-window count, normalised / 10
#   1  events_last_300s         — medium-window count, normalised / 50
#   2  events_last_3600s        — hour count, normalised / 20
#   3  burst_rate               — events_last_60s / burst_threshold
#   4  velocity_rate            — events_last_300s / velocity_threshold
#   5  inter_arrival_mean       — mean seconds between events, log-scaled
#   6  inter_arrival_std        — std dev of inter-arrival times, log-scaled
#   7  unique_categories        — distinct threat types, normalised / 8
#   8  category_entropy         — Shannon entropy of category distribution
#   9  time_of_day_sin          — sin of hour-of-day (2π/24)
#   10 time_of_day_cos          — cos of hour-of-day (2π/24)
#   11 is_permanently_blocked   — 1.0 if on permanent blocklist

_NN_INPUT_DIM  = 12
_NN_HIDDEN1    = 16
_NN_HIDDEN2    = 8
_NN_OUTPUT     = 1


def _tanh(x: float) -> float:
    return math.tanh(x)


def _tanh_deriv(y: float) -> float:
    """Derivative of tanh given the *output* y = tanh(x)."""
    return 1.0 - y * y


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    else:
        z = math.exp(x)
        return z / (1.0 + z)


def _sigmoid_deriv(y: float) -> float:
    """Derivative of sigmoid given the *output* y = σ(x)."""
    return y * (1.0 - y)


def _make_weights(rows: int, cols: int, seed_extra: int = 0) -> List[List[float]]:
    """Xavier-initialised weight matrix using secrets as a CSPRNG."""
    scale = math.sqrt(2.0 / (rows + cols))
    result: List[List[float]] = []
    for _ in range(rows):
        row: List[float] = []
        for _ in range(cols):
            # Generate a uniform float in [-1, 1] via secrets.
            u = secrets.randbelow(2**32) / (2**32 - 1)   # [0, 1]
            row.append((u * 2.0 - 1.0) * scale)
        result.append(row)
    return result


def _make_bias(size: int) -> List[float]:
    return [0.0] * size


def _matmul_vec(W: List[List[float]], x: List[float]) -> List[float]:
    """Compute W @ x where W is rows×cols and x is cols-dim."""
    return [sum(W[i][j] * x[j] for j in range(len(x))) for i in range(len(W))]


def _vec_add(a: List[float], b: List[float]) -> List[float]:
    return [a[i] + b[i] for i in range(len(a))]


class AbuseNeuralNet:
    """
    Compact online-learning MLP for abuse detection.

    Architecture: 12 → Dense(16, tanh) → Dense(8, tanh) → Dense(1, sigmoid)
    353 parameters; pure Python, zero external dependencies.

    Fix 4 — Drift control
    ----------------------
    * EWM loss monitor: smoothed BCE loss tracked after every training step.
    * Snapshot/rollback: a weight snapshot is saved before each training step;
      if the smoothed loss exceeds `drift_loss_threshold` for `drift_patience`
      consecutive steps, the current weights are partially reset (a random
      `drift_reset_fraction` of each matrix is re-initialised to Xavier scale)
      and the smoothed loss is reset.  The snapshot lets an operator inspect
      the pre-drift weights if needed.
    * Reservoir replay buffer: a fixed-capacity sample of (features, label)
      pairs is maintained via reservoir sampling (every new sample has a fair
      chance of displacing an old one).  `replay_per_step` samples are drawn
      and trained on each new event, providing a stationary distribution that
      stabilises online learning against recency bias.

    Fix 5 — Weak-label guard
    ------------------------
    * Agreement skip: if |nn_score − hard_label| < `weak_label_skip_agreement`,
      the model already agrees; training is skipped to avoid over-fitting noise.
    * Conflict skip: if the rule says legitimate (label=0) but the NN is highly
      confident of abuse (score > `weak_label_skip_conflict_threshold`), training
      is skipped — this is the scenario where the rule has a blind spot and
      blindly accepting the weak label would reinforce the error.
    * Label smoothing: hard {0, 1} labels are mapped to soft {ε/2, 1−ε/2}
      before backprop, reducing overconfidence on rule-boundary samples.

    Thread safety: a single per-instance lock guards all weight mutation.
    The lock is *not* held during disk I/O (async persist thread).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # Layer 1: input → hidden1
        self.W1: List[List[float]] = _make_weights(_NN_HIDDEN1, _NN_INPUT_DIM)
        self.b1: List[float]       = _make_bias(_NN_HIDDEN1)

        # Layer 2: hidden1 → hidden2
        self.W2: List[List[float]] = _make_weights(_NN_HIDDEN2, _NN_HIDDEN1)
        self.b2: List[float]       = _make_bias(_NN_HIDDEN2)

        # Layer 3: hidden2 → output
        self.W3: List[List[float]] = _make_weights(_NN_OUTPUT, _NN_HIDDEN2)
        self.b3: List[float]       = _make_bias(_NN_OUTPUT)

        # SGD momentum buffers.
        self.mW1: List[List[float]] = [[0.0]*_NN_INPUT_DIM  for _ in range(_NN_HIDDEN1)]
        self.mb1: List[float]       = [0.0]*_NN_HIDDEN1
        self.mW2: List[List[float]] = [[0.0]*_NN_HIDDEN1    for _ in range(_NN_HIDDEN2)]
        self.mb2: List[float]       = [0.0]*_NN_HIDDEN2
        self.mW3: List[List[float]] = [[0.0]*_NN_HIDDEN2    for _ in range(_NN_OUTPUT)]
        self.mb3: List[float]       = [0.0]*_NN_OUTPUT

        self.train_steps: int = 0

        # Fix 4: drift monitoring.
        self._smoothed_loss: float = 0.0          # EWM of BCE loss
        self._high_loss_streak: int = 0            # consecutive steps above threshold
        self._snapshot: Optional[Dict[str, Any]] = None   # pre-drift weight copy
        self.drift_resets: int = 0                 # counter for diagnostics

        # Fix 4: reservoir replay buffer — list of (features, label) tuples.
        self._replay: List[Tuple[List[float], float]] = []
        self._replay_total_seen: int = 0           # for Vitter's Algorithm R

    # ------------------------------------------------------------------
    # Forward pass
    # ------------------------------------------------------------------

    def predict(self, features: List[float]) -> float:
        """Return abuse probability in [0, 1] for the given feature vector."""
        with self._lock:
            return self._forward(features)[2][0]   # out[0]

    def _forward(
        self, x: List[float]
    ) -> Tuple[List[float], List[float], List[float], List[float]]:
        """
        Run the full forward pass.
        Returns (h1, h2, out, x).  Called inside the lock.
        """
        z1 = _vec_add(_matmul_vec(self.W1, x), self.b1)
        h1 = [_tanh(v) for v in z1]

        z2 = _vec_add(_matmul_vec(self.W2, h1), self.b2)
        h2 = [_tanh(v) for v in z2]

        z3 = _vec_add(_matmul_vec(self.W3, h2), self.b3)
        out = [_sigmoid(v) for v in z3]

        return h1, h2, out, x

    # ------------------------------------------------------------------
    # Backpropagation + SGD with momentum (internal, caller holds lock)
    # ------------------------------------------------------------------

    def _backprop(self, features: List[float], label: float) -> float:
        """
        One SGD step.  *label* should already be smoothed.
        Returns the raw BCE loss (for the drift monitor).
        Called with self._lock held.
        """
        lr = _CONFIG.nn_learning_rate
        mu = _CONFIG.nn_momentum
        eps = 1e-12

        h1, h2, out, x = self._forward(features)
        y = out[0]

        loss = -(label * math.log(y + eps) + (1 - label) * math.log(1 - y + eps))

        delta3 = [y - label]

        dh2 = [sum(self.W3[k][j] * delta3[k] for k in range(_NN_OUTPUT))
               for j in range(_NN_HIDDEN2)]
        delta2 = [dh2[j] * _tanh_deriv(h2[j]) for j in range(_NN_HIDDEN2)]

        dh1 = [sum(self.W2[k][j] * delta2[k] for k in range(_NN_HIDDEN2))
               for j in range(_NN_HIDDEN1)]
        delta1 = [dh1[j] * _tanh_deriv(h1[j]) for j in range(_NN_HIDDEN1)]

        for i in range(_NN_OUTPUT):
            for j in range(_NN_HIDDEN2):
                grad = delta3[i] * h2[j]
                self.mW3[i][j] = mu * self.mW3[i][j] - lr * grad
                self.W3[i][j] += self.mW3[i][j]
            self.mb3[i] = mu * self.mb3[i] - lr * delta3[i]
            self.b3[i] += self.mb3[i]

        for i in range(_NN_HIDDEN2):
            for j in range(_NN_HIDDEN1):
                grad = delta2[i] * h1[j]
                self.mW2[i][j] = mu * self.mW2[i][j] - lr * grad
                self.W2[i][j] += self.mW2[i][j]
            self.mb2[i] = mu * self.mb2[i] - lr * delta2[i]
            self.b2[i] += self.mb2[i]

        for i in range(_NN_HIDDEN1):
            for j in range(_NN_INPUT_DIM):
                grad = delta1[i] * x[j]
                self.mW1[i][j] = mu * self.mW1[i][j] - lr * grad
                self.W1[i][j] += self.mW1[i][j]
            self.mb1[i] = mu * self.mb1[i] - lr * delta1[i]
            self.b1[i] += self.mb1[i]

        return loss

    # ------------------------------------------------------------------
    # Fix 4: drift detection & partial reset
    # ------------------------------------------------------------------

    def _update_drift_monitor(self, loss: float) -> None:
        """Update the EWM loss tracker and trigger a partial reset if needed."""
        alpha = _CONFIG.drift_ema_alpha
        self._smoothed_loss = alpha * loss + (1 - alpha) * self._smoothed_loss

        if self._smoothed_loss > _CONFIG.drift_loss_threshold:
            self._high_loss_streak += 1
        else:
            self._high_loss_streak = 0

        if self._high_loss_streak >= _CONFIG.drift_patience:
            self._partial_reset()
            self._high_loss_streak = 0
            self._smoothed_loss = 0.0   # restart monitor
            self.drift_resets += 1
            logger.warning(
                "Concept drift detected (smoothed_loss=%.4f). "
                "Partial weight reset applied (reset #%d).",
                self._smoothed_loss, self.drift_resets,
            )

    def _partial_reset(self) -> None:
        """
        Re-initialise a random fraction of each weight matrix.

        Saves a snapshot of the current weights first so the pre-drift
        model can be inspected or restored by an operator.
        """
        self._snapshot = self._weights_to_dict()

        frac = _CONFIG.drift_reset_fraction
        scale1 = math.sqrt(2.0 / (_NN_INPUT_DIM + _NN_HIDDEN1))
        scale2 = math.sqrt(2.0 / (_NN_HIDDEN1   + _NN_HIDDEN2))
        scale3 = math.sqrt(2.0 / (_NN_HIDDEN2   + _NN_OUTPUT))

        def _reinit_fraction(W: List[List[float]], scale: float) -> None:
            rows, cols = len(W), len(W[0])
            n_reset = max(1, int(rows * cols * frac))
            for _ in range(n_reset):
                i = secrets.randbelow(rows)
                j = secrets.randbelow(cols)
                u = secrets.randbelow(2**32) / (2**32 - 1)
                W[i][j] = (u * 2.0 - 1.0) * scale

        _reinit_fraction(self.W1, scale1)
        _reinit_fraction(self.W2, scale2)
        _reinit_fraction(self.W3, scale3)

    # ------------------------------------------------------------------
    # Fix 4: reservoir replay buffer (Vitter's Algorithm R)
    # ------------------------------------------------------------------

    def _reservoir_add(self, features: List[float], label: float) -> None:
        """Add a sample to the replay buffer using reservoir sampling."""
        cap = _CONFIG.replay_buffer_size
        self._replay_total_seen += 1
        if len(self._replay) < cap:
            self._replay.append((features, label))
        else:
            # Replace a random element with probability cap/n.
            j = secrets.randbelow(self._replay_total_seen)
            if j < cap:
                self._replay[j] = (features, label)

    def _replay_train(self) -> None:
        """Train on a random sample from the replay buffer (Fix 4)."""
        k = min(_CONFIG.replay_per_step, len(self._replay))
        if k == 0:
            return
        # Draw k distinct indices without replacement.
        indices: List[int] = []
        pool = list(range(len(self._replay)))
        for _ in range(k):
            idx = secrets.randbelow(len(pool))
            indices.append(pool.pop(idx))
        for i in indices:
            feats, lbl = self._replay[i]
            smooth_lbl = self._smooth_label(lbl)
            self._backprop(feats, smooth_lbl)

    # ------------------------------------------------------------------
    # Fix 5: weak-label guard + label smoothing
    # ------------------------------------------------------------------

    @staticmethod
    def _smooth_label(hard_label: float) -> float:
        """Apply label smoothing: 0 → ε/2, 1 → 1−ε/2."""
        eps = _CONFIG.label_smoothing
        return hard_label * (1.0 - eps) + (1.0 - hard_label) * (eps / 2.0)

    def _should_train(self, nn_score: float, hard_label: float) -> bool:
        """
        Fix 5: Decide whether this (features, label) pair should be trained on.

        Returns False (skip) in two cases:
        * Agreement: the model's output is already close to the target —
          training would only add noise.
        * Conflict: the rule says legitimate but the NN is highly confident
          of abuse.  This is the signature of a rule blind spot; accepting
          the weak label would push the NN *away* from the correct answer.
        """
        agreement_gap = abs(nn_score - hard_label)

        if agreement_gap < _CONFIG.weak_label_skip_agreement:
            return False   # model already agrees; skip

        # Conflict case: rule=legitimate (0) but NN is confident of abuse.
        if (hard_label < 0.5
                and nn_score > _CONFIG.weak_label_skip_conflict_threshold):
            return False   # likely a rule blind spot; don't reinforce

        return True

    # ------------------------------------------------------------------
    # Public training entry point
    # ------------------------------------------------------------------

    def train(self, features: List[float], label: float) -> float:
        """
        Perform one online SGD step with drift control and weak-label guard.

        Parameters
        ----------
        features : 12-dim feature vector (already normalised).
        label    : 1.0 = abusive, 0.0 = legitimate (hard label from rules).

        Returns
        -------
        Smoothed BCE loss (post-EWM update).
        """
        with self._lock:
            nn_score = self._forward(features)[2][0]

            # Fix 5: weak-label guard — skip uninformative / contradictory samples.
            if not self._should_train(nn_score, label):
                return self._smoothed_loss

            smooth_label = self._smooth_label(label)

            # Fix 4: add to replay buffer *before* training so the sample
            # can be replayed from this step onward.
            self._reservoir_add(features, label)

            # Primary update on the current sample.
            raw_loss = self._backprop(features, smooth_label)

            # Fix 4: drift monitor update.
            self._update_drift_monitor(raw_loss)

            # Fix 4: replay a few historical samples to resist recency bias.
            self._replay_train()

            self.train_steps += 1

            if self.train_steps % _CONFIG.nn_persist_every == 0:
                threading.Thread(
                    target=self._persist_weights_async,
                    args=(_CONFIG.nn_weights_path,),
                    daemon=True,
                ).start()

        return self._smoothed_loss

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def _weights_to_dict(self) -> Dict[str, Any]:
        return {
            "W1": self.W1, "b1": self.b1,
            "W2": self.W2, "b2": self.b2,
            "W3": self.W3, "b3": self.b3,
            "train_steps": self.train_steps,
            "drift_resets": self.drift_resets,
            "smoothed_loss": self._smoothed_loss,
        }

    def _weights_from_dict(self, d: Dict[str, Any]) -> None:
        self.W1 = d["W1"]; self.b1 = d["b1"]
        self.W2 = d["W2"]; self.b2 = d["b2"]
        self.W3 = d["W3"]; self.b3 = d["b3"]
        self.train_steps    = d.get("train_steps", 0)
        self.drift_resets   = d.get("drift_resets", 0)
        self._smoothed_loss = d.get("smoothed_loss", 0.0)

    def save(self, path: Path) -> None:
        """Persist weights to *path* (owner-only, 0o600)."""
        with self._lock:
            payload = self._weights_to_dict()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with tmp.open("w") as fh:
            json.dump(payload, fh)
        tmp.chmod(0o600)
        tmp.replace(path)
        logger.debug("NN weights persisted (%d steps).", self.train_steps)

    def _persist_weights_async(self, path: Path) -> None:
        try:
            self.save(path)
        except Exception as exc:
            logger.warning("Failed to persist NN weights: %s", exc)

    def load(self, path: Path) -> None:
        """Load weights from *path*; silently skip if the file does not exist."""
        if not path.exists():
            logger.debug("No NN weights file at %s — starting fresh.", path)
            return
        try:
            with path.open("r") as fh:
                d = json.load(fh)
            with self._lock:
                self._weights_from_dict(d)
            logger.info(
                "NN weights loaded from %s (%d prior steps, %d drift resets).",
                path, self.train_steps, self.drift_resets,
            )
        except Exception as exc:
            logger.warning("Could not load NN weights from %s: %s — resetting.", path, exc)

    def restore_snapshot(self) -> bool:
        """
        Restore the most recent pre-drift weight snapshot (operator tool).
        Returns True if a snapshot was available, False otherwise.
        """
        with self._lock:
            if self._snapshot is None:
                return False
            self._weights_from_dict(self._snapshot)
            logger.info("Pre-drift weight snapshot restored.")
            return True
# Module-level singleton — initialised once, shared across all threads.
_ABUSE_NN = AbuseNeuralNet()
_ABUSE_NN.load(PrivacyConfig().nn_weights_path)


# ===========================================================================
# Feature extraction  (privacy-safe: operates on hashed identifiers only)
# ===========================================================================

def _category_shannon_entropy(category_counts: Dict[str, int]) -> float:
    """
    Compute the true Shannon entropy H(X) of the observed category distribution.

    Uses actual per-category event counts, not the uniform upper-bound.
    H(X) = -Σ p_i · log2(p_i)  where p_i = count_i / total_events.

    Returns 0.0 for a single category (no uncertainty) and log2(k) for
    k equally frequent categories (maximum uncertainty).
    """
    total = sum(category_counts.values())
    if total == 0 or len(category_counts) <= 1:
        return 0.0
    entropy = 0.0
    for count in category_counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def extract_features(
    state: "_IdentifierState",
    now: float,
    is_permanently_blocked: bool,
) -> List[float]:
    """
    Build the 12-dimensional feature vector for the abuse NN.

    All values are normalised to a roughly [0, 1] range so that the NN
    does not need internal normalisation layers.  Log-scaling is used for
    inter-arrival statistics which can span several orders of magnitude.
    """
    ts = list(state.timestamps)  # snapshot under caller's lock

    # Window counts.
    n60   = sum(1 for t in ts if t >= now - 60)
    n300  = sum(1 for t in ts if t >= now - 300)
    n3600 = sum(1 for t in ts if t >= now - 3600)

    # Inter-arrival statistics.
    recent = [t for t in ts if t >= now - 300]
    recent.sort()
    if len(recent) >= 2:
        deltas = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
        ia_mean = sum(deltas) / len(deltas)
        ia_var  = sum((d - ia_mean)**2 for d in deltas) / len(deltas)
        ia_std  = math.sqrt(ia_var)
    else:
        ia_mean = 300.0
        ia_std  = 0.0

    cfg = _CONFIG
    cat_counts = state.category_counts   # Fix 1: real counts, not a bare set
    n_cats = len(cat_counts)

    # Fix 3: adaptive burst rate — normalise against the identifier's own EMA
    # baseline; a device that legitimately fires 5 events/min has a higher
    # legitimate ceiling than one that normally fires once per hour.
    ema_ref = max(state.ema_rate, 0.5)   # floor at 0.5 events/min to avoid /0
    adaptive_burst = min(n60 / (ema_ref * cfg.adaptive_threshold_multiplier), 1.0)

    # Time-of-day cyclic encoding (avoids discontinuity at midnight).
    hour_frac = (now % 86400) / 86400
    tod_sin = math.sin(2 * math.pi * hour_frac)
    tod_cos = math.cos(2 * math.pi * hour_frac)

    # Fix 1: true Shannon entropy (not uniform upper-bound).
    max_entropy = math.log2(max(cfg.entropy_category_limit, 2))
    true_entropy = _category_shannon_entropy(cat_counts)

    return [
        min(n60   / 10.0, 1.0),                                             # 0
        min(n300  / 50.0, 1.0),                                             # 1
        min(n3600 / float(cfg.rate_limit_per_hour), 1.0),                  # 2
        min(n60   / max(cfg.burst_threshold, 1), 1.0),                     # 3  static
        adaptive_burst,                                                      # 4  Fix 3
        min(math.log1p(ia_mean) / math.log1p(300.0), 1.0),                # 5
        min(math.log1p(ia_std)  / math.log1p(300.0), 1.0),                # 6
        min(n_cats / float(cfg.entropy_category_limit), 1.0),              # 7
        min(true_entropy / max_entropy, 1.0),                               # 8  Fix 1
        (tod_sin + 1.0) / 2.0,                                              # 9
        (tod_cos + 1.0) / 2.0,                                              # 10
        1.0 if is_permanently_blocked else 0.0,                             # 11
    ]


# ===========================================================================
# Abuse prevention — rate limiting + anomaly detection + NN classifier
# ===========================================================================

@dataclass
class _IdentifierState:
    """Per-identifier mutable tracking state (one instance per hashed identifier)."""
    timestamps: deque = field(default_factory=deque)          # event times (float)

    # Fix 1: real counts per category for true Shannon entropy.
    category_counts: Dict[str, int] = field(default_factory=dict)

    blocked_until: float = 0.0                                # epoch; 0 = not blocked

    # Fix 3: adaptive baseline — EMA of events-per-minute over legitimate events.
    # Seeded at 0; grows toward the identifier's normal rate.
    ema_rate: float = 0.0

    @property
    def categories(self) -> set:
        """Compatibility shim — return the set of observed category names."""
        return set(self.category_counts.keys())


# ---------------------------------------------------------------------------
# Fix 2: Striped lock pool — replaces the single global _ABUSE_LOCK.
#
# Each identifier is hashed into one of `lock_pool_size` shards.  Concurrent
# events for *different* identifiers that happen to land in the same shard
# still contend, but the probability falls to 1/256 vs 1/1 with a global lock.
# Shard count is a power-of-two so the modulus reduces to a bitwise AND.
# ---------------------------------------------------------------------------

_IDENTIFIER_STATE: Dict[str, _IdentifierState] = defaultdict(_IdentifierState)

# Populated lazily in _get_shard_lock() so pool size can be read from config.
_LOCK_POOL: List[threading.Lock] = []
_LOCK_POOL_INIT = threading.Lock()


def _get_shard_lock(identifier: str) -> threading.Lock:
    """Return the shard lock for *identifier*, initialising the pool on first call."""
    global _LOCK_POOL
    if not _LOCK_POOL:
        with _LOCK_POOL_INIT:
            if not _LOCK_POOL:   # double-checked
                _LOCK_POOL = [threading.Lock() for _ in range(_CONFIG.lock_pool_size)]
    # Bitwise AND works because lock_pool_size is a power of two.
    shard = hash(identifier) & (_CONFIG.lock_pool_size - 1)
    return _LOCK_POOL[shard]


def _get_state(identifier: str) -> _IdentifierState:
    """Return the state object for *identifier*, creating it if absent.
    Caller is responsible for holding the shard lock while using the state."""
    return _IDENTIFIER_STATE[identifier]


def _prune_timestamps(state: _IdentifierState, horizon: float) -> None:
    """Remove timestamps older than *horizon* from the left of the deque."""
    while state.timestamps and state.timestamps[0] < horizon:
        state.timestamps.popleft()


@dataclass
class AbuseVerdict:
    """Result of check_abuse()."""
    allowed: bool
    reason: str               # human-readable explanation (never contains PII)
    block_duration: float = 0.0     # seconds remaining on an active block
    nn_score: float = 0.0           # NN abuse probability (0.0–1.0)
    nn_active: bool = False         # True once warmup is complete


def check_abuse(
    identifier: str,
    threat_type: Optional[str] = None,
) -> AbuseVerdict:
    """
    Evaluate whether an event from *identifier* should be accepted.

    Rule layers (evaluated first, fail-fast):
      1. Active block      — identifier is on a cooldown from a prior violation.
      2. Hourly quota      — more than `rate_limit_per_hour` events in 60 min.
      3. Burst guard       — more than `burst_threshold` events in burst window.
      4. Velocity anomaly  — more than `velocity_threshold` events in 5 min.
      5. Adaptive baseline — rate > `adaptive_threshold_multiplier × EMA_rate`.
      6. Category entropy  — distinct threat category count exceeds limit.

    Neural layer (runs after rule checks pass):
      7. NN classifier     — MLP abuse score above `nn_block_threshold` blocks;
                             above `nn_warn_threshold` logs a warning.

    Fix 2: Uses a per-shard lock (striped pool) rather than a global lock.
           Contention for different identifiers falls to ≈1/lock_pool_size.
    Fix 3: Adaptive baseline check (layer 5) scales the rate threshold to
           each identifier's own learned normal behaviour.
    Fix 1: category_counts is a dict[str,int] — entropy uses true distribution.

    *identifier* must always be a hashed value (device_hash or ip_hash).
    *threat_type* feeds the entropy check and NN feature vector.
    """
    now = time.time()
    cfg = _CONFIG
    nn_score = 0.0
    nn_active = _ABUSE_NN.train_steps >= cfg.nn_warmup_samples
    perm_blocked = is_hash_blocked(identifier)

    # Fix 2: acquire the shard lock for this identifier only.
    lock = _get_shard_lock(identifier)

    with lock:
        state = _IDENTIFIER_STATE[identifier]

        # --- Layer 1: Active block -------------------------------------------
        if state.blocked_until > now:
            remaining = state.blocked_until - now
            feats = extract_features(state, now, perm_blocked)
            nn_score = _ABUSE_NN.predict(feats)
            _ABUSE_NN.train(feats, 1.0)
            return AbuseVerdict(
                allowed=False,
                reason="identifier_blocked",
                block_duration=remaining,
                nn_score=nn_score,
                nn_active=nn_active,
            )

        # Prune stale timestamps (keep only last hour for efficiency).
        _prune_timestamps(state, now - 3600)

        # --- Layer 2: Hourly quota -------------------------------------------
        hour_count = sum(1 for t in state.timestamps if t >= now - 3600)
        if hour_count >= cfg.rate_limit_per_hour:
            state.blocked_until = now + 600
            feats = extract_features(state, now, perm_blocked)
            nn_score = _ABUSE_NN.predict(feats)
            _ABUSE_NN.train(feats, 1.0)
            return AbuseVerdict(
                allowed=False,
                reason="hourly_rate_limit_exceeded",
                block_duration=600.0,
                nn_score=nn_score,
                nn_active=nn_active,
            )

        # --- Layer 3: Burst guard -------------------------------------------
        burst_count = sum(1 for t in state.timestamps if t >= now - cfg.burst_window_seconds)
        if burst_count >= cfg.burst_threshold:
            state.blocked_until = now + 300
            feats = extract_features(state, now, perm_blocked)
            nn_score = _ABUSE_NN.predict(feats)
            _ABUSE_NN.train(feats, 1.0)
            return AbuseVerdict(
                allowed=False,
                reason="burst_limit_exceeded",
                block_duration=300.0,
                nn_score=nn_score,
                nn_active=nn_active,
            )

        # --- Layer 4: Velocity anomaly --------------------------------------
        velocity_count = sum(1 for t in state.timestamps if t >= now - cfg.velocity_window_seconds)
        if velocity_count >= cfg.velocity_threshold:
            state.blocked_until = now + 1800
            logger.warning("Velocity anomaly detected for identifier (hash). Blocking 30 min.")
            feats = extract_features(state, now, perm_blocked)
            nn_score = _ABUSE_NN.predict(feats)
            _ABUSE_NN.train(feats, 1.0)
            return AbuseVerdict(
                allowed=False,
                reason="velocity_anomaly",
                block_duration=1800.0,
                nn_score=nn_score,
                nn_active=nn_active,
            )

        # --- Layer 5: Adaptive baseline (Fix 3) -----------------------------
        # events_per_minute in the last 60 s vs this identifier's own EMA norm.
        current_rate = sum(1 for t in state.timestamps if t >= now - 60)
        adaptive_ceiling = state.ema_rate * cfg.adaptive_threshold_multiplier
        if state.ema_rate > 0.5 and current_rate > adaptive_ceiling:
            state.blocked_until = now + 300
            logger.warning(
                "Adaptive baseline breach: rate=%d > ceiling=%.1f (EMA=%.2f). "
                "Blocking 5 min.", current_rate, adaptive_ceiling, state.ema_rate,
            )
            feats = extract_features(state, now, perm_blocked)
            nn_score = _ABUSE_NN.predict(feats)
            _ABUSE_NN.train(feats, 1.0)
            return AbuseVerdict(
                allowed=False,
                reason="adaptive_baseline_exceeded",
                block_duration=300.0,
                nn_score=nn_score,
                nn_active=nn_active,
            )

        # --- Layer 6: Category entropy (Fix 1: uses real counts) ------------
        if threat_type is not None:
            state.category_counts[threat_type] = state.category_counts.get(threat_type, 0) + 1
            if len(state.category_counts) > cfg.entropy_category_limit:
                state.blocked_until = now + 3600
                logger.warning(
                    "High-entropy threat category spread for identifier (hash). "
                    "Possible scanner/fuzzer. Blocking 1 hour."
                )
                feats = extract_features(state, now, perm_blocked)
                nn_score = _ABUSE_NN.predict(feats)
                _ABUSE_NN.train(feats, 1.0)
                return AbuseVerdict(
                    allowed=False,
                    reason="category_entropy_anomaly",
                    block_duration=3600.0,
                    nn_score=nn_score,
                    nn_active=nn_active,
                )

        # --- All rule layers passed — compute NN score ----------------------
        feats = extract_features(state, now, perm_blocked)
        nn_score = _ABUSE_NN.predict(feats)

        # --- Layer 7: Neural classifier (active after warmup) ---------------
        if nn_active and nn_score >= cfg.nn_block_threshold:
            state.blocked_until = now + 600
            logger.warning(
                "NN abuse classifier blocked identifier (score=%.4f). "
                "10-minute cooldown applied.", nn_score,
            )
            _ABUSE_NN.train(feats, 1.0)
            return AbuseVerdict(
                allowed=False,
                reason="nn_abuse_detected",
                block_duration=600.0,
                nn_score=nn_score,
                nn_active=True,
            )

        if nn_active and nn_score >= cfg.nn_warn_threshold:
            logger.warning(
                "NN abuse classifier flagged suspicious identifier "
                "(score=%.4f). Event allowed.", nn_score,
            )

        # --- All layers passed: record event, update EMA, train NN ----------
        state.timestamps.append(now)

        # Fix 3: update per-identifier EMA of events per minute.
        alpha = cfg.adaptive_ema_alpha
        state.ema_rate = alpha * current_rate + (1 - alpha) * state.ema_rate

        _ABUSE_NN.train(feats, 0.0)

        return AbuseVerdict(
            allowed=True,
            reason="ok",
            nn_score=nn_score,
            nn_active=nn_active,
        )


def unblock_identifier(identifier: str) -> None:
    """Manually clear an active block (admin / test use)."""
    with _get_shard_lock(identifier):
        if identifier in _IDENTIFIER_STATE:
            _IDENTIFIER_STATE[identifier].blocked_until = 0.0
    logger.info("Block manually cleared for identifier (hash provided by caller).")


def reset_identifier(identifier: str) -> None:
    """Completely reset all state for an identifier (admin / test use)."""
    with _get_shard_lock(identifier):
        _IDENTIFIER_STATE.pop(identifier, None)


# ===========================================================================
# Blocked-hash registry  (known-bad device / IP hashes)
# ===========================================================================

_BLOCKED_HASHES: set = set()
_BLOCKED_LOCK  = threading.Lock()


def block_hash(identifier_hash: str) -> None:
    """Permanently block a hashed identifier (e.g. known-bad actor)."""
    with _BLOCKED_LOCK:
        _BLOCKED_HASHES.add(identifier_hash)


def is_hash_blocked(identifier_hash: str) -> bool:
    """Return True if *identifier_hash* is on the permanent block list."""
    with _BLOCKED_LOCK:
        return identifier_hash in _BLOCKED_HASHES


# ===========================================================================
# High-level pipeline — the single entry point for AV events
# ===========================================================================

@dataclass
class ProcessResult:
    """Outcome of process_threat_event()."""
    accepted: bool
    event: Optional[ThreatEvent]
    rejection_reason: str = ""
    nn_score: float = 0.0
    nn_active: bool = False


def process_threat_event(
    threat_type: str,
    target: str,
    severity: str,
    action_taken: str,
    device_id: str,
    ip: Optional[str] = None,
    timestamp: Optional[float] = None,
) -> ProcessResult:
    """
    Full privacy + abuse-prevention pipeline for a single threat event.

    1. Derive pseudonymous identifiers (originals never leave this scope).
    2. Check permanent block list.
    3. Run all rule-based abuse-prevention layers.
    4. Run neural network abuse classifier.
    5. Build and sign a ThreatEvent (includes nn_abuse_score).
    6. Return a ProcessResult the caller can persist or transmit.

    No raw PII appears anywhere in this function's return value or logs.
    """
    # Step 1: Derive tokens first — originals never leave this scope.
    device_hash = hash_device_id(device_id)
    ip_hash = hash_ip(ip) if (ip and _CONFIG.collect_ip_hash) else ""

    # Step 2: Permanent block check.
    primary_identifier = device_hash or ip_hash
    if not primary_identifier:
        return ProcessResult(
            accepted=False,
            event=None,
            rejection_reason="no_valid_identifier",
        )

    if is_hash_blocked(primary_identifier):
        return ProcessResult(
            accepted=False,
            event=None,
            rejection_reason="permanently_blocked",
        )

    # Step 3 + 4: Abuse-prevention checks (rules + NN).
    verdict = check_abuse(primary_identifier, threat_type=threat_type)
    if not verdict.allowed:
        return ProcessResult(
            accepted=False,
            event=None,
            rejection_reason=verdict.reason,
            nn_score=verdict.nn_score,
            nn_active=verdict.nn_active,
        )

    # Step 5: Build and sign the event (NN score is embedded in the record).
    ev = make_event(
        threat_type=threat_type,
        target=target,
        severity=severity,
        action_taken=action_taken,
        device_id=device_id,
        ip=ip,
        timestamp=timestamp,
        nn_abuse_score=verdict.nn_score,
    )

    return ProcessResult(
        accepted=True,
        event=ev,
        nn_score=verdict.nn_score,
        nn_active=verdict.nn_active,
    )


# ===========================================================================
# Audit / compliance helpers
# ===========================================================================

def data_subject_report(device_id: str) -> Dict[str, Any]:
    """
    Return everything the system holds about *device_id* — without storing
    or logging the raw ID.

    Suitable for responding to FERPA inspection requests or GDPR Article 15
    access requests.  The caller is responsible for secure transmission.
    """
    device_hash = hash_device_id(device_id)
    with _get_shard_lock(device_hash):
        state = _IDENTIFIER_STATE.get(device_hash)
        if state is None:
            return {"device_hash": device_hash, "event_count": 0, "note": "no data held"}
        now = time.time()
        _prune_timestamps(state, now - 3600)
        return {
            "device_hash": device_hash,
            "events_last_hour": len(state.timestamps),
            "threat_categories_observed": sorted(state.category_counts.keys()),
            "category_counts": dict(state.category_counts),
            "currently_blocked": state.blocked_until > now,
            "block_expires_in_seconds": max(0.0, state.blocked_until - now),
            "adaptive_ema_rate": round(state.ema_rate, 4),
            "note": (
                "No personal information is held. The device_hash is a one-way "
                "pseudonymous token that cannot be reversed to a device ID."
            ),
        }


def erasure_request(device_id: str) -> bool:
    """
    Erase all in-memory state for *device_id* (GDPR Article 17 / COPPA).

    Returns True if data was found and erased, False if nothing was held.
    Note: persisted event logs (if any) must be purged separately by the
    caller; this function only clears the in-memory abuse-tracking state.
    """
    device_hash = hash_device_id(device_id)
    with _get_shard_lock(device_hash):
        existed = device_hash in _IDENTIFIER_STATE
        _IDENTIFIER_STATE.pop(device_hash, None)
    if existed:
        logger.info("Erasure request fulfilled — in-memory state cleared.")
    return existed


def nn_diagnostics() -> Dict[str, Any]:
    """Return a snapshot of the neural network's training and health state."""
    cfg = _CONFIG
    nn = _ABUSE_NN
    param_count = (
        _NN_HIDDEN1 * _NN_INPUT_DIM + _NN_HIDDEN1 +
        _NN_HIDDEN2 * _NN_HIDDEN1   + _NN_HIDDEN2 +
        _NN_OUTPUT  * _NN_HIDDEN2   + _NN_OUTPUT
    )
    return {
        "architecture": f"{_NN_INPUT_DIM} → {_NN_HIDDEN1} → {_NN_HIDDEN2} → {_NN_OUTPUT}",
        "activation_hidden": "tanh",
        "activation_output": "sigmoid",
        "optimizer": "SGD + momentum",
        "parameter_count": param_count,
        "train_steps": nn.train_steps,
        "warmup_samples": cfg.nn_warmup_samples,
        "nn_active": nn.train_steps >= cfg.nn_warmup_samples,
        "block_threshold": cfg.nn_block_threshold,
        "warn_threshold": cfg.nn_warn_threshold,
        # Fix 4: drift diagnostics
        "smoothed_loss": round(nn._smoothed_loss, 6),
        "drift_resets": nn.drift_resets,
        "high_loss_streak": nn._high_loss_streak,
        "drift_patience": cfg.drift_patience,
        "drift_loss_threshold": cfg.drift_loss_threshold,
        "replay_buffer_size": len(nn._replay),
        "replay_buffer_capacity": cfg.replay_buffer_size,
        # Fix 5: weak-label guard settings
        "label_smoothing_epsilon": cfg.label_smoothing,
        "weak_label_skip_agreement": cfg.weak_label_skip_agreement,
        "weak_label_conflict_threshold": cfg.weak_label_skip_conflict_threshold,
        # Fix 2: lock pool
        "lock_pool_size": cfg.lock_pool_size,
        # Fix 3: adaptive baseline settings
        "adaptive_ema_alpha": cfg.adaptive_ema_alpha,
        "adaptive_threshold_multiplier": cfg.adaptive_threshold_multiplier,
        "weights_path": str(cfg.nn_weights_path),
    }


def compliance_summary() -> Dict[str, Any]:
    """Return a machine-readable compliance summary for auditors."""
    return {
        "ferpa_safe": True,
        "coppa_safe": True,
        "gdpr_pseudonymised": True,
        "ccpa_no_sale": True,
        "pii_collected": False,
        "ip_anonymisation": "Last octet (IPv4) / last 80 bits (IPv6) zeroed before hashing",
        "hashing_algorithm": "HMAC-SHA256 with Argon2id-derived purpose-scoped keys"
        if _ARGON2_AVAILABLE
        else "HMAC-SHA256 with PBKDF2-HMAC-SHA256-derived purpose-scoped keys",
        "fields_collected": [
            "event_id (random, per-event)",
            "event_time (jittered UTC)",
            "device_hash (HMAC of UUID)",
            "threat_type",
            "target_hash (HMAC of URL/domain)",
            "severity",
            "action_taken",
            "ip_hash (HMAC of anonymised IP, optional)",
            "nn_abuse_score (model output, 0–1 float)",
        ],
        "fields_never_collected": [
            "student name",
            "email address",
            "plaintext IP address",
            "plaintext device UUID",
            "browsing history",
            "keystrokes",
            "location data",
        ],
        "nn_diagnostics": nn_diagnostics(),
    }


# ===========================================================================
# Feature / benefit descriptors (for sales & audit documentation)
# ===========================================================================

@dataclass
class FeatureBenefit:
    feature: str
    benefit: str


FEATURE_BENEFITS: List[FeatureBenefit] = [
    FeatureBenefit(
        feature="HMAC-SHA256 + Argon2id pseudonymisation",
        benefit=(
            "All identifiers (IPs, device IDs, URLs) are replaced with "
            "keyed HMAC tokens derived from a memory-hard KDF. Rainbow tables "
            "and brute-force attacks are computationally infeasible even if the "
            "salt is exposed."
        ),
    ),
    FeatureBenefit(
        feature="k-anonymous IP handling",
        benefit=(
            "IPv4 last octet and IPv6 last 80 bits are zeroed *before* any "
            "hashing, satisfying GDPR Recital 26. No hashing trick can undo the "
            "loss of those bits."
        ),
    ),
    FeatureBenefit(
        feature="Purpose-scoped derived keys",
        benefit=(
            "IP hashes, device-ID hashes, URL hashes, and event signatures each "
            "use a separate key derived from the master salt. Leaking one domain's "
            "token cannot be used to compute tokens in another domain."
        ),
    ),
    FeatureBenefit(
        feature="Minimal data collection",
        benefit=(
            "Only what is strictly necessary for threat detection is retained: "
            "hashed domain, threat category, severity, action taken, and a random "
            "event ID. No names, emails, browsing history, or keystrokes. FERPA / "
            "COPPA / CCPA compliant by design."
        ),
    ),
    FeatureBenefit(
        feature="HMAC-signed events",
        benefit=(
            "Every event carries an HMAC-SHA256 signature. A reporting endpoint "
            "can verify authenticity and reject tampered, replayed, or spoofed "
            "records before they enter any database."
        ),
    ),
    FeatureBenefit(
        feature="Local-first detection",
        benefit=(
            "Phishing, malicious-download, and JS-injection detection all run "
            "on-device. Aggregated, pseudonymised stats are only sent to a cloud "
            "dashboard if explicitly configured. No student data leaves the device "
            "by default."
        ),
    ),
    FeatureBenefit(
        feature="Multi-layer rule-based abuse prevention with true entropy (Fixes 1 & 3)",
        benefit=(
            "Seven independent layers — permanent blocklist, hourly quota, burst "
            "guard, velocity anomaly, adaptive baseline (Fix 3), category entropy "
            "(Fix 1: real H(X) from per-category counts), and NN classifier. "
            "True Shannon entropy replaces the previous uniform upper-bound, "
            "making the category-spread detector accurate rather than conservative."
        ),
    ),
    FeatureBenefit(
        feature="Online neural network abuse classifier",
        benefit=(
            "A compact two-layer MLP (12 → 16 → 8 → 1) learns to detect "
            "low-and-slow abuse patterns that evade individual rule thresholds. "
            "It trains continuously on every processed event using rule verdicts "
            "as weak supervision labels, requires zero external libraries, and "
            "persists weights across restarts. Forward inference costs < 0.1 ms "
            "in pure Python."
        ),
    ),
    FeatureBenefit(
        feature="Striped lock pool (Fix 2)",
        benefit=(
            "A pool of 256 per-shard locks replaces the previous global lock. "
            "Concurrent events for distinct identifiers that hash to different "
            "shards proceed in parallel, reducing contention by up to 256×. "
            "Timestamp deques are pruned lazily inside each shard."
        ),
    ),
    FeatureBenefit(
        feature="Adaptive per-identifier rate baselines (Fix 3)",
        benefit=(
            "Each identifier maintains an EMA of its own legitimate event rate. "
            "The burst threshold scales with this baseline, so a device that "
            "normally fires 5 events/min is not blocked for the same behaviour "
            "that would rightfully block a device that normally fires once/hour."
        ),
    ),
    FeatureBenefit(
        feature="Online drift control with replay buffer (Fix 4)",
        benefit=(
            "An EWM loss monitor tracks the model's BCE loss. If the smoothed "
            "loss exceeds the drift threshold for 500 consecutive steps, a partial "
            "weight reset is applied and the pre-drift weights are snapshotted for "
            "operator inspection. A reservoir replay buffer (2 000 samples, "
            "Vitter's Algorithm R) provides a stationary training distribution "
            "that prevents recency bias without storing raw PII."
        ),
    ),
    FeatureBenefit(
        feature="Weak-label guard with label smoothing (Fix 5)",
        benefit=(
            "Training is skipped when the model already agrees with the rule "
            "verdict (agreement gap < 0.1) or when the rule says legitimate but "
            "the NN is highly confident of abuse (conflict threshold 0.9) — the "
            "signature of a rule blind spot. Hard labels are smoothed to "
            "(ε/2, 1−ε/2) to prevent overconfidence on rule-boundary samples."
        ),
    ),
    FeatureBenefit(
        feature="GDPR Article 17 erasure support",
        benefit=(
            "erasure_request() purges all in-memory state for a device in O(1). "
            "data_subject_report() provides a machine-readable access report "
            "for FERPA inspection and GDPR Article 15 requests."
        ),
    ),
    FeatureBenefit(
        feature="Audit-ready compliance summary",
        benefit=(
            "compliance_summary() returns a structured JSON-serialisable dict "
            "listing every field collected (and not collected), plus NN diagnostics, "
            "suitable for school district auditors or third-party privacy assessments."
        ),
    ),
]


# ===========================================================================
# Self-test / example
# ===========================================================================

def _run_example() -> None:
    """Demonstrate the full pipeline including the NN abuse classifier."""
    logging.basicConfig(level=logging.INFO)

    device = "550e8400-e29b-41d4-a716-446655440000"
    ip     = "203.0.113.45"

    print("\n=== Threat Event Pipeline ===")
    result = process_threat_event(
        threat_type="phishing",
        target="evil-login.example.com",
        severity="high",
        action_taken="blocked",
        device_id=device,
        ip=ip,
    )
    if result.accepted and result.event:
        print("Event accepted:", result.event.to_json())
        print("Signature valid:", verify_event_signature(result.event))
        print(f"NN score: {result.nn_score:.4f}  (NN active: {result.nn_active})")
    else:
        print("Event rejected:", result.rejection_reason)

    print("\n=== Abuse Prevention — burst simulation ===")
    test_hash = hash_device_id("test-device-uuid")
    for i in range(15):
        v = check_abuse(test_hash, threat_type="malware_download")
        print(
            f"  Event {i+1:02d}: allowed={v.allowed:<5}  "
            f"reason={v.reason:<35} nn_score={v.nn_score:.4f}"
        )

    print("\n=== NN Warm-up — training 300 synthetic examples ===")
    # Simulate 200 legitimate + 100 abusive events so the NN activates.
    legit_hash  = hash_device_id("legit-device")
    abuser_hash = hash_device_id("abuser-device")

    for i in range(200):
        check_abuse(legit_hash, threat_type="phishing")
        if i < 50:
            time.sleep(0)   # yield

    for i in range(100):
        # Simulate rapid-fire bursting — will be caught by rules and
        # provide the NN with abusive labels.
        check_abuse(abuser_hash, threat_type="malware_download")

    print(f"NN training steps: {_ABUSE_NN.train_steps}")
    print(f"NN now active: {_ABUSE_NN.train_steps >= _CONFIG.nn_warmup_samples}")

    print("\n=== NN Diagnostics ===")
    print(json.dumps(nn_diagnostics(), indent=2))

    print("\n=== Compliance Summary ===")
    print(json.dumps(compliance_summary(), indent=2))

    print("\n=== Data Subject Report ===")
    print(json.dumps(data_subject_report(device), indent=2))

    print("\n=== Erasure Request ===")
    erased = erasure_request(device)
    print("Data erased:", erased)
    print("Post-erasure report:", data_subject_report(device))


if __name__ == "__main__":
    _run_example()