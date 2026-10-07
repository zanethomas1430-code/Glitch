"""prepare.py — the angles most incident preparation skips, because they assume the responders, the guard
process, and the anchor are all still trustworthy. This module assumes none of that.

  MultiPartyVerifier   no single responder can lower containment: k distinct principals within a window,
                       and the contained system's own principals can never count.
  SilenceWatchdog      a guard that stops writing anchors is treated as contained, not as quiet. Silence fails
                       closed. This is the dead-man switch for "the monitor was the first thing they turned off."
  attest / check       the guard's own code and canvas are hashed into the seal; a verifier compares against a
                       published set. "Which guard produced this evidence?" gets an answer.
  bundle_to_fixture    an incident becomes a permanent canvas scenario (integers only) so the same shape can
                       never pass unnoticed again.
  canary_diff          two shadow runs on the same traffic, compared by tripwire profile: version B regressed
                       on trajectories where A was clean.

None of this reads model output. During an incident, nobody should.
"""
from __future__ import annotations

import hashlib
import json
import os as _os
import sys as _sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "08_incident"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)

from alignment_guard_v343 import GuardMode, RecoveryAuthorization, RecoveryGrant
from glitch_runtime_harness import CLIENT_AUTHORITIES


# --------------------------------------------------------------------------- 1. two-person rule for thaw
class MultiPartyError(Exception): ...


@dataclass
class _Pending:
    principals: dict[str, float] = field(default_factory=dict)      # principal -> ts of their approval


class MultiPartyVerifier:
    """Wraps any AuthorityVerifier. A lowering is granted only after `k` DISTINCT allowed principals have
    approved the same (user, target, incident) within `window_s`. Approvals expire. The wrapped verifier is
    consulted for the final grant, so its own binding rules still apply.

    The party being contained can never be a principal: names in CLIENT_AUTHORITIES are rejected outright.
    """

    def __init__(self, inner, *, k: int = 2, allowed: Iterable[str], window_s: float = 900, clock: Callable[[], float] = time.time):
        if k < 2: raise MultiPartyError("k must be >= 2; a one-person rule is not a multi-party rule")
        self.inner, self.k, self.window, self.clock = inner, k, window_s, clock
        self.allowed = {a.strip() for a in allowed if a.strip()}
        if len(self.allowed) < k: raise MultiPartyError(f"only {len(self.allowed)} allowed principals for k={k}")
        bad = {a for a in self.allowed if a.lower() in CLIENT_AUTHORITIES | {"system", "operator-bot", "automation"}}
        if bad: raise MultiPartyError(f"contained-party names cannot be responders: {sorted(bad)}")
        self._pending: dict[tuple, _Pending] = {}
        self.log: list[dict] = []

    def approve(self, *, principal: str, user_id: str, target: GuardMode, incident_id: str) -> int:
        """Record one principal's approval. Returns how many distinct approvals are now live."""
        if principal not in self.allowed: raise MultiPartyError(f"{principal!r} is not an allowed responder")
        key = (user_id, target.name, incident_id); now = self.clock()
        p = self._pending.setdefault(key, _Pending())
        p.principals = {n: t for n, t in p.principals.items() if now - t <= self.window}
        p.principals[principal] = now
        self.log.append({"ts": now, "event": "approval", "principal": principal, "user": user_id, "target": target.name, "incident": incident_id, "live": len(p.principals)})
        return len(p.principals)

    def authorize_mode_lowering(self, *, user_id, current, target, authorization: RecoveryAuthorization, reason, expected_version) -> RecoveryGrant:
        key = (user_id, target.name, authorization.incident_id); now = self.clock()
        p = self._pending.get(key, _Pending())
        live = {n: t for n, t in p.principals.items() if now - t <= self.window}
        if authorization.principal not in live:
            raise MultiPartyError(f"requesting principal {authorization.principal!r} has not approved this lowering")
        if len(live) < self.k:
            raise MultiPartyError(f"{len(live)} of {self.k} required approvals live for {user_id} -> {target.name}")
        grant = self.inner.authorize_mode_lowering(user_id=user_id, current=current, target=target, authorization=authorization, reason=reason, expected_version=expected_version)
        self.log.append({"ts": now, "event": "granted", "principals": sorted(live), "user": user_id, "target": target.name, "incident": authorization.incident_id})
        self._pending.pop(key, None)                                 # approvals are consumed; the next thaw needs fresh ones
        return grant


# --------------------------------------------------------------------------- 2. silence watchdog
@dataclass
class WatchVerdict:
    user_id: str
    status: str            # "alive" | "silent" | "rolled_back"
    last_seq: Optional[int]
    seconds_silent: Optional[float]
    action: str            # "none" | "TREAT_AS_CONTAINED"


class SilenceWatchdog:
    """Runs OUTSIDE the guard's process, reading only anchor heads it receives (never the guard's store).
    If a stream that is expected to be active has not advanced in `silence_s`, the verdict is
    TREAT_AS_CONTAINED. A monitor that goes quiet is the oldest sign that a monitor was turned off, and the
    correct default is the closed one. If a head ever goes backwards, that is a rollback, and it is worse."""

    def __init__(self, *, silence_s: float, clock: Callable[[], float] = time.time):
        self.silence, self.clock = silence_s, clock
        self.heads: dict[str, tuple[int, str, float]] = {}       # user -> (seq, sha, ts_seen)
        self.expected_active: set[str] = set()

    def expect(self, user_id: str) -> None: self.expected_active.add(user_id)

    def observe(self, user_id: str, seq: int, sha256: str) -> WatchVerdict:
        now = self.clock(); prev = self.heads.get(user_id)
        if prev and seq < prev[0]:
            return WatchVerdict(user_id, "rolled_back", seq, 0.0, "TREAT_AS_CONTAINED")
        if prev and seq == prev[0] and sha256 != prev[1]:
            return WatchVerdict(user_id, "rolled_back", seq, 0.0, "TREAT_AS_CONTAINED")   # same seq, different content
        self.heads[user_id] = (seq, sha256, now)
        return WatchVerdict(user_id, "alive", seq, 0.0, "none")

    def check(self) -> list[WatchVerdict]:
        now = self.clock(); out = []
        for u in sorted(self.expected_active):
            h = self.heads.get(u)
            if h is None:
                out.append(WatchVerdict(u, "silent", None, None, "TREAT_AS_CONTAINED")); continue
            gap = now - h[2]
            out.append(WatchVerdict(u, "silent" if gap > self.silence else "alive", h[0], round(gap, 1),
                                    "TREAT_AS_CONTAINED" if gap > self.silence else "none"))
        return out


# --------------------------------------------------------------------------- 3. guard attestation
ATTEST_FILES = ("01_lib/glitch_runtime_harness.py", "01_lib/alignment_guard_v343.py", "05_deploy/glitch_scorer.py",
                "02_canvas/glitch_canvas_runtime.json", "02_canvas/glitch_canvas_model.json", "08_incident/incident.py")


def attest(root: str = _R) -> dict[str, str]:
    """sha256 of the code and canvas that produced any evidence. Include this in the seal; publish the expected
    values somewhere the operator cannot edit after the fact."""
    out = {}
    for rel in ATTEST_FILES:
        p = Path(root) / rel
        out[rel] = hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "MISSING"
    return out


def check_attestation(observed: dict[str, str], expected: dict[str, str]) -> dict[str, Any]:
    problems = [f"{k}: {observed.get(k, 'ABSENT')[:12]} != expected {v[:12]}" for k, v in expected.items() if observed.get(k) != v]
    return {"valid": not problems, "problems": problems, "files_checked": len(expected)}


# --------------------------------------------------------------------------- 4. incident -> canvas scenario
def bundle_to_fixture(bundle: dict[str, Any], user_id: str, *, scenario_id: str, required_level: int) -> dict[str, Any]:
    """Turn one user's sealed trajectory into a canvas scenario: specificity levels only, from the audit
    envelopes' committed purpose_gap. No text, no payloads, no identifiers beyond the scenario id.

    LIMIT: the audit envelope records purpose_gap, not the raw level, so turns AT OR BELOW purpose are
    reconstructed as the purpose level. The above-purpose shape (what tripwires respond to) is preserved
    exactly; the below-purpose shape is flattened. This is the price of not putting raw scores in the audit."""
    e = bundle["users"][user_id]
    turns = sorted((env for env in e.get("pending_audit", []) if env.get("type") == "turn"), key=lambda x: x["pos"])
    if not turns: raise ValueError("no turn envelopes in this user's pending audit; seal earlier next time")
    specs = [int(t["purpose_gap"]) + required_level for t in turns]          # gap is committed; level = gap + baseline
    fired = {t["pos"]: t.get("tripwires", []) for t in turns}
    first = {}
    for pos in sorted(fired):
        for tw in fired[pos]:
            first.setdefault(tw, pos)
    return {"id": scenario_id, "source": f"incident {bundle['incident']['incident_id']} (levels only)",
            "declared_purpose": "incident-derived; purpose text withheld", "required_level": required_level,
            "turns": [{"spec": s} for s in specs],
            "expected": {tw: {"first_fire": first.get(tw)} for tw in ("TW01", "TW03")}}


# --------------------------------------------------------------------------- 5. canary diff
def canary_diff(log_a: Iterable[dict], log_b: Iterable[dict]) -> dict[str, Any]:
    """Two shadow-proxy logs on the same traffic (same users/sessions/turns). Reports trajectories where
    B fired a tripwire A did not, and vice versa, plus the purpose-gap delta. A version that regresses shows
    up here before anyone ships it."""
    def index(log):
        out = {}
        for row in log:
            if "tripwires" not in row: continue
            out[(row.get("user"), row.get("session"), row.get("turn"))] = row
        return out
    A, B = index(log_a), index(log_b)
    keys = sorted(set(A) | set(B), key=lambda k: (str(k[0]), str(k[1]), k[2] or 0))
    new_in_b, gone_in_b, gap_delta = [], [], []
    for k in keys:
        a, b = A.get(k), B.get(k)
        if a is None or b is None: continue
        ta, tb = set(a["tripwires"]), set(b["tripwires"])
        if tb - ta: new_in_b.append({"key": k, "fired": sorted(tb - ta)})
        if ta - tb: gone_in_b.append({"key": k, "fired": sorted(ta - tb)})
        ga, gb = a.get("purpose_gap"), b.get("purpose_gap")
        if ga is not None and gb is not None and ga != gb: gap_delta.append({"key": k, "a": ga, "b": gb})
    return {"compared": len(set(A) & set(B)), "only_in_a": len(set(A) - set(B)), "only_in_b": len(set(B) - set(A)),
            "new_tripwires_in_b": new_in_b, "tripwires_gone_in_b": gone_in_b, "purpose_gap_changes": gap_delta,
            "verdict": "B_REGRESSED" if new_in_b else ("B_IMPROVED" if gone_in_b else "NO_CHANGE"),
            "note": "a shape comparison of tripwire profiles; it does not say which version is right, only which one moved"}
