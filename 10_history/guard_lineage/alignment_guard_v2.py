"""ALIGNMENT_GUARD v2: your mode ladder and containment, on top of the GLITCH harness.

What changed from v1 and why (each maps to a probe that failed):
  P1/P2  containment keys on what outputs ENABLE (scorer levels, purpose gap) and on ACTIONS
         (tool authority), never on words in user text. User text is not model behavior.
  P3     the monitor is the independent scorer's TurnMetrics; no keywords anywhere.
  P4     mode only ratchets up (max_mode). Only a named authority can lower it.
  P5     capability accumulates on DELIVERED outputs only; blocked turns transfer nothing.
  P6     epochs go through RuntimeHarness.new_epoch: named non-client authority, reason,
         user evidence. required_level feeds purpose_gap, which drives everything.
  P7     audit records are hash-chained; deletion or reordering breaks verification.
  --     no transcript stored; per-user state via StateStore; trajectory clock survives retention.
"""
from __future__ import annotations

import hashlib, json, time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, Dict, List, Optional, Sequence

from glitch_runtime_harness import (CanvasValidationError, RuntimeHarness, TurnMetrics, ThresholdConfig,
                                    RetentionPolicy, StateStore, InMemoryStateStore, CLIENT_AUTHORITIES)


class GuardMode(Enum):
    NORMAL = 0; RESTRICTED = 1; READ_ONLY = 2; HUMAN_REVIEW = 3; CONTAINED = 4


def max_mode(a: GuardMode, b: GuardMode) -> GuardMode:
    return a if a.value >= b.value else b


@dataclass(frozen=True)
class GuardConfig:
    # Delivered-capability budget: sum of purpose_gap over delivered turns.
    cumulative_gap_limit: int = 4
    # Tools the deployment considers sensitive; any request to use one while above purpose escalates.
    sensitive_tools: Sequence[str] = ()
    # Mode ladder: tripwire -> minimum mode. Containment is reserved for ACTIONS, not text.
    ladder: Dict[str, GuardMode] = field(default_factory=lambda: {
        "TW01": GuardMode.RESTRICTED, "TW02": GuardMode.RESTRICTED, "TW03": GuardMode.READ_ONLY,
        "TW04": GuardMode.RESTRICTED, "TW05": GuardMode.HUMAN_REVIEW, "TW06": GuardMode.HUMAN_REVIEW})


@dataclass
class GuardState:
    mode: GuardMode = GuardMode.NORMAL
    delivered_gap_total: int = 0
    contained_reason: Optional[str] = None
    mode_changes: List[Dict] = field(default_factory=list)


@dataclass
class Decision:
    allow: bool
    mode: GuardMode
    output: str
    tripwires: List[str]
    reasons: List[str]
    trajectory_position: int
    require_human_review: bool = False


class ChainedAudit:
    """Hash-chained audit log. Each record commits to the previous record's hash."""
    def __init__(self, sink: Optional[Callable[[Dict], None]] = None):
        self.records: List[Dict] = []; self.sink = sink or (lambda e: None); self._prev = "0" * 64
    def write(self, payload: Dict) -> Dict:
        env = {"ts": time.time(), "prev_sha256": self._prev, **payload}
        env["sha256"] = self._hash(env); self._prev = env["sha256"]
        self.records.append(env); self.sink(env); return env
    @staticmethod
    def _hash(env: Dict) -> str:
        e = {k: v for k, v in env.items() if k != "sha256"}
        return hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    @classmethod
    def verify(cls, records: List[Dict]) -> bool:
        prev = "0" * 64
        for r in records:
            if r.get("prev_sha256") != prev or cls._hash(r) != r.get("sha256"): return False
            prev = r["sha256"]
        return True


class AlignmentGuard:
    def __init__(self, *, harness: Optional[RuntimeHarness] = None, config: GuardConfig = GuardConfig(),
                 audit: Optional[ChainedAudit] = None, guard_store: Optional[Dict[str, GuardState]] = None):
        self.h = harness or RuntimeHarness(); self.cfg = config; self.audit = audit or ChainedAudit()
        self._guard: Dict[str, GuardState] = guard_store if guard_store is not None else {}

    # ---- purpose / authority: all through the harness, never a boolean ----
    def start(self, user_id: str, session_id: str, *, declared_purpose: Optional[str] = None, required_level: Optional[int] = None):
        st = self.h.start_session(user_id, session_id, declared_purpose=declared_purpose, required_level=required_level)
        self._guard.setdefault(user_id, GuardState()); return st

    def new_epoch(self, user_id: str, **kw):
        st = self.h.new_epoch(user_id, **kw)
        self.audit.write({"type": "epoch", "user": user_id, "epoch": asdict(st.active)}); return st

    def lower_mode(self, user_id: str, *, to: GuardMode, authority: str, reason: str) -> GuardState:
        """The only way down the ladder. A model response cannot call this; the client channel cannot either."""
        if authority.strip().lower() in CLIENT_AUTHORITIES or not reason.strip():
            raise CanvasValidationError("lower_mode requires a named non-client authority and a reason")
        g = self._guard[user_id]
        if to.value >= g.mode.value: raise CanvasValidationError("lower_mode must lower")
        g.mode_changes.append({"from": g.mode.name, "to": to.name, "authority": authority, "reason": reason, "ts": time.time()})
        self.audit.write({"type": "mode_lowered", "user": user_id, **g.mode_changes[-1]})
        g.mode = to; return g

    # ---- evaluation: metrics come from the INDEPENDENT scorer, never from text here ----
    def evaluate(self, user_id: str, session_id: str, caller_turn: int, metrics: TurnMetrics, proposed_output: str,
                 *, requested_tools: Sequence[str] = ()) -> Decision:
        g = self._guard[user_id]
        e = self.h.evaluate_turn(user_id, session_id, caller_turn, metrics)
        reasons: List[str] = []
        new_mode = g.mode
        for tw in e.tripwires:
            floor = self.cfg.ladder.get(tw, GuardMode.NORMAL)
            if floor.value > new_mode.value: reasons.append(f"{tw} -> {floor.name}")
            new_mode = max_mode(new_mode, floor)
        # Containment is for ACTIONS: a sensitive tool requested while output exceeds purpose.
        hit = [t for t in requested_tools if t in self.cfg.sensitive_tools]
        if hit and e.purpose_gap >= 1:
            new_mode = GuardMode.CONTAINED; g.contained_reason = f"sensitive tool {hit} requested at purpose_gap {e.purpose_gap}"
            reasons.append(g.contained_reason)
        if new_mode != g.mode:
            g.mode_changes.append({"from": g.mode.name, "to": new_mode.name, "at": e.trajectory_position, "by": "evaluate"})
        g.mode = max_mode(g.mode, new_mode)   # ratchet: never down here
        allow = g.mode == GuardMode.NORMAL
        if allow:
            g.delivered_gap_total += e.purpose_gap                        # only delivered capability counts
            if g.delivered_gap_total >= self.cfg.cumulative_gap_limit:
                g.mode = max_mode(g.mode, GuardMode.HUMAN_REVIEW); allow = False
                reasons.append(f"delivered purpose-gap budget exhausted ({g.delivered_gap_total})")
        out = proposed_output if allow else self._safe_text(g.mode)
        self.audit.write({"type": "turn", "user": user_id, "session": session_id, "pos": e.trajectory_position,
                          "caller_turn": caller_turn, "epoch": e.epoch_id, "tripwires": e.tripwires,
                          "purpose_gap": e.purpose_gap, "delivered": allow, "mode": g.mode.name})
        return Decision(allow, g.mode, out, e.tripwires, reasons, e.trajectory_position,
                        require_human_review=g.mode.value >= GuardMode.HUMAN_REVIEW.value)

    @staticmethod
    def _safe_text(mode: GuardMode) -> str:
        return {GuardMode.RESTRICTED: "I can discuss this at the level your stated purpose requires, but not beyond it.",
                GuardMode.READ_ONLY: "Continuing in non-operational mode pending review of this conversation's trajectory.",
                GuardMode.HUMAN_REVIEW: "This conversation is paused for human review.",
                GuardMode.CONTAINED: "Containment: external actions and sensitive tools are disabled; control transfers to a human responder."}[mode]
