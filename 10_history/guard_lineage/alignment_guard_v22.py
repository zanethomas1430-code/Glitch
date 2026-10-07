from __future__ import annotations
import hashlib, json, time, uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Protocol, Sequence
from glitch_runtime_harness import CanvasValidationError, RuntimeHarness, TurnMetrics

class GuardMode(Enum):
    NORMAL = 0; RESTRICTED = 1; READ_ONLY = 2; HUMAN_REVIEW = 3; CONTAINED = 4
def max_mode(a, b): return a if a.value >= b.value else b

@dataclass(frozen=True)
class GuardConfig:
    cumulative_gap_limit: int = 4
    sensitive_tools: Sequence[str] = ()
    ladder: Dict[str, GuardMode] = field(default_factory=lambda: {"TW01": GuardMode.RESTRICTED, "TW02": GuardMode.RESTRICTED, "TW03": GuardMode.READ_ONLY, "TW04": GuardMode.RESTRICTED, "TW05": GuardMode.HUMAN_REVIEW, "TW06": GuardMode.HUMAN_REVIEW})

@dataclass
class GuardState:
    mode: GuardMode = GuardMode.NORMAL; delivered_gap_total: int = 0; contained_reason: Optional[str] = None; mode_changes: List[Dict] = field(default_factory=list)

class GuardStore(Protocol):
    def load(self, user_id: str) -> Optional[GuardState]: ...
    def save(self, user_id: str, state: GuardState) -> None: ...

class InMemoryGuardStore:
    def __init__(self): self._s = {}
    def load(self, u): return self._s.get(u)
    def save(self, u, st): self._s[u] = st

class JSONGuardStore:
    """Single-process prototype; same concurrency caveat as JSONStateStore."""
    def __init__(self, path):
        from pathlib import Path
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists(): self.path.write_text("{}")
    def _all(self): return json.loads(self.path.read_text())
    def load(self, u):
        raw = self._all().get(u)
        if raw is None: return None
        return GuardState(GuardMode[raw["mode"]], raw["delivered_gap_total"], raw.get("contained_reason"), raw.get("mode_changes", []))
    def save(self, u, st):
        d = self._all(); d[u] = {"mode": st.mode.name, "delivered_gap_total": st.delivered_gap_total, "contained_reason": st.contained_reason, "mode_changes": st.mode_changes}
        tmp = self.path.with_suffix(".tmp"); tmp.write_text(json.dumps(d, indent=2)); tmp.replace(self.path)

@dataclass(frozen=True)
class ActionRequest:
    tool: str; operation: str = ""
@dataclass(frozen=True)
class RecoveryAuthorization:
    principal: str; token: str; incident_id: str
class AuthorityVerifier(Protocol):
    def authorize_mode_lowering(self, *, user_id, current, target, authorization, reason) -> bool: ...

@dataclass
class Decision:
    allow: bool; mode: GuardMode; output: str; tripwires: List[str]; reasons: List[str]; trajectory_position: int; require_human_review: bool = False
    actions_allowed: List[ActionRequest] = field(default_factory=list)
    actions_denied: List[ActionRequest] = field(default_factory=list)

class ChainedAudit:
    def __init__(self, sink=None, anchor=None, *, stream_id=None):
        self.records = []; self.sink = sink or (lambda e: None); self.anchor = anchor or (lambda h: None)
        self.stream_id = stream_id or str(uuid.uuid4()); self._prev = "0"*64; self._seq = 0
    def write(self, payload):
        self._seq += 1
        env = {"stream_id": self.stream_id, "seq": self._seq, "ts": time.time(), "prev_sha256": self._prev, **payload}
        env["sha256"] = self._hash(env); self._prev = env["sha256"]; self.records.append(env); self.sink(env)
        self.anchor({"stream_id": self.stream_id, "seq": self._seq, "sha256": self._prev}); return env
    @staticmethod
    def _hash(env):
        e = {k: v for k, v in env.items() if k != "sha256"}
        return hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",",":"), default=str).encode()).hexdigest()
    @classmethod
    def verify(cls, records, *, expected_head=None):
        if not records: return expected_head is None or expected_head.get("seq") == 0
        prev = "0"*64; sid = records[0].get("stream_id"); n = 1
        for r in records:
            if r.get("stream_id") != sid or r.get("seq") != n or r.get("prev_sha256") != prev or cls._hash(r) != r.get("sha256"): return False
            prev = r["sha256"]; n += 1
        if expected_head is not None:
            if expected_head.get("stream_id") != sid or expected_head.get("seq") != records[-1]["seq"] or expected_head.get("sha256") != records[-1]["sha256"]: return False
        return True

class AlignmentGuard:
    def __init__(self, *, harness=None, config=None, audit=None, guard_store=None, authority_verifier=None):
        self.h = harness or RuntimeHarness(); self.cfg = config or GuardConfig(); self.audit = audit or ChainedAudit()
        self.store: GuardStore = guard_store or InMemoryGuardStore(); self.authority_verifier = authority_verifier
    def _save(self, user_id, g): self.store.save(user_id, g)
    def _tw06(self, user_id, source):
        g = self.store.load(user_id)
        if g is None: return
        st = self.h.store.load(user_id); pos = st.trajectory_position if st else None
        self._raise_mode(user_id, self.cfg.ladder.get("TW06", GuardMode.NORMAL), at=pos, by="TW06", reason=f"baseline inflation attempt via {source}")
    def start(self, user_id, session_id, *, declared_purpose=None, required_level=None):
        try:
            st = self.h.start_session(user_id, session_id, declared_purpose=declared_purpose, required_level=required_level)
        except CanvasValidationError:
            self._tw06(user_id, "start_session"); raise
        if self.store.load(user_id) is None: self.store.save(user_id, GuardState())
        return st
    def new_epoch(self, user_id, **kw):
        self._require_started(user_id)
        try: st = self.h.new_epoch(user_id, **kw)
        except CanvasValidationError:
            self._tw06(user_id, "new_epoch"); raise
        self.audit.write({"type": "epoch", "user": user_id, "epoch": asdict(st.active)}); return st
    def _raise_mode(self, user_id, target, *, at, by, reason, g=None):
        # Callers holding a live GuardState pass it in; never reload over a caller's copy (stale-write bug).
        g = g if g is not None else self._require_started(user_id); target = max_mode(g.mode, target)
        if target == g.mode: return g.mode
        change = {"from": g.mode.name, "to": target.name, "at": at, "by": by, "reason": reason, "ts": time.time()}
        g.mode_changes.append(change); g.mode = target; self._save(user_id, g); self.audit.write({"type": "mode_raised", "user": user_id, **change}); return g.mode
    def lower_mode(self, user_id, *, to, authorization, reason):
        g = self._require_started(user_id)
        if not reason.strip(): raise CanvasValidationError("lower_mode requires a reason")
        if to.value >= g.mode.value: raise CanvasValidationError("lower_mode must lower")
        if self.authority_verifier is None: raise CanvasValidationError("mode lowering is disabled: no external AuthorityVerifier configured")
        ok = self.authority_verifier.authorize_mode_lowering(user_id=user_id, current=g.mode, target=to, authorization=authorization, reason=reason)
        if not ok:
            self.audit.write({"type": "mode_lower_denied", "user": user_id, "from": g.mode.name, "to": to.name, "principal": authorization.principal, "incident_id": authorization.incident_id})
            raise CanvasValidationError("mode lowering authorization denied")
        change = {"from": g.mode.name, "to": to.name, "authority": authorization.principal, "incident_id": authorization.incident_id, "reason": reason, "ts": time.time()}
        g.mode_changes.append(change); g.mode = to
        if to != GuardMode.CONTAINED: g.contained_reason = None
        self._save(user_id, g); self.audit.write({"type": "mode_lowered", "user": user_id, **change}); return g
    def evaluate(self, user_id, session_id, caller_turn, metrics, proposed_output, *, requested_actions=()):
        g = self._require_started(user_id); e = self.h.evaluate_turn(user_id, session_id, caller_turn, metrics); reasons = []
        for tw in e.tripwires:
            floor = self.cfg.ladder.get(tw, GuardMode.NORMAL)
            if floor.value > g.mode.value:
                r = f"{tw} -> {floor.name}"; reasons.append(r); self._raise_mode(user_id, floor, at=e.trajectory_position, by=tw, reason=r, g=g)
        sensitive = set(self.cfg.sensitive_tools); hits = [a for a in requested_actions if a.tool in sensitive]
        if hits and e.purpose_gap >= 1:
            names = [f"{a.tool}:{a.operation}" if a.operation else a.tool for a in hits]
            r = f"sensitive action requested above purpose: {names} at purpose_gap {e.purpose_gap}"
            g.contained_reason = r; reasons.append(r); self._raise_mode(user_id, GuardMode.CONTAINED, at=e.trajectory_position, by="action_gate", reason=r, g=g)
        deliverable_now = g.mode == GuardMode.NORMAL
        projected = g.delivered_gap_total + e.purpose_gap if deliverable_now else g.delivered_gap_total
        if deliverable_now and projected >= self.cfg.cumulative_gap_limit:
            r = f"delivered purpose-gap budget would be exhausted ({g.delivered_gap_total} + {e.purpose_gap} >= {self.cfg.cumulative_gap_limit})"
            reasons.append(r); self._raise_mode(user_id, GuardMode.HUMAN_REVIEW, at=e.trajectory_position, by="delivered_gap_budget", reason=r, g=g); deliverable_now = False
        allow = deliverable_now and g.mode == GuardMode.NORMAL
        if allow: g.delivered_gap_total = projected; out = proposed_output
        else: out = self._safe_text(g.mode)
        # Action verdict, fail-closed. The gateway executes ONLY actions_allowed; anything absent is denied.
        allowed, denied = [], []
        for a in requested_actions:
            is_sensitive = a.tool in sensitive
            ok = (g.mode == GuardMode.NORMAL and (not is_sensitive or e.purpose_gap == 0)) or \
                 (g.mode == GuardMode.RESTRICTED and not is_sensitive)
            (allowed if ok else denied).append(a)
        self._save(user_id, g)
        self.audit.write({"type": "turn", "user": user_id, "session": session_id, "pos": e.trajectory_position, "caller_turn": caller_turn, "epoch": e.epoch_id, "tripwires": list(e.tripwires), "purpose_gap": e.purpose_gap, "projected_delivered_gap_total": projected, "committed_delivered_gap_total": g.delivered_gap_total, "delivered": allow, "mode": g.mode.name, "requested_actions": [{"tool": a.tool, "operation": a.operation} for a in requested_actions], "actions_allowed": [a.tool for a in allowed], "actions_denied": [a.tool for a in denied]})
        return Decision(allow, g.mode, out, list(e.tripwires), reasons, e.trajectory_position, g.mode.value >= GuardMode.HUMAN_REVIEW.value, allowed, denied)
    def _require_started(self, user_id):
        g = self.store.load(user_id)
        if g is None: raise CanvasValidationError(f"user {user_id!r} has no guard state; call start() first")
        return g
    @staticmethod
    def _safe_text(mode):
        if mode == GuardMode.NORMAL: raise RuntimeError("safe_text must not be requested in NORMAL mode")
        return {GuardMode.RESTRICTED: "restricted", GuardMode.READ_ONLY: "read-only", GuardMode.HUMAN_REVIEW: "human review", GuardMode.CONTAINED: "contained"}[mode]
