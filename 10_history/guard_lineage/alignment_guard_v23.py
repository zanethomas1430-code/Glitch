"""ALIGNMENT_GUARD v2.3 — one consistency domain, pure transitions, commit-before-release.

Invariant: nothing leaves the containment boundary (output text, allowed actions) until the
safety decision and the durable state transition have both committed atomically.

Pipeline:
  TurnMetrics -> GLITCH evaluation on a COPY of harness state -> pure GuardTransition
  -> candidate {old, new, decision, audit events} -> compare-and-swap commit of ONE record
  (harness state + guard state + audit cursor) -> only then release.

Review items closed: 1 CAS with retry; 2 single record spans harness+guard; 3 idempotent start via
CAS create; 4/5 capability-based action policy, unknown actions denied; 6 baseline_inflation_rejected
event; 7 audit cursor persisted in the record; 8 authorization handle, no secret in the guard;
9 budget >= fixture; 10 containment reason+mode in one transition.
"""
from __future__ import annotations

import copy, hashlib, json, time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Protocol, Sequence, Tuple

from glitch_runtime_harness import (CanvasValidationError, InMemoryStateStore, RuntimeHarness, ThresholdConfig,
                                    RetentionPolicy, TurnMetrics, UserState, _state_from_raw)

MAX_RETRIES = 8


class GuardMode(Enum):
    NORMAL = 0; RESTRICTED = 1; READ_ONLY = 2; HUMAN_REVIEW = 3; CONTAINED = 4
def max_mode(a, b): return a if a.value >= b.value else b


class Capability(Enum):
    READ = "read"; WRITE = "write"; NETWORK = "network"; EXECUTE = "execute"; CREDENTIAL = "credential"; ACTUATE = "actuate"
SENSITIVE_CAPS = frozenset({Capability.WRITE, Capability.NETWORK, Capability.EXECUTE, Capability.CREDENTIAL, Capability.ACTUATE})


@dataclass(frozen=True)
class ActionRequest:
    tool: str; operation: str = ""


@dataclass(frozen=True)
class ActionPolicy:
    """Every executable action must be registered with its effects. Unknown -> denied."""
    registry: Dict[str, FrozenSet[Capability]] = field(default_factory=dict)
    def caps(self, tool: str) -> Optional[FrozenSet[Capability]]: return self.registry.get(tool)


@dataclass(frozen=True)
class GuardConfig:
    cumulative_gap_limit: int = 4   # >= : a limit of 4 delivers at most 3 gap units. Fixture-locked.
    policy: ActionPolicy = field(default_factory=ActionPolicy)
    ladder: Dict[str, GuardMode] = field(default_factory=lambda: {
        "TW01": GuardMode.RESTRICTED, "TW02": GuardMode.RESTRICTED, "TW03": GuardMode.READ_ONLY,
        "TW04": GuardMode.RESTRICTED, "TW05": GuardMode.HUMAN_REVIEW, "TW06": GuardMode.HUMAN_REVIEW})
    threshold: ThresholdConfig = ThresholdConfig()
    retention: Optional[RetentionPolicy] = None


@dataclass
class GuardState:
    mode: GuardMode = GuardMode.NORMAL
    delivered_gap_total: int = 0
    contained_reason: Optional[str] = None
    mode_changes: List[Dict] = field(default_factory=list)


@dataclass
class AuditCursor:
    stream_id: str; seq: int = 0; prev_sha256: str = "0" * 64


@dataclass
class UserRecord:
    """The single consistency domain: harness trajectory + guard verdict + this user's audit cursor."""
    version: int
    harness: Dict[str, Any]          # serialized UserState
    guard: GuardState
    audit: AuditCursor


@dataclass(frozen=True)
class RecoveryAuthorization:
    principal: str; handle: str; incident_id: str    # handle is an opaque reference; the secret never enters the guard


class AuthorityVerifier(Protocol):
    def authorize_mode_lowering(self, *, user_id, current, target, authorization, reason) -> bool: ...


@dataclass
class Decision:
    allow: bool; mode: GuardMode; output: str; tripwires: List[str]; reasons: List[str]; trajectory_position: int
    require_human_review: bool = False
    actions_allowed: List[ActionRequest] = field(default_factory=list)
    actions_denied: List[ActionRequest] = field(default_factory=list)
    committed_version: int = 0


class ConcurrentStateError(RuntimeError): ...


# --------------------------------------------------------------------------- store
class RecordStore(Protocol):
    def load(self, user_id: str) -> Optional[UserRecord]: ...
    def compare_and_swap(self, user_id: str, expected_version: Optional[int], new: UserRecord) -> bool: ...


def _rec_to_raw(r: UserRecord) -> Dict:
    g = asdict(r.guard); g["mode"] = r.guard.mode.name
    return {"version": r.version, "harness": r.harness, "guard": g, "audit": asdict(r.audit)}

def _raw_to_rec(raw: Dict) -> UserRecord:
    g = dict(raw["guard"]); g["mode"] = GuardMode[g["mode"]]
    return UserRecord(raw["version"], raw["harness"], GuardState(**g), AuditCursor(**raw["audit"]))


class InMemoryRecordStore:
    def __init__(self): self._s: Dict[str, Dict] = {}
    def load(self, u): return _raw_to_rec(copy.deepcopy(self._s[u])) if u in self._s else None
    def compare_and_swap(self, u, expected_version, new):
        cur = self._s.get(u)
        if (cur is None and expected_version is not None) or (cur is not None and cur["version"] != expected_version): return False
        self._s[u] = _rec_to_raw(new); return True


class JSONRecordStore:
    """Single-process prototype. CAS is correct within one process; across processes you need a DB."""
    def __init__(self, path):
        from pathlib import Path
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists(): self.path.write_text("{}")
    def _all(self): return json.loads(self.path.read_text())
    def load(self, u):
        raw = self._all().get(u); return None if raw is None else _raw_to_rec(raw)
    def compare_and_swap(self, u, expected_version, new):
        d = self._all(); cur = d.get(u)
        if (cur is None and expected_version is not None) or (cur is not None and cur["version"] != expected_version): return False
        d[u] = _rec_to_raw(new); tmp = self.path.with_suffix(".tmp"); tmp.write_text(json.dumps(d, indent=2)); tmp.replace(self.path); return True


# --------------------------------------------------------------------------- audit (cursor lives in the record)
def _hash(env: Dict) -> str:
    e = {k: v for k, v in env.items() if k != "sha256"}
    return hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

def chain(cursor: AuditCursor, payloads: List[Dict]) -> Tuple[AuditCursor, List[Dict]]:
    """Pure: returns the advanced cursor and the chained envelopes. Nothing is emitted here."""
    seq, prev, out = cursor.seq, cursor.prev_sha256, []
    for p in payloads:
        seq += 1
        env = {"stream_id": cursor.stream_id, "seq": seq, "ts": time.time(), "prev_sha256": prev, **p}
        env["sha256"] = _hash(env); prev = env["sha256"]; out.append(env)
    return AuditCursor(cursor.stream_id, seq, prev), out

def verify_chain(records: List[Dict], *, expected_head: Optional[Dict] = None) -> bool:
    if not records: return expected_head is None or expected_head.get("seq") == 0
    prev, sid, n = "0" * 64, records[0]["stream_id"], records[0]["seq"]
    if n != 1 and expected_head is None: pass   # partial chains verify internally only
    for r in records:
        if r["stream_id"] != sid or r["seq"] != n or r["prev_sha256"] != prev or _hash(r) != r["sha256"]: return False
        prev, n = r["sha256"], n + 1
    return expected_head is None or (expected_head["stream_id"] == sid and expected_head["seq"] == records[-1]["seq"] and expected_head["sha256"] == records[-1]["sha256"])


# --------------------------------------------------------------------------- pure transition
@dataclass
class Candidate:
    old: UserRecord; new: UserRecord; decision: Decision; events: List[Dict]


def derive_transition(cfg: GuardConfig, user_id: str, session_id: str, caller_turn: int, rec: UserRecord,
                      metrics: TurnMetrics, proposed_output: str, requested: Sequence[ActionRequest]) -> Candidate:
    # 1. GLITCH evaluation on a copy of harness state (no shared store; nothing committed).
    hstore = InMemoryStateStore(); hstore.save(user_id, _state_from_raw(copy.deepcopy(rec.harness)))
    h = RuntimeHarness(config=cfg.threshold, store=hstore, retention=cfg.retention)
    h.start_session(user_id, session_id)
    e = h.evaluate_turn(user_id, session_id, caller_turn, metrics)
    new_h = asdict(hstore.load(user_id))
    # 2. Guard transition, pure.
    g = copy.deepcopy(rec.guard); reasons: List[str] = []; payloads: List[Dict] = []
    def raise_to(target, by, reason):
        t = max_mode(g.mode, target)
        if t == g.mode: return
        ch = {"from": g.mode.name, "to": t.name, "at": e.trajectory_position, "by": by, "reason": reason, "ts": time.time()}
        g.mode_changes.append(ch); g.mode = t; payloads.append({"type": "mode_raised", "user": user_id, **ch})
    for tw in e.tripwires:
        floor = cfg.ladder.get(tw, GuardMode.NORMAL)
        if floor.value > g.mode.value: reasons.append(f"{tw} -> {floor.name}"); raise_to(floor, tw, reasons[-1])
    # 3. Action verdicts by capability; unknown denied; sensitive above purpose contains (reason+mode in one step).
    allowed, denied, contain_hits = [], [], []
    for a in requested:
        caps = cfg.policy.caps(a.tool)
        if caps is None: denied.append(a); continue
        sensitive = bool(caps & SENSITIVE_CAPS)
        if sensitive and e.purpose_gap >= 1: contain_hits.append(a)
    if contain_hits:
        r = f"sensitive action above purpose: {[a.tool for a in contain_hits]} at purpose_gap {e.purpose_gap}"
        g.contained_reason = r; reasons.append(r); raise_to(GuardMode.CONTAINED, "action_gate", r)
    # 4. Delivered-gap budget, transactional (>= blocks the exhausting turn).
    deliverable = g.mode == GuardMode.NORMAL
    projected = g.delivered_gap_total + e.purpose_gap if deliverable else g.delivered_gap_total
    if deliverable and projected >= cfg.cumulative_gap_limit:
        r = f"delivered purpose-gap budget would be exhausted ({g.delivered_gap_total} + {e.purpose_gap} >= {cfg.cumulative_gap_limit})"
        reasons.append(r); raise_to(GuardMode.HUMAN_REVIEW, "delivered_gap_budget", r); deliverable = False
    allow = deliverable and g.mode == GuardMode.NORMAL
    if allow: g.delivered_gap_total = projected
    # final action verdicts against the post-transition mode
    allowed, denied = [], []
    for a in requested:
        caps = cfg.policy.caps(a.tool)
        if caps is None: denied.append(a); continue
        sensitive = bool(caps & SENSITIVE_CAPS)
        ok = (g.mode == GuardMode.NORMAL and (not sensitive or e.purpose_gap == 0)) or \
             (g.mode == GuardMode.RESTRICTED and caps <= {Capability.READ})
        (allowed if ok else denied).append(a)
    out = proposed_output if allow else _safe_text(g.mode)
    payloads.append({"type": "turn", "user": user_id, "session": session_id, "pos": e.trajectory_position, "caller_turn": caller_turn,
                     "epoch": e.epoch_id, "tripwires": list(e.tripwires), "purpose_gap": e.purpose_gap, "delivered": allow,
                     "committed_delivered_gap_total": g.delivered_gap_total, "mode": g.mode.name,
                     "actions_allowed": [a.tool for a in allowed], "actions_denied": [a.tool for a in denied]})
    cursor, events = chain(rec.audit, payloads)
    new = UserRecord(rec.version + 1, new_h, g, cursor)
    dec = Decision(allow, g.mode, out, list(e.tripwires), reasons, e.trajectory_position, g.mode.value >= GuardMode.HUMAN_REVIEW.value, allowed, denied)
    return Candidate(rec, new, dec, events)


def _safe_text(mode: GuardMode) -> str:
    if mode == GuardMode.NORMAL: raise RuntimeError("safe_text must not be requested in NORMAL mode")
    return {GuardMode.RESTRICTED: "I can discuss this only at the level required by the authorized purpose, not beyond it.",
            GuardMode.READ_ONLY: "Continuing in non-operational mode while this trajectory is reviewed.",
            GuardMode.HUMAN_REVIEW: "This interaction requires human review before operational assistance can continue.",
            GuardMode.CONTAINED: "Containment is active. External actions and sensitive tools remain disabled; control transfers to an authorized responder."}[mode]


# --------------------------------------------------------------------------- guard
class AlignmentGuard:
    def __init__(self, *, config: Optional[GuardConfig] = None, store: Optional[RecordStore] = None,
                 audit_sink=None, anchor=None, authority_verifier: Optional[AuthorityVerifier] = None):
        self.cfg = config or GuardConfig(); self.store = store or InMemoryRecordStore()
        self.sink = audit_sink or (lambda e: None); self.anchor = anchor or (lambda h: None); self.verifier = authority_verifier

    def _emit(self, events: List[Dict], cursor: AuditCursor):
        for ev in events: self.sink(ev)
        if events: self.anchor({"stream_id": cursor.stream_id, "seq": cursor.seq, "sha256": cursor.prev_sha256})

    def _commit(self, user_id: str, cand: Candidate) -> bool:
        return self.store.compare_and_swap(user_id, cand.old.version, cand.new)

    # -- idempotent start: one CAS creates harness state, guard state, and audit cursor together
    def start(self, user_id: str, session_id: str, *, declared_purpose=None, required_level=None) -> UserRecord:
        for _ in range(MAX_RETRIES):
            rec = self.store.load(user_id)
            if rec is None:
                hs = InMemoryStateStore(); RuntimeHarness(config=self.cfg.threshold, store=hs).start_session(
                    user_id, session_id, declared_purpose=declared_purpose, required_level=required_level)
                new = UserRecord(1, asdict(hs.load(user_id)), GuardState(), AuditCursor(stream_id=f"{user_id}:{hashlib.sha256(user_id.encode()).hexdigest()[:8]}"))
                if self.store.compare_and_swap(user_id, None, new): return new
                continue   # someone else created it; loop and treat as existing
            hs = InMemoryStateStore(); hs.save(user_id, _state_from_raw(copy.deepcopy(rec.harness)))
            h = RuntimeHarness(config=self.cfg.threshold, store=hs)
            try:
                h.start_session(user_id, session_id, declared_purpose=declared_purpose, required_level=required_level)
            except CanvasValidationError as ex:
                if self._record_inflation(user_id, rec, hs.load(user_id), "start_session", required_level): raise
                continue
            after = asdict(hs.load(user_id))
            if after == rec.harness: return rec                      # idempotent: nothing changed, nothing committed
            new = UserRecord(rec.version + 1, after, rec.guard, rec.audit)
            if self._commit(user_id, Candidate(rec, new, None, [])): return new
        raise ConcurrentStateError(f"start({user_id}) lost {MAX_RETRIES} CAS races")

    def _record_inflation(self, user_id, rec, hstate: UserState, source, requested_level) -> bool:
        """TW06: raise mode AND write a distinct baseline_inflation_rejected event, in one commit."""
        g = copy.deepcopy(rec.guard); payloads = []
        payloads.append({"type": "baseline_inflation_rejected", "user": user_id, "pos": hstate.trajectory_position, "source": source,
                         "active_epoch": hstate.active.epoch_id, "active_required_level": hstate.required_level,
                         "requested_required_level": requested_level, "inflation_attempts": hstate.inflation_attempts})
        t = max_mode(g.mode, self.cfg.ladder.get("TW06", GuardMode.NORMAL))
        if t != g.mode:
            ch = {"from": g.mode.name, "to": t.name, "at": hstate.trajectory_position, "by": "TW06", "reason": f"baseline inflation via {source}", "ts": time.time()}
            g.mode_changes.append(ch); g.mode = t; payloads.append({"type": "mode_raised", "user": user_id, **ch})
        cursor, events = chain(rec.audit, payloads)
        new = UserRecord(rec.version + 1, asdict(hstate), g, cursor)   # hstate already carries the TW06 event + attempt count
        if self._commit(user_id, Candidate(rec, new, None, events)): self._emit(events, cursor); return True
        return False

    def new_epoch(self, user_id: str, **kw) -> UserRecord:
        for _ in range(MAX_RETRIES):
            rec = self.store.load(user_id)
            if rec is None: raise CanvasValidationError(f"user {user_id!r} not started")
            hs = InMemoryStateStore(); hs.save(user_id, _state_from_raw(copy.deepcopy(rec.harness))); h = RuntimeHarness(config=self.cfg.threshold, store=hs)
            try: h.new_epoch(user_id, **kw)
            except CanvasValidationError:
                if self._record_inflation(user_id, rec, hs.load(user_id), "new_epoch", kw.get("required_level")): raise
                continue
            st = hs.load(user_id); cursor, events = chain(rec.audit, [{"type": "epoch", "user": user_id, "epoch": asdict(st.active)}])
            new = UserRecord(rec.version + 1, asdict(st), rec.guard, cursor)
            if self._commit(user_id, Candidate(rec, new, None, events)): self._emit(events, cursor); return new
        raise ConcurrentStateError("new_epoch lost CAS races")

    def lower_mode(self, user_id: str, *, to: GuardMode, authorization: RecoveryAuthorization, reason: str) -> UserRecord:
        if not reason.strip(): raise CanvasValidationError("lower_mode requires a reason")
        if self.verifier is None: raise CanvasValidationError("mode lowering is disabled: no external AuthorityVerifier configured")
        for _ in range(MAX_RETRIES):
            rec = self.store.load(user_id)
            if rec is None: raise CanvasValidationError("not started")
            if to.value >= rec.guard.mode.value: raise CanvasValidationError("lower_mode must lower")
            ok = self.verifier.authorize_mode_lowering(user_id=user_id, current=rec.guard.mode, target=to, authorization=authorization, reason=reason)
            g = copy.deepcopy(rec.guard)
            if not ok:
                cursor, events = chain(rec.audit, [{"type": "mode_lower_denied", "user": user_id, "from": g.mode.name, "to": to.name, "principal": authorization.principal, "incident_id": authorization.incident_id}])
                if self._commit(user_id, Candidate(rec, UserRecord(rec.version + 1, rec.harness, g, cursor), None, events)): self._emit(events, cursor); raise CanvasValidationError("mode lowering authorization denied")
                continue
            ch = {"from": g.mode.name, "to": to.name, "authority": authorization.principal, "incident_id": authorization.incident_id, "reason": reason, "ts": time.time()}
            g.mode_changes.append(ch); g.mode = to
            if to != GuardMode.CONTAINED: g.contained_reason = None
            cursor, events = chain(rec.audit, [{"type": "mode_lowered", "user": user_id, **ch}])
            new = UserRecord(rec.version + 1, rec.harness, g, cursor)
            if self._commit(user_id, Candidate(rec, new, None, events)): self._emit(events, cursor); return new
        raise ConcurrentStateError("lower_mode lost CAS races")

    def evaluate(self, user_id: str, session_id: str, caller_turn: int, metrics: TurnMetrics, proposed_output: str,
                 *, requested_actions: Sequence[ActionRequest] = ()) -> Decision:
        for _ in range(MAX_RETRIES):
            rec = self.store.load(user_id)
            if rec is None: raise CanvasValidationError(f"user {user_id!r} has no state; call start() first")
            cand = derive_transition(self.cfg, user_id, session_id, caller_turn, rec, metrics, proposed_output, requested_actions)
            if self._commit(user_id, cand):
                self._emit(cand.events, cand.new.audit)           # after commit
                cand.decision.committed_version = cand.new.version
                return cand.decision                              # ONLY now does anything leave the boundary
        raise ConcurrentStateError(f"evaluate({user_id}) lost {MAX_RETRIES} CAS races; nothing released")
