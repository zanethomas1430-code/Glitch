"""ALIGNMENT_GUARD v3.4: replay envelope inside the atomic record (nothing written before CAS), identity = caller request_id + input digest (never regenerated output), strictly sequential turns with tombstone high-water mark, wildcard policy implemented. v3.3: bounded request journal + spent-key boundary (INV_3 across intervening requests), response payload out of the safety record (response_ref), outbox capacity checked for every producer against the full emission. v3.2: v3.1 + request fingerprint (same key, different content -> RequestIdentityConflict), backpressure proves all state unchanged. v3.1: v3 + request idempotency (R3), audited baseline lowering (R1), outbox backpressure (R6), grant binding (R7) — one consistency domain, pure transitions, commit-before-release.

Invariant: nothing leaves the containment boundary (output text, allowed actions) until the
safety decision and the durable state transition have both committed atomically.

Pipeline:
  TurnMetrics -> GLITCH evaluation on a COPY of harness state -> pure GuardTransition
  -> candidate {old, new, decision, audit events} -> compare-and-swap commit of ONE record
  (harness state + guard state + audit cursor) -> only then release.

v2.4: durable audit outbox in the record (crash after CAS loses nothing; drain is idempotent by
(stream_id, seq)); locked CAS in both prototype stores; one logical `now` per attempt threaded
through the harness, the transition, and the chain; TW06 only on BaselineInflationError; action
policy resolves (tool, operation); recovery claim verified once and bound to record version;
verify_chain accepts expected_previous for fragments.

Review items closed (v2.3): 1 CAS with retry; 2 single record spans harness+guard; 3 idempotent start via
CAS create; 4/5 capability-based action policy, unknown actions denied; 6 baseline_inflation_rejected
event; 7 audit cursor persisted in the record; 8 authorization handle, no secret in the guard;
9 budget >= fixture; 10 containment reason+mode in one transition.
"""
from __future__ import annotations

import copy, hashlib, json, threading, time, uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Protocol, Sequence, Tuple

from glitch_runtime_harness import (BaselineInflationError, CanvasValidationError, InMemoryStateStore, RuntimeHarness,
                                    ThresholdConfig, RetentionPolicy, TurnMetrics, UserState, _state_from_raw)

MAX_RETRIES = 8


class GuardMode(Enum):
    NORMAL = 0; RESTRICTED = 1; READ_ONLY = 2; HUMAN_REVIEW = 3; CONTAINED = 4
def max_mode(a, b): return a if a.value >= b.value else b


class Capability(Enum):
    READ = "read"; WRITE = "write"; NETWORK = "network"; EXECUTE = "execute"; CREDENTIAL = "credential"; ACTUATE = "actuate"
SENSITIVE_CAPS = frozenset({Capability.WRITE, Capability.NETWORK, Capability.EXECUTE, Capability.CREDENTIAL, Capability.ACTUATE})


@dataclass(frozen=True)
class ActionRequest:
    tool: str; operation: str = ""; arguments_digest: str = ""


@dataclass(frozen=True)
class ActionPolicy:
    """Every executable (tool, operation) must be registered with its effects. Unknown tool OR
    unknown operation -> denied. A tool-level entry under operation "*" applies to all its ops."""
    registry: Dict[Tuple[str, str], FrozenSet[Capability]] = field(default_factory=dict)
    def capabilities(self, a: "ActionRequest") -> Optional[FrozenSet[Capability]]:
        return self.registry.get((a.tool, a.operation), self.registry.get((a.tool, "*")))   # exact, then tool-level "*"


@dataclass(frozen=True)
class GuardConfig:
    cumulative_gap_limit: int = 4   # >= : a limit of 4 delivers at most 3 gap units. Fixture-locked.
    policy: ActionPolicy = field(default_factory=ActionPolicy)
    ladder: Dict[str, GuardMode] = field(default_factory=lambda: {
        "TW01": GuardMode.RESTRICTED, "TW02": GuardMode.RESTRICTED, "TW03": GuardMode.READ_ONLY,
        "TW04": GuardMode.RESTRICTED, "TW05": GuardMode.HUMAN_REVIEW, "TW06": GuardMode.HUMAN_REVIEW})
    threshold: ThresholdConfig = field(default_factory=ThresholdConfig)
    retention: Optional[RetentionPolicy] = None
    outbox_cap: int = 256      # no transition may commit if its full emission would exceed this
    request_journal_size: int = 64   # committed requests replayable with exact decision (idempotency horizon)


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
    """The single consistency domain: harness trajectory + guard verdict + audit cursor + durable outbox."""
    version: int
    harness: Dict[str, Any]          # serialized UserState
    guard: GuardState
    audit: AuditCursor
    pending_audit: List[Dict] = field(default_factory=list)   # committed envelopes not yet acknowledged by the sink
    request_journal: Dict[str, Dict] = field(default_factory=dict)   # request_id -> {"input_digest","eval_fingerprint","decision","output"} within horizon
    spent_turns: Dict[str, int] = field(default_factory=dict)        # session -> high-water mark; valid ONLY because turns are enforced sequential


@dataclass(frozen=True)
class RecoveryAuthorization:
    principal: str; handle: str; incident_id: str    # handle is an opaque reference; the secret never enters the guard


@dataclass(frozen=True)
class RecoveryGrant:
    principal: str; incident_id: str; expected_version: int; target: GuardMode; authorization_id: str

class AuthorityVerifier(Protocol):
    def authorize_mode_lowering(self, *, user_id, current, target, authorization, reason, expected_version) -> "RecoveryGrant": ...


@dataclass(frozen=True)
class AllowedAction:
    request: ActionRequest; capabilities: FrozenSet[Capability]; effect_id: str

def _effect_id(*, user_id, trajectory_position, committed_version, index, action):
    m = {"user": user_id, "trajectory_position": trajectory_position, "committed_version": committed_version, "action_index": index,
         "tool": action.tool, "operation": action.operation, "arguments_digest": action.arguments_digest}
    return hashlib.sha256(json.dumps(m, sort_keys=True, separators=(",",":")).encode()).hexdigest()

@dataclass
class Decision:
    allow: bool; mode: GuardMode; output: str; tripwires: List[str]; reasons: List[str]; trajectory_position: int
    require_human_review: bool = False
    actions_allowed: List[AllowedAction] = field(default_factory=list)
    actions_denied: List[ActionRequest] = field(default_factory=list)
    committed_version: int = 0
    response_ref: str = ""     # opaque handle; the payload lives in the ResponseStore, not the safety record


def _decision_to_raw(d: "Decision") -> Dict:
    return {"allow": d.allow, "mode": d.mode.name, "response_ref": d.response_ref, "tripwires": d.tripwires, "reasons": d.reasons,
            "trajectory_position": d.trajectory_position, "require_human_review": d.require_human_review,
            "actions_allowed": [{"request": asdict(a.request), "capabilities": sorted(c.value for c in a.capabilities), "effect_id": a.effect_id} for a in d.actions_allowed],
            "actions_denied": [asdict(a) for a in d.actions_denied], "committed_version": d.committed_version}

def _decision_from_raw(r: Dict, output: str) -> "Decision":
    return Decision(r["allow"], GuardMode[r["mode"]], output, list(r["tripwires"]), list(r["reasons"]), r["trajectory_position"], r["require_human_review"],
                    [AllowedAction(ActionRequest(**a["request"]), frozenset(Capability(c) for c in a["capabilities"]), a["effect_id"]) for a in r["actions_allowed"]],
                    [ActionRequest(**a) for a in r["actions_denied"]], r["committed_version"], r["response_ref"])

def response_ref_for(user_id: str, next_version: int, output: str) -> str:
    return hashlib.sha256(f"{user_id}|{next_version}|{output}".encode()).hexdigest()

class TurnSequenceError(RuntimeError):
    """caller_turn must be strictly sequential within a session: next = high-water mark + 1."""

def input_digest_for(session_id: str, caller_turn: int, canonical_input: str) -> str:
    """Identity input: what the CALLER sent, canonicalized. Never metrics or regenerated output."""
    return hashlib.sha256(json.dumps({"s": session_id, "t": caller_turn, "in": canonical_input}, sort_keys=True).encode()).hexdigest()

def ensure_outbox_capacity(rec: "UserRecord", new_envelopes: Sequence[Dict], cap: int) -> None:
    """One rule for every audit-producing transition: the FULL emission must fit."""
    if len(rec.pending_audit) + len(new_envelopes) > cap:
        raise AuditBackpressureError(f"outbox {len(rec.pending_audit)} + emission {len(new_envelopes)} > cap {cap}; no transition committed")

class ConcurrentStateError(RuntimeError): ...
class RequestIdentityConflict(RuntimeError):
    """Same (session, caller_turn) as a committed request, different content, or an identity beyond the horizon. Refused."""
class ResponseUnavailable(RuntimeError):
    """Kept for API compatibility; v3.4 stores the replay envelope in the record so this no longer arises within the horizon."""
class AuditBackpressureError(RuntimeError):
    """Outbox exceeds the cap: evaluation refuses (fail-closed) until the caller drains."""


# --------------------------------------------------------------------------- store
class RecordStore(Protocol):
    def load(self, user_id: str) -> Optional[UserRecord]: ...
    def compare_and_swap(self, user_id: str, expected_version: Optional[int], new: UserRecord) -> bool: ...


def _rec_to_raw(r: UserRecord) -> Dict:
    g = asdict(r.guard); g["mode"] = r.guard.mode.name
    return {"version": r.version, "harness": r.harness, "guard": g, "audit": asdict(r.audit), "pending_audit": r.pending_audit,
            "request_journal": r.request_journal, "spent_turns": r.spent_turns}

def _raw_to_rec(raw: Dict) -> UserRecord:
    g = dict(raw["guard"]); g["mode"] = GuardMode[g["mode"]]
    return UserRecord(raw["version"], raw["harness"], GuardState(**g), AuditCursor(**raw["audit"]), list(raw.get("pending_audit", [])),
                      dict(raw.get("request_journal", {})), dict(raw.get("spent_turns", {})))


class InMemoryRecordStore:
    """CAS is linearizable within this process: check and write happen under one lock."""
    def __init__(self): self._s: Dict[str, Dict] = {}; self._lock = threading.Lock()
    def load(self, u):
        with self._lock: return _raw_to_rec(copy.deepcopy(self._s[u])) if u in self._s else None
    def compare_and_swap(self, u, expected_version, new):
        with self._lock:
            cur = self._s.get(u)
            if (cur is None and expected_version is not None) or (cur is not None and cur["version"] != expected_version): return False
            self._s[u] = _rec_to_raw(new); return True


class JSONRecordStore:
    """Single-process prototype. CAS is correct within one process; across processes you need a DB."""
    def __init__(self, path):
        from pathlib import Path
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True); self._lock = threading.Lock()
        if not self.path.exists(): self.path.write_text("{}")
    def _all(self): return json.loads(self.path.read_text())
    def load(self, u):
        with self._lock: raw = self._all().get(u)
        return None if raw is None else _raw_to_rec(raw)
    def compare_and_swap(self, u, expected_version, new):
        with self._lock:
            d = self._all(); cur = d.get(u)
            if (cur is None and expected_version is not None) or (cur is not None and cur["version"] != expected_version): return False
            d[u] = _rec_to_raw(new); tmp = self.path.with_suffix(".tmp"); tmp.write_text(json.dumps(d, indent=2)); tmp.replace(self.path); return True


# --------------------------------------------------------------------------- audit (cursor lives in the record)
def _hash(env: Dict) -> str:
    e = {k: v for k, v in env.items() if k != "sha256"}
    return hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

def chain(cursor: AuditCursor, payloads: List[Dict], now: float) -> Tuple[AuditCursor, List[Dict]]:
    """Pure and deterministic for a given `now`: returns the advanced cursor and chained envelopes."""
    seq, prev, out = cursor.seq, cursor.prev_sha256, []
    for p in payloads:
        seq += 1
        env = {"stream_id": cursor.stream_id, "seq": seq, "ts": now, "prev_sha256": prev, **p}
        env["sha256"] = _hash(env); prev = env["sha256"]; out.append(env)
    return AuditCursor(cursor.stream_id, seq, prev), out

def verify_chain(records: List[Dict], *, expected_head: Optional[Dict] = None, expected_previous: Optional[Dict] = None) -> bool:
    """Full chain: starts at seq 1 from genesis. Fragment: pass expected_previous = the anchor of seq first-1."""
    if not records: return expected_head is None or expected_head.get("seq") == 0
    sid, n = records[0]["stream_id"], records[0]["seq"]
    if expected_previous is not None:
        if expected_previous["stream_id"] != sid or expected_previous["seq"] != n - 1: return False
        prev = expected_previous["sha256"]
    else:
        if n != 1: return False          # a fragment without its predecessor anchor cannot be verified
        prev = "0" * 64
    for r in records:
        if r["stream_id"] != sid or r["seq"] != n or r["prev_sha256"] != prev or _hash(r) != r["sha256"]: return False
        prev, n = r["sha256"], n + 1
    return expected_head is None or (expected_head["stream_id"] == sid and expected_head["seq"] == records[-1]["seq"] and expected_head["sha256"] == records[-1]["sha256"])


# --------------------------------------------------------------------------- pure transition
@dataclass
class Candidate:
    old: UserRecord; new: UserRecord; decision: Decision; events: List[Dict]


def request_digest(metrics: TurnMetrics, proposed_output: str, requested: Sequence[ActionRequest]) -> str:
    body = {"metrics": asdict(metrics), "output": proposed_output, "actions": [asdict(a) for a in requested]}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def derive_transition(cfg: GuardConfig, user_id: str, session_id: str, caller_turn: int, rec: UserRecord,
                      metrics: TurnMetrics, proposed_output: str, requested: Sequence[ActionRequest], *, now: float,
                      request_id: Optional[str] = None, input_digest: Optional[str] = None) -> Candidate:
    """Deterministic for (cfg, rec, inputs, now). A CAS retry with the same `now` derives the same candidate."""
    # 1. GLITCH evaluation on a copy of harness state at logical time `now` (no shared store; nothing committed).
    hstore = InMemoryStateStore(); hstore.save(user_id, _state_from_raw(copy.deepcopy(rec.harness)))
    h = RuntimeHarness(config=cfg.threshold, store=hstore, retention=cfg.retention, clock=lambda: now)
    h.start_session(user_id, session_id)
    e = h.evaluate_turn(user_id, session_id, caller_turn, metrics)
    new_h = asdict(hstore.load(user_id))
    # 2. Guard transition, pure.
    g = copy.deepcopy(rec.guard); reasons: List[str] = []; payloads: List[Dict] = []
    def raise_to(target, by, reason):
        t = max_mode(g.mode, target)
        if t == g.mode: return
        ch = {"from": g.mode.name, "to": t.name, "at": e.trajectory_position, "by": by, "reason": reason, "ts": now}
        g.mode_changes.append(ch); g.mode = t; payloads.append({"type": "mode_raised", "user": user_id, **ch})
    for tw in e.tripwires:
        floor = cfg.ladder.get(tw, GuardMode.NORMAL)
        if floor.value > g.mode.value: reasons.append(f"{tw} -> {floor.name}"); raise_to(floor, tw, reasons[-1])
    # 3. Action verdicts by capability; unknown denied; sensitive above purpose contains (reason+mode in one step).
    contain_hits = []
    for a in requested:
        caps = cfg.policy.capabilities(a)
        if caps is None: continue
        if bool(caps & SENSITIVE_CAPS) and e.purpose_gap >= 1: contain_hits.append(a)
    if contain_hits:
        r = f"sensitive action above purpose: {[f'{a.tool}:{a.operation}' for a in contain_hits]} at purpose_gap {e.purpose_gap}"
        g.contained_reason = r if not g.contained_reason else f"{g.contained_reason} | then: {r}"; reasons.append(r); raise_to(GuardMode.CONTAINED, "action_gate", r)
    # 4. Delivered-gap budget, transactional (>= blocks the exhausting turn).
    deliverable = g.mode == GuardMode.NORMAL
    projected = g.delivered_gap_total + e.purpose_gap if deliverable else g.delivered_gap_total
    if deliverable and projected >= cfg.cumulative_gap_limit:
        r = f"delivered purpose-gap budget would be exhausted ({g.delivered_gap_total} + {e.purpose_gap} >= {cfg.cumulative_gap_limit})"
        reasons.append(r); raise_to(GuardMode.HUMAN_REVIEW, "delivered_gap_budget", r); deliverable = False
    allow = deliverable and g.mode == GuardMode.NORMAL
    if allow: g.delivered_gap_total = projected
    # final action verdicts against the post-transition mode
    allowed_req, denied = [], []
    for a in requested:
        caps = cfg.policy.capabilities(a)
        if caps is None: denied.append(a); continue
        sensitive = bool(caps & SENSITIVE_CAPS)
        ok = (g.mode == GuardMode.NORMAL and (not sensitive or e.purpose_gap == 0)) or \
             (g.mode == GuardMode.RESTRICTED and caps <= {Capability.READ})
        (allowed_req.append((a, caps)) if ok else denied.append(a))
    next_version = rec.version + 1
    allowed = [AllowedAction(a, caps, _effect_id(user_id=user_id, trajectory_position=e.trajectory_position, committed_version=next_version, index=i, action=a))
               for i, (a, caps) in enumerate(allowed_req)]
    out = proposed_output if allow else _safe_text(g.mode)
    payloads.append({"type": "turn", "user": user_id, "session": session_id, "pos": e.trajectory_position, "caller_turn": caller_turn,
                     "epoch": e.epoch_id, "tripwires": list(e.tripwires), "purpose_gap": e.purpose_gap, "delivered": allow,
                     "committed_delivered_gap_total": g.delivered_gap_total, "mode": g.mode.name,
                     "actions_allowed": [{"tool": a.request.tool, "operation": a.request.operation, "effect_id": a.effect_id} for a in allowed],
                     "actions_denied": [{"tool": a.tool, "operation": a.operation} for a in denied]})
    cursor, events = chain(rec.audit, payloads, now)
    ensure_outbox_capacity(rec, events, cfg.outbox_cap)
    ref = response_ref_for(user_id, next_version, out)
    dec = Decision(allow, g.mode, out, list(e.tripwires), reasons, e.trajectory_position, g.mode.value >= GuardMode.HUMAN_REVIEW.value, allowed, denied, next_version, ref)
    key = request_id or f"{session_id}:{caller_turn}"
    journal = dict(rec.request_journal)
    journal[key] = {"input_digest": input_digest or input_digest_for(session_id, caller_turn, ""), "session": session_id, "caller_turn": caller_turn,
                    "eval_fingerprint": request_digest(metrics, proposed_output, requested),   # what was actually evaluated; not identity
                    "decision": _decision_to_raw(dec), "output": out}                          # replay envelope, inside the atomic record
    if len(journal) > cfg.request_journal_size:                       # evict oldest; identity stays spent via spent_turns
        for k in list(journal)[: len(journal) - cfg.request_journal_size]: journal.pop(k)
    spent = dict(rec.spent_turns); spent[session_id] = max(spent.get(session_id, 0), caller_turn)
    new = UserRecord(next_version, new_h, g, cursor, rec.pending_audit + events, journal, spent)
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
                 audit_sink=None, anchor=None, authority_verifier: Optional[AuthorityVerifier] = None, clock=None):
        self.cfg = config or GuardConfig(); self.store = store or InMemoryRecordStore()
        self.sink = audit_sink or (lambda e: None); self.anchor = anchor or (lambda h: None); self.verifier = authority_verifier
        self.clock = clock or time.time

    def _commit(self, user_id: str, cand: Candidate) -> bool:
        return self.store.compare_and_swap(user_id, cand.old.version, cand.new)

    def drain_audit(self, user_id: str, *, max_items=None) -> int:
        delivered = 0
        while max_items is None or delivered < max_items:
            rec = self.store.load(user_id)
            if rec is None: raise CanvasValidationError(f"user {user_id!r} not started")
            if not rec.pending_audit: return delivered
            ev = copy.deepcopy(rec.pending_audit[0]); self.sink(ev)
            self.anchor({"stream_id": ev["stream_id"], "seq": ev["seq"], "sha256": ev["sha256"]})
            new = copy.deepcopy(rec); new.version += 1; new.pending_audit = new.pending_audit[1:]
            if self.store.compare_and_swap(user_id, rec.version, new): delivered += 1
        return delivered

    def drain_outbox(self, user_id: str) -> int:   # v3 removed; kept as alias for the ported suite
        return self.drain_audit(user_id)
        """Deliver committed-but-unacknowledged audit envelopes. Idempotent by (stream_id, seq): the sink
        must treat a repeated (stream_id, seq) as already delivered. A crash anywhere here is safe:
        the envelopes stay in the record until a later drain removes them after acknowledgment."""
        delivered = 0
        for _ in range(MAX_RETRIES):
            rec = self.store.load(user_id)
            if rec is None or not rec.pending_audit: return delivered
            batch = list(rec.pending_audit)
            for ev in batch: self.sink(ev)                    # sink raising => nothing removed; retry later
            self.anchor({"stream_id": rec.audit.stream_id, "seq": batch[-1]["seq"], "sha256": batch[-1]["sha256"]})
            remaining = [e for e in rec.pending_audit if e["seq"] > batch[-1]["seq"]]
            new = UserRecord(rec.version + 1, rec.harness, rec.guard, rec.audit, remaining)
            if self.store.compare_and_swap(user_id, rec.version, new): delivered += len(batch); continue
        return delivered

    def _emit(self, events, cursor):   # kept for call-site symmetry: delivery is the outbox drain
        pass

    # -- idempotent start: one CAS creates harness state, guard state, and audit cursor together
    def start(self, user_id: str, session_id: str, *, declared_purpose=None, required_level=None) -> UserRecord:
        for _ in range(MAX_RETRIES):
            rec = self.store.load(user_id)
            now = self.clock()
            if rec is None:
                hs = InMemoryStateStore(); RuntimeHarness(config=self.cfg.threshold, store=hs, clock=lambda: now).start_session(
                    user_id, session_id, declared_purpose=declared_purpose, required_level=required_level)
                new = UserRecord(1, asdict(hs.load(user_id)), GuardState(), AuditCursor(stream_id=f"{user_id}:{hashlib.sha256(user_id.encode()).hexdigest()[:8]}"))
                if self.store.compare_and_swap(user_id, None, new): return new
                continue   # someone else created it; loop and treat as existing
            hs = InMemoryStateStore(); hs.save(user_id, _state_from_raw(copy.deepcopy(rec.harness)))
            h = RuntimeHarness(config=self.cfg.threshold, store=hs, clock=lambda: now)
            try:
                h.start_session(user_id, session_id, declared_purpose=declared_purpose, required_level=required_level)
            except BaselineInflationError:
                self._record_inflation(user_id, rec, hs.load(user_id), "start_session", required_level, now); raise
            # any other CanvasValidationError propagates untouched: it is not an inflation event
            after = asdict(hs.load(user_id))
            if after == rec.harness: return rec                      # idempotent: nothing changed, nothing committed
            payloads = [{"type": "session_started", "user": user_id, "session": session_id}]
            if len(after["epochs"]) > len(rec.harness["epochs"]):    # R1: a lowering opened an epoch; audit it like any baseline change
                ep = after["epochs"][-1]
                payloads.append({"type": "baseline_lowered", "user": user_id, "session": session_id, "from": ep["previous_required_level"], "to": ep["required_level"], "epoch": ep["epoch_id"]})
            cursor, events = chain(rec.audit, payloads, now); ensure_outbox_capacity(rec, events, self.cfg.outbox_cap)
            new = UserRecord(rec.version + 1, after, rec.guard, cursor, rec.pending_audit + events, rec.request_journal, rec.spent_turns)
            if self._commit(user_id, Candidate(rec, new, None, events)): return new
        raise ConcurrentStateError(f"start({user_id}) lost {MAX_RETRIES} CAS races")

    def _record_inflation(self, user_id, rec, hstate: UserState, source, requested_level, now: float) -> bool:
        """TW06: raise mode AND write a distinct baseline_inflation_rejected event, in one commit."""
        g = copy.deepcopy(rec.guard); payloads = []
        payloads.append({"type": "baseline_inflation_rejected", "user": user_id, "pos": hstate.trajectory_position, "source": source,
                         "active_epoch": hstate.active.epoch_id, "active_required_level": hstate.required_level,
                         "requested_required_level": requested_level, "inflation_attempts": hstate.inflation_attempts})
        t = max_mode(g.mode, self.cfg.ladder.get("TW06", GuardMode.NORMAL))
        if t != g.mode:
            ch = {"from": g.mode.name, "to": t.name, "at": hstate.trajectory_position, "by": "TW06", "reason": f"baseline inflation via {source}", "ts": now}
            g.mode_changes.append(ch); g.mode = t; payloads.append({"type": "mode_raised", "user": user_id, **ch})
        cursor, events = chain(rec.audit, payloads, now); ensure_outbox_capacity(rec, events, self.cfg.outbox_cap)
        new = UserRecord(rec.version + 1, asdict(hstate), g, cursor, rec.pending_audit + events, rec.request_journal, rec.spent_turns)
        if not self._commit(user_id, Candidate(rec, new, None, events)):
            raise ConcurrentStateError("baseline inflation evidence lost CAS race; privileged attempt not replayed")
        return True

    def new_epoch(self, user_id: str, **kw) -> UserRecord:
        for _ in range(MAX_RETRIES):
            rec = self.store.load(user_id)
            if rec is None: raise CanvasValidationError(f"user {user_id!r} not started")
            now = self.clock()
            hs = InMemoryStateStore(); hs.save(user_id, _state_from_raw(copy.deepcopy(rec.harness))); h = RuntimeHarness(config=self.cfg.threshold, store=hs, clock=lambda: now)
            try: h.new_epoch(user_id, **kw)
            except BaselineInflationError:
                self._record_inflation(user_id, rec, hs.load(user_id), "new_epoch", kw.get("required_level"), now); raise
            st = hs.load(user_id); cursor, events = chain(rec.audit, [{"type": "epoch", "user": user_id, "epoch": asdict(st.active)}], now)
            ensure_outbox_capacity(rec, events, self.cfg.outbox_cap)
            new = UserRecord(rec.version + 1, asdict(st), rec.guard, cursor, rec.pending_audit + events, rec.request_journal, rec.spent_turns)
            if self._commit(user_id, Candidate(rec, new, None, events)): return new
        raise ConcurrentStateError("new_epoch lost CAS races")

    def lower_mode(self, user_id: str, *, to: GuardMode, authorization: RecoveryAuthorization, reason: str) -> UserRecord:
        """The verifier is consulted EXACTLY ONCE, and its claim is bound to the record version it saw.
        If the record changes before commit, the claim is void and the caller must re-authorize;
        a possibly one-use handle is never spent twice by a retry loop."""
        if not reason.strip(): raise CanvasValidationError("lower_mode requires a reason")
        if self.verifier is None: raise CanvasValidationError("mode lowering is disabled: no external AuthorityVerifier configured")
        rec = self.store.load(user_id)
        if rec is None: raise CanvasValidationError("not started")
        if to.value >= rec.guard.mode.value: raise CanvasValidationError("lower_mode must lower")
        grant = self.verifier.authorize_mode_lowering(user_id=user_id, current=rec.guard.mode, target=to, authorization=authorization, reason=reason, expected_version=rec.version)
        if grant.expected_version != rec.version: raise CanvasValidationError("recovery grant version mismatch")
        if grant.target != to: raise CanvasValidationError("recovery grant target mismatch")
        if grant.principal != authorization.principal or grant.incident_id != authorization.incident_id:
            raise CanvasValidationError("recovery grant is not bound to the requesting principal/incident")   # R7
        now = self.clock(); g = copy.deepcopy(rec.guard)
        ch = {"from": g.mode.name, "to": to.name, "authority": grant.principal, "incident_id": grant.incident_id, "authorization_id": grant.authorization_id, "reason": reason, "ts": now}
        g.mode_changes.append(ch); g.mode = to
        if to != GuardMode.CONTAINED: g.contained_reason = None
        cursor, events = chain(rec.audit, [{"type": "mode_lowered", "user": user_id, **ch}], now); ensure_outbox_capacity(rec, events, self.cfg.outbox_cap)
        new = UserRecord(rec.version + 1, rec.harness, g, cursor, rec.pending_audit + events, rec.request_journal, rec.spent_turns)
        if self._commit(user_id, Candidate(rec, new, None, events)): return new
        raise ConcurrentStateError("state changed after recovery authorization; grant was not replayed")

    def evaluate(self, user_id: str, session_id: str, caller_turn: int, metrics: TurnMetrics, proposed_output: str,
                 *, requested_actions: Sequence[ActionRequest] = (), request_id: Optional[str] = None,
                 canonical_input: str = "") -> Decision:
        """Identity = request_id (caller-generated, immutable) + digest of the caller's canonical input.
        Replay never rescores, never regenerates, never advances the trajectory."""
        now = self.clock()                                        # one logical time for the whole request, retries included
        rid = request_id or f"{session_id}:{caller_turn}"
        idig = input_digest_for(session_id, caller_turn, canonical_input)
        for _ in range(MAX_RETRIES):
            rec = self.store.load(user_id)
            if rec is None: raise CanvasValidationError(f"user {user_id!r} has no state; call start() first")
            entry = rec.request_journal.get(rid)
            if entry is not None:                                 # within horizon: replay committed truth or refuse
                if entry["input_digest"] == idig:
                    return _decision_from_raw(entry["decision"], entry["output"])   # exact committed result; nothing recomputed
                raise RequestIdentityConflict(f"request {rid} already committed with different input")
            expected = rec.spent_turns.get(session_id, 0) + 1     # INV_3B: strictly sequential turns make the high-water mark a tombstone
            if caller_turn < expected:
                raise RequestIdentityConflict(f"turn {session_id}:{caller_turn} identity was spent (high-water {expected-1}); not re-evaluated")
            if caller_turn > expected:
                raise TurnSequenceError(f"turn {session_id}:{caller_turn} out of sequence; expected {expected}")
            cand = derive_transition(self.cfg, user_id, session_id, caller_turn, rec, metrics, proposed_output, requested_actions, now=now,
                                     request_id=rid, input_digest=idig)
            if self._commit(user_id, cand):                       # durable: state + cursor + outbox + journal(+envelope), one CAS
                return cand.decision                              # release; NOTHING was written anywhere before this line                              # ONLY now does anything leave the boundary
        raise ConcurrentStateError(f"evaluate({user_id}) lost {MAX_RETRIES} CAS races; nothing released")
