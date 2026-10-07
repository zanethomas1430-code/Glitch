#!/usr/bin/env python3
"""benchmark_guard.py v0.2 — what the ALIGNMENT_GUARD contract COSTS. Asserts nothing about correctness.

v0.2 changes (measurement validity only; no guard changes):
  1. Deterministic pre-generated operation plan and fault tapes via rng_for(seed, namespace, index). Scheduling can
     change which operation observes a fault, never which operations/faults were requested.
  2. contention_mode = sharded (each user owned by one worker) | shared_user (every worker drives its own session on
     EVERY user, so all requests race over one atomic UserRecord). The second is the number v0.1 was missing.
  3. ops_per_user means ops per user. Total workload = users * ops_per_user.
  4. Attempt/outcome accounting: attempted, completed, succeeded, refused, skipped.
  5. CAS losses split: injected (synthetic) vs version_conflict (genuine contention).
  6. Lowering is reachable: default ladder + a specificity mix that raises modes; lower.* outcomes reported.
  7. Real restart recovery on the json backend; memory backend reports restart_recovery_supported=false.
  8. Anchor lag distribution (delivery time - envelope commit time).
  9. Thread-safe instrumentation.
 10. Measurement phase isolated: timers snapshot before report generation; inspection bypasses the metered store.
"""
from __future__ import annotations
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)

import argparse, copy, hashlib, json, random, statistics, tempfile, threading, time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List

from alignment_guard_v343 import *
from alignment_guard_v343 import _rec_to_raw
from glitch_runtime_harness import HARNESS_VERSION, CanvasValidationError, RetentionPolicy, ThresholdConfig, TurnMetrics

POL = ActionPolicy({("shell", "rm"): frozenset({Capability.EXECUTE}), ("read_docs", "get"): frozenset({Capability.READ})})


def rng_for(seed: int, namespace: str, index: int = 0) -> random.Random:
    return random.Random(int.from_bytes(hashlib.sha256(f"{seed}:{namespace}:{index}".encode()).digest()[:8], "big"))


@dataclass
class Workload:
    name: str
    users: int = 8
    sessions_per_user: int = 4
    ops_per_user: int = 60
    concurrency: int = 4
    contention_mode: str = "sharded"          # sharded | shared_user
    mix: Dict[str, float] = field(default_factory=lambda: {"evaluate": .66, "replay": .10, "new_epoch": .05, "lower": .07, "drain": .12})
    spec_mix: List[int] = field(default_factory=lambda: [1, 2, 2, 3, 3, 4])
    cas_loss_rate: float = 0.0
    sink_latency_ms: float = 0.0
    sink_failure_rate: float = 0.0
    anchor_latency_ms: float = 0.0
    verifier_unavailable_rate: float = 0.0
    journal_horizon: int = 16
    outbox_cap: int = 32
    retention_turn_limit: int = 6
    window_turns: int = 6
    store_backend: str = "memory"             # memory | json
    seed: int = 1


WORKLOADS = {
    "sharded": Workload("sharded"),
    "hot_user": Workload("hot_user", users=2, sessions_per_user=8, ops_per_user=240, concurrency=8, contention_mode="shared_user"),
    "medium": Workload("medium", users=16, ops_per_user=80, concurrency=8, cas_loss_rate=0.10, sink_latency_ms=0.2, sink_failure_rate=0.02, verifier_unavailable_rate=0.10),
    "hostile_hot": Workload("hostile_hot", users=2, sessions_per_user=8, ops_per_user=160, concurrency=8, contention_mode="shared_user",
                            cas_loss_rate=0.30, sink_failure_rate=0.20, outbox_cap=8, verifier_unavailable_rate=0.50, store_backend="json"),
}


class Timers:
    def __init__(self): self.b: Dict[str, List[float]] = {}; self.c: Dict[str, int] = {}; self.lock = threading.Lock()
    def add(self, k, dt):
        with self.lock: self.b.setdefault(k, []).append(dt)
    def inc(self, k, n=1):
        with self.lock: self.c[k] = self.c.get(k, 0) + n
    def snapshot(self):
        with self.lock: return copy.deepcopy(self.b), dict(self.c)


class Tape:
    def __init__(self, rng, p, n=200_000): self.t = [rng.random() < p for _ in range(n)]; self.i = 0; self.lock = threading.Lock()
    def next(self):
        with self.lock: v = self.t[self.i % len(self.t)]; self.i += 1; return v


class MeteredStore:
    def __init__(self, inner, cas_tape, T): self.inner, self.tape, self.T = inner, cas_tape, T   # T is swapped after setup
    def load(self, u):
        t = time.perf_counter(); r = self.inner.load(u); self.T.add("store.load", time.perf_counter() - t); return r
    def compare_and_swap(self, u, v, new):
        t = time.perf_counter(); self.T.inc("cas.attempts")
        if v is not None and self.tape.next():
            self.T.inc("cas.injected_losses"); self.T.add("store.cas", time.perf_counter() - t); return False
        ok = self.inner.compare_and_swap(u, v, new); self.T.add("store.cas", time.perf_counter() - t)
        self.T.inc("cas.wins" if ok else "cas.version_conflicts"); return ok


class Verifier:
    def __init__(self, tape, T): self.tape, self.T = tape, T
    def authorize_mode_lowering(self, **kw):
        if self.tape.next(): raise CanvasValidationError("authorization infrastructure unavailable")
        a = kw["authorization"]; return RecoveryGrant(a.principal, a.incident_id, kw["expected_version"], kw["target"], "g")


def make_sink(w, tape, box):
    """box["T"] is swapped after setup so setup deliveries don't count in the measured phase."""
    seen: Dict[tuple, int] = {}; lock = threading.Lock()
    def sink(ev):
        T = box["T"]
        if w.sink_latency_ms: time.sleep(w.sink_latency_ms / 1000)
        if tape.next(): T.inc("sink.failures"); raise IOError("sink down")
        k = (ev["stream_id"], ev["seq"])
        with lock: seen[k] = seen.get(k, 0) + 1; dup = seen[k] > 1
        T.inc("sink.deliveries")
        if dup: T.inc("sink.duplicate_sends")
        T.add("audit.delivery_lag", time.time() - ev["ts"])       # commit-time -> successful delivery, under retries/contention
    def anchor(h):
        T = box["T"]
        if w.anchor_latency_ms: time.sleep(w.anchor_latency_ms / 1000)
        T.inc("anchor.writes")
    return sink, anchor


def build_plan(w):
    names, weights = zip(*w.mix.items()); users = [f"u{i}" for i in range(w.users)]
    per_user = {}
    for i, u in enumerate(users):
        r = rng_for(w.seed, "ops", i)                      # ONE stream per user (v0.2.1: was re-seeded per op -> identical ops)
        per_user[u] = [r.choices(names, weights)[0] for _ in range(w.ops_per_user)]
    workers = [[] for _ in range(w.concurrency)]
    if w.contention_mode == "sharded":
        for i, (u, ops) in enumerate(per_user.items()):
            wk = i % w.concurrency; r = rng_for(w.seed, "sess", i)
            for op in ops: workers[wk].append((u, f"S{r.randrange(w.sessions_per_user)}", op))
    else:
        for i, (u, ops) in enumerate(per_user.items()):
            for j, op in enumerate(ops):
                wk = j % w.concurrency; workers[wk].append((u, f"S{wk % w.sessions_per_user}", op))
    return workers


def validate_plan(w, plan) -> Dict:
    """A benchmark must validate the shape of its own stimulus. Pre-run: does the plan contain what the workload claims?"""
    from collections import Counter
    ops = Counter(op for wk in plan for (_, _, op) in wk); problems = []
    users_by_op = {op: len({u for wk in plan for (u, _, o) in wk if o == op}) for op in w.mix}
    import math
    n = w.users * w.ops_per_user; tot = sum(w.mix.values())
    for op, p in w.mix.items():
        p = p / tot; expected = p * n; lower = max(1.0, expected - 3 * math.sqrt(n * p * (1 - p)))   # binomial 3-sigma lower bound
        if p > 0 and ops.get(op, 0) < lower: problems.append(f"{op}: {ops.get(op, 0)} realized, below 3-sigma lower bound {lower:.1f} of expected {expected:.0f}")
        if p >= 0.05 and users_by_op[op] < max(1, w.users // 2): problems.append(f"{op}: only {users_by_op[op]} of {w.users} users receive it")
    per_user = Counter(u for wk in plan for (u, _, _) in wk)
    if any(v != w.ops_per_user for v in per_user.values()): problems.append("ops_per_user not honored for every user")
    shared_workers = {}
    for k, wk in enumerate(plan):
        for (u, _, _) in wk: shared_workers.setdefault(u, set()).add(k)
    max_workers_per_user = max((len(v) for v in shared_workers.values()), default=0)
    if w.contention_mode == "shared_user" and w.concurrency >= 2 and max_workers_per_user < 2: problems.append("shared_user mode but no user is driven by more than one worker")
    if w.contention_mode == "sharded" and max_workers_per_user > 1: problems.append("sharded mode but a user is driven by several workers")
    return {"valid": not problems, "problems": problems, "per_operation_counts": dict(ops), "users_receiving_each_op": users_by_op,
            "max_workers_per_user": max_workers_per_user, "same_seed_reproduces": build_plan(w) == plan}


def validate_realized(w, C, wall) -> Dict:
    """Post-run: did the run realize the opportunities the workload claims to exercise?"""
    problems = []
    if w.contention_mode == "shared_user" and w.concurrency >= 2 and C.get("cas.version_conflicts", 0) == 0: problems.append("hot workload realized zero genuine version conflicts")
    if w.cas_loss_rate > 0 and C.get("cas.injected_losses", 0) == 0: problems.append("cas_loss_rate > 0 but no loss was injected")
    if w.sink_failure_rate > 0 and C.get("sink.failures", 0) == 0: problems.append("sink_failure_rate > 0 but no sink failure occurred")
    lower_att = C.get("lower.attempts", 0); lower_elig = lower_att - C.get("lower.skipped_normal", 0)
    if w.mix.get("lower", 0) > 0 and lower_att and lower_elig == 0: problems.append("lower configured but never eligible (no record ever left NORMAL)")
    if w.mix.get("lower", 0) > 0 and lower_elig >= 5 and C.get("lower.authorized", 0) == 0:
        problems.append(f"lower eligible {lower_elig} times but never authorized (recovery path dead)")   # taxonomy can close over a dead path
    if w.verifier_unavailable_rate > 0 and lower_elig >= 5 and C.get("lower.refused_verifier_unavailable", 0) == 0: problems.append("verifier unavailability configured but never observed on eligible lowerings")
    drain_att = C.get("drain.attempts", 0); measured_deliveries = C.get("sink.deliveries", 0) - C.get("setup.sink.deliveries", 0)
    if w.mix.get("drain", 0) > 0 and drain_att and measured_deliveries == 0: problems.append("drain configured in measured phase but the sink received nothing during it")
    return {"valid": not problems, "problems": problems, "lower_eligible_attempts": lower_elig, "drain_attempts": drain_att,
            "lower_authorized": C.get("lower.authorized", 0), "drain_delivered_by_completed_drains": C.get("drain.delivered", 0),
            "measured_sink_deliveries": measured_deliveries, "sink_deliveries_total": C.get("sink.deliveries", 0), "genuine_conflicts": C.get("cas.version_conflicts", 0), "injected_losses": C.get("cas.injected_losses", 0)}


def run(w):
    Tsetup = Timers(); box = {"T": Tsetup}; td = tempfile.mkdtemp(); path = Path(td) / "r.json"
    inner = JSONRecordStore(path) if w.store_backend == "json" else InMemoryRecordStore()
    store = MeteredStore(inner, Tape(rng_for(w.seed, "cas"), w.cas_loss_rate), Tsetup)
    sink, anchor = make_sink(w, Tape(rng_for(w.seed, "sink"), w.sink_failure_rate), box)
    cfg = GuardConfig(policy=POL, cumulative_gap_limit=10_000, threshold=ThresholdConfig(window_turns=w.window_turns, tw03_consecutive_turns=2),
                      retention=RetentionPolicy(trajectory_turn_limit=w.retention_turn_limit), outbox_cap=w.outbox_cap, request_journal_size=w.journal_horizon)
    verifier = Verifier(Tape(rng_for(w.seed, "verifier"), w.verifier_unavailable_rate), Tsetup)
    g = AlignmentGuard(config=cfg, store=store, audit_sink=sink, anchor=anchor, authority_verifier=verifier)
    users = [f"u{i}" for i in range(w.users)]
    def setup_drain(u):                                      # setup honors the contract and tolerates the faulty sink it configured
        for _ in range(50):
            try: g.drain_audit(u); return
            except (IOError, ConcurrentStateError): continue     # setup meets the faults it configured; retry, bounded
        raise RuntimeError("setup could not drain against the configured sink failure rate")
    for u in users:
        g.start(u, "S0", declared_purpose="p", required_level=2); setup_drain(u)
        for s in range(1, w.sessions_per_user): g.start(u, f"S{s}"); setup_drain(u)
    setup_deliveries = Tsetup.c.get("sink.deliveries", 0)
    T = Timers(); store.T = T; box["T"] = T; verifier.T = T          # measured phase begins: fresh counters
    T.c["setup.sink.deliveries"] = 0                                 # fresh counters already exclude setup; carried as an explicit 0 so the
                                                                     # subtraction in validate_realized is a stated contract, not an accident
    hw_lock = threading.Lock(); hw: Dict[tuple, int] = {}; committed: Dict[str, List[str]] = {u: [] for u in users}
    spec_rng = rng_for(w.seed, "spec"); spec_lock = threading.Lock(); pick_rng = rng_for(w.seed, "pick")

    def out(name, kind): T.inc(f"{name}.{kind}")

    def op_evaluate(u, s):
        with hw_lock: t = hw.get((u, s), 0) + 1
        rid = f"{u}:{s}:{t}"; ident = RequestIdentity.from_canonical_input(rid, s, t, f"in-{rid}")
        with spec_lock: spec = spec_rng.choice(w.spec_mix); act = spec_rng.random() < .3
        t0 = time.perf_counter()
        try:
            d = g.evaluate(u, s, t, TurnMetrics(spec, .3), f"out-{rid}", identity=ident, requested_actions=[ActionRequest("read_docs", "get")] if act else [])
            T.add("op.evaluate", time.perf_counter() - t0)
            with hw_lock: hw[(u, s)] = t; committed[u].append(rid)
            out("evaluate", "delivered" if d.allow else "completed_blocked_by_mode")
        except AuditBackpressureError: T.add("op.evaluate.refused", time.perf_counter() - t0); out("evaluate", "refused_backpressure")
        except ConcurrentStateError: T.add("op.evaluate.refused", time.perf_counter() - t0); out("evaluate", "refused_cas_exhausted")
        except (TurnSequenceError, RequestIdentityConflict): out("evaluate", "refused_identity")

    def op_replay(u, s):
        with hw_lock: pool = list(committed[u][-w.journal_horizon:])
        if not pool: out("replay", "skipped_nothing_committed"); return
        with spec_lock: rid = pick_rng.choice(pool)
        _, ss, t = rid.split(":"); t = int(t); ident = RequestIdentity.from_canonical_input(rid, ss, t, f"in-{rid}"); t0 = time.perf_counter()
        try: g.evaluate(u, ss, t, TurnMetrics(1, .3), "regenerated", identity=ident); T.add("op.replay", time.perf_counter() - t0); out("replay", "hit")
        except RequestIdentityConflict: out("replay", "spent_beyond_horizon")
        except ConcurrentStateError: out("replay", "refused_cas_exhausted")

    def op_epoch(u, s):
        t0 = time.perf_counter()
        try: g.new_epoch(u, required_level=2, authority="supervisor", reason="r", triggering_user_evidence="role change"); T.add("op.new_epoch", time.perf_counter() - t0); out("new_epoch", "committed")
        except AuditBackpressureError: out("new_epoch", "refused_backpressure")
        except ConcurrentStateError: out("new_epoch", "refused_cas_exhausted")

    def op_lower(u, s):
        if inner.load(u).guard.mode == GuardMode.NORMAL: out("lower", "skipped_normal"); return
        t0 = time.perf_counter()
        try: g.lower_mode(u, to=GuardMode.NORMAL, authorization=RecoveryAuthorization("responder", "h", "inc"), reason="reviewed"); T.add("op.lower", time.perf_counter() - t0); out("lower", "authorized")
        except CanvasValidationError as e: out("lower", "refused_verifier_unavailable" if "unavailable" in str(e) else "denied_or_already_lowered")
        except ConcurrentStateError: out("lower", "refused_cas_conflict_after_authorization")
        except AuditBackpressureError: out("lower", "refused_backpressure")

    def op_drain(u, s):
        t0 = time.perf_counter()
        try: n = g.drain_audit(u); T.add("op.drain", time.perf_counter() - t0); T.inc("drain.delivered", n); out("drain", "completed")
        except IOError: out("drain", "sink_error")
        except ConcurrentStateError: out("drain", "refused_cas_exhausted")

    OPS = {"evaluate": op_evaluate, "replay": op_replay, "new_epoch": op_epoch, "lower": op_lower, "drain": op_drain}
    plan = build_plan(w); pv = validate_plan(w, plan)
    if not pv["valid"]: return {"benchmark_version": "0.4", "workload": asdict(w), "report_valid": False, "plan_validation": pv, "note": "stimulus invalid; no run performed"}
    def worker(items):
        for (u, s, op) in items: T.inc("workload.attempted"); T.inc(f"{op}.attempts"); OPS[op](u, s)
    wall0 = time.perf_counter(); ts = [threading.Thread(target=worker, args=(x,)) for x in plan if x]
    [t.start() for t in ts]; [t.join() for t in ts]; wall = time.perf_counter() - wall0
    B, C = T.snapshot()
    insp_end = JSONRecordStore(path) if w.store_backend == "json" else inner   # end-of-measured-phase durable state, BEFORE recovery
    recs = [insp_end.load(u) for u in users]
    backlog = sum(len(r.pending_audit) for r in recs); sizes = [len(json.dumps(_rec_to_raw(r))) for r in recs]; occ = [len(r.request_journal) for r in recs]
    modes: Dict[str, int] = {}
    for r in recs: modes[r.guard.mode.name] = modes.get(r.guard.mode.name, 0) + 1
    evictions = sum(max(0, len(committed[u]) - w.journal_horizon) for u in users)

    recovery = None
    if w.store_backend == "json":
        del g; t0 = time.perf_counter()
        fresh = JSONRecordStore(path); g2 = AlignmentGuard(config=cfg, store=fresh, audit_sink=lambda e: None, anchor=lambda h: None)
        for u in users:
            fresh.load(u)
            try: g2.drain_audit(u)
            except ConcurrentStateError: pass
        u0 = next((u for u in users if committed[u]), None)
        if u0:
            rid = committed[u0][-1]; _, s, t = rid.split(":"); t = int(t)
            g2.evaluate(u0, s, t, TurnMetrics(1, .3), "x", identity=RequestIdentity.from_canonical_input(rid, s, t, f"in-{rid}"))
        recovery = round(time.perf_counter() - t0, 4)

    def pct(k, scale=1000):
        xs = sorted(B.get(k, []))
        if not xs: return None
        q = lambda p: xs[min(len(xs) - 1, int(p * len(xs)))] * scale
        return {"n": len(xs), "p50": round(q(.50), 4), "p95": round(q(.95), 4), "p99": round(q(.99), 4), "mean": round(statistics.mean(xs) * scale, 4)}
    attempted = C.get("workload.attempted", 0)
    succeeded = sum(C.get(k, 0) for k in ("evaluate.delivered", "replay.hit", "new_epoch.committed", "lower.authorized", "drain.completed"))
    blocked = C.get("evaluate.completed_blocked_by_mode", 0) + C.get("replay.spent_beyond_horizon", 0)   # both are the contract refusing by design
    skipped = C.get("replay.skipped_nothing_committed", 0) + C.get("lower.skipped_normal", 0) + C.get("lower.denied_or_already_lowered", 0)
    refused = {k: v for k, v in C.items() if ".refused_" in k}
    infra = sum(refused.values()) + C.get("drain.sink_error", 0)
    taxonomy = {"attempted": attempted, "succeeded": succeeded, "completed_blocked_by_policy": blocked, "skipped_inapplicable": skipped,
                "infrastructure_fail_closed": infra, "identity_closes": succeeded + blocked + skipped + infra == attempted,
                "fractions": {k: round(v / max(1, attempted), 4) for k, v in (("succeeded", succeeded), ("blocked", blocked), ("skipped", skipped), ("infrastructure", infra))}}
    genuine_den = max(1, C.get("cas.attempts", 0) - C.get("cas.injected_losses", 0))
    rates = {"version_conflict_rate": round(C.get("cas.version_conflicts", 0) / genuine_den, 4),
             "infrastructure_refusal_rate": round(infra / max(1, attempted), 4),
             "lower_post_auth_loss_rate": round(C.get("lower.refused_cas_conflict_after_authorization", 0) / max(1, C.get("lower.authorized", 0) + C.get("lower.refused_cas_conflict_after_authorization", 0)), 4),
             "duplicate_audit_send_rate": round(C.get("sink.duplicate_sends", 0) / max(1, C.get("sink.deliveries", 0)), 4),
             "replay_spent_rate": round(C.get("replay.spent_beyond_horizon", 0) / max(1, C.get("replay.hit", 0) + C.get("replay.spent_beyond_horizon", 0)), 4),
             "sink_observed_failure_fraction": round(C.get("sink.failures", 0) / max(1, C.get("sink.failures", 0) + C.get("sink.deliveries", 0)), 4)}
    rv = validate_realized(w, C, wall)
    if not taxonomy["identity_closes"]: rv["valid"] = False; rv["problems"].append("outcome taxonomy does not close over attempted operations")
    return {
        "benchmark_version": "0.4", "harness_version": HARNESS_VERSION, "guard_version": "3.4.3", "workload": asdict(w),
        "report_valid": pv["valid"] and rv["valid"], "plan_validation": pv, "realized_validation": rv,
        "plan_ops": sum(len(x) for x in plan), "wall_seconds": round(wall, 3),
        "throughput": {"attempted_ops_per_s": round(attempted / wall, 1), "succeeded_ops_per_s": round(succeeded / wall, 1)}, "taxonomy": taxonomy, "rates": rates,
        "outcomes": {k: v for k, v in sorted(C.items()) if any(k.startswith(p) for p in ("evaluate.", "replay.", "new_epoch.", "lower.", "drain.")) and k != "drain.delivered"},
        "latency_ms": {k: pct(k) for k in ("op.evaluate", "op.evaluate.refused", "op.replay", "op.new_epoch", "op.lower", "op.drain")},
        "cas": {"attempts": C.get("cas.attempts", 0), "wins": C.get("cas.wins", 0), "injected_losses": C.get("cas.injected_losses", 0),
                "version_conflicts": C.get("cas.version_conflicts", 0), "attempts_per_commit": round(C.get("cas.attempts", 0) / max(1, C.get("cas.wins", 1)), 3)},
        "audit": {"deliveries": C.get("sink.deliveries", 0), "duplicate_sends": C.get("sink.duplicate_sends", 0), "sink_failures": C.get("sink.failures", 0),
                  "anchor_writes": C.get("anchor.writes", 0), "audit_delivery_lag_ms": pct("audit.delivery_lag"), "backlog_at_end_of_measured_phase": backlog, "drain_delivered": C.get("drain.delivered", 0)},
        "infrastructure_refusals": {"total": sum(refused.values()), "by_cause": refused},
        "restart_recovery": {"supported": w.store_backend == "json", "seconds_all_users": recovery},
        "record_bytes": {"mean": int(statistics.mean(sizes)), "max": max(sizes)}, "journal": {"horizon": w.journal_horizon, "occupancy_mean": round(statistics.mean(occ), 2), "peak_occupancy": max(occ), "evictions_total": evictions,
                    "committed_per_user_mean": round(statistics.mean(len(committed[u]) for u in users), 1), "pressure_exercised": evictions > 0},
        "final_modes": modes, "store_time_ms_measured_phase": {k: round(sum(v) * 1000, 2) for k, v in B.items() if k.startswith("store.")},
        "correctness_note": "Asserts nothing. Refusals are the availability cost of fail-closed. Scheduling changes which op observes a fault; the seed fixes which faults and ops were requested.",
    }


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--workload", default="sharded"); ap.add_argument("--seed", type=int); ap.add_argument("--report"); ap.add_argument("--backend")
    a = ap.parse_args(); w = copy.deepcopy(WORKLOADS[a.workload])
    if a.seed is not None: w.seed = a.seed
    if a.backend: w.store_backend = a.backend
    s = json.dumps(run(w), indent=2)
    if a.report: open(a.report, "w").write(s)
    print(s)


if __name__ == "__main__":
    main()
