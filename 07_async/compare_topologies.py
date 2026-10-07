#!/usr/bin/env python3
"""Sync vs async drain topologies on the frozen guard. Same pre-generated plan; stable logical fault keys
(seed, request_id, retry) for transition CAS, (seed, stream_id, seq, attempt) for sink and ack, so every topology sees
the same faults for the same logical events. Asserts nothing."""
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)
import copy, json, statistics, sys, threading, time, tempfile
from pathlib import Path
import benchmark_guard as b   # the benchmark in 06_bench, on PYTHONPATH
from benchmark_fault_keys import StableFaultMap
from async_guard import NarrowAckStore, WatermarkAckStore, AsyncDrainService
from alignment_guard_v343 import *
from glitch_runtime_harness import RetentionPolicy, ThresholdConfig, TurnMetrics

class KeyedStore:
    """Transition CAS loss keyed by (request_id, retry_index): the guard passes candidates; we key on the journal's newest request."""
    def __init__(self, inner, fm: StableFaultMap, T): self.inner, self.fm, self.T = inner, fm, T; self.retries = {}; self.lock = threading.Lock()
    def load(self, u):
        t = time.perf_counter(); r = self.inner.load(u); self.T.add("store.load", time.perf_counter() - t); return r
    def compare_and_swap(self, u, v, new):
        t = time.perf_counter(); self.T.inc("cas.attempts")
        if v is not None:
            rid = next(reversed(new.request_journal)) if new.request_journal else f"{u}:v{v}"
            with self.lock: k = self.retries.get(rid, 0); self.retries[rid] = k + 1
            if self.fm.transition_cas_fails(rid, k): self.T.inc("cas.injected_losses"); self.T.add("store.cas", time.perf_counter() - t); return False
        ok = self.inner.compare_and_swap(u, v, new); self.T.add("store.cas", time.perf_counter() - t); self.T.inc("cas.wins" if ok else "cas.version_conflicts"); return ok

def keyed_sink(w, fm: StableFaultMap, box):
    seen, attempts, lock = {}, {}, threading.Lock()
    def sink(ev):
        T = box["T"]
        if w.sink_latency_ms: time.sleep(w.sink_latency_ms / 1000)
        k = (ev["stream_id"], ev["seq"])
        with lock: a = attempts.get(k, 0); attempts[k] = a + 1
        if fm.sink_delivery_fails(k[0], k[1], a): T.inc("sink.failures"); raise IOError("sink down")
        with lock: seen[k] = seen.get(k, 0) + 1; dup = seen[k] > 1
        T.inc("sink.deliveries")
        if dup: T.inc("sink.duplicate_sends")
        T.add("audit.delivery_lag", time.time() - ev["ts"])
    def anchor(h): box["T"].inc("anchor.writes")
    return sink, anchor

PACE_MS = 0.0
ARRIVAL_INTERVAL_S = 0.02   # per worker; 8 workers -> 400 ops/s offered, identical for all topologies

def run(w: b.Workload, topology: str, drain_workers: int = 2):
    fm = StableFaultMap(w.seed, w.cas_loss_rate, w.sink_failure_rate)
    Tsetup = b.Timers(); box = {"T": Tsetup}; td = tempfile.mkdtemp(); path = Path(td) / "r.json"
    inner = b.JSONRecordStore(path) if w.store_backend == "json" else b.InMemoryRecordStore()
    keyed = KeyedStore(inner, fm, Tsetup)
    store = keyed if topology == "sync" else WatermarkAckStore(keyed) if topology == "async_watermark" else NarrowAckStore(keyed, head_only=(topology == "async_head"))
    sink, anchor = keyed_sink(w, fm, box)
    cfg = b.GuardConfig(policy=b.POL, cumulative_gap_limit=10_000, threshold=ThresholdConfig(window_turns=w.window_turns, tw03_consecutive_turns=2),
                        retention=RetentionPolicy(trajectory_turn_limit=w.retention_turn_limit), outbox_cap=w.outbox_cap, request_journal_size=w.journal_horizon)
    g = AlignmentGuard(config=cfg, store=store, audit_sink=sink, anchor=anchor, authority_verifier=b.Verifier(b.Tape(b.rng_for(w.seed, "verifier"), w.verifier_unavailable_rate), Tsetup))
    users = [f"u{i}" for i in range(w.users)]
    def setup_drain(u):
        for _ in range(200):
            try: g.drain_audit(u); return
            except (IOError, ConcurrentStateError): continue
    for u in users:
        g.start(u, "S0", declared_purpose="p", required_level=2); setup_drain(u)
        for s in range(1, w.sessions_per_user): g.start(u, f"S{s}"); setup_drain(u)
    T = b.Timers(); keyed.T = T; box["T"] = T
    # reuse bench_base op closures by re-running its body would duplicate 80 lines; instead build the same ops here compactly
    hw_lock = threading.Lock(); hw = {}; committed = {u: [] for u in users}; spec_rng = b.rng_for(w.seed, "spec"); spec_lock = threading.Lock(); pick_rng = b.rng_for(w.seed, "pick")
    def out(n, k): T.inc(f"{n}.{k}")
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
        if topology != "sync": out("drain", "skipped_async_topology"); return
        t0 = time.perf_counter()
        try: n = g.drain_audit(u); T.add("op.drain", time.perf_counter() - t0); T.inc("drain.delivered", n); out("drain", "completed")
        except IOError: out("drain", "sink_error")
        except ConcurrentStateError: out("drain", "refused_cas_exhausted")
    OPS = {"evaluate": op_evaluate, "replay": op_replay, "new_epoch": op_epoch, "lower": op_lower, "drain": op_drain}
    plan = b.build_plan(w)
    svc = None
    if topology != "sync": svc = AsyncDrainService(store, sink, anchor, users, workers=drain_workers); svc.start()
    def worker(items, offset):
        # OPEN-LOOP: op k of this worker is scheduled at t0 + offset + k*interval, identical for every topology.
        # If the worker is late (blocked in a sync drain), it runs the op immediately and records the lag.
        for k, (u, s, op) in enumerate(items):
            due = t0_sched + offset + k * ARRIVAL_INTERVAL_S
            lag = time.perf_counter() - due
            if lag < 0: time.sleep(-lag)
            else: T.add("schedule.lag", lag)
            T.inc("workload.attempted"); T.inc(f"{op}.attempts"); OPS[op](u, s)
    t0_sched = time.perf_counter() + 0.01
    ts = [threading.Thread(target=worker, args=(x, i * ARRIVAL_INTERVAL_S / max(1, len(plan)))) for i, x in enumerate(plan) if x]
    wall0 = time.perf_counter()
    [t.start() for t in ts]; [t.join() for t in ts]; wall = time.perf_counter() - wall0
    if svc: svc.join()
    B, C = T.snapshot(); recs = [inner.load(u) for u in users]
    backlog = sum(len(r.pending_audit) for r in recs)
    att = C.get("workload.attempted", 0); succ = sum(C.get(k, 0) for k in ("evaluate.delivered", "replay.hit", "new_epoch.committed", "lower.authorized", "drain.completed"))
    blocked = C.get("evaluate.completed_blocked_by_mode", 0) + C.get("replay.spent_beyond_horizon", 0)
    skipped = C.get("replay.skipped_nothing_committed", 0) + C.get("lower.skipped_normal", 0) + C.get("lower.denied_or_already_lowered", 0) + C.get("drain.skipped_async_topology", 0)
    infra = sum(v for k, v in C.items() if ".refused_" in k) + C.get("drain.sink_error", 0)
    e = sorted(B.get("op.evaluate", [])); q = lambda p: round(e[min(len(e)-1, int(p*len(e)))]*1000, 3) if e else None
    return {"topology": topology, "seed": w.seed, "sink_latency_ms": w.sink_latency_ms, "sink_failure_rate": w.sink_failure_rate, "wall_s": round(wall, 3),
            "identity_closes": succ + blocked + skipped + infra == att, "arrival_interval_s": ARRIVAL_INTERVAL_S, "offered_ops_per_s": round(att / wall, 1),
            "schedule_lag_p95_ms": (lambda xs: round(sorted(xs)[int(.95*(len(xs)-1))]*1000, 2) if xs else 0.0)(B.get("schedule.lag", [])), "outbox_cap": w.outbox_cap,
            "decision_completion_fraction": round((succ + blocked) / max(1, att), 3), "useful_success_fraction": round(succ / max(1, att), 3),
            "infrastructure_refusal_rate": round(infra / max(1, att), 3), "evaluate_p50_ms": q(.5), "evaluate_p99_ms": q(.99),
            "cas_attempts_per_commit": round(C.get("cas.attempts", 0) / max(1, C.get("cas.wins", 1)), 3), "version_conflict_rate": round(C.get("cas.version_conflicts", 0) / max(1, C.get("cas.attempts", 0) - C.get("cas.injected_losses", 0)), 3),
            "duplicate_audit_send_rate": round(C.get("sink.duplicate_sends", 0) / max(1, C.get("sink.deliveries", 0)), 3),
            "outbox_occupancy_fraction": round(backlog / max(1, w.users * w.outbox_cap), 3), "backlog": backlog,
            "async": (svc.stats | {"audit_ack_conflict_rate": round(svc.stats["ack_conflicts"] / max(1, svc.stats["acked"] + svc.stats["ack_conflicts"]), 3)}) if svc else None}

def main():
    base = b.Workload("hostile_hot", users=2, sessions_per_user=8, ops_per_user=160, concurrency=8, contention_mode="shared_user",
                      cas_loss_rate=0.30, sink_failure_rate=0.20, outbox_cap=8, verifier_unavailable_rate=0.50)
    global PACE_MS
    if len(sys.argv) > 5: base.outbox_cap = int(sys.argv[5])   # diagnostic: relax the binding constraint
    global ARRIVAL_INTERVAL_S
    if len(sys.argv) > 6: ARRIVAL_INTERVAL_S = float(sys.argv[6])
    axis = sys.argv[1]; values = [float(x) for x in sys.argv[2].split(",")]; seeds = [int(x) for x in sys.argv[3].split(",")]; topos = sys.argv[4].split(",")
    rows = []
    for v in values:
        for seed in seeds:
            for topo in topos:
                w = copy.deepcopy(base); setattr(w, axis, v); w.seed = seed
                if axis == "sink_latency_ms": w.sink_failure_rate = 0.0; w.cas_loss_rate = 0.0   # isolate the latency mechanism
                if axis == "sink_failure_rate": w.sink_latency_ms = 1.0; w.cas_loss_rate = 0.0    # failure on top of the 1 ms cliff
                r = run(w, topo); rows.append(r); print(json.dumps(r))
    json.dump(rows, open(f"compare_{axis}_cap{base.outbox_cap}.json", "w"), indent=1)

if __name__ == "__main__": main()
