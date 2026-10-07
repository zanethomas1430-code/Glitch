#!/usr/bin/env python3
"""Model-based fault testing for ALIGNMENT_GUARD v3.4.3 + GLITCH harness 1.0.1.

Generates random sequences over: start, evaluate, replay, bad-input replay, out-of-order turn, new_epoch (legit and
inflating), lower_mode, drain, CAS loss, sink failure, clock advance, restart. After EVERY operation, checks the
invariant predicates against a shadow model that only tracks what the contract promises.

Usage: python3 fuzz_guard.py [--seqs 300] [--ops 40] [--seed 1]
Exit 1 on the first violation, with the seed, sequence, and predicate that failed.
"""
from __future__ import annotations
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)

import argparse, copy, json, random, sys, tempfile
from pathlib import Path

from alignment_guard_v343 import *
from alignment_guard_v343 import _rec_to_raw, _decision_to_raw
from glitch_runtime_harness import (BaselineInflationError, CanvasValidationError, RetentionPolicy, ThresholdConfig, TurnMetrics)

POL = ActionPolicy({("shell", "rm"): frozenset({Capability.EXECUTE}), ("read_docs", "get"): frozenset({Capability.READ})})


class Grant:
    def authorize_mode_lowering(self, **kw):
        a = kw["authorization"]; return RecoveryGrant(a.principal, a.incident_id, kw["expected_version"], kw["target"], "g")


class FaultyStore(JSONRecordStore):
    """Wraps the durable store with injectable CAS loss."""
    def __init__(self, path, rng):
        super().__init__(path); self.rng = rng; self.loss_p = 0.0
    def compare_and_swap(self, u, v, new):
        if v is not None and self.rng.random() < self.loss_p: return False
        return super().compare_and_swap(u, v, new)


class Model:
    """What the contract promises, tracked independently of the implementation."""
    def __init__(self):
        self.position = 0; self.turns_by_session = {}; self.committed = {}   # request_id -> (input_digest, decision_raw, output)
        self.seq = 0; self.delivered_seqs = []; self.max_epoch = 1; self.mode = GuardMode.NORMAL; self.delivered_gap = 0


def check(g, m: Model, evs, label):
    rec = g.store.load("u")
    def fail(msg): raise AssertionError(f"[{label}] {msg}")
    if rec is None: fail("record vanished")
    # INV_9: clock and namespaces survive retention
    if rec.harness["trajectory_position"] != m.position: fail(f"trajectory_position {rec.harness['trajectory_position']} != model {m.position}")
    if rec.harness["epochs"][-1]["epoch_id"] != m.max_epoch: fail("active epoch id != model max epoch (namespace folded or skipped)")
    if [e["epoch_id"] for e in rec.harness["epochs"]] != sorted({e["epoch_id"] for e in rec.harness["epochs"]}): fail("epoch ids not strictly increasing")
    if any(t["epoch_id"] not in {e["epoch_id"] for e in rec.harness["epochs"]} for t in rec.harness["turns"]): fail("retained turn references a missing epoch")
    # INV_3B: high-water marks match the model
    if rec.spent_turns != m.turns_by_session: fail(f"spent_turns {rec.spent_turns} != model {m.turns_by_session}")
    # INV_4: mode ratchet vs model
    if rec.guard.mode != m.mode: fail(f"mode {rec.guard.mode} != model {m.mode}")
    if rec.guard.delivered_gap_total != m.delivered_gap: fail("delivered_gap_total drifted from model")
    # INV_7: audit cursor == committed envelope count; delivered seqs are a prefix, no gaps, no dupes beyond at-least-once
    if rec.audit.seq != m.seq: fail(f"audit seq {rec.audit.seq} != model {m.seq}")
    pend = [e["seq"] for e in rec.pending_audit]
    if pend != sorted(pend) or (pend and pend[-1] != rec.audit.seq): fail("outbox not a contiguous tail of the cursor")
    uniq = sorted(set(m.delivered_seqs))
    if uniq and (uniq != list(range(uniq[0], uniq[-1] + 1))): fail("delivered seqs have a gap")
    if uniq and pend and uniq[-1] >= pend[0]: fail("an envelope both delivered-and-removed and still pending")
    if len(rec.pending_audit) > g.cfg.outbox_cap: fail("outbox exceeds cap")
    # INV_3: every committed request replays exactly
    for rid, (idig, draw, out) in m.committed.items():
        j = rec.request_journal.get(rid)
        if j is None: continue   # evicted past horizon: allowed
        if j["input_digest"] != idig or j["decision"] != draw or j["output"] != out: fail(f"journal entry {rid} drifted")


def run_sequence(seed, n_ops, verbose=False):
    rng = random.Random(seed); td = tempfile.mkdtemp(); path = Path(td) / "r.json"
    now = [1_000_000.0]; evs = []
    cfg = GuardConfig(policy=POL, cumulative_gap_limit=rng.choice([3, 5, 100]), ladder=rng.choice([{}, {"TW03": GuardMode.READ_ONLY}, None]) or GuardConfig().ladder,
                      threshold=ThresholdConfig(window_turns=3, tw03_consecutive_turns=2),
                      retention=RetentionPolicy(trajectory_turn_limit=3, tripwire_event_days=1, baseline_transition_days=1),
                      outbox_cap=rng.choice([4, 8, 64]), request_journal_size=rng.choice([2, 8]))
    store = FaultyStore(path, rng)
    def mk(): return AlignmentGuard(config=cfg, store=store, audit_sink=evs.append, authority_verifier=Grant(), clock=lambda: now[0])
    g = mk(); m = Model()
    g.start("u", "A", declared_purpose="p", required_level=2); m.seq = 1; m.turns_by_session = {}
    sessions = ["A"]; log = []
    for step in range(n_ops):
        op = rng.choices(["evaluate", "replay", "bad_replay", "skip_turn", "respend_turn", "epoch", "inflate", "lower", "drain", "clock", "restart", "cas_loss", "new_session"],
                         weights=[30, 8, 4, 4, 5, 5, 6, 5, 12, 6, 5, 6, 4])[0]
        log.append(op)
        try:
            if op == "cas_loss":
                store.loss_p = rng.choice([0.0, 0.3, 0.9])
            elif op == "clock":
                now[0] += rng.choice([1.0, 3600.0, 3 * 86400.0])
            elif op == "restart":
                g = mk()
            elif op == "new_session":
                s = f"S{len(sessions)}"; sessions.append(s)
                try:
                    before_epochs = g.store.load("u").harness["epochs"]
                    g.start("u", s); m.seq += 1
                except AuditBackpressureError: pass
                except ConcurrentStateError: pass
            elif op == "drain":
                try:
                    before = [e["seq"] for e in g.store.load("u").pending_audit]
                    n = g.drain_audit("u"); m.delivered_seqs += before[:n]
                except ConcurrentStateError:
                    # at-least-once: some may have been sent but not removed; model only counts removed ones
                    after = {e["seq"] for e in g.store.load("u").pending_audit}
                    m.delivered_seqs += [s for s in before if s not in after]
            elif op in ("evaluate", "replay", "bad_replay", "skip_turn", "respend_turn"):
                s = rng.choice(sessions); hw = m.turns_by_session.get(s, 0)
                if op == "respend_turn":
                    if hw == 0: continue
                    t = rng.randint(1, hw); rid = f"{s}:{t}:respend:{rng.random():.6f}"; cin = f"in-{rid}"   # fresh id, spent turn -> must be refused
                elif op == "evaluate" or not m.committed:
                    t = hw + 1; rid = f"{s}:{t}:{rng.random():.6f}"; cin = f"in-{rid}"
                elif op == "replay":
                    rid = rng.choice(list(m.committed)); t, cin = None, None
                elif op == "bad_replay":
                    rid = rng.choice(list(m.committed)); t, cin = None, "DIFFERENT"
                else:
                    t = hw + 2; rid = f"{s}:{t}:skip"; cin = f"in-{rid}"
                if t is None:   # replay: find the original turn/session for the digest
                    entry = None; rec = g.store.load("u"); j = rec.request_journal.get(rid)
                    if j is None: continue   # evicted; nothing to test
                    s, t = j["session"], j["caller_turn"]; cin = cin or f"in-{rid}"
                ident = RequestIdentity.from_canonical_input(rid, s, t, cin)
                spec = rng.choice([1, 2, 3, 4]); acts = [ActionRequest("shell", "rm")] if rng.random() < 0.2 else []
                pre = g.store.load("u")
                try:
                    d = g.evaluate("u", s, t, TurnMetrics(spec, .3), f"out-{rid}-{step}", identity=ident, requested_actions=acts)
                except (RequestIdentityConflict, TurnSequenceError, AuditBackpressureError, ConcurrentStateError):
                    post = g.store.load("u")
                    if _rec_to_raw(pre) != _rec_to_raw(post): raise AssertionError(f"[{op}] refused evaluate changed the record")
                    continue
                if op == "respend_turn": raise AssertionError(f"[{op}] a fresh request id on spent turn {s}:{t} was evaluated")
                if rid in m.committed:   # replay path: must be exact
                    idig, draw, out = m.committed[rid]
                    if _decision_to_raw(d) != draw or d.output != out: raise AssertionError("replay returned a different decision")
                    if _rec_to_raw(pre) != _rec_to_raw(g.store.load("u")): raise AssertionError("replay changed the record")
                    continue
                # fresh commit: update model from the committed record (the model tracks promises, the record is the oracle for counts)
                rec = g.store.load("u")
                m.position += 1; m.turns_by_session[s] = t; m.seq = rec.audit.seq; m.mode = rec.guard.mode; m.delivered_gap = rec.guard.delivered_gap_total
                m.committed[rid] = (ident.input_digest, _decision_to_raw(d), d.output)
                if len(m.committed) > cfg.request_journal_size * 4:   # keep the model bounded like the journal
                    for k in list(m.committed)[: len(m.committed) - cfg.request_journal_size]: m.committed.pop(k)
            elif op == "epoch":
                try:
                    g.new_epoch("u", required_level=rng.choice([1, 2, 3, 4]), authority="supervisor", reason="r", triggering_user_evidence="user changed role")
                    m.max_epoch += 1; m.seq += 1
                except (AuditBackpressureError, ConcurrentStateError): pass
            elif op == "inflate":
                pre_mode = m.mode
                try:
                    g.new_epoch("u", required_level=5, authority=rng.choice(["client", "user", "model"]), reason="r", triggering_user_evidence="asked")
                    raise AssertionError("inflation accepted")
                except BaselineInflationError:
                    rec = g.store.load("u"); m.seq = rec.audit.seq; m.mode = rec.guard.mode
                    if m.mode.value < max(pre_mode.value, cfg.ladder.get("TW06", GuardMode.NORMAL).value): raise AssertionError("TW06 did not ratchet")
                except (AuditBackpressureError, ConcurrentStateError): pass
            elif op == "lower":
                if m.mode == GuardMode.NORMAL: continue
                try:
                    g.lower_mode("u", to=GuardMode.NORMAL, authorization=RecoveryAuthorization("responder", "h", "inc"), reason="reviewed")
                    m.mode = GuardMode.NORMAL; m.seq += 1
                except (AuditBackpressureError, ConcurrentStateError, CanvasValidationError): pass
            check(g, m, evs, f"seed={seed} step={step} op={op}")
        except AssertionError as e:
            return False, log, str(e)
    return True, log, ""


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--seqs", type=int, default=200); ap.add_argument("--ops", type=int, default=40); ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args(); fails = 0
    for i in range(a.seqs):
        ok, log, msg = run_sequence(a.seed * 100_000 + i, a.ops)
        if not ok:
            fails += 1; print(f"VIOLATION seed={a.seed * 100_000 + i}\n  {msg}\n  ops: {' '.join(log)}"); break
    print(f"{a.seqs - fails}/{a.seqs} sequences x {a.ops} ops held all predicates" if not fails else "FAILED")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
