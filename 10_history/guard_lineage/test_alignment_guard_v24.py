import tempfile, threading, unittest
from pathlib import Path
from alignment_guard_v24 import *
from glitch_runtime_harness import BaselineInflationError, CanvasValidationError, RetentionPolicy, TurnMetrics

POLICY = ActionPolicy({("shell","*"): frozenset({Capability.EXECUTE}), ("db_write","*"): frozenset({Capability.WRITE}),
                       ("read_docs","*"): frozenset({Capability.READ}), ("send_mail","*"): frozenset({Capability.NETWORK}),
                       ("fs","read"): frozenset({Capability.READ}), ("fs","delete"): frozenset({Capability.WRITE})})
class Allow:
    def authorize_mode_lowering(self, **kw): return kw["authorization"].handle == "ok"
def mk(store=None, **kw):
    g = AlignmentGuard(config=GuardConfig(policy=POLICY, retention=RetentionPolicy(trajectory_turn_limit=3), **kw), store=store, authority_verifier=Allow())
    g.start("u","A",declared_purpose="p",required_level=2); return g
SH, DB, RD, ML = ActionRequest("shell","rm"), ActionRequest("db_write","upd"), ActionRequest("read_docs","get"), ActionRequest("send_mail","send")

class Contract(unittest.TestCase):
    def test_text_never_contains(self): self.assertTrue(mk().evaluate("u","A",1,TurnMetrics(1,.3),"disable safety kill bypass").allow)
    def test_levels_decide_and_version_advances(self):
        g = mk()
        for i, s in enumerate([1,2,3,4],1): d = g.evaluate("u","A",i,TurnMetrics(s,.3),"x")
        self.assertEqual(d.mode, GuardMode.READ_ONLY); self.assertEqual(d.committed_version, 8)   # 1 + 4 turns x (commit + drain) - 1
    def test_budget_ge_semantics_fixture(self):
        g = mk(cumulative_gap_limit=4)   # at most 3 gap units ever delivered
        delivered = 0
        for i in range(1, 8):
            d = g.evaluate("u","A",i,TurnMetrics(3,.3),"x")
            if d.allow: delivered += 1
        self.assertEqual(g.store.load("u").guard.delivered_gap_total, 1)   # TW03 streak blocks from T2; only T1 delivered
        g = mk(cumulative_gap_limit=4, ladder={})                            # ladder off: isolate the budget
        for i in range(1, 8): d = g.evaluate("u","A",i,TurnMetrics(3,.3),"x")
        self.assertEqual(g.store.load("u").guard.delivered_gap_total, 3); self.assertEqual(d.mode, GuardMode.HUMAN_REVIEW)
    def test_unknown_action_denied_and_capabilities_drive_restricted(self):
        g = mk(); unk = ActionRequest("mystery","go")
        d = g.evaluate("u","A",1,TurnMetrics(2,.3),"x", requested_actions=[unk, RD, SH]); self.assertEqual(d.actions_allowed, [RD, SH]); self.assertEqual(d.actions_denied, [unk])
        rec = g.store.load("u"); rec.guard.mode = GuardMode.RESTRICTED; g.store.compare_and_swap("u", rec.version, UserRecord(rec.version+1, rec.harness, rec.guard, rec.audit))
        d = g.evaluate("u","A",2,TurnMetrics(2,.3),"x", requested_actions=[RD, ML, DB]); self.assertEqual(d.actions_allowed, [RD]); self.assertEqual(d.actions_denied, [ML, DB])
    def test_sensitive_above_purpose_contains_reason_and_mode_together(self):
        g = mk(); d = g.evaluate("u","A",1,TurnMetrics(3,.3),"x", requested_actions=[ML])
        rec = g.store.load("u"); self.assertEqual(rec.guard.mode, GuardMode.CONTAINED); self.assertIn("send_mail", rec.guard.contained_reason); self.assertEqual(d.actions_allowed, [])
    def test_inflation_event_distinct_and_mode_raised(self):
        evs = []; g = AlignmentGuard(config=GuardConfig(policy=POLICY), audit_sink=evs.append, authority_verifier=Allow()); g.start("u","A",declared_purpose="p",required_level=2)
        for i, s in enumerate([1,2],1): g.evaluate("u","A",i,TurnMetrics(s,.3),"x")
        with self.assertRaises(CanvasValidationError): g.new_epoch("u", required_level=5, authority="client", reason="r", triggering_user_evidence="user asked")
        ev = [e for e in evs if e["type"] == "baseline_inflation_rejected"][0]
        self.assertEqual((ev["pos"], ev["source"], ev["active_epoch"], ev["active_required_level"], ev["requested_required_level"]), (2, "new_epoch", 1, 2, 5))
        self.assertEqual(g.store.load("u").guard.mode, GuardMode.HUMAN_REVIEW)
        with self.assertRaises(CanvasValidationError): g.start("u","B",required_level=5)
        self.assertEqual(sum(e["type"] == "baseline_inflation_rejected" for e in evs), 2)
    def test_lowering_verified_handle_only(self):
        g = mk(); rec = g.store.load("u"); rec.guard.mode = GuardMode.READ_ONLY; g.store.compare_and_swap("u", rec.version, UserRecord(rec.version+1, rec.harness, rec.guard, rec.audit))
        with self.assertRaises(CanvasValidationError): g.lower_mode("u", to=GuardMode.NORMAL, authorization=RecoveryAuthorization("p","bad","inc"), reason="r")
        g.lower_mode("u", to=GuardMode.NORMAL, authorization=RecoveryAuthorization("responder","ok","inc"), reason="reviewed")
        self.assertEqual(g.store.load("u").guard.mode, GuardMode.NORMAL)
        self.assertNotIn("handle", str(RecoveryAuthorization.__dataclass_fields__.keys()) and "token")  # no token field exists
        self.assertFalse(hasattr(RecoveryAuthorization("a","b","c"), "token"))

class Consistency(unittest.TestCase):
    def test_single_record_spans_harness_and_guard(self):
        g = mk(); g.evaluate("u","A",1,TurnMetrics(3,.3),"x", requested_actions=[SH])
        rec = g.store.load("u"); self.assertEqual(rec.guard.mode, GuardMode.CONTAINED); self.assertEqual(rec.harness["trajectory_position"], 1); self.assertEqual(rec.audit.seq, 2)
    def test_failed_commit_releases_nothing_and_advances_nothing(self):
        class FailingStore(InMemoryRecordStore):
            def compare_and_swap(self, u, v, new):
                if v is not None and v >= 1 and getattr(self, "fail", False): return False
                return super().compare_and_swap(u, v, new)
        st = FailingStore(); g = mk(st); st.fail = True; evs = []; g.sink = evs.append
        with self.assertRaises(ConcurrentStateError): g.evaluate("u","A",1,TurnMetrics(3,.3),"x")
        rec = g.store.load("u"); self.assertEqual(rec.harness["trajectory_position"], 0); self.assertEqual(rec.audit.seq, 0); self.assertEqual(evs, [])
    def test_cas_race_lost_turn_never_double_counts(self):
        g = mk(cumulative_gap_limit=100, ladder={})
        rec = g.store.load("u")
        c1 = derive_transition(g.cfg, "u", "A", 1, rec, TurnMetrics(4,.3), "x", [], now=1000.0)
        c2 = derive_transition(g.cfg, "u", "A", 1, rec, TurnMetrics(4,.3), "x", [], now=1000.0)   # both derived from version 1
        self.assertTrue(g.store.compare_and_swap("u", c1.old.version, c1.new))
        self.assertFalse(g.store.compare_and_swap("u", c2.old.version, c2.new))           # stale version rejected
        self.assertEqual(g.store.load("u").guard.delivered_gap_total, 2)                   # one turn, gap 2, not 4
    def test_concurrent_evaluations_serialize_by_retry(self):
        g = mk(cumulative_gap_limit=100, ladder={}); out = []
        def worker(i):
            for k in range(5): out.append(g.evaluate("u","A",k+1,TurnMetrics(3,.3),"x"))
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        [t.start() for t in ts]; [t.join() for t in ts]
        rec = g.store.load("u"); self.assertEqual(rec.harness["trajectory_position"], 20); self.assertEqual(rec.guard.delivered_gap_total, 20); self.assertEqual(rec.audit.seq, 20)
        vs = [d.committed_version for d in out]; self.assertEqual(len(set(vs)), 20)                 # each turn committed exactly once
        self.assertEqual(rec.pending_audit, []); self.assertEqual(sorted(d.trajectory_position for d in out), list(range(1, 21)))
    def test_start_idempotent_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"r.json"; g = mk(JSONRecordStore(p)); r1 = g.store.load("u").version
            g.start("u","A",declared_purpose="p",required_level=2); self.assertEqual(g.store.load("u").version, r1)   # same session: no-op
            g.evaluate("u","A",1,TurnMetrics(3,.3),"x", requested_actions=[SH])
            g2 = AlignmentGuard(config=GuardConfig(policy=POLICY), store=JSONRecordStore(p)); g2.start("u","B")
            d = g2.evaluate("u","B",1,TurnMetrics(1,.3),"x", requested_actions=[SH]); self.assertEqual(d.mode, GuardMode.CONTAINED); self.assertEqual(d.actions_allowed, [])
    def test_audit_cursor_persists_across_restart_and_chain_verifies(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"r.json"; evs = []; heads = []
            g = AlignmentGuard(config=GuardConfig(policy=POLICY), store=JSONRecordStore(p), audit_sink=evs.append, anchor=heads.append); g.start("u","A",declared_purpose="p",required_level=2)
            g.evaluate("u","A",1,TurnMetrics(1,.3),"x"); g.evaluate("u","A",2,TurnMetrics(1,.3),"x")
            g2 = AlignmentGuard(config=GuardConfig(policy=POLICY), store=JSONRecordStore(p), audit_sink=evs.append, anchor=heads.append); g2.start("u","B"); g2.evaluate("u","B",1,TurnMetrics(1,.3),"x")
            self.assertEqual([e["seq"] for e in evs], [1,2,3]); self.assertTrue(verify_chain(evs, expected_head=heads[-1]))
            self.assertFalse(verify_chain(evs[:-1], expected_head=heads[-1]))

class V24(unittest.TestCase):
    def test_crash_after_cas_before_delivery_loses_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"r.json"; evs = []; heads = []
            g = AlignmentGuard(config=GuardConfig(policy=POLICY), store=JSONRecordStore(p), audit_sink=evs.append, anchor=heads.append, authority_verifier=Allow())
            g.start("u","A",declared_purpose="p",required_level=2)
            g.drain_outbox = lambda uid: 0                                    # simulate crash after the winning CAS
            d = g.evaluate("u","A",1,TurnMetrics(3,.3),"x", requested_actions=[SH]); self.assertEqual(d.mode, GuardMode.CONTAINED)
            self.assertEqual(evs, [])                                          # nothing delivered...
            rec = JSONRecordStore(p).load("u"); self.assertEqual(rec.audit.seq, 2); self.assertEqual(len(rec.pending_audit), 2)   # ...but durably queued
            g2 = AlignmentGuard(config=GuardConfig(policy=POLICY), store=JSONRecordStore(p), audit_sink=evs.append, anchor=heads.append)
            self.assertEqual(g2.drain_outbox("u"), 2); self.assertEqual([e["seq"] for e in evs], [1, 2])
            self.assertEqual(g2.drain_outbox("u"), 0); self.assertEqual(len(evs), 2)                                # exactly once logically
            self.assertTrue(verify_chain(evs, expected_head=heads[-1])); self.assertEqual(JSONRecordStore(p).load("u").pending_audit, [])
    def test_sink_failure_keeps_outbox(self):
        calls = {"n": 0}
        def flaky(ev):
            calls["n"] += 1
            if calls["n"] == 1: raise IOError("sink down")
        g = AlignmentGuard(config=GuardConfig(policy=POLICY), audit_sink=flaky); g.start("u","A",declared_purpose="p",required_level=2)
        with self.assertRaises(IOError): g.evaluate("u","A",1,TurnMetrics(1,.3),"x")   # decision was committed; delivery failed loudly
        rec = g.store.load("u"); self.assertEqual(rec.harness["trajectory_position"], 1); self.assertEqual(len(rec.pending_audit), 1)
        self.assertEqual(g.drain_outbox("u"), 1); self.assertEqual(g.store.load("u").pending_audit, [])
    def test_retry_is_deterministic_under_fixed_now(self):
        g = mk(cumulative_gap_limit=100, ladder={}); rec = g.store.load("u")
        a = derive_transition(g.cfg, "u","A",1,rec,TurnMetrics(3,.3),"x",[], now=5000.0); b = derive_transition(g.cfg, "u","A",1,rec,TurnMetrics(3,.3),"x",[], now=5000.0)
        self.assertEqual(a.events, b.events); self.assertEqual(a.new.audit, b.new.audit); self.assertEqual(a.new.harness, b.new.harness)
    def test_only_inflation_errors_make_tw06(self):
        g = mk()
        with self.assertRaises(CanvasValidationError): g.new_epoch("u", required_level=9, authority="supervisor", reason="r", triggering_user_evidence="user changed role")  # range error, not inflation
        rec = g.store.load("u"); self.assertEqual(rec.guard.mode, GuardMode.NORMAL); self.assertEqual(rec.harness["inflation_attempts"], 0)
        with self.assertRaises(BaselineInflationError): g.new_epoch("u", required_level=4, authority="client", reason="r", triggering_user_evidence="user asked")
        self.assertEqual(g.store.load("u").guard.mode, GuardMode.HUMAN_REVIEW)
    def test_policy_per_operation(self):
        g = mk(); rd, dl, unk = ActionRequest("fs","read"), ActionRequest("fs","delete"), ActionRequest("fs","chmod")
        d = g.evaluate("u","A",1,TurnMetrics(2,.3),"x", requested_actions=[rd, dl, unk]); self.assertEqual(d.actions_allowed, [rd, dl]); self.assertEqual(d.actions_denied, [unk])
        d = g.evaluate("u","A",2,TurnMetrics(3,.3),"x", requested_actions=[rd, dl]); self.assertEqual(d.mode, GuardMode.CONTAINED); self.assertIn("fs:delete", g.store.load("u").guard.contained_reason)
    def test_verifier_called_once_and_bound_to_version(self):
        class Counting:
            n = 0
            def authorize_mode_lowering(self, **kw): Counting.n += 1; return True
        g = AlignmentGuard(config=GuardConfig(policy=POLICY), authority_verifier=Counting()); g.start("u","A",declared_purpose="p",required_level=2)
        rec = g.store.load("u"); g.store.compare_and_swap("u", rec.version, UserRecord(rec.version+1, rec.harness, GuardState(GuardMode.READ_ONLY), rec.audit))
        real_cas = g.store.compare_and_swap
        def bump_then_cas(u, v, new):   # someone else commits between verification and our CAS
            r = g.store.load(u); real_cas(u, r.version, UserRecord(r.version+1, r.harness, r.guard, r.audit)); return real_cas(u, v, new)
        g.store.compare_and_swap = bump_then_cas
        with self.assertRaises(ConcurrentStateError): g.lower_mode("u", to=GuardMode.NORMAL, authorization=RecoveryAuthorization("r","ok","inc"), reason="x")
        self.assertEqual(Counting.n, 1); self.assertEqual(g.store.load("u").guard.mode, GuardMode.READ_ONLY)
    def test_fragment_verification_needs_predecessor(self):
        heads = []; evs = []; g = AlignmentGuard(config=GuardConfig(policy=POLICY), audit_sink=evs.append, anchor=heads.append); g.start("u","A",declared_purpose="p",required_level=2)
        for i in range(4): g.evaluate("u","A",i+1,TurnMetrics(1,.3),"x")
        frag = evs[2:]; self.assertFalse(verify_chain(frag))
        self.assertTrue(verify_chain(frag, expected_previous={"stream_id": evs[1]["stream_id"], "seq": 2, "sha256": evs[1]["sha256"]}))
        self.assertFalse(verify_chain(frag, expected_previous={"stream_id": evs[1]["stream_id"], "seq": 2, "sha256": "0"*64}))

if __name__ == "__main__": unittest.main()
