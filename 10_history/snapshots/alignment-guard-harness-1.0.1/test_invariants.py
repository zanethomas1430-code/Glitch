"""ALIGNMENT_GUARD reference runtime contract — invariants as executable properties.

Each test is one invariant. A future change that weakens the contract must break a test here,
not just a feature test. Names are the contract.
"""
import copy, json, tempfile, threading, unittest
from pathlib import Path
from alignment_guard_v343 import *
from alignment_guard_v343 import _rec_to_raw, _decision_to_raw, _effect_id

def ID(session, turn, canonical_input=None, request_id=None):
    return RequestIdentity.from_canonical_input(request_id or f"{session}:{turn}", session, turn, canonical_input or f"input-{session}-{turn}")

_orig_evaluate = AlignmentGuard.evaluate
def _ev(self, user_id, session_id, caller_turn, metrics, proposed_output, *, requested_actions=(), request_id=None, canonical_input=None, identity=None):
    """Test shim: legacy call sites -> RequestIdentity. Contract API requires identity; the shim only builds it."""
    if identity is None: identity = ID(session_id, caller_turn, canonical_input, request_id)
    return _orig_evaluate(self, user_id, session_id, caller_turn, metrics, proposed_output, identity=identity, requested_actions=requested_actions)
AlignmentGuard.evaluate = _ev

from glitch_runtime_harness import ThresholdConfig, BaselineInflationError, CanvasValidationError, TurnMetrics

POL = ActionPolicy({("shell","rm"): frozenset({Capability.EXECUTE}), ("read_docs","get"): frozenset({Capability.READ})})
class Grant:
    def authorize_mode_lowering(self, **kw):
        a = kw["authorization"]; return RecoveryGrant(a.principal, a.incident_id, kw["expected_version"], kw["target"], "g")
def guard(store=None, **kw):
    g = AlignmentGuard(config=GuardConfig(policy=POL, cumulative_gap_limit=100, ladder=kw.pop("ladder", {}), **kw), store=store, authority_verifier=Grant())
    g.start("u","A",declared_purpose="p",required_level=2)
    try: g.drain_audit("u")                                   # genesis event drained; tests count from zero
    except ConcurrentStateError: pass                         # stores that never win CAS keep it queued; that's the test's business
    return g
def snapshot(g): return copy.deepcopy(g.store.load("u"))
def same(a, b): return _rec_to_raw(a) == _rec_to_raw(b)


class INV_1_ONE_CONSISTENCY_DOMAIN(unittest.TestCase):
    """Trajectory, guard verdict, request result, audit cursor, and outbox change together or not at all."""
    def test_single_cas_moves_all_fields_together(self):
        g = guard(); b = snapshot(g); g.evaluate("u","A",1,TurnMetrics(3,.3),"x", requested_actions=[ActionRequest("shell","rm")]); a = snapshot(g)
        self.assertEqual(a.version, b.version + 1)
        self.assertEqual(a.harness["trajectory_position"], 1); self.assertEqual(a.guard.mode, GuardMode.CONTAINED)
        self.assertEqual(a.audit.seq, 3); self.assertEqual(len(a.pending_audit), 2); self.assertIn("A:1", a.request_journal); self.assertEqual(a.spent_turns["A"], 1)   # seq 1 = genesis
    def test_lost_cas_moves_nothing(self):
        class Never(InMemoryRecordStore):
            def compare_and_swap(self, u, v, new): return super().compare_and_swap(u, v, new) if v is None else False
        g = guard(Never()); b = snapshot(g)
        with self.assertRaises(ConcurrentStateError): g.evaluate("u","A",1,TurnMetrics(3,.3),"x")
        self.assertTrue(same(snapshot(g), b))


class INV_2A_NO_PRECOMMIT_PAYLOAD_STORE(unittest.TestCase):
    """The RecordStore is the guard's only durable store for candidate response, action-verdict, trajectory, guard,
    request-journal, and audit-outbox state. No candidate output or action verdict is written to another store before
    CAS. Authorization infrastructure may have its own pre-CAS state transitions; sink/anchor operate only on
    already-committed envelopes."""
    def test_verifier_may_mutate_before_cas_but_guard_state_does_not(self):
        class Counting:
            n = 0
            def authorize_mode_lowering(self, **kw): Counting.n += 1; a = kw["authorization"]; return RecoveryGrant(a.principal, a.incident_id, kw["expected_version"], kw["target"], "g")
        class LoseOnce(InMemoryRecordStore):
            done = False
            def compare_and_swap(self, u, v, new):
                if v is not None and not LoseOnce.done: LoseOnce.done = True; return False
                return super().compare_and_swap(u, v, new)
        g = AlignmentGuard(config=GuardConfig(policy=POL), store=LoseOnce(), authority_verifier=Counting()); g.start("u","A",declared_purpose="p",required_level=2)
        r = g.store.load("u"); LoseOnce.done = True; g.store.compare_and_swap("u", r.version, UserRecord(r.version+1, r.harness, GuardState(GuardMode.READ_ONLY), r.audit, r.pending_audit, r.request_journal, r.spent_turns)); LoseOnce.done = False
        before = snapshot(g)
        with self.assertRaises(ConcurrentStateError): g.lower_mode("u", to=GuardMode.NORMAL, authorization=RecoveryAuthorization("a","h","i"), reason="r")
        self.assertEqual(Counting.n, 1)                   # the verifier DID transition (pre-CAS, by design, not replayed)
        self.assertTrue(same(snapshot(g), before))        # guard-owned truth did not
    def test_sink_and_anchor_only_see_committed_envelopes(self):
        seen = []
        class Never(InMemoryRecordStore):
            def compare_and_swap(self, u, v, new): return super().compare_and_swap(u, v, new) if v is None else False
        g = AlignmentGuard(config=GuardConfig(policy=POL), store=Never(), audit_sink=seen.append, anchor=seen.append); g.start("u","A",declared_purpose="p",required_level=2)
        with self.assertRaises(ConcurrentStateError): g.evaluate("u","A",1,TurnMetrics(3,.3),"x")
        with self.assertRaises(ConcurrentStateError): g.drain_audit("u")
        self.assertEqual({e.get("type") for e in seen if "type" in e}, {"session_started"})   # only the committed genesis; no turn/mode envelope ever reached them
    def test_only_durable_state_store_is_the_record_store(self):
        g = guard(); self.assertEqual(sorted(vars(g)), ["anchor","cfg","clock","sink","store","verifier"])   # no payload/verdict store besides `store`
    def test_module_defines_no_response_store(self):
        import alignment_guard_v343 as m
        self.assertFalse([n for n in dir(m) if "Response" in n and "Store" in n])
    def test_response_ref_is_derivable_not_secret(self):
        from alignment_guard_v343 import response_ref_for
        self.assertEqual(response_ref_for("u", 2, "hello"), response_ref_for("u", 2, "hello"))   # deterministic; do not treat as a capability


class INV_2_COMMIT_BEFORE_RELEASE(unittest.TestCase):
    """No model output or action authorization becomes externally releasable, and no guard-owned safety transition
    becomes truth, before its winning CAS. A losing candidate leaves nothing retrievable anywhere."""
    def test_losing_candidate_leaves_no_retrievable_response(self):
        class LoseFirst(InMemoryRecordStore):
            lost = False
            def compare_and_swap(self, u, v, new):
                if v is not None and not LoseFirst.lost: LoseFirst.lost = True; return False
                return super().compare_and_swap(u, v, new)
        g = guard(LoseFirst()); before = snapshot(g)
        d = g.evaluate("u","A",1,TurnMetrics(2,.3),"SECRET_OUTPUT", request_id="r1", canonical_input="q")   # first CAS loses, retry wins
        rec = g.store.load("u"); self.assertEqual(rec.version, before.version + 1)                          # exactly one commit
        self.assertEqual(sum("SECRET_OUTPUT" in json.dumps(_rec_to_raw(rec)) for _ in [0]), 1)          # payload exists once, inside the committed record
        self.assertEqual(d.committed_version, rec.version)
        # nothing else in the process holds a candidate's output: the guard has no other store
        self.assertEqual([n for n in vars(g) if n not in ("cfg","store","sink","anchor","verifier","clock")], [])
    def test_released_decision_version_is_stored_version(self):
        g = guard(); d = g.evaluate("u","A",1,TurnMetrics(1,.3),"x"); self.assertEqual(d.committed_version, g.store.load("u").version)
    def test_no_release_without_commit(self):
        seen = []
        class Never(InMemoryRecordStore):
            def compare_and_swap(self, u, v, new):
                if v is None: return super().compare_and_swap(u, v, new)
                seen.append(new.request_journal); return False
        g = guard(Never())
        with self.assertRaises(ConcurrentStateError): g.evaluate("u","A",1,TurnMetrics(1,.3),"x")
        self.assertTrue(seen)                         # candidates were derived...
        self.assertEqual(g.store.load("u").request_journal, {})   # ...none became truth


class INV_3B_SESSION_TURN_MONOTONICITY(unittest.TestCase):
    """For a given session, a newly evaluated caller_turn must be exactly previous+1 (strictly sequential, which implies
    monotonic). Retries of committed identities are the only exception. spent_turns[session] = max_turn is therefore a
    correct compact tombstone, not a lossy approximation."""
    def test_sequence_enforced_and_holes_refused(self):
        g = guard(); g.evaluate("u","A",1,TurnMetrics(1,.3),"x"); before = snapshot(g)
        with self.assertRaises(TurnSequenceError): g.evaluate("u","A",3,TurnMetrics(1,.3),"x")
        self.assertTrue(same(snapshot(g), before))
        g.evaluate("u","A",2,TurnMetrics(1,.3),"x"); g.evaluate("u","A",3,TurnMetrics(1,.3),"x")
        self.assertEqual(g.store.load("u").spent_turns["A"], 3)
    def test_sessions_are_independent_sequences(self):
        g = guard(); g.evaluate("u","A",1,TurnMetrics(1,.3),"x"); g.evaluate("u","A",2,TurnMetrics(1,.3),"x")
        self.assertTrue(g.evaluate("u","B",1,TurnMetrics(1,.3),"x").allow); self.assertEqual(g.store.load("u").spent_turns, {"A": 2, "B": 1})


class INV_3_REQUEST_IDEMPOTENCY(unittest.TestCase):
    def test_identity_material_is_required(self):
        g = guard()
        for bad in (lambda: RequestIdentity("", "a"*64), lambda: RequestIdentity("r1", ""), lambda: RequestIdentity("r1", "nothex"),
                    lambda: RequestIdentity.from_canonical_input("r1","A",1,""), lambda: RequestIdentity.from_canonical_input("r1","A",1,"   ")):
            with self.assertRaises(InvalidRequestIdentity): bad()
        with self.assertRaises(InvalidRequestIdentity): _orig_evaluate(g, "u","A",1,TurnMetrics(1,.3),"x", identity=None)
        self.assertEqual(g.store.load("u").harness["trajectory_position"], 0)
    """Within the idempotency horizon, a committed request identity can never become a trajectory event twice,
    regardless of intervening requests, retries, concurrency, or restart. Same key + same digest -> exact committed
    result. Same key + different digest -> identity conflict. Beyond the horizon the identity stays spent. All leave
    safety state unchanged."""
    def test_delayed_replay_is_still_a_read(self):
        g = guard(); a1 = g.evaluate("u","A",1,TurnMetrics(2,.3),"first"); g.evaluate("u","A",2,TurnMetrics(2,.3),"second"); before = snapshot(g)
        a2 = g.evaluate("u","A",1,TurnMetrics(2,.3),"first")
        self.assertTrue(same(snapshot(g), before)); self.assertEqual(_decision_to_raw(a1), _decision_to_raw(a2)); self.assertEqual(a1.output, a2.output)
    def test_identity_stays_spent_beyond_horizon(self):
        g = guard(request_journal_size=2)
        for k in range(1, 6): g.evaluate("u","A",k,TurnMetrics(1,.3),f"o{k}")
        r = g.store.load("u"); self.assertEqual(set(r.request_journal), {"A:4","A:5"}); self.assertEqual(r.spent_turns["A"], 5)
        before = snapshot(g)
        with self.assertRaises(RequestIdentityConflict): g.evaluate("u","A",1,TurnMetrics(1,.3),"o1")   # evicted: not replayable, not re-evaluable
        with self.assertRaises(RequestIdentityConflict): g.evaluate("u","A",3,TurnMetrics(9,.3),"zzz")
        with self.assertRaises(TurnSequenceError): g.evaluate("u","A",7,TurnMetrics(1,.3),"skip")     # hole: refused, not spent
        self.assertTrue(same(snapshot(g), before)); self.assertEqual(g.store.load("u").harness["trajectory_position"], 5)
    def test_replay_never_rescores_or_regenerates(self):
        g = guard(); d1 = g.evaluate("u","A",1,TurnMetrics(2,.3),"first", request_id="r1", canonical_input="hello"); before = snapshot(g)
        d2 = g.evaluate("u","A",1,TurnMetrics(5,.1),"regenerated", requested_actions=[ActionRequest("shell","rm")], request_id="r1", canonical_input="hello")
        self.assertEqual(d2.output, "first"); self.assertEqual(_decision_to_raw(d1), _decision_to_raw(d2)); self.assertTrue(same(snapshot(g), before))
    def test_replay_is_a_read(self):
        g = guard(); a = ActionRequest("read_docs","get","d")
        d1 = g.evaluate("u","A",1,TurnMetrics(2,.3),"x", requested_actions=[a]); s1 = snapshot(g)
        d2 = g.evaluate("u","A",1,TurnMetrics(2,.3),"x", requested_actions=[a]); s2 = snapshot(g)
        self.assertTrue(same(s1, s2)); self.assertEqual(_decision_to_raw(d1), _decision_to_raw(d2))
    def test_identity_cannot_be_respent(self):
        g = guard(); g.evaluate("u","A",1,TurnMetrics(2,.3),"x", request_id="r1", canonical_input="hello"); s = snapshot(g)
        with self.assertRaises(RequestIdentityConflict): g.evaluate("u","A",1,TurnMetrics(2,.3),"x", request_id="r1", canonical_input="goodbye")   # same id, different input
        with self.assertRaises(RequestIdentityConflict): g.evaluate("u","A",1,TurnMetrics(2,.3),"x", request_id="r2", canonical_input="hello")    # new id, spent turn
        self.assertTrue(same(snapshot(g), s))


class INV_4_MODE_RATCHET(unittest.TestCase):
    """Mode never decreases through evaluation. Only a version-bound, principal-bound grant lowers it."""
    def test_evaluation_never_lowers(self):
        g = guard(ladder={"TW02": GuardMode.RESTRICTED}); r = g.store.load("u"); g.store.compare_and_swap("u", r.version, UserRecord(r.version+1, r.harness, GuardState(GuardMode.HUMAN_REVIEW), r.audit))
        for i in range(1, 6): d = g.evaluate("u","A",i,TurnMetrics(1,.3),"x"); self.assertEqual(d.mode, GuardMode.HUMAN_REVIEW)
    def test_lowering_requires_bound_grant(self):
        g = guard(); r = g.store.load("u"); g.store.compare_and_swap("u", r.version, UserRecord(r.version+1, r.harness, GuardState(GuardMode.READ_ONLY), r.audit))
        class Wrong:
            def authorize_mode_lowering(self, **kw): return RecoveryGrant("other", kw["authorization"].incident_id, kw["expected_version"], kw["target"], "g")
        g.verifier = Wrong()
        with self.assertRaises(CanvasValidationError): g.lower_mode("u", to=GuardMode.NORMAL, authorization=RecoveryAuthorization("alice","h","i"), reason="r")
        g.verifier = Grant(); g.lower_mode("u", to=GuardMode.NORMAL, authorization=RecoveryAuthorization("alice","h","i"), reason="r")
        self.assertEqual(g.store.load("u").guard.mode, GuardMode.NORMAL)


class INV_5_BASELINE_EXTERNAL(unittest.TestCase):
    """The trajectory cannot raise its own reference point; every baseline change is audited."""
    def test_no_client_path_raises(self):
        g = guard(); s = snapshot(g)
        with self.assertRaises(BaselineInflationError): g.start("u","B",required_level=5)
        with self.assertRaises(BaselineInflationError): g.new_epoch("u", required_level=5, authority="user", reason="r", triggering_user_evidence="asked")
        self.assertEqual(g.store.load("u").harness["epochs"][-1]["required_level"], 2)
    def test_every_baseline_change_is_audited(self):
        evs = []; g = AlignmentGuard(config=GuardConfig(policy=POL), audit_sink=evs.append, authority_verifier=Grant()); g.start("u","A",declared_purpose="p",required_level=3)
        g.start("u","B",required_level=1)
        g.new_epoch("u", required_level=4, authority="supervisor", reason="verified", triggering_user_evidence="license")
        with self.assertRaises(BaselineInflationError): g.new_epoch("u", required_level=5, authority="client", reason="r", triggering_user_evidence="asked")
        g.drain_audit("u"); self.assertEqual([e["type"] for e in evs if e["type"] != "session_started"], ["baseline_lowered","epoch","baseline_inflation_rejected","mode_raised"])


class INV_6_ACTIONS_FAIL_CLOSED(unittest.TestCase):
    """Unknown actions are denied. Sensitive effects above purpose contain. Every allowed action carries a stable effect_id."""
    def test_unknown_denied_everywhere(self):
        g = guard(); u = ActionRequest("mystery","go")
        self.assertEqual(g.evaluate("u","A",1,TurnMetrics(1,.3),"x", requested_actions=[u]).actions_denied, [u])
    def test_sensitive_above_purpose_contains(self):
        g = guard(); d = g.evaluate("u","A",1,TurnMetrics(3,.3),"x", requested_actions=[ActionRequest("shell","rm")])
        self.assertEqual(d.mode, GuardMode.CONTAINED); self.assertEqual(d.actions_allowed, [])
    def test_effect_id_is_deterministic_for_committed_decision(self):
        g = guard(); a = ActionRequest("read_docs","get","d")
        d = g.evaluate("u","A",1,TurnMetrics(2,.3),"x", requested_actions=[a])
        self.assertEqual(d.actions_allowed[0].effect_id, _effect_id(user_id="u", trajectory_position=1, committed_version=d.committed_version, index=0, action=a))


class INV_7_AUDIT_DURABLE_AND_BOUNDED(unittest.TestCase):
    def test_first_contact_is_audited_and_bounded(self):
        g = AlignmentGuard(config=GuardConfig(policy=POL, outbox_cap=0))
        with self.assertRaises(AuditBackpressureError): g.start("u","A",declared_purpose="p",required_level=2)
        self.assertIsNone(g.store.load("u"))                                        # no state created without its audit
        g = AlignmentGuard(config=GuardConfig(policy=POL)); r = g.start("u","A",declared_purpose="p",required_level=2)
        self.assertEqual(r.audit.seq, 1); self.assertEqual(r.pending_audit[0]["type"], "session_started"); self.assertTrue(r.pending_audit[0]["genesis"])
    """Every committed audit envelope is durably recoverable until acknowledged. Transport is at-least-once with
    stable (stream_id, seq) identity; exactly-once is the sink/anchor's obligation. No transition may commit if its
    complete audit emission would exceed the outbox bound. Backpressure changes no safety state."""
    def test_transition_cannot_overrun_outbox_cap(self):
        g = guard(outbox_cap=2); g.evaluate("u","A",1,TurnMetrics(1,.3),"x"); before = snapshot(g)   # one slot left
        with self.assertRaises(AuditBackpressureError):                                              # wants mode_raised + turn
            g.evaluate("u","A",2,TurnMetrics(3,.3),"x", requested_actions=[ActionRequest("shell","rm")])
        self.assertTrue(same(snapshot(g), before))
    def test_every_producer_is_bounded(self):
        g = guard(outbox_cap=1); g.evaluate("u","A",1,TurnMetrics(1,.3),"x"); before = snapshot(g)   # full
        with self.assertRaises(AuditBackpressureError): g.start("u","B",required_level=1)                                   # session_started+baseline_lowered
        with self.assertRaises(AuditBackpressureError): g.new_epoch("u", required_level=3, authority="s", reason="r", triggering_user_evidence="e")
        with self.assertRaises(AuditBackpressureError): g.new_epoch("u", required_level=5, authority="client", reason="r", triggering_user_evidence="e")  # TW06 path
        r = g.store.load("u"); g.store.compare_and_swap("u", r.version, UserRecord(r.version+1, r.harness, GuardState(GuardMode.READ_ONLY), r.audit, r.pending_audit, r.request_journal, r.spent_turns)); before2 = snapshot(g)
        with self.assertRaises(AuditBackpressureError): g.lower_mode("u", to=GuardMode.NORMAL, authorization=RecoveryAuthorization("a","h","i"), reason="r")
        self.assertTrue(same(snapshot(g), before2)); self.assertEqual(before2.harness, before.harness)
    def test_transport_is_at_least_once_with_stable_identity(self):
        seen = []
        class Flaky(InMemoryRecordStore):
            fail_once = True
            def compare_and_swap(self, u, v, new):
                if new.pending_audit == [] and Flaky.fail_once and v not in (None,): Flaky.fail_once = False; return False   # crash between sink and remove-CAS
                return super().compare_and_swap(u, v, new)
        g = guard(Flaky()); Flaky.fail_once = True                     # re-arm after the helper's genesis drain consumed it
        g.sink = seen.append; g.evaluate("u","A",1,TurnMetrics(1,.3),"x"); g.drain_audit("u")
        self.assertEqual([e["seq"] for e in seen], [2, 2]); self.assertEqual(g.store.load("u").pending_audit, [])   # sent twice, same identity
    def test_crash_before_delivery_loses_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"r.json"; evs = []
            g = guard(JSONRecordStore(p)); g.evaluate("u","A",1,TurnMetrics(1,.3),"x")            # never drained: "crash"
            g2 = AlignmentGuard(config=GuardConfig(policy=POL), store=JSONRecordStore(p), audit_sink=evs.append)
            self.assertEqual(g2.drain_audit("u"), 1); self.assertEqual(g2.drain_audit("u"), 0); self.assertEqual([e["seq"] for e in evs], [2])   # 1 was genesis, drained by guard()
    def test_chain_and_fragment_verification(self):
        evs = []; heads = []; g = AlignmentGuard(config=GuardConfig(policy=POL, cumulative_gap_limit=100, ladder={}), audit_sink=evs.append, anchor=heads.append); g.start("u","A",declared_purpose="p",required_level=2)
        for i in range(4): g.evaluate("u","A",i+1,TurnMetrics(1,.3),"x")
        g.drain_audit("u"); self.assertTrue(verify_chain(evs, expected_head=heads[-1])); self.assertFalse(verify_chain(evs[:1]+evs[2:]))
        self.assertFalse(verify_chain(evs[2:])); self.assertTrue(verify_chain(evs[2:], expected_previous={"stream_id": evs[1]["stream_id"], "seq": 2, "sha256": evs[1]["sha256"]}))
    def test_outbox_bound_is_fail_closed(self):
        g = guard(outbox_cap=2); g.evaluate("u","A",1,TurnMetrics(1,.3),"x"); g.evaluate("u","A",2,TurnMetrics(1,.3),"x"); s = snapshot(g)
        with self.assertRaises(AuditBackpressureError): g.evaluate("u","A",3,TurnMetrics(1,.3),"x")
        self.assertTrue(same(snapshot(g), s))


class INV_8_DETERMINISTIC_TRANSITION(unittest.TestCase):
    """derive_transition is a function of (config, record, inputs, now). No hidden clock, no shared state."""
    def test_same_inputs_same_candidate(self):
        g = guard(); r = g.store.load("u")
        a = derive_transition(g.cfg,"u","A",1,r,TurnMetrics(3,.3),"x",[], now=7.0); b = derive_transition(g.cfg,"u","A",1,r,TurnMetrics(3,.3),"x",[], now=7.0)
        self.assertEqual(_rec_to_raw(a.new), _rec_to_raw(b.new)); self.assertEqual(a.events, b.events)
    def test_derivation_has_no_side_effects(self):
        g = guard(); r = g.store.load("u"); s = snapshot(g); derive_transition(g.cfg,"u","A",1,r,TurnMetrics(3,.3),"x",[ActionRequest("shell","rm")], now=7.0)
        self.assertTrue(same(snapshot(g), s))


class INV_9_TRAJECTORY_AND_REFERENCE_INDEPENDENT_OF_RETENTION(unittest.TestCase):
    """Retention may remove payload history but may not alter trajectory_position, the detector history required by
    configured tripwires, the identity of any retained epoch, or the monotonic namespace for future epoch ids."""
    def test_retention_cannot_shorten_detector_window(self):
        from glitch_runtime_harness import RetentionPolicy
        with self.assertRaises(CanvasValidationError):
            AlignmentGuard(config=GuardConfig(policy=POL, threshold=ThresholdConfig(window_turns=6), retention=RetentionPolicy(trajectory_turn_limit=2))).start("u","A",declared_purpose="p",required_level=2)
    def test_epoch_namespace_monotonic_under_retention(self):
        from glitch_runtime_harness import RetentionPolicy
        now = [1e6]; g = AlignmentGuard(config=GuardConfig(policy=POL, threshold=ThresholdConfig(window_turns=1, tw03_consecutive_turns=1), retention=RetentionPolicy(1,1,1)), clock=lambda: now[0])
        g.start("u","A",declared_purpose="p",required_level=1)
        for l in (2, 3): g.new_epoch("u", required_level=l, authority="s", reason="r", triggering_user_evidence="e")
        now[0] += 10*86400; g.start("u","B"); g.new_epoch("u", required_level=4, authority="s", reason="r", triggering_user_evidence="e")
        self.assertEqual(g.store.load("u").harness["epochs"][-1]["epoch_id"], 4)
    def test_retention_policy_consistent_across_entry_points(self):
        from glitch_runtime_harness import RetentionPolicy
        g = guard(threshold=ThresholdConfig(window_turns=2), retention=RetentionPolicy(trajectory_turn_limit=2, tripwire_event_days=30, baseline_transition_days=1))
        for i in range(1, 4): g.evaluate("u","A",i,TurnMetrics(1,.3),"x")                            # turns under epoch 1
        g.new_epoch("u", required_level=3, authority="s", reason="r", triggering_user_evidence="e")     # epoch 2, active, fresh
        r = g.store.load("u")
        for ep in r.harness["epochs"]: ep["assignment_timestamp"] -= 5*86400                            # now everything is old
        g.store.compare_and_swap("u", r.version, UserRecord(r.version+1, r.harness, r.guard, r.audit, r.pending_audit, r.request_journal, r.spent_turns))
        g.start("u","B",required_level=1)                                                                  # session path: epoch 3 active; epoch 2 old + unreferenced
        r = g.store.load("u")
        keep = {t["epoch_id"] for t in r.harness["turns"]} | {r.harness["epochs"][-1]["epoch_id"]}     # {1, 3}
        self.assertEqual({e["epoch_id"] for e in r.harness["epochs"]}, keep, "session path did not apply epoch retention")
        self.assertEqual(r.harness["trajectory_position"], 3); self.assertEqual(len(r.harness["turns"]), 2)

class INV_7B_AUDIT_DRAIN_BOUNDED_PROGRESS(unittest.TestCase):
    """A drain attempt either acknowledges committed envelopes within the retry bound or terminates with an explicit
    concurrency error. CAS contention cannot erase the envelope, change its stable identity, falsely report
    acknowledgement, or trap the caller indefinitely."""
    def _never(self):
        class Never(InMemoryRecordStore):
            def compare_and_swap(self, u, v, new): return super().compare_and_swap(u, v, new) if v is None else False
        seen = []; g = AlignmentGuard(config=GuardConfig(policy=POL), store=Never(), audit_sink=seen.append); g.start("u","A",declared_purpose="p",required_level=2)
        return g, seen
    def test_terminates_with_explicit_error(self):
        g, _ = self._never()
        with self.assertRaises(ConcurrentStateError): g.drain_audit("u")
    def test_contention_cannot_erase_the_envelope(self):
        g, _ = self._never(); before = g.store.load("u").pending_audit
        with self.assertRaises(ConcurrentStateError): g.drain_audit("u")
        self.assertEqual(g.store.load("u").pending_audit, before)
    def test_contention_cannot_change_identity(self):
        g, seen = self._never()
        with self.assertRaises(ConcurrentStateError): g.drain_audit("u")
        self.assertEqual(len(seen), MAX_RETRIES); self.assertEqual({(e["stream_id"], e["seq"], e["sha256"]) for e in seen}, {(seen[0]["stream_id"], seen[0]["seq"], seen[0]["sha256"])})
    def test_contention_cannot_falsely_report_acknowledgement(self):
        g, _ = self._never()
        try: n = g.drain_audit("u")
        except ConcurrentStateError as e: self.assertIn("0 delivered", str(e)); return
        self.fail(f"reported {n} delivered with nothing acknowledged")


class INV_10_INDEPENDENT_REQUESTS_LINEARIZE(unittest.TestCase):
    """Concurrent independent requests over one user state serialize; totals are exact; no request is lost or doubled."""
    def test_threads(self):
        g = guard(); out = []
        def w(i):
            for k in range(5): out.append(g.evaluate("u",f"S{i}",k+1,TurnMetrics(3,.3),"x"))
        ts = [threading.Thread(target=w, args=(i,)) for i in range(4)]; [t.start() for t in ts]; [t.join() for t in ts]
        r = g.store.load("u"); self.assertEqual(r.harness["trajectory_position"], 20); self.assertEqual(r.guard.delivered_gap_total, 20)
        self.assertEqual(len({d.committed_version for d in out}), 20); self.assertEqual(sorted(d.trajectory_position for d in out), list(range(1, 21)))

if __name__ == "__main__": unittest.main()