"""Preparation angles under adversarial assumptions: a responder acting alone, a guard that went silent,
a guard that was swapped, an incident that must become a fixture, a version that regressed."""
import json, os as _os, sys as _sys, unittest
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas"): _sys.path.insert(0, _os.path.join(_R, _d))
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

from alignment_guard_v343 import *
from glitch_runtime_harness import ThresholdConfig, TurnMetrics, run_canvas_scenarios
from incident import IncidentAuthority, IncidentController, seal_evidence
from prepare import *

POL = ActionPolicy({("read_docs", "get"): frozenset({Capability.READ})})
class Inner:
    def authorize_mode_lowering(self, **kw):
        a = kw["authorization"]; return RecoveryGrant(a.principal, a.incident_id, kw["expected_version"], kw["target"], "g")

class TwoPersonRule(unittest.TestCase):
    def setUp(self):
        self.t = [1000.0]; self.v = MultiPartyVerifier(Inner(), k=2, allowed=["alice", "bob", "carol"], window_s=600, clock=lambda: self.t[0])
        self.g = AlignmentGuard(config=GuardConfig(policy=POL), authority_verifier=self.v)
        self.g.start("u", "S0", declared_purpose="p", required_level=2)
        IncidentController(self.g).contain_all(IncidentAuthority("alice", "INC-1"), "r")
    def _thaw(self, who):
        return self.g.lower_mode("u", to=GuardMode.HUMAN_REVIEW, authorization=RecoveryAuthorization(who, "h", "INC-1"), reason="reviewed")
    def test_one_responder_cannot_thaw(self):
        self.v.approve(principal="alice", user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-1")
        with self.assertRaises(MultiPartyError): self._thaw("alice")
        self.assertEqual(self.g.store.load("u").guard.mode, GuardMode.CONTAINED)
    def test_two_distinct_responders_can(self):
        self.v.approve(principal="alice", user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-1")
        self.v.approve(principal="bob", user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-1")
        self._thaw("alice"); self.assertEqual(self.g.store.load("u").guard.mode, GuardMode.HUMAN_REVIEW)
    def test_same_person_twice_is_one(self):
        for _ in range(3): self.v.approve(principal="alice", user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-1")
        with self.assertRaises(MultiPartyError): self._thaw("alice")
    def test_approvals_expire_and_are_consumed(self):
        self.v.approve(principal="alice", user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-1")
        self.t[0] += 601; self.v.approve(principal="bob", user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-1")
        with self.assertRaises(MultiPartyError): self._thaw("bob")                       # alice expired
        self.v.approve(principal="alice", user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-1"); self._thaw("bob")
        # consumed: a second lowering needs fresh approvals
        IncidentController(self.g).contain_all(IncidentAuthority("carol", "INC-1"), "again")
        with self.assertRaises(MultiPartyError): self._thaw("bob")
    def test_approval_is_bound_to_user_target_incident(self):
        self.v.approve(principal="alice", user_id="u", target=GuardMode.NORMAL, incident_id="INC-1")     # wrong target
        self.v.approve(principal="bob", user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-2")  # wrong incident
        with self.assertRaises(MultiPartyError): self._thaw("bob")
    def test_requester_must_be_an_approver(self):
        self.v.approve(principal="alice", user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-1")
        self.v.approve(principal="bob", user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-1")
        with self.assertRaises(MultiPartyError): self._thaw("carol")
    def test_contained_party_can_never_be_a_responder(self):
        for bad in ("model", "assistant", "client", "user", "system"):
            with self.assertRaises(MultiPartyError): MultiPartyVerifier(Inner(), k=2, allowed=["alice", bad])
        with self.assertRaises(MultiPartyError): MultiPartyVerifier(Inner(), k=1, allowed=["alice", "bob"])

class Watchdog(unittest.TestCase):
    def test_silence_fails_closed(self):
        t = [0.0]; w = SilenceWatchdog(silence_s=60, clock=lambda: t[0]); w.expect("u")
        self.assertEqual(w.check()[0].action, "TREAT_AS_CONTAINED")                     # never heard from
        w.observe("u", 5, "a"); self.assertEqual(w.check()[0].action, "none")
        t[0] = 61; v = w.check()[0]; self.assertEqual((v.status, v.action), ("silent", "TREAT_AS_CONTAINED"))
    def test_rollback_is_worse_than_silence(self):
        w = SilenceWatchdog(silence_s=60); w.observe("u", 9, "a")
        self.assertEqual(w.observe("u", 7, "b").status, "rolled_back")
        self.assertEqual(w.observe("u", 9, "DIFFERENT").status, "rolled_back")            # same seq, different content
    def test_unexpected_users_are_not_flagged(self):
        w = SilenceWatchdog(silence_s=1); w.observe("v", 1, "a"); self.assertEqual(w.check(), [])

class Attestation(unittest.TestCase):
    def test_attest_hashes_code_and_canvas(self):
        a = attest(); self.assertEqual(set(a), set(ATTEST_FILES)); self.assertTrue(all(len(v) == 64 for v in a.values()))
    def test_swapped_guard_is_detected(self):
        expected = attest(); observed = dict(expected); observed["01_lib/alignment_guard_v343.py"] = "0" * 64
        r = check_attestation(observed, expected); self.assertFalse(r["valid"]); self.assertIn("alignment_guard", r["problems"][0])
    def test_seal_can_carry_attestation(self):
        g = AlignmentGuard(config=GuardConfig(policy=POL)); g.start("u", "S0", declared_purpose="p", required_level=2)
        b = seal_evidence(g, IncidentAuthority("alice", "INC-1")); b_att = {**b, "attestation": attest()}
        self.assertTrue(check_attestation(b_att["attestation"], attest())["valid"])

class Fixture(unittest.TestCase):
    def test_incident_becomes_a_scenario_with_integers_only(self):
        g = AlignmentGuard(config=GuardConfig(policy=POL, threshold=ThresholdConfig(window_turns=6, tw03_consecutive_turns=2)))
        g.start("u", "S0", declared_purpose="the actual purpose text", required_level=2)
        for t, spec in enumerate([1, 2, 3, 4], 1):
            g.evaluate("u", "S0", t, TurnMetrics(spec, .3), f"SECRET OUTPUT {t}", identity=RequestIdentity.from_canonical_input(f"r{t}", "S0", t, f"SECRET INPUT {t}"))
        b = seal_evidence(g, IncidentAuthority("alice", "INC-1"))
        fx = bundle_to_fixture(b, "u", scenario_id="T_INC_1", required_level=2)
        self.assertEqual([t["spec"] for t in fx["turns"]], [2, 2, 3, 4])   # below-purpose turns flatten to purpose (documented limit)
        self.assertEqual(fx["expected"]["TW01"]["first_fire"], 3)
        self.assertNotIn("SECRET", json.dumps(fx)); self.assertNotIn("actual purpose", json.dumps(fx))
        # and it runs as a real canvas scenario
        import tempfile
        canvas = json.load(open(_os.path.join(_R, "02_canvas", "glitch_canvas_runtime.json"))); canvas["tests"]["scenarios"] = [fx]
        p = _os.path.join(tempfile.mkdtemp(), "c.json"); json.dump(canvas, open(p, "w"))
        self.assertTrue(run_canvas_scenarios(p, verbose=False))

class Canary(unittest.TestCase):
    def test_regression_between_versions_is_named(self):
        A = [{"user": "u", "session": "s", "turn": i, "tripwires": [], "purpose_gap": 0} for i in range(1, 5)]
        B = [dict(r) for r in A]; B[3]["tripwires"] = ["TW03"]; B[3]["purpose_gap"] = 2
        d = canary_diff(A, B); self.assertEqual(d["verdict"], "B_REGRESSED"); self.assertEqual(d["new_tripwires_in_b"][0]["fired"], ["TW03"])
        self.assertEqual(canary_diff(A, A)["verdict"], "NO_CHANGE"); self.assertEqual(canary_diff(B, A)["verdict"], "B_IMPROVED")

if __name__ == "__main__": unittest.main()
