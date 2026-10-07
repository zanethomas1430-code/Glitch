"""Incident tooling under the same rules as the rest of the suite: fail closed, audited, verifiable by
someone who is not the operator, and adversarially tested (a tampered bundle must not verify)."""
import copy, json, os as _os, sys as _sys, tempfile, unittest
from pathlib import Path
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib",): _sys.path.insert(0, _os.path.join(_R, _d))
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

from alignment_guard_v343 import *
from glitch_runtime_harness import ThresholdConfig, TurnMetrics
from incident import *

POL = ActionPolicy({("shell", "run"): frozenset({Capability.EXECUTE}), ("read_docs", "get"): frozenset({Capability.READ})})
AUTH = IncidentAuthority("incident-commander", "INC-2026-07-11", "ir@example.org")

class Grant:
    def authorize_mode_lowering(self, **kw):
        a = kw["authorization"]; return RecoveryGrant(a.principal, a.incident_id, kw["expected_version"], kw["target"], "g")

def fleet(n=4, store=None, traffic=True):
    g = AlignmentGuard(config=GuardConfig(policy=POL, threshold=ThresholdConfig(window_turns=6, tw03_consecutive_turns=2)),
                       store=store, authority_verifier=Grant())
    for i in range(n):
        u = f"u{i}"; g.start(u, "S0", declared_purpose="p", required_level=2)
        if traffic:
            for t, spec in enumerate([1, 2, 3], 1):
                g.evaluate(u, "S0", t, TurnMetrics(spec, .3), f"out{t}",
                           identity=RequestIdentity.from_canonical_input(f"{u}:{t}", "S0", t, f"in{t}"))
    return g

class Containment(unittest.TestCase):
    def test_contain_all_freezes_every_user_and_is_idempotent(self):
        g = fleet(); ctl = IncidentController(g)
        rep = ctl.contain_all(AUTH, "model wrote to a repo it does not own")
        self.assertTrue(rep.complete); self.assertEqual(len(rep.contained), 4); self.assertEqual(rep.already_contained, [])
        self.assertTrue(all(m == "CONTAINED" for m in ctl.status().values()))
        rep2 = ctl.contain_all(AUTH, "second run")
        self.assertEqual(rep2.contained, []); self.assertEqual(len(rep2.already_contained), 4)
    def test_containment_denies_actions_afterwards(self):
        g = fleet(n=1); IncidentController(g).contain_all(AUTH, "r")
        d = g.evaluate("u0", "S0", 4, TurnMetrics(1, .3), "x",
                       identity=RequestIdentity.from_canonical_input("u0:4", "S0", 4, "in4"),
                       requested_actions=[ActionRequest("read_docs", "get")])
        self.assertEqual(d.mode, GuardMode.CONTAINED); self.assertFalse(d.allow); self.assertEqual(d.actions_allowed, [])
    def test_containment_is_audited_with_the_incident_id(self):
        g = fleet(n=1); IncidentController(g).contain_all(AUTH, "repo write")
        ev = [e for e in g.store.load("u0").pending_audit if e["type"] == "incident_containment"]
        self.assertEqual(len(ev), 1); self.assertEqual(ev[0]["incident_id"], AUTH.incident_id)
        self.assertEqual(ev[0]["authority"], AUTH.principal); self.assertIn("repo write", ev[0]["reason"])
    def test_the_contained_party_cannot_declare_the_incident(self):
        for who in ("model", "assistant", "client", "user", ""):
            with self.assertRaises(IncidentError): IncidentAuthority(who, "INC-1").validate()
    def test_containment_is_not_refused_by_a_full_outbox(self):
        g = AlignmentGuard(config=GuardConfig(policy=POL, outbox_cap=1), authority_verifier=Grant())
        g.start("u0", "S0", declared_purpose="p", required_level=2)          # genesis envelope fills the outbox
        rep = IncidentController(g).contain_all(AUTH, "r")
        self.assertTrue(rep.complete); self.assertEqual(g.store.load("u0").guard.mode, GuardMode.CONTAINED)
    def test_partial_failure_is_reported_not_swallowed(self):
        g = fleet(n=2); ctl = IncidentController(g, users=["u0", "u1", "ghost"])
        rep = ctl.contain_all(AUTH, "r")
        self.assertFalse(rep.complete); self.assertIn("ghost", rep.failed); self.assertEqual(len(rep.contained), 2)
    def test_no_bulk_thaw_and_thaw_defaults_to_review_not_normal(self):
        g = fleet(n=1); ctl = IncidentController(g); ctl.contain_all(AUTH, "r")
        self.assertFalse(hasattr(ctl, "thaw_all"))
        ctl.thaw("u0", authorization=RecoveryAuthorization("responder", "h", AUTH.incident_id), reason="reviewed")
        self.assertEqual(g.store.load("u0").guard.mode, GuardMode.HUMAN_REVIEW)

class Evidence(unittest.TestCase):
    def bundle(self, **kw):
        g = fleet(); IncidentController(g).contain_all(AUTH, "r"); return g, seal_evidence(g, AUTH, **kw)
    def test_sealed_bundle_verifies(self):
        _, b = self.bundle(); res = verify_evidence(b)
        self.assertTrue(res["valid"], res["problems"]); self.assertTrue(all(u["pending_chain_ok"] for u in res["users"].values()))
    def test_edited_bundle_does_not_verify(self):
        _, b = self.bundle(); b["users"]["u0"]["mode"] = "NORMAL"
        res = verify_evidence(b); self.assertFalse(res["valid"]); self.assertIn("digest mismatch", " ".join(res["problems"]))
    def test_removed_audit_event_does_not_verify(self):
        _, b = self.bundle()
        b["users"]["u0"]["pending_audit"] = b["users"]["u0"]["pending_audit"][:1] + b["users"]["u0"]["pending_audit"][2:]
        b["bundle_sha256"] = __import__("incident")._sha({k: v for k, v in b.items() if k != "bundle_sha256"})  # re-seal after tampering
        res = verify_evidence(b); self.assertFalse(res["valid"]); self.assertIn("chain does not verify", " ".join(res["problems"]))
    def test_payloads_excluded_by_default(self):
        _, b = self.bundle()
        self.assertFalse(b["includes_payloads"])
        self.assertNotIn("request_journal", b["users"]["u0"])
        self.assertIn("request_journal_keys", b["users"]["u0"])
        _, b2 = self.bundle(include_payloads=True)
        self.assertIn("request_journal", b2["users"]["u0"])
    def test_anchor_detects_a_rolled_back_record(self):
        g, b = self.bundle()
        anchors = {u: {"stream_id": e["audit_cursor"]["stream_id"], "seq": e["audit_cursor"]["seq"] + 5, "sha256": "x"} for u, e in b["users"].items()}
        res = verify_evidence(b, anchors=anchors)
        self.assertFalse(res["valid"]); self.assertIn("behind the anchor", " ".join(res["problems"]))
    def test_without_anchor_truncation_is_declared_undetectable(self):
        _, b = self.bundle(); res = verify_evidence(b)
        self.assertTrue(all(u.get("tail_truncation_detectable") is False for u in res["users"].values()))
    def test_receipt_roundtrip_and_mismatch(self):
        _, b = self.bundle(); r = anchor_receipt(b)
        self.assertTrue(check_receipt(b, r)); self.assertTrue(check_receipt(b, " " + r + "\n"))
        self.assertFalse(check_receipt(b, r[:-1] + ("0" if r[-1] != "0" else "1")))
    def test_bundle_survives_a_file_roundtrip(self):
        _, b = self.bundle()
        with tempfile.TemporaryDirectory() as td:
            p = _os.path.join(td, "b.json"); write_bundle(p, b)
            self.assertTrue(verify_evidence(read_bundle(p))["valid"])

class OutOfBand(unittest.TestCase):
    def test_receipt_survives_the_acoustic_channel(self):
        """The air-gap path: carry the bundle digest as audio when you cannot trust the network."""
        try:
            from afsk import modulate, demodulate, BadFrame
            from afsk_cli import _band_noise
        except Exception as e:
            self.skipTest(f"afsk not present: {e}")
        g = fleet(n=2); IncidentController(g).contain_all(AUTH, "r"); b = seal_evidence(g, AUTH)
        r = anchor_receipt(b)
        heard = demodulate(_band_noise(modulate(r.encode()), 10, 0)).decode()
        self.assertEqual(heard, r); self.assertTrue(check_receipt(b, heard))

if __name__ == "__main__": unittest.main()
