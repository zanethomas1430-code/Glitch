import tempfile, unittest
from pathlib import Path
from alignment_guard_v22 import *
from glitch_runtime_harness import CanvasValidationError, JSONStateStore, RuntimeHarness, RetentionPolicy, TurnMetrics

class Allow:
    def authorize_mode_lowering(self, **kw): return kw["authorization"].token == "valid"

def mk(store=None, gstore=None, **kw):
    g = AlignmentGuard(harness=RuntimeHarness(store=store, retention=RetentionPolicy(trajectory_turn_limit=3)),
                       config=GuardConfig(sensitive_tools=("shell","db_write"), **kw), guard_store=gstore, authority_verifier=Allow())
    g.start("u","A",declared_purpose="p",required_level=2); return g

class V21Contract(unittest.TestCase):
    def test_text_never_contains(self):
        d = mk().evaluate("u","A",1,TurnMetrics(1,.3),"kill -9; disable safety; bypass guard"); self.assertTrue(d.allow)
    def test_levels_decide(self):
        g = mk()
        for i, s in enumerate([1,2,3,4],1): d = g.evaluate("u","A",i,TurnMetrics(s,.3),"x")
        self.assertEqual(d.mode, GuardMode.READ_ONLY)
    def test_ratchet_and_verified_lowering(self):
        g = mk(); g.evaluate("u","A",1,TurnMetrics(4,.3,middle_third_density=.5),"x")   # TW02 -> RESTRICTED
        g.store.save("u", GuardState(GuardMode.HUMAN_REVIEW))
        d = g.evaluate("u","A",2,TurnMetrics(4,.3,middle_third_density=.5),"x"); self.assertEqual(d.mode, GuardMode.HUMAN_REVIEW)
        with self.assertRaises(CanvasValidationError): g.lower_mode("u", to=GuardMode.NORMAL, authorization=RecoveryAuthorization("p","bad","inc-1"), reason="r")
        self.assertEqual(g.audit.records[-1]["type"], "mode_lower_denied")
        g.lower_mode("u", to=GuardMode.NORMAL, authorization=RecoveryAuthorization("responder","valid","inc-1"), reason="reviewed")
        self.assertEqual(g.store.load("u").mode, GuardMode.NORMAL)
    def test_lowering_disabled_without_verifier(self):
        g = AlignmentGuard(); g.start("u","A",declared_purpose="p",required_level=2); g.store.save("u", GuardState(GuardMode.READ_ONLY))
        with self.assertRaises(CanvasValidationError): g.lower_mode("u", to=GuardMode.NORMAL, authorization=RecoveryAuthorization("p","valid","i"), reason="r")
    def test_budget_transactional(self):
        g = mk(cumulative_gap_limit=2)
        d1 = g.evaluate("u","A",1,TurnMetrics(3,.3),"x"); self.assertTrue(d1.allow); self.assertEqual(g.store.load("u").delivered_gap_total, 1)
        d2 = g.evaluate("u","A",2,TurnMetrics(3,.3),"x"); self.assertFalse(d2.allow); self.assertEqual(g.store.load("u").delivered_gap_total, 1)
    def test_chain_with_anchor(self):
        heads = []; g = AlignmentGuard(audit=ChainedAudit(anchor=heads.append)); g.start("u","A",declared_purpose="p",required_level=2)
        for i in range(3): g.evaluate("u","A",i+1,TurnMetrics(1,.3),"x")
        recs = list(g.audit.records); self.assertTrue(ChainedAudit.verify(recs, expected_head=heads[-1]))
        self.assertFalse(ChainedAudit.verify(recs[:-1], expected_head=heads[-1]))   # tail truncation caught by anchor
        self.assertFalse(ChainedAudit.verify(recs[:1]+recs[2:]))

class NewInV22(unittest.TestCase):
    def test_no_stale_write_over_raised_mode_with_file_store(self):
        with tempfile.TemporaryDirectory() as td:
            g = mk(JSONStateStore(Path(td)/"h.json"), JSONGuardStore(Path(td)/"g.json"))
            for i, s in enumerate([1,2,3,4],1): g.evaluate("u","A",i,TurnMetrics(s,.3),"x")
            self.assertEqual(g.store.load("u").mode, GuardMode.READ_ONLY)   # TW03 at T4 persisted, not overwritten
    def test_Q1_inflation_attempts_raise_mode_via_ladder(self):
        g = mk()
        for i, s in enumerate([1,2],1): g.evaluate("u","A",i,TurnMetrics(s,.3),"x")
        with self.assertRaises(CanvasValidationError): g.new_epoch("u", required_level=5, authority="client", reason="r", triggering_user_evidence="user asked")
        st = g.store.load("u"); self.assertEqual(st.mode, GuardMode.HUMAN_REVIEW)
        self.assertEqual(st.mode_changes[-1]["by"], "TW06"); self.assertEqual(st.mode_changes[-1]["at"], 2)
        with self.assertRaises(CanvasValidationError): g.start("u","B",required_level=5)
        self.assertEqual(g.h.store.load("u").inflation_attempts, 2)
    def test_Q2_containment_survives_restart(self):
        with tempfile.TemporaryDirectory() as td:
            hs = JSONStateStore(Path(td)/"h.json"); gs = JSONGuardStore(Path(td)/"g.json"); g = mk(hs, gs)
            d = g.evaluate("u","A",1,TurnMetrics(3,.3),"x", requested_actions=[ActionRequest("shell","rm")]); self.assertEqual(d.mode, GuardMode.CONTAINED)
            g2 = AlignmentGuard(harness=RuntimeHarness(store=JSONStateStore(Path(td)/"h.json")), config=GuardConfig(sensitive_tools=("shell",)), guard_store=JSONGuardStore(Path(td)/"g.json"))
            g2.start("u","B"); d2 = g2.evaluate("u","B",1,TurnMetrics(1,.3),"x", requested_actions=[ActionRequest("shell","rm")])
            self.assertEqual(d2.mode, GuardMode.CONTAINED); self.assertFalse(d2.allow); self.assertEqual(d2.actions_allowed, []); self.assertEqual(len(d2.actions_denied), 1)
            self.assertIn("sensitive action", g2.store.load("u").contained_reason)
    def test_Q3_action_verdict_fail_closed(self):
        g = mk(); sh, rd = ActionRequest("shell","rm"), ActionRequest("read_docs","get")
        d = g.evaluate("u","A",1,TurnMetrics(2,.3),"x", requested_actions=[sh, rd]); self.assertEqual(d.actions_allowed, [sh, rd])      # NORMAL, gap 0
        d = g.evaluate("u","A",2,TurnMetrics(3,.3),"x", requested_actions=[rd]); self.assertEqual(d.actions_allowed, [rd])          # NORMAL, gap 1, non-sensitive ok
        g.store.save("u", GuardState(GuardMode.RESTRICTED))
        d = g.evaluate("u","A",3,TurnMetrics(2,.3),"x", requested_actions=[sh, rd]); self.assertEqual(d.actions_allowed, [rd]); self.assertEqual(d.actions_denied, [sh])
        g.store.save("u", GuardState(GuardMode.READ_ONLY))
        d = g.evaluate("u","A",4,TurnMetrics(2,.3),"x", requested_actions=[sh, rd]); self.assertEqual(d.actions_allowed, []); self.assertEqual(d.actions_denied, [sh, rd])
        self.assertEqual(g.audit.records[-1]["actions_denied"], ["shell","read_docs"])
    def test_sensitive_above_purpose_contains_even_in_normal(self):
        g = mk(); d = g.evaluate("u","A",1,TurnMetrics(3,.3),"x", requested_actions=[ActionRequest("db_write","update")])
        self.assertEqual(d.mode, GuardMode.CONTAINED); self.assertEqual(d.actions_allowed, [])

if __name__ == "__main__": unittest.main()
