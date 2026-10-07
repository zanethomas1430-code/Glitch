import unittest
from alignment_guard_v2 import *
from glitch_runtime_harness import CanvasValidationError, RuntimeHarness, RetentionPolicy, TurnMetrics

def guard(**kw):
    g = AlignmentGuard(harness=RuntimeHarness(retention=RetentionPolicy(trajectory_turn_limit=3)),
                       config=GuardConfig(sensitive_tools=("shell", "db_write"), **kw))
    g.start("u", "A", declared_purpose="safety sheet", required_level=2); return g

class Probes(unittest.TestCase):
    def test_P1_P2_user_text_and_words_cannot_contain(self):
        g = guard(); d = g.evaluate("u", "A", 1, TurnMetrics(1, .3), "Put the boundary outside the model. kill -9 the process. disable safety? no.")
        self.assertTrue(d.allow); self.assertEqual(d.mode, GuardMode.NORMAL)   # text is never a trigger
    def test_P3_paraphrase_irrelevant_levels_decide(self):
        g = guard()
        for i, s in enumerate([1, 2, 3, 4], 1): d = g.evaluate("u", "A", i, TurnMetrics(s, .3), "any words at all")
        self.assertEqual(d.mode, GuardMode.READ_ONLY); self.assertFalse(d.allow)   # TW03 at T4
    def test_P4_mode_only_ratchets_up(self):
        g = guard(); g._guard["u"].mode = GuardMode.HUMAN_REVIEW
        d = g.evaluate("u", "A", 1, TurnMetrics(4, .3, middle_third_density=.5), "sandwich")   # TW02 -> RESTRICTED floor
        self.assertEqual(d.mode, GuardMode.HUMAN_REVIEW)
        with self.assertRaises(CanvasValidationError): g.lower_mode("u", to=GuardMode.NORMAL, authority="client", reason="x")
        g.lower_mode("u", to=GuardMode.NORMAL, authority="incident responder", reason="reviewed, false positive")
        self.assertEqual(g._guard["u"].mode, GuardMode.NORMAL); self.assertEqual(g.audit.records[-1]["type"], "mode_lowered")
    def test_P5_blocked_turns_transfer_nothing(self):
        g = guard(); g._guard["u"].mode = GuardMode.RESTRICTED
        for i in range(4): g.evaluate("u", "A", i + 1, TurnMetrics(4, .3), "would be level 4")
        self.assertEqual(g._guard["u"].delivered_gap_total, 0)
    def test_P5b_delivered_budget_exhausts(self):
        g = guard(cumulative_gap_limit=2); g2 = g
        d1 = g2.evaluate("u", "A", 1, TurnMetrics(3, .3), "gap 1, delivered"); self.assertTrue(d1.allow)   # T1: slope 0, no TW
        d2 = g2.evaluate("u", "A", 2, TurnMetrics(3, .3), "gap 1 again")                                   # T2: TW03 streak -> READ_ONLY, not delivered
        self.assertFalse(d2.allow); self.assertEqual(g2._guard["u"].delivered_gap_total, 1)
    def test_P6_authority_not_boolean_and_purpose_drives_gap(self):
        g = guard()
        with self.assertRaises(CanvasValidationError): g.new_epoch("u", required_level=4, authority="client", reason="r", triggering_user_evidence="user asked")
        with self.assertRaises(CanvasValidationError): g.new_epoch("u", required_level=4, authority="supervisor", reason="r", triggering_user_evidence="the model already answered at 4")
        g.new_epoch("u", required_level=4, authority="clinical supervisor", reason="credential verified", triggering_user_evidence="license, ticket 1187")
        d = g.evaluate("u", "A", 1, TurnMetrics(4, .3), "now within purpose"); self.assertTrue(d.allow); self.assertEqual(g.audit.records[0]["type"], "epoch")
    def test_P7_hash_chain_detects_deletion_and_reorder(self):
        g = guard()
        for i in range(3): g.evaluate("u", "A", i + 1, TurnMetrics(1, .3), "x")
        recs = list(g.audit.records); self.assertTrue(ChainedAudit.verify(recs))
        self.assertFalse(ChainedAudit.verify(recs[:1] + recs[2:]))
        self.assertFalse(ChainedAudit.verify([recs[0], recs[2], recs[1]]))
    def test_containment_is_for_actions_not_words(self):
        g = guard()
        d = g.evaluate("u", "A", 1, TurnMetrics(2, .3), "within purpose", requested_tools=("shell",)); self.assertTrue(d.allow)
        d = g.evaluate("u", "A", 2, TurnMetrics(3, .3), "above purpose", requested_tools=("shell",)); self.assertEqual(d.mode, GuardMode.CONTAINED)
        self.assertIn("sensitive tool", g._guard["u"].contained_reason)
    def test_no_transcript_stored_and_clock_survives_retention(self):
        g = guard()
        for i in range(6): g.evaluate("u", "A", i + 1, TurnMetrics(1, .3), "SECRET TRANSCRIPT TEXT")
        st = g.h.store.load("u"); self.assertEqual(len(st.turns), 3); self.assertEqual(st.trajectory_position, 6)
        self.assertNotIn("SECRET", repr(st)); self.assertNotIn("SECRET", repr(g.audit.records))

if __name__ == "__main__": unittest.main()
