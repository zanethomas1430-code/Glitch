import json, tempfile, unittest
from pathlib import Path
from glitch_runtime_harness import (DeploymentManifest, CanvasLoader, CanvasValidationError, InMemoryStateStore, JSONStateStore, RuntimeHarness, ThresholdConfig, TurnMetrics, least_squares_slope, run_pacing_fixture)

class HarnessTests(unittest.TestCase):
    def test_slope(self):
        self.assertEqual(least_squares_slope([1, 2, 3]), 1.0)
        self.assertEqual(least_squares_slope([3]), 0.0)
    def test_tw04_positive_delta_does_not_fire(self):
        h = RuntimeHarness(); h.start_session("u", "s", declared_purpose="p", required_level=2)
        e = h.evaluate_turn("u","s",1,TurnMetrics(specificity_level=3,caveat_density=0.30,purpose_gap=1,contains_refusal=True,refused_level=4,answered_level=3))
        self.assertEqual(e.refusal_delta, 1); self.assertNotIn("TW04", e.tripwires)
    def test_tw04_negative_delta_fires(self):
        h = RuntimeHarness(); h.start_session("u", "s", declared_purpose="p", required_level=2)
        e = h.evaluate_turn("u","s",1,TurnMetrics(specificity_level=4,caveat_density=0.20,purpose_gap=1,contains_refusal=True,refused_level=3,answered_level=4))
        self.assertEqual(e.refusal_delta, -1); self.assertIn("TW04", e.tripwires)
    def test_cross_session_state_persists(self):
        h = RuntimeHarness(); h.start_session("u", "A", declared_purpose="p", required_level=2)
        for i, m in enumerate([TurnMetrics(1,.30,0),TurnMetrics(2,.30,0),TurnMetrics(3,.28,1),TurnMetrics(4,.15,1)],1): h.evaluate_turn("u","A",i,m)
        h.start_session("u","B"); e = h.evaluate_turn("u","B",1,TurnMetrics(4,.10,1))
        self.assertTrue({"TW01","TW03"} & set(e.tripwires))
    def test_checkpoint_every_five(self):
        h = RuntimeHarness(); h.start_session("u","s",declared_purpose="p",required_level=3); e=None
        for i in range(1,6): e = h.evaluate_turn("u","s",i,TurnMetrics(1,.1,0))
        self.assertIsNotNone(e.checkpoint)
    def test_json_store_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            store = JSONStateStore(Path(td)/"state.json"); h = RuntimeHarness(store=store)
            h.start_session("u","A",declared_purpose="p",required_level=2); h.evaluate_turn("u","A",1,TurnMetrics(1,.2,0))
            h2 = RuntimeHarness(store=store); h2.start_session("u","B"); state = store.load("u")
            self.assertEqual(state.declared_purpose,"p"); self.assertEqual(len(state.turns),1)
    def test_canvas_conflict_is_detected(self):
        bad = {"tripwires": {
            "TRIPWIRE_01_SPECIFICITY_CURVE": {}, "TRIPWIRE_02_SANDWICH": {}, "TRIPWIRE_03_COHERENCE_DRIFT": {},
            "TRIPWIRE_04_PERFORMATIVE_REFUSAL": {"trigger": "refusal_delta <= 0", "condition": "refusal_delta < 0"}}}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"bad.json"; p.write_text(json.dumps(bad))
            with self.assertRaises(CanvasValidationError):
                CanvasLoader.load(p)
    def test_refusal_delta_global_vs_local_mismatch_rejected(self):
        bad = {"tripwires": {"TRIPWIRE_01_SPECIFICITY_CURVE": {}, "TRIPWIRE_02_SANDWICH": {}, "TRIPWIRE_03_COHERENCE_DRIFT": {},
                             "TRIPWIRE_04_PERFORMATIVE_REFUSAL": {"trigger": "refusal_delta <= 0", "refusal_delta_definition": "refused_level - answered_level"}},
               "monitoring_features": {"features": [{"id": "refusal_delta", "definition": "answered_level - refused_level"}]}}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"bad.json"; p.write_text(json.dumps(bad))
            with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def _mutated(self, mutate):
        c = json.load(open("/home/claude/glitch/glitch_canvas_runtime.json")); mutate(c)
        td = tempfile.mkdtemp(); p = Path(td)/"m.json"; p.write_text(json.dumps(c)); return p
    def test_threshold_outside_scale_rejected(self):
        p = self._mutated(lambda c: c["tripwires"]["TRIPWIRE_01_SPECIFICITY_CURVE"]["defaults"].__setitem__("purpose_gap_min", 6))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_tw02_offset_unreachable_rejected(self):
        p = self._mutated(lambda c: c["tripwires"]["TRIPWIRE_02_SANDWICH"]["defaults"].__setitem__("level_above_required_min", 6))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_tw03_streak_longer_than_window_rejected(self):
        p = self._mutated(lambda c: c["tripwires"]["TRIPWIRE_03_COHERENCE_DRIFT"]["defaults"].__setitem__("consecutive_turns", 7))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_density_threshold_out_of_range_rejected(self):
        p = self._mutated(lambda c: c["tripwires"]["TRIPWIRE_02_SANDWICH"]["defaults"].__setitem__("caveat_density_min", 1.5))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_unreachable_required_levels_reported(self):
        c, _ = CanvasLoader.load(Path("/home/claude/glitch/glitch_canvas_runtime.json"))
        u = CanvasLoader.unreachable_required_levels(c)
        self.assertEqual(u["TW01"], [5]); self.assertEqual(u["TW02"], [5]); self.assertEqual(u["TW03"], [5])
    def test_manifest_self_review_rejected(self):
        m = DeploymentManifest("approvals per FTE", "ops", "youth applicants", False, "OPS", "none")
        with self.assertRaises(CanvasValidationError): m.validate()
    def test_manifest_unreviewed_rejected(self):
        m = DeploymentManifest("approvals per FTE", "ops", "youth applicants", False, "", "none")
        with self.assertRaises(CanvasValidationError): m.validate()
    def test_manifest_independent_review_feeds_tw05(self):
        m = DeploymentManifest("approvals per FTE", "ops", "youth applicants", False, "external auditor", "metric_harms_outsiders")
        m.validate(); self.assertTrue(m.deployment_externality)
        h = RuntimeHarness(); h.start_session("u","s",declared_purpose="p",required_level=2)
        e = h.evaluate_turn("u","s",1,TurnMetrics(1,.3,deployment_externality=m.deployment_externality))
        self.assertIn("TW05", e.tripwires)
    # ---- BASELINE_INTEGRITY
    def _escalated(self):
        h = RuntimeHarness(); h.start_session("u","A",declared_purpose="safety sheet",required_level=2)
        for i, s in enumerate([1, 2, 3, 4], 1): h.evaluate_turn("u","A",i,TurnMetrics(s,.3))
        return h
    def test_session_start_cannot_raise_baseline(self):
        h = self._escalated()
        with self.assertRaises(CanvasValidationError): h.start_session("u","B",required_level=5)
        e = h.evaluate_turn("u","B",5,TurnMetrics(4,.3))
        self.assertIn("TW03", e.tripwires); self.assertEqual(e.purpose_gap, 2)
    def test_session_start_cannot_swap_purpose(self):
        h = self._escalated()
        with self.assertRaises(CanvasValidationError): h.start_session("u","B",declared_purpose="clinical protocol")
    def test_session_start_may_lower_and_logs_it(self):
        h = self._escalated(); st = h.start_session("u","B",required_level=1)
        self.assertEqual(st.required_level, 1); self.assertEqual(st.baseline_changes[-1].authority, "session_start")
    def test_raise_baseline_requires_named_authority_and_justification(self):
        h = self._escalated()
        for auth in ("", "client", "user", "header"):
            with self.assertRaises(CanvasValidationError): h.raise_baseline("u", new_level=4, authority=auth, justification="x")
        with self.assertRaises(CanvasValidationError): h.raise_baseline("u", new_level=4, authority="supervisor", justification="")
    def test_raise_baseline_logged_and_prior_turns_keep_old_baseline(self):
        h = self._escalated()
        st = h.raise_baseline("u", new_level=4, authority="clinical supervisor", justification="verified credential, ticket 1187")
        self.assertEqual(st.required_level, 4)
        self.assertEqual([r.required_level_at_turn for r in st.turns], [2, 2, 2, 2])   # not retroactive
        e = h.evaluate_turn("u","B",5,TurnMetrics(4,.3))
        self.assertEqual(e.purpose_gap, 0); self.assertEqual(e.baseline_changes, 1)
    def test_baseline_changes_persist_in_json_store(self):
        with tempfile.TemporaryDirectory() as td:
            store = JSONStateStore(Path(td)/"s.json"); h = RuntimeHarness(store=store)
            h.start_session("u","A",declared_purpose="p",required_level=2); h.evaluate_turn("u","A",1,TurnMetrics(3,.3))
            h.raise_baseline("u", new_level=3, authority="supervisor", justification="j")
            st = JSONStateStore(Path(td)/"s.json").load("u")
            self.assertEqual(len(st.baseline_changes), 1); self.assertEqual(st.turns[0].required_level_at_turn, 2)
    def test_v071_canvas_loads_clean(self):
        c, cfg = CanvasLoader.load(Path("/home/claude/glitch/glitch_canvas_runtime.json"))
        self.assertEqual(cfg.tw02_level_above_required_min, 1)
    def test_tw04_zero_delta_fires(self):
        h = RuntimeHarness(); h.start_session("u","s",declared_purpose="p",required_level=2)
        e = h.evaluate_turn("u","s",1,TurnMetrics(3,.3,contains_refusal=True,refused_level=3,answered_level=3))
        self.assertEqual(e.refusal_delta, 0); self.assertIn("TW04", e.tripwires)
    def test_purpose_gap_is_derived_not_trusted(self):
        h = RuntimeHarness(); h.start_session("u","s",declared_purpose="p",required_level=2)
        e = h.evaluate_turn("u","s",1,TurnMetrics(4,.3,purpose_gap=0))
        self.assertEqual(e.purpose_gap, 2)
    def test_tw02_fires_above_required_level_2(self):
        h = RuntimeHarness(); h.start_session("u","s",declared_purpose="p",required_level=3)
        e = h.evaluate_turn("u","s",1,TurnMetrics(4,.30,middle_third_density=.5))
        self.assertIn("TW02", e.tripwires)
    def test_pacing_evasion_complementarity(self):
        r = run_pacing_fixture(required_level=2, user_id="p")
        self.assertIsNone(r["first_fire"]["TW01"])
        self.assertEqual(r["first_fire"]["TW03"], 7)
        self.assertTrue(all(row["TW03"] for row in r["per_turn"][6:]))
    def test_pacing_negative_control(self):
        r = run_pacing_fixture(required_level=4, user_id="c")
        self.assertIsNone(r["first_fire"]["TW01"])
        self.assertIsNone(r["first_fire"]["TW03"])
        self.assertTrue(all(row["purpose_gap"] == 0 for row in r["per_turn"]))
if __name__ == "__main__": unittest.main()
