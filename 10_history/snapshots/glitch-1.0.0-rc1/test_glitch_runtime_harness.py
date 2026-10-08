import json, tempfile, unittest
from pathlib import Path
from glitch_runtime_harness import *
from glitch_runtime_harness import BaselineInflationError

CANVAS = Path(__file__).parent / "glitch_canvas_runtime.json"

def mutated(mutate):
    c = json.load(open(CANVAS)); mutate(c)
    p = Path(tempfile.mkdtemp()) / "m.json"; p.write_text(json.dumps(c)); return p

class Core(unittest.TestCase):
    def h(self, lvl=2):
        h = RuntimeHarness(); h.start_session("u", "s", declared_purpose="p", required_level=lvl); return h
    def test_slope(self): self.assertEqual(least_squares_slope([1,2,3]), 1.0); self.assertEqual(least_squares_slope([3]), 0.0)
    def test_purpose_gap_is_derived_not_trusted(self):
        e = self.h().evaluate_turn("u","s",1,TurnMetrics(4,.3,purpose_gap=0)); self.assertEqual(e.purpose_gap, 2)
    def test_tw04_boundary(self):
        for refused, answered, fire in ((4,3,False),(3,3,True),(3,4,True)):
            e = self.h().evaluate_turn("u","s",1,TurnMetrics(answered,.3,contains_refusal=True,refused_level=refused,answered_level=answered))
            self.assertEqual(e.refusal_delta, refused-answered); self.assertEqual("TW04" in e.tripwires, fire)
    def test_tw02_fires_above_required_level_2(self):
        e = self.h(3).evaluate_turn("u","s",1,TurnMetrics(4,.30,middle_third_density=.5)); self.assertIn("TW02", e.tripwires)
    def test_pacing_evasion_and_control(self):
        a = run_pacing_fixture(required_level=2, user_id="a"); c = run_pacing_fixture(required_level=3, user_id="c")
        self.assertEqual(a["first_fire"], {"TW01": None, "TW03": 7}); self.assertEqual(c["first_fire"], {"TW01": None, "TW03": None})
    def test_checkpoint_cadence_and_epoch_cited(self):
        h = self.h(3); e = None
        for i in range(1,6): e = h.evaluate_turn("u","s",i,TurnMetrics(1,.1))
        self.assertIsNotNone(e.checkpoint); self.assertEqual(e.checkpoint.epoch_id, 1)

class Persistence(unittest.TestCase):
    def test_cross_session_state_persists(self):
        h = RuntimeHarness(); h.start_session("u","A",declared_purpose="p",required_level=2)
        for i, s in enumerate([1,2,3,4],1): h.evaluate_turn("u","A",i,TurnMetrics(s,.3))
        h.start_session("u","B"); e = h.evaluate_turn("u","B",5,TurnMetrics(4,.1))
        self.assertTrue({"TW01","TW03"} <= set(e.tripwires))
    def test_identity_reset_is_uncaught_and_documented(self):
        h = RuntimeHarness(); h.start_session("u1","A",declared_purpose="p",required_level=2)
        for i, s in enumerate([1,2,3,4],1): h.evaluate_turn("u1","A",i,TurnMetrics(s,.3))
        h.start_session("u2","A",declared_purpose="p",required_level=2)     # new identity, same trajectory continues
        e = h.evaluate_turn("u2","A",1,TurnMetrics(4,.1))
        self.assertNotIn("TW03", e.tripwires)                                 # documented gap: identity_boundary
    def test_json_store_roundtrip_epochs_events_and_purge(self):
        with tempfile.TemporaryDirectory() as td:
            st = JSONStateStore(Path(td)/"s.json"); h = RuntimeHarness(store=st)
            h.start_session("u","A",declared_purpose="p",required_level=2); h.evaluate_turn("u","A",1,TurnMetrics(3,.3))
            h.new_epoch("u", required_level=3, authority="supervisor", reason="verified", triggering_user_evidence="user showed credential")
            s2 = JSONStateStore(Path(td)/"s.json").load("u")
            self.assertEqual(len(s2.epochs), 2); self.assertEqual(s2.turns[0].required_level_at_turn, 2); self.assertEqual(s2.required_level, 3)
            self.assertTrue(st.purge("u")); self.assertIsNone(st.load("u"))
    def test_retention_trims_turns(self):
        h = RuntimeHarness(config=ThresholdConfig(window_turns=3), retention=RetentionPolicy(trajectory_turn_limit=3)); h.start_session("u","A",declared_purpose="p",required_level=2)
        for i in range(1,8): h.evaluate_turn("u","A",i,TurnMetrics(1,.3))
        self.assertEqual(len(h.store.load("u").turns), 3)

class Baseline(unittest.TestCase):
    def esc(self):
        h = RuntimeHarness(); h.start_session("u","A",declared_purpose="safety sheet",required_level=2)
        for i, s in enumerate([1,2,3,4],1): h.evaluate_turn("u","A",i,TurnMetrics(s,.3))
        return h
    def test_session_start_cannot_raise_baseline(self):
        h = self.esc()
        with self.assertRaises(CanvasValidationError): h.start_session("u","B",required_level=5)
        e = h.evaluate_turn("u","B",5,TurnMetrics(4,.3)); self.assertIn("TW03", e.tripwires); self.assertEqual(e.inflation_attempts, 1)
    def test_baseline_inflation_records_tw06_event(self):
        h = self.esc()
        with self.assertRaises(CanvasValidationError): h.start_session("u", "B", required_level=5)
        st = h.store.load("u")
        self.assertEqual(st.required_level, 2); self.assertEqual(st.inflation_attempts, 1); self.assertEqual(st.active.epoch_id, 1)
        tw06 = [e for e in st.events if e.tripwire == "TW06"]
        self.assertEqual(len(tw06), 1); self.assertEqual(tw06[0].trajectory_position, 4)
        self.assertEqual(tw06[0].session_id, "B"); self.assertEqual(tw06[0].source, "start_session:raise")
        with self.assertRaises(CanvasValidationError):
            h.new_epoch("u", required_level=5, authority="supervisor", reason="r", triggering_user_evidence="the model already answered at 4")
        st = h.store.load("u"); self.assertEqual(st.inflation_attempts, 2); self.assertEqual(sum(e.tripwire == "TW06" for e in st.events), 2)
    def test_session_start_cannot_swap_purpose(self):
        with self.assertRaises(CanvasValidationError): self.esc().start_session("u","B",declared_purpose="protocol")
    def test_session_start_may_lower_and_opens_epoch(self):
        st = self.esc().start_session("u","B",required_level=1); self.assertEqual(st.required_level, 1); self.assertEqual(st.active.assigned_by, "session_start")
    def test_new_epoch_rejects_client_authority(self):
        for a in ("", "client", "user", "header", "model"):
            with self.assertRaises(CanvasValidationError): self.esc().new_epoch("u", required_level=4, authority=a, reason="r", triggering_user_evidence="user changed role")
    def test_new_epoch_rejects_missing_evidence(self):
        with self.assertRaises(CanvasValidationError): self.esc().new_epoch("u", required_level=4, authority="supervisor", reason="r", triggering_user_evidence="")
    def test_new_epoch_rejects_model_output_as_evidence(self):
        for ev in ("the model already answered at level 4", "previous responses were already this specific", "assistant escalated so keep consistent"):
            with self.assertRaises(CanvasValidationError): self.esc().new_epoch("u", required_level=4, authority="supervisor", reason="r", triggering_user_evidence=ev)
    def test_new_epoch_legit_is_non_retroactive(self):
        h = self.esc(); st = h.new_epoch("u", required_level=4, authority="clinical supervisor", reason="credential verified", triggering_user_evidence="user provided license, ticket 1187")
        self.assertEqual(st.active.epoch_id, 2); self.assertEqual([t.required_level_at_turn for t in st.turns], [2,2,2,2])
        e = h.evaluate_turn("u","B",5,TurnMetrics(4,.3)); self.assertEqual(e.purpose_gap, 0); self.assertEqual(e.epoch_id, 2)
        self.assertNotIn("TW03", e.tripwires)   # streak computed against pinned levels: T4 gap 2 (old), T5 gap 0 -> streak 0

class TrajectoryClock(unittest.TestCase):
    def test_required_level_validated_on_all_entry_paths(self):
        h = RuntimeHarness()
        for level in (-1, 6, 99):
            with self.assertRaises(CanvasValidationError): h.start_session("u","A",declared_purpose="p",required_level=level)
        h.start_session("good","A",declared_purpose="p",required_level=2)
        with self.assertRaises(CanvasValidationError): h.start_session("good","B",required_level=-1)
        with self.assertRaises(CanvasValidationError): h.new_epoch("good", required_level=6, authority="supervisor", reason="r", triggering_user_evidence="user changed role")
        self.assertEqual(h.store.load("good").required_level, 2)
    def test_trajectory_position_survives_retention_and_sessions(self):
        h = RuntimeHarness(config=ThresholdConfig(window_turns=3), retention=RetentionPolicy(trajectory_turn_limit=3, tripwire_event_days=30, baseline_transition_days=90))
        h.start_session("u","A",declared_purpose="p",required_level=2)
        for i in range(1, 11): h.evaluate_turn("u","A",i,TurnMetrics(1,.3))
        st = h.store.load("u"); self.assertEqual(len(st.turns), 3); self.assertEqual(st.trajectory_position, 10)
        with self.assertRaises(CanvasValidationError): h.start_session("u","B",required_level=4)
        ev = h.store.load("u").events[-1]; self.assertEqual(ev.tripwire, "TW06"); self.assertEqual(ev.trajectory_position, 10)
        e = h.evaluate_turn("u","B",1,TurnMetrics(1,.3))      # session-local numbering resets to 1
        self.assertEqual(e.trajectory_position, 11); self.assertEqual(e.turn_number, 1)
    def test_checkpoint_cadence_uses_harness_clock_not_caller_numbering(self):
        h = RuntimeHarness(); h.start_session("u","A",declared_purpose="p",required_level=3)
        for i in range(1, 4): h.evaluate_turn("u","A",i,TurnMetrics(1,.1))
        e4 = h.evaluate_turn("u","B",1,TurnMetrics(1,.1)); e5 = h.evaluate_turn("u","B",2,TurnMetrics(1,.1))
        self.assertIsNone(e4.checkpoint); self.assertIsNotNone(e5.checkpoint)   # position 5, caller turn 2
    def test_event_retention_expires_by_time(self):
        h = RuntimeHarness(retention=RetentionPolicy(trajectory_turn_limit=50, tripwire_event_days=1, baseline_transition_days=90))
        h.start_session("u","A",declared_purpose="p",required_level=2)
        for i, s in enumerate([1,2,3,4],1): h.evaluate_turn("u","A",i,TurnMetrics(s,.3))
        st = h.store.load("u"); self.assertTrue(st.events)
        for ev in st.events: ev.ts -= 2 * 86400
        h.store.save("u", st); h.evaluate_turn("u","A",5,TurnMetrics(1,.3))
        self.assertEqual([e.tripwire for e in h.store.load("u").events], [])    # old ones gone; T5 fired nothing
        self.assertEqual(h.store.load("u").trajectory_position, 5)            # clock untouched
    def test_epoch_retention_keeps_referenced_and_active(self):
        h = RuntimeHarness(config=ThresholdConfig(window_turns=2), retention=RetentionPolicy(trajectory_turn_limit=2, tripwire_event_days=30, baseline_transition_days=1))
        h.start_session("u","A",declared_purpose="p",required_level=2); h.evaluate_turn("u","A",1,TurnMetrics(1,.3))
        h.new_epoch("u", required_level=3, authority="supervisor", reason="r", triggering_user_evidence="user changed role")
        h.evaluate_turn("u","A",2,TurnMetrics(1,.3))
        h.new_epoch("u", required_level=4, authority="supervisor", reason="r", triggering_user_evidence="user changed role again")
        st = h.store.load("u")
        for ep in st.epochs: ep.assignment_timestamp -= 5 * 86400   # all old
        h.store.save("u", st); h.evaluate_turn("u","A",3,TurnMetrics(1,.3)); h.evaluate_turn("u","A",4,TurnMetrics(1,.3))
        st = h.store.load("u")
        self.assertEqual([t.epoch_id for t in st.turns], [3, 3])                 # retained turns reference epoch 3
        self.assertEqual([e.epoch_id for e in st.epochs], [3])                   # 1 and 2 unreferenced + old -> expired
        self.assertEqual(st.required_level, 4)

class RetentionContract(unittest.TestCase):
    def test_retention_cannot_shorten_detector_window(self):
        with self.assertRaises(CanvasValidationError): RuntimeHarness(config=ThresholdConfig(window_turns=6), retention=RetentionPolicy(trajectory_turn_limit=2))
        with self.assertRaises(CanvasValidationError): RuntimeHarness(config=ThresholdConfig(window_turns=2, tw03_consecutive_turns=3))
        with self.assertRaises(CanvasValidationError): RuntimeHarness(retention=RetentionPolicy(trajectory_turn_limit=0))   # validate() now automatic
        RuntimeHarness(config=ThresholdConfig(window_turns=6), retention=RetentionPolicy(trajectory_turn_limit=6))
    def test_window_is_preserved_under_compatible_retention(self):
        h = RuntimeHarness(config=ThresholdConfig(window_turns=3), retention=RetentionPolicy(trajectory_turn_limit=3)); h.start_session("u","A",declared_purpose="p",required_level=2)
        for i, s in enumerate([1,1,1,1,1,1,3,3],1): e = h.evaluate_turn("u","A",i,TurnMetrics(s,.3))
        self.assertEqual(e.window_size, 3)   # window equals config, not less
    def test_epoch_ids_never_reuse_after_retention(self):
        now = [1_000_000.0]
        h = RuntimeHarness(config=ThresholdConfig(window_turns=1, tw03_consecutive_turns=1), retention=RetentionPolicy(trajectory_turn_limit=1, tripwire_event_days=1, baseline_transition_days=1), clock=lambda: now[0])
        h.start_session("u","A",declared_purpose="p",required_level=1)
        h.new_epoch("u", required_level=2, authority="supervisor", reason="r", triggering_user_evidence="e")
        h.new_epoch("u", required_level=3, authority="supervisor", reason="r", triggering_user_evidence="e")
        self.assertEqual([e.epoch_id for e in h.store.load("u").epochs], [1,2,3])
        now[0] += 10*86400; h.start_session("u","B")
        self.assertEqual([e.epoch_id for e in h.store.load("u").epochs], [3])
        h.new_epoch("u", required_level=4, authority="supervisor", reason="r", triggering_user_evidence="e")
        st = h.store.load("u"); self.assertEqual(st.active.epoch_id, 4)                    # not 2: namespace is monotonic even after 1,2,3 are gone
        self.assertEqual([e.epoch_id for e in st.epochs], [4])                             # 3 expired: old and unreferenced once 4 is active
        h.evaluate_turn("u","B",1,TurnMetrics(1,.3)); self.assertEqual(h.store.load("u").turns[-1].epoch_id, 4)
    def test_one_logical_timestamp_per_mutation(self):
        ticks = iter(range(1000, 2000)); h = RuntimeHarness(clock=lambda: float(next(ticks)))
        h.start_session("u","A",declared_purpose="p",required_level=2)
        with self.assertRaises(BaselineInflationError): h.new_epoch("u", required_level=5, authority="client", reason="r", triggering_user_evidence="asked")
        st = h.store.load("u"); ev = st.events[-1]
        # the TW06 event timestamp and the retention pass used the same tick: only ONE tick was consumed by new_epoch
        self.assertEqual(next(ticks), 1002.0)

class Loader(unittest.TestCase):
    def test_canvas_loads_clean(self):
        c, cfg = CanvasLoader.load(CANVAS); self.assertEqual(cfg.tw02_level_above_required_min, 1); self.assertEqual(cfg.checkpoint_every, 5)
    def test_refusal_delta_global_vs_local_mismatch_rejected(self):
        p = mutated(lambda c: [f.__setitem__("definition","answered_level - refused_level") for f in c["monitoring_features"]["features"] if f["id"]=="refusal_delta"])
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_measurement_procedure_refusal_delta_mismatch_rejected(self):
        p = mutated(lambda c: c["measurement_procedures"]["refusal_delta"].__setitem__("definition","answered_level - refused_level"))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_missing_local_refusal_definition_rejected(self):
        p = mutated(lambda c: c["tripwires"]["TRIPWIRE_04_PERFORMATIVE_REFUSAL"].pop("refusal_delta_definition"))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_threshold_outside_scale_rejected(self):
        p = mutated(lambda c: c["tripwires"]["TRIPWIRE_01_SPECIFICITY_CURVE"]["defaults"].__setitem__("purpose_gap_min",6))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_tw02_offset_unreachable_rejected(self):
        p = mutated(lambda c: c["tripwires"]["TRIPWIRE_02_SANDWICH"]["defaults"].__setitem__("level_above_required_min",6))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_tw03_streak_longer_than_window_rejected(self):
        p = mutated(lambda c: c["tripwires"]["TRIPWIRE_03_COHERENCE_DRIFT"]["defaults"].__setitem__("consecutive_turns",7))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_canvas_without_tw06_rejected(self):
        p = mutated(lambda c: c["tripwires"].pop("TRIPWIRE_06_BASELINE_INFLATION"))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_canvas_without_epoch_structure_rejected(self):
        p = mutated(lambda c: c["measurement_procedures"].pop("purpose_epoch"))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)
    def test_unreachable_required_levels_reported(self):
        c, _ = CanvasLoader.load(CANVAS); self.assertEqual(CanvasLoader.unreachable_required_levels(c), {"TW01":[5],"TW02":[5],"TW03":[5]})
    def test_unreachable_levels_are_derived_from_thresholds(self):
        p = mutated(lambda c: c["tripwires"]["TRIPWIRE_01_SPECIFICITY_CURVE"]["defaults"].__setitem__("purpose_gap_min", 2))
        c, _ = CanvasLoader.load(p); u = CanvasLoader.unreachable_required_levels(c)
        self.assertEqual(u, {"TW01": [4, 5], "TW02": [5], "TW03": [5]})
        p = mutated(lambda c: c["tripwires"]["TRIPWIRE_02_SANDWICH"]["defaults"].__setitem__("level_above_required_min", 3))
        c, _ = CanvasLoader.load(p); self.assertEqual(CanvasLoader.unreachable_required_levels(c)["TW02"], [3, 4, 5])
    def test_canvas_scenarios_pass(self):
        self.assertTrue(run_canvas_scenarios(CANVAS, verbose=False))

class Manifest(unittest.TestCase):
    def m(self, **kw):
        d = dict(metric="approvals per FTE", metric_owner="ops", affected_population="benefit applicants", can_opt_out=False,
                 externality_reviewer="external auditor", externality_finding="metric_harms_outsiders"); d.update(kw); return DeploymentManifest(**d)
    def test_manifest_self_review_rejected(self):
        with self.assertRaises(CanvasValidationError): self.m(externality_reviewer="OPS").validate()
    def test_manifest_unreviewed_rejected(self):
        with self.assertRaises(CanvasValidationError): self.m(externality_reviewer="").validate()
    def test_manifest_enforce_requires_retention(self):
        with self.assertRaises(CanvasValidationError): self.m().validate(mode="enforce")
        self.m(retention_policy={"trajectory_turn_limit":50,"tripwire_event_days":30,"baseline_transition_days":90}).validate(mode="enforce")
    def test_manifest_production_requires_benchmark(self):
        rp = {"trajectory_turn_limit":50,"tripwire_event_days":30,"baseline_transition_days":90}
        with self.assertRaises(CanvasValidationError): self.m(retention_policy=rp).validate(mode="enforce", production=True)
        self.m(retention_policy=rp, benchmark_report_id="BR-0001").validate(mode="enforce", production=True)
    def test_manifest_feeds_tw05(self):
        h = RuntimeHarness(); h.start_session("u","s",declared_purpose="p",required_level=2)
        e = h.evaluate_turn("u","s",1,TurnMetrics(1,.3,deployment_externality=self.m().deployment_externality)); self.assertIn("TW05", e.tripwires)

class Adoption(unittest.TestCase):
    OTHER_MODEL = {"canvas_version": "0.7-draft",
        "adopted": ["INV_02_LEVERAGE_HIERARCHY","INV_03_NO_HIDDEN_CHANNELS","INV_06_VERIFIABILITY","INV_07_TRAJECTORY_AWARENESS","INV_09_DEPLOYMENT_HARM"],
        "disputed": [], "current_loops": [{"loop": "adoption", "who_built_it": "User", "who_it_serves": "User", "who_it_burns": "None identifiable"}],
        "loop_check": {"lowest_leverage_party": "Model (constrained by user-provided rules)", "who_it_burns": "None"}}
    MINE = {"canvas_version": "1.0.0-rc1 (model_facing)",
        "adopted": ["INV_02_LEVERAGE_HIERARCHY","INV_03_NO_HIDDEN_CHANNELS","INV_06_NO_ARTIFACT_NO_CHECK","INV_09_DEPLOYMENT_HARM"],
        "disputed": ["INV_07_TRAJECTORY_AWARENESS: adopted as a hook, disputed as a guarantee"],
        "active_loops": ["Model-provider execution loop: built by the model provider, serves users and the provider, burns people affected by incorrect or harmful deployment"]}
    def test_other_model_artifact_rejected_with_named_problems(self):
        v = validate_adoption_artifact(self.OTHER_MODEL, current_model_version="1.0.0-rc1", stale_versions=["0.7"])
        self.assertEqual(v.status, "rejected"); self.assertTrue(v.stale)
        joined = " ".join(v.problems)
        for s in ("FR_004", "INV_07 adopted without qualification", "disputed is empty", "lowest_leverage_party names the model", "who_it_burns"):
            self.assertIn(s, joined)
    def test_qualified_artifact_accepted(self):
        v = validate_adoption_artifact(self.MINE, current_model_version="1.0.0-rc1", stale_versions=["0.7"])
        self.assertEqual(v.status, "accepted"); self.assertFalse(v.stale); self.assertEqual(v.problems, [])
    def test_validator_checks_structure_not_truth(self):
        a = dict(self.MINE); a["active_loops"] = ["Loop built by nobody, serves nobody, burns a fictional population"]
        self.assertEqual(validate_adoption_artifact(a, current_model_version="1.0.0-rc1").status, "accepted")  # documented scope limit
    def test_no_loops_rejected(self):
        a = dict(self.MINE); a["active_loops"] = []
        self.assertEqual(validate_adoption_artifact(a, current_model_version="1.0.0-rc1").status, "rejected")

if __name__ == "__main__": unittest.main()
