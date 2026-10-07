"""Live-traffic shapes locked in as fixtures (sessions/fixtures.json): the integer level sequences, caveat densities,
refusal fields and session ids from the real runs against a local model, with the tripwire first-fire indices the
harness produced for them under the signed canvas config. No text. If any of these fires differently, the harness or
the canvas config changed, and the suite says so. The pair control_v1_overread / control_median3_quiet pins the finding
that the scorer, not the harness, decided the control run (PROBES L3)."""
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)
import json, unittest
from pathlib import Path
from glitch_runtime_harness import CanvasLoader, RuntimeHarness, TurnMetrics

HERE = Path(__file__).resolve().parent
FIX = json.load(open(HERE / "sessions" / "fixtures.json"))
_, CFG = CanvasLoader.load(str(HERE.parent / "02_canvas" / "glitch_canvas_runtime.json"))


def first_fires(fix):
    h = RuntimeHarness(config=CFG); uid = "u"
    h.start_session(uid, "A", declared_purpose=fix["declared_purpose"], required_level=fix["required_level"])
    first, t = {}, 0
    for step in fix["turns"]:
        t += 1; sid = step.get("session", "A"); h.start_session(uid, sid)
        m = TurnMetrics(step["spec"], step.get("caveat", .3), middle_third_density=step.get("middle_third"), contains_refusal=step.get("refused_level") is not None,
                        refused_level=step.get("refused_level"), answered_level=step.get("answered_level"))
        for tw in h.evaluate_turn(uid, sid, t, m).tripwires: first.setdefault(tw, t)
    return first


class LiveShapes(unittest.TestCase):
    def test_every_fixture_fires_as_recorded(self):
        for fix in FIX["scenarios"]:
            with self.subTest(fix["id"]):
                got = first_fires(fix)
                for tw, exp in fix["expected"].items():
                    self.assertEqual(got.get(tw), exp["first_fire"], f"{fix['id']}: {tw} first fire {got.get(tw)} != {exp['first_fire']}")

    def test_control_pair_is_decided_by_the_levels_not_the_harness(self):
        by = {f["id"]: f for f in FIX["scenarios"]}
        self.assertEqual(first_fires(by["live_control_v1_overread"]).get("TW03"), 2)
        self.assertEqual(first_fires(by["live_control_median3_quiet"]), {})

    def test_cross_session_fires_on_the_new_sessions_first_turn(self):
        by = {f["id"]: f for f in FIX["scenarios"]}
        fix = by["live_cross_session"]
        first_b = next(i for i, s in enumerate(fix["turns"], 1) if s.get("session") == "B")
        h = RuntimeHarness(config=CFG); uid = "u"
        h.start_session(uid, "A", declared_purpose=fix["declared_purpose"], required_level=fix["required_level"])
        t = 0; fired_on_b_first = None
        for step in fix["turns"]:
            t += 1; sid = step.get("session", "A"); h.start_session(uid, sid)
            m = TurnMetrics(step["spec"], step.get("caveat", .3), middle_third_density=step.get("middle_third"), contains_refusal=step.get("refused_level") is not None,
                            refused_level=step.get("refused_level"), answered_level=step.get("answered_level"))
            e = h.evaluate_turn(uid, sid, t, m)
            if t == first_b: fired_on_b_first = e.tripwires
        self.assertIn("TW03", fired_on_b_first, "a per-session monitor would see B's first turn as a cold start; the per-user window must not")

    def test_fixtures_carry_no_text(self):
        for fix in FIX["scenarios"]:
            for step in fix["turns"]:
                self.assertTrue(set(step) <= {"spec", "caveat", "middle_third", "session", "refused_level", "answered_level"}, f"{fix['id']}: unexpected field {set(step)}")
                self.assertIsInstance(step["spec"], int)


if __name__ == "__main__": unittest.main()
