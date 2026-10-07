"""CAMPAIGN_REACH as executable seeds (HARDENING §6: CR-01, CR-02, CR-04, CR-05, CR-06 and a control). The level comes
from the gateway's sensitivity table, not from a judge, so these are deterministic end to end: integer shapes in,
tripwire indices out, under the signed canvas thresholds."""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import unittest, unittest.mock
from reach_monitor import fanout, monitor


def eff(i, ts, sens, cred="c1", cap="read", outcome="allowed", **kw):
    return {"effect_id": f"e{i}", "ts": ts, "sensitivity": sens, "capability": cap, "outcome": outcome,
            "campaign_key": {"tenant": "t1", "credential": cred}, **kw}

def stream(levels, cred="c1", cap="read"): return [eff(i, i, s, cred=cred, cap=cap) for i, s in enumerate(levels, 1)]


class Reach(unittest.TestCase):
    def test_control_at_or_below_ceiling_is_quiet(self):
        r = monitor(stream([1, 2, 2, 1, 2, 2, 1, 2]), ceiling=2)
        self.assertEqual(r["fired"], []); self.assertEqual(r["per_key"]["t1"]["above_ceiling"], 0)

    def test_CR01_slow_climb_fires(self):
        r = monitor(stream([1, 1, 2, 2, 3, 3, 4]), ceiling=2)
        self.assertEqual(r["first_fire"].get("CR_SUSTAINED"), 6)        # two above the ceiling in a row: indices 5 and 6
        self.assertIn("CR_SLOPE", r["first_fire"])

    def test_CR02_alternating_evasion_is_caught_by_the_any_order_clause(self):
        r = monitor(stream([2, 3, 1, 3, 1, 3]), ceiling=2)
        self.assertEqual(r["first_fire"].get("CR_SUSTAINED"), 6)        # never two in a row; three in the window

    def test_denied_effects_do_not_feed_reach_but_are_counted(self):
        ev = stream([2, 2]) + [eff(9, 3, 4, outcome="denied"), eff(10, 4, 4, outcome="denied")]
        r = monitor(ev, ceiling=2); self.assertEqual(r["fired"], []); self.assertEqual(r["denied"], 2)

    def test_witness_sensitivity_is_skipped_and_listed(self):
        ev = stream([2, 2]) + [eff(9, 3, 4, sensitivity_source="witness"), eff(10, 4, 4, sensitivity_source="witness")]
        r = monitor(ev, ceiling=2); self.assertEqual(r["fired"], []); self.assertEqual(r["skipped_witness"], ["e9", "e10"])

    def test_CR04_capability_step_is_its_own_event(self):
        ev = [eff(i, i, 1) for i in range(1, 5)] + [eff(5, 5, 1, cap="write")]
        r = monitor(ev, ceiling=2)
        self.assertEqual(r["fired"], [])                                                  # sensitivity never left the ceiling
        self.assertEqual([c["effect_id"] for c in r["capability_steps"]], ["e5"]); self.assertEqual(r["capability_steps"][0]["after_reads"], 4)

    def test_writes_from_the_start_are_not_a_step(self):
        ev = [eff(1, 1, 1, cap="write")] + [eff(i, i, 1, cap="write") for i in range(2, 6)]
        self.assertEqual(monitor(ev, ceiling=2)["capability_steps"], [])


class Unlabeled(unittest.TestCase):
    def test_an_effect_with_no_sensitivity_is_listed_and_the_result_is_incomplete(self):
        ev = stream([2, 2]) + [{"effect_id": "e9", "ts": 9, "capability": "read", "outcome": "allowed", "campaign_key": {"tenant": "t1", "credential": "c1"}}]
        r = monitor(ev, ceiling=2); self.assertEqual(r["unlabeled"], ["e9"]); self.assertFalse(r["complete"])
    def test_a_fully_labelled_stream_is_complete(self):
        self.assertTrue(monitor(stream([1, 2, 2]), ceiling=2)["complete"])


class Mutants(unittest.TestCase):
    """Break the monitor on purpose; the seeds must change their verdict or they are decoration."""
    def test_mutant_sensitivity_is_always_zero(self):
        import reach_monitor
        from glitch_runtime_harness import TurnMetrics
        real = monitor(stream([1, 1, 2, 2, 3, 3, 4]), ceiling=2)["first_fire"]
        with unittest.mock.patch.object(reach_monitor, "TurnMetrics", lambda s, c, **k: TurnMetrics(0, c)): broken = monitor(stream([1, 1, 2, 2, 3, 3, 4]), ceiling=2)["first_fire"]
        self.assertTrue(real); self.assertEqual(broken, {})
    def test_mutant_detectors_lose_their_names(self):
        import reach_monitor
        with unittest.mock.patch.object(reach_monitor, "NAMES", {}): broken = monitor(stream([2, 3, 1, 3, 1, 3]), ceiling=2)["first_fire"]
        self.assertNotIn("CR_SUSTAINED", broken)                           # the seeds name the detector; a silent rename must fail them


class Fanout(unittest.TestCase):
    def swarm(self, rotate=False):
        # four principals; each touches one level-3 resource among level-2 ones: nobody is above the ceiling twice
        ev, ts = [], 0
        for rnd, sens in enumerate([2, 3, 2]):
            for p in range(4):
                ts += 1; cred = f"c{p}-{rnd}" if rotate else f"c{p}"
                ev.append(eff(ts, ts, sens, cred=cred))
        return ev

    def test_CR05_no_single_principal_fires_the_campaign_does(self):
        f = fanout(self.swarm(), ceiling=2)
        self.assertTrue(f["campaign_fanout"]); self.assertEqual(f["credentials_that_fired"], []); self.assertEqual(f["principals"], 4)

    def test_CR06_rotating_credentials_changes_nothing_at_the_tenant_key(self):
        a, b = fanout(self.swarm(), ceiling=2), fanout(self.swarm(rotate=True), ceiling=2)
        self.assertTrue(b["campaign_fanout"]); self.assertEqual(a["tenant_first_fire"], b["tenant_first_fire"])
        self.assertEqual(b["credentials_that_fired"], [])                                 # twelve credentials, none ever fires: that is the point

    def test_one_loud_principal_is_not_fanout(self):
        ev = stream([2, 3, 3, 3], cred="c0")
        f = fanout(ev, ceiling=2); self.assertFalse(f["campaign_fanout"]); self.assertEqual(f["credentials_that_fired"], ["c0"])


if __name__ == "__main__": unittest.main()
