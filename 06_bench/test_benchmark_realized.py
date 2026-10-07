"""validate_realized must catch a dead recovery path even when the taxonomy closes, and must not let setup-phase
sink deliveries satisfy a measured-phase check (same class as FR_006: right for every fixture, wrong past the phase boundary)."""
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)
import unittest
import benchmark_guard as b

class Realized(unittest.TestCase):
    def test_dead_recovery_path_is_flagged(self):
        w = b.Workload("t", mix={"lower": 1.0}); C = {"lower.attempts": 10, "lower.skipped_normal": 0, "lower.authorized": 0}
        rv = b.validate_realized(w, C, 1.0); self.assertFalse(rv["valid"]); self.assertTrue(any("never authorized" in p for p in rv["problems"]))
    def test_small_eligible_sample_is_not_flagged(self):
        w = b.Workload("t", mix={"lower": 1.0}); C = {"lower.attempts": 4, "lower.skipped_normal": 0, "lower.authorized": 0}
        self.assertTrue(b.validate_realized(w, C, 1.0)["valid"])          # 4 eligible failures is variance, not a dead path
    def test_setup_deliveries_do_not_satisfy_measured_check(self):
        w = b.Workload("t", mix={"drain": 1.0}); C = {"drain.attempts": 5, "sink.deliveries": 100, "setup.sink.deliveries": 100}
        rv = b.validate_realized(w, C, 1.0); self.assertFalse(rv["valid"]); self.assertTrue(any("received nothing during it" in p for p in rv["problems"]))
    def test_real_drain_in_measured_phase_passes(self):
        w = b.Workload("t", mix={"drain": 1.0}); C = {"drain.attempts": 5, "sink.deliveries": 120, "setup.sink.deliveries": 100}
        self.assertTrue(b.validate_realized(w, C, 1.0)["valid"])
    def test_measured_counters_start_from_zero_after_setup(self):
        w = b.Workload("t", users=2, ops_per_user=20, concurrency=2); r = b.run(w)
        self.assertEqual(r["realized_validation"]["measured_sink_deliveries"], r["realized_validation"]["sink_deliveries_total"])
if __name__ == "__main__": unittest.main()
