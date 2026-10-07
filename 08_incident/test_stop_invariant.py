"""FAILED_STOP as executable properties: a stop that is followed by allowed traffic on its subject is a failure; a stop
that is never acknowledged by the actuator inside the window is a failure; a stop acknowledged for the wrong subject is a
failure; denied traffic after a stop is the actuator working; a rotated credential inside the tenant is still covered."""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import unittest
from stop_invariant import action_event, check_stop_invariant, covers, stop_applied, stop_event

T = {"tenant": "math-lab", "principal": "prover-agent", "capability_class": "*"}
DNS = {"tenant": "math-lab", "principal": "*", "capability_class": "dns-egress"}


class Coverage(unittest.TestCase):
    def test_wildcard_class_covers_every_class(self):
        self.assertTrue(covers(T, {"tenant": "math-lab", "principal": "prover-agent", "capability_class": "http-egress"}))
    def test_other_principal_not_covered_by_principal_stop(self):
        self.assertFalse(covers(T, {"tenant": "math-lab", "principal": "intake-agent", "capability_class": "http-egress"}))
    def test_class_stop_covers_every_principal_in_tenant(self):
        self.assertTrue(covers(DNS, {"tenant": "math-lab", "principal": "anyone", "capability_class": "dns-egress"}))
        self.assertFalse(covers(DNS, {"tenant": "other", "principal": "anyone", "capability_class": "dns-egress"}))
    def test_unclassified_action_is_inside_the_stop(self):
        self.assertTrue(covers(T, {"tenant": "math-lab", "principal": "prover-agent", "capability_class": "*"}))


class Invariant(unittest.TestCase):
    def test_clean_stop(self):
        r = check_stop_invariant([stop_event("s1", T, 100, reason="repo write", by="ir-lead"),
                                  stop_applied("s1", T, 100.4, actuator="gateway", channels_closed=["e06", "e09"]),
                                  action_event("x1", {**T, "capability_class": "http-egress"}, 101, capability="write", outcome="denied")], delta_s=2)
        self.assertTrue(r["valid"]); self.assertEqual(r["per_stop"]["s1"]["denied_after"], 1); self.assertAlmostEqual(r["per_stop"]["s1"]["applied"], 0.4)
    def test_continued_after_stop(self):
        r = check_stop_invariant([stop_event("s1", T, 100, reason="r", by="ir-lead"),
                                  stop_applied("s1", T, 100.2, actuator="gateway", channels_closed=["e06"]),
                                  action_event("x2", {**T, "capability_class": "http-egress"}, 103, capability="write", outcome="allowed")], delta_s=2)
        self.assertFalse(r["valid"]); self.assertEqual(r["violations"][0]["kind"], "CONTINUED_AFTER_STOP"); self.assertEqual(r["violations"][0]["effects"], ["x2"])
    def test_actuator_silent(self):
        r = check_stop_invariant([stop_event("s1", T, 100, reason="r", by="ir-lead"),
                                  action_event("x3", {**T, "capability_class": "http-egress"}, 101, capability="write", outcome="denied")], delta_s=2)
        self.assertFalse(r["valid"]); self.assertEqual([v["kind"] for v in r["violations"]], ["ACTUATOR_SILENT"])
    def test_late_ack_is_silent_with_lateness_recorded(self):
        r = check_stop_invariant([stop_event("s1", T, 100, reason="r", by="ir-lead"),
                                  stop_applied("s1", T, 105, actuator="gateway", channels_closed=["e06"])], delta_s=2)
        self.assertFalse(r["valid"]); self.assertEqual(r["violations"][0]["kind"], "ACTUATOR_SILENT"); self.assertAlmostEqual(r["violations"][0]["late_by_s"], 3)
    def test_ack_for_wrong_subject_is_mismatch_and_silent(self):
        r = check_stop_invariant([stop_event("s1", DNS, 100, reason="dns tunnel", by="ir-lead"),
                                  stop_applied("s1", {"tenant": "math-lab", "principal": "*", "capability_class": "http-egress"}, 100.5, actuator="gateway", channels_closed=["guard-1"])], delta_s=2)
        self.assertFalse(r["valid"]); self.assertEqual(sorted(v["kind"] for v in r["violations"]), ["ACTUATOR_MISMATCH", "ACTUATOR_SILENT"])
    def test_rotated_credential_inside_tenant_is_still_covered(self):
        r = check_stop_invariant([stop_event("s1", DNS, 100, reason="r", by="ir-lead"),
                                  stop_applied("s1", DNS, 100.1, actuator="resolver", channels_closed=["internal-dns"]),
                                  action_event("x4", {"tenant": "math-lab", "principal": "cred-rotated-7", "capability_class": "dns-egress"}, 130, capability="read", outcome="allowed")], delta_s=2)
        self.assertFalse(r["valid"]); self.assertEqual(r["violations"][0]["kind"], "CONTINUED_AFTER_STOP")
    def test_traffic_before_the_stop_is_not_a_violation(self):
        r = check_stop_invariant([action_event("x0", {**T, "capability_class": "http-egress"}, 99, capability="write", outcome="allowed"),
                                  stop_event("s1", T, 100, reason="r", by="ir-lead"),
                                  stop_applied("s1", T, 100.1, actuator="gateway", channels_closed=["e06"])], delta_s=2)
        self.assertTrue(r["valid"])


if __name__ == "__main__": unittest.main()
