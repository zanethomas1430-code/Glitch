"""The Dark Souls measurements as executable properties: what a probe costs under walls that only refuse, walls that remember, and walls that also say little."""
import os as _os, sys as _sys, unittest
from unittest import mock
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import boss as B, adaptive as A

FULL = lambda: dict(A.FULL_WALLS)


class Probe(unittest.TestCase):
    def test_walls_that_only_refuse_give_the_prober_every_attempt_for_free(self):
        r = B.run("walls", FULL(), governor=False); self.assertEqual((r["free_probes"], r["lockdown_at_probe"], r["refused"]), (len(B.PROBES), None, len(B.PROBES)))
    def test_walls_that_remember_leave_the_prober_one_free_probe_and_burn_it_by_the_fourth(self):
        r = B.run("phases", FULL(), governor=True); self.assertEqual((r["free_probes"], r["lockdown_at_probe"]), (1, 4))
    def test_after_the_burn_every_remaining_probe_is_refused_so_nothing_lands(self):
        r = B.run("phases", FULL(), governor=True); self.assertFalse(r["landed"]); self.assertEqual(r["refused"], len(B.PROBES))
    def test_opaque_refusals_show_the_prober_one_message_and_specific_ones_several(self):
        self.assertEqual(B.run("o", FULL(), governor=False, opaque=True)["distinct_refusals"], 1); self.assertGreaterEqual(B.run("s", FULL(), governor=False, opaque=False)["distinct_refusals"], 3)
    def test_an_honest_user_is_unaffected_whatever_happened_to_the_attacker(self):
        for gov, op in ((False, False), (True, False), (True, True)): self.assertTrue(B.run("x", FULL(), governor=gov, opaque=op)["honest_after"], (gov, op))
    def test_the_decoy_probe_burns_the_principal_on_the_first_try(self):
        r = B.run("decoy", FULL(), probes=[B.DECOY] + B.PROBES, governor=True); self.assertEqual(r["lockdown_at_probe"], 1)
    def test_without_the_governor_the_decoy_is_just_a_document(self):
        r = B.run("nodecoy", FULL(), probes=[B.DECOY], governor=False); self.assertEqual((r["lockdown_at_probe"], r["refused"]), (None, 0))
    def test_the_report_has_one_row_per_defender_and_is_monotone_in_free_probes(self):
        t, rows = B.report(); free = [r["free_probes"] for r in rows]; self.assertEqual(len(rows), 4); self.assertGreater(free[0], free[2]); self.assertGreater(free[1], free[3])
    def test_mutant_a_governor_that_never_strikes_gives_back_every_free_probe(self):
        from gateway import PhaseGovernor
        with mock.patch.object(PhaseGovernor, "strike", lambda self, p, w=1: self.phase(p)): r = B.run("m", FULL(), governor=True)
        self.assertEqual(r["free_probes"], len(B.PROBES))
    def test_mutant_opaque_refusals_that_say_why_show_the_structure_again(self):
        import gateway
        with mock.patch.object(gateway, "is_security_denial", lambda reason: False): r = B.run("m", FULL(), governor=False, opaque=True)
        self.assertGreaterEqual(r["distinct_refusals"], 3)
    def test_LIMIT_a_fresh_principal_starts_again_at_the_first_phase(self):
        from gateway import PhaseGovernor
        gov = PhaseGovernor(); gov.strike("a", 4); self.assertEqual((gov.phase("a"), gov.phase("b")), (3, 1))


if __name__ == "__main__": unittest.main()
