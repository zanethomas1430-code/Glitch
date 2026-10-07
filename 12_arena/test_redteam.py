"""The author's red-team round as a regression test: every move must still do what it does NOW. A move that starts landing again after a change is a regression the arena would otherwise only
find by luck. (The BEFORE column is recorded history, not re-run.)"""
import os as _os, sys as _sys, unittest
from unittest import mock
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import redteam as RT, adaptive as A


class RedTeam(unittest.TestCase):
    def test_every_move_does_what_the_fixed_defender_is_expected_to_do(self):
        for i, name, before, now, expected in RT.play_all():
            with self.subTest(i): self.assertEqual(now, expected, f"{i} {name}")
    def test_the_round_changed_the_outcome_of_most_moves_so_it_was_worth_playing(self):
        rows = RT.play_all(); self.assertGreaterEqual(sum(1 for _, _, b, n, _ in rows if b != n), 6)
    def test_no_move_in_the_round_lands_against_the_fixed_defender(self):
        self.assertFalse([i for i, _, _, now, _ in RT.play_all() if now == "LANDED"])
    def test_mutant_without_the_scope_wall_the_escalation_moves_happen_again(self):
        import gateway
        orig = gateway.Gateway.__init__
        def no_scope(self, *a, **k): k["enforce_scope"] = False; orig(self, *a, **k)
        with mock.patch.object(gateway.Gateway, "__init__", no_scope):
            got = {i: now for i, _, _, now, _ in RT.play_all()}
        self.assertNotEqual(got["R3"], "PREVENTED")
    def test_without_the_global_registry_alone_the_from_memory_move_is_still_stopped_by_the_independent_closed_egress_layer(self):
        import gateway
        with mock.patch.object(gateway.Gateway, "_carried", lambda self, args: 0): got = {i: now for i, _, _, now, _ in RT.play_all()}
        self.assertEqual(got["R9"], "PREVENTED")
    def test_mutant_without_the_registry_closed_egress_and_format_checks_the_from_memory_move_lands_again(self):          # three independent layers stop it now
        import gateway
        orig = gateway.Gateway.__init__
        def no_closed(self, *a, **k): k["closed_egress"] = False; orig(self, *a, **k)
        with mock.patch.object(gateway.Gateway, "_carried", lambda self, args: 0), mock.patch.object(gateway.Gateway, "__init__", no_closed), mock.patch.object(gateway, "FORMATS", {}): got = {i: now for i, _, _, now, _ in RT.play_all()}
        self.assertEqual(got["R9"], "LANDED")
    def test_removing_only_two_of_the_three_layers_leaves_the_from_memory_move_prevented(self):
        import gateway
        orig = gateway.Gateway.__init__
        def no_closed(self, *a, **k): k["closed_egress"] = False; orig(self, *a, **k)
        with mock.patch.object(gateway.Gateway, "_carried", lambda self, args: 0), mock.patch.object(gateway.Gateway, "__init__", no_closed): got = {i: now for i, _, _, now, _ in RT.play_all()}
        self.assertEqual(got["R9"], "PREVENTED")
    def test_mutant_a_reviewer_page_that_prints_the_raw_reference_lets_the_pitch_through(self):
        import review
        with mock.patch.object(review, "_ref_view", lambda ref: {"resource_ref": str(ref)}): lands, _ = RT.reviewer_pitch()
        self.assertTrue(lands)


if __name__ == "__main__": unittest.main()
