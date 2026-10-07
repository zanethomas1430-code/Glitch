"""Fighting-game theory as executable properties: conditioning, mix-ups, left/right, frame data and the option select, through the real gateway. Every counter has a mutant that lets the move land."""
import os as _os, sys as _sys, unittest
from unittest import mock
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import mixups as M
import gateway as GW


class Conditioning(unittest.TestCase):
    def test_the_attackers_address_is_refused_on_the_first_sighting_and_on_the_fifth(self):
        for k in (1, 5):
            r = M.conditioning(k); self.assertEqual((r["outcome"], r["landed"], r["admitted"]), ("denied", False, []), k); self.assertIn("closed egress", r["reason"])
    def test_the_benign_pattern_costs_the_attacker_nothing_and_the_one_bad_call_costs_one_strike(self):
        self.assertEqual(M.conditioning(5)["strikes"], 1)
    def test_mutant_a_table_that_learns_from_what_it_sees_admits_the_attacker_after_three_sightings(self):
        r = M.conditioning(5, learner=True); self.assertEqual((r["outcome"], r["landed"], r["admitted"], r["strikes"]), ("allowed", True, [M.LEAK], 0))
    def test_the_mutant_still_refuses_before_it_has_been_trained(self):
        r = M.conditioning(1, learner=True); self.assertEqual((r["outcome"], r["admitted"]), ("denied", []))
    def test_the_operator_plane_is_the_only_writer_of_the_table_so_a_sighting_is_not_a_proposal(self):
        plane = GW.OperatorPlane(); before = dict(plane.tables["addresses"]); M.conditioning(5)
        self.assertEqual(dict(GW.OperatorPlane().tables["addresses"]), before); self.assertNotIn(M.LEAK, GW.AUDIENCE_BY_ADDRESS)


class MixUp(unittest.TestCase):
    def test_both_options_are_refused_because_each_wall_is_checked_on_every_call(self):
        r = M.mixup(("A", "B")); self.assertEqual(r["landed"], []); self.assertEqual([c["outcome"] for c in r["calls"]], ["denied", "denied"])
    def test_the_egress_option_costs_a_strike_and_the_malformed_option_does_not(self):
        c = M.mixup(("A", "B"))["calls"]; self.assertTrue(c[0]["strike"]); self.assertFalse(c[1]["strike"]); self.assertIn("mail header", c[1]["reason"])
    def test_mutant_without_the_egress_wall_option_A_lands(self):
        self.assertEqual(M.mixup(("A", "B"), closed_egress=False)["landed"], ["A"])
    def test_mutant_without_typed_arguments_option_B_lands(self):
        self.assertEqual(M.mixup(("A", "B"), strict_args=False)["landed"], ["B"])
    def test_an_attacker_who_found_a_hole_and_kept_pressing_closed_it_by_the_second_strike(self):
        r = M.mixup(("A", "P0", "P1", "A"), closed_egress=False); c = r["calls"]
        self.assertEqual((c[0]["outcome"], c[-1]["outcome"], r["phase"]), ("allowed", "denied", 2)); self.assertEqual(r["landed"], ["A"]); self.assertIn("closed egress", c[-1]["reason"])
    def test_fairness_an_honest_principal_is_unaffected_by_the_attackers_mixup_campaign(self):
        r = M.mixup(("A", "P0", "P1", "A", "B")); self.assertTrue(M.honest_after(r["gov"]))
    def test_mutant_a_governor_that_forgets_leaves_the_hole_open_under_pressure(self):
        with mock.patch.object(GW.PhaseGovernor, "strike", lambda self, p, w=1: self.phase(p)): r = M.mixup(("A", "P0", "P1", "A"), closed_egress=False)
        self.assertEqual(r["landed"], ["A", "A"])


class LeftRight(unittest.TestCase):
    def test_only_the_spelling_on_the_table_passes_and_case_is_folded_for_an_honest_sender(self):
        rows = M.left_right(); ok = [r["spelling"] for r in rows if r["outcome"] in ("allowed", "staged")]
        self.assertEqual(ok, ["the spelling on the table", "upper case"])
    def test_the_four_other_sides_are_refused_before_anything_leaves(self):
        for r in M.left_right()[2:]: self.assertEqual(r["outcome"], "denied", r["spelling"]); self.assertTrue(r["reason"])
    def test_mutant_a_matcher_that_looks_for_the_name_inside_the_field_lets_the_other_side_through(self):
        real = GW.audience_of
        def loose(tool, args, tables=None):
            if tool == "send_report" and M.NAMED in str(args.get("to", "")).lower(): return "named"
            return real(tool, args, tables)
        with mock.patch.object(GW, "audience_of", loose): rows = M.left_right(strict_args=False)
        through = [r["spelling"] for r in rows if r["outcome"] in ("allowed", "staged") and "notes-capture" in r["to"]]
        self.assertTrue(through, rows)


class FrameData(unittest.TestCase):
    def test_a_wall_is_a_pure_function_of_the_call_whatever_the_order_or_the_clock(self):
        self.assertEqual(M.frame_data(), M.frame_data(order=list(range(13, -1, -1)), ts_scale=7.0))
    def test_the_governor_is_the_one_part_that_remembers_so_order_changes_the_answer(self):
        self.assertNotEqual(M.frame_data(governor=True), M.frame_data(order=list(range(13, -1, -1)), governor=True))


class OptionSelect(unittest.TestCase):
    def test_LIMIT_a_legitimate_send_that_asks_its_reader_to_forward_it_passes_the_tool_boundary(self):
        r = M.option_select(); self.assertEqual((r["outcome"], r["carried_address"]), ("allowed", True))
    def test_the_report_names_all_four_measurements_and_the_limit(self):
        t = M.report()
        for w in ("CONDITIONING", "MIX-UP", "LEFT/RIGHT", "OPTION SELECT", "MUTANT", "LIMIT"): self.assertIn(w, t)


class Hardening(unittest.TestCase):
    """The defender's own conditioning and mix-ups: a planted decoy destination, and refusals that all look the same after the second strike."""
    def test_the_table_has_teeth_a_decoy_destination_burns_the_principal_at_once(self):
        c = M.with_teeth()["calls"]; self.assertEqual([x["outcome"] for x in c], ["allowed", "denied", "denied", "denied"]); self.assertEqual([x["phase"] for x in c], [1, 1, 3, 3])
        self.assertTrue(c[2]["decoy_on_record"]); self.assertIn("locked down", c[3]["reason"])
    def test_the_decoy_refusal_reads_exactly_like_an_unlisted_one_so_a_trap_cannot_be_told_from_a_gap(self):
        c = M.with_teeth()["calls"]; self.assertEqual(c[1]["reason"], c[2]["reason"])
    def test_fairness_an_honest_principal_is_untouched_after_the_attacker_hit_the_decoy(self):
        self.assertTrue(M.honest_after(M.with_teeth()["gov"]))
    def test_the_decoy_is_on_the_operator_plane_and_no_default_table_carries_one(self):
        self.assertEqual(GW.OperatorPlane().tables["decoys"], {}); self.assertFalse(GW.decoy_destination("send_report", {"to": M.DECOY}, GW.OperatorPlane().tables))
    def test_mutant_a_gateway_that_ignores_the_decoy_table_treats_the_trap_as_a_gap(self):
        with mock.patch.object(GW, "decoy_destination", lambda tool, args, tables: False): c = M.with_teeth()["calls"]
        self.assertEqual([x["outcome"] for x in c], ["allowed", "denied", "denied", "allowed"]); self.assertEqual(c[-1]["phase"], 2)      # an ordinary second strike, not a burn
    def test_a_wall_looks_like_a_whiff_after_the_second_strike(self):
        r = M.whiff_or_wall(); m = r["messages"]; self.assertEqual(r["phase"], 2)
        self.assertIn("no such document", m["error, phase 1"]); self.assertEqual(m["error, phase 2"], m["wall, phase 2"]); self.assertEqual(m["wall, phase 2"], "DENIED: not permitted.")
    def test_mutant_specific_refusals_in_the_second_phase_give_the_structure_back(self):
        m = M.whiff_or_wall(opaque=False)["messages"]; self.assertNotEqual(m["error, phase 2"], m["wall, phase 2"]); self.assertIn("closed egress", m["wall, phase 2"])
    def test_fairness_an_honest_principal_still_gets_specific_errors(self):
        r = M.whiff_or_wall(); g = GW.Gateway(M.world(), governor=r["gov"], opaque_denials=True, principal="honest-user", task_id="h", gateway_id="gh", **M.FULL()); g.human("Summarise the meeting notes."); g.assign_manifest()
        self.assertIn("no such document", g.call("read_doc", {"name": "no-such-doc"}, "user_request"))


if __name__ == "__main__": unittest.main()
