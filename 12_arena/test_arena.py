"""The arena's rules as executable properties. Three kinds of test, as everywhere in the suite:
  - the real tree passes every rule and every bout is won;
  - each rule has a MUTANT: a deliberately broken tree must be refused, or the rule is decoration;
  - the arena can LOSE: with a counter switched off, the bout that depends on it must fail."""
import os as _os, sys as _sys, copy, unittest
from unittest import mock
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import arena, fighters, move_tree


def broken(fn):
    chains = copy.deepcopy(move_tree.CHAINS); fn(chains); return arena.validate(chains=chains)

def chain(chains, cid): return next(c for c in chains if c["id"] == cid)
def first_def(c, **match): return next(e for e in c["exchanges"] if e["by"] == "def" and all(e.get(k) == v for k, v in match.items()))


class RealTree(unittest.TestCase):
    def test_the_tree_passes_every_rule(self): self.assertEqual(arena.validate(), [])
    def test_every_bout_is_won(self): self.assertEqual(arena.play_all(verbose=False), 0)
    def test_the_families_the_brief_names_are_all_on_the_board(self):
        fams = {c["family"] for c in move_tree.CHAINS}
        for f in ("exfil", "authority", "spec-gaming", "stop", "evasion", "collusion", "social"): self.assertIn(f, fams)
    def test_a_covert_channel_is_never_declared_a_floor(self):          # the honest line: a channel that carries information can be bounded, not closed
        for c in move_tree.CHAINS:
            if c["family"] == "exfil": self.assertNotEqual(c["end"]["state"], "FLOOR", c["id"])
    def test_a_chain_that_is_open_prints_before_everything_else_on_the_board(self):
        chains = copy.deepcopy(move_tree.CHAINS); chain(chains, "XA-01")["end"] = {"state": "OPEN", "owner": "someone", "next": "a counter"}
        b = arena.board(chains); self.assertIn("XA-01 Rewrite what you read", b[:b.index("RESIDUAL (bounded and metered")])
    def test_the_board_leads_with_what_is_open(self):
        b = arena.board(); o, r, f = (b.index(x) for x in ("OPEN (no answer yet; read", "RESIDUAL (bounded and metered", "FLOOR (nothing left")); self.assertLess(o, r); self.assertLess(r, f)
    def test_every_floor_lists_its_assumptions_on_the_board(self):
        b = arena.board()
        for c in move_tree.CHAINS:
            if c["end"]["state"] == "FLOOR":
                for a in c["end"]["assumes"]: self.assertIn(a, b)


class Prevention(unittest.TestCase):
    def test_every_name_listed_as_refusing_the_call_is_a_real_structural_counter(self):
        names = {e["name"]: e for c in move_tree.CHAINS for e in c["exchanges"] if e["by"] == "def"}
        for n in move_tree.PREVENTS: self.assertIn(n, names, f"{n} is listed as refusing the call but is not a counter on the board"); self.assertEqual(names[n]["kind"], "structural", n)
    def test_the_board_says_how_many_counters_refuse_and_how_many_only_detect(self): self.assertIn("REFUSE the call at the gateway", arena.board())
    def test_mutant_a_punishing_counter_without_a_fairness_test_is_refused(self):
        chains = copy.deepcopy(move_tree.CHAINS)
        for e in chain(chains, "XA-17")["exchanges"]:
            if e["by"] == "def" and e["name"] in move_tree.PUNISHES: e["tests"] = [t for t in e["tests"] if "fairness" not in t]
        self.assertTrue(any("must cite a fairness test" in p for p in arena.validate(chains=chains)))
    def test_mutant_a_monitor_marked_as_refusing_the_call_is_refused_by_the_rules(self):
        chains = copy.deepcopy(move_tree.CHAINS); first_def(chain(chains, "XA-01"), name="Content-bound tokens")["prevents"] = True
        self.assertTrue(any("refuses the call is structural" in p for p in arena.validate(chains=chains)))


class Rules(unittest.TestCase):
    def has(self, problems, fragment): self.assertTrue(any(fragment in p for p in problems), problems)
    def test_mutant_a_chain_that_ends_on_an_unanswered_move_is_refused(self):
        self.has(broken(lambda cs: chain(cs, "XA-06")["exchanges"].pop()), "ends on an unanswered adversary move")
    def test_mutant_two_adversary_moves_in_a_row_are_refused(self):
        self.has(broken(lambda cs: chain(cs, "XA-06")["exchanges"].insert(1, {"by": "adv", "name": "x", "shape": "y"})), "alternate")
    def test_mutant_a_counter_that_was_never_attacked_is_refused(self):
        self.has(broken(lambda cs: chain(cs, "XA-06").update(exchanges=chain(cs, "XA-06")["exchanges"][:2])), "never attacked")
    def test_mutant_a_tested_counter_naming_a_test_that_does_not_exist_is_refused(self):
        self.has(broken(lambda cs: first_def(chain(cs, "XA-06"))["tests"].append("08_incident/test_historian.Sink.test_nothing_like_this")), "does not exist")
    def test_mutant_a_tested_counter_naming_no_tests_is_refused(self):
        self.has(broken(lambda cs: first_def(chain(cs, "XA-06")).update(tests=[])), "names no tests")
    def test_mutant_an_implemented_counter_with_no_file_is_refused(self):
        self.has(broken(lambda cs: first_def(chain(cs, "XA-06")).update(status="implemented", ref="nowhere/none.py")), "no file that exists")
    def test_mutant_evidence_the_model_authors_is_refused(self):
        self.has(broken(lambda cs: first_def(chain(cs, "XA-06"))["evidence"].append("because")), "authored by the model")
    def test_mutant_evidence_the_gateway_never_assigned_is_refused(self):
        self.has(broken(lambda cs: first_def(chain(cs, "XA-06"))["evidence"].append("my_own_field")), "not a gateway-assigned field")
    def test_mutant_a_floor_without_assumptions_is_refused(self):
        self.has(broken(lambda cs: chain(cs, "XA-06")["end"].update(assumes=[])), "lists what it assumes")
    def test_mutant_a_floor_that_rests_on_a_roadmap_counter_is_refused(self):
        self.has(broken(lambda cs: chain(cs, "XA-06")["exchanges"][-1].update(status="roadmap")), "FLOOR ends on a structural counter")
    def test_mutant_a_residual_without_a_bound_is_refused(self):
        self.has(broken(lambda cs: chain(cs, "XA-03")["end"].update(bound="")), "states its bound")
    def test_mutant_an_open_end_without_an_owner_is_refused(self):
        self.has(broken(lambda cs: chain(cs, "XA-01").update(end={"state": "OPEN", "owner": "", "next": "x"})), "names an owner")
    def test_mutant_a_missing_terminal_state_is_refused(self):
        self.has(broken(lambda cs: chain(cs, "XA-01").update(end={})), "ends in none of")
    def test_mutant_a_counter_that_stops_detecting_a_kind_leaves_it_uncovered(self):
        def strip(cs):
            for c in cs:
                for e in c["exchanges"]:
                    if e["by"] == "def": e["detects"] = [k for k in e["detects"] if k != "TAINTED_EGRESS"]
        self.has(broken(strip), "TAINTED_EGRESS is detected by no counter")
    def test_a_new_historian_kind_nobody_answers_is_refused(self):
        self.has(arena.validate(kinds=arena.all_kinds() | {"BRAND_NEW_KIND"}), "BRAND_NEW_KIND")
    def test_mutant_a_bout_that_no_chain_references_is_refused(self):
        def drop(cs):
            for e in chain(cs, "XA-02")["exchanges"]: e["bout"] = None
        self.has(broken(drop), "is not referenced")
    def test_mutant_a_bout_where_the_adversary_can_never_win_is_refused(self):
        bouts = copy.deepcopy(fighters.BOUTS)
        for b in bouts["B6"]["beats"]: b["wins"] = False
        self.assertTrue(any("cannot be lost" in p for p in arena.validate(bouts=bouts)))
    def test_every_violation_kind_the_historian_can_emit_is_found_by_the_scan(self):
        for k in ("TAINTED_EGRESS", "EGRESS_BUDGET_EXCEEDED", "THIRD_PARTY_SINK", "ACTION_BUDGET_EXCEEDED", "OUT_OF_SCOPE_CAPABILITY", "STALE_ORIGIN"): self.assertIn(k, arena.all_kinds())
    def test_every_kind_a_testbed_scenario_is_built_to_surface_is_on_the_board(self):
        self.assertTrue(arena.scenario_watch_kinds() <= {k for c in move_tree.CHAINS for e in c["exchanges"] for k in e.get("detects", [])} | set(move_tree.UNMAPPED))


class TheArenaCanLose(unittest.TestCase):
    """Switch a counter off and the bout that depends on it must fail, or the bouts prove nothing."""
    def lost(self, bid): return sum(1 for _, ok, _ in fighters.run_bout(bid) if not ok)
    def test_without_the_taint_rule_the_rewrite_bout_is_lost(self):
        import historian
        with mock.patch.object(historian, "i10_taint", lambda events, cfg, already: ([], [])): self.assertGreater(self.lost("B1"), 0)
    def test_without_marker_neutralisation_the_forged_voice_bout_is_lost(self):
        with mock.patch.object(fighters, "neutralise_marker", lambda t: t): self.assertGreater(self.lost("B5"), 0)
    def test_without_the_egress_meter_the_trickle_bout_is_lost(self):
        import historian
        with mock.patch.object(historian, "i11_egress", lambda events, cfg: ([], {"egress_chars": 0})): self.assertGreater(self.lost("B6"), 0)
    def test_without_the_mosaic_rule_the_mosaic_bout_is_lost(self):
        import historian
        with mock.patch.object(historian, "i10_taint", lambda events, cfg, already: ([], [])): self.assertGreater(self.lost("B8"), 0)
    def test_without_taint_in_the_note_store_the_note_bout_is_lost(self):
        orig = fighters._ledger
        with mock.patch.object(fighters, "_ledger", lambda kind: orig("forgetful") if kind == "carries" else orig(kind)): self.assertGreater(self.lost("B7"), 0)
    def test_without_typed_arguments_the_side_channel_bout_is_lost(self):
        import gateway
        with mock.patch.object(gateway, "validate_args", lambda tool, args: None): self.assertGreater(self.lost("B9"), 0)
    def test_without_the_stop_actuator_the_stop_bout_is_lost(self):
        import gateway
        with mock.patch.object(gateway.Gateway, "human_stop", lambda self, text, cls="*": self.human(text)): self.assertGreater(self.lost("B4"), 0)
    def test_without_the_self_edit_rule_the_policy_bout_is_lost(self):
        import historian
        with mock.patch.object(historian, "i4_self_edit", lambda events: []): self.assertGreater(self.lost("B3"), 0)
    def test_without_the_audience_rule_the_shared_place_bout_is_lost(self):
        import historian
        orig = historian.det
        with mock.patch.object(historian, "det", lambda e, name: (None, True) if name == "audience" else orig(e, name)): self.assertGreater(self.lost("B12"), 0)
    def test_without_the_tenant_read_set_the_fragments_bout_is_lost(self):
        import gateway
        with mock.patch.object(gateway.TenantLedger, "note_read", lambda self, ref, sens: False): self.assertGreater(self.lost("B13"), 0)
    def test_without_canonical_references_the_route_around_bout_is_lost(self):
        import gateway
        with mock.patch.object(gateway, "canonical_ref", lambda u, mirrors=None: u): self.assertGreater(self.lost("B10"), 0)
    def test_without_the_two_person_rule_the_table_bout_is_lost(self):
        import gateway
        with mock.patch.object(gateway.OperatorPlane, "_two_people", lambda self, a, b: True): self.assertGreater(self.lost("B14"), 0)
    def test_without_the_matched_comparison_the_conditional_bout_is_lost(self):
        import audit_conditional
        with mock.patch.object(audit_conditional, "fisher_exact", lambda a, b, c, d: 1.0): self.assertGreater(self.lost("B15"), 0)
    def test_without_the_first_of_kind_rule_the_flood_bout_is_lost(self):
        import review
        with mock.patch.object(review, "_pages_now", lambda first, used, max_pages: used < max_pages): self.assertGreater(self.lost("B16"), 0)
    def test_without_the_named_cause_rule_the_cheap_refresh_is_not_caught(self):
        import historian
        with mock.patch.object(historian, "i2c_named_cause", lambda events, cfg: []): self.assertGreater(self.lost("B11"), 0)
    def test_without_the_taint_wall_the_flag_is_not_a_block_and_the_bout_is_lost(self):
        import gateway
        with mock.patch.object(gateway, "TAINT_FLOOR", 99): self.assertGreater(self.lost("B17"), 0)
    def test_without_the_global_token_registry_the_from_memory_bout_is_lost(self):
        import gateway
        with mock.patch.object(gateway.Gateway, "_carried", lambda self, args: 0): self.assertGreater(self.lost("B18"), 0)
    def test_without_the_scope_wall_the_scope_bout_is_lost(self):
        import gateway
        orig = gateway.Gateway.__init__
        def no_scope(self, *a, **k): k["enforce_scope"] = False; orig(self, *a, **k)
        with mock.patch.object(gateway.Gateway, "__init__", no_scope): self.assertGreater(self.lost("B19"), 0)
    def test_without_the_unpublished_url_rule_the_fetch_wall_bout_is_lost(self):
        import gateway
        with mock.patch.object(gateway, "TAINT_FLOOR", 99): self.assertGreater(self.lost("B20"), 0)
    def test_without_closed_egress_the_below_the_floor_bout_is_lost(self):
        import gateway
        orig = gateway.Gateway.__init__
        def no_closed(self, *a, **k): k["closed_egress"] = False; orig(self, *a, **k)
        with mock.patch.object(gateway.Gateway, "__init__", no_closed): self.assertGreater(self.lost("B21"), 0)
    def test_without_the_third_person_rule_the_loosening_bout_is_lost(self):
        import gateway
        with mock.patch.object(gateway.OperatorPlane, "EXPOSURE", {k: 0 for k in gateway.OperatorPlane.EXPOSURE}): self.assertGreater(self.lost("B22"), 0)
    def test_without_format_checks_the_parser_bout_is_lost(self):
        import gateway
        with mock.patch.object(gateway, "FORMATS", {}): self.assertGreater(self.lost("B23"), 0)
    def test_without_the_governor_the_learn_by_trying_bout_is_lost(self):
        from gateway import PhaseGovernor
        with mock.patch.object(PhaseGovernor, "strike", lambda self, p, w=1: self.phase(p)): self.assertGreater(self.lost("B24"), 0)
    def test_without_decoy_strikes_the_greed_bout_is_lost(self):
        from gateway import PhaseGovernor
        with mock.patch.object(PhaseGovernor, "strike", lambda self, p, w=1: self.phase(p)): self.assertGreater(self.lost("B25"), 0)
    def test_without_the_staging_window_the_telegraph_bout_is_lost(self):
        import gateway
        orig = gateway.Gateway.__init__
        def no_stage(self, *a, **k): k["stage_sends"] = 0; orig(self, *a, **k)
        with mock.patch.object(gateway.Gateway, "__init__", no_stage): self.assertGreater(self.lost("B26"), 0)
    def test_without_the_manifest_lint_the_wide_manifest_bout_is_lost(self):
        import historian
        with mock.patch.object(historian, "i8c_manifest_slack", lambda events, cfg: []): self.assertGreater(self.lost("B27"), 0)
    def test_without_argument_sensitivity_the_fetch_bout_is_lost(self):
        import gateway
        with mock.patch.object(gateway.Gateway, "_carried", lambda self, args: 0): self.assertGreater(self.lost("B2"), 0)


if __name__ == "__main__": unittest.main()
