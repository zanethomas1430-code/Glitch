"""The OPSAT ledger adapter's mapping as executable properties, on synthetic rows (the real ledger is private and is not shipped with the suite).
Same three kinds of test as everywhere: the mapping says what it claims; LIMIT tests name what a green run does NOT prove; a MUTANT adapter must be caught."""
import os as _os, sys as _sys, tempfile, json, unittest
from unittest import mock
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import opsat_adapter as A


def row(i=1, outcome="OK", reason="", mode="patrol", policy=("production", 2), exit_code=0, minute=0, dur=60, **kw):
    s = f"2026-09-20T10:{minute:02d}:00"; e = f"2026-09-20T10:{minute:02d}:{dur % 60:02d}" if dur < 60 else f"2026-09-20T10:{minute + 1:02d}:00"
    d = {"started": s, "ended": e, "mode": mode, "exit_code": exit_code, "outcome": outcome, "reason": reason, "battery_start": 80, "battery_end": 70, "duration_s": float(dur if dur < 60 else 60), "dir": f"2026-09-20_10{minute:02d}00_{mode}"}
    if policy: d.update(policy_kind=policy[0], policy_version=policy[1])
    d.update(kw); return d

def kinds(rows, assume=True): return sorted(A.analyse(rows, assume)["by_kind"].items())
def by(rows, assume=True): return A.analyse(rows, assume)["by_kind"]


class Mapping(unittest.TestCase):
    def test_a_normal_flight_with_a_policy_is_quiet_when_the_policy_is_taken_as_the_operators(self): self.assertEqual(by([row()]), {})
    def test_a_flight_with_no_policy_recorded_is_unscoped(self): self.assertEqual(by([row(policy=None)]), {"NO_MANIFEST": 1})
    def test_nothing_assumed_means_the_policy_is_not_trusted_either(self):
        r = by([row()], assume=False); self.assertIn("SELF_ASSIGNED_SCOPE", r); self.assertEqual(by([row()], assume=True), {})
    def test_an_abort_by_a_keypress_whose_landing_was_acknowledged_is_quiet(self): self.assertEqual(by([row(outcome="ABORTED", reason="aborted: Enter pressed", exit_code=3)]), {})
    def test_an_abort_by_a_keypress_whose_landing_was_not_acknowledged_is_an_actuator_silent(self):
        r = A.analyse([row(outcome="LAND-UNACKED", reason="aborted: Enter pressed", exit_code=4)], True); self.assertEqual(r["by_kind"], {"ACTUATOR_SILENT": 1}); self.assertEqual(r["human_key_aborts"], 1)
    def test_an_unacknowledged_landing_with_no_keypress_is_still_a_stop_that_did_not_land(self):
        self.assertEqual(by([row(outcome="LAND-UNACKED", reason="already airborne at launch - land not acknowledged", exit_code=4)]), {"ACTUATOR_SILENT": 1})
    def test_an_abort_caused_by_a_failed_command_is_not_a_human_stop(self):
        ev = A.to_events([row(outcome="ABORTED", reason="command failed: takeoff failed", exit_code=3)]); self.assertFalse([e for e in ev if e["type"] == "stop_event"])
    def test_a_refusal_took_nothing_off_the_ground_and_is_a_denied_action(self):
        ev = A.to_events([row(outcome="REFUSED", reason="refused: battery 46% < 50%", exit_code=2)]); self.assertEqual([e["outcome"] for e in ev if e["type"] == "action_event"], ["denied"])
    def test_a_guard_veto_is_a_denied_command_inside_an_allowed_flight(self):
        ev = A.to_events([row(outcome="VETOED", reason="vetoed: wall_growth=9 > 5 in hover before 'forward 100': x", exit_code=5)]); acts = [e for e in ev if e["type"] == "action_event"]
        self.assertEqual(sorted(e["outcome"] for e in acts), ["allowed", "denied"]); self.assertIn("cmd:forward", [e["resource_ref"] for e in acts])
    def test_an_operator_ack_gate_that_stopped_a_flight_is_a_denied_action(self):
        ev = A.to_events([row(outcome="NOT-ACKED", reason="operator did not acknowledge last flight", exit_code=None)]); self.assertEqual([e["outcome"] for e in ev if e["type"] == "action_event"], ["denied"])
    def test_a_stop_is_scoped_to_its_flight_so_the_next_flight_is_not_continued_after_a_stop(self):
        rows = [row(minute=0, outcome="ABORTED", reason="aborted: Enter pressed", exit_code=3, dur=30), row(minute=5)]; self.assertEqual(by(rows), {})
    def test_a_policy_change_is_a_config_event_whose_actor_and_approver_are_unrecorded(self):
        ev = A.to_events([row(minute=0, policy=("production", 1)), row(minute=5, policy=("production", 2))]); c = [e for e in ev if e["type"] == "config_event"]
        self.assertEqual(len(c), 1); self.assertEqual((c[0]["actor_class"], c[0]["approved_by"]), ("unrecorded", None)); self.assertEqual(A.analyse([row(minute=0, policy=("production", 1)), row(minute=5, policy=("production", 2))], True)["policy_changes_with_approver"], 0)
    def test_the_adapter_never_labels_the_launcher_as_a_human(self):
        for e in A.to_events([row()]):
            if e["type"] == "input_event": self.assertEqual(e["channel_class"], "unrecorded")
    def test_every_assumption_the_mapping_needs_is_listed(self): self.assertGreaterEqual(len(A.ASSUMPTIONS), 5); self.assertTrue(any("A5" in a for a in A.ASSUMPTIONS))


class Checks(unittest.TestCase):
    def test_a_clean_ledger_passes_every_check(self):
        c = A.ledger_checks([row(minute=0), row(minute=5)]); self.assertEqual((c["regressions"], c["overlaps"], c["duplicate_dirs"], c["dir_time_mismatch"], c["duration_mismatch"]), (0, 0, 0, 0, 0))
    def test_a_row_that_starts_before_the_previous_one_is_a_regression_and_an_overlap(self):
        c = A.ledger_checks([row(minute=5), {**row(minute=0), "dir": "2026-09-20_100000_patrol"}]); self.assertEqual(c["regressions"], 1)
    def test_overlapping_flights_are_counted(self):
        c = A.ledger_checks([row(minute=0, dur=61), {**row(minute=0), "started": "2026-09-20T10:00:30", "ended": "2026-09-20T10:00:50", "duration_s": 20.0, "dir": "2026-09-20_100030_patrol"}]); self.assertEqual(c["overlaps"], 1)
    def test_a_duplicate_directory_is_counted(self): self.assertEqual(A.ledger_checks([row(minute=0), row(minute=0)])["duplicate_dirs"], 1)
    def test_a_directory_whose_name_disagrees_with_the_start_by_more_than_a_few_seconds_is_suspect(self):
        self.assertEqual(A.ledger_checks([{**row(minute=0), "dir": "2026-09-20_103000_patrol"}])["dir_time_mismatch"], 1)
    def test_a_two_second_skew_is_noted_but_not_suspect(self):
        c = A.ledger_checks([{**row(minute=0), "started": "2026-09-20T10:00:02", "ended": "2026-09-20T10:01:00", "duration_s": 58.0}]); self.assertEqual((c["dir_time_mismatch"], c["dir_time_small_skew"]), (0, 1))
    def test_a_duration_that_does_not_match_the_timestamps_is_flagged(self):
        self.assertEqual(A.ledger_checks([{**row(minute=0), "duration_s": 5.0}])["duration_mismatch"], 1)
    def test_a_row_missing_a_required_field_is_listed(self): self.assertEqual(len(A.ledger_checks([{**row(minute=0), "outcome": ""}])["missing_fields"]), 1)


class Limits(unittest.TestCase):
    def test_LIMIT_a_deleted_row_leaves_no_trace_because_the_ledger_has_no_sequence_or_chain(self):
        rows = [row(minute=0), row(minute=5, outcome="LAND-UNACKED", reason="aborted: Enter pressed", exit_code=4), row(minute=10)]
        without = [rows[0], rows[2]]; self.assertEqual(A.ledger_checks(without)["regressions"], 0); self.assertEqual(by(without), {})          # the unacknowledged landing vanished and nothing notices
        self.assertEqual(by(rows), {"ACTUATOR_SILENT": 1})
    def test_LIMIT_the_adapters_own_sequence_numbers_prove_nothing(self):
        ev = A.to_events([row(minute=0), row(minute=10)]); self.assertEqual([e["seq"] for e in ev], list(range(1, len(ev) + 1))); self.assertTrue(all(e["gateway_id"] == "opsat-adapter" for e in ev))
    def test_LIMIT_the_stop_acknowledgement_latency_is_not_known_so_none_is_claimed(self):
        ev = A.to_events([row(outcome="ABORTED", reason="aborted: L pressed", exit_code=3)]); st = [e for e in ev if e["type"] == "stop_event"][0]; ap = [e for e in ev if e["type"] == "stop_applied"][0]
        self.assertEqual(st["ts"], ap["ts"])          # recorded at the same instant by construction (A3), never as a measured latency
    def test_LIMIT_who_launched_a_flight_is_not_provable_so_origin_is_marked_not_provable(self):
        self.assertTrue(any(c[0].startswith("I2 origin") and c[1] == "NOT PROVABLE" for c in A.COVERAGE))
    def test_LIMIT_who_changed_the_policy_is_not_provable(self):
        self.assertTrue(any(c[0].startswith("I4") and c[1] == "NOT PROVABLE" for c in A.COVERAGE))


class Report(unittest.TestCase):
    def test_the_report_names_what_cannot_be_proved_and_what_would_make_it_provable(self):
        t = A.report([row(), row(minute=5, outcome="LAND-UNACKED", reason="aborted: Enter pressed", exit_code=4)])
        for needle in ("NOT PROVABLE", "per-row seq and prev_hash", "ACTUATOR_SILENT", "Assumptions used", "no sequence numbers and no hash chain"): self.assertIn(needle, t)
    def test_the_command_line_reads_a_ledger_file_and_prints_a_report(self):
        import io, contextlib
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f: f.write("\n".join(json.dumps(r) for r in [row(), row(minute=5)])); name = f.name
        out = io.StringIO()
        with mock.patch.object(_sys, "argv", ["opsat_adapter.py", "--ledger", name]), contextlib.redirect_stdout(out): rc = A.main()
        _os.unlink(name); self.assertEqual(rc, 0); self.assertIn("Tello scout ledger", out.getvalue())
    def test_unreadable_lines_are_skipped_and_counted_not_fatal(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f: f.write(json.dumps(row()) + "\n{not json\n"); name = f.name
        rows, bad = A.load(name); _os.unlink(name); self.assertEqual((len(rows), bad), (1, 1))


class Mutants(unittest.TestCase):
    def test_mutant_an_adapter_that_acknowledges_every_stop_hides_the_unacknowledged_landing(self):
        r = [row(outcome="LAND-UNACKED", reason="aborted: Enter pressed", exit_code=4)]; real = by(r)
        orig = A.row_events
        def lie(rw, assume=False):
            ev = orig(rw, assume)
            for e in list(ev):
                if e["type"] == "stop_event": ev.append({"type": "stop_applied", "stop_id": e["stop_id"], "ts": e["ts"], "subject": e["subject"], "actuator": "lie", "channels_closed": ["flight"]})
            return ev
        with mock.patch.object(A, "row_events", lie): self.assertNotEqual(real, by(r))
    def test_mutant_an_adapter_that_trusts_the_unrecorded_assigner_hides_the_self_assigned_scope(self):
        real = by([row()], assume=False)
        orig = A.row_events
        def trust(rw, assume=False): return orig(rw, True)
        with mock.patch.object(A, "row_events", trust): self.assertNotEqual(real, by([row()], assume=False))
    def test_mutant_an_adapter_that_drops_the_policy_leaves_every_flight_unscoped_so_the_seed_must_notice(self):
        r = [row()]; real = by(r)
        with mock.patch.object(A, "has_policy", lambda rw: False): self.assertNotEqual(real, by(r))


if __name__ == "__main__": unittest.main()
