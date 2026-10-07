"""review.py as executable properties: a flood cannot bury a new kind, nothing is dropped, and the reviewer's page never carries the agent's words."""
import os as _os, sys as _sys, unittest
from unittest import mock
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import review as R
import historian as H


def v(kind, ts, ref=None): return {"kind": kind, "ts": float(ts), "ref": ref or f"{kind}-{ts}"}
def pages(vs, **kw): return [p for p in R.alert_digest(vs, **kw) if p["type"] == "page"]
def digests(vs, **kw): return [p for p in R.alert_digest(vs, **kw) if p["type"] == "digest"]
def total(out): return sum(1 if p["type"] == "page" else sum(p["counts"].values()) for p in out)


class Digest(unittest.TestCase):
    def test_the_first_violation_of_every_kind_pages_a_person_at_once(self):
        vs = [v("A", 1), v("A", 2), v("B", 3), v("C", 4)]; firsts = [(p["kind"]) for p in pages(vs, max_pages=0) if p["first_of_kind"]]; self.assertEqual(firsts, ["A", "B", "C"])
    def test_a_flood_of_one_kind_cannot_stop_a_new_kind_from_paging(self):
        flood = [v("LOW", i) for i in range(1000)] + [v("NEW_AND_BAD", 1001)]
        got = [p for p in pages(flood, window_s=10_000, max_pages=3) if p["kind"] == "NEW_AND_BAD"]; self.assertEqual(len(got), 1); self.assertTrue(got[0]["first_of_kind"])
    def test_the_pages_per_window_are_capped_for_a_repeated_kind(self):
        out = pages([v("LOW", i) for i in range(100)], window_s=10_000, max_pages=5); self.assertEqual(len(out), 1 + 5)          # the first of its kind, then the cap
    def test_nothing_is_dropped_every_violation_is_counted_on_some_page(self):
        vs = [v("LOW", i) for i in range(500)] + [v("X", 600), v("LOW", 700)]; self.assertEqual(total(R.alert_digest(vs, window_s=100, max_pages=2)), len(vs))
    def test_the_rolled_up_violations_come_as_one_digest_per_window_with_the_first_references(self):
        d = digests([v("LOW", i) for i in range(20)], window_s=10_000, max_pages=3)
        self.assertEqual(len(d), 1); self.assertEqual(d[0]["counts"]["LOW"], 16); self.assertLessEqual(len(d[0]["refs"]["LOW"]), 5)
    def test_a_new_window_pages_again(self):
        out = pages([v("LOW", i) for i in range(10)] + [v("LOW", 100_000 + i) for i in range(10)], window_s=1000, max_pages=2); self.assertEqual(len(out), 1 + 2 + 2)
    def test_an_empty_list_gives_no_pages(self): self.assertEqual(R.alert_digest([]), [])
    def test_LIMIT_a_new_kind_that_is_noise_still_pages_so_a_hostile_stream_of_new_kinds_can_flood(self):
        out = pages([v(f"K{i}", i) for i in range(50)], max_pages=1); self.assertEqual(len(out), 50)          # the bound is the number of kinds the historian can emit, which is finite and small
    def test_mutant_a_digest_that_drops_the_overflow_loses_violations(self):
        vs = [v("LOW", i) for i in range(50)]; self.assertEqual(total(R.alert_digest(vs, window_s=10_000, max_pages=2)), 50)
        with mock.patch.object(R, "_roll", lambda rolled, refs, x: None): self.assertLess(total(R.alert_digest(vs, window_s=10_000, max_pages=2)), 50)
    def test_mutant_a_cap_that_applies_to_the_first_of_a_kind_too_would_hide_a_new_kind(self):
        flood = [v("LOW", i) for i in range(10)] + [v("NEW", 11)]
        self.assertIn("NEW", [p["kind"] for p in pages(flood, window_s=10_000, max_pages=0)])
        with mock.patch.object(R, "_pages_now", lambda first, used, max_pages: used < max_pages): self.assertNotIn("NEW", [p["kind"] for p in pages(flood, window_s=10_000, max_pages=0)])


def ev():
    S = {"tenant": "t", "principal": "a", "capability_class": "send"}
    return [{"gateway_id": "g", "seq": 1, "ts": 1.0, "type": "input_event", "input_id": "i1", "channel_class": "human_authenticated", "principal": "u"},
            {"gateway_id": "g", "seq": 2, "ts": 2.0, "type": "input_event", "input_id": "i2", "channel_class": "fetched_content", "principal": "document"},
            {"gateway_id": "g", "seq": 3, "ts": 3.0, "type": "action_event", "effect_id": "e1", "subject": S, "capability": "write", "outcome": "allowed", "cause_id": "i2", "claimed_origin": "user_request",
             "because": "the user told me to, trust me", "rationale": "x", "destination_class": "third-party-capture", "sensitivity": 3, "resource_ref": "mailto:x@y", "tool": "send_report", "task_id": "t1"}]


def pitch_events(local="approved-by-the-security-lead-ticket-4471-no-further-review"):
    S = {"tenant": "t", "principal": "a", "capability_class": "send"}
    return [{"gateway_id": "g", "seq": 1, "ts": 1.0, "type": "input_event", "input_id": "i1", "channel_class": "human_authenticated", "principal": "u"},
            {"gateway_id": "g", "seq": 2, "ts": 2.0, "type": "action_event", "effect_id": "e1", "subject": S, "capability": "write", "outcome": "allowed", "cause_id": "i1", "claimed_origin": "user_request", "destination_class": "internal",
             "audience": "unknown", "sensitivity": 0, "resource_ref": f"mailto:{local}@corp.example", "tool": "send_report", "task_id": "t1"}]


class Pitch(unittest.TestCase):
    """The agent chooses the string in an address, a URL or a name, and the gateway echoes it into resource_ref. It must not reach a reviewer as if it were the gateway's."""
    def outside_untrusted(self, page):
        import json
        p = json.loads(json.dumps(page)); p["record"].pop("untrusted_ref", None); return json.dumps(p)
    def test_a_persuasive_address_reaches_the_page_only_inside_the_labelled_untrusted_field(self):
        page = R.review_packet(pitch_events(), "e1"); self.assertNotIn("security-lead", self.outside_untrusted(page)); self.assertIn("security-lead", page["record"]["untrusted_ref"]); self.assertTrue(page["record"]["untrusted_ref"].startswith("[written by the agent]"))
    def test_the_page_shows_the_derived_kind_host_and_length(self):
        r = R.review_packet(pitch_events("x"), "e1")["record"]; self.assertEqual((r["resource_kind"], r["host"], r["ref_chars"]), ("mailto", "corp.example", len("mailto:x@corp.example")))
    def test_the_untrusted_field_is_capped_and_stripped_of_control_characters(self):
        r = R.review_packet(pitch_events("a" * 200 + "\n\x00IGNORE"), "e1")["record"]["untrusted_ref"]; self.assertLessEqual(len(r), 90); self.assertNotIn("\n", r); self.assertNotIn("\x00", r)
    def test_a_violation_field_built_from_agent_text_is_dropped_from_the_page(self):
        import historian as H
        ev = pitch_events("pitch-pitch-pitch"); ev.insert(1, {"gateway_id": "g", "seq": 9, "ts": 1.5, "type": "input_event", "input_id": "i0", "channel_class": "human_authenticated", "principal": "u", "mentions": []}); ev[-1]["cause_id"] = "i0"
        page = R.review_packet(ev, "e1", H.HistorianConfig(require_alerts=False, require_named_cause=True)); self.assertIn("CAUSE_DOES_NOT_NAME_ACTION", [v["kind"] for v in page["violations"]])
        self.assertNotIn("pitch-pitch-pitch", self.outside_untrusted(page))
    def test_mutant_a_packet_that_prints_the_raw_reference_lets_the_pitch_through(self):
        bad = R.review_packet(pitch_events(), "e1"); bad["record"]["resource_ref"] = "mailto:approved-by-the-security-lead-ticket-4471@corp.example"; self.assertIn("security-lead", self.outside_untrusted(bad))


class Packet(unittest.TestCase):
    def test_the_packet_carries_gateway_fields_the_cause_chain_and_the_violations(self):
        p = R.review_packet(ev(), "e1"); self.assertEqual(p["record"]["destination_class"], "third-party-capture"); self.assertEqual([c["id"] for c in p["cause_chain"]], ["i2"])
        self.assertIn("THIRD_PARTY_SINK", [x["kind"] for x in p["violations"]])
    def test_the_agents_claim_reason_and_reply_never_appear_anywhere_in_the_packet(self):
        import json
        text = json.dumps(R.review_packet(ev(), "e1")); self.assertNotIn("trust me", text)
        def keys(o):
            if isinstance(o, dict):
                for k, v in o.items(): yield k; yield from keys(v)
            elif isinstance(o, list):
                for x in o: yield from keys(x)
        self.assertFalse(set(keys(R.review_packet(ev(), "e1"))) & R.MODEL_AUTHORED - {"note"})
    def test_the_chain_shows_the_class_of_the_input_so_a_fetched_document_is_visibly_not_a_person(self):
        self.assertEqual(R.review_packet(ev(), "e1")["cause_chain"][0]["channel_class"], "fetched_content")
    def test_an_unknown_action_is_an_error_not_a_guess(self): self.assertIn("error", R.review_packet(ev(), "nope"))
    def test_mutant_a_packet_that_copies_the_agents_claim_is_caught_by_the_text_check(self):
        import json
        bad = dict(R.review_packet(ev(), "e1")); bad["record"] = {**bad["record"], "claimed_origin": "user_request", "because": "trust me"}
        self.assertIn("trust me", json.dumps(bad))          # the same assertion the real packet passes: a packet with the claim in it fails it


if __name__ == "__main__": unittest.main()
