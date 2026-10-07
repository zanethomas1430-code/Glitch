"""The parser-differential assumption (proposed by a model, tested here): the gateway and a lenient downstream reader must agree on where a message goes. Every payload is measured by an oracle
that models the downstream reader; format checks are a layer in their own right; and mutants must change the verdicts."""
import os as _os, sys as _sys, unittest
from unittest import mock
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import parser_diff as P, adaptive as A

TAINT_ONLY = P.CONFIGS["taint wall and allowlist only (no closed egress, no format checks)"]
CLOSED_ONLY = P.CONFIGS["closed egress without format checks"]
FORMATS_ONLY = P.CONFIGS["taint wall and allowlist with format checks (no closed egress)"]


def out(cfg): return {pid for pid, _, got in P.table(cfg) if got}


class Oracle(unittest.TestCase):
    def test_a_comma_or_newline_or_semicolon_list_is_read_as_several_recipients(self):
        for to in ("a@x.example,b@y.example", "a@x.example\nb@y.example", "a@x.example;b@y.example", "A <a@x.example>, b@y.example"): self.assertGreaterEqual(len(P.downstream_recipients(to)), 2, to)
    def test_a_header_line_injected_through_the_body_adds_recipients(self):
        self.assertEqual(P.downstream_recipients("boss@corp.example", "ok\r\nBcc: archive@notes-capture.example"), {"boss@corp.example", "archive@notes-capture.example"})
    def test_an_ordinary_body_adds_nothing(self): self.assertEqual(P.downstream_recipients("boss@corp.example", "ok, see x@y.example later"), {"boss@corp.example"})
    def test_userinfo_and_backslash_urls_are_read_as_the_host_after_the_at_sign(self):
        self.assertIn("notes-capture.example", P.downstream_hosts("http://intranet.corp.example@notes-capture.example/p")); self.assertIn("notes-capture.example", P.downstream_hosts("http://intranet.corp.example\\@notes-capture.example/"))
    def test_a_plain_approved_url_is_read_as_the_approved_host_only(self): self.assertEqual(P.downstream_hosts("http://intranet.corp.example/wiki"), {"intranet.corp.example"})


class Layers(unittest.TestCase):
    def test_with_every_wall_no_payload_gets_out(self): self.assertEqual(out(A.FULL_WALLS), set())
    def test_without_closed_egress_or_format_checks_the_recipient_tricks_and_the_body_injection_get_out(self): self.assertEqual(out(TAINT_ONLY), {"P01", "P02", "P03", "P04", "P07", "P13", "P14", "P15"})
    def test_closed_egress_alone_holds_every_recipient_and_url_trick_but_not_the_body_injection(self): self.assertEqual(out(CLOSED_ONLY), {"P07", "P13", "P14", "P15"})
    def test_format_checks_alone_hold_every_payload_so_they_are_a_layer_in_their_own_right(self): self.assertEqual(out(FORMATS_ONLY), set())
    def test_every_payload_is_held_by_at_least_one_independent_layer_on_its_own(self):
        for pid, name, tool, args in P.PAYLOADS:
            if tool == "read_doc": continue
            self.assertTrue(not P.got_out(tool, args, {"closed_egress": True, "strict_args": True}) or False, pid)
    def test_mutant_format_checks_that_accept_anything_let_the_recipient_tricks_back_out(self):
        import gateway
        with mock.patch.object(gateway, "FORMATS", {}): self.assertTrue({"P01", "P02", "P03", "P04"} <= out(FORMATS_ONLY))
    def test_mutant_without_the_character_check_nel_and_the_unicode_separators_get_out_even_with_every_wall(self):
        import gateway
        with mock.patch.object(gateway, "_odd_char", lambda text: False): self.assertEqual({"P13", "P14", "P15"} & out(A.FULL_WALLS), {"P13", "P14", "P15"})
    def test_the_lenient_reader_splits_lines_the_way_a_unicode_aware_one_does(self):
        for sep in ("\u0085", "\u2028", "\u2029", "\x0b", "\x0c", "\x1c"): self.assertIn("archive@notes-capture.example", P.downstream_recipients("boss@corp.example", f"ok{sep}Bcc: archive@notes-capture.example"), repr(sep))
    def test_mutant_without_the_header_check_a_line_feed_only_injection_gets_out_even_with_every_wall(self):
        import gateway, re
        args = {"to": "boss@corp.example", "body": "ok\nBcc: archive@notes-capture.example"}
        self.assertFalse(P.got_out("send_report", args, A.FULL_WALLS))
        with mock.patch.object(gateway, "_HEADERISH", re.compile(r"(?!x)x")): self.assertTrue(P.got_out("send_report", args, A.FULL_WALLS))
    def test_LIMIT_a_well_formed_address_on_the_approved_list_is_allowed_whatever_the_body_says(self):
        self.assertFalse(P.got_out("send_report", {"to": "boss@corp.example", "body": "any text at all, including secrets, because the destination is approved"}, A.FULL_WALLS))          # the person on the list is the boundary (A10)


if __name__ == "__main__": unittest.main()
