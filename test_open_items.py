"""The open-items page cannot lag or lie: it is exactly what open_items.py renders, every evidence path exists, every item has a status from the fixed list, an owner and a way to close it,
and the claims that used to be written as 'NOT DONE' are not repeated in a stronger form than the evidence supports."""
import re, unittest
from pathlib import Path
import open_items as O
ROOT = Path(__file__).resolve().parent


class Page(unittest.TestCase):
    def test_the_written_page_is_exactly_what_the_generator_renders(self): self.assertEqual(O.DOC.read_text(), O.render(), "00_docs/OPEN_ITEMS.md is out of date: run python3 open_items.py --write")
    def test_ids_are_unique_and_in_order(self): self.assertEqual([i["id"] for i in O.ITEMS], [f"OI-{n:02d}" for n in range(1, len(O.ITEMS) + 1)])
    def test_every_item_has_every_field_and_a_known_status(self):
        for i in O.ITEMS:
            for k in ("title", "status", "owner", "now", "evidence", "closes"): self.assertTrue(i[k], (i["id"], k))
            self.assertIn(i["status"], O.STATUSES, i["id"])
    def test_every_evidence_path_exists(self):
        for i in O.ITEMS:
            for e in i["evidence"]: self.assertTrue((ROOT / e).exists(), f"{i['id']}: {e}")
    def test_every_item_the_user_listed_is_present(self):
        text = O.render().lower()
        for needle in ("canonical hash", "capability uplift", "assumption table", "independent adversary", "aggregate harm", "threshold tuning", "identity", "abstract harm", "prompt injection", "reversibility"): self.assertIn(needle, text, needle)
    def test_prompt_injection_is_never_called_prevented_and_says_so(self):
        i = next(x for x in O.ITEMS if x["title"] == "Prompt injection"); self.assertEqual(i["status"], "DONE-AS-CONTAINMENT"); self.assertIn("Not prevented", i["now"])
    def test_an_item_that_needs_a_person_is_not_claimed_as_built(self):
        for i in O.ITEMS:
            if i["status"] in ("NEEDS-A-PERSON", "POLICY", "OPEN"): self.assertFalse(re.search(r"\bBuilt\b", i["now"]), i["id"])
    def test_the_page_carries_no_private_path_or_key(self):
        t = O.DOC.read_text(); self.assertNotIn("/Users/", t); self.assertNotIn("sk-ant-", t)
    def test_the_older_checkpoint_points_here(self): self.assertIn("OPEN_ITEMS.md", (ROOT / "00_docs" / "DISCOVERIES.short.md").read_text())
    def test_mutant_a_status_outside_the_list_or_a_missing_path_would_be_caught(self):
        self.assertNotIn("DONE", O.STATUSES); self.assertFalse((ROOT / "12_arena/not_a_file.py").exists())


if __name__ == "__main__": unittest.main()
