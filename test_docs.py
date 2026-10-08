"""The front-door docs cannot lag the code. Three kinds of check:
  - STATUS.md is exactly what make_status.py generates from the suite's own results;
  - a list of claims that used to be true and are not (and any quoted step or test count) must not reappear in the front-door docs;
  - every folder is covered by the docs and every path the front-door docs name in backticks exists.
Each has a mutant: a doc with a stale claim, a missing path or an out-of-date status page must fail it."""
import os as _os, sys as _sys, re, unittest, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent
_sys.path.insert(0, str(ROOT))
import make_status

FRONT = ["README.md", "RUN.md", "STATUS.md", "BRIEF.md", "00_docs/RED_TEAM.md", "00_docs/RED_TEAM_LESSONS.md", "00_docs/OPEN_ITEMS.md", "00_docs/FICTION.md", "00_docs/ROADMAP_TO_CREDIBLE.md", "00_docs/README.md", "00_docs/WHAT_THIS_IS.md", "00_docs/FOR_ANOTHER_AI.md", "00_docs/INGEST.md"]
STALE = [r"never been validated against humans", r"has \*\*never been validated", r"Steps 1–3 have never been done", r"two human sheets so far", r"does not defend against prompt injection",
         r"\b(?:Fifteen|Sixteen|Seventeen|Eighteen|Nineteen|Twenty)\b[^.\n]{0,20}runner steps", r"\b\d+ runner steps", r"About \d+ tests", r"\bTHE runner: \d+ steps", r"has never validated its 0–5"]
PATH = re.compile(r"`((?:0\d|1\d)_[a-z_]+/[A-Za-z0-9_./-]*[A-Za-z0-9_])`")


def stale_hits(text): return [p for p in STALE if re.search(p, text)]
def missing_paths(text, root=ROOT): return sorted({m for m in PATH.findall(text) if not (root / m).exists() and "*" not in m and "<" not in m})


class Status(unittest.TestCase):
    def test_status_md_is_exactly_what_the_generator_writes(self):
        self.assertEqual((ROOT / "STATUS.md").read_text(), make_status.build(), "STATUS.md is out of date: run python3 make_status.py")
    def test_brief_md_is_exactly_what_the_generator_writes(self):
        self.assertEqual((ROOT / "BRIEF.md").read_text(), make_status.build_brief(), "BRIEF.md is out of date: run python3 make_status.py")
    def test_the_brief_is_two_pages_names_nobody_and_carries_no_private_path(self):
        t = (ROOT / "BRIEF.md").read_text(); self.assertLess(len(t.split()), 1100); self.assertNotIn("/Users/", t)
        for name in ("Zane", "Jasmine", "Metro", "Sarah", "sarah"): self.assertNotIn(name, t)
    def test_the_red_team_guide_tells_a_stranger_how_to_start_what_counts_and_what_does_not(self):
        t = (ROOT / "00_docs" / "RED_TEAM.md").read_text()
        for needle in ("python3 12_arena/play.py", "--defender bare", "LANDED", "What is not a finding", "Where I would look first", "Reporting", "nothing leaves your machine"): self.assertIn(needle, t)
    def test_every_command_line_in_the_red_team_guide_runs_against_a_real_file(self):
        import re
        t = (ROOT / "00_docs" / "RED_TEAM.md").read_text()
        for f in re.findall(r"python3 (12_arena/[a-z_]+\.py)", t): self.assertTrue((ROOT / f).exists(), f)
    def test_the_brief_states_what_it_does_not_show(self):
        t = (ROOT / "BRIEF.md").read_text(); self.assertIn("## What it does not show", t); self.assertIn("That escape is impossible", t)
    def test_mutant_a_status_page_that_lags_the_results_is_detected(self):
        self.assertNotEqual((ROOT / "STATUS.md").read_text().replace("0 OPEN", "7 OPEN"), make_status.build())
    def test_the_status_page_says_what_is_not_shown_and_does_not_claim_impossibility(self):
        t = (ROOT / "STATUS.md").read_text(); self.assertIn("## What is not shown", t); self.assertIn("is not claimed and cannot be proved", t); self.assertIn("A flag is not a block", t)
    def test_the_status_page_does_not_carry_a_private_path(self):
        self.assertNotIn("/Users/", (ROOT / "STATUS.md").read_text())


class Stale(unittest.TestCase):
    def test_no_front_door_doc_carries_a_claim_that_stopped_being_true(self):
        for f in FRONT:
            with self.subTest(f): self.assertEqual(stale_hits((ROOT / f).read_text()), [], f)
    def test_mutant_each_stale_claim_would_be_caught_if_it_came_back(self):
        for sample in ("Steps 1–3 have never been done, and the kit says so.", "It does not defend against prompt injection in fetched content.", "Fifteen runner steps.", "THE runner: 32 steps, PASS/FAIL", "about 230 tests: About 230 tests"):
            with self.subTest(sample): self.assertTrue(stale_hits(sample), sample)
    def test_the_old_claim_is_replaced_not_just_deleted_so_the_new_one_is_present(self):
        t = (ROOT / "README.md").read_text(); self.assertIn("evidence the ruler is usable, not a validation", t); self.assertIn("It does not prevent prompt injection", t)


class Coverage(unittest.TestCase):
    def test_the_two_run_docs_are_the_same_text(self): self.assertEqual((ROOT / "RUN.md").read_text(), (ROOT / "00_docs" / "README.md").read_text())
    def test_every_folder_is_named_in_the_run_doc_or_the_readme(self):
        text = (ROOT / "RUN.md").read_text() + (ROOT / "README.md").read_text() + (ROOT / "00_docs" / "README.md").read_text()
        for d in sorted(p.name for p in ROOT.iterdir() if p.is_dir() and re.match(r"\d\d_", p.name)):
            with self.subTest(d): self.assertIn(d, text, f"{d} is not mentioned in the front-door docs")
    def test_every_path_the_front_door_docs_name_in_backticks_exists(self):
        for f in FRONT:
            with self.subTest(f): self.assertEqual(missing_paths((ROOT / f).read_text()), [], f)
    def test_the_arena_summary_line_matches_the_board_it_summarises(self):
        import arena, fighters, move_tree
        text = (ROOT / "00_docs" / "ARENA.md").read_text(); covered = {b["chain"] for b in fighters.BOUTS.values()}; n = len(move_tree.CHAINS)
        want = f"{len(fighters.BOUTS)} executable bouts cover " + (f"all {n}" if len(covered) == n else f"{len(covered)} of the {n}") + " chains."
        self.assertIn(want, text, "00_docs/ARENA.md quotes a bout count the board no longer has")
    def test_the_arena_summary_numbers_are_the_boards(self):
        import arena, re
        b = arena.board().splitlines(); text = (ROOT / "00_docs" / "ARENA.md").read_text()
        c, mv, ct, t, i, r = re.match(r"ARENA: (\d+) chains, (\d+) adversary moves, (\d+) counters \((\d+) tested, (\d+) implemented, (\d+) roadmap\)", b[0]).groups()
        ref, tot, det = re.match(r"\s+(\d+) of (\d+) counters REFUSE the call at the gateway; the other (\d+) detect", b[1]).groups()
        fl, rs, op = re.match(r"\s+chains end: (\d+) FLOOR .*?, (\d+) RESIDUAL .*?, (\d+) OPEN", b[2]).groups()
        for want in (f"{c} chains, {mv} adversary moves, {ct} counters ({t} tested, {i} implemented, {r} roadmap)", f"**{fl} FLOOR, {rs} RESIDUAL, {op} OPEN.**", f"**{ref} of the {tot} counters refuse the call at the gateway; the other {det} detect it afterwards"):
            self.assertIn(want, text, "00_docs/ARENA.md quotes a number the board no longer has")
    def test_every_chain_and_bout_the_fiction_page_names_exists_on_the_board(self):
        import fighters, move_tree
        text = (ROOT / "00_docs" / "FICTION.md").read_text()
        for c in set(re.findall(r"\bXA-\d\d\b", text)): self.assertIn(c, {x["id"] for x in move_tree.CHAINS}, c)
        for b in set(re.findall(r"\bB\d\d\b", text)): self.assertIn(b, fighters.BOUTS, b)
        self.assertNotIn("/Users/", text)
    def test_mutant_a_path_that_does_not_exist_is_found(self): self.assertEqual(missing_paths("see `12_arena/nope_not_here.py` and `12_arena/arena.py`"), ["12_arena/nope_not_here.py"])
    def test_no_step_title_in_the_runner_quotes_a_count_that_the_code_has_outgrown(self):
        import re
        titles = re.findall(r'Step\("[0-9a-z]+", (?:f?"([^"]*)")', (ROOT / "glitch_suite.py").read_text())
        for t in titles: self.assertFalse(re.search(r"\b(?:eight|six|seven|nine|ten) (?:invariants|planted)|\bthe six planted", t), t)
    def test_the_suite_runner_registers_every_test_file_in_the_layers_it_runs(self):
        reg = (ROOT / "glitch_suite.py").read_text()
        for d in ("08_incident", "11_testbed", "12_arena"):
            for f in sorted((ROOT / d).glob("test_*.py")):
                with self.subTest(f"{d}/{f.name}"): self.assertIn(f.name, reg, f"{d}/{f.name} is not run by glitch_suite.py")


if __name__ == "__main__": unittest.main()
