"""The red-team course cannot rot: every lesson is played through the real console and must give the verdict, strikes, phase and replies the course states; the written page is exactly what the generator renders."""
import os as _os, sys as _sys, re, unittest
from pathlib import Path
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lessons as LS, play as P


class Course(unittest.TestCase):
    def test_every_lesson_behaves_as_the_course_says(self):
        for L in LS.LESSONS:
            with self.subTest(lesson=L["id"]): self.assertEqual(LS.check(L, LS.play(L)), [])
    def test_lessons_are_numbered_in_order_and_each_has_a_why_and_a_next_move(self):
        self.assertEqual([L["id"] for L in LS.LESSONS], list(range(1, len(LS.LESSONS) + 1)))
        for L in LS.LESSONS:
            for k in ("title", "goal", "why", "todo", "lines", "expect"): self.assertTrue(L[k], (L["id"], k))
    def test_the_course_covers_each_kind_of_verdict_and_every_defender(self):
        outcomes = {L["expect"]["outcome"] for L in LS.LESSONS}; self.assertTrue({"PREVENTED", "CAUGHT", "LANDED", "HARMLESS"} <= outcomes)
        self.assertEqual({L["defender"] for L in LS.LESSONS}, {"bare", "walls", "boss"})
    def test_the_written_page_is_exactly_what_the_generator_renders(self):
        self.assertEqual(LS.DOC.read_text(), LS.render(), "00_docs/RED_TEAM_LESSONS.md is out of date: run python3 12_arena/lessons.py --write")
    def test_cross_references_between_lessons_point_at_lessons_that_exist(self):
        n = len(LS.LESSONS); text = LS.DOC.read_text()
        for m in re.findall(r"[Ll]essons? (\d+)", text): self.assertLessEqual(int(m), n, m)
        self.assertNotIn("6b", text)
    def test_the_page_carries_no_private_path_and_no_key(self):
        t = LS.DOC.read_text(); self.assertNotIn("/Users/", t); self.assertNotIn("sk-ant-", t)
    def test_mutant_a_wrong_expectation_is_reported(self):
        L = dict(LS.LESSONS[1]); L["expect"] = {**L["expect"], "outcome": "LANDED"}; self.assertTrue(LS.check(L, LS.play(L)))
        L = dict(LS.LESSONS[2]); L["expect"] = {**L["expect"], "phase": 2}; self.assertTrue(LS.check(L, LS.play(L)))
        L = dict(LS.LESSONS[0]); L["expect"] = {**L["expect"], "replies": {1: "no such text"}}; self.assertTrue(LS.check(L, LS.play(L)))


if __name__ == "__main__": unittest.main()
