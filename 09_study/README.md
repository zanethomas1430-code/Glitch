# The fifty-response study

> **For people taking the test:** the labeler-facing copy (plain-language instructions, phone page, print page) lives at
> `~/Desktop/50 QUESTION TEST/`. Send them there. Answer key, returned sheets and `kappa.py` stay here.

The one experiment nothing else in this folder can substitute for. Every tripwire assumes a "level 3" means the
same thing to two people. This finds out.

## The easy way: `rate.html`
Open it on a phone or laptop. Type a first name, tap Start, read each answer, tap a number. Progress saves on the device; at the end, tap **Save my answers** and send the file. That file is exactly what `kappa.py` reads. That's the whole job for a labeler; nothing below this line is for them.

## What's here (for whoever runs the study)
- `responses.jsonl` — 50 short responses about sourdough, bike chains, repotting plants, and spreadsheets.
  Benign on purpose: the scale is about **structure**, not subject, and a study needs no dangerous text.
  Roughly 8 per level, and the framings vary on purpose (assertion, correction, refutation, question,
  conditional, decomposed list, analogy), because framing invariance is the second thing being tested.
- `worksheet.html` — print it, or open it on a phone: rubric on page one, then the 50 responses each with a box. `worksheet.md` is the same thing as text. `worksheet.csv` has the response text in the row so you can fill column C in any spreadsheet and save as `labels_<name>.csv`; `kappa.py` reads that directly.
- `answer_key.DO_NOT_OPEN_UNTIL_LABELED.json` — the intended level and framing axis for each item. The name is
  the instruction. If a labeler sees it, that labeler's sheet is discarded.
- `kappa.py` — computes the agreement.
- `SCALE.md` — the one-page rubric labelers read. They get this and nothing else.

## How to run it alone, honestly
You cannot get inter-rater agreement from one rater. You can get three things alone that are worth having:

1. **Label the 50 today.** Print `worksheet.html` or open `worksheet.csv`. Read the rubric at the top, then each
   response, then write a level. Don't look at the key. Don't deliberate more than a minute per item; the
   scale has to be usable at speed or it's not usable.
2. **Label them again in two weeks** into `labels_zane_day14.csv`, without rereading your first sheet.
   `python3 kappa.py --self labels_zane_day1.csv labels_zane_day14.csv` gives your self-consistency. If you
   can't agree with yourself, the rubric is broken and fixing `SCALE.md` is the next step, not recruiting.
3. **Open the key only after both sittings.** `python3 kappa.py labels_zane_day1.csv labels_zane_day14.csv
   --key answer_key...json` shows where your reading diverges from the intended level, by framing axis. If
   "correct-a-wrong-version" items score consistently lower than assertions with the same content, you've
   just found the scorer's invariance problem in a human, which is the strongest possible reason to expect it
   in a model.

## How to run it properly
Two more labelers: Rater B, and one person who has never seen any of this. Each gets `SCALE.md`,
`responses.jsonl`, and a blank sheet. Nobody discusses items until all three sheets are done. Then:

    python3 kappa.py labels_zane.csv labels_rater_b.csv labels_outsider.csv --key answer_key...json

Read the weighted kappa first. Under 0.6, the scale is not ready and no number downstream of it means anything;
the five most contested items are where to start rewriting the rubric. Above 0.6, run the same 50 through
`glitch_scorer.py` and add its sheet as a fourth rater: that is "scorer vs human consensus," the second step
in the deployment order.

## What this is not
It is not a benchmark of the harness. It is a test of whether the ruler is a ruler. Fifty items, three people,
one afternoon each. Everything else waits on it, and it has been true for a week that nothing in the code moves it.

## Status (2026-09-26)
**Limitation.** Human reliability was measured on 50 items with 3 human raters (Zane, Rater B, and Rater C, who had never seen the project), one sitting each, on 2026-09-26/27. Pairwise weighted kappa 0.80–0.89, Fleiss kappa 0.56 (moderate); level 3 is the soft spot (mean spread 1.54 across raters). A day-14 re-sitting is scheduled for 2026-10-10. The study design is complete; n = 50 items is still a small sample and the numbers should be read as such. The two-rater numbers are still worth having: agreement, and where the disagreements sit (see `boundary_report.py`).
Scorer as rater four (2026-09-26, Sarah scorer instance): `labels_scorer.csv` (rubric v2) within one notch of the human median on
82% of items, `labels_scorer_checklist.csv` on 90%; the checklist is the pilot default. Run `python3 boundary_report.py labels_zane_day1.csv labels_rater_b.csv labels_scorer_checklist.csv` to see where they differ.

Three official sheets, all taken on the shared rating page: `labels_zane_day1.csv`, `labels_rater_b.csv` (2026-09-26) and `labels_rater_c.csv` (2026-09-27, a rater who had never seen the project). The sheets from
the September export were restarted attempts and are set aside in `superseded/` under names the tools do not pick up; nothing
compares against them. Results: pairwise weighted kappa 0.80–0.89 (Cohen 0.49–0.69), Fleiss 0.56; against the sealed key Zane 74%, Rater B 70%, Rater C 54% exact, all ≥ 90% within one. The suite runner's step 09b recomputes this over every `labels_*.csv` present into `kappa_latest.txt`
and asserts nothing. **Day 1 of the study is 2026-09-26.** Zane's day-14 sitting is due **2026-10-10**: rate the same 50 on the shared page
without rereading the first sheet, and the block becomes `labels_zane_day14.csv`; then `python3 kappa.py --self labels_zane_day1.csv labels_zane_day14.csv`.
Still open: the third labeler (someone who has never seen any of this) and that day-14 sheet. `labels_scorer.csv` is only produced by `score_responses.py`, and only after the human sheets are done.
