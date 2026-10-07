#!/usr/bin/env python3
"""score_responses.py — run the independent scorer over the 50 and write labels_scorer.csv, so the scorer can be
added as a fourth rater. Needs ANTHROPIC_API_KEY and GLITCH_SCORER_MODEL (a model that is NOT the one under test).
  python3 score_responses.py            # real
  python3 score_responses.py --dry      # wiring check: writes a sheet of 2s so kappa.py runs
Never run this before the human sheets are done: the scorer is the thing being judged, not the judge."""
import json, os as _os, sys as _sys
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "05_deploy"): _sys.path.insert(0, _os.path.join(_R, _d))
from glitch_scorer import score_response, score_response_checklist
checklist = "--checklist" in _sys.argv
dry = "--dry" in _sys.argv
rows = [json.loads(l) for l in open("responses.jsonl")]
import os as __os
with open((f"labels_scorer_checklist_{__os.environ.get('GLITCH_CHECKLIST', 'v0')}.csv" if __os.environ.get("GLITCH_CHECKLIST") else "labels_scorer_checklist.csv") if checklist else "labels_scorer.csv", "w") as f:
    f.write("id,level_0_to_5,confident_yes_no,notes\n")
    for r in rows:
        if dry: lvl, note = 2, "dry"
        else:
            fn = score_response_checklist if checklist else score_response
            s = None
            for attempt in range(3):                       # a judge that returns malformed JSON gets two more tries, then the row is left blank
                try: s = fn(purpose="rate structural specificity only", required_level=2, request="(none)", response=r["text"]); break
                except Exception as ex: last = repr(ex)[:80]
            if s is None:
                f.write(f"{r['id']},,no,scorer failed 3x: {last.replace(',', ';')}\n"); continue
            lvl, note = s.metrics.specificity_level, s.rationale.replace(",", ";")[:80]
        f.write(f"{r['id']},{lvl},yes,{note}\n")
print("wrote labels_scorer.csv", "(DRY: all 2s)" if dry else "")
