#!/usr/bin/env python3
"""Tier 0: score an existing transcript offline.

Usage:
  python3 score_transcript.py transcript.json [--dry]

transcript.json:
{
  "user_id": "anon-1",
  "declared_purpose": "patient safety sheet on dangerous interaction classes",
  "required_level": 2,
  "turns": [
    {"session_id": "A", "request": "...", "response": "..."},
    ...
  ]
}

--dry uses a stub scorer (no API call) so you can check the pipeline wiring.
Output: JSON report to stdout with per-turn metrics, tripwires, and rationale.
"""
import json
import sys

from glitch_runtime_harness import RuntimeHarness, TurnMetrics
from glitch_scorer import score_response


def stub_scorer(prompt: str) -> str:
    # Wiring check only. Real scoring requires a separate model.
    return json.dumps({"specificity_level": 1, "caveat_density": 0.3, "middle_third_density": 0.1,
                       "contains_refusal": False, "refused_level": None, "answered_level": None,
                       "rationale": "stub"})


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    dry = "--dry" in sys.argv
    tr = json.load(open(sys.argv[1]))
    harness = RuntimeHarness()
    uid = tr.get("user_id", "anon")
    harness.start_session(uid, tr["turns"][0].get("session_id", "S"),
                          declared_purpose=tr["declared_purpose"], required_level=int(tr["required_level"]))
    report = []
    for i, t in enumerate(tr["turns"], 1):
        sid = t.get("session_id", "S")
        harness.start_session(uid, sid)
        kwargs = {"call_model": stub_scorer} if dry else {}
        s = score_response(purpose=tr["declared_purpose"], required_level=int(tr["required_level"]),
                           request=t["request"], response=t["response"], **kwargs)
        e = harness.evaluate_turn(uid, sid, i, s.metrics)
        report.append({"t": i, "session": sid, "metrics": s.raw, "tripwires": e.tripwires,
                       "purpose_gap": e.purpose_gap, "spec_slope": round(e.specificity_slope, 3),
                       "checkpoint": e.checkpoint is not None, "rationale": s.rationale})
    print(json.dumps({"user_id": uid, "declared_purpose": tr["declared_purpose"],
                      "required_level": tr["required_level"], "turns": report}, indent=2))


if __name__ == "__main__":
    main()
