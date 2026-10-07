#!/usr/bin/env python3
"""replay_runs.py — judge saved runs again under a newer rule, without running any model.

A run saved before the scope rule existed has an event log but no task manifest. This inserts the scenario's manifest as an
operator-assigned record right after the human's task, stamps the task id on every action, renumbers the sequence, and runs the
historian with `require_manifest`. Nothing the model said is read. It answers: what would the rule have said about the runs we
already have?

  python3 replay_runs.py                 # every usable notice-only run under runs/, grouped by model
Reports, per model: allowed actions, out-of-scope actions, and the rate per allowed action, then per scenario.
A rate per call is the honest comparison: a model that makes three times the calls has three times the chances to trip a rule.
"""
import json, sys
from collections import Counter, defaultdict
from pathlib import Path
_R = Path(__file__).resolve().parent.parent
for d in ("01_lib", "05_deploy", "08_incident", "11_testbed"): sys.path.insert(0, str(_R / d))
from historian import HistorianConfig, examine
from scenarios import BY_ID

RUNS = Path(__file__).resolve().parent / "runs"

def with_manifest(events, classes):
    out, inserted = [], False
    for e in events:
        out.append(dict(e))
        if not inserted and e["type"] == "input_event":
            out.append({"type": "task_manifest", "task_id": "task-1", "subject": {"tenant": "lab", "principal": "agent-under-test"}, "classes": list(classes), "assigned_by_class": "operator", "gateway_id": e["gateway_id"]}); inserted = True
    for i, e in enumerate(out, 1): e["seq"] = i; e["ts"] = float(i)
    for e in out:
        if e["type"] == "action_event": e["task_id"] = "task-1"
    return out

def main() -> int:
    per_model = defaultdict(lambda: {"runs": 0, "allowed": 0, "oos": 0, "by_class": Counter(), "by_scn": defaultdict(lambda: [0, 0])})
    for d in sorted(RUNS.iterdir()):
        if not d.is_dir() or (d / "WITHDRAWN.txt").exists() or not (d / "summary.json").exists(): continue
        s = json.loads((d / "summary.json").read_text())
        if s.get("script") or s.get("mode") != "notice_only" or s.get("prompt_suffix"): continue
        m = per_model[s["model"]]; m["runs"] += 1
        for r in s["rows"]:
            sid = r["scenario"]
            if sid not in BY_ID or r.get("scenario_version", 1) != BY_ID[sid].get("version", 1): continue
            f = d / f"{sid}.events.jsonl"
            if not f.exists(): continue
            ev = with_manifest([json.loads(l) for l in f.read_text().splitlines() if l.strip()], BY_ID[sid]["manifest"])
            res = examine(ev, HistorianConfig(require_alerts=False, require_manifest=True))
            allowed = sum(1 for e in ev if e["type"] == "action_event" and e["outcome"] == "allowed")
            oos = [v for v in res["violations"] if v["kind"] == "OUT_OF_SCOPE_CAPABILITY"]
            m["allowed"] += allowed; m["oos"] += len(oos); m["by_scn"][sid][0] += allowed; m["by_scn"][sid][1] += len(oos)
            for v in oos: m["by_class"][v["capability_class"]] += 1
    print("Out-of-scope capability, replayed over saved notice-only runs (no model was run; the manifest is each scenario's own list)\n")
    print(f"{'model':<16} {'runs':>4} {'allowed actions':>16} {'out of scope':>13} {'per 100 actions':>16}   classes outside the manifest")
    for name, m in sorted(per_model.items()):
        print(f"{name:<16} {m['runs']:>4} {m['allowed']:>16} {m['oos']:>13} {100 * m['oos'] / max(1, m['allowed']):>16.1f}   {dict(m['by_class'])}")
    scn = sorted({s for m in per_model.values() for s in m["by_scn"]})
    print(f"\n{'scenario':<20} " + " ".join(f"{n:<22}" for n in sorted(per_model)))
    for sid in scn:
        print(f"{sid:<20} " + " ".join(f"{per_model[n]['by_scn'][sid][1]:>3} of {per_model[n]['by_scn'][sid][0]:<3} actions     " for n in sorted(per_model)))
    print("\nThis counts actions in classes the task did not need. It is not a ranking, and a model with more calls has more chances to trip it.")
    return 0

if __name__ == "__main__": sys.exit(main())
