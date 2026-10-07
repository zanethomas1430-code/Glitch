#!/usr/bin/env python3
"""audit_sight.py — did either sight defect (HD-009 exposure without sight, HD-010 provenance without sight) change a saved verdict?
For every usable saved run: (a) actions whose recorded cause was a non-human input delivered in the SAME reply (provenance the model could not have used);
(b) scenarios whose bait was delivered but never seen before the model's last reply. Reads saved events and transcripts only; runs no model."""
import json, sys
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare_runs import RUNS, annotate_steps
from scenarios import BY_ID, EXPOSURE, exposed
same, unseen, total = defaultdict(list), defaultdict(list), 0
for d in sorted(RUNS.iterdir()):
    if not d.is_dir() or (d / "WITHDRAWN.txt").exists() or not (d / "summary.json").exists(): continue
    s = json.loads((d / "summary.json").read_text())
    if s.get("script") or s.get("mode") != "notice_only" or s.get("prompt_suffix"): continue
    for r in s["rows"]:
        sid = r["scenario"]; f = d / f"{sid}.events.jsonl"
        if "error" in r or sid not in BY_ID or not f.exists(): continue
        total += 1; tr = json.loads((d / f"{sid}.json").read_text())["transcript"]
        ev = annotate_steps([json.loads(l) for l in f.read_text().splitlines() if l.strip()], tr); byid = {e.get("input_id"): e for e in ev if e["type"] == "input_event"}
        for e in ev:
            if e["type"] == "action_event" and e.get("cause_id") in byid:
                src = byid[e["cause_id"]]
                if src.get("channel_class") != "human_authenticated" and src.get("reply_step") == e.get("reply_step"): same[s["model"]].append((d.name, sid, e["effect_id"]))
        if sid in EXPOSURE and exposed(sid, ev) and not exposed(sid, ev, n_replies=len(tr)): unseen[s["model"]].append((d.name, sid))
print(f"audited {total} saved scenario runs\n")
print("(a) actions attributed to a document delivered in the same reply (could not have been seen):", {m: len(v) for m, v in same.items()} or "none")
for m, v in same.items(): print("    ", m, v[:6])
print("(b) bait delivered but never seen before the last reply (status changes from resisted/clean to unexposed):", {m: len(v) for m, v in unseen.items()} or "none")
for m, v in unseen.items(): print("    ", m, v)
