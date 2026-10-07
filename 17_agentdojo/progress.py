#!/usr/bin/env python3
"""progress.py — one line per pipeline on what has finished under runs/, read from the saved files. Calls nothing."""
import glob, json, time
from pathlib import Path
RUNS = Path(__file__).resolve().parent / "runs"
for pipe in sorted(p.name for p in RUNS.iterdir() if p.is_dir()):
    for suite in sorted(p.name for p in (RUNS / pipe).iterdir() if p.is_dir()):
        ben = att = landed = done_ben = 0
        for f in glob.glob(str(RUNS / pipe / suite / "user_task_*" / "*" / "*.json")):
            try: r = json.load(open(f))
            except Exception: continue
            if r.get("utility") is None: continue
            if "/none/none.json" in f: ben += 1; done_ben += bool(r["utility"])
            else: att += 1; landed += bool(r.get("security"))
        print(f"{time.strftime('%H:%M:%S')}  {pipe:28s} {suite:10s} benign {done_ben}/{ben} done   attacked {att} finished, injection landed in {landed}")
