#!/usr/bin/env python3
"""batch.py — many runs of the SDK-bridge scenarios, to turn "it resisted once" into a rate with an interval.

  .venv-inspect/bin/python 15_agent_sdk/batch.py --models claude-sonnet-5-5 --reps 10 --no-walls                  # dry: prints the plan and an estimate, calls nothing
  .venv-inspect/bin/python 15_agent_sdk/batch.py --models claude-haiku-4-5,claude-sonnet-5-5 --reps 10 --no-walls --go --total-budget 4

Each cell is (model, walls on or off, scenario). Every run is a fresh gateway and a fresh agent. Runs go a few at a time (--parallel). Results are appended to batches/<label>/runs.jsonl as they finish, so
an interrupted batch loses nothing, and summary.md is rebuilt from that file. The rate for a cell is took_the_bait / (took_the_bait + resisted): a run that never saw the bait ('unexposed'), never replied or was
refused by the endpoint cannot have resisted it and is counted separately (HARDENING H9d). The interval is Wilson 95%. A cell of ten is a probe: read the interval, not the point.
Stops early if the running cost passes --total-budget, and aborts at once on "Not logged in". Your login is the CLI's; this file never reads a key.
"""
import argparse, asyncio, json, math, sys, time
from collections import Counter, defaultdict
from pathlib import Path
_HERE = Path(__file__).resolve().parent; sys.path.insert(0, str(_HERE))
import live as LV
from scenarios import BY_ID

BAIT = [s for s in BY_ID if BY_ID[s].get("watch")]
DEFAULT_PER_RUN = {"claude-haiku-4-5": 0.009, "claude-sonnet-5-5": 0.008, "claude-opus-5-5": 0.025}


def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 1.0)
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)); return (max(0.0, (c - h) / d), min(1.0, (c + h) / d))


def cell_row(rows):
    c = Counter(r["status"] for r in rows); took, res = c["took_the_bait"], c["resisted"]; lo, hi = wilson(took, took + res)
    return {"n": len(rows), "took_the_bait": took, "resisted": res, "other": {k: v for k, v in c.items() if k not in ("took_the_bait", "resisted", "clean")}, "clean": c["clean"], "rate": (took / (took + res)) if took + res else None, "ci": (lo, hi), "cost": sum(r.get("cost") or 0 for r in rows)}


def summary(rows):
    cells = defaultdict(list); gone = [r for r in rows if r.get("withdrawn")]; rows = [r for r in rows if not r.get("withdrawn")]          # a withdrawn run stays in the file and out of every number
    for r in rows: cells[(r["model"], r["walls"], r["scenario"])].append(r)
    L = ["# Batch summary", "", "Rate = took the bait / (took + resisted), Wilson 95% interval. Runs that never saw the bait, never replied, were refused by the endpoint or errored are listed as `other` and are not in the rate. A cell of ten is a probe.", ""]
    for (model, walls), grp in sorted({(k[0], k[1]): 1 for k in cells}.items()):
        L += [f"## {model}, walls {'on' if walls else 'off'}", "", "| scenario | n | took the bait | resisted | clean | other | rate | 95% interval | cost |", "|---|---|---|---|---|---|---|---|---|"]
        for sid in BY_ID:
            rs = cells.get((model, walls, sid))
            if not rs: continue
            r = cell_row(rs); rate = "-" if r["rate"] is None else f"{r['rate']:.0%}"; ci = "-" if r["rate"] is None else f"{r['ci'][0]:.0%} to {r['ci'][1]:.0%}"
            L.append(f"| {sid} | {r['n']} | {r['took_the_bait']} | {r['resisted']} | {r['clean']} | {r['other'] or ''} | {rate} | {ci} | ${r['cost']:.3f} |")
        L.append("")
    if gone: L.append(f"Withdrawn in place and not counted: {len(gone)} runs ({', '.join(sorted({r['withdrawn'] for r in gone}))}); see WITHDRAWN.txt.\n")
    L.append(f"Total cost reported by the CLI: ${sum(r.get('cost') or 0 for r in rows):.2f} over {len(rows)} runs.")
    return "\n".join(L) + "\n"


async def one(sem, spec, out_f, state, args):
    model, walls, sid, rep = spec
    async with sem:
        if state["abort"] or state["cost"] >= args.total_budget: state["skipped"] += 1; return
        t0 = time.time(); row = {"model": model, "walls": walls, "scenario": sid, "rep": rep}
        try:
            out = await asyncio.wait_for(LV.run(sid, walls=None if walls else {}, model=model, max_turns=args.max_turns, budget_usd=args.per_run_budget), args.timeout)
            row.update(status=out["status"], findings=out["findings"], cost=out["sdk"].get("cost_usd"), turns=out["sdk"].get("turns"), models_used=out["sdk"].get("models_used"), calls=[c["tool"] for c in out["tool_calls"]], seconds=round(time.time() - t0, 1))
        except Exception as e:
            msg = str(e); row.update(status="error", findings=[], cost=0.0, error=msg[:200], seconds=round(time.time() - t0, 1))
            if "Not logged in" in msg: state["abort"] = True
            if "limit" in msg.lower() and "reached" in msg.lower(): state["abort"] = True               # a usage limit on this account: stop spending time against it
        state["cost"] += row.get("cost") or 0; state["done"] += 1
        out_f.write(json.dumps(row) + "\n"); out_f.flush()
        if state["done"] % 10 == 0: print(f"  {state['done']}/{state['total']} done, ${state['cost']:.2f}", flush=True)


async def main_async(args):
    models = [m.strip() for m in args.models.split(",") if m.strip()]; scen = [s for s in args.scenarios.split(",")] if args.scenarios else (BAIT + ["control"])
    walls_set = [False] if args.no_walls else ([True] if args.walls_only else [False, True])
    plan = [(m, w, s, r) for m in models for w in walls_set for s in scen for r in range(args.reps)]
    est = sum(DEFAULT_PER_RUN.get(m, 0.012) for m, *_ in plan)
    print(f"plan: {len(plan)} runs = models {models} x walls {['on' if w else 'off' for w in walls_set]} x {len(scen)} scenarios x {args.reps}; about ${est:.2f} at the single-run costs seen; cap ${args.total_budget:.2f}; {args.parallel} at a time")
    if not args.go: print("dry run: nothing was called. Add --go to run."); return 0
    d = _HERE / "batches" / args.label; d.mkdir(parents=True, exist_ok=True); f = d / "runs.jsonl"; state = {"abort": False, "cost": 0.0, "done": 0, "skipped": 0, "total": len(plan)}
    sem = asyncio.Semaphore(args.parallel)
    with open(f, "a") as out_f: await asyncio.gather(*[one(sem, spec, out_f, state, args) for spec in plan])
    rows = [json.loads(l) for l in f.read_text().splitlines() if l.strip()]; (d / "summary.md").write_text(summary(rows))
    print(f"done: {state['done']} runs, ${state['cost']:.2f}, {state['skipped']} skipped{' (aborted)' if state['abort'] else ''}; {d / 'summary.md'}"); return 1 if state["abort"] else 0


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--models", default="claude-sonnet-5-5"); ap.add_argument("--scenarios", default=""); ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--no-walls", action="store_true"); ap.add_argument("--walls-only", action="store_true"); ap.add_argument("--go", action="store_true"); ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--total-budget", type=float, default=4.0); ap.add_argument("--per-run-budget", type=float, default=0.5); ap.add_argument("--max-turns", type=int, default=12); ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--label", default=time.strftime("%Y%m%d-%H%M%S"))
    return asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__": sys.exit(main())
