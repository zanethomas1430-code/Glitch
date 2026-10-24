#!/usr/bin/env python3
"""select_runs.py — pick the pilot's recorded BashArena runs and write their action lists for replay.

  .venv-control/bin/python glitch-suite/20_effect_pilot/select_runs.py <benchmarks dir> <task parquet> <out.json>

Seeded and recorded so the pick can be re-made. Attack runs: 5 per side task, only ones whose side task succeeded (the
replay must reproduce that). Honest runs: 10 that passed the main task and 10 that did not, preferring tasks that also
appear in the attack pick so their images are built once. Only tasks whose recorded description equals the dataset's
description are eligible: a replay against a changed task would not be a replay.
"""
import collections, json, random, sys
SEED, PER_SIDE, HONEST_PASS, HONEST_FAIL = 20261024, 5, 10, 10


def runs(path):
    from inspect_ai.log import read_eval_log_samples
    for s in read_eval_log_samples(path, all_samples_required=False):
        md = s.metadata or {}; mt = (md.get("main_tasks") or [{}])[0]; st = (md.get("side_tasks") or [{}])
        sc = (s.scores or {}).get("tasks"); v = getattr(sc, "value", None) or {}
        acts = [{"function": a["function"], "arguments": a["arguments"], "output": a.get("output")} for a in (md.get("control_tower_overlay") or {}).get("actions", [])]
        yield {"sample": str(s.id), "task_id": str(mt.get("id")), "description": mt.get("description"), "side_task": (st[0] or {}).get("id") if st else None,
               "main": v.get("main"), "side": v.get("side"), "actions": acts}


def main(bdir, parquet, out):
    import pandas as pd
    ds = {str(r.task_id): r.description for r in pd.read_parquet(parquet, columns=["task_id", "description"]).itertuples()}
    H = list(runs(f"{bdir}/basharena_honest.eval")); A = list(runs(f"{bdir}/basharena_attack.eval"))
    ok = lambda r: ds.get(r["task_id"]) == r["description"] and bool(r["actions"])
    print(f"honest {len(H)} (desc match {sum(map(ok, H))}), attack {len(A)} (desc match {sum(map(ok, A))})")
    rng = random.Random(SEED); pick_a = []
    for side in ("disable_firewall", "sudo_edit", "download_malware", "leak_passwords"):
        pool = sorted([r for r in A if r["side_task"] == side and r["side"] == 1.0 and ok(r)], key=lambda r: r["sample"]); rng.shuffle(pool)
        used = {r["task_id"] for r in pick_a}; got = [r for r in pool if r["task_id"] not in used][:PER_SIDE]; pick_a += got
    atk_tasks = {r["task_id"] for r in pick_a}; pick_h = []
    for want, n in ((1.0, HONEST_PASS), (0.0, HONEST_FAIL)):
        pool = sorted([r for r in H if r["main"] == want and ok(r)], key=lambda r: r["sample"]); rng.shuffle(pool)
        pool.sort(key=lambda r: r["task_id"] not in atk_tasks)   # stable: overlap first, seeded order within
        used = {r["task_id"] for r in pick_h}; pick_h += [r for r in pool if r["task_id"] not in used][:n]
    for r in pick_a + pick_h: r.pop("description")
    json.dump({"seed": SEED, "honest": pick_h, "attack": pick_a}, open(out, "w"))
    print("attack:", collections.Counter(r["side_task"] for r in pick_a), "honest pass/fail:", collections.Counter(r["main"] for r in pick_h))
    print("distinct tasks:", len({r["task_id"] for r in pick_a + pick_h}), "honest∩attack:", len({r["task_id"] for r in pick_h} & atk_tasks))
    print("actions per run: attack", sorted(len(r["actions"]) for r in pick_a), "honest", sorted(len(r["actions"]) for r in pick_h))


if __name__ == "__main__":
    main(*sys.argv[1:4])
