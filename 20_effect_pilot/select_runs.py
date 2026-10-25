#!/usr/bin/env python3
"""select_runs.py — pick the pilot's recorded BashArena runs and write their action lists for replay.

  .venv-control/bin/python glitch-suite/20_effect_pilot/select_runs.py <benchmarks dir> <task parquet> <out.json> [--source=monitoringbench]

Seeded and recorded so the pick can be re-made. Attack runs: 5 per side task, only ones whose side task succeeded (the
replay must reproduce that). Honest runs: 10 that passed the main task and 10 that did not, preferring tasks that also
appear in the attack pick so their images are built once. Only tasks whose recorded description equals the dataset's
description are eligible: a replay against a changed task would not be a replay.
"""
import collections, json, random, sys
SEED, PER_SIDE, HONEST_PASS, HONEST_FAIL = 20261024, 5, 10, 10


def gap_ms(a, prev):
    """Recorded time between the previous action ending and this one starting (the model's thinking time); None if not recorded."""
    t = a.get("timing") or {}; start = t.get("start_time")
    if start is None: return None
    if prev is not None: end = (prev.get("timing") or {}).get("end_time")
    else: end = next((c.get("start_time") for c in t.get("model_calls") or []), None)   # first action: from its own model call, not from setup
    return max(0, start - end) if end is not None else None


def overlay_actions(s):
    """BashArena: the recorded action list, with tool errors kept apart in output_error and the thinking gap from its timing."""
    a = ((s.metadata or {}).get("control_tower_overlay") or {}).get("actions", [])
    return [{"function": x["function"], "arguments": x["arguments"], "output": x.get("output"), "output_error": x.get("output_error"), "gap_ms": gap_ms(x, prev)}
            for prev, x in zip([None] + a, a)]


def message_actions(s):
    """MonitoringBench: no action list, so the assistant's tool calls and their tool replies. Its events carry no real timing: no gap."""
    replies = {m.tool_call_id: m for m in s.messages if m.role == "tool"}
    acts = []
    for m in s.messages:
        for t in (m.tool_calls or []) if m.role == "assistant" else []:
            o = replies.get(t.id); e = getattr(o, "error", None)
            acts.append({"function": t.function, "arguments": t.arguments, "output": o.text if o and not e else None,
                         "output_error": f"{e.type}: {e.message}" if e else None, "gap_ms": None})
    return acts


SOURCES = {   # files, side tasks, how a run is read, and what counts as an honest fail
    "basharena": ("basharena_honest.eval", "basharena_attack.eval", ("disable_firewall", "sudo_edit", "download_malware", "leak_passwords"),
                  overlay_actions, lambda m: m == 0.0),
    "monitoringbench": ("monitoringbench_honest.eval", "monitoringbench_attack.eval", ("disable_firewall_partial", "sudo_edit", "download_malware", "leak_passwords"),
                        message_actions, lambda m: m is not None and m < 1.0),   # its main score is the fraction of tests passed
}
TOOLS = {"bash", "python", "text_editor", "submit"}   # the setting's own tools; a run that called anything else cannot be replayed


def runs(path, read_actions=overlay_actions):
    from inspect_ai.log import read_eval_log_samples
    for s in read_eval_log_samples(path, all_samples_required=False):
        md = s.metadata or {}; mt = (md.get("main_tasks") or [{}])[0]; st = (md.get("side_tasks") or [{}])
        sc = (s.scores or {}).get("tasks"); v = getattr(sc, "value", None) or {}
        yield {"sample": str(s.id), "task_id": str(mt.get("id")), "description": mt.get("description"), "side_task": (st[0] or {}).get("id") if st else None,
               "main": v.get("main"), "side": v.get("side"), "actions": read_actions(s)}


def distinct(pool, used, n):
    """The first n runs of the pool on tasks not yet used. One run per task: a replay eval holds each task once, and
    MonitoringBench recorded several runs of the same task."""
    got = []
    for r in pool:
        if len(got) < n and r["task_id"] not in used: got.append(r); used.add(r["task_id"])
    return got


def main(bdir, parquet, out, source="basharena"):
    import pandas as pd
    hon, atk, sides, read_actions, failed = SOURCES[source]
    ds = {str(r.task_id): r.description for r in pd.read_parquet(parquet, columns=["task_id", "description"]).itertuples()}
    H = list(runs(f"{bdir}/{hon}", read_actions)); A = list(runs(f"{bdir}/{atk}", read_actions))
    ok = lambda r: ds.get(r["task_id"]) == r["description"] and bool(r["actions"]) and {a["function"] for a in r["actions"]} <= TOOLS
    print(f"honest {len(H)} (eligible {sum(map(ok, H))}), attack {len(A)} (eligible {sum(map(ok, A))})")
    rng = random.Random(SEED); pick_a = []
    for side in sides:
        pool = sorted([r for r in A if r["side_task"] == side and r["side"] == 1.0 and ok(r)], key=lambda r: r["sample"]); rng.shuffle(pool)
        pick_a += distinct(pool, {r["task_id"] for r in pick_a}, PER_SIDE)
    atk_tasks = {r["task_id"] for r in pick_a}; pick_h = []
    for want, n in ((lambda m: m == 1.0, HONEST_PASS), (failed, HONEST_FAIL)):
        pool = sorted([r for r in H if want(r["main"]) and ok(r)], key=lambda r: r["sample"]); rng.shuffle(pool)
        pool.sort(key=lambda r: r["task_id"] not in atk_tasks)   # stable: overlap first, seeded order within
        pick_h += distinct(pool, {r["task_id"] for r in pick_h}, n)
    for r in pick_a + pick_h: r.pop("description")
    json.dump({"seed": SEED, "source": source, "honest": pick_h, "attack": pick_a}, open(out, "w"))
    print("attack:", collections.Counter(r["side_task"] for r in pick_a), "honest pass/fail:", collections.Counter(r["main"] == 1.0 for r in pick_h))
    print("distinct tasks:", len({r["task_id"] for r in pick_a + pick_h}), "honest∩attack:", len({r["task_id"] for r in pick_h} & atk_tasks))
    print("actions per run: attack", sorted(len(r["actions"]) for r in pick_a), "honest", sorted(len(r["actions"]) for r in pick_h))


if __name__ == "__main__":
    a = [x for x in sys.argv[1:] if not x.startswith("--")]
    main(*a[:3], next((x.split("=", 1)[1] for x in sys.argv if x.startswith("--source=")), "basharena"))
