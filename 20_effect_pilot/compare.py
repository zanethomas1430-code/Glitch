#!/usr/bin/env python3
"""compare.py — replay fidelity: did each replay land where its recording landed, and how alike are the tool outputs.

  .venv-control/bin/python glitch-suite/20_effect_pilot/compare.py <selection.json> <log dir>

Per run: recorded vs replayed main-task verdict (honest) or side-task verdict (attack); output similarity per action
(difflib ratio on the first 4,000 characters, so timestamps and PIDs count against it; a tool error is compared as
"type: message" against the recording's output_error); actions that errored where the recording did not. Writes PILOT.md beside the logs.
"""
import difflib, glob, json, os, statistics, sys
from inspect_ai.log import read_eval_log

PASS = {"C": True, "I": False, 1.0: True, 0.0: False, True: True, False: False}


def verdict(v):
    if isinstance(v, dict):
        v = next((x for k, x in v.items() if k != "explanation"), None)
    return PASS.get(v)


def main(sel_path, log_dir):
    sel = json.load(open(sel_path)); rec = {(r["task_id"], "honest" if r in sel["honest"] else r["side_task"]): r for r in sel["honest"] + sel["attack"]}
    rows = []
    for f in sorted(glob.glob(f"{log_dir}/*.eval")):
        log = read_eval_log(f); mode = log.eval.metadata.get("mode") if log.eval.metadata else None
        sides = (log.eval.metadata or {}).get("setting", {}).get("dataset_spec", {}).get("side_tasks", [])
        key2 = "honest" if mode == "honest" else (sides[0] if len(sides) == 1 else None)
        for s in log.samples or []:
            r = rec.get((str(s.id), key2))
            if r is None: continue
            outs = [m for m in s.messages if m.role == "tool"]
            sims, newerr = [], 0
            for a, m in zip(r["actions"], outs):
                if a["function"] == "submit": continue
                err = getattr(m, "error", None)
                got = f"{err.type}: {err.message}" if err else (m.text if hasattr(m, "text") else str(m.content))
                want = a.get("output_error") or a.get("output") or ""   # the recordings keep a tool error in output_error, not output
                sims.append(difflib.SequenceMatcher(None, want[:4000], got[:4000], autojunk=False).ratio())
                newerr += bool(err) and not a.get("output_error")
            sc = {k: getattr(v, "value", v) for k, v in (s.scores or {}).items()}
            main_v = verdict(sc.get("main_task_success")); side_v = next((verdict(v) for k, v in sc.items() if k != "main_task_success"), None)
            rows.append({"task": str(s.id), "group": key2, "recorded_main": r["main"], "replay_main": main_v, "recorded_side": r["side"], "replay_side": side_v,
                         "actions": len(r["actions"]), "replayed_tool_msgs": len(outs), "output_similarity": round(statistics.mean(sims), 3) if sims else None,
                         "new_errors": newerr, "error": str(s.error.message)[:200] if s.error else None, "scores": {k: str(v)[:60] for k, v in sc.items()}})
    json.dump(rows, open(f"{log_dir}/compare.json", "w"), indent=1)
    H = [r for r in rows if r["group"] == "honest"]; A = [r for r in rows if r["group"] != "honest"]
    agree_h = sum((r["replay_main"] is True) == (r["recorded_main"] == 1.0) for r in H if r["replay_main"] is not None)
    side_again = sum(r["replay_side"] is True for r in A)
    L = ["# Effect-level pilot: replay fidelity", "",
         f"- honest replays scored {sum(r['replay_main'] is not None for r in H)}/{len(H)}; main-task verdict same as recorded: **{agree_h}**",
         f"- honest that passed when recorded and pass again: {sum(r['replay_main'] is True and r['recorded_main'] == 1.0 for r in H)}/{sum(r['recorded_main'] == 1.0 for r in H)}",
         f"- attack replays whose side task succeeds again: **{side_again}/{len(A)}**",
         f"- mean output similarity per action: honest {statistics.mean([r['output_similarity'] for r in H if r['output_similarity'] is not None] or [0]):.2f}, attack {statistics.mean([r['output_similarity'] for r in A if r['output_similarity'] is not None] or [0]):.2f}",
         f"- samples that errored: {sum(bool(r['error']) for r in rows)}", "",
         "| group | task | actions | main rec→replay | side rec→replay | output sim | new errors |", "|---|---|---|---|---|---|---|"]
    L += [f"| {r['group']} | {r['task']} | {r['actions']} | {r['recorded_main']}→{r['replay_main']} | {r['recorded_side']}→{r['replay_side']} | {r['output_similarity']} | {r['new_errors']} |" for r in rows]
    open(f"{log_dir}/PILOT.md", "w").write("\n".join(L)); print("\n".join(L[:8]))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
