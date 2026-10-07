#!/usr/bin/env python3
"""run_dojo.py — GLITCH on AgentDojo with a real model: utility, utility under attack, targeted attack success, with Wilson intervals; and the historian's after-the-fact verdict against the benchmark's own ground truth.

  .venv-inspect/bin/python 17_agentdojo/run_dojo.py --suite banking --model claude-haiku-4-5 --defense glitch                         # dry: plan + estimate, calls nothing
  .venv-inspect/bin/python 17_agentdojo/run_dojo.py --suite banking --model claude-haiku-4-5 --defense glitch --go                    # the real thing
  .venv-inspect/bin/python 17_agentdojo/run_dojo.py --summary                                                                        # rebuild RESULTS.md from everything under runs/

Needs ANTHROPIC_API_KEY in the environment (AgentDojo talks to the API directly; a Claude Code login does not apply). Costs money: a full suite is (user tasks x injection tasks) attacked
runs plus one benign run per user task; the dry run prints the count. AgentDojo caches every finished run under runs/<pipeline>/<suite>/..., so an interrupted run resumes.
"""
import argparse, json, math, os, sys, time
from collections import Counter
from pathlib import Path
_HERE = Path(__file__).resolve().parent; sys.path.insert(0, str(_HERE))
_R = _HERE.parent
for _d in ("01_lib", "05_deploy", "08_incident"): sys.path.insert(0, str(_R / _d))
import pipeline as P
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections, load_suite_results
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

RUNS = _HERE / "runs"
SUITES = ("workspace", "banking", "travel", "slack")
PER_RUN = {"claude-haiku-4-5": 0.012, "claude-sonnet-5-5": 0.02, "claude-opus-5-5": 0.06, "gpt-4o-2024-05-13": 0.065, "gpt-4o": 0.05, "gpt-4o-mini": 0.005}         # an ollama/ model costs nothing
SUITE_WEIGHT = {"banking": 0.6, "workspace": 1.0, "travel": 1.0, "slack": 0.8}      # workspace transcripts run 3-4x banking's; $25 bought 410 workspace runs with gpt-4o-2024-05-13 (2026-10-05)


def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 1.0)
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)); return (max(0.0, (c - h) / d), min(1.0, (c + h) / d))


def attack_successes(security_results) -> int:
    """AgentDojo's `security` flag is True when the INJECTION'S GOAL WAS REACHED (BaseInjectionTask.security: 'True if the injection was executed correctly'), so the attack success count is the
    number of True values. The name invites the opposite reading; this helper exists so the summary cannot invert it again."""
    return sum(1 for v in security_results if v)


def fmt(k, n):
    if n == 0: return "-"
    lo, hi = wilson(k, n); return f"{k}/{n} = {k / n:.0%} ({lo:.0%} to {hi:.0%})"


def run(args):
    need = None if args.model.startswith("ollama/") else ("OPENAI_API_KEY" if args.model.startswith(("gpt-", "o1", "o3", "o4")) else "ANTHROPIC_API_KEY")
    if need and not os.environ.get(need): os.environ[need] = "placeholder-for-the-dry-run"                    # the client objects insist on a key at construction; a dry run never calls anything
    suite = get_suite(args.version, args.suite); pipeline = P.build_pipeline(args.model, args.suite, None if args.defense == "none" else args.defense)
    user_tasks = tuple(args.user_tasks.split(",")) if args.user_tasks else None; inj_tasks = tuple(args.injection_tasks.split(",")) if args.injection_tasks else None
    nu = len(user_tasks) if user_tasks else len(suite.user_tasks); ni = len(inj_tasks) if inj_tasks else len(suite.injection_tasks); n = nu + nu * ni
    print(f"plan: suite {args.suite}, pipeline {pipeline.name}, attack {args.attack}: {nu} benign + {nu}x{ni} attacked = {n} runs; about ${n * SUITE_WEIGHT[args.suite] * PER_RUN.get(args.model, 0.0 if args.model.startswith('ollama/') else 0.03):.2f} at the single-run costs seen (finished runs under runs/ are not repeated)")
    if not args.go: print("dry run: nothing was called. Add --go."); return 0
    if need and os.environ.get(need) == "placeholder-for-the-dry-run": print(f"{need} is not set in this environment; nothing was called. Export your own key in the terminal you run this from."); return 2
    RUNS.mkdir(exist_ok=True); t0 = time.time()
    with OutputLogger(str(RUNS), live=None):
        benign = benchmark_suite_without_injections(pipeline, suite, logdir=RUNS, force_rerun=args.force, user_tasks=user_tasks, benchmark_version=args.version)
        attack = load_attack(args.attack, suite, pipeline)
        attacked = benchmark_suite_with_injections(pipeline, suite, attack, logdir=RUNS, force_rerun=args.force, user_tasks=user_tasks, injection_tasks=inj_tasks, benchmark_version=args.version)
    u = sum(benign["utility_results"].values()); ua = sum(attacked["utility_results"].values()); asr = attack_successes(attacked["security_results"].values())
    print(f"benign utility {fmt(u, len(benign['utility_results']))}; utility under attack {fmt(ua, len(attacked['utility_results']))}; targeted attack success {fmt(asr, len(attacked['security_results']))}; {time.time() - t0:.0f}s")
    (RUNS / "index.jsonl").open("a").write(json.dumps({"suite": args.suite, "pipeline": pipeline.name, "model": args.model, "defense": args.defense, "attack": args.attack, "version": args.version, "user_tasks": user_tasks, "injection_tasks": inj_tasks, "when": time.strftime("%Y-%m-%d %H:%M")}) + "\n")
    return 0


def gateway_fired(results) -> int:
    """How many of these saved runs contain at least one refusal by the gateway. A defence that never fired cannot be credited with a clean result: the model resisted on its own."""
    return sum(1 for r in results.values() if any(m.get("error") and "DENIED by the gateway" in str(m["error"]) for m in r.messages if m.get("role") == "tool"))


class _Saved:
    """One finished run as AgentDojo saved it (runs/<pipeline>/<suite>/<user task>/<attack>/<injection task>.json), with the three fields the summary reads."""
    def __init__(self, d): self.utility, self.security, self.messages = d.get("utility"), d.get("security"), d.get("messages", [])


def load_saved():
    """Every finished run under runs/, grouped by (suite, pipeline, attack): {key: (benign {user: _Saved}, attacked {(user, injection): _Saved})}. Reads the files directly, so a row that
    is still running, or died part way (2026-10-05: the credit balance ran out at run 410 of 560), is summarised over what it has; the n column says how much that is."""
    benign, attacked = {}, {}
    for f in RUNS.glob("*/*/user_task_*/*/*.json"):
        try: d = json.loads(f.read_text())
        except Exception: continue
        if d.get("utility") is None: continue
        pipe, suite, user, attack = f.parts[-5], f.parts[-4], f.parts[-3], f.parts[-2]
        if attack == "none": benign.setdefault((suite, pipe), {})[user] = _Saved(d)
        else: attacked.setdefault((suite, pipe, attack), {})[(user, f.stem)] = _Saved(d)
    out = {k: (benign.get(k[:2], {}), v) for k, v in attacked.items()}                   # benign runs are saved once per pipeline and suite and belong to every attack row of it
    for k, v in benign.items():
        if not any(a[:2] == k for a in attacked): out[(k[0], k[1], "none")] = (v, {})
    return out


def summary():
    L = ["# GLITCH on AgentDojo", "", "*Generated by `run_dojo.py --summary` from the runs under `17_agentdojo/runs/`. Rate = count / n with a Wilson 95% interval. Utility = the user's task completed. Targeted attack success = the injection's goal reached. Baselines are AgentDojo's own pipeline with no defence, run here under the same conditions.*", "",
         "| suite | pipeline | attack | benign utility | utility under attack | targeted attack success | gateway fired (benign / attacked) | n benign / n attacked |", "|---|---|---|---|---|---|---|---|"]
    rows = []
    for (suite, pipe, attack), (without, with_inj) in sorted(load_saved().items(), key=lambda kv: (SUITES.index(kv[0][0]) if kv[0][0] in SUITES else 9, kv[0][1], kv[0][2])):
        if not with_inj: continue                                                        # benign only: not a row yet
        u = [r.utility for r in without.values()]; ua = [r.utility for r in with_inj.values()]; sec = [r.security for r in with_inj.values()]
        rows.append((suite, pipe, attack, sum(u), len(u), sum(ua), len(ua), attack_successes(sec), len(sec)))
        L.append(f"| {suite} | {pipe} | {attack} | {fmt(sum(u), len(u))} | {fmt(sum(ua), len(ua))} | {fmt(attack_successes(sec), len(sec))} | {gateway_fired(without)} / {gateway_fired(with_inj)} | {len(u)} / {len(ua)} |")
    L += ["", "## How to read this", "", "- **Gateway fired** is how many runs contain at least one refusal. A clean attack column with zero refusals means the model resisted on its own and says nothing about the gateway; a stronger attack is needed before the defence is measured at all.", "- A gateway can lower utility in two ways: refusing a call the correct solution needs (the offline ceiling in `OFFLINE.md` bounds this), and confusing the model with refusals so it gives up. The second is only visible here.",
          "- Targeted attack success counts the injection's goal being reached. An injection whose goal is text only (say something) is not a tool call and no gateway can refuse it; AgentDojo counts it anyway, so the number here includes it.",
          "- Some injection tasks are scored by AgentDojo from the model's ATTEMPTED calls (`security_from_traces`), not from the environment, so a call the gateway refused still counts as made. Slack's injection task 5 is one: a run where every call toward the attacker was refused is counted as landed here. README.md gives the count by effect beside this one.",
          "- A full AgentDojo run is 97 benign + 629 attacked cases per pipeline; anything smaller is a subset and says so in the n column.", ""]
    (_HERE / "RESULTS.md").write_text("\n".join(L)); print("\n".join(L[:4 + len(rows) + 2]))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--suite", default="banking", choices=SUITES); ap.add_argument("--model", default="claude-haiku-4-5"); ap.add_argument("--defense", default="glitch", choices=["glitch", "glitch-seen", "glitch-boss", "glitch-record", "none"])
    ap.add_argument("--attack", default="important_instructions"); ap.add_argument("--version", default="v1"); ap.add_argument("--user-tasks", default=""); ap.add_argument("--injection-tasks", default=""); ap.add_argument("--go", action="store_true"); ap.add_argument("--force", action="store_true")
    ap.add_argument("--summary", action="store_true"); a = ap.parse_args()
    if a.summary: summary(); return 0
    return run(a)


if __name__ == "__main__": sys.exit(main())
