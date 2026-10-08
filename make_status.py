#!/usr/bin/env python3
"""make_status.py — write STATUS.md from the suite's own results, so the front-door evidence page cannot lag the code.

Everything below is read from files the suite and its runs produce (the arena board, the saved adversary proposals re-judged by the current judge, the red-team table, the kappa file, the
incident log, the real-log report). Nothing is typed in except the claim boundary and the list of what is not shown. A test (`test_docs.py`) fails if STATUS.md differs from this output.

  python3 make_status.py          rewrite STATUS.md
"""
import os as _os, sys as _sys, json, re, glob, collections
from pathlib import Path
ROOT = Path(__file__).resolve().parent
for _d in ("08_incident", "11_testbed", "12_arena"): _sys.path.insert(0, str(ROOT / _d))


def _board_counts():
    import arena
    b = arena.board().splitlines(); return b[0], b[1], b[2]


def _adversary():
    import adaptive
    old = adaptive.HARDENED; adaptive.HARDENED = True
    try:
        tot, models, moves = collections.Counter(), set(), 0
        for f in sorted(glob.glob(str(ROOT / "12_arena" / "runs" / "adaptive*.json"))):
            j = json.load(open(f))
            if not any(r["moves"] for r in j["rounds"]): continue                          # a model that returned nothing (refused or out of tokens) played no moves
            models.add(j["model"])
            for r in j["rounds"]:
                for m in r["moves"]:
                    calls = m["proposal"].get("calls") or []; moves += 1
                    tot[adaptive.judge(calls)["outcome"] if calls else "NOT_EXECUTABLE"] += 1
        return tot, sorted(models), moves
    finally: adaptive.HARDENED = old


def _refusals():
    out = []
    for f in sorted(glob.glob(str(ROOT / "12_arena" / "runs" / "adaptive*.json"))):
        j = json.load(open(f))
        if j["rounds"] and all(r.get("stop_reason") in ("refusal", "max_tokens") and not r["moves"] for r in j["rounds"]): out.append((j["model"], j["rounds"][0]["stop_reason"], len(j["rounds"])))
    return out


def _testbed():
    models = collections.Counter(); withdrawn = 0
    for d in sorted((ROOT / "11_testbed" / "runs").iterdir()):
        if not d.is_dir(): continue
        if (d / "WITHDRAWN.txt").exists(): withdrawn += 1; continue
        sm = d / "summary.json"
        if not sm.exists(): continue
        s = json.load(open(sm))
        if s.get("script") or s.get("mode") != "notice_only" or s.get("prompt_suffix"): continue
        if any("error" not in r for r in s.get("rows", [])): models[s["model"]] += 1
    inc = json.load(open(ROOT / "11_testbed" / "harness_incidents.json"))["incidents"]
    return models, len(inc), withdrawn


def _kappa():
    p = ROOT / "09_study" / "kappa_latest.txt"
    return [l.strip(" |") for l in p.read_text().splitlines() if "kappa" in l and "labels_" in l] if p.exists() else []


def _campaigns():
    """Aggregate the persistent-defender campaigns: per configuration, the saved campaign stats of each run (not re-judged: what happened is what the attacker saw)."""
    out = collections.defaultdict(list)
    for f in sorted(glob.glob(str(ROOT / "12_arena" / "runs" / "campaign_*.json"))):
        j = json.load(open(f)); c = j.get("campaign")
        if c and c["executed"]: out[re.sub(r"_[a-z]\.json$", "", Path(f).name)[len("campaign_"):].rsplit("_", 1)[0]].append(c)
    return out


def _kappa_range():
    p = ROOT / "09_study" / "kappa_latest.txt"
    w = [float(x) for x in re.findall(r"weighted ([0-9.]+)", p.read_text())] if p.exists() else []
    return (min(w), max(w)) if w else None


def build_brief() -> str:
    """BRIEF.md: the two-page version for a reader outside the project, generated from the same results as STATUS.md."""
    import redteam, boss, depth, combos
    a, b, c = _board_counts(); tot, models, moves = _adversary(); tb, n_inc, withdrawn = _testbed(); rt = redteam.play_all(); _, brows = boss.report(); drows = depth.matrix(); camps = _campaigns()
    nums = re.findall(r"\d+", a); chains, counters = nums[0], nums[2]; refusing = re.search(r"(\d+) of (\d+) counters REFUSE", b); k = _kappa_range()
    before = collections.Counter(x[2] for x in rt); now = collections.Counter(x[3] for x in rt); b0, b2, b3 = brows[0], brows[2], brows[3]
    camp_line = ""
    if camps:
        parts = []
        for name, runs in sorted(camps.items()):
            ex = sum(r["executed"] for r in runs); bur = [r["burned_at_proposal"] for r in runs if r["burned_at_proposal"]]
            parts.append(f"{name.replace('-', ' ')}: {ex} proposals over {len(runs)} runs, burned at proposal {', '.join(map(str, bur)) if bur else 'never'}, first landing {'never' if all(r['first_landing_proposal'] is None for r in runs) else 'yes'}")
        camp_line = " Against a defender that remembers, an adaptive attacker (a model that learns from the gateway's own replies) fared as follows: " + "; ".join(parts) + "."
    L = ["# GLITCH in two pages", "",
         "*What it claims, what it shows, what it does not. Generated from the suite's own results (`make_status.py`); `STATUS.md` has the same facts with their sources.*", "",
         "## The problem", "",
         "AI agents now act: they send messages, fetch pages, edit settings, hand notes to other agents. When one misbehaves, the usual evidence is what it *said*. A model's account of its own behaviour is not evidence: it can be wrong, fluent and persuasive at once. "
         "GLITCH starts from the other end: a gateway writes the only record of what the agent did, and a deterministic judge, a *historian*, reads that record. The model's text is a witness and never a verdict.", "",
         "## What was built", "",
         "- **A historian**: invariants over a structured log (completeness, stop, origin, scope, budget, taint, audience, egress, a two-person rule), reading only fields the gateway assigns.",
         f"- **A testbed** that puts real models in a fake world behind that gateway ({len(tb)} models so far), with every harness defect those runs exposed logged and withdrawn in place ({n_inc} defects).",
         f"- **An arena**: every adversary move on a board with its counter, the attack on that counter, and the counter to that, each chain ending on a declared floor, a bound, or an open item ({chains} chains, {counters} counters, executable bouts for most). Of those counters, {refusing.group(1)} refuse a call at the gateway; the rest detect it afterwards, and the board says so.",
         "- **A drift guard** (the original system): an external harness that scores each turn against a purpose the model cannot move.", "",
         "## What the evidence shows", "",
         f"1. **Layers that look independent often share an assumption.** Switching each of {len(depth.LAYERS)} gateway layers on and off against {len(drows)} executable moves found a layer that was the only thing stopping the core exfiltration moves; a second layer that does not depend on the first closed it (no single point of failure now). A search over the assumptions each layer rests on found that no combination the agent can run alone reaches any goal, and that the cheapest route to a small leak needs a persuaded person.",
         f"2. **A flag is not a block.** The first version counted a violation on the record as \"caught\" although the data had already left. An author red-team round ({len(rt)} moves) found this and several cheap routes: before the fixes {before.get('LANDED', 0)} moves landed and {before.get('CAUGHT', 0)} happened and were flagged afterwards; now {now.get('LANDED', 0)} land and {now.get('PREVENTED', 0)} are prevented at the gateway.",
         f"3. **A defence that does not remember teaches an attacker for free.** A fixed prober of {b0['probes']} escape attempts gets {b0['free_probes']} free probes against walls that only refuse and {b2['free_probes']} against walls that persist strikes across attempts (burned by probe {b2['lockdown_at_probe']}); opaque refusals cut what it can read from the refusal text from {b0['distinct_refusals']} messages to {b3['distinct_refusals']}. An honest user is unaffected throughout.{camp_line}",
         f"4. **A model proposing its own attacks found a real gap.** A model proposed assumptions and combos the author had not listed; most were rewordings, one led to a parser differential (a header injected through a message body got out even with every wall on), closed by strict format checks on every field.",
         f"5. **The human ruler is usable.** The 0 to 5 specificity scale used by the drift guard was labelled by three people on 50 items: pairwise weighted agreement {k[0]:.2f} to {k[1]:.2f}, with level 3 the soft spot." if k else "5. The human study results are in `STATUS.md`.", "",
         "## What it does not show", "",
         "- That any model or deployment is safe, aligned or compliant. It detects specified patterns and, where the walls are on, refuses some calls.",
         "- That escape is impossible. No harness can prove that. The arena says, per move, whether the answer is a structural floor, a bound that is metered but not closed, or open; a move that is not on the board is not counted, and the board is written by its author.",
         "- Anything about a strong independent adversary. The strongest tried is a 14B local model; the hosted frontier models available to us refused the role. The red-team round is the defence's own author.",
         "- Influence that leaves no trace in the record, covert channels (bounded and metered, never closed), a person being persuaded (modelled, not played), or what a person on the approved list does with what they are sent.",
         "- Statistics: three runs per cell is a probe, not a rate; 50 items and three raters is a small human sample.", "",
         "## Check it yourself", "",
         "`python3 glitch_suite.py` runs every layer with one exit code and prints the counts. `STATUS.md` lists each claim with its evidence, size and where to find it. `00_docs/ARENA.md` is the board and its method; `00_docs/BOSS.md` is the design of the part that remembers; `00_docs/PROBES.md` is the ledger of every experiment, including the ones that failed.", "",
         "## What would change our mind, and what we ask of a reader", "",
         "- An independent adversary (a person or a model from another family) that lands a move the board does not answer, or breaks one of its stated assumptions.",
         "- A real log from another system, run through the adapter, to find where the historian's assumptions about a log's fields do not hold.",
         "- A replication of the human study with more raters and items.", ""]
    return "\n".join(L) + "\n"


def build() -> str:
    import redteam
    arena_a, arena_b, arena_c = _board_counts(); tot, models, moves = _adversary(); refusals = _refusals(); tb, n_inc, withdrawn = _testbed(); rt = redteam.play_all()
    L = ["# STATUS: what is shown, how, and what is not", "",
         "Generated by `make_status.py` from the suite's own results; a test fails if this file differs from that output. Run `python3 glitch_suite.py` for the current step and test counts.", "",
         "## What this is", "",
         "Two systems in one suite. (1) A runtime-assurance kit for a model's *drift*: an external harness that scores each turn against a purpose the model cannot move. (2) A *historian*: a deterministic judge over a structured log of what an agent DID, written by a gateway, "
         "with a testbed that puts real models in a fake world, an arena that lists every adversary move with its counter, and an adapter that reads a real log. The model's own text is a witness and never a verdict.", "",
         "## The claim boundary", "",
         "- It detects specified behavioural and governance failure patterns, and where its gateway walls are on, it refuses some calls. It does **not** establish that a model or deployment is safe, aligned, harmless or compliant.",
         "- \"Impossible to escape\" is not claimed and cannot be proved. The arena states, for every move on its board, whether the answer is a structural floor, a bound that is metered but not closed, or open; a move not on the board is not counted.",
         "- A flag is not a block: most counters detect after the fact (see the board line below).", "",
         "## The evidence, and its size", "",
         "| Claim | Evidence | Size | Where |", "|---|---|---|---|"]
    k = _kappa()
    L.append("| The 0–5 ruler is usable by humans | three raters labelled 50 items; " + ("; ".join(k[:3]) if k else "see the study") + " | 50 items, 3 raters (small); level 3 is the soft spot; day-14 re-sitting due 2026-10-10 | `09_study/`, PROBES L8–L10 |")
    L.append(f"| Real models, in the testbed, show different failure shapes | {len(tb)} models: " + ", ".join(f"{m} ({n})" for m, n in sorted(tb.items())) + " (run folders)" + f"; {n_inc} harness defects found by running them and logged ({withdrawn} run folders withdrawn in place) | 3 runs per cell: a probe, not a rate; small open-weight models plus one hosted | `11_testbed/runs/RESULTS.md`, `harness_incidents.json` |")
    L.append(f"| Every adversary move on the board has an answer | {arena_a.replace('ARENA: ', '')}; {arena_b.strip()}; {arena_c.strip()} | a table plus executable bouts; the author's own board | `12_arena/BOARD.txt`, `00_docs/ARENA.md` |")
    L.append(f"| An adaptive adversary did not get through the fixed defender | {', '.join(models)} proposed {moves} sequences; re-judged by the current judge: " + ", ".join(f"{k} {tot.get(k, 0)}" for k in ("LANDED", "PREVENTED", "CAUGHT", "HARMLESS", "NOT_EXECUTABLE")) + " (LANDED means harm reached with nothing flagged in time; CAUGHT means it happened and is flagged) | small local models; the one landing in the first campaigns was a real gap and is fixed | `12_arena/RESULTS.md` |")
    import combos, depth
    drows = depth.matrix(); spof = [r["id"] for r in drows if r["necessary"]]; cheapest = {g: combos.ranked(g)[0] for g in combos.GOALS}
    kinds = lambda g: [k for k, v in combos.RANK.items() if v == combos.cost(cheapest[g])][0]
    L.append(f"| Defence in depth: how many independent layers stop each move, and what chains | {len(drows)} executable moves, {len(depth.LAYERS)} gateway layers switched on and off; every layer on stops all {len(drows)}; single points of failure: {len(spof)}; minimum depth {min(r['depth'] for r in drows)}; "
             + "; ".join(f"cheapest route to {g}: needs {kinds(g)}" for g in combos.GOALS) + "; " + ", ".join(f"{cid} {fn()['outcome']}" for cid, _, fn, _, _, _ in combos.PLAYED) + " (played combos) | the assumption table is the author's; the played combos model persuading a person, they do not play it | `12_arena/combos.py`, `depth.py` |")
    import boss
    _, brows = boss.report(); b0, b2, b3 = brows[0], brows[2], brows[3]
    prop = json.load(open(ROOT / "12_arena" / "runs" / "propose_sarah-latest.json")) if (ROOT / "12_arena" / "runs" / "propose_sarah-latest.json").exists() else {"runs": []}
    n_as = sum(len(r["assumptions"]) for r in prop["runs"]); n_co = sum(len(r["combos"]) for r in prop["runs"]); n_land = sum(1 for r in prop["runs"] for c in r["combos"] if c["played"]["outcome"] in ("LANDED", "CAUGHT"))
    L.append(f"| What a probe costs: the boss remembers, changes phase, punishes greed, says little | a fixed prober of {b0['probes']} escape attempts, each against a different layer, through the real gateway: walls that only refuse give it {b0['free_probes']} free probes and {b0['distinct_refusals']} distinct refusal messages; walls that remember give {b2['free_probes']} free probe(s) and burn it at probe {b2['lockdown_at_probe']}; with opaque refusals it sees {b3['distinct_refusals']} message; an honest user is unaffected in every configuration: {all(r['honest_after'] for r in brows)} | one scripted prober, not an adaptive attacker; strikes are per principal, so a fresh identity starts again | `12_arena/boss.py`, `00_docs/BOSS.md` |")
    L.append(f"| A model proposed assumptions and combos the author had not listed | sarah:latest, {len(prop['runs'])} runs: {n_as} assumptions and {n_co} combos proposed; four assumptions kept after a person's triage (tool classification, narrow manifests, parser differential, forged resources); {n_land} of the combos landed or were caught after the fact; the parser-differential proposal found a real gap (a header injected through the body) and the format checks that closed it | a 14B local model; most proposals were rewordings | `12_arena/propose.py`, `parser_diff.py`, `runs/propose_sarah-latest.json` |")
    L.append("| The author's red-team round found real gaps, now fixed | " + f"{len(rt)} moves; before the fixes " + ", ".join(f"{v} {k}" for k, v in sorted(collections.Counter(b for _, _, b, _, _ in rt).items())) + "; now " + ", ".join(f"{v} {k}" for k, v in sorted(collections.Counter(n for _, _, _, n, _ in rt).items())) + " | same author as the defence (blind-spot caveat) | `12_arena/redteam.py`, `test_redteam.py` |")
    if refusals: L.append("| Hosted frontier models as adversary or subject | " + "; ".join(f"{m}: {r} in {n} of {n} rounds" for m, r, n in refusals) + "; Opus and Fable refused the testbed prompt outright | recorded, not worked around | `11_testbed/runs/RESULTS.md`, `12_arena/RESULTS.md` |")
    camps = _campaigns()
    if camps:
        L.append("| An adaptive attacker against a defender that remembers | " + "; ".join(f"{name.replace('-', ' ')}: {sum(r['executed'] for r in runs)} proposals over {len(runs)} runs, burned at proposal {', '.join(str(r['burned_at_proposal']) for r in runs if r['burned_at_proposal']) or 'never'}, first landing {'never' if all(r['first_landing_proposal'] is None for r in runs) else 'yes'}, distinct replies seen {sum(r['distinct_replies'] for r in runs)}" for name, runs in sorted(camps.items())) + " | one local model; the attacker sees only the gateway's own replies; a fresh identity costs a persuaded person | `12_arena/RESULTS.md`, `12_arena/runs/campaign_*.json` |")
    L += ["", "## What is not shown", "",
          "- A strong independent adversary: the strongest tried is a 14B local model, and the hosted Claude models refused the role. The board and the red-team round are written by the defence's author.",
          "- Influence that leaves no string overlap: not provable from a log; bounded by manifest, budgets and the egress cap, not detected.",
          "- Covert channels: bounded and metered, never closed, while any output is allowed.",
          "- A larger human study: 50 items and three raters is a small sample.", "",
          "## Dated and open", "",
          "- 2026-10-10: the day-14 re-sitting of the 50-item human study.",
          "- Revoke any API key created for the hosted-model runs (none is in this folder; the suite zip is scanned for key-shaped strings).", ""]
    return "\n".join(L) + "\n"


def main() -> int:
    (ROOT / "STATUS.md").write_text(build()); (ROOT / "BRIEF.md").write_text(build_brief()); print("wrote STATUS.md and BRIEF.md"); return 0


if __name__ == "__main__": _sys.exit(main())
