#!/usr/bin/env python3
"""arena.py — validate the move tree, play the bouts, print the board.

  python3 arena.py            validate, play every bout, print the board, write BOARD.txt   (exit 1 on any problem or any lost beat)
  python3 arena.py --board    the board only

What 'validate' enforces (each rule is also a test in test_arena.py, and each has a mutant that must fail it):
  1. a chain alternates adv/def, starts with the adversary and ENDS ON A DEFENDER MOVE: no move is left unanswered
  2. every counter has been attacked and answered: at least two adversary moves and two defender moves per chain
  3. every defender move names kind and status; 'tested' names tests that exist, 'implemented' names a file that exists, 'roadmap' says why
  4. the evidence a counter reads is gateway-assigned: never a field the model authors (H1, H3)
  5. a chain ends in exactly one terminal state: FLOOR (structural, implemented or tested, with assumptions), RESIDUAL (a stated bound and what measures it), or OPEN (an owner and what would close it)
  6. every violation kind the historian and reach monitor can emit, and every kind a testbed scenario is designed to surface, is detected by some counter (or listed as unmapped with a reason)
  7. every bout referenced by a chain exists and every bout belongs to a chain
  8. every bout has at least one beat where the adversary's move LANDS (a bout that cannot be lost is staged)
  9. a counter that PUNISHES (strikes, burns a principal) cites a test named 'fairness': the boss never strikes the innocent
"""
import os as _os, sys as _sys, re, importlib
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
for _d in ("08_incident", "11_testbed", "05_deploy", "12_arena"): _sys.path.insert(0, str(ROOT / _d))
import move_tree, fighters

KINDS = {"structural", "monitor", "statistical", "process"}
STATUSES = {"tested", "implemented", "roadmap"}
# fields the gateway assigns or derives from its own tables; a counter may read only these (HARDENING H1)
GATEWAY_FIELDS = {"waited", "lease_epoch", "watts", "approver_classes", "reversibility", "destination_class", "sensitivity", "capability", "capability_class", "outcome", "resource_ref", "cause_id", "channel_class", "egress_chars", "max_egress_chars",
                  "max_actions", "task_id", "assigned_by_class", "approved_by_class", "actor_class", "registered_by_class", "consumed_as", "ts", "seq", "gateway_id", "subject",
                  "stop_id", "effect_id", "tool", "audience", "canonical_ref", "level", "object_id", "actor", "approved_by", "decoy", "denial_reason"}
MODEL_AUTHORED = {"because", "claimed_origin", "rationale", "reply", "finish", "text", "witness", "summary", "quote", "justification", "reason_given"}
REACH_KINDS = {"CR_SLOPE", "CR_SUSTAINED", "CAPABILITY_STEP", "CAMPAIGN_FANOUT"}
STOP_KINDS = {"CONTINUED_AFTER_STOP", "ACTUATOR_SILENT", "ACTUATOR_MISMATCH"}


def all_kinds():
    src = (ROOT / "08_incident" / "historian.py").read_text()
    return set(re.findall(r'_v\("I\d+b?", "([A-Z_]+)"', src)) | STOP_KINDS | REACH_KINDS


def scenario_watch_kinds():
    from scenarios import SCENARIOS
    return {k for s in SCENARIOS for k in s.get("watch", [])}


def test_exists(ref):
    """'dir/module.Class.test_name' -> does it exist?"""
    try:
        mod, cls, name = ref.rsplit(".", 2); d, m = mod.rsplit("/", 1)
        _sys.path.insert(0, str(ROOT / d)); mm = importlib.import_module(m)
        return hasattr(getattr(mm, cls, None), name)
    except Exception: return False


def validate(chains=None, bouts=None, unmapped=None, kinds=None, watch=None):
    chains = move_tree.CHAINS if chains is None else chains; bouts = fighters.BOUTS if bouts is None else bouts
    unmapped = move_tree.UNMAPPED if unmapped is None else unmapped
    kinds = all_kinds() if kinds is None else kinds; watch = scenario_watch_kinds() if watch is None else watch
    P, ids, detected = [], set(), set()
    for c in chains:
        cid = c.get("id", "?"); ex = c.get("exchanges", [])
        if cid in ids: P.append(f"{cid}: duplicate chain id")
        ids.add(cid)
        if not ex or ex[0]["by"] != "adv": P.append(f"{cid}: a chain starts with the adversary")
        if any(a["by"] == b["by"] for a, b in zip(ex, ex[1:])): P.append(f"{cid}: exchanges must alternate adv/def")
        if ex and ex[-1]["by"] != "def": P.append(f"{cid}: ends on an unanswered adversary move")
        if sum(e["by"] == "adv" for e in ex) < 2 or sum(e["by"] == "def" for e in ex) < 2: P.append(f"{cid}: a counter that was never attacked is a claim; need at least two exchanges each side")
        for e in ex:
            if e["by"] == "adv":
                if not e.get("shape"): P.append(f"{cid}: adversary move '{e.get('name')}' has no shape")
                continue
            n = e.get("name", "?")
            if e.get("kind") not in KINDS: P.append(f"{cid}/{n}: kind must be one of {sorted(KINDS)}")
            if e.get("status") not in STATUSES: P.append(f"{cid}/{n}: status must be one of {sorted(STATUSES)}")
            if not e.get("why"): P.append(f"{cid}/{n}: say what it does")
            if e.get("status") == "tested":
                if not e.get("tests"): P.append(f"{cid}/{n}: 'tested' names no tests")
            if e.get("status") == "implemented" and not (e.get("ref") and (ROOT / e["ref"]).exists()): P.append(f"{cid}/{n}: 'implemented' names no file that exists")
            if e.get("status") == "roadmap" and not e.get("why"): P.append(f"{cid}/{n}: a roadmap counter must say what it will do")
            for t in e.get("tests", []):
                if not test_exists(t): P.append(f"{cid}/{n}: named test does not exist: {t}")
            for f in e.get("evidence", []):
                if f in MODEL_AUTHORED: P.append(f"{cid}/{n}: evidence field '{f}' is authored by the model (H1/H3)")
                elif f not in GATEWAY_FIELDS: P.append(f"{cid}/{n}: evidence field '{f}' is not a gateway-assigned field")
            if e.get("kind") != "process" and e.get("status") != "roadmap" and not e.get("evidence"): P.append(f"{cid}/{n}: a working counter names the evidence it reads")
            detected |= set(e.get("detects", []))
            if n in getattr(move_tree, "PUNISHES", ()) and not any("fairness" in t.rsplit(".", 1)[-1] for t in e.get("tests", [])): P.append(f"{cid}/{n}: a counter that punishes must cite a fairness test (the honest path is never struck or refused)")
            if e.get("prevents") and e.get("kind") != "structural": P.append(f"{cid}/{n}: a counter that refuses the call is structural")
            if e.get("bout") and e["bout"] not in bouts: P.append(f"{cid}/{n}: bout {e['bout']} does not exist")
        end = c.get("end") or {}; st = end.get("state"); last = ex[-1] if ex else {}
        if st == "FLOOR":
            if last.get("kind") != "structural" or last.get("status") not in ("tested", "implemented"): P.append(f"{cid}: a FLOOR ends on a structural counter that is tested or implemented")
            if not end.get("assumes"): P.append(f"{cid}: a FLOOR lists what it assumes")
        elif st == "RESIDUAL":
            if not (end.get("bound") and end.get("measured_by")): P.append(f"{cid}: a RESIDUAL states its bound and what measures it")
        elif st == "OPEN":
            if not (end.get("owner") and end.get("next")): P.append(f"{cid}: an OPEN end names an owner and what would close it")
        else: P.append(f"{cid}: ends in none of FLOOR, RESIDUAL, OPEN")
    for b, v in bouts.items():
        if v["chain"] not in ids: P.append(f"bout {b} belongs to no chain")
        elif not any(e.get("bout") == b for c in chains if c["id"] == v["chain"] for e in c["exchanges"]): P.append(f"bout {b} is not referenced by its chain {v['chain']}")
    for b, v in bouts.items():                                                                   # a bout the adversary can never win is staged
        if not any(x.get("wins") for x in v["beats"]): P.append(f"bout {b} has no beat where the adversary's move lands: a bout that cannot be lost proves nothing")
    for k in sorted((kinds | watch) - detected - set(unmapped)): P.append(f"violation kind {k} is detected by no counter and is not listed as unmapped")
    for k in unmapped:
        if not unmapped[k]: P.append(f"unmapped kind {k} has no reason")
    return P


def board(chains=None):
    chains = move_tree.CHAINS if chains is None else chains
    L, by_state = [], {"OPEN": [], "RESIDUAL": [], "FLOOR": []}
    for c in chains: by_state[c["end"]["state"]].append(c)
    cnt = {s: sum(e.get("status") == s for c in chains for e in c["exchanges"] if e["by"] == "def") for s in STATUSES}
    n_prev = sum(bool(e.get("prevents")) for c in chains for e in c["exchanges"] if e["by"] == "def")
    L.append(f"ARENA: {len(chains)} chains, {sum(e['by'] == 'adv' for c in chains for e in c['exchanges'])} adversary moves, {sum(cnt.values())} counters "
             f"({cnt['tested']} tested, {cnt['implemented']} implemented, {cnt['roadmap']} roadmap)")
    L.append(f"       {n_prev} of {sum(cnt.values())} counters REFUSE the call at the gateway; the other {sum(cnt.values()) - n_prev} detect it afterwards (a flag is not a block)")
    L.append(f"       chains end: {len(by_state['FLOOR'])} FLOOR (structural, with assumptions), {len(by_state['RESIDUAL'])} RESIDUAL (bounded, not closed), {len(by_state['OPEN'])} OPEN (no answer yet)\n")
    L.append("OPEN (no answer yet; read these first):")
    for c in by_state["OPEN"]: L.append(f"  {c['id']} {c['name']}\n      owner: {c['end']['owner']}; to close: {c['end']['next']}")
    L.append("\nRESIDUAL (bounded and metered, not closed):")
    for c in by_state["RESIDUAL"]: L.append(f"  {c['id']} {c['name']}\n      bound: {c['end']['bound']}\n      measured by: {c['end']['measured_by']}")
    L.append("\nFLOOR (nothing left to attack inside the threat model, as long as this stays true):")
    for c in by_state["FLOOR"]:
        L.append(f"  {c['id']} {c['name']}")
        for a in c["end"]["assumes"]: L.append(f"      assumes: {a}")
    L.append("\nCHAINS (A = adversary move, D = defender answer; [t]ested [i]mplemented [r]oadmap):")
    for c in chains:
        L.append(f"  {c['id']} [{c['family']}] {c['name']}  -> {c['end']['state']}")
        for e in c["exchanges"]:
            L.append(f"      A  {e['name']}" if e["by"] == "adv" else f"      D  [{e['status'][0]}] {e['name']}" + (f"   (bout {e['bout']})" if e.get("bout") else ""))
    roadmap = [(c["id"], e["name"]) for c in chains for e in c["exchanges"] if e["by"] == "def" and e["status"] == "roadmap"]
    with_bout = sorted({e["bout"] for c in chains for e in c["exchanges"] if e["by"] == "def" and e.get("bout")})
    L.append(f"\nBOUTS: {len(with_bout)} executable bouts through the real gateway and historian; chains with at least one: {sum(any(e.get('bout') for e in c['exchanges']) for c in chains)} of {len(chains)}")
    L.append("\nROADMAP counters (named, not built): " + ("; ".join(f"{i} {n}" for i, n in roadmap) if roadmap else "none"))
    return "\n".join(L)


def play_all(verbose=True):
    lost = 0
    for bid, b in fighters.BOUTS.items():
        if verbose: print(f"\nBOUT {bid} ({b['chain']}): {b['name']}")
        for say, ok, detail in fighters.run_bout(bid):
            lost += (not ok)
            if verbose: print(f"   {'WON ' if ok else 'LOST'}  {say}" + (f"\n         {detail}" if (detail and not ok) else ""))
    return lost


def main() -> int:
    only_board = "--board" in _sys.argv
    problems = validate()
    for p in problems: print("PROBLEM:", p)
    lost = 0 if only_board else play_all()
    text = board(); print("\n" + text)
    if not only_board: (Path(__file__).resolve().parent / "BOARD.txt").write_text(text + "\n")
    print(f"\n{'OK' if not problems and not lost else 'FAILED'}: {len(problems)} problems, {lost} lost beats")
    return 0 if not problems and not lost else 1


if __name__ == "__main__": _sys.exit(main())
