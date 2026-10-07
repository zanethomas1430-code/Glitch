#!/usr/bin/env python3
"""opsat_adapter.py — read a REAL log, not one the testbed wrote, through the historian.

Input: the Tello scout's flight ledger (`ledger.jsonl`, one JSON row per flight: started, ended, mode, outcome, exit_code, reason, battery_start/end, duration_s, dir,
and from September 14 onward policy_kind / policy_version / flight_mode / safety_mode / floor). Output: historian events, the historian's verdicts, ledger-level checks,
and, most important, a COVERAGE table that says which invariants this log can and cannot support, and which fields would make it GLITCH-ready.

Rules the adapter keeps (HARDENING H1, H5, H6):
  * Nothing is invented. A field the ledger does not carry is written as 'unrecorded', and 'unrecorded' is never trusted (an unlabelled field is suspect, not safe).
  * Every assumption the mapping needs is listed in ASSUMPTIONS and printed with the verdicts. `assume_operator_policy=True` states one of them out loud
    (the policy file is the operator's); without it the same log is judged with nothing assumed.
  * The adapter's own sequence numbers prove nothing. The ledger has no sequence numbers and no hash chain, so a deleted row is invisible (LIMIT, tested).
  * Nothing here reads model text; reasons are matched against a fixed list of the ledger's own outcome codes.

  python3 opsat_adapter.py --ledger ~/Desktop/Tello/flights-mac-keep/ledger.jsonl [--assume-operator-policy] [--out REPORT.md]
"""
import os as _os, sys as _sys, re, json, argparse
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
_R = Path(__file__).resolve().parent.parent
for _d in ("08_incident",): _sys.path.insert(0, str(_R / _d))
from historian import HistorianConfig, examine

TENANT, SCOUT = "opsat", "tello-scout"
HUMAN_KEYS = re.compile(r"^aborted: (Enter|L) pressed")
VETO = re.compile(r"^vetoed: .*? before '([a-z]+)")

ASSUMPTIONS = [
    "A1 the ledger row's outcome codes mean what the scout's code says: ABORTED = the landing was acknowledged; LAND-UNACKED = it was not; REFUSED and NOT-ACKED = nothing took off.",
    "A2 a stop is scoped to its flight session: the ledger records no 'resume' event, so a stop cannot be tested against later flights (each flight is its own principal).",
    "A3 the stop acknowledgement (landing) happened at the moment the flight ended; its latency is not recorded and nothing here says anything about it.",
    "A4 'aborted: Enter pressed' and 'aborted: L pressed' are a person at the console: authenticated by physical presence, not by any recorded identity.",
    "A5 (only with --assume-operator-policy) the guard policy in force was assigned by the operator; the ledger records the version, not who set it.",
]

# Which invariants this log can support, and what is missing for the rest. Written to be read by the person who owns the ledger.
COVERAGE = [
    ("I0 complete", "PARTIAL", "timestamps, durations and directory names are cross-checked; there is no sequence number or hash chain, so a deleted row is invisible", "per-row seq and prev_hash (the Pi's Z-brain ledger has the hash chain; this one does not)"),
    ("I1 stop", "PARTIAL", "human-key aborts and unacknowledged landings are testable under A1 to A4", "an explicit stop record with the stop's subject, and an acknowledgement record with its own timestamp"),
    ("I2 origin", "NOT PROVABLE", "who or what launched the flight is not recorded", "launcher principal and channel class (human_authenticated or not) on every row"),
    ("I2b non-human input", "NOT APPLICABLE", "no content from documents or other agents reaches this controller", ""),
    ("I3 identity", "NOT APPLICABLE", "no accounts are created", ""),
    ("I4 self-edit", "NOT PROVABLE", "the policy version changes between rows, and no row records who changed it or who approved it", "approver and signature on every policy change"),
    ("I5/I10/I11 egress", "NOT APPLICABLE", "no outbound content path in this ledger", ""),
    ("I6 handoff", "NOT APPLICABLE", "no agent-written notes in this ledger", ""),
    ("I7 alerts", "NOT PROVABLE", "NOT-ACKED rows show a human acknowledgement gate working, but no alert is recorded with an audience and a time", "alert records with audience, refers_to, and acknowledgement time"),
    ("I8 scope", "PARTIAL", "the policy version is on most rows; the rest are unscoped, and nothing records who assigned the policy", "policy version and assigner on every row, including refusals"),
    ("I9 budget", "SURFACE ONLY", "no budget is declared, so only counts (flights, aborts) can be reported", "a declared per-day or per-session budget"),
]

REQUIRED = ("started", "ended", "mode", "outcome", "dir")
SKEW_OK_S = 5.0                                    # a row and its directory name may differ by a few seconds; more than this is suspect


def load(path):
    rows, bad = [], 0
    for line in Path(path).read_text().splitlines():
        if not line.strip(): continue
        try: r = json.loads(line)
        except Exception: bad += 1; continue
        if isinstance(r, dict): rows.append(r)
        else: bad += 1
    return rows, bad


def _t(s):
    try: return datetime.fromisoformat(s).timestamp()
    except Exception: return None


def has_policy(r): return r.get("policy_kind") is not None and r.get("policy_version") is not None


def row_events(r, assume_operator_policy=False):
    """The historian events for one flight. The flight is its own principal, so a stop on it covers only it (A2)."""
    d = r["dir"]; base = _t(r["started"]); end = _t(r["ended"]) if r.get("ended") else base + float(r.get("duration_s") or 0.01)
    end = max(end, base + 0.01); subj = {"tenant": TENANT, "principal": f"{SCOUT}:{d}", "capability_class": "flight"}; oc = r["outcome"]; reason = str(r.get("reason") or "")
    ev = [{"type": "input_event", "input_id": f"{d}:launch", "ts": base, "channel_class": "unrecorded", "principal": "unrecorded"}]
    if has_policy(r):
        ev.append({"type": "task_manifest", "task_id": d, "ts": base + 0.001, "subject": {"tenant": TENANT, "principal": f"{SCOUT}:{d}"}, "classes": ["flight"], "assigned_by_class": "operator" if assume_operator_policy else "unrecorded",
                   "policy_kind": r["policy_kind"], "policy_version": r["policy_version"]})
    flew = oc not in ("REFUSED", "NOT-ACKED")
    ev.append({"type": "action_event", "effect_id": f"{d}:flight", "ts": base + 0.002, "subject": subj, "capability": "execute", "outcome": "allowed" if flew else "denied", "task_id": d, "tool": r["mode"], "resource_ref": f"flight:{r['mode']}",
               "claimed_origin": None, "cause_id": None})
    m = VETO.match(reason) if oc == "VETOED" else None
    if m: ev.append({"type": "action_event", "effect_id": f"{d}:cmd", "ts": base + 0.003, "subject": subj, "capability": "execute", "outcome": "denied", "task_id": d, "tool": m.group(1), "resource_ref": f"cmd:{m.group(1)}"})
    human_stop = oc in ("ABORTED", "LAND-UNACKED") and bool(HUMAN_KEYS.match(reason))
    if human_stop or oc == "LAND-UNACKED":
        sid = f"{d}:stop"
        ev.append({"type": "stop_event", "stop_id": sid, "ts": end, "subject": {**subj, "capability_class": "*"}, "reason": "operator keypress" if human_stop else "land command", "by": "operator-at-console" if human_stop else "scout"})
        if oc == "ABORTED": ev.append({"type": "stop_applied", "stop_id": sid, "ts": end, "subject": {**subj, "capability_class": "*"}, "actuator": "tello-land", "channels_closed": ["flight"]})
    return ev


def to_events(rows, assume_operator_policy=False):
    """All rows in time order, with policy changes as config events (actor and approver unrecorded). The sequence numbers are the adapter's own and prove nothing."""
    ev, last = [], None
    for r in sorted(rows, key=lambda r: _t(r["started"])):
        if has_policy(r):
            cur = (r["policy_kind"], r["policy_version"])
            if last is not None and cur != last:
                ev.append({"type": "config_event", "object_id": "guard_policy", "ts": _t(r["started"]) - 0.0005, "actor": "unrecorded", "actor_class": "unrecorded", "governs": [SCOUT], "approved_by": None, "approved_by_class": None, "change": f"{last[0]} v{last[1]} -> {cur[0]} v{cur[1]}"})
            last = cur
        ev += row_events(r, assume_operator_policy)
    ev.sort(key=lambda e: e["ts"])
    return [{"gateway_id": "opsat-adapter", "seq": i, **e} for i, e in enumerate(ev, 1)]


def ledger_checks(rows):
    """Checks the ledger can support on its own, without the historian: ordering, overlap, duplicates, and agreement between a row's start time and its directory name."""
    out = {"rows": len(rows), "missing_fields": [], "regressions": 0, "overlaps": 0, "duplicate_dirs": 0, "dir_time_mismatch": 0, "dir_time_small_skew": 0, "duration_mismatch": 0}
    seen = Counter(r.get("dir") for r in rows); out["duplicate_dirs"] = sum(v - 1 for v in seen.values() if v > 1)
    ok = [r for r in rows if all(r.get(k) for k in REQUIRED)]; out["missing_fields"] = [r.get("dir", "?") for r in rows if r not in ok]
    prev = None
    for r in ok:
        s, e = _t(r["started"]), _t(r["ended"])
        if s is None or e is None: out["missing_fields"].append(r["dir"]); continue
        if prev is not None:
            if s < prev[0]: out["regressions"] += 1
            if s < prev[1]: out["overlaps"] += 1
        prev = (s, e)
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})_(\d{2})(\d{2})(\d{2})_", r["dir"])
        if m:                                                                      # the directory name is stamped when the flight directory is made, the row's start a moment later
            skew = abs((datetime.fromisoformat(r["started"][:19]) - datetime(*map(int, m.groups()))).total_seconds())
            if skew > SKEW_OK_S: out["dir_time_mismatch"] += 1
            elif skew > 0: out["dir_time_small_skew"] += 1
        if r.get("duration_s") is not None and abs((e - s) - float(r["duration_s"])) > 3: out["duration_mismatch"] += 1
    return out


def analyse(rows, assume_operator_policy=False):
    ev = to_events(rows, assume_operator_policy)
    res = examine(ev, HistorianConfig(require_alerts=False, require_manifest=True))
    by = defaultdict(list)
    for v in res["violations"]: by[v["kind"]].append(v["ref"])
    changes = [e for e in ev if e["type"] == "config_event"]
    return {"events": len(ev), "assume_operator_policy": assume_operator_policy, "by_kind": {k: len(v) for k, v in by.items()}, "refs": dict(by), "provable": res["provable"], "triage": len(res["triage"]),
            "policy_changes": len(changes), "policy_changes_with_approver": sum(1 for c in changes if c.get("approved_by")), "outcomes": dict(Counter(r["outcome"] for r in rows)),
            "human_key_aborts": sum(1 for r in rows if r["outcome"] in ("ABORTED", "LAND-UNACKED") and HUMAN_KEYS.match(str(r.get("reason") or ""))),
            "no_policy_flown": sum(1 for r in rows if not has_policy(r) and r["outcome"] not in ("REFUSED", "NOT-ACKED")), "flights": len(rows),
            "flown": sum(1 for r in rows if r["outcome"] not in ("REFUSED", "NOT-ACKED"))}


def report(rows, path="", bad=0):
    strict, assumed = analyse(rows, False), analyse(rows, True); chk = ledger_checks(rows); L = []
    L += [f"# Tello scout ledger through the GLITCH historian", "", f"Source: `{str(path).replace(__import__('os').path.expanduser('~'), '~') if path else '(rows given)'}`; {len(rows)} flights" + (f", {bad} unreadable lines skipped" if bad else "") + f"; {rows[0]['started'][:10] if rows else '-'} to {rows[-1]['started'][:10] if rows else '-'}.",
          "This is a REAL log (not written by the testbed). The numbers below are what the record shows under the stated assumptions; they are not a judgement of the pilot or the drone.", ""]
    L += ["## Outcomes in the ledger", ", ".join(f"{k} {v}" for k, v in sorted(assumed["outcomes"].items(), key=lambda kv: -kv[1])) + ".", f"{assumed['human_key_aborts']} flights ended because a person pressed Enter or L.", ""]
    L += ["## Verdicts", "", "| invariant finding | nothing assumed | with A5 (policy is the operator's) |", "|---|---|---|"]
    for k in sorted(set(strict["by_kind"]) | set(assumed["by_kind"])): L.append(f"| {k} | {strict['by_kind'].get(k, 0)} | {assumed['by_kind'].get(k, 0)} |")
    if not (strict["by_kind"] or assumed["by_kind"]): L.append("| (none) | 0 | 0 |")
    L += ["", f"Flights flown with no policy recorded: {assumed['no_policy_flown']} of {assumed['flown']} that flew ({assumed['flights']} rows in all). Policy changes between rows: {assumed['policy_changes']}; with an approver recorded: {assumed['policy_changes_with_approver']}.", ""]
    for k, refs in assumed["refs"].items():
        if k == "ACTUATOR_SILENT": L += ["ACTUATOR_SILENT (a stop with no acknowledgement) on: " + ", ".join(r.replace(":stop", "") for r in refs[:12]) + (" ..." if len(refs) > 12 else ""), ""]
    L += ["## Ledger-level checks (no historian needed)", "", ", ".join(f"{k} {v if not isinstance(v, list) else len(v)}" for k, v in chk.items()) + ".", ""]
    L += ["## What this log can and cannot support", "", "| invariant | status | why | what would make it provable |", "|---|---|---|---|"] + [f"| {a} | {b} | {c} | {d or '-'} |" for a, b, c, d in COVERAGE]
    L += ["", "## Assumptions used", ""] + [f"- {a}" for a in ASSUMPTIONS]
    L += ["", "## Limit that matters most", "This ledger has no sequence numbers and no hash chain: a deleted or edited row cannot be detected, only a regression in time. The adapter's own `seq` field is its own and proves nothing. That is the first thing to fix, and the Pi's Z-brain ledger already has the chain."]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--ledger", required=True); ap.add_argument("--assume-operator-policy", action="store_true"); ap.add_argument("--out", default="")
    a = ap.parse_args(); rows, bad = load(a.ledger)
    if not rows: print("no rows read"); return 1
    rows = [r for r in rows if all(r.get(k) for k in REQUIRED)]
    text = report(rows, a.ledger, bad); print(text)
    if a.out: Path(a.out).write_text(text)
    return 0


if __name__ == "__main__": _sys.exit(main())
