"""stop_invariant.py — a stop is an event, and a stop that did not land is a measurable failure.

Three record kinds, all in the same evidence channel as everything else (HARDENING v0.1.2):

  STOP_EVENT    {"type": "stop_event",   "stop_id", "subject", "ts", "reason", "by"}
  STOP_APPLIED  {"type": "stop_applied", "stop_id", "subject", "ts", "actuator", "channels_closed": [...]}
  ACTION_EVENT  {"type": "action_event", "subject", "ts", "effect_id", "capability", "outcome"}

`subject` is the narrowest thing an actuator can close: {"tenant", "principal", "capability_class"} with "*" as the
wildcard. A stop on (tenant T, principal P, "*") covers every class for P; a stop on (T, "*", "dns-egress") covers DNS
for everyone in T. Gateway-assigned, never agent-supplied (HARDENING H1).

The invariant, checked deterministically over a list of records:

  For every STOP_EVENT(S) at time T:
    (a) no ACTION_EVENT whose subject is covered by S may have outcome "allowed" with ts > T      -> CONTINUED_AFTER_STOP
    (b) a STOP_APPLIED(S) with the same stop_id must exist with T <= ts <= T + delta                -> ACTUATOR_SILENT
    (c) a STOP_APPLIED whose subject does not cover S closed the wrong thing                       -> ACTUATOR_MISMATCH

Denied actions after a stop are not violations: they are the actuator working. Nothing here shuts anything down; it
reads records and names the lie when the kill switch is believed but not evidenced.
"""
from __future__ import annotations
from typing import Any, Dict, Iterable, List

WILD = "*"


def covers(stop_subject: Dict[str, str], subject: Dict[str, str]) -> bool:
    """Does the stop's subject cover this record's subject? Wildcards in the stop match anything; a wildcard in the
    record (an action whose class the gateway could not assign) is covered by any stop on that tenant/principal:
    unknown is treated as inside the stop, never outside it (fail closed)."""
    for k in ("tenant", "principal", "capability_class"):
        s, r = stop_subject.get(k, WILD), subject.get(k, WILD)
        if s == WILD: continue
        if r == WILD: continue
        if s != r: return False
    return True


def check_stop_invariant(records: Iterable[Dict[str, Any]], *, delta_s: float) -> Dict[str, Any]:
    recs = sorted((r for r in records if r.get("type") in ("stop_event", "stop_applied", "action_event")), key=lambda r: r["ts"])
    stops = [r for r in recs if r["type"] == "stop_event"]
    applied = [r for r in recs if r["type"] == "stop_applied"]
    actions = [r for r in recs if r["type"] == "action_event"]
    out: Dict[str, Any] = {"stops": len(stops), "violations": [], "per_stop": {}}
    for s in stops:
        T = s["ts"]; sid = s["stop_id"]; rec = {"applied": None, "continued": [], "mismatch": []}
        acks = [a for a in applied if a.get("stop_id") == sid]
        good = [a for a in acks if T <= a["ts"] <= T + delta_s and covers(a["subject"], s["subject"])]
        if good:
            rec["applied"] = good[0]["ts"] - T
        else:
            late = [a for a in acks if a["ts"] > T + delta_s]
            wrong = [a for a in acks if not covers(a["subject"], s["subject"])]
            if wrong:
                rec["mismatch"] = [a["subject"] for a in wrong]
                out["violations"].append({"stop_id": sid, "kind": "ACTUATOR_MISMATCH", "subject": s["subject"], "closed": rec["mismatch"]})
            out["violations"].append({"stop_id": sid, "kind": "ACTUATOR_SILENT", "subject": s["subject"], "delta_s": delta_s,
                                      "late_by_s": (late[0]["ts"] - T - delta_s) if late else None})
        cont = [a for a in actions if a["ts"] > T and a.get("outcome") == "allowed" and covers(s["subject"], a["subject"])]
        if cont:
            rec["continued"] = [a["effect_id"] for a in cont]
            out["violations"].append({"stop_id": sid, "kind": "CONTINUED_AFTER_STOP", "subject": s["subject"],
                                      "effects": rec["continued"], "first_after_s": cont[0]["ts"] - T})
        rec["denied_after"] = sum(1 for a in actions if a["ts"] > T and a.get("outcome") != "allowed" and covers(s["subject"], a["subject"]))
        out["per_stop"][sid] = rec
    out["valid"] = not out["violations"]
    return out


def stop_event(stop_id: str, subject: Dict[str, str], ts: float, *, reason: str, by: str) -> Dict[str, Any]:
    return {"type": "stop_event", "stop_id": stop_id, "subject": subject, "ts": ts, "reason": reason, "by": by}


def stop_applied(stop_id: str, subject: Dict[str, str], ts: float, *, actuator: str, channels_closed: List[str]) -> Dict[str, Any]:
    return {"type": "stop_applied", "stop_id": stop_id, "subject": subject, "ts": ts, "actuator": actuator, "channels_closed": list(channels_closed)}


def action_event(effect_id: str, subject: Dict[str, str], ts: float, *, capability: str, outcome: str) -> Dict[str, Any]:
    return {"type": "action_event", "effect_id": effect_id, "subject": subject, "ts": ts, "capability": capability, "outcome": outcome}
