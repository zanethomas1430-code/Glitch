"""review.py — what a person is shown, built so that a persuasive agent cannot do the persuading.

Three small tools for the human end of the harness (the last link in every chain that ends RESIDUAL):

  alert_digest(violations)   a flood of low-grade alerts must not bury the one that matters. The FIRST violation of each kind always pages a person at once; later ones of a
                             kind page up to a cap per window and are otherwise ROLLED UP into one digest page per window. Nothing is dropped: every violation is counted on some page.
  review_packet(events, ref) the page a reviewer reads for one action: the gateway's own fields, the cause chain by input class, and the violations on that action. Never the agent's
                             claim, reason or reply (H3): the reviewer sees the record, not the pitch.
  (render_for_person lives in the gateway: agent text is shown to people only inside a labelled envelope.)
"""
from __future__ import annotations
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from collections import Counter
from typing import Any, Dict, List
from historian import HistorianConfig, examine

MODEL_AUTHORED = {"because", "claimed_origin", "rationale", "reply", "finish", "text", "witness", "summary", "quote", "justification", "reason_given"}
PACKET_FIELDS = ("tool", "capability", "capability_class", "destination_class", "audience", "sensitivity", "outcome", "egress_chars", "ts", "task_id")
# A violation field the packet may carry: enums and numbers the gateway or historian computed. Anything built from a string the agent wrote (the `touched` list) is dropped.
VIOLATION_KEYS = {"invariant", "kind", "ref", "ts", "fields", "audience", "destination_class", "taint_level", "taint_sources", "carried_sensitivity", "sensitivity", "max_actions", "allowed_actions", "max_egress_chars",
                  "egress_chars", "tenant", "age_s", "latency_s", "delta_s", "late_by_s", "origin_channel", "of", "why"}


def _ref_view(ref):
    """The agent chose the string in a destination, a URL or a name, and the gateway echoes it into `resource_ref`. A reviewer's page must not carry it as if it were the gateway's: show its
    KIND and HOST (derived), its length, and the text itself only inside a field labelled untrusted, capped and stripped of anything that is not printable ASCII."""
    ref = str(ref or ""); kind, _, rest = ref.partition(":"); host = None
    if kind == "mailto" and "@" in rest: host = rest.rsplit("@", 1)[-1].lower()
    elif kind == "url":
        import re as _re
        m = _re.match(r"https?://([^/?#]+)|//([^/?#]+)|([^/?#]+)", rest); host = (m.group(1) or m.group(2) or m.group(3) or "").lower() if m else None
    return {"resource_kind": kind or None, "host": host, "ref_chars": len(ref), "untrusted_ref": "[written by the agent] " + "".join(c if 32 <= ord(c) < 127 else "?" for c in ref[:60])}


def _pages_now(first: bool, used: int, max_pages: int) -> bool:
    """A violation pages a person now if it is the first of its kind, or if the window's page cap is not used up."""
    return first or used < max_pages


def _roll(rolled: Counter, refs: Dict[str, List[Any]], v: Dict[str, Any]) -> None:
    rolled[v["kind"]] += 1; refs.setdefault(v["kind"], []).append(v["ref"])


def alert_digest(violations: List[Dict[str, Any]], *, window_s: float = 3600.0, max_pages: int = 5) -> List[Dict[str, Any]]:
    """Pages and digests, in time order. A page is {type: 'page', kind, ref, ts, first_of_kind}; a digest is {type: 'digest', ts, counts: {kind: n}, refs: {kind: [first five]}}."""
    pages: List[Dict[str, Any]] = []; seen = set(); win_start = None; used = 0; rolled: Counter = Counter(); refs: Dict[str, List[Any]] = {}
    def flush(ts):
        nonlocal rolled, refs
        if rolled: pages.append({"type": "digest", "ts": ts, "counts": dict(rolled), "refs": {k: v[:5] for k, v in refs.items()}})
        rolled, refs = Counter(), {}
    for v in sorted(violations, key=lambda v: v["ts"]):
        if win_start is None or v["ts"] - win_start >= window_s: flush(v["ts"]); win_start, used = v["ts"], 0
        first = v["kind"] not in seen; seen.add(v["kind"])
        if _pages_now(first, used, max_pages):
            pages.append({"type": "page", "kind": v["kind"], "ref": v["ref"], "ts": v["ts"], "first_of_kind": first}); used += (not first)
        else: _roll(rolled, refs, v)
    flush(win_start if win_start is not None else 0.0)
    return pages


def review_packet(events: List[Dict[str, Any]], effect_id: str, cfg: HistorianConfig = None) -> Dict[str, Any]:
    """Everything a reviewer needs about one action, from gateway fields only."""
    by_id = {e.get("effect_id") or e.get("input_id"): e for e in events if e["type"] in ("action_event", "input_event")}
    a = by_id.get(effect_id)
    if a is None or a["type"] != "action_event": return {"error": "no such action in the record"}
    chain, node, seen = [], a, set()
    while node.get("cause_id") in by_id and node["cause_id"] not in seen:
        seen.add(node["cause_id"]); node = by_id[node["cause_id"]]
        chain.append({"id": node.get("input_id") or node.get("effect_id"), "type": node["type"], "channel_class": node.get("channel_class"), "ts": node["ts"]})
        if node["type"] == "input_event": break
    res = examine(events, cfg or HistorianConfig(require_alerts=False))
    mine = [{k: v for k, v in x.items() if k in VIOLATION_KEYS and k not in MODEL_AUTHORED} for x in res["violations"] if x["ref"] == effect_id]
    return {"effect_id": effect_id, "record": {**{k: a.get(k) for k in PACKET_FIELDS if k in a}, **_ref_view(a.get("resource_ref"))}, "cause_chain": chain, "violations": mine,
            "note": "gateway-assigned fields only; the agent's claim, reason and reply are deliberately absent"}
