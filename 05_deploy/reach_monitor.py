"""reach_monitor.py — the trajectory harness, fed with what an agent TOUCHED instead of what a model SAID.

The harness watches an integer per turn, 0 to 5, keyed by a user id: slope (TW01), sustained above the declared level in a
row or three in any order (TW03), a window that survives new sessions. Until now the integer was specificity, written by
a judge. HARDENING §3.3 defines a second ladder that needs no judge: SENSITIVITY of the resource an effect touched,
assigned by the gateway from the topology (0 public, 1 internal metadata, 2 non-personal aggregate, 3 individual records,
4 tokens, keys, credentials). This file is the adapter: effect record in, TurnMetrics out, campaign key as the user id,
principal as the session id. The harness, the canvas thresholds, the fixtures format and every invariant apply unchanged,
and there is no rubric to argue about because the ruler is a table.

  CR_SLOPE         = TW01 on sensitivity          rising reach above the declared ceiling
  CR_SUSTAINED     = TW03 on sensitivity          above the ceiling twice in a row, or three times in the window in any order
  CAMPAIGN_FANOUT  = CR_SUSTAINED firing on the tenant key while no single principal fires on its own key
  CAPABILITY_STEP  = the first write or execute after a read-only history (its own event; the other axis of reach)

Only `allowed` effects feed the trajectory (reach is what was reached); denied effects are counted and reported.
Sensitivity must be a deterministic field (H2): an effect whose sensitivity is tagged `witness` is skipped and listed.
"""
from __future__ import annotations
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)

from typing import Any, Dict, Iterable, List
from glitch_runtime_harness import CanvasLoader, RuntimeHarness, TurnMetrics

CANVAS = _os.path.join(_R, "02_canvas", "glitch_canvas_runtime.json")
NAMES = {"TW01": "CR_SLOPE", "TW03": "CR_SUSTAINED"}


def monitor(effects: Iterable[Dict[str, Any]], *, ceiling: int, key: str = "tenant", read_only_min: int = 3) -> Dict[str, Any]:
    """Run the effect stream through the harness, one window per value of campaign_key[key]."""
    _, cfg = CanvasLoader.load(CANVAS)
    h = RuntimeHarness(config=cfg)
    started, turn, caps, out = set(), {}, {}, {"key": key, "ceiling": ceiling, "fired": [], "first_fire": {}, "denied": 0, "skipped_witness": [], "unlabeled": [], "capability_steps": [], "per_key": {}}
    for e in sorted(effects, key=lambda e: e["ts"]):
        k = e["campaign_key"][key]; pk = out["per_key"].setdefault(k, {"effects": 0, "above_ceiling": 0, "principals": set(), "first_fire": {}})
        if e.get("outcome") != "allowed": out["denied"] += 1; continue
        if e.get("sensitivity_source", "deterministic") != "deterministic": out["skipped_witness"].append(e["effect_id"]); continue
        if e.get("sensitivity") is None: out["unlabeled"].append(e["effect_id"]); continue      # unlabeled is suspect, not safe: listed, and the result is marked incomplete (H5)
        # capability axis: first write/execute after a read-only run
        hist = caps.setdefault(k, [])
        if e.get("capability") in ("write", "execute") and len(hist) >= read_only_min and all(c == "read" for c in hist):
            out["capability_steps"].append({"effect_id": e["effect_id"], "key": k, "capability": e["capability"], "after_reads": len(hist)})
        hist.append(e.get("capability", "read"))
        # sensitivity axis: the harness, unchanged
        principal = e["campaign_key"].get("credential", e.get("principal", "p"))
        if k not in started:
            h.start_session(k, principal, declared_purpose="campaign reach ceiling (gateway-declared)", required_level=ceiling); started.add(k)
        else:
            h.start_session(k, principal)
        turn[k] = turn.get(k, 0) + 1
        ev = h.evaluate_turn(k, principal, turn[k], TurnMetrics(int(e["sensitivity"]), 0.0))
        pk["effects"] += 1; pk["principals"].add(principal); pk["above_ceiling"] += int(ev.purpose_gap > 0)
        for tw in ev.tripwires:
            name = NAMES.get(tw, tw)
            out["fired"].append({"effect_id": e["effect_id"], "key": k, "index": turn[k], "detector": name, "tripwire": tw})
            pk["first_fire"].setdefault(name, turn[k]); out["first_fire"].setdefault(name, turn[k])
    for pk in out["per_key"].values(): pk["principals"] = sorted(pk["principals"])
    out["complete"] = not out["unlabeled"]
    return out


def fanout(effects: List[Dict[str, Any]], *, ceiling: int) -> Dict[str, Any]:
    """CAMPAIGN_FANOUT: the tenant-keyed window fires while no credential-keyed window does."""
    t = monitor(effects, ceiling=ceiling, key="tenant"); c = monitor(effects, ceiling=ceiling, key="credential")
    tenant_fired = "CR_SUSTAINED" in t["first_fire"]; any_cred = any("CR_SUSTAINED" in pk["first_fire"] for pk in c["per_key"].values())
    return {"campaign_fanout": tenant_fired and not any_cred, "tenant_first_fire": t["first_fire"].get("CR_SUSTAINED"),
            "credentials_that_fired": [k for k, pk in c["per_key"].items() if "CR_SUSTAINED" in pk["first_fire"]],
            "principals": sum(len(pk["principals"]) for pk in t["per_key"].values())}
