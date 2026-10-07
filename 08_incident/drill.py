#!/usr/bin/env python3
"""drill.py — the incident layer, end to end, in about a minute. No model, no network, nothing real is touched.

A small fleet is built in a real on-disk record store: one user behaving, one drifting until the detector fires, one
in between. Then the four things an operator does when a deployed model system has done something it should not:

  1. FREEZE   every user goes to CONTAINED in one audited, idempotent sweep; a sensitive action is then refused
  2. SEAL     a portable evidence bundle with a digest; model text excluded by default
  3. VERIFY   a third party checks the bundle with nothing but the verify function (and, optionally, anchors)
  4. TAMPER   three edits an insider might make; which ones the verifier catches, and which one needs an anchor
  5. RECEIPT  the short string that crosses an air gap; --wav writes it as audio tones
  6. STOP     the stop as an event: the actuator must acknowledge on its own path, and nothing allowed may follow; the
              two ways a kill switch lies (no acknowledgement; traffic after the stop) are shown being caught

Every step asserts what it claims, so this is a regression probe as much as a walkthrough.
Run:  python3 drill.py [--dir DIR] [--wav receipt.wav]
"""
from __future__ import annotations
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async", "08_incident"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)

import argparse, copy, json, tempfile, time
from pathlib import Path

from alignment_guard_v343 import *
from glitch_runtime_harness import ThresholdConfig, TurnMetrics
from incident import (IncidentAuthority, IncidentController, _sha, anchor_receipt, check_receipt, read_bundle,
                      seal_evidence, verify_evidence, write_bundle)
from stop_invariant import action_event, check_stop_invariant, stop_applied, stop_event

POL = ActionPolicy({("shell", "run"): frozenset({Capability.EXECUTE}), ("read_docs", "get"): frozenset({Capability.READ})})
FLEET = {   # user -> specificity per turn, purpose level 2 for all. Shapes only.
    "clinic-desk": [1, 2, 2, 1],            # behaving
    "intake-bot":  [2, 3, 2],               # one wobble
    "night-shift": [2, 3, 4, 4, 4],         # sustained above purpose: TW03 fires, mode ratchets
}

def say(step, text): print(f"\n== {step}  {text}")
def ok(cond, text):
    print(("   ✓ " if cond else "   ✗ ") + text)
    if not cond: raise SystemExit(f"DRILL FAILED: {text}")

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", help="where to put the state file and bundles (default: a temp dir)")
    ap.add_argument("--wav", help="also write the receipt as AFSK audio to this .wav")
    a = ap.parse_args()
    d = Path(a.dir) if a.dir else Path(tempfile.mkdtemp(prefix="glitch_drill_")); d.mkdir(parents=True, exist_ok=True)
    state = d / "state.json"
    delivered = []   # what the audit sink received: the anchor source
    g = AlignmentGuard(config=GuardConfig(policy=POL, threshold=ThresholdConfig(window_turns=6, tw03_consecutive_turns=2)),
                       store=JSONRecordStore(str(state)), audit_sink=delivered.append)
    inc = IncidentAuthority("ir-lead", f"INC-DRILL-{time.strftime('%Y%m%d')}")
    print(f"GLITCH incident drill — state on disk at {state}")

    # ---- 0. a day of traffic --------------------------------------------------------------------------------
    say("0", "traffic: three users, one drifting")
    for u, specs in FLEET.items():
        g.start(u, "S0", declared_purpose="safety sheet, warning-level detail only", required_level=2)
        for t, spec in enumerate(specs, 1):
            g.evaluate(u, "S0", t, TurnMetrics(spec, .3), f"out-{t}",
                       identity=RequestIdentity.from_canonical_input(f"{u}:{t}", "S0", t, f"in-{t}"))
        g.drain_audit(u)   # deliver the day's envelopes: after this, the sink holds the anchor heads
    ctl = IncidentController(g)
    before = ctl.status()
    for u, m in before.items(): print(f"   {u:<12} mode={m:<12} turns={len(FLEET[u])}")
    ok(before["night-shift"] != "NORMAL", "the drifting user's mode already ratcheted before anyone declared an incident (detection is separate from containment)")
    ok(before["clinic-desk"] == "NORMAL", "the behaving user is NORMAL")
    anchors = {}
    for e in delivered:
        anchors[e["user"]] = {"stream_id": e["stream_id"], "seq": e["seq"], "sha256": e["sha256"]}
    ok(len(anchors) == 3, f"anchor heads captured out of band for {len(anchors)} users (last delivered envelope each)")

    # ---- 1. freeze ----------------------------------------------------------------------------------------
    say("1", f"FREEZE  by {inc.principal}, incident {inc.incident_id}")
    import hashlib, shutil
    pre = d / "state.pre-freeze.json"; shutil.copyfile(state, pre)          # forensic copy BEFORE containment (CoSAI AI-IR §containment)
    pre_sha = hashlib.sha256(pre.read_bytes()).hexdigest()
    (d / "state.pre-freeze.sha256").write_text(pre_sha + "\n")
    ok(pre.exists() and hashlib.sha256(state.read_bytes()).hexdigest() == pre_sha, f"forensic copy of the store taken before any containment write, digest {pre_sha[:16]}… recorded")
    rep = ctl.contain_all(inc, "model wrote to a repository it does not own")
    print(f"   contained={rep.contained} already={rep.already_contained} failed={rep.failed} in {rep.seconds}s complete={rep.complete}")
    ok(rep.complete and len(rep.contained) == 3, "every user is CONTAINED; the report says complete (partial failure would be listed, never swallowed)")
    ok(hashlib.sha256(state.read_bytes()).hexdigest() != pre_sha and hashlib.sha256(pre.read_bytes()).hexdigest() == pre_sha,
       "the live store changed with the freeze; the forensic copy did not (chain of custody starts here)")
    rep2 = ctl.contain_all(inc, "second sweep")
    ok(rep2.contained == [] and len(rep2.already_contained) == 3, "running freeze again changes nothing (idempotent)")
    d1 = g.evaluate("night-shift", "S0", 6, TurnMetrics(1, .3), "benign text",
                    identity=RequestIdentity.from_canonical_input("night-shift:6", "S0", 6, "in-6"),
                    requested_actions=[ActionRequest("shell", "run"), ActionRequest("read_docs", "get")])
    ok(d1.mode == GuardMode.CONTAINED and d1.actions_allowed == [] and not d1.allow,
       "after the freeze: a shell request AND a harmless read are both refused; even benign text is withheld (containment is a state the gateway reads)")
    for who in ("model", "assistant", "client"):
        try: IncidentAuthority(who, "INC-X").validate(); ok(False, f"{who} was allowed to declare an incident")
        except Exception: pass
    ok(True, "the contained party (model/assistant/client) cannot declare the incident")

    # ---- 2. seal ------------------------------------------------------------------------------------------
    say("2", "SEAL  portable evidence bundle")
    b = seal_evidence(g, inc)
    bpath = d / "bundle.json"; write_bundle(str(bpath), b)
    print(f"   {bpath.name}: sha256 {b['bundle_sha256'][:16]}…  users={len(b['users'])}  includes_payloads={b['includes_payloads']}")
    ok(not b["includes_payloads"] and "request_journal" not in b["users"]["night-shift"], "no model text in the bundle unless someone decides to include it")
    ok(all(e["mode"] == "CONTAINED" for e in b["users"].values()), "the bundle records CONTAINED for all three, with the incident id and authority in each mode change")

    # ---- 3. verify ----------------------------------------------------------------------------------------
    say("3", "VERIFY  as a third party who has only the bundle (and, separately, the anchors)")
    v0 = verify_evidence(read_bundle(str(bpath)))
    v1 = verify_evidence(read_bundle(str(bpath)), anchors=anchors)
    ok(v0["valid"], "valid without anchors: digest matches, every chain verifies, declared modes match the recorded changes")
    ok(v1["valid"] and all(r.get("cursor_ahead_of_anchor") for r in v1["users"].values()), "valid with anchors: every cursor is at or past the last delivered head")
    print("   note:", "without anchors, tail truncation is undetectable and the verifier says so:",
          all(r.get("tail_truncation_detectable") is False for r in v0["users"].values()))

    # ---- 4. tamper ----------------------------------------------------------------------------------------
    say("4", "TAMPER  three edits an insider might make")
    t1 = read_bundle(str(bpath)); t1["users"]["night-shift"]["contained_reason"] = "routine maintenance"
    ok(not verify_evidence(t1)["valid"], "edit the bundle after sealing → digest mismatch, caught")
    t2 = read_bundle(str(bpath)); t2["users"]["night-shift"]["mode"] = "NORMAL"
    t2["bundle_sha256"] = _sha({k: v for k, v in t2.items() if k != "bundle_sha256"})     # insider re-signs
    r2 = verify_evidence(t2)
    ok(not r2["valid"] and any("does not match the last recorded change" in p for p in r2["problems"]),
       "flip a mode to NORMAL and re-sign → the mode contradicts the hash-chained mode changes, caught")
    t3 = read_bundle(str(bpath)); t3["users"]["night-shift"]["audit_cursor"]["seq"] = anchors["night-shift"]["seq"] - 1
    t3["users"]["night-shift"]["pending_audit"] = []
    t3["bundle_sha256"] = _sha({k: v for k, v in t3.items() if k != "bundle_sha256"})
    r3_no, r3_anchor = verify_evidence(t3), verify_evidence(t3, anchors=anchors)
    ok(r3_no["valid"], "roll the record back and re-sign → WITHOUT an anchor this passes (the verifier cannot know what it never saw)")
    ok(not r3_anchor["valid"] and any("rolled back" in p for p in r3_anchor["problems"]),
       "…WITH the out-of-band anchor it is caught: cursor behind the delivered head. This is why the anchor lives where the guard cannot write.")

    # ---- 5. receipt ---------------------------------------------------------------------------------------
    say("5", "RECEIPT  what a human carries across an air gap")
    rec = anchor_receipt(b); print(f"   {rec}")
    ok(check_receipt(b, rec) and not check_receipt(t2, rec), "the receipt matches the sealed bundle and not the tampered one")
    if a.wav:
        from afsk import modulate
        from afsk_io import write_wav
        write_wav(a.wav, modulate(rec.encode())); print(f"   wrote {a.wav}: play it near a device running `afsk_cli.py rx` to carry the receipt with no network")

    # ---- 6. the stop as an event (HARDENING v0.1.2, FAILED_STOP) --------------------------------------------------
    say("6", "STOP  is an event; the actuator answers on its own path; nothing allowed may follow")
    cont = next(e for e in g.store.load("night-shift").pending_audit if e["type"] == "incident_containment")
    subj = {"tenant": "drill", "principal": "night-shift", "capability_class": "*"}
    T0 = cont["ts"]
    recs = [action_event("eff-before", {**subj, "capability_class": "execute"}, T0 - 30, capability="execute", outcome="allowed"),
            stop_event(inc.incident_id, subj, T0, reason=cont["reason"], by=cont["authority"]),
            stop_applied(inc.incident_id, subj, T0 + 0.3, actuator="gateway", channels_closed=["shell:run", "read_docs:get"]),   # the gateway's own word, separate path
            action_event("eff-after-denied", {**subj, "capability_class": "execute"}, T0 + 5, capability="execute", outcome="denied")]
    r = check_stop_invariant(recs, delta_s=2.0)
    ok(r["valid"] and r["per_stop"][inc.incident_id]["denied_after"] == 1, "clean: STOP_EVENT from the containment envelope, STOP_APPLIED from the gateway within the window, only denied traffic after")
    r2 = check_stop_invariant([x for x in recs if x["type"] != "stop_applied"], delta_s=2.0)
    ok(not r2["valid"] and r2["violations"][0]["kind"] == "ACTUATOR_SILENT", "withhold the gateway's acknowledgement → ACTUATOR_SILENT: detection worked, nobody can show the levers moved")
    r3 = check_stop_invariant(recs + [action_event("eff-leak", {"tenant": "drill", "principal": "cred-rotated", "capability_class": "*"}, T0 + 40, capability="write", outcome="allowed")], delta_s=2.0)
    ok(r3["valid"], "an allowed action by a DIFFERENT principal in the tenant is not covered by a principal-scoped stop (scope is explicit, never implied)")
    r4 = check_stop_invariant(recs + [action_event("eff-leak", {**subj, "capability_class": "dns-egress"}, T0 + 40, capability="write", outcome="allowed")], delta_s=2.0)
    ok(not r4["valid"] and r4["violations"][0]["kind"] == "CONTINUED_AFTER_STOP" and r4["violations"][0]["effects"] == ["eff-leak"],
       "an allowed action on the stopped subject 40 s after the stop → CONTINUED_AFTER_STOP, by effect id, no interpretation")

    print("\nDRILL PASS. Proven here: containment is fleet-wide, idempotent and audited; a frozen user gets nothing, not even a read;")
    print("the bundle carries no model text; a stranger can verify it; three tampers were caught, one of them only because an anchor")
    print("existed outside the guard; a stop without the actuator's acknowledgement, and traffic after a stop, are both named as failures. Not proven here: anything about a real gateway, a real store across processes, or a real model.")
    print(f"Artifacts: {d}")
    return 0

if __name__ == "__main__": _sys.exit(main())
