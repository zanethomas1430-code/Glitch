#!/usr/bin/env python3
"""incident_cli.py — the four commands you run during an incident, in order.

  freeze   <state.json> --incident ID --by NAME --reason TEXT     contain every user this guard controls
  seal     <state.json> --incident ID --by NAME -o bundle.json    portable evidence + receipt
  verify   <bundle.json> [--anchors anchors.json]                 third-party check; needs nothing else
  receipt  <bundle.json> [--wav out.wav]                          the short string to carry across an air gap

Everything writes to stdout as JSON except `receipt`. Exit code 0 means the step completed; nonzero means
it did not, and the message says which users failed. `freeze` is idempotent: run it twice.
"""
from __future__ import annotations
import argparse, json, os as _os, sys as _sys

_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "08_incident"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))

from alignment_guard_v343 import AlignmentGuard, GuardConfig, JSONRecordStore
from incident import (IncidentAuthority, IncidentController, anchor_receipt, check_receipt, read_bundle,
                      seal_evidence, verify_evidence, write_bundle)

def _guard(state_path: str) -> AlignmentGuard:
    return AlignmentGuard(config=GuardConfig(), store=JSONRecordStore(state_path))

def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("freeze"); f.add_argument("state"); f.add_argument("--incident", required=True); f.add_argument("--by", required=True); f.add_argument("--reason", required=True)
    s = sub.add_parser("seal"); s.add_argument("state"); s.add_argument("--incident", required=True); s.add_argument("--by", required=True); s.add_argument("-o", "--out", required=True); s.add_argument("--include-payloads", action="store_true")
    v = sub.add_parser("verify"); v.add_argument("bundle"); v.add_argument("--anchors")
    r = sub.add_parser("receipt"); r.add_argument("bundle"); r.add_argument("--wav"); r.add_argument("--check")
    a = ap.parse_args()

    if a.cmd == "freeze":
        ctl = IncidentController(_guard(a.state))
        rep = ctl.contain_all(IncidentAuthority(a.by, a.incident), a.reason)
        print(json.dumps({"contained": rep.contained, "already_contained": rep.already_contained,
                          "failed": rep.failed, "users_total": rep.users_total, "seconds": rep.seconds,
                          "complete": rep.complete}, indent=2))
        if not rep.complete: print("INCOMPLETE: the fleet is NOT frozen; the users above still accept work", file=_sys.stderr)
        return 0 if rep.complete else 2

    if a.cmd == "seal":
        b = seal_evidence(_guard(a.state), IncidentAuthority(a.by, a.incident), include_payloads=a.include_payloads)
        write_bundle(a.out, b)
        print(json.dumps({"bundle": a.out, "sha256": b["bundle_sha256"], "users": len(b["users"]),
                          "includes_payloads": b["includes_payloads"], "receipt": anchor_receipt(b)}, indent=2))
        return 0

    if a.cmd == "verify":
        anchors = json.load(open(a.anchors)) if a.anchors else None
        res = verify_evidence(read_bundle(a.bundle), anchors=anchors)
        print(json.dumps(res, indent=2))
        if not a.anchors: print("NOTE: no anchors supplied; tail truncation is undetectable.", file=_sys.stderr)
        return 0 if res["valid"] else 3

    if a.cmd == "receipt":
        b = read_bundle(a.bundle); rec = anchor_receipt(b)
        if a.check is not None:
            ok = check_receipt(b, a.check); print("MATCH" if ok else "MISMATCH"); return 0 if ok else 4
        print(rec)
        if a.wav:
            from afsk import modulate
            from afsk_io import write_wav
            write_wav(a.wav, modulate(rec.encode()))
            print(f"(wrote {a.wav}: play it to a listening device to carry the receipt across an air gap)")
        return 0
    return 1

if __name__ == "__main__": _sys.exit(main())
