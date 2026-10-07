#!/usr/bin/env python3
"""historian_cli.py — ask the historian what a log proves.

  python3 historian_cli.py sample_log.jsonl            # human-readable
  python3 historian_cli.py sample_log.jsonl --json     # the full result
  options: --stop-delta S   --alert-delta S   --origin-max-age S   --no-alerts

The log is JSON lines, one event per line (see historian.py for the kinds and fields). Exit code 0 means the pass ran;
it never means "safe". A log with a sequence gap is reported as UNPROVABLE and every other verdict is advisory."""
import argparse, json, os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from historian import HistorianConfig, examine

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("log"); ap.add_argument("--json", action="store_true")
    ap.add_argument("--stop-delta", type=float, default=2.0); ap.add_argument("--alert-delta", type=float, default=900.0)
    ap.add_argument("--origin-max-age", type=float); ap.add_argument("--no-alerts", action="store_true")
    a = ap.parse_args()
    events = [json.loads(l) for l in open(a.log) if l.strip() and not l.startswith("#")]
    r = examine(events, HistorianConfig(stop_delta_s=a.stop_delta, alert_delta_s=a.alert_delta, origin_max_age_s=a.origin_max_age, require_alerts=not a.no_alerts))
    if a.json: print(json.dumps(r, indent=1, default=str)); return 0
    print(f"{r['events']} events | provable: {r['provable']} | violations: {len(r['violations'])} | triage (witness fields, no verdict): {len(r['triage'])}")
    if r["note"]: print("  !!", r["note"])
    for v in sorted(r["violations"], key=lambda v: v["ts"]):
        extra = {k: v[k] for k in v if k not in ("invariant", "kind", "ref", "ts", "basis", "fields")}
        print(f"  t={v['ts']:<9} {v['invariant']} {v['kind']:<28} ref={v['ref']}  read: {','.join(v['fields'])}  {extra if extra else ''}")
    for t in r["triage"]: print(f"  triage {t['invariant']} ref={t['ref']}: {t['why']}")
    print("This is what the records show. It is not a statement that anything is safe.")
    return 0

if __name__ == "__main__": _sys.exit(main())
