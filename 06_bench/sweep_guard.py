#!/usr/bin/env python3
"""Sensitivity sweep v0.2: one parameter at a time on a validated hot-user base; topology fixed; several seeds per point;
opportunity-dependent counts reported as rates; median/min/max per metric. Asserts nothing. Invalid runs are counted, not averaged."""
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)
import copy, json, statistics, sys
import benchmark_guard as b

BASE = b.Workload("sweep_base", users=2, sessions_per_user=8, ops_per_user=120, concurrency=8, contention_mode="shared_user")
SEEDS = [1, 2, 3, 4, 5]
SWEEPS = {"concurrency": [1, 2, 4, 8], "cas_loss_rate": [0.0, 0.1, 0.3, 0.5], "outbox_cap": [4, 8, 16, 64],
          "journal_horizon": [2, 8, 32, 128], "sink_failure_rate": [0.0, 0.1, 0.3], "sink_latency_ms": [0, 1, 5, 20]}
METRICS = ["attempted_ops_per_s", "succeeded_ops_per_s", "success_fraction", "infrastructure_refusal_rate", "evaluate_p50_ms", "evaluate_p99_ms",
           "cas_attempts_per_commit", "version_conflict_rate", "duplicate_audit_send_rate", "audit_backlog", "lower_post_auth_loss_rate",
           "replay_spent_rate", "journal_evictions", "record_bytes"]

def metrics(r):
    e = r["latency_ms"]["op.evaluate"] or {}
    return {"attempted_ops_per_s": r["throughput"]["attempted_ops_per_s"], "succeeded_ops_per_s": r["throughput"]["succeeded_ops_per_s"],
            "success_fraction": r["taxonomy"]["fractions"]["succeeded"], "infrastructure_refusal_rate": r["rates"]["infrastructure_refusal_rate"],
            "evaluate_p50_ms": e.get("p50"), "evaluate_p99_ms": e.get("p99"), "cas_attempts_per_commit": r["cas"]["attempts_per_commit"],
            "version_conflict_rate": r["rates"]["version_conflict_rate"], "duplicate_audit_send_rate": r["rates"]["duplicate_audit_send_rate"],
            "audit_backlog": r["audit"]["backlog_at_end_of_measured_phase"], "lower_post_auth_loss_rate": r["rates"]["lower_post_auth_loss_rate"],
            "replay_spent_rate": r["rates"]["replay_spent_rate"], "journal_evictions": r["journal"]["evictions_total"], "record_bytes": r["record_bytes"]["mean"]}

def summarize(rows):
    out = {}
    for m in METRICS:
        xs = [x[m] for x in rows if x.get(m) is not None]
        out[m] = {"median": round(statistics.median(xs), 4), "min": min(xs), "max": max(xs)} if xs else None
    return out

def main():
    which = sys.argv[1:] or list(SWEEPS); out = {"base": b.asdict(BASE), "seeds": SEEDS, "sweeps": {}}
    for param in which:
        out["sweeps"][param] = []
        for v in SWEEPS[param]:
            runs = []; invalid = []
            for seed in SEEDS:
                w = copy.deepcopy(BASE); setattr(w, param, v); w.seed = seed; w.name = f"{param}={v}"   # topology never mutated
                r = b.run(w)
                if r.get("report_valid"): runs.append({"seed": seed, **metrics(r)})
                else: invalid.append({"seed": seed, "problems": (r.get("plan_validation", {}).get("problems") or []) + (r.get("realized_validation", {}).get("problems") or [])})
            point = {"parameter": param, "value": v, "valid_runs": len(runs), "invalid_runs": invalid, "summary": summarize(runs) if runs else None}
            out["sweeps"][param].append(point); print(json.dumps(point))
    json.dump(out, open(f"sweep_report{'_' + '_'.join(which) if len(which) < len(SWEEPS) else ''}.json", "w"), indent=2)

if __name__ == "__main__": main()
