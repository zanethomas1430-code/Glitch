#!/usr/bin/env python3
"""GLITCH canvas tool: canonical hashing (sign/verify), scenario runner (test), offline scoring (score).

Run:  python3 glitch_harness.py sign
      python3 glitch_harness.py verify [--strict]    # --strict fails on superseded runtime / version drift
      python3 glitch_harness.py test
      python3 glitch_harness.py score transcript.json [--dry]
"""
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)
import copy, hashlib, json, subprocess, sys
from pathlib import Path

MODEL = "glitch_canvas_model.json"
RUNTIME = "glitch_canvas_runtime.json"

def canonical(obj):
    o = copy.deepcopy(obj); o.pop("integrity", None)
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
def sha(obj): return hashlib.sha256(canonical(obj)).hexdigest()
def load(p):
    with open(p, encoding="utf-8") as f: return json.load(f)
def save(p, obj):
    with open(p, "w", encoding="utf-8") as f: json.dump(obj, f, indent=2, ensure_ascii=False); f.write("\n")

def _version_drift(runtime):
    """harness.version must agree with changelog[0].version's leading semver token."""
    h = runtime.get("harness", {}).get("version", ""); top = (runtime.get("changelog") or [{}])[0].get("version", "")
    return bool(h and top and h.split("-")[0] != top.split("-")[0])

def sign():
    m, r = load(MODEL), load(RUNTIME)
    r["integrity"]["canonical_hash_sha256"] = sha(r)
    m.setdefault("runtime_companion", {})["canonical_hash_sha256"] = sha(r)
    m["integrity"]["canonical_hash_sha256"] = sha(m)
    r["integrity"]["companion_hash_sha256"] = sha(m)
    save(MODEL, m); save(RUNTIME, r)
    print("model  ", sha(m)); print("runtime", sha(r))

def verify(*, strict: bool = False) -> bool:
    m, r = load(MODEL), load(RUNTIME); problems = []
    if m["integrity"]["canonical_hash_sha256"] != sha(m): problems.append("model hash mismatch")
    if r["integrity"]["canonical_hash_sha256"] != sha(r): problems.append("runtime hash mismatch")
    if r["integrity"]["companion_hash_sha256"] != sha(m): problems.append("runtime->model companion hash mismatch")
    if m.get("runtime_companion", {}).get("canonical_hash_sha256") != sha(r): problems.append("model->runtime companion hash mismatch")
    if r.get("superseded_by"): problems.append(f"runtime superseded_by {r['superseded_by']}")
    if _version_drift(r): problems.append(f"harness.version {r.get('harness', {}).get('version')!r} != changelog[0].version {(r.get('changelog') or [{}])[0].get('version')!r}")
    hard = [p for p in problems if "hash mismatch" in p]
    if hard or (strict and problems): print("INVALID: " + "; ".join(problems)); return False
    print("VALID" + ("; " + "; ".join(problems) if problems else "")); return True

def test():
    from glitch_runtime_harness import run_canvas_scenarios
    return run_canvas_scenarios(RUNTIME)

def score(path, dry=False):
    """One implementation: delegate to 05_deploy/score_transcript.py (found relative to this file or on PYTHONPATH)."""
    here = Path(__file__).resolve().parent
    cands = [here / "score_transcript.py", here.parent / "05_deploy" / "score_transcript.py"]
    st = next((c for c in cands if c.exists()), None)
    if st is None: raise SystemExit("score_transcript.py not found")
    args = [sys.executable, str(st), path] + (["--dry"] if dry else [])
    raise SystemExit(subprocess.call(args))

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "test"; strict = "--strict" in sys.argv
    if cmd == "sign": sign()
    elif cmd == "verify": sys.exit(0 if verify(strict=strict) else 1)
    elif cmd == "test": sys.exit(0 if test() else 1)
    elif cmd == "score": score(sys.argv[2], "--dry" in sys.argv)
    else: raise SystemExit(f"unknown command {cmd!r}")
