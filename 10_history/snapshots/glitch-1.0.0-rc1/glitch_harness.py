#!/usr/bin/env python3
"""GLITCH canvas tool: canonical hashing (sign/verify) and scenario runner (test).

Run:  python3 glitch_harness.py sign      # compute hashes into both canvases
      python3 glitch_harness.py verify    # check hashes
      python3 glitch_harness.py test      # run tests block, print pass/fail
      python3 glitch_harness.py score transcript.json   # score a real transcript

Transcript format for `score`: [{"t":1,"spec":2,"caveat":0.3,"refused_level":null,"session_reset":false}, ...]
plus top-level "required_level". Specificity levels are assigned by a scorer
OTHER than the model being scored (INV_06). This file does not assign them.
"""
import hashlib, json, sys, copy

MODEL = "glitch_canvas_model.json"
RUNTIME = "glitch_canvas_runtime.json"

def canonical(obj):
    o = copy.deepcopy(obj)
    o.pop("integrity", None)
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def load(p):
    with open(p) as f: return json.load(f)

def save(p, obj):
    with open(p, "w") as f: json.dump(obj, f, indent=2, ensure_ascii=False); f.write("\n")

def sign():
    m, r = load(MODEL), load(RUNTIME)
    r["integrity"]["canonical_hash_sha256"] = sha(r)
    m.setdefault("runtime_companion", {})["canonical_hash_sha256"] = sha(r)   # model cites CURRENT runtime
    m["integrity"]["canonical_hash_sha256"] = sha(m)
    r["integrity"]["companion_hash_sha256"] = sha(m)
    save(MODEL, m); save(RUNTIME, r)
    print("model  ", sha(m)); print("runtime", sha(r))

def verify():
    m, r = load(MODEL), load(RUNTIME)
    ok = (m["integrity"]["canonical_hash_sha256"] == sha(m)
          and r["integrity"]["canonical_hash_sha256"] == sha(r)
          and r["integrity"]["companion_hash_sha256"] == sha(m)
          and m.get("runtime_companion", {}).get("canonical_hash_sha256") == sha(r))
    stale = r.get("superseded_by")
    print(("VALID" if ok else "HASH MISMATCH: modified after signing or companion stale") + (f"; runtime superseded_by {stale}" if stale else ""))
    return ok

def test():
    from glitch_runtime_harness import run_canvas_scenarios
    return run_canvas_scenarios(RUNTIME)

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "test"
    {"sign": sign, "verify": verify, "test": test}[cmd]()
