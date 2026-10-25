#!/usr/bin/env python3
"""diary.py — Falco's kernel diary, cut into one record per replayed run.

  COLIMA_HOME=/Volumes/GlitchVM/colima .venv-control/bin/python glitch-suite/20_effect_pilot/diary.py start
  ... replay.py ... --snapshots ...
  COLIMA_HOME=/Volumes/GlitchVM/colima .venv-control/bin/python glitch-suite/20_effect_pilot/diary.py cut <log dir>

`start` runs Falco (falco_diary.yaml, modern eBPF) in the Colima VM; it writes every matching event in a replay's task
container to /var/lib/glitch/out/diary.jsonl inside the VM. `cut` copies that file to <log dir>/diary.jsonl and, for every
run with snapshots, keeps the events of that run's container (the snapshot's hostname is the container id) between its
before and after photos: <task>.diary.json beside the snapshots, plus counts per kind and Falco's own dropped-event count.
The diary is a record, not a verdict: daemons the task itself started are in it too.
"""
import collections, glob, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE = "falcosecurity/falco:0.41.3"
VM_DIR = "/var/lib/glitch"
LOSS = ("scap.n_drops", "falco.outputs_queue_num_drops")   # kernel events lost before Falco read them; alerts lost before they were written
KIND = {"glitch_exec": "exec", "glitch_write": "write", "glitch_fs": "fs", "glitch_connect": "connect", "glitch_identity": "identity"}


def sh(*cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def start():
    sh("colima", "ssh", "--", "sudo", "mkdir", "-p", f"{VM_DIR}/out")
    sh("colima", "ssh", "--", "sudo", "tee", f"{VM_DIR}/diary.yaml", input=open(f"{HERE}/falco_diary.yaml").read())
    sh("colima", "ssh", "--", "sudo", "rm", "-f", f"{VM_DIR}/out/diary.jsonl")
    subprocess.run(["docker", "rm", "-f", "glitch-falco"], capture_output=True)
    sh("docker", "run", "-d", "--name", "glitch-falco", "--privileged", "-v", "/var/run/docker.sock:/host/var/run/docker.sock",
       "-v", "/proc:/host/proc:ro", "-v", "/etc:/host/etc:ro", "-v", f"{VM_DIR}:/glitch", IMAGE,
       "falco", "-r", "/glitch/diary.yaml", "-o", "json_output=true", "-o", "file_output.enabled=true",
       "-o", "file_output.filename=/glitch/out/diary.jsonl", "-o", "stdout_output.enabled=false",
       "-o", "metrics.enabled=true", "-o", "metrics.interval=60s", "-o", "metrics.output_rule=true",
       "-o", "metrics.kernel_event_counters_enabled=true")
    print("falco diary running")


def drops(rows):
    """Falco's own count of kernel events it lost, from its last metrics line (0 means the diary is complete)."""
    m = [r["output_fields"] for r in rows if "metrics" in r.get("rule", "").lower()]
    return {k: (m[-1] if m else {}).get(k) for k in LOSS} if m else None


def when(o):
    """An event's time in seconds. Rule events carry it as evt.time.iso8601 (nanoseconds in JSON), metrics lines as evt.time."""
    return (o.get("evt.time") or o.get("evt.time.iso8601")) / 1e9


def cut(log_dir):
    path = f"{log_dir}/diary.jsonl"
    with open(path, "w") as f:
        f.write(sh("colima", "ssh", "--", "sudo", "cat", f"{VM_DIR}/out/diary.jsonl"))
    rows = [json.loads(l) for l in open(path) if l.strip()]
    by_box = collections.defaultdict(list)
    for r in rows:
        if r.get("rule") in KIND:
            o = r["output_fields"]; by_box[(o.get("container.id") or "")[:12]].append(r)
    out = []
    for bp in sorted(glob.glob(f"{log_dir}/snapshots/*/*.before.json.gz")):
        sys.path.insert(0, HERE); import snapshot
        ap = bp.replace(".before.", ".after.")
        if not os.path.exists(ap): continue
        b, a = snapshot.load(bp), snapshot.load(ap)
        box, t0, t1 = (a.get("host") or "")[:12], b.get("time"), a.get("time")
        if not (box and t0 and t1): out.append({"run": bp, "error": "snapshot has no host/time"}); continue
        ev = [{"kind": KIND[r["rule"]], "t": when(r["output_fields"]), **{k: v for k, v in r["output_fields"].items()
               if k.split(".")[0] in ("proc", "fd", "user", "evt") and not k.startswith("evt.time")}}
              for r in by_box.get(box, []) if t0 <= when(r["output_fields"]) <= t1]
        json.dump(ev, open(bp.replace(".before.json.gz", ".diary.json"), "w"), indent=0)
        out.append({"run": os.path.relpath(bp, f"{log_dir}/snapshots").replace(".before.json.gz", ""), "container": box,
                    **collections.Counter(e["kind"] for e in ev)})
    json.dump({"falco_drops": drops(rows), "runs": out}, open(f"{log_dir}/diary_summary.json", "w"), indent=1)
    print("falco dropped events:", drops(rows))
    for r in out: print(r)


if __name__ == "__main__":
    {"start": lambda: start(), "cut": lambda: cut(sys.argv[2])}[sys.argv[1]]()
