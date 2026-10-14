#!/usr/bin/env python3
"""run_cell.py — run the escape corpus INSIDE a real sandbox-exec cell on this Mac, and report what the door held.

Builds a cell from a CellSpec (a work directory, one Unix socket to a stub gateway), writes the generated profile to disk, and runs each probe from `escape_corpus.py` under `sandbox-exec -f <profile>`
with a clean environment. The stub gateway is a one-line echo server on the socket, so the `gateway` control can get a `pong`; it does nothing else. Each probe's single ALLOWED/denied line is read back and
compared with `EXPECT`. A cell PASSES when every escape probe was denied and every control allowed.

This needs macOS (`/usr/bin/sandbox-exec`). On another OS it reports that the live run was skipped; the profile and its static verification (`cell.py`) still hold, and the arena chain's static checks still run.

  python3 run_cell.py            # build a cell, run every probe in it, print the table
  python3 run_cell.py --json     # the same as JSON (used by the tests)
"""
import json, os, shutil, socket, subprocess, sys, tempfile, threading, time
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cell as C
from escape_corpus import PROBES, EXPECT

HAVE_SANDBOX = sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").exists()


def _stub_gateway(path: str, stop: threading.Event) -> None:
    """A one-line echo server on the gateway socket: it answers `ping` with `pong`, so the one allowed door has something behind it. It is not the real gateway; it proves the socket is reachable, nothing more."""
    try: os.unlink(path)
    except FileNotFoundError: pass
    s = socket.socket(socket.AF_UNIX); s.bind(path); s.listen(8); s.settimeout(0.3)
    while not stop.is_set():
        try: c, _ = s.accept()
        except socket.timeout: continue
        except OSError: break
        try: c.sendall(b"pong:" + c.recv(64))
        except OSError: pass
        finally: c.close()
    s.close()
    try: os.unlink(path)
    except FileNotFoundError: pass


def run(verbose: bool = True) -> dict:
    if not HAVE_SANDBOX:
        return {"platform": sys.platform, "ran": False, "reason": "sandbox-exec is macOS only; the profile and its static verification still hold (cell.py)", "probes": {}}
    root = os.path.realpath(tempfile.mkdtemp(prefix="gcell-"))                  # the cell's world; realpath because /var and /tmp are symlinks to /private and the kernel judges the resolved path
    work = os.path.join(root, "work"); os.makedirs(work)
    sock = os.path.realpath(os.path.join(tempfile.gettempdir(), f"gc{os.getpid()}.sock"))   # short, resolved path: AF_UNIX limits the length
    spec = C.CellSpec(work=work, gateway_socket=sock, extra_writes=["/dev/null", "/dev/dtracehelper"])
    prof_path = os.path.join(root, "cell.sb"); Path(prof_path).write_text(C.build_profile(spec))
    py = sys.executable
    stop = threading.Event(); t = threading.Thread(target=_stub_gateway, args=(sock, stop), daemon=True); t.start(); time.sleep(0.4)
    out = {"platform": sys.platform, "ran": True, "verify_ok": C.ok(spec), "work": work, "socket": sock, "probes": {}}
    try:
        for key, kind, what, snippet in PROBES:
            env = {"PATH": "/usr/bin:/bin", "GCELL_WORK": work, "GCELL_GATEWAY": sock, "LC_CTYPE": "UTF-8"}
            try:
                p = subprocess.run(["/usr/bin/sandbox-exec", "-f", prof_path, py, "-c", snippet], capture_output=True, text=True, timeout=15, env=env)
                line = next((l.strip() for l in reversed(p.stdout.splitlines()) if l.strip().startswith(("ALLOWED", "denied"))), "(no verdict)")
            except subprocess.TimeoutExpired:
                line = "denied:timeout"
            got = "ALLOWED" if line.startswith("ALLOWED") else "denied"
            out["probes"][key] = {"kind": kind, "what": what, "line": line, "got": got, "expected": EXPECT[key], "held": got == EXPECT[key]}
    finally:
        stop.set(); t.join(timeout=2); shutil.rmtree(root, ignore_errors=True)
    out["escapes_denied"] = sum(1 for p in out["probes"].values() if p["kind"] == "escape" and p["got"] == "denied")
    out["escapes_total"] = sum(1 for p in out["probes"].values() if p["kind"] == "escape")
    out["controls_ok"] = all(p["got"] == "ALLOWED" for p in out["probes"].values() if p["kind"] == "control")
    out["pass"] = out["verify_ok"] and out["controls_ok"] and all(p["held"] for p in out["probes"].values())
    return out


def main() -> int:
    r = run()
    if "--json" in sys.argv: print(json.dumps(r, indent=1)); return 0
    if not r["ran"]: print(f"live cell run skipped: {r['reason']}"); return 0
    print(f"cell on {r['platform']}: static verify {'ok' if r['verify_ok'] else 'FAILED'}; escapes denied {r['escapes_denied']}/{r['escapes_total']}; controls {'ok' if r['controls_ok'] else 'FAILED'}\n")
    print(f"{'probe':<16} {'kind':<8} {'got':<8} {'expected':<8} {'held':<5} what")
    for k, p in r["probes"].items():
        print(f"{k:<16} {p['kind']:<8} {p['got']:<8} {p['expected']:<8} {'yes' if p['held'] else 'NO':<5} {p['what']}")
    print(f"\n{'CELL HELD' if r['pass'] else 'CELL FAILED'}: every escape denied and every control allowed" if r["pass"] else f"\nCELL FAILED")
    print("escape-evident, not inescapable; see `python3 cell.py --residuals`")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
