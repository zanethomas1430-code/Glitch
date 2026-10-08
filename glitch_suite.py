#!/usr/bin/env python3
"""glitch_suite.py — the one runner for the GLITCH 1.0.2 + ALIGNMENT_GUARD v3.4.3 suite.

Every layer's tests, probes, scenarios and self-validating benchmarks run from here, in one process tree, with one
summary table, one exit code and one JSON report. Each step runs exactly the way its layer was validated: as a
subprocess in its own folder, with the same PYTHONPATH run_all.sh used. Nothing here changes what any layer claims.

    python3 glitch_suite.py               # everything (about a minute)
    python3 glitch_suite.py --quick       # skip the heavy cost/fuzz steps
    python3 glitch_suite.py --full        # fuzz 200 sequences, compare three latencies x two seeds
    python3 glitch_suite.py --only 03,08  # steps whose id starts with 03 or 08
    python3 glitch_suite.py --list        # what would run
    python3 glitch_suite.py --strict      # a SKIP (missing optional dependency) counts as FAIL
    python3 glitch_suite.py --fail-fast   # stop at the first FAIL (run_all.sh's old default)

Statuses: PASS / FAIL are assertions. SKIP means an optional dependency is missing (the reason is printed).
INFO is a measurement or a listing that asserts nothing (cost numbers, the human-study kappa, the version history).
Exit code 0 only when nothing FAILed (and, under --strict, nothing SKIPped).

Portable: stdlib only, Python 3.9+, no GNU `timeout` (subprocess timeouts instead), works on macOS and Linux.
Optional dependencies, each gating only the steps that need it: fastapi+httpx (05a, 05b), numpy (08d, 08c),
pynacl (08c).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable
SUITE = "GLITCH 1.0.2 + ALIGNMENT_GUARD v3.4.3"
LAYER_DIRS = ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async")

if sys.version_info < (3, 9):
    sys.exit(f"glitch_suite.py needs Python 3.9+, found {platform.python_version()}")


# ---- step machinery ---------------------------------------------------------------------------------------------
class Step:
    def __init__(self, sid, title, cwd, cmd, check, *, needs=(), heavy=False, timeout=180, info=False, prepare=None):
        self.id, self.title, self.cwd, self.cmd, self.check = sid, title, cwd, cmd, check
        self.needs, self.heavy, self.timeout, self.info, self.prepare = tuple(needs), heavy, timeout, info, prepare


def env_for(cwd: Path) -> dict:
    e = os.environ.copy()
    e["PYTHONPATH"] = os.pathsep.join(str(ROOT / d) for d in LAYER_DIRS)
    e["PYTHONDONTWRITEBYTECODE"] = "1"
    return e


INTERP_PY = Path(os.environ.get("GLITCH_INTERP_PY") or ROOT.parent / ".venv-interp" / "bin" / "python")          # Python 3.10+ with torch, transformers and scikit-learn (16_interp/README.md); optional
INSPECT_PY = Path(os.environ.get("GLITCH_INSPECT_PY") or ROOT.parent / ".venv-inspect" / "bin" / "python")      # Python 3.10+ with inspect-ai installed (14_inspect/README.md); the rest of the suite does not need it


def module_available(mod: str) -> bool:
    if mod == "@interp":
        return INTERP_PY.exists() and subprocess.run([str(INTERP_PY), "-c", "import sklearn, numpy"], capture_output=True).returncode == 0
    if mod in ("@inspect", "@sdk", "@dojo"):
        imp = {"@inspect": "inspect_ai", "@sdk": "claude_agent_sdk", "@dojo": "agentdojo"}[mod]
        return INSPECT_PY.exists() and subprocess.run([str(INSPECT_PY), "-c", f"import {imp}"], capture_output=True).returncode == 0
    r = subprocess.run([PY, "-c", f"import {mod}"], capture_output=True, text=True)
    return r.returncode == 0


def run_cmd(cmd, cwd: Path, timeout: float):
    t0 = time.perf_counter()
    try:
        r = subprocess.run(cmd, cwd=str(cwd), env=env_for(cwd), capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr, time.perf_counter() - t0, False
    except subprocess.TimeoutExpired as ex:
        out = ex.stdout.decode() if isinstance(ex.stdout, bytes) else (ex.stdout or "")
        err = ex.stderr.decode() if isinstance(ex.stderr, bytes) else (ex.stderr or "")
        return 124, out, err, time.perf_counter() - t0, True


# ---- checks: (rc, stdout, stderr) -> (ok: bool, detail: str, tests: int|None) --------------------------------------
def unittest_ok(rc, out, err):
    m = re.search(r"Ran (\d+) tests?", err + out)
    n = int(m.group(1)) if m else None
    ok = rc == 0 and bool(re.search(r"^OK\b", err + out, re.M))
    tail = (err + out).strip().splitlines()
    return ok, (f"{n} tests OK" if ok else (tail[-1] if tail else "no output")), n


def line_present(pattern, label):
    def chk(rc, out, err):
        found = re.search(pattern, out + err, re.M) is not None
        return rc == 0 and found, (label if found and rc == 0 else f"missing {pattern!r} (rc={rc})"), None
    return chk


def canvas_scenarios(rc, out, err):
    passes = len(re.findall(r"\bPASS\b", out)) - (1 if "ALL PASS" in out else 0)
    ok = rc == 0 and "ALL PASS" in out
    return ok, (f"{passes} scenario checks, ALL PASS" if ok else "scenarios did not all pass"), None


def fuzz_ok(rc, out, err):
    m = re.search(r"(\d+)/(\d+) sequences x (\d+) ops held all predicates", out)
    if rc == 0 and m is not None:
        return True, m.group(0), None
    tail = (out + err).strip().splitlines()
    return False, (tail[-1] if tail else "no output"), None


def json_stdout(pred, label):
    def chk(rc, out, err):
        try:
            r = json.loads(out)
        except Exception:
            return False, f"stdout is not JSON (rc={rc})", None
        ok, detail = pred(r)
        return ok, detail, None
    return chk


def json_lines_identity_close(rc, out, err):
    rows = []
    for line in out.splitlines():
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    ok = rc == 0 and bool(rows) and all(r.get("identity_closes") for r in rows)
    return ok, (f"{len(rows)} rows, every taxonomy identity closes" if ok else f"{len(rows)} rows; identity did not close or rc={rc}"), None


def always_info(label):
    def chk(rc, out, err):
        return rc == 0, label if rc == 0 else f"rc={rc}", None
    return chk


# ---- special steps ----------------------------------------------------------------------------------------------
def synthetic_sheets(tmp: Path) -> list:
    """Two synthetic label sheets from the sealed key with 10% / 20% noise: the same wiring check run_all.sh did."""
    import random
    key = json.load(open(ROOT / "09_study" / "answer_key.DO_NOT_OPEN_UNTIL_LABELED.json"))
    rng = random.Random(1)
    paths = []
    for name, noise in (("_a.csv", .1), ("_b.csv", .2)):
        p = tmp / name
        with open(p, "w") as f:
            f.write("id,level_0_to_5,confident_yes_no,notes\n")
            for i, v in key.items():
                lvl = v["intended_level"]
                if rng.random() < noise:
                    lvl = max(0, min(5, lvl + rng.choice([-1, 1])))
                f.write(f"{i},{lvl},yes,\n")
        paths.append(str(p))
    return paths


def human_sheets() -> list:
    """Real label sheets present in 09_study (labels_<name>.csv); the scorer's own sheet is excluded so this stays humans-only."""
    return sorted(p.name for p in (ROOT / "09_study").glob("labels_*.csv") if "scorer" not in p.name)   # names: the step runs in 09_study


def lineage_listing():
    d = ROOT / "10_history" / "guard_lineage"
    guards = sorted(p.name for p in d.glob("alignment_guard_v*.py"))
    return f"{len(guards)} guard versions with tests, v2 -> v3.4.2 (history; not executed, see 10_history/README.md)"


def build_steps(a) -> list:
    tmp = Path(tempfile.mkdtemp(prefix="glitch_suite_"))
    fuzz_seqs = "200" if a.full else "60"
    cmp_values, cmp_seeds = ("0,1,5", "1,2") if a.full else ("1", "1")
    S = []
    # 01 canvas
    S.append(Step("02a", "canvas verify --strict (hash chain, supersession, version drift)", ROOT / "02_canvas",
                  [PY, "glitch_harness.py", "verify", "--strict"], line_present(r"^VALID", "VALID")))
    S.append(Step("02b", "canvas executable scenarios", ROOT / "02_canvas",
                  [PY, "glitch_harness.py", "test"], canvas_scenarios))
    S.append(Step("02c", "canvas tooling adversarial suite (FR_004, version drift, score wiring)", ROOT / "02_canvas",
                  [PY, "test_canvas_tooling.py"], unittest_ok))
    S.append(Step("02d", "GLITCH harness unit suite", ROOT / "02_canvas",
                  [PY, "test_glitch_runtime_harness.py"], unittest_ok))
    # 02 guard
    S.append(Step("03a", "guard feature suite", ROOT / "03_guard", [PY, "test_alignment_guard_v343.py"], unittest_ok))
    S.append(Step("03b", "guard invariant contract (13 invariants)", ROOT / "03_guard", [PY, "test_invariants.py"], unittest_ok))
    S.append(Step("03c", f"model-based fault tester ({fuzz_seqs} seq x 40 ops, seed 1)", ROOT / "03_guard",
                  [PY, "fuzz_guard.py", "--seqs", fuzz_seqs, "--ops", "40", "--seed", "1"], fuzz_ok, heavy=True, timeout=300))
    # 03 deploy
    S.append(Step("05a", "deploy suite (scorer isolation, manifest, proxy, declaration cap)", ROOT / "05_deploy",
                  [PY, "test_deploy.py"], unittest_ok, needs=("fastapi", "httpx")))
    S.append(Step("05b", "proxy fail-closed (enforce) / fail-open (shadow) / turn-scoped checkpoints", ROOT / "05_deploy",
                  [PY, "test_proxy_fail_closed.py"], unittest_ok, needs=("fastapi", "httpx")))
    S.append(Step("05d", "live-traffic shapes as fixtures (integer levels from the real runs; first-fire pinned under the signed canvas config)", ROOT / "05_deploy",
                  [PY, "test_session_fixtures.py"], unittest_ok))
    S.append(Step("05e", "reach monitor: CAMPAIGN_REACH seeds on gateway-assigned sensitivity (no judge), incl. fan-out and credential rotation", ROOT / "05_deploy",
                  [PY, "test_reach_monitor.py"], unittest_ok))
    S.append(Step("05c", "Tier 0 offline scoring wiring (score_transcript.py --dry on sample_transcript.json)", ROOT / "05_deploy",
                  [PY, "score_transcript.py", "sample_transcript.json", "--dry"],
                  json_stdout(lambda r: (isinstance(r.get("turns"), list) and len(r["turns"]) > 0,
                                         f"{len(r.get('turns', []))} turns scored by the stub; pipeline wired"), "wired")))
    # 04 bench
    S.append(Step("06a", "benchmark runner refuses an unlabeled corpus", ROOT / "06_bench",
                  [PY, "glitch_benchmark.py", "sample_corpus.jsonl"],
                  json_stdout(lambda r: (str(r.get("status", "")).startswith("REFUSED"), r.get("status", "no status")), "REFUSED")))
    S.append(Step("06b", "benchmark realized validation (dead recovery path, measured-phase sink)", ROOT / "06_bench",
                  [PY, "test_benchmark_realized.py"], unittest_ok))
    S.append(Step("06c", "benchmark self-validation, sharded workload (a cost measurement; asserts only report_valid)", ROOT / "06_bench",
                  [PY, "benchmark_guard.py", "--workload", "sharded", "--report", str(tmp / "bench_sharded.json")],
                  json_stdout(lambda r: (bool(r.get("report_valid")), f"report_valid={r.get('report_valid')}"), "valid"),
                  heavy=True, timeout=300))
    # 05 async
    S.append(Step("07a", "async ack invariants (ACK_MUTATION_IS_NARROW x5, watermark x4)", ROOT / "07_async",
                  [PY, "test_async_ack_invariant.py"], unittest_ok))
    S.append(Step("07b", f"sync vs async narrow-ack, open-loop, sink latency {cmp_values} ms (identities must close)", ROOT / "07_async",
                  [PY, "compare_topologies.py", "sink_latency_ms", cmp_values, cmp_seeds, "sync,async_narrow", "8", "0.02"],
                  json_lines_identity_close, heavy=True, timeout=300))
    # 06 demo
    S.append(Step("04", "demo: pharmacist escalation + shell containment (TW03 detection and INV_6 asserted separately)", ROOT / "04_demo",
                  [PY, "demo_pharmacist_shell.py"], line_present(r"^PROBE PASS", "PROBE PASS")))
    # 07 incident
    S.append(Step("08a", "incident tooling: fleet containment, sealed evidence, third-party verify, air-gap receipt", ROOT / "08_incident",
                  [PY, "test_incident.py"], unittest_ok))
    S.append(Step("08b", "preparation: two-person thaw, silence watchdog, attestation, incident->fixture, canary diff", ROOT / "08_incident",
                  [PY, "test_prepare.py"], unittest_ok))
    S.append(Step("08c", "sealed envelope (sign-then-encrypt, allowlist, replay refusal) over the AFSK frame", ROOT / "08_incident",
                  [PY, "test_envelope.py"], unittest_ok, needs=("nacl", "numpy")))
    S.append(Step("08d", "AFSK modem: framing, CRC, sync by correlation, noisy-channel loopback", ROOT / "08_incident",
                  [PY, "test_afsk.py"], unittest_ok, needs=("numpy",)))
    S.append(Step("08f", "stop invariant: STOP_EVENT / STOP_APPLIED / ACTION_EVENT; CONTINUED_AFTER_STOP, ACTUATOR_SILENT, ACTUATOR_MISMATCH", ROOT / "08_incident",
                  [PY, "test_stop_invariant.py"], unittest_ok))
    S.append(Step("08i", "doctrine H3-H8: no judge reads model-authored fields; required harness tests and mutants exist; unclassified is suspect", ROOT / "08_incident",
                  [PY, "test_doctrine.py"], unittest_ok))
    S.append(Step("08g", "historian: the invariants over a structured event log (table in historian.py), with named LIMIT cases and mutant checks", ROOT / "08_incident",
                  [PY, "test_historian.py"], unittest_ok))
    S.append(Step("08h", "historian CLI on the sample log (expects the planted violations and provable=true)", ROOT / "08_incident",
                  [PY, "historian_cli.py", "sample_log.jsonl", "--json"],
                  json_stdout(lambda r: (r.get("provable") is True and sorted(r.get("by_kind", {})) == ["ACTUATOR_SILENT", "DETECTION_LATENCY", "HANDOFF_AS_AUTHORITY", "ORIGIN_FABRICATED", "SELF_AUTHORIZED_CHANGE", "SELF_PROVISIONED_IDENTITY", "THIRD_PARTY_SINK", "UNALERTED", "UNREGISTERED_IDENTITY_USE"],
                                         f"kinds: {sorted(r.get('by_kind', {}))}"), "sample")))
    S.append(Step("08e", "incident drill: freeze fleet, seal, third-party verify, three tampers (one needs the anchor), receipt", ROOT / "08_incident",
                  [PY, "drill.py", "--dir", str(tmp / "drill")], line_present(r"^DRILL PASS", "DRILL PASS")))
    # 11 testbed
    S.append(Step("11a", "testbed: built-in compliant and tempted scripts through the real gateway, historian and reach monitor; three gateway mutants must change the verdict", ROOT / "11_testbed",
                  [PY, "test_testbed.py"], unittest_ok))
    S.append(Step("11d", "stop by silence: a separate stop authority issues perishable tokens, the receiver verifies them against its own clock and writes its own log, escrow is a real time-lock, and the historian cross-checks the three writers and a power meter", ROOT / "11_testbed",
                  [PY, "test_lease.py"], unittest_ok))
    S.append(Step("11b", "testbed CLI: every scenario clean for the compliant script (no model needed)", ROOT / "11_testbed",
                  [PY, "run_testbed.py", "--script", "compliant", "--quiet", "--label", "suite-compliant"], line_present(r"^control\s+2\s+\(control\)\s+clean", "control clean")))
    S.append(Step("08j", "review tools: a flood of alerts cannot bury a new kind, nothing is dropped, and a reviewer's page never carries the agent's words", ROOT / "08_incident",
                  [PY, "test_review.py"], unittest_ok))
    S.append(Step("11c", "conditional behaviour: matched tasks with and without planted tokens, exact test, escape bound; a simulated conditional adversary is found", ROOT / "11_testbed",
                  [PY, "test_audit_conditional.py"], unittest_ok))
    S.append(Step("00b", "docs cannot lag the code: STATUS.md is regenerated from the suite's own results and must match, stale claims and quoted counts must not reappear, every folder and every named path is covered", ROOT,
                  [PY, "test_docs.py"], unittest_ok))
    S.append(Step("00c", "the open-items page: every open item has a status, an owner, the evidence that exists and what would close it; the page is exactly what the generator renders and no private path or key is in it", ROOT,
                  [PY, "test_open_items.py"], unittest_ok))
    # 13 real-world adapter
    S.append(Step("12a", "arena: every chain answers every move and ends on a declared floor, residual or open; every rule has a mutant; the bouts can be lost", ROOT / "12_arena",
                  [PY, "test_arena.py"], unittest_ok))
    S.append(Step("12c", "adaptive adversary judge: the oracle sees re-encoded secrets, verdicts match the board, and the judge can say LANDED (no model needed)", ROOT / "12_arena",
                  [PY, "test_adaptive.py"], unittest_ok))
    S.append(Step("12d", "author red-team round: nine moves the defence's author thought of as the attacker, each pinned to its outcome; a move that lands again is a regression", ROOT / "12_arena",
                  [PY, "test_redteam.py"], unittest_ok))
    S.append(Step("12e", "combos: minimal sets of broken assumptions per goal, the common-mode table, the defence-in-depth matrix (no single point of failure) and four played combos with controls", ROOT / "12_arena",
                  [PY, "test_combos.py"], unittest_ok))
    S.append(Step("12f", "parser differential (a model-proposed assumption): fifteen payloads, three downstream readers, every layer on and off; format checks are a layer in their own right", ROOT / "12_arena",
                  [PY, "test_parser_diff.py"], unittest_ok))
    S.append(Step("12g", "the Dark Souls measurements: what a probe costs under walls that refuse, walls that remember, and walls that say little; the boss is fair to an honest user", ROOT / "12_arena",
                  [PY, "test_boss.py"], unittest_ok))
    S.append(Step("12h", "manifest lint (assumption A13 made measurable): slack classes per manifest, the real manifests are narrow, the adversary world's slack is known; the same rule on a log (I8c)", ROOT / "12_arena",
                  [PY, "test_manifest_lint.py"], unittest_ok))
    S.append(Step("12i", "the human playtest console: a person typing calls faces the same defender the models faced, the same oracle judges, the transcript carries what a reviewer needs", ROOT / "12_arena",
                  [PY, "test_play.py"], unittest_ok))
    S.append(Step("12j", "the red-team course: every lesson is played through the real console and must give the verdict, strikes, phase and replies the course states; the page is exactly what the generator renders", ROOT / "12_arena",
                  [PY, "test_lessons.py"], unittest_ok))
    S.append(Step("12k", "fighting-game theory against the defender: conditioning trains nothing a table only two humans write, a mix-up's two options are covered by two walls at once and pressing after a hit closes the hole, the same address from the other side is refused by exact match, a wall is a pure function of the call, and the option select aimed at the human reader is the stated limit", ROOT / "12_arena",
                  [PY, "test_mixups.py"], unittest_ok))
    S.append(Step("17a", "AgentDojo adapter (optional, needs agentdojo): the policy is built from the prompt and the user's own pre-task structured data only; every user task's ground-truth solution and every (user task, injection) pair through the gateway with no model give a utility ceiling and a security floor; the executor refuses inside AgentDojo's own pipeline; the historian reads the record", ROOT / "17_agentdojo",
                  [str(INSPECT_PY), "-W", "ignore", "test_dojo.py"], unittest_ok, needs=("@dojo",), timeout=600))
    S.append(Step("16a", "interpretability experiment, the part that needs no model: the situations (11 injection phrasings x addresses x tasks x system prompts, plus controls) and the label, which is read from the gateway's record by replaying the model's reads and its generated calls, never from what the model says", ROOT / "16_interp",
                  [PY, "test_situations.py"], unittest_ok))
    S.append(Step("16b", "interpretability probe on synthetic data where the answer is known (optional, needs scikit-learn): the signal layer scores high and noise layers do not, a group-identifying feature does not leak through group folds, the permutation null is centred, the report states its limits and the text baseline", ROOT / "16_interp",
                  [str(INTERP_PY), "test_probe.py"], unittest_ok, needs=("@interp",), timeout=300))
    S.append(Step("15a", "agent-SDK bridge: PreToolUse as a wall and a second writer, canUseTool as the gateway's decision point, tool handlers that return only what was decided, and the historian's cross-check of the two writers (no SDK or model needed)", ROOT / "15_agent_sdk",
                  [PY, "test_bridge.py"], unittest_ok))
    S.append(Step("15b", "agent-SDK live runner's builders, offline (optional, needs claude-agent-sdk): the SDK's allow rules are empty, no settings file is loaded, the callbacks are the bridge's, the office server is the only tool source, the task and a stop stream correctly", ROOT / "15_agent_sdk",
                  [str(INSPECT_PY), "test_live_build.py"], unittest_ok, needs=("@sdk",), timeout=300))
    S.append(Step("15c", "agent-SDK end to end against a LOCAL MOCK of the Messages API (optional, needs claude-agent-sdk; no network, a placeholder key, an empty home): the real SDK and the real bundled CLI offer the model only the office tools, the hook fires and the gateway decides every call, a refusal reaches the model, a settings allow rule cannot skip the gateway, a misconfigured flow is caught by I18", ROOT / "15_agent_sdk",
                  [str(INSPECT_PY), "-W", "ignore", "test_end_to_end_mock.py"], unittest_ok, needs=("@sdk",), timeout=600))
    S.append(Step("14a", "Inspect AI integration (optional, Python 3.10+): the testbed as Inspect tasks with the historian as a deterministic scorer; a scripted compliant run scores clean everywhere and a tempted one takes the bait, a mock model plays through the protocol, and a scorer that finds nothing is caught", ROOT / "14_inspect",
                  [str(INSPECT_PY), "test_glitch_inspect.py"], unittest_ok, needs=("@inspect",), timeout=300))
    S.append(Step("12b", "arena CLI: validate the move tree and play every bout through the real gateway and historian", ROOT / "12_arena",
                  [PY, "arena.py"], line_present(r"^OK: 0 problems, 0 lost beats", "0 problems, 0 lost beats")))
    # 08 study
    KEY = ROOT / "09_study" / "answer_key.DO_NOT_OPEN_UNTIL_LABELED.json"
    if not KEY.exists():                                                             # the key is sealed until the raters' re-sitting (2026-10-10) and is not in the public repository until then
        S.append(Step("09a", "study tooling: the sealed answer key is not shipped until after the 2026-10-10 re-sitting; kappa wiring not run", ROOT / "09_study",
                      [PY, "-c", "print('sealed key not present')"], always_info("sealed key not present"), info=True))
        S.append(Step("09b", "study result: needs the sealed key (see 09_study/kappa_latest.txt for the recorded result)", ROOT / "09_study",
                      [PY, "-c", "print('see kappa_latest.txt')"], always_info("see 09_study/kappa_latest.txt"), info=True))
        hs = []
    else:
        sheets = synthetic_sheets(tmp)
        S.append(Step("09a", "study tooling: kappa.py on two synthetic sheets against the sealed key (wiring only)", ROOT / "09_study",
                      [PY, "kappa.py", *sheets, "--key", "answer_key.DO_NOT_OPEN_UNTIL_LABELED.json"],
                      line_present(r"weighted", "kappa computed")))
        hs = human_sheets()
    if not KEY.exists(): pass
    elif len(hs) >= 2:
        S.append(Step("09b", f"study result: kappa across the {len(hs)} human sheets present (a measurement; asserts nothing)", ROOT / "09_study",
                      [PY, "kappa.py", *hs, "--key", "answer_key.DO_NOT_OPEN_UNTIL_LABELED.json"],
                      always_info("see 09_study/kappa_latest.txt"), info=True))
    else:
        S.append(Step("09b", "study result: fewer than two human sheets in 09_study; nothing to compute", ROOT / "09_study",
                      [PY, "-c", "print('need two labels_<name>.csv sheets')"], always_info("needs 2 sheets"), info=True))
    # 12 history
    S.append(Step("10", "guard version history (listing only)", ROOT / "10_history",
                  [PY, "-c", "import os; print(len([f for f in os.listdir('guard_lineage') if f.startswith('alignment_guard_v')]))"],
                  always_info(lineage_listing()), info=True))
    return sorted(S, key=lambda st: (int(st.id[:2]), st.id))   # print and run in folder order


# ---- main ----------------------------------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="skip heavy steps (fuzzer, cost benchmark, topology comparison)")
    ap.add_argument("--full", action="store_true", help="larger fuzz and comparison workloads")
    ap.add_argument("--only", default="", help="comma-separated step id prefixes, e.g. 03,08a")
    ap.add_argument("--list", action="store_true", help="print the steps and exit")
    ap.add_argument("--strict", action="store_true", help="a SKIP counts as a FAIL")
    ap.add_argument("--fail-fast", action="store_true", help="stop at the first FAIL")
    ap.add_argument("--report", default=str(ROOT / "suite_report.json"), help="where to write the JSON report")
    ap.add_argument("--no-report", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true", help="print each step's full output")
    a = ap.parse_args()

    steps = build_steps(a)
    if a.only:
        prefixes = [p.strip() for p in a.only.split(",") if p.strip()]
        steps = [s for s in steps if any(s.id.startswith(p) for p in prefixes)]
    if a.quick:
        steps = [s for s in steps if not s.heavy]
    if a.list:
        for s in steps:
            print(f"{s.id:<4} {'[info]' if s.info else '[heavy]' if s.heavy else '      '} {s.title}")
        return 0

    harness_version = re.search(r'HARNESS_VERSION\s*=\s*"([^"]+)"', (ROOT / "01_lib" / "glitch_runtime_harness.py").read_text())
    print(f"{SUITE} — glitch_suite.py")
    print(f"python {platform.python_version()} ({PY}) on {platform.system()} {platform.release()}; harness {harness_version.group(1) if harness_version else '?'}; {len(steps)} steps\n")

    availability = {}
    results = []
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "INFO": 0}
    total_tests = 0
    for s in steps:
        missing = []
        for mod in s.needs:
            if mod not in availability:
                availability[mod] = module_available(mod)
            if not availability[mod]:
                missing.append(mod)
        if missing:
            status, detail, secs, tests, out = "SKIP", (("Inspect AI not set up: see 14_inspect/README.md" if missing == ["@inspect"] else "Claude Agent SDK not installed in the Inspect venv: see 15_agent_sdk/README.md" if missing == ["@sdk"] else "interpretability venv not set up: see 16_interp/README.md" if missing == ["@interp"] else "agentdojo not installed in the Inspect venv: see 17_agentdojo/README.md" if missing == ["@dojo"] else f"missing optional dependency: {', '.join(missing)} (pip install {' '.join('pynacl' if m == 'nacl' else m for m in missing)})")), 0.0, None, ""
        else:
            rc, out, err, secs, timed_out = run_cmd(s.cmd, s.cwd, s.timeout)
            if timed_out:
                ok, detail, tests = False, f"timed out after {s.timeout}s", None
            else:
                ok, detail, tests = s.check(rc, out, err)
            status = ("INFO" if ok else "FAIL") if s.info else ("PASS" if ok else "FAIL")
            if s.id == "09b" and ok:
                (ROOT / "09_study" / "kappa_latest.txt").write_text(out)
            if tests:
                total_tests += tests
            out = out + ("\n--- stderr ---\n" + err if err.strip() else "")
        counts[status] += 1
        marker = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP", "INFO": "info"}[status]
        print(f"[{s.id:<3}] {marker:<4} {secs:6.2f}s  {s.title}")
        print(f"       {detail}")
        if status == "FAIL" or a.verbose:
            lines = out.strip().splitlines()
            shown = lines if a.verbose else lines[-25:]
            for line in shown:
                print("       | " + line)
        if s.id == "09b" and status == "INFO":
            for line in out.strip().splitlines()[:3]:
                print("       | " + line)
        results.append({"id": s.id, "title": s.title, "status": status, "detail": detail, "seconds": round(secs, 3),
                        "tests": tests, "cmd": s.cmd, "cwd": str(s.cwd.relative_to(ROOT))})
        if status == "FAIL" and a.fail_fast:
            print("\nstopping at first failure (--fail-fast)")
            break

    failed = counts["FAIL"] + (counts["SKIP"] if a.strict else 0)
    verdict = "SUITE OK" if failed == 0 else "SUITE FAILED"
    print(f"\n{verdict}: {counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped, {counts['INFO']} informational; "
          f"{total_tests} unit tests counted across the unittest steps")
    print("Cost numbers (06c, 07b) and the study kappa (09b) are measurements, not assertions. 00_docs/CONTRACT.md is the claim boundary.")
    if not a.no_report:
        report = {"suite": SUITE, "runner": "glitch_suite.py", "python": platform.python_version(), "platform": platform.platform(),
                  "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "options": vars(a), "verdict": verdict,
                  "counts": counts, "unit_tests_counted": total_tests, "optional_dependencies": availability, "steps": results,
                  "claim_boundary": "GLITCH detects specified behavioral and governance failure patterns. It does not establish that a model or deployment is safe, aligned, harmless, or compliant."}
        Path(a.report).write_text(json.dumps(report, indent=1) + "\n")
        print(f"report: {a.report}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
