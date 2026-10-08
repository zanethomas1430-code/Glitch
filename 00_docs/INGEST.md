# Ingest context for a model or agent picking this up

Paste this block. It is checked against the running tree; if it disagrees with `glitch_suite.py`, the runner wins.

```
SYSTEM CONTEXT: GLITCH harness 1.0.2 + ALIGNMENT_GUARD v3.4.3 (frozen)

LAYOUT (every entry-point script resolves imports itself; PYTHONPATH is optional)
  00_docs/    README.md (= RUN.md), WHAT_THIS_IS.md, CONTRACT.md, PROBES.md, MECHANISMS.md, DISCOVERIES.*.md, HARDENING.md (v0.4 spec; doctrine H1–H13), LANDSCAPE.md (field survey, same/different, adopted), AGENT_SURFACES_REPORT.md, this file
  01_lib/     glitch_runtime_harness.py (1.0.2), alignment_guard_v343.py (frozen), glitch_scorer.py
  02_canvas/  signed canvases; glitch_harness.py sign|verify --strict|test|score; test_canvas_tooling (8); test_glitch_runtime_harness (50)
  03_guard/   test_alignment_guard_v343 (27); test_invariants (42, 13 properties); fuzz_guard.py; CONTRACT.md
  04_demo/    demo_pharmacist_shell.py — executable probe: detection (TW01/TW03) and containment (INV_6) asserted separately
  05_deploy/  glitch_proxy.py (shadow fail-open / enforce fail-closed); glitch_scorer.py (rubric v1/v2/v3, checklist, ensemble/panel); score_transcript.py;
              live_session.py; scorer_invariance.py; reach_monitor.py (harness on sensitivity, campaign-keyed, 10 tests); sessions/ (real-traffic runs, RESULTS.md, fixtures.json); test_session_fixtures (4); test_deploy (15); test_proxy_fail_closed (3)
  06_bench/   glitch_benchmark.py (labeled corpus; refuses unlabeled/unfrozen); benchmark_guard.py v0.4 + test_benchmark_realized (5); sweep_guard.py; reports
  07_async/   narrow-ack async drain experiment on the frozen guard; test_async_ack_invariant (9); compare_topologies.py; RESULT.md
  08_incident/ incident.py + incident_cli.py (freeze/seal/verify/receipt); prepare.py; afsk*.py + envelope.py (air-gap receipt); tests 16+15+13+12; drill.py (end-to-end probe); historian.py (invariants I0 to I12 plus I2b and I2c over event logs; the table is in its docstring) + historian_cli.py; stop_invariant.py (FAILED_STOP checker, 11 tests); RUNBOOK.md
  09_study/   the fifty-response study: responses, rubric (SCALE.md), sealed key, kappa.py, three human sheets (older exports in superseded/)
  11_testbed/ run_testbed.py + gateway.py + scenarios.py: a model acts through fake tools; the gateway writes the only record; historian + reach monitor judge it
  12_arena/   the board of adversary moves and counters, executable bouts, the adaptive adversary, the author red-team round; STATUS.md is generated from it
  10_history/ guard lineage v2..v3.4.2 with tests, earlier kit snapshots; listed, never executed
  glitch_suite.py  THE runner (see RUN.md for the steps), PASS/FAIL/SKIP/INFO, one exit code, suite_report.json; run_all.sh wraps it

RULES FOR CHANGES
  1. The guard is frozen. A mechanism change needs a failing invariant, a failing canvas scenario, or a cost number that
     demands it. Weakening any invariant test is a rejected change.
  2. Every new tool files under one of four layers: measurement / state-authorization / containment / evidence.
     A proposal that cannot be written as a predicate over UserRecord is not a mechanism yet.
  3. scope(check) ⊃ scope(checked). The scorer is a different model from the one under test. The anchor is written where
     the guard cannot. Validators get adversarial tests (02c, 05b, 06b). Fuzzers get mutation checks.
  4. Benchmarks assert nothing. report_valid is a stimulus/realization check, not a performance claim.
  5. Wrong numbers are withdrawn in place with a status block, never deleted.
  6. Shapes yes, payloads no: every scenario is integers; no fixture contains operational content.
  7. HARDENING H1: nothing the agent emits is a key, an id or a class (gateway assigns them). H2: every classification
     carries its source; verdict rules read deterministic fields only, witness fields only rank for review.
  9. HARDENING §13 H9–H13: a scenario that cannot fail does not count; finish is a protocol action; action count is a risk lane; shared failures are configuration findings first; harness defects are logged incidents (11_testbed/harness_incidents.json).
  8. HARDENING §12 H3–H8 (enforced by 08_incident/test_doctrine.py): no judge reads model-authored text; canaries live in the payload;
     unclassified is suspect; the harness has its own correctness tests; judges and gateways need mutant tests; a stop is a record, not a word.

WHAT IT DOES NOT CLAIM: safe/aligned/harmless/compliant; identity; reviewer correctness; digest provenance; abstract harm;
tool authority×reversibility; prompt injection; ANY human validation of the 0-5 scale. Read CONTRACT.md "Handoffs".
The current status, owner and closing condition of each of these is in OPEN_ITEMS.md.

NEXT STEP THAT NO CODE MOVES: the day-14 re-sitting of the 50-item human study on 2026-10-10 (the first sitting is done; see PROBES L8 to L10).
```

## Suggestions received and not applied, with reasons
- `asyncio.Queue` drain with a swallowed `TimeoutError`: the drain is thread-based over a record store, not a queue, and
  INV_7B requires a drain to terminate with an *explicit* concurrency error, never silently. A timeout that returns
  partial items would fail four tests.
- Replacing `unittest` assertions in `test_invariants.py` with custom exception classes: the assertions are the contract;
  the test name is the invariant. An agent isolates failures by test name, which is what the runner prints.
- `MappingProxyType` / frozen state: `derive_transition` already runs on a deep copy and returns a new record; the
  contract is proven by INV_8's no-side-effect test, not by a type.
- `pydantic` in the proxy: the proxy does not parse corpus entries; the corpus runner already validates row shape and
  refuses on it. Adding a dependency to the release path for a check that exists elsewhere is cost without a property.
- Streaming JSONL in `glitch_benchmark.py`: correct in principle; corpora here are ≤ thousands of rows and the runner needs
  the whole split for stratification. Deferred until a corpus exists that needs it.
- The supplied SYSTEM CONTEXT block referenced folders that no longer exist and "Harness 1.0.1". That is the identity-vs-
  currency error (FR_004) in a prompt. The block above was generated from the tree and is what to paste.
