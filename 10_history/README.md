# 10_history — where the frozen guard came from

Nothing in this folder runs as part of the suite. It is kept so the lineage that PROBES.md and DISCOVERIES.pseudo.md
describe (FR_001 … FR_008, the v1 → v3.4.3 probes) has its source next to the words, and so a reader can diff any two
versions instead of trusting a changelog.

## guard_lineage/
Every ALIGNMENT_GUARD version before the frozen v3.4.3, each with the test file that was written against it:

| file | version | lines (guard / tests) | what changed (see 00_docs/PROBES.md) |
|---|---|---|---|
| alignment_guard_v2.py | v2 | 147 / 57 | levels come from the scorer; containment reserved for actions |
| alignment_guard_v22.py | v2.2 | 163 / 78 | persisted guard store; fail-closed action verdicts |
| alignment_guard_v23.py | v2.3 | 335 / 100 | audit chain; lower_mode needs named authority |
| alignment_guard_v24.py | v2.4 | 378 / 158 | one record, one CAS; request identity |
| alignment_guard_v31.py | v3.1 | 430 / 198 | outbox + drain; replay envelope |
| alignment_guard_v32.py | v3.2 | 440 / 209 | recovery grants bound to version/target/incident |
| alignment_guard_v33.py | v3.3 | 489 / 212 | genesis envelope atomic with creation |
| alignment_guard_v34.py | v3.4 | 481 / 213 | effect ids; delivered-only gap accounting |
| alignment_guard_v341.py | v3.4.1 | 462 / 213 | journal horizon; spent turns |
| alignment_guard_v342.py | v3.4.2 | 483 / 223 | last pre-freeze; v3.4.3 is in 01_lib |

**Why the runner does not execute these tests.** They were written against a harness that no longer exists in any
surviving snapshot: their fixtures set `trajectory_turn_limit=3` with a 6-turn window, which the current loader rejects
("retention would shorten detector history", FR_007), and the 0.7.1 harness predates `RetentionPolicy` /
`BaselineInflationError`. Against harness 1.0.1 and 1.0.2 every one of them errors on that rule; against 0.7.1 they
fail to import. That is the suite working as designed: a fixture that shrinks the window below the detector's horizon
is exactly what FR_007 forbids. They stay here as history, not as tests. If you want to run one, pin the harness it
was written for; do not relax the retention rule to make it pass.

## snapshots/
| folder | what it is |
|---|---|
| glitch-0.7.1-draft/ | the first deployment kit: harness (no version constant yet), draft canvases, the v0.7.1 harness report, the kit README |
| glitch-1.0.0-rc1/ | the 1.0.0-rc1 kit with harness 1.0.1 and the 1.0.0-rc1 canvas, proxy, scorer, deploy tests |
| alignment-guard-harness-1.0.1/ | the guard layer as shipped alongside harness 1.0.1: v3.4.3, invariants, fuzzer, benchmark v0.4 reports, sweep report, CONTRACT/PROBES of that date |

The consolidated layout that supersedes all three is the suite itself (harness 1.0.2, guard v3.4.3 frozen).
The 2026-09-10 layout (folders `01_glitch_canvas`, `02_glitch_tests`, `08_experiments`, `09_demo`) is archived outside
the suite in `../archive/`; every file in it is either identical to, or older than, the copy here.
