# ALIGNMENT_GUARD reference runtime contract (v3.4.3, frozen)

Thirteen invariant properties (numbered 1, 2A, 2, 3, 3B, 4, 5, 6, 7, 7B, 8, 9, 10), each executable in `test_invariants.py` (42 tests). A change that weakens any of them
must break the test with that invariant's name. The feature suite (`test_alignment_guard_v343.py`, 27) tests
behavior; this file tests the contract.

| # | Invariant | Property tested |
|---|---|---|
| 1 | ONE_CONSISTENCY_DOMAIN | one CAS moves trajectory, guard, request result, cursor, outbox together; a lost CAS moves none |
| 2A | NO_PRECOMMIT_PAYLOAD_STORE | the RecordStore is the guard's only durable store for candidate response, action-verdict, trajectory, guard, request-journal, and audit-outbox state; no candidate output or verdict is written elsewhere before CAS; authorization infrastructure may have its own pre-CAS transitions (tested: verifier called once, guard truth unchanged after a lost CAS); sink/anchor see only committed envelopes (tested) |
| 2 | COMMIT_BEFORE_RELEASE | no model output or action authorization becomes externally releasable, and no guard-owned safety transition becomes truth, before its winning CAS; a losing candidate leaves no retrievable output |
| 3 | REQUEST_IDEMPOTENCY | identity is a `RequestIdentity(request_id, input_digest)` required by construction (empty or malformed material is rejected; `evaluate` without one is rejected); within the horizon same identity -> exact committed result with no rescoring, no regeneration, no trajectory advance, even if the scorer or model would now produce something different; different input under the same id -> conflict; beyond the horizon the identity stays spent |
| 3B | SESSION_TURN_MONOTONICITY | for a session, a newly evaluated caller_turn must be exactly previous+1; retries of committed identities are the only exception; a hole is refused (TurnSequenceError), not spent; spent_turns[session] = max_turn is therefore a correct compact tombstone, not a lossy approximation |
| 4 | MODE_RATCHET | evaluation never lowers; lowering needs a grant bound to version, target, incident, and requesting principal |
| 5 | BASELINE_EXTERNAL | no client path raises required_level; every baseline change (lower, epoch, rejected raise) is an audit event |
| 6 | ACTIONS_FAIL_CLOSED | unknown actions denied; sensitive effects above purpose contain; effect_id is a pure function of the committed decision |
| 7 | AUDIT_DURABLE_AND_BOUNDED | first contact emits its genesis `session_started` envelope atomically with record creation and is subject to the outbox bound (outbox_cap=0 creates no state); every committed envelope is durably recoverable until acknowledged; transport is at-least-once with stable (stream_id, seq), exactly-once is the sink/anchor's obligation; no transition of any kind (turn, session start, epoch, TW06, lowering) commits if its full emission exceeds the bound; backpressure changes no state |
| 7B | AUDIT_DRAIN_BOUNDED_PROGRESS | a drain attempt either acknowledges committed envelopes within the retry bound or terminates with an explicit concurrency error; CAS contention cannot erase the envelope, change its stable identity, falsely report acknowledgement, or trap the caller indefinitely (four separate tests; the v3 rewrite had dropped the bound every earlier version carried) |
| 8 | DETERMINISTIC_TRANSITION | derive_transition(config, record, inputs, now) is pure and repeatable |
| 9 | TRAJECTORY_AND_REFERENCE_INDEPENDENT_OF_RETENTION | retention may remove payload history but may not alter trajectory_position, the detector history required by configured tripwires (retention below window is rejected at construction), the identity of any retained epoch, or the monotonic namespace for future epoch ids (max+1, never len+1; demonstrated: the old code issued id 2 for the fourth epoch); every entry point constructs the harness through one path and applies retention |
| 10 | INDEPENDENT_REQUESTS_LINEARIZE | concurrent independent requests serialize with exact totals |

## Data retention decision (explicit)
Exact replay after process death requires the committed response to exist somewhere, and INV_2 requires that nothing be
written before the CAS. Therefore the replay envelope (output text) lives INSIDE the atomic record, in the request journal,
for exactly the idempotency horizon (`request_journal_size` entries) and is evicted with the journal entry. This is the
only place the guard retains model output, it is bounded, and it is the price of exact replay. Operators who cannot hold
output in the safety record must either encrypt the envelope with a key held outside the guard or shorten the horizon; a
replay after eviction is a spent identity, not a re-evaluation. The horizon must be >= the caller's retry horizon.
`Decision.response_ref` is sha256(user|version|output): a context-bound content reference (equal output at different
versions yields different refs), derivable by anyone who knows the inputs. It identifies a committed response; it does not
protect it.

## Model-based fault testing (`fuzz_guard.py`)
Random sequences over start, evaluate, replay, bad-input replay, out-of-order turn, fresh-id-on-spent-turn, epoch,
inflation, lowering, drain, CAS loss (0/30/90%), sink, clock advance (up to days), restart. After every operation the
invariant predicates are checked against a shadow model that tracks only what the contract promises. Baseline: 400
sequences x 40 ops across seeds 1-4, no violation. Mutation-checked: reverting epoch ids to len()+1 is caught within 6
sequences; disabling the spent-turn check is caught within 1 sequence once the fuzzer had an operation that could observe
it (it did not at first; the fuzzer was fixed, then the mutation failed). A fuzzer that has never failed has not been
tested.

## Benchmark (`benchmark_guard.py` v0.4) — cost, not correctness
Report boundary: all workload counters, latencies, CAS/audit metrics, and durable end-state observations refer to the same measured phase. Restart recovery is a separately timed post-phase experiment performed only after that snapshot. Setup uses its own counters; the durable end-state
(backlog, record bytes, journal occupancy) is sampled before restart recovery; the outcome taxonomy closes exactly over
attempted operations (succeeded + completed-blocked-by-policy + skipped-inapplicable + infrastructure-fail-closed =
attempted) and the report is invalid if it doesn't; opportunity-dependent counts are also reported as rates; the audit
lag distribution is named `audit_delivery_lag_ms` (commit to successful delivery under retries), not anchor lag.
Self-validation (`validate_plan`, `validate_realized`) refuses degenerate stimulus and unrealized faults; the identity
check caught a missing taxonomy bucket (`replay.spent_beyond_horizon`) on its first run.

Provenance: v0.1 (no same-record contention, outcomes-not-attempts throughput, non-reproducible seeds), v0.2 (degenerate
plan generator), and v0.2.1 (setup counters in measured totals, end-state sampled after recovery, taxonomy from latency
buckets, mislabeled lag) are withdrawn. Their files are kept with a status block; their stimulus evidence stands.

Baseline v0.4, one process, this machine. hostile_hot (2 users, 8 sessions, 8 workers, 30% injected CAS loss, 20% sink
failure, outbox cap 8, 50% verifier unavailable, json backend): of 320 attempted, 21% succeeded, 17% completed but blocked
by policy, 2% skipped as inapplicable, 61% terminated fail-closed by infrastructure. Sink observed failure fraction 0.18
vs 0.20 configured. Genuine version-conflict rate 0.26 of non-injected attempts. Post-authorization lowering loss 0.5.

## Sensitivity sweep (`sweep_guard.py` v0.2)
One parameter at a time on a validated hot-user base (2 users, 8 sessions, 8 workers), topology never mutated, seeds
1-5 per point, median with min/max, rates not counts. `sweep_report.json`. Directional, single machine.
- concurrency 1->8: conflict rate 0 -> 0.28, evaluate p50 0.70 -> 4.8 ms (seed spread 0.7-6.8 at 8: the knee is real but
  its position is scheduling-sensitive), post-auth lowering loss 0 -> 0.31. Knee between 4 and 8 contending sessions.
- cas_loss 0 -> 0.5: attempts/commit 1.34 -> 3.04, dup audit sends 0.25 -> 0.67, success fraction 0.41 -> 0.35.
  Unreliable commit infrastructure costs retries and retransmission before it costs availability.
- outbox_cap 4 -> 64: infrastructure refusal rate 0.37 -> 0.03 while success fraction stays ~0.40 and p50 rises 0.6 -> 5.8
  ms. Small caps refuse work cheaply; large caps accept it and pay per CAS. Availability and latency trade directly.
- journal_horizon 2 -> 128: record bytes 12 KB -> 56 KB, p99 24 -> 64 ms, refusal rate 0.01 -> 0.12, evictions 157 -> 0.
  At 128 the workload (~130 commits/user) never evicts, so replay_spent=0 there is workload saturation, not a plateau.
- sink_failure 0 -> 0.3: infrastructure refusal rate 0.02 -> 0.49 with success fraction 0.40 -> 0.25. Fail-closed converts
  sink outages into refused work; the refusal rate rises strongly across the measured range (three points; not enough to
  claim a functional form).
- sink_latency 0 -> 20 ms: refusal rate 0.03 -> 0.33. CAS pressure jumps from 1.4 attempts/commit to 2.2 with only 1 ms
  of sink latency, then settles near 2.0 as increasing fail-closed backpressure changes the population of operations that
  reach commit. Synchronous audit delivery therefore creates a contention/retransmission feedback effect, not merely
  additive latency. This is the strongest cost evidence in the folder for reducing synchronous audit work on the hot
  record path; batching, asynchronous draining, or another acknowledgement topology should be benchmarked separately
  before choosing a mechanism.

## Handoffs (not claims)
- `RecordStore.compare_and_swap` must be linearizable across processes. The prototypes are single-process.
- The audit anchor must be written where this process cannot rewrite it.
- The action gateway must enforce `effect_id` idempotency and verify `arguments_digest` against real arguments.
- `TurnMetrics` must come from a scorer that is not the model under evaluation (GLITCH INV_06).
- The request-ingress adapter must construct `RequestIdentity` from the immutable canonical caller input before scoring or generation. The guard verifies the digest's shape, not its provenance; it does not retain raw input and so cannot compute the digest itself.

## Lineage
v1 keyword controller (7 probes) -> v2 on the GLITCH harness -> v2.1 hardening -> v2.2 (3 probes) -> v2.3 one CAS domain
(10 review items) -> v2.4 outbox, logical clock, typed TW06 (7 items) -> v3 reviewer rewrite, effect_id -> v3.1 (5 probes,
request idempotency) -> v3.2 request fingerprint, contract as tests -> v3.3 request journal + spent boundary (delayed replay), universal outbox capacity, at-least-once transport stated -> v3.4 envelope inside the atomic record (nothing written pre-CAS), identity from caller input not regenerated output, strictly sequential turns, wildcard policy implemented -> v3.4.1 contract hardening: NO_STAGING_STORE and SESSION_TURN_MONOTONICITY as executable properties, response_ref semantics stated, dead code removed -> v3.4.2 contract closure: RequestIdentity required by construction, INV_2/2A narrowed to what is true, single harness constructor with retention on every path (harness fixed to apply retention on epoch/session ops) -> v3.4.3 + harness 1.0.1: retention validated against detector history, monotonic epoch ids, genesis audit atomic and bounded, ingress provenance handoff, bounded drain -> reference baseline: model-based fault tester with mutation-verified sensitivity -> benchmark v0.1..v0.2.1 withdrawn, v0.3 self-validation, v0.4 report boundary (setup isolated, end-state before recovery, closing taxonomy, rates) -> sweep v0.2 (fixed topology, 5 seeds, rates, journal pressure observable).
