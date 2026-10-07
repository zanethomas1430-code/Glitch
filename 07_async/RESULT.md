# v3.4.3-async-experiment — result

Status: **evidence for a topology change, not a version bump.** The frozen guard (`alignment_guard_v343.py`) is unmodified;
everything here is an adapter (`NarrowAckStore`), a transport worker (`DrainWorker`), and a comparison harness. The
frozen 42 invariant tests pass unchanged; `test_async_ack_invariant.py` adds 9 (ACK_MUTATION_IS_NARROW x5 incl. a
mutant-killer, WATERMARK_ACK_PROTOTYPE x4).

## Verdict (open-loop, ~390 ops/s offered, hot_user 2x8 sessions, 8 producers, 2 drain workers, outbox cap 8, seeds 1-2)
| sink latency | topology | decision completion | refusal rate | CAS attempts/commit | conflict rate | dup sends | producer lag p95 |
|---|---|---|---|---|---|---|---|
| 1 ms | sync (v3.4.3 as shipped) | 0.62 | 0.36 | 2.46 | 0.59 | 0.74 | 190 ms |
| 1 ms | async_narrow (spec) | 0.79 | 0.08 | 1.00 | 0.00 | 0.00 | 0 |
| 5 ms | sync | 0.45 | 0.51 | 2.87 | 0.65 | 0.79 | 233 ms |
| 5 ms | async_narrow | 0.46 | 0.38 | 1.00 | 0.00 | 0.00 | 0 |

With 20% sink failure on top of 1 ms latency: sync refusal 0.44 / dup 0.59; async_narrow 0.13 / 0.00. At 30%: 0.69 vs 0.18.

The 1 ms CAS-pressure cliff is suppressed by the topology as specified, without weakening outbox capacity, taxonomy
closure (every run closes), failure visibility, or any frozen invariant. The ack-conflict rate (~0.43) is the mechanism
working in the right direction: acknowledgements yield to transitions, never the reverse. At 5 ms the residual ~0.35
refusal rate is drain capacity (2 workers x 5 ms per envelope vs ~1.5 envelopes per op), not the feedback loop.

## What was wrong first, and why it is on the record
The first two comparisons (closed-loop, `cmp_lat_cap8.log`, `cmp_lat_cap64.log`) said the opposite: async worse on
everything at cap 64, availability collapse at cap 8. That was a measurement error: the sync topology's producers throttle
themselves by blocking in their own drains (offered load fell to 336 ops/s at 5 ms) while async producers ran at ~1,070.
Per-op pacing (`cmp_paced*.log`) did not equalize it. Open-loop scheduled arrivals, identical across topologies, did.
Same family as the benchmark's earlier "contention that wasn't there": a stimulus property (arrival rate) that the
harness assumed was equal and was not. The wrong verdict was stated before the corrected one; both stay in this folder.

## Beyond the spec: watermark ack (`WatermarkAckStore`)
An ack-only watermark that does not bump the transition version removes ack conflicts entirely (0.00) but is not needed
for the cliff and costs a store-side filter on every commit (p50 1.2 ms vs 0.8; 59 ms producer lag at 0 ms latency). It
is a prototype with 4 properties tested; it is not proposed.

## What this does not establish
Single process, in-memory store, GIL. Drain capacity sizing, sink batching, and cross-process ack semantics are open.
The transplant onto a real `RecordStore` must keep `ack_audit` free of any caller-supplied record (the mutant-killer
test is the contract for that).
