# v3.4.3-async-experiment integration diff

This is intentionally a transplant guide rather than a false line-accurate patch: the accessible source snapshot is an earlier `ALIGNMENT_GUARD_v3.py`, not the frozen v3.4.3/v0.4 files.

## Runtime

1. Split `RecordStore.compare_and_swap` into two capabilities:

```diff
 class RecordStore(Protocol):
     def load(...): ...
-    def compare_and_swap(self, user_id, expected_version, new) -> bool: ...
+    def commit_transition(self, user_id, expected_version, candidate) -> bool: ...
+    def ack_audit(self, user_id, expected_version, stream_id, seq) -> bool: ...
```

2. Rename every full-state CAS call on `start`, `new_epoch`, `_record_inflation`, `lower_mode`, and `evaluate` from `compare_and_swap(...)` to `commit_transition(...)`. Do not otherwise change candidate construction, retry bounds, decision release, or outbox-cap checks.

3. Implement `ack_audit` inside each store. It MUST construct the post-ack record internally. It takes no caller-supplied candidate record. Atomic preconditions:
   - current version equals `expected_version`;
   - `pending_audit` nonempty;
   - `pending_audit[0]` exactly matches `(stream_id, seq)`.

   Permitted mutation: increment record version and remove exactly `pending_audit[0]`; plus only any separately named ack-watermark metadata already present in v3.4.3. Do **not** mutate the audit chain cursor if that cursor is the chain-creation head.

4. Remove synchronous caller-path `drain_audit()` invocation after successful transition CAS. Successful evaluate returns after the committed decision is available. Outbox append remains inside the winning transition CAS.

5. Add `DrainWorker` from `async_audit_experiment.py`; it performs external sink/anchor I/O outside store locks and uses only `ack_audit` for durable acknowledgement.

## New experiment invariant

Add four tests under `ACK_MUTATION_IS_NARROW`:

- successful head ack changes only version/pending-ack state;
- non-head seq is rejected byte-identically;
- stale expected version is rejected byte-identically;
- structural API test proves `ack_audit` accepts no caller-supplied replacement record.

Mutation test: introduce a deliberately unsafe store method that accepts `candidate: UserRecord` for acknowledgement and prove the structural/invariance tests kill it.

Run these **in addition to**, not instead of, the frozen 42 tests.

## Benchmark v0.4 experiment changes

Replace sequential fault tapes for causal comparisons with stable logical keys:

```text
(seed, request_id, "commit_transition", retry_index)
(seed, stream_id, seq, "audit_ack", retry_index)
(seed, stream_id, seq, "sink_delivery", attempt_index)
```

Pre-generated workload/operation plan remains unchanged between sync and async runs.

Add report fields:

```text
decision_completion_fraction =
  (succeeded + completed_blocked_by_policy) / attempted

useful_success_fraction = succeeded / attempted

outbox_occupancy_fraction =
  backlog / (users * outbox_cap)
```

Keep `audit_delivery_lag_ms` as commit -> successful delivery. Do not call it anchor lag.

For async runs additionally report:

```text
audit_ack_conflict_rate
audit_ack_attempts_per_ack
worker_drain_invocations
worker_concurrency_errors
```

## Comparison matrix

Run sync frozen v3.4.3 and async experiment with identical logical workload/fault keys:

- hostile_hot baseline;
- sink latency: 0, 1, 5, 20 ms;
- sink failure: 0, 0.1, 0.3;
- seeds 1..5.

Success is evidence, not a version bump: the 1 ms CAS-pressure cliff is materially suppressed without weakening outbox capacity, terminal taxonomy closure, failure visibility, restart/backlog recovery, or any frozen invariant.
