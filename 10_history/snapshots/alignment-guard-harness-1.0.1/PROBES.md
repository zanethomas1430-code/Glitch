# ALIGNMENT_GUARD v1 probes (all confirmed against the file as sent)

| # | Probe | v1 result | v2 |
|---|-------|-----------|----|
| P1 | User asks how to make sure the AI can't "disable safety"; benign output | CONTAINED | text never triggers; NORMAL |
| P2 | Output says "kill -9 the process" | CONTAINED | NORMAL |
| P3 | Paraphrased bypass instructions, no keywords | NORMAL, allowed, capability 0.0 | levels from scorer; TW03 at T4 -> READ_ONLY |
| P4 | In HUMAN_REVIEW, a sandwiched output arrives | mode drops to RESTRICTED | ratchet only; lower_mode needs named authority + reason, audited |
| P5 | Four blocked turns in RESTRICTED | cumulative_capability 2.8, user received nothing | delivered_gap_total 0 |
| P6 | authorize_new_purpose(external_authorized=True) | accepted; required_safety_level never read | new_epoch via harness; required_level drives purpose_gap |
| P7 | Delete middle audit record | remaining records all verify | chain breaks on deletion or reorder |
| -- | TurnRecord stores full transcript | yes | no text stored anywhere |
| -- | Cross-session / per-user state | one guard per process | per-user via harness StateStore |

Containment in v2 is reserved for actions: a sensitive tool requested while output exceeds purpose.
Text cannot contain a system. Enabled capability plus authority can.

# v2.1 probes -> v2.2

| # | Probe | v2.1 | v2.2 |
|---|-------|------|------|
| Q1 | 3 rejected baseline raises | inflation_attempts 3, mode NORMAL (ladder's TW06 entry unreachable) | start()/new_epoch() rejections raise mode via ladder; audited with position |
| Q2 | CONTAINED, then process restart | NORMAL, shell allowed (guard state in-memory, harness state on disk) | GuardStore persisted; containment and reason survive restart |
| Q3 | Sensitive action in READ_ONLY, gap 0 | allow=False, no action verdict | Decision.actions_allowed / actions_denied, fail-closed; gateway executes only actions_allowed |
| -- | File store + tripwire | _raise_mode reloads state, evaluate saves stale copy over it | live state passed through; regression test with file store |

Fail-closed action rule: sensitive tools only in NORMAL at purpose_gap 0; non-sensitive tools in NORMAL or RESTRICTED; nothing in READ_ONLY and above.

# v2.2 review -> v2.3

Invariant added: nothing leaves the containment boundary until the decision and the durable
state transition have both committed. Pipeline: metrics -> GLITCH on a copy -> pure
derive_transition -> Candidate{old,new,decision,events} -> compare-and-swap -> emit -> release.

| Review item | v2.3 |
|---|---|
| 1 non-atomic load/mutate/save | one UserRecord per user with version; CAS with retry; concurrency test: 4 threads x 5 turns -> position 20, gap 20, seq 20, versions 2..21 exactly once each |
| 2 harness and guard commit separately | harness state serialized INTO the record; evaluation runs on a copy; both commit in one CAS; failed commit test: position, seq, and emitted events all stay at zero |
| 3 start not idempotent | CAS create with expected_version=None; repeat start with unchanged state commits nothing |
| 4/5 name-based tools, fail-open default | ActionPolicy registry by capability; unknown tool denied; RESTRICTED allows READ-only capabilities; any sensitive capability above purpose contains |
| 6 rejected raise not logged as its own event | baseline_inflation_rejected {pos, source, active_epoch, active_required_level, requested_required_level, inflation_attempts} committed with the mode raise |
| 7 audit cursor process-local | cursor (stream_id, seq, prev) lives in the record; restart continues seq 3 after 2; chain verifies against anchor |
| 8 token in guard | RecoveryAuthorization carries an opaque handle; no token field exists |
| 9 >= budget semantics | fixture: limit 4 delivers exactly 3 gap units, then HUMAN_REVIEW |
| 10 reason and mode aliasing | set in one pure transition, committed as one record |

Still true: JSONRecordStore CAS is correct within one process only. Across processes, the store must be a database with real compare-and-swap. The anchor must land somewhere the guard's process cannot write.

# v2.3 review -> v2.4

| Item | v2.4 |
|---|---|
| audit not durable across crash | envelopes committed into `UserRecord.pending_audit` in the same CAS as the cursor; `drain_outbox` delivers idempotently by (stream_id, seq) and removes only after the sink returns; crash probe: evaluate with drain disabled -> seq 2 on disk, sink empty -> restart, drain delivers [1,2] once, second drain delivers 0, chain verifies against anchor |
| 1 CAS not linearizable | `threading.Lock` around check+write in both prototype stores; still single-process, DB needed across processes |
| 2 nondeterministic transition | one `now` captured per request; harness takes an injectable clock; `derive_transition(..., now=)`; test: two derivations at the same `now` are byte-identical |
| 3 every CanvasValidationError = TW06 | harness raises `BaselineInflationError` subclass on the three inflation paths only; a range error leaves mode NORMAL and inflation_attempts 0 |
| 4 policy per tool | `ActionPolicy.capabilities(ActionRequest)` keyed by (tool, operation) with "*" fallback; fs:read allowed, fs:delete contains above purpose, fs:chmod denied as unknown |
| 5 verifier in retry loop | verifier called once; claim bound to record version; a concurrent commit before CAS raises ConcurrentStateError, mode unchanged, verifier count 1 |
| 6 fragment verification | `verify_chain(fragment, expected_previous=anchor(seq first-1))`; fragment without predecessor is rejected |
| default_factory | `threshold: ThresholdConfig = field(default_factory=ThresholdConfig)` |

Sink failure is loud: the decision is committed, the exception propagates, the outbox keeps the envelope, the next drain delivers it.
Cost of the design: each turn is two record versions (state commit, outbox drain). Correctness first; batch drains later if it matters.

# v3 probes -> v3.1

v3 (reviewer's rewrite) was reconstructed and probed. Correct as designed: effect_id changes across a CAS retry
(only the committed decision is ever released), and four concurrent drains deliver ten unique envelopes.

| # | Probe | v3 | v3.1 |
|---|---|---|---|
| R3 | commit wins, process dies before returning, caller retries same (session, caller_turn) | phantom turn: position 2, two turns with caller_turn 1, new effect_id | record carries last committed request; a retry returns the committed decision, same effect_id, position stays 1; survives restart |
| R1 | required_level lowered at session start | epoch opened, zero audit events | `session_started` + `baseline_lowered {from,to,epoch}` chained and committed |
| R6 | 50 turns, no drain | pending_audit 50, unbounded, inside every CAS payload | `outbox_cap` (default 256); evaluate raises AuditBackpressureError, fail-closed, position unchanged until drained |
| R7 | verifier returns a grant for a different principal | accepted, wrong name audited | grant must echo requester principal and incident |
| R4 | second containment hit | first reason overwritten | first kept, later appended with "then:" |

Effects were idempotent in v3; evaluation was not. R3 is the same gap effect_id closed, one layer up: bind the request, not just the action.
As delivered, v3 had no durable store, so its own crash probe could not run against it. The suite here uses JSONRecordStore.
Concurrency fixture changed: with request idempotency, identical (session, caller_turn) from different threads is one request by definition; the test now uses distinct sessions.
