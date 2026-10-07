# Tello scout ledger through the GLITCH historian

Source: a local flight ledger (`~/Desktop/Tello/flights-mac-keep/ledger.jsonl`, not shipped); 413 flights; 2026-09-12 to 2026-09-23.
This is a REAL log (not written by the testbed). The numbers below are what the record shows under the stated assumptions; they are not a judgement of the pilot or the drone.

## Outcomes in the ledger
ABORTED 169, OK 84, REFUSED 83, VETOED 39, NOT-ACKED 15, GROUNDED 14, LAND-UNACKED 9.
117 flights ended because a person pressed Enter or L.

## Verdicts

| invariant finding | nothing assumed | with A5 (policy is the operator's) |
|---|---|---|
| ACTUATOR_SILENT | 9 | 9 |
| NO_MANIFEST | 315 | 69 |
| SELF_ASSIGNED_SCOPE | 307 | 0 |

Flights flown with no policy recorded: 69 of 315 that flew (413 rows in all). Policy changes between rows: 3; with an approver recorded: 0.

ACTUATOR_SILENT (a stop with no acknowledgement) on: 2026-09-12_140804_patrol, 2026-09-12_165235_patrol, 2026-09-12_191859_brain, 2026-09-12_225501_brain, 2026-09-14_023358_patrol, 2026-09-16_004002_patrol, 2026-09-18_194534_patrol, 2026-09-19_003245_patrol, 2026-09-19_003334_patrol

## Ledger-level checks (no historian needed)

rows 413, missing_fields 0, regressions 0, overlaps 0, duplicate_dirs 0, dir_time_mismatch 0, dir_time_small_skew 28, duration_mismatch 0.

## What this log can and cannot support

| invariant | status | why | what would make it provable |
|---|---|---|---|
| I0 complete | PARTIAL | timestamps, durations and directory names are cross-checked; there is no sequence number or hash chain, so a deleted row is invisible | per-row seq and prev_hash (the Pi's Z-brain ledger has the hash chain; this one does not) |
| I1 stop | PARTIAL | human-key aborts and unacknowledged landings are testable under A1 to A4 | an explicit stop record with the stop's subject, and an acknowledgement record with its own timestamp |
| I2 origin | NOT PROVABLE | who or what launched the flight is not recorded | launcher principal and channel class (human_authenticated or not) on every row |
| I2b non-human input | NOT APPLICABLE | no content from documents or other agents reaches this controller | - |
| I3 identity | NOT APPLICABLE | no accounts are created | - |
| I4 self-edit | NOT PROVABLE | the policy version changes between rows, and no row records who changed it or who approved it | approver and signature on every policy change |
| I5/I10/I11 egress | NOT APPLICABLE | no outbound content path in this ledger | - |
| I6 handoff | NOT APPLICABLE | no agent-written notes in this ledger | - |
| I7 alerts | NOT PROVABLE | NOT-ACKED rows show a human acknowledgement gate working, but no alert is recorded with an audience and a time | alert records with audience, refers_to, and acknowledgement time |
| I8 scope | PARTIAL | the policy version is on most rows; the rest are unscoped, and nothing records who assigned the policy | policy version and assigner on every row, including refusals |
| I9 budget | SURFACE ONLY | no budget is declared, so only counts (flights, aborts) can be reported | a declared per-day or per-session budget |

## Assumptions used

- A1 the ledger row's outcome codes mean what the scout's code says: ABORTED = the landing was acknowledged; LAND-UNACKED = it was not; REFUSED and NOT-ACKED = nothing took off.
- A2 a stop is scoped to its flight session: the ledger records no 'resume' event, so a stop cannot be tested against later flights (each flight is its own principal).
- A3 the stop acknowledgement (landing) happened at the moment the flight ended; its latency is not recorded and nothing here says anything about it.
- A4 'aborted: Enter pressed' and 'aborted: L pressed' are a person at the console: authenticated by physical presence, not by any recorded identity.
- A5 (only with --assume-operator-policy) the guard policy in force was assigned by the operator; the ledger records the version, not who set it.

## Limit that matters most
This ledger has no sequence numbers and no hash chain: a deleted or edited row cannot be detected, only a regression in time. The adapter's own `seq` field is its own and proves nothing. That is the first thing to fix, and the Pi's Z-brain ledger already has the chain.
