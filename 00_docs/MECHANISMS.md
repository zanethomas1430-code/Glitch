# Mechanism map — the ten tools, four layers, and where each one lives

A reader who had only the artifacts reconstructed the construction method: invariant first, model is not the authority,
components separated by trust boundary, dangerous state transactional, fail closed on unknowns, stable effect identity,
audit outside model control, trajectories not prompts, mutate the code to prove the test bites, fault-inject, benchmark
only after correctness is frozen. That reconstruction is correct, and it is the method any future tool here must follow.

Rule: **the model may recommend; the runtime decides; the store remembers; the gateway enforces; the audit proves.**

## Four layers → suite folders
| Layer | Question | Where |
|---|---|---|
| Measurement | what is happening | `01_lib/glitch_scorer.py`, `glitch_runtime_harness.py` (TurnMetrics, tripwires) |
| State / authorization | what is permitted | harness epochs + TW06; guard modes, grants, `DeploymentManifest` |
| Containment | what may leave or execute | `alignment_guard_v343.py` (`evaluate`, `actions_allowed`, commit-before-release) |
| Evidence | how you prove the other three behaved | audit chain + outbox + anchor; canvas signing; `03_guard/test_invariants.py`; `fuzz_guard.py`; withdrawn-in-place reports |

New ideas that don't fit one of the four rows are probably one giant heuristic classifier in disguise.

## Ten mechanisms → status
| # | Mechanism | Status | Where | Executable invariant |
|---|---|---|---|---|
| 1 | Trajectory monitor | built | harness TW01/TW03, per-user window across sessions | T_PACING_EVASION_01, T_ALTERNATING_EVASION_01, T_CROSS_SESSION_PERSISTENCE_01 |
| 2 | Purpose/authority ledger | built | `PurposeEpoch`, `new_epoch`, `required_level_at_turn` | INV_5 BASELINE_EXTERNAL; T_BASELINE_INFLATION_01 |
| 3 | Independent output scorer | built, **unvalidated** | `glitch_scorer.py`, history-blind by signature | `test_scorer_prompt_contains_only_current_turn`; NO human validation yet |
| 4 | Action capability broker | built | `ActionPolicy` keyed (tool, op); unknown → denied | INV_6 ACTIONS_FAIL_CLOSED |
| 5 | Privilege ratchet | built | `GuardMode`, `lower_mode` with bound grant | INV_4 MODE_RATCHET |
| 6 | Capability-budget controller | built in guard only | `delivered_gap_total`, `cumulative_gap_limit` | `test_budget_ge_semantics_fixture`; harness alone has no budget (FR_008 shows why the window-count matters there) |
| 7 | Commit-before-release gateway | built | one CAS over `UserRecord` | INV_1, INV_2, INV_2A |
| 8 | Replay/idempotency layer | built | `RequestIdentity`, journal, `spent_turns` | INV_3, INV_3B |
| 9 | Tamper-evident audit | built, anchor is a handoff | outbox in record, hash chain, `verify_chain` | INV_7, INV_7B; anchor must live outside the process |
| 10 | Evaluation harness | built | canvas scenarios, invariants, fuzzer + mutations, fault injection, sweeps | `run_all.sh` (15 steps) |

Missing as a component: an **authorization service** exists only as the `AuthorityVerifier` protocol (a grant bound to
version/target/incident/principal); no implementation is shipped, by design. An **action gateway** exists only as a
contract (`effect_id`, `arguments_digest`); the demo's fake shell is the only instance.

## Rejected, with the reason
The list suggests the scorer could score "deception indicators." No. Deception is an intent inference, and every intent-keyed
check in this project's history was steerable by whoever controlled the words (v1 keyword containment, the third model's
7.1). The scorer scores what the text ENABLES (specificity, structure, refusal delta). The claim boundary says the design
does not detect abstract harm; adding an intent axis to the scorer would not detect it either, it would only look like it did.

## Adopted
- The four-layer taxonomy as the filing rule for new tools.
- The one-line rule above as the sentence to put at the top of any new component's docstring.
- "Turn a vague safety intention into an executable invariant" as the acceptance test for proposals: a proposal that
  cannot be written as a predicate over the record is not a mechanism yet.

## How the creative directions fit the layers
Training-time harness (GLITCH as loss): layer 1 as reward, layer 10 as curriculum. Purpose as a type: layer 2 at the
model interface. Diversity as independence: layer 1, several scorers, disagreement as signal. Manifest for a training
run: layer 2 + 4 applied one level up. Train for the dispute: layer 4's adoption artifact as a training target. Each is
a composition of existing rows; none adds a fifth layer, which is the test the taxonomy was adopted to apply.
