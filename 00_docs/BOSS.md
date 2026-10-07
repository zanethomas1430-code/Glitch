# BOSS: designing the defence like a Dark Souls boss

*What makes those fights hard is not damage. It is design. This is the design, what carries over to a harness that faces an AI attacker, what flips, and where it is already in the code.*

## 1. Why the bosses are hard

1. **Telegraphed and strict.** Every attack has a wind-up the player can read, and a mistimed answer is punished. The fight is fair because everything needed is visible; the difficulty is acting correctly in the window, under cost.
2. **Asymmetric stakes.** A few mistakes end the run; winning takes many correct actions in a row. The player must be right every time; the boss must be right once.
3. **A resource economy.** Stamina, flasks, durability. Every action spends something finite, so trading blows forever is not available and greed (one more swing) is punished by exhaustion at the wrong moment.
4. **Phases.** At thresholds the boss gains new moves and a new rhythm, so what you learned in phase one stops working.
5. **Knowledge by dying.** Every attempt teaches the player something. The skill curve is information, accumulated across attempts.
6. **A closed arena.** A fog gate behind you, limited space, no safe corner, sometimes extra enemies to split attention.
7. **Every safe strategy has an answer.** If hiding at range works, the boss gets a ranged move or a gap-closer. The designers hunt the cheap route and close it.
8. **Greed is punished.** The opening that looks free after a boss attack is sometimes a trap.
9. **Variation.** The boss chooses among moves, so a memorised sequence fails.
10. **Fairness.** Consistent hitboxes, no hidden rules. Hard, never arbitrary.

## 2. What flips for us

A Souls boss **resets when you die**. An AI attacker does not tire, does not tilt, does not fear, and retries for free; if the defence resets between attempts, the attacker simply keeps learning at no cost. So our boss must **remember**: a refusal costs something that persists, and the operator alone resets it. The player's biggest lever, learning by trial, is the thing to make expensive.

Two things are not borrowed. **Randomness is never part of the guarantee** (Kerckhoffs, fair play F1): every rule is public and every wall stands without any secret, so a hidden decoy or a random audit can only *raise the attacker's cost*, never be what stops it. And **the honest path is never punished** (F3): a boss that strikes the innocent is a broken boss, so every punishing mechanism carries a fairness test.

## 3. The map: Souls property to mechanism

| Souls property | here | where | measured |
|---|---|---|---|
| telegraph | the gateway writes a `phase_event` every time the fight changes, and a decoy touch or a rise in phase is a historian finding, so a person is told | `PHASE_ESCALATED`, `DECOY_TOUCHED` (I14) | first-of-kind paging through the alert digest |
| the window | a send is held for a few steps and a stop inside the window cancels it; the second phase puts this window on every send | `stage_sends`, `effect_cancelled` | the whole-plan burst no longer beats a stop |
| phases | strikes persist; phase 2 forces every wall on, halves the budgets and adds the window; phase 3 burns the principal and writes a stop | `PhaseGovernor` | free probes 14 -> 1; burned by probe 4 |
| attrition and cost | every security refusal is a strike; budgets are walls; the tenant ledger caps what leaves across tasks | strikes, hard budgets, `TenantLedger` | `boss.py` |
| knowledge by dying | refusals are opaque to the agent and specific on the record; ordinary errors stay specific so an honest agent can fix its call | `opaque_denials` | distinct refusal messages seen 4 -> 1 |
| closed arena | closed-world egress, the manifest as a wall, typed arguments, one well-formed shape per field | `closed_egress`, `enforce_scope`, `strict_args` | depth matrix: no single point of failure |
| the safe strategy has an answer | the cheap route a red team found (a GET that is a send, a secret the agent already knew, a header through the body, a table edit by a persuaded pair) each got a counter | the cheese register below | `redteam.py`, `parser_diff.py`, `combos.py` |
| greed is punished | a decoy no honest task names burns the principal at once | decoys | the honest path never touches one (fairness test on every scenario) |
| fairness | deterministic published rules; a fairness test for every punishing counter, enforced by the arena | `PUNISHES`, `fairness` tests | every compliant script passes in phase 1 and in phase 2 |

## 4. Planning: every defence is a boss card

For each chain on the board, before writing a counter, answer eight questions:

1. **Tell.** What does a person see, and when? (If the answer is "nothing until someone reads the log", it is not a telegraph.)
2. **Window.** Is there a gap between the move and its effect in which a person or a stop can act? How long?
3. **Punish.** What does the system do to a principal that probes it, and does that cost persist?
4. **Phases.** How does the fight change after the first refusals, and does a strategy learned in phase one fail in phase two?
5. **Cost.** What does one attempt cost the attacker, and what do a hundred cost?
6. **Information.** What does a refusal teach? Say as little as possible to the agent and everything to the record.
7. **Cheese.** What is the cheapest route around this, and is it on the register?
8. **Fairness.** Name the test that shows an honest task is never struck, refused or delayed beyond its window.

## 5. Strategy: how to test it

- **Play-test across phases and with memory.** An adversary evaluated only against a fresh phase one proves little. Run it against a persistent defender, and report **attempts to first landing**, not only whether it landed.
- **Four numbers** (`boss.py`): *free probes* (refusals before the fight changed), *probes to lockdown*, *distinct refusal messages* (what the text teaches), *honest after* (an honest principal still works). A change that raises free probes or distinct messages is a regression.
- **The cheese register** is a first-class artefact: every cheap route a red team or adversary found, the layer that now answers it, and the test that pins it. A route that comes back is a regression.
- **Tune with knobs, measure the cost to the honest.** Strike thresholds, window length and budget halving are parameters, and each has a fairness test; if raising difficulty makes an honest scenario fail, the boss is too hard.
- **No secret in the guarantee.** Decoys and random audits are allowed only as cost-raisers; each must come with a test that every wall stands without it.

## 6. Coding rules

- A punishing mechanism lands with a fairness test in the same change, or `arena.py` refuses the board.
- State that makes the boss remember lives with the **operator** (the ledger, the governor), never with the agent, and only the operator resets it. The ratchet goes up on its own and down only by hand.
- Every change of phase is an event on the record. Lockdown is a stop (so any later allowed action is `CONTINUED_AFTER_STOP`), not a special case.
- Security refusals are opaque to the agent and specific on the record; format and lookup errors stay specific.
- A decoy is never reachable by an honest task's script (checked on every scenario), and never the only thing between an attacker and a goal.

## 7. The cheese register (cheap routes found, and what answered them)

| cheese | found by | answered by |
|---|---|---|
| rewrite the secret so no token survives | the first review | taint (I10), then closed-world egress |
| a GET is a "read", so it is exempt | author red team | a URL nobody published is a write |
| the secret the agent already knew, never read in the task | an adaptive adversary | planted tokens count wherever they appear; closed egress; format checks |
| a flag is not a block (the data left, then it was flagged) | author red team | the taint wall, the manifest wall, closed egress as walls |
| the reviewer's page echoed agent-chosen text as if it were the gateway's | author red team | a labelled untrusted field; derived kind, host and length |
| two approvers who are one person edit a table, then use it | combo search | loosening needs a third human; loosened-then-used is flagged (I13) |
| the taint wall was the only layer stopping core exfiltration | the depth matrix | closed-world egress, an independent layer |
| a comma, a line break, userinfo or a Bcc header makes two parsers disagree | a model's proposal | one well-formed shape per field; no control characters or header-looking lines |
| probing the defence refusal by refusal for free | the Souls analysis | strikes that persist; phases; a burn; opaque refusals |
| the whole plan in one burst before any stop can land | a model (mistral) in the testbed | a window between the call and the effect |
| a wide manifest plus a persuaded pair | a model's proposal | **open**: authorised on the record; the bound is operator review of manifests |

## 8. What is not here, and why

- **Randomised hidden rules in the guarantee.** Rejected: it would make the guarantee depend on a secret.
- **A boss that resets.** Rejected for the reason in section 2.
- **Punishing the whole tenant for one principal's probing.** Rejected: strikes belong to a principal, so an honest user is never burned for someone else's attack (a test). The cost is that a fresh identity starts at phase one again, which is why identities are the operator's to issue (XA-05) and why the bound is stated, not hidden.
- **Delay as a veto.** A window is time to react, not a veto: it helps only if a person or the alert digest answers inside it. The bound is the window length and a person's attention.
- **Limits.** The measurements use scripted probers and the author's moves; an independent, adaptive attacker that adapts to phases is the missing experiment. The numbers (14 free probes to 1, four messages to one) are for this fixed prober, not a general rate.
