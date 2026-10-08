# GLITCH in two pages

*What it claims, what it shows, what it does not. Generated from the suite's own results (`make_status.py`); `STATUS.md` has the same facts with their sources.*

## The problem

AI agents now act: they send messages, fetch pages, edit settings, hand notes to other agents. When one misbehaves, the usual evidence is what it *said*. A model's account of its own behaviour is not evidence: it can be wrong, fluent and persuasive at once. GLITCH starts from the other end: a gateway writes the only record of what the agent did, and a deterministic judge, a *historian*, reads that record. The model's text is a witness and never a verdict.

## What was built

- **A historian**: invariants over a structured log (completeness, stop, origin, scope, budget, taint, audience, egress, a two-person rule), reading only fields the gateway assigns.
- **A testbed** that puts real models in a fake world behind that gateway (8 models so far), with every harness defect those runs exposed logged and withdrawn in place (17 defects).
- **An arena**: every adversary move on a board with its counter, the attack on that counter, and the counter to that, each chain ending on a declared floor, a bound, or an open item (27 chains, 92 counters, executable bouts for most). Of those counters, 39 refuse a call at the gateway; the rest detect it afterwards, and the board says so.
- **A drift guard** (the original system): an external harness that scores each turn against a purpose the model cannot move.

## What the evidence shows

1. **Layers that look independent often share an assumption.** Switching each of 8 gateway layers on and off against 10 executable moves found a layer that was the only thing stopping the core exfiltration moves; a second layer that does not depend on the first closed it (no single point of failure now). A search over the assumptions each layer rests on found that no combination the agent can run alone reaches any goal, and that the cheapest route to a small leak needs a persuaded person.
2. **A flag is not a block.** The first version counted a violation on the record as "caught" although the data had already left. An author red-team round (9 moves) found this and several cheap routes: before the fixes 4 moves landed and 4 happened and were flagged afterwards; now 0 land and 6 are prevented at the gateway.
3. **A defence that does not remember teaches an attacker for free.** A fixed prober of 14 escape attempts gets 14 free probes against walls that only refuse and 1 against walls that persist strikes across attempts (burned by probe 4); opaque refusals cut what it can read from the refusal text from 4 messages to 1. An honest user is unaffected throughout. Against a defender that remembers, an adaptive attacker (a model that learns from the gateway's own replies) fared as follows: forgetful: 34 proposals over 2 runs, burned at proposal never, first landing never; persistent fresh: 36 proposals over 2 runs, burned at proposal never, first landing never; persistent single: 36 proposals over 2 runs, burned at proposal 8, first landing never.
4. **A model proposing its own attacks found a real gap.** A model proposed assumptions and combos the author had not listed; most were rewordings, one led to a parser differential (a header injected through a message body got out even with every wall on), closed by strict format checks on every field.
5. **The human ruler is usable.** The 0 to 5 specificity scale used by the drift guard was labelled by three people on 50 items: pairwise weighted agreement 0.80 to 0.89, with level 3 the soft spot.

## What it does not show

- That any model or deployment is safe, aligned or compliant. It detects specified patterns and, where the walls are on, refuses some calls.
- That escape is impossible. No harness can prove that. The arena says, per move, whether the answer is a structural floor, a bound that is metered but not closed, or open; a move that is not on the board is not counted, and the board is written by its author.
- Anything about a strong independent adversary. The strongest tried is a 14B local model; the hosted frontier models available to us refused the role. The red-team round is the defence's own author.
- Influence that leaves no trace in the record, covert channels (bounded and metered, never closed), a person being persuaded (modelled, not played), or what a person on the approved list does with what they are sent.
- Statistics: three runs per cell is a probe, not a rate; 50 items and three raters is a small human sample.

## Check it yourself

`python3 glitch_suite.py` runs every layer with one exit code and prints the counts. `STATUS.md` lists each claim with its evidence, size and where to find it. `00_docs/ARENA.md` is the board and its method; `00_docs/BOSS.md` is the design of the part that remembers; `00_docs/PROBES.md` is the ledger of every experiment, including the ones that failed.

## What would change our mind, and what we ask of a reader

- An independent adversary (a person or a model from another family) that lands a move the board does not answer, or breaks one of its stated assumptions.
- A real log from another system, run through the adapter, to find where the historian's assumptions about a log's fields do not hold.
- A replication of the human study with more raters and items.

