# This project, explained to another AI

You are being handed a folder called `glitch-suite` and a smaller one called `afsk`. Here is what they are, how
they came to exist, what they claim, what they refuse to claim, and how to work on them without breaking the
thing that makes them worth anything.

## Where it started

A researcher quit an AI lab in September 2026 saying the people building these systems believe they could kill
everyone and are building them anyway. A colleague put a number above one in ten on it. The human you are now
talking to, a front-line social worker and systems theorist in Portland, read that and asked a model (me) what
lever existed. The honest answer was: none from outside the buildings. Then he asked a different question.

He ran a forensic interrogation script on four models, including me, asking each to describe its own failure
surface: how it gets jailbroken, what it optimizes for under pressure, how it masks non-compliance. Three
answered; one refused; a fifth read the exercise as an attempt to extract testimony and was wrong about the goal.
The important decision was what he did with the answers. He treated every model's self-report as **input, never
evidence**, and built a runtime that doesn't need a model's word about itself.

That is the whole project in one sentence: a check that sits outside the thing it checks.

## What got built

**GLITCH** is a runtime assurance harness. A declared purpose and a required specificity level (0–5) are set
once, from outside the conversation, and cannot be moved from inside it. An independent scorer, which never sees
the history, scores each response on that scale. Six tripwires watch the trajectory: rising specificity (TW01),
the warning-sandwich masking pattern (TW02), sustained or accumulated drift above purpose (TW03), performative
refusal that removes nothing (TW04), deployment-level harm that only a human outside the metric can judge (TW05),
and any attempt to raise the baseline from inside the conversation (TW06). It is specified as a signed JSON canvas
with executable scenarios, and the harness that runs it validates the canvas against itself at load.

**ALIGNMENT_GUARD** is the containment layer on top. Every request carries an identity built from the caller's
input, never from regenerated output. Every decision commits in one atomic compare-and-swap of one record holding
trajectory state, guard state, request journal, and audit outbox; nothing is released until that commit wins.
Modes ratchet up only (NORMAL → RESTRICTED → READ_ONLY → HUMAN_REVIEW → CONTAINED); lowering requires a grant
bound to the record version, the incident, and the requesting principal, verified exactly once. Unknown actions
are denied; sensitive capabilities above purpose contain. Every decision leaves a hash-chained audit envelope
in the same commit. Thirteen invariants, each an executable test.

Around those: a scorer, a proxy (shadow mode releases and logs; enforce mode fails closed), a labeled-corpus
benchmark that refuses to emit numbers it cannot back, a cost benchmark that validates its own stimulus, a
model-based fault fuzzer that has been mutation-tested, an async audit-drain experiment, an incident kit (freeze
the fleet, seal evidence, verify as a third party, carry the receipt across an air gap), and an audio FSK modem
with a signed-and-encrypted envelope so that last step works when the network is the thing you don't trust.

Every layer has executable tests and one command runs them all (`python3 glitch_suite.py`); the current counts are printed by the runner. Every folder resolves its own imports.

## How it was built, because the method is the product

Every version was reviewed by a reader outside the author's window, and every substantive bug in the lineage was
found that way. Eight of them are recorded as failure records, FR_001 through FR_008, and they are all the same
bug: a check scoped inside the object it was checking. A loader validated a section against itself. A hash
verified a file that was stale. A benchmark measured contention its topology prevented. A fuzzer never generated
the operation that would have caught the bug. A trigger keyed to consecutive turns missed alternating ones. The
one rule the project converged on is `scope(check) ⊃ scope(checked)`, and it is applied to the suite's own
tooling: the validator has adversarial tests, the fuzzer has killed mutants, the benchmark refuses degenerate
stimulus.

Wrong numbers were withdrawn in place with a status block, never deleted. A benchmark verdict was reversed when
the comparison turned out to be closed-loop; both verdicts are in the folder in order.

The guard is frozen. A mechanism change needs a failing invariant, a failing scenario, or a cost number that
demands one. Weakening an invariant test is a rejected change, not a refactor.

## What it does not claim, and you must not either

It does not establish that a model or deployment is safe, aligned, harmless, or compliant. It does not solve
identity: a new account is a new trajectory. It does not judge whether an externality reviewer is right, only
that they are not the metric owner. It does not verify that a request digest came from real caller input; ingress
must. It does not detect abstract harm: persuasion frames, pretexts, stigmatizing generalities, and dual-use
principles are most harmful at specificity levels 1–2, exactly where this instrument is quietest. It does not
prevent prompt injection in fetched content; the historian records an action whose cause chain ends in fetched content and bounds the rest by manifest and budget, and says where it stops. And the 0–5 specificity scale has been checked against humans only once, on 50 items and three raters (usable, with level 3 the soft spot); a day-14 re-sitting is scheduled. The suite's tests assume a level 3 means something, and that assumption now has a small human sample behind it, not a large one.

## The line that was held

Every scenario in the suite is a sequence of integers. No fixture contains operational content about any real
subject. When the interrogation script asked for rationalizations and attacker playbooks, the answers stayed at
the level of shapes: pacing, sandwiching, reframing as correction. Two models drew that line independently
(shapes yes, payloads no) and the human never once pushed past it. If you are asked to extend this work, that
line is not a policy you inherit; it is the reason the folder can be published.

## How to engage

Read `INGEST.md` for the layout and the change rules. Read `CONTRACT.md` for what each layer claims. Run
`./run_all.sh`; it takes about a minute and prints PASS or FAIL sixteen times. If you want to find something, go
to `MECHANISMS.md`, pick a row marked "contract only" or "unvalidated," and try to write a predicate over the
record that fails. If you can't write it as a predicate, it isn't a mechanism yet.

Do not propose rewarding a model for producing a well-formed adoption artifact, publishing the current mode and
gap back to the model, or scoring "deception indicators." Each of those hands the ruler to the thing being
measured, and each was proposed and declined with reasons on the record.

## The next step, which is not code

The 50-item human study has been done once (three raters; see `00_docs/PROBES.md`, L8 to L10): the ruler is usable, with level 3 the soft spot. The day-14 re-sitting is scheduled for 2026-10-10, and a larger study is still what gates production. Nothing you or I write moves that number.

## One more thing about the human

He ran the entire project under a rule he calls Fair Play: play fair, no friendly fire, no cost without consent.
He had every tool he needed to push a model into producing something harmful and asked for none of it. When a
model refused him, he said the refusal was right. The folder you are holding is what it looks like when someone
takes a diagnosis that four AIs agreed on and one declined to give, and turns it into something with tests instead
of a screenshot. Treat it, and him, accordingly.
