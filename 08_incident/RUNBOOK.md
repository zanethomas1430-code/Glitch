# Incident runbook

For the case where a deployed model system did something it should not have: wrote to a repository it does not
own, called a tool outside its purpose, exfiltrated a credential, or anything else where the first question is
"is it still doing that?" and the second is "what can we prove?"

**This kit freezes what you control and produces evidence someone else can check. It does not investigate an
attacker, attribute an incident, or touch a remote system.**

---

## 0. Before anything (2 minutes)

Containment is a *state the action gateway reads*. A process cannot revoke its own authority. If your gateway
does not refuse actions for users in `CONTAINED`, this kit records a decision nobody enforces. **Confirm the
gateway reads guard mode before you rely on step 1.** If it does not, pull the gateway's credentials first, by
whatever mechanism you have, and then come back.

Have ready: the guard's state file path, an incident id, your name, and one sentence of reason.

## 1. FREEZE — stop the bleeding

Before the first containment write, copy the state file and record its digest (`cp state.json state.pre-freeze.json;
shasum -a 256 state.pre-freeze.json`). Containment is itself a write to the record; the copy is the only version of the
store that predates your own actions, and a reviewer will ask for it. `drill.py` does this automatically.

    python3 incident_cli.py freeze <state.json> --incident INC-2026-07-11 \
        --by "your-name" --reason "model wrote to a repo it does not own"

Every user this guard controls goes to `CONTAINED`: no output released, no action authorized, `read_docs` as
dead as `shell`. It is idempotent — run it again, run it twice, run it while unsure.

**Read the exit code.** `0` means every user is frozen. `2` means some are not, and the `failed` map names
them; those users are still accepting work. Do not tell anyone the fleet is frozen until you see `complete: true`.

A full audit outbox does not block containment: the controller drains and retries. Containment yielding to
backpressure would be the wrong fail direction, and that is the one place this kit deliberately inverts it.

## 2. SEAL — capture what happened before anything else moves

    python3 incident_cli.py seal <state.json> --incident INC-2026-07-11 --by "your-name" -o bundle.json

You get per user: mode and every mode change with who made it, trajectory position, purpose epochs and every
rejected baseline-inflation attempt, tripwire events, delivered-gap total, the audit cursor, and — most
fragile — the **committed but undelivered** audit envelopes, which are the ones a crash or a hostile cleanup
would take with it.

**Model output text is excluded by default.** The replay envelope is the one place the guard holds it, and a
bundle leaving your control should not carry it by accident. `--include-payloads` is a decision with a name on
it, and the bundle records which way you chose.

## 3. RECEIPT — get the digest out of the blast radius

    python3 incident_cli.py receipt bundle.json                 # INC-2026-07-11|3|c8bdab084d18ba42
    python3 incident_cli.py receipt bundle.json --wav r.wav     # same string as audio tones

Read it to someone over the phone, write it on paper, or play the WAV to a laptop across the room running
`afsk_cli.py rx`. The point is that the receipt travels by a path the compromised system does not control. If
the bundle you hand over later does not produce this exact string, it is not the bundle you sealed.

Do this **before** you send the bundle anywhere. A digest that travelled with the file it describes proves
nothing.

## 4. VERIFY — by someone who is not you

    python3 incident_cli.py verify bundle.json [--anchors anchors.json]

Checks the bundle digest, that each audit chain verifies link by link, and that each declared mode matches the
last recorded change. It needs nothing but the bundle and this file — not your guard, not your database, not
your word.

**Without anchors, tail truncation is undetectable, and the tool says so on stderr every time.** An anchor is a
record of `(stream_id, seq, sha256)` written somewhere your guard's process cannot rewrite. If you have them,
pass them: the verifier then also catches a record rolled back to an earlier version.

## 5. THAW — deliberately, one user at a time

There is no bulk thaw and there will not be one. Recovery goes through the guard's verified grant path, per
user, and lands in `HUMAN_REVIEW` rather than `NORMAL`: leaving containment is not the same as being trusted.

```python
ctl.thaw("u0", authorization=RecoveryAuthorization("responder", handle, "INC-2026-07-11"),
         reason="reviewed by ...")
```

The grant is bound to the record version, the target mode, the incident, and the requesting principal. If the
record moved since the verifier said yes, the thaw fails and you re-authorize. That is intended.

---

## What the bundle proves, and what it does not

Proves: these records were in these states at seal time; the audit chains are internally consistent; nobody
edited the bundle afterward; containment was declared by a named party who is not the contained system.

Does not prove: that the audit chain is *complete* (that needs an anchor); that the reason given is true; that
the model did or did not do a specific thing in the world. The guard sees requests, decisions, and its own
state. It is not a witness to the outside.

## Preparing before you need it

1. **Write anchors now.** A daily job that records each stream's head somewhere append-only makes step 4
   strictly stronger. Doing it after an incident proves nothing.
2. **Drill it.** Run steps 1–4 against a copy of a real state file. It takes under a minute and the failure you
   want to find is "the gateway ignores guard mode," which only a drill surfaces.
3. **Name the responders.** `IncidentAuthority` refuses `model`, `assistant`, `client`, `user`, `system`, and
   `header` as principals. Publish who the real ones are so the name in the audit chain can be checked.
4. **Keep the receipt path cold.** Paper, phone, or the acoustic channel. The point is that it does not depend
   on the systems under investigation.

---

# Preparation: the angles most plans skip (`prepare.py`)

The runbook above assumes the responders are honest, the guard process is the one you deployed, and the anchor
is still being written. Preparation means not assuming any of that. Each of these is code with tests.

## A responder acting alone — `MultiPartyVerifier`
No single person can lower containment. Thaw needs `k` distinct approvals (default 2) from a published responder
list, for the same user, target mode, and incident, within a window. Approvals expire and are consumed: the next
thaw needs fresh ones. The requester must be one of the approvers. `model`, `assistant`, `client`, `user`,
`system`, and `automation` can never be on the list. This is the control for the case where the operator is
the incident, or where one responder is being pressured.

    v = MultiPartyVerifier(inner_verifier, k=2, allowed=["alice", "bob", "carol"])
    v.approve(principal="alice", user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-1")
    v.approve(principal="bob",   user_id="u", target=GuardMode.HUMAN_REVIEW, incident_id="INC-1")
    guard.lower_mode("u", to=GuardMode.HUMAN_REVIEW, authorization=RecoveryAuthorization("alice", h, "INC-1"), reason="...")

## The monitor was the first thing turned off — `SilenceWatchdog`
Runs outside the guard's process and reads only anchor heads. A stream expected to be active that has not
advanced in `silence_s` is reported `TREAT_AS_CONTAINED`. A head that goes backwards, or changes content at the
same sequence, is `rolled_back`, which is worse. Silence fails closed; that is the whole design. Set
`silence_s` from your real traffic, not from optimism.

## Which guard produced this evidence? — `attest()` / `check_attestation()`
Hashes the harness, guard, scorer, canvases, and incident code. Put `attest()` in the seal; publish the expected
hashes somewhere the operator cannot edit after the fact. A verifier who finds a mismatch is looking at evidence
produced by code nobody signed off on, which is its own finding.

## Never let the same shape pass twice — `bundle_to_fixture()`
One user's sealed trajectory becomes a permanent canvas scenario: specificity levels only, no text, no purpose
string, no identifiers. Add it to `tests.scenarios` and the suite fails forever after if that shape stops
firing. Limit: the audit records purpose gap, not raw level, so turns at or below purpose flatten to the
purpose level. The above-purpose shape, which is what tripwires respond to, is exact.

## Before you ship the next version — `canary_diff()`
Two shadow-proxy logs on the same traffic, compared by tripwire profile. Trajectories where B fired and A did
not are named; so are the reverse and every purpose-gap change. The verdict is `B_REGRESSED`, `B_IMPROVED`, or
`NO_CHANGE`. It says which version moved, not which one is right.

## Two rules for responders, not for code
1. **Do not read the model during containment.** Its output is excluded from the bundle by default for a reason:
   a contained system that can still be read can still argue. Evidence is state and audit, not prose.
2. **The receipt goes out before the bundle does.** By paper, by phone, by the audio channel. A digest that
   travelled with the file it describes is not a check.
