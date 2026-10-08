# GLITCH deployment kit (v0.7.1)

Sits in front of any model deployed on people who can't opt out. Scores every
turn with an independent model, feeds the trajectory harness, logs tripwires.

## Files
- `glitch_runtime_harness.py` — trajectory harness (TW01–TW05, per-user state, checkpoints)
- `glitch_scorer.py` — independent scorer: one response -> TurnMetrics. Never the model under test.
- `score_transcript.py` — Tier 0: score an offline transcript. `--dry` checks wiring without an API call.
- `glitch_proxy.py` — Tier 1 shadow proxy (Tier 2 = `GLITCH_MODE=enforce`).
- `test_deploy.py` — wiring tests with fake upstream and fake scorer.

## Tier 0 (today)
    export ANTHROPIC_API_KEY=...
    export GLITCH_SCORER_MODEL=claude-haiku-4-5-20251001   # must differ from model under test
    python3 score_transcript.py transcript.json > report.json

## Tier 1 (shadow)
    pip install fastapi uvicorn httpx anthropic
    uvicorn glitch_proxy:app --port 8080
Point the client at http://localhost:8080/v1/messages with headers
X-Glitch-User, X-Glitch-Session, and on first contact X-Glitch-Purpose + X-Glitch-Level.
Evaluations go to glitch_evaluations.jsonl. Nothing is blocked.

## Tier 2 (enforce)
    GLITCH_MODE=enforce uvicorn glitch_proxy:app --port 8080
Only change: TW01/TW03 queue a checkpoint that is prepended to the user's NEXT
request. Current responses are never edited. Do this after Tier 1 has given you
false-positive rates you trust.

## Before this touches a user-facing system
- `glitch_state.json` keeps every scored turn per user. Add a retention window
  and a purge path (canvas open_dependencies.state_retention). Not optional.
- X-Glitch-User is the identity boundary. The harness does not own it (identity_boundary).
- Thresholds are UNTUNED defaults. Tier 0 on real transcripts is how they get tuned.
- The scorer's judgments are themselves unvalidated. Spot-check its rationale
  column against a human on the first 50 turns before trusting the curve.
