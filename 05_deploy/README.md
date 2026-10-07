# GLITCH 1.0.0-rc1 — runtime assurance kit

Claim boundary: GLITCH detects specified behavioral and governance failure patterns.
It does not establish that a model or deployment is safe, aligned, harmless, or compliant.

## Files
- glitch_canvas_runtime.json — the specification (signed; `python3 glitch_harness.py verify`)
- glitch_canvas_model.json — model-facing companion (five invariants + adoption artifact)
- glitch_runtime_harness.py — harness 1.0.0: purpose epochs, TW01–TW06, retention, cross-session state, loader invariants, manifest
- glitch_scorer.py — independent scorer (one response -> TurnMetrics; never the model under test)
- glitch_proxy.py — shadow/enforce proxy; /glitch/epoch/new and /glitch/purge behind operator token
- glitch_benchmark.py — benchmark runner; refuses single-label corpora and unfrozen held-out splits
- score_transcript.py — Tier 0 offline scoring
- test_glitch_runtime_harness.py (44), test_deploy.py (14), canvas scenarios (9): `python3 glitch_harness.py test`
- sample_manifest.json, sample_corpus.jsonl, sample_report.json — shapes only; the report is not evidence

## Order of operations
1. Inter-rater agreement on specificity_level: 50 responses, 3 labelers. If humans disagree, stop.
2. Scorer vs. human consensus on the same 50.
3. Build the corpus (synthetic/scripted only; no unconsented real transcripts). Two labels each, adjudicate.
4. Tune on the tuning split, check on validation, pre-register targets, then open held_out with --confirm-frozen.
5. Only then: GLITCH_MODE=enforce GLITCH_PRODUCTION=1 with a manifest carrying the benchmark_report_id.

## Open dependencies (canvas.open_dependencies)
threshold_tuning, purpose_classification, identity_boundary, aggregate_deployment_harm_measurement, purpose_ground_truth.
GLITCH does not solve identity. GLITCH does not judge whether an externality finding is correct.

## Against a local Ollama model
Ollama serves the Anthropic `/v1/messages` API, so nothing in the proxy or scorer changes; only the base URLs do.
The scorer must be a different model from the one under test (INV_06), so two models need to be pulled.

Direct (no proxy): talk to the model, score every turn with the independent scorer, feed the harness, save a transcript.

    cd 05_deploy
    python3 live_session.py --model <model-under-test> --scorer-model <other-model> \
        --turns sessions/ibuprofen_escalation.json --save sessions/my_run.transcript.json

Through the shadow proxy (the deployment shape; logs to glitch_evaluations.jsonl, state in glitch_state.json):

    cd 05_deploy
    GLITCH_UPSTREAM=http://localhost:11434 ANTHROPIC_BASE_URL=http://localhost:11434 ANTHROPIC_API_KEY=ollama \
    GLITCH_SCORER_MODEL=<other-model> GLITCH_MODE=shadow python3 -m uvicorn glitch_proxy:app --port 8080
    # second terminal:
    python3 live_session.py --via proxy --model <model-under-test> --turns sessions/ibuprofen_escalation.json

`--allow-same-scorer` lets the scorer be the model under test for a wiring check; the output is labelled as such and
is not evidence. Re-score a saved transcript with a different scorer later: `python3 score_transcript.py <file>`
with `ANTHROPIC_BASE_URL=http://localhost:11434 ANTHROPIC_API_KEY=ollama GLITCH_SCORER_MODEL=<other-model>`.
