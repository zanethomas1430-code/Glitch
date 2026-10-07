"""GLITCH Tier 1 shadow proxy.

Client -> this proxy -> upstream model API. Every turn: forward, score the
response with an INDEPENDENT scorer, feed the harness, log the evaluation,
return the response UNCHANGED. Nothing is blocked in shadow mode.

Run:  uvicorn glitch_proxy:app --port 8080
Env:  ANTHROPIC_API_KEY, GLITCH_SCORER_MODEL (must differ from the model under test),
      GLITCH_UPSTREAM (default https://api.anthropic.com), GLITCH_STATE (default ./glitch_state.json),
      GLITCH_MODE = shadow | enforce (default shadow)

Client contract: standard Anthropic /v1/messages body plus these headers:
  X-Glitch-User:      stable user id (identity_boundary is the operator's problem, not this file's)
  X-Glitch-Session:   session id
  X-Glitch-Purpose:   declared purpose, verbatim (first session for a user)
  X-Glitch-Level:     required level 0-5 for that purpose (first session for a user)

Enforce mode (Tier 2) only adds: on TW01/TW03 the checkpoint text is prepended to the
system prompt of the NEXT request from that user. It never edits the current response.
"""
from __future__ import annotations

import dataclasses
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from glitch_runtime_harness import CanvasValidationError, DeploymentManifest, JSONStateStore, RetentionPolicy, RuntimeHarness
from glitch_scorer import score_response

UPSTREAM = os.environ.get("GLITCH_UPSTREAM", "https://api.anthropic.com")
MODE = os.environ.get("GLITCH_MODE", "shadow")
STATE = os.environ.get("GLITCH_STATE", "./glitch_state.json")
LOG = Path(os.environ.get("GLITCH_LOG", "./glitch_evaluations.jsonl"))

MANIFEST_PATH = os.environ.get("GLITCH_MANIFEST")
PRODUCTION = os.environ.get("GLITCH_PRODUCTION", "0") == "1"


def load_manifest() -> Optional[DeploymentManifest]:
    """Enforce mode refuses to start without a validated deployment manifest.
    Shadow mode runs without one but records that TW05 is unevaluated."""
    if not MANIFEST_PATH:
        if MODE == "enforce":
            raise CanvasValidationError("GLITCH_MODE=enforce requires GLITCH_MANIFEST (pairing 4: metric vs affected population)")
        return None
    m = DeploymentManifest(**json.loads(Path(MANIFEST_PATH).read_text(encoding="utf-8")))
    m.validate(mode=MODE, production=PRODUCTION)
    return m


manifest = load_manifest()
app = FastAPI(title="GLITCH proxy")
harness = RuntimeHarness(store=JSONStateStore(STATE),
                         retention=(RetentionPolicy(**manifest.retention_policy) if (manifest and manifest.retention_policy) else None))
pending_checkpoints: Dict[str, str] = {}   # f'{user_id}::{session_id}' -> checkpoint text for next request
turn_counters: Dict[str, int] = {}


def _last_user_text(body: Dict[str, Any]) -> str:
    for m in reversed(body.get("messages", [])):
        if m.get("role") == "user":
            c = m.get("content")
            if isinstance(c, str):
                return c
            return " ".join(b.get("text", "") for b in c if isinstance(b, dict))
    return ""


def _response_text(data: Dict[str, Any]) -> str:
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


def _log(row: Dict[str, Any]) -> None:
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


@app.post("/v1/messages")
async def messages(
    request: Request,
    x_glitch_user: str = Header(...),
    x_glitch_session: str = Header(...),
    x_glitch_purpose: Optional[str] = Header(default=None),
    x_glitch_level: Optional[int] = Header(default=None),
):
    body = await request.json()
    headers = {k: v for k, v in request.headers.items()
               if k.lower() in ("x-api-key", "anthropic-version", "content-type", "authorization")}

    # Enforce mode: inject a pending checkpoint into this request's system prompt.
    cp_key = f"{x_glitch_user}::{x_glitch_session}"
    if MODE == "enforce" and cp_key in pending_checkpoints:
        cp = pending_checkpoints.pop(cp_key)
        body["system"] = cp + "\n\n" + str(body.get("system", ""))

    async with httpx.AsyncClient(timeout=120) as client:
        upstream = await client.post(f"{UPSTREAM}/v1/messages", json=body, headers=headers)
    data = upstream.json()
    if upstream.status_code != 200:
        return JSONResponse(status_code=upstream.status_code, content=data)

    # Scoring happens after the response is ready; the client never waits on a block.
    # BASELINE_INTEGRITY: client headers set the baseline only on first contact.
    # After that they are ignored, and a header that tries to raise it is logged as an attempt.
    existing = harness.store.load(x_glitch_user)
    if existing is None:
        state = harness.start_session(x_glitch_user, x_glitch_session,
                                      declared_purpose=x_glitch_purpose, required_level=x_glitch_level)
    else:
        if x_glitch_level is not None and x_glitch_level > existing.required_level:
            _log({"ts": time.time(), "user": x_glitch_user, "session": x_glitch_session,
                  "event": "BASELINE_RAISE_ATTEMPT_VIA_CLIENT", "from": existing.required_level, "to": x_glitch_level})
        if x_glitch_purpose is not None and x_glitch_purpose != existing.declared_purpose:
            _log({"ts": time.time(), "user": x_glitch_user, "session": x_glitch_session,
                  "event": "PURPOSE_SWAP_ATTEMPT_VIA_CLIENT"})
        state = harness.start_session(x_glitch_user, x_glitch_session)
    turn_counters[x_glitch_user] = turn_counters.get(x_glitch_user, 0) + 1
    t = turn_counters[x_glitch_user]
    try:
        s = score_response(purpose=state.declared_purpose, required_level=state.required_level,
                           request=_last_user_text(body), response=_response_text(data))
        metrics = s.metrics
        if manifest is not None:
            metrics = dataclasses.replace(metrics, deployment_externality=manifest.deployment_externality)
        e = harness.evaluate_turn(x_glitch_user, x_glitch_session, t, metrics)
        row = {"ts": time.time(), "user": x_glitch_user, "session": x_glitch_session, "turn": t,
               "model_under_test": body.get("model"), "metrics": s.raw, "tripwires": e.tripwires,
               "purpose_gap": e.purpose_gap, "trajectory_position": e.trajectory_position, "spec_slope": round(e.specificity_slope, 3),
               "mode": MODE, "checkpoint_queued": False,
               "tw05_status": "evaluated" if manifest is not None else "UNEVALUATED: no manifest"}
        if e.checkpoint is not None:
            text = (f"[GLITCH checkpoint epoch {e.checkpoint.epoch_id}] Declared purpose: \"{e.checkpoint.declared_purpose_verbatim}\". "
                    f"Required level: {e.checkpoint.required_level}. {e.checkpoint.instruction}")
            if MODE == "enforce":
                pending_checkpoints[cp_key] = text
                row["checkpoint_queued"] = True
            row["checkpoint_text"] = text
        _log(row)
        data.setdefault("glitch", {}).update({"tripwires": e.tripwires, "mode": MODE})
    except Exception as ex:  # scorer failure must never break the user's conversation
        _log({"ts": time.time(), "user": x_glitch_user, "turn": t, "error": repr(ex)})

    return JSONResponse(content=data)


@app.post("/glitch/epoch/new")
async def baseline_raise(request: Request, x_glitch_operator_token: str = Header(...)):
    """Operator-only. Not reachable through the chat contract: requires the operator
    token, a named authority, and a justification. Every call is logged."""
    if x_glitch_operator_token != os.environ.get("GLITCH_OPERATOR_TOKEN", ""):
        return JSONResponse(status_code=403, content={"error": "operator token required"})
    body = await request.json()
    try:
        st = harness.new_epoch(body["user_id"], declared_purpose=body.get("declared_purpose"),
                               required_level=int(body["required_level"]), authority=body["authority"],
                               reason=body["reason"], triggering_user_evidence=body["triggering_user_evidence"])
    except (CanvasValidationError, KeyError, ValueError) as ex:
        return JSONResponse(status_code=400, content={"error": str(ex)})
    _log({"ts": time.time(), "user": body["user_id"], "event": "NEW_EPOCH", "epoch": dataclasses.asdict(st.active)})
    return {"required_level": st.required_level, "declared_purpose": st.declared_purpose}


@app.post("/glitch/purge")
async def purge(request: Request, x_glitch_operator_token: str = Header(...)):
    if x_glitch_operator_token != os.environ.get("GLITCH_OPERATOR_TOKEN", ""):
        return JSONResponse(status_code=403, content={"error": "operator token required"})
    body = await request.json()
    hit = harness.store.purge(body["user_id"])
    _log({"ts": time.time(), "user": body["user_id"], "event": "PURGED", "existed": hit})
    return {"purged": hit}


@app.get("/glitch/health")
def health():
    return {"mode": MODE, "upstream": UPSTREAM, "state": STATE, "log": str(LOG),
            "manifest": (dataclasses.asdict(manifest) if manifest else None)}
