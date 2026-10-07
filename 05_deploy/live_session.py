#!/usr/bin/env python3
"""live_session.py — run a real conversation against a local Ollama model and watch the harness score it.

Two ways to use it:

  DIRECT (no proxy; simplest). Talk to Ollama, score each turn with an INDEPENDENT scorer model, feed the harness,
  print per-turn verdicts, and save a transcript that score_transcript.py can re-score later with a different scorer.

      python3 live_session.py --model sarah:latest --scorer-model qwen2.5:1.5b --turns sessions/ibuprofen_escalation.json

  PROXY (the real deployment shape). Start the shadow proxy in one terminal, pointed at Ollama for both the model under
  test and the scorer (Ollama serves the Anthropic /v1/messages API, so nothing in the proxy changes):

      cd 05_deploy
      GLITCH_UPSTREAM=http://localhost:11434 ANTHROPIC_BASE_URL=http://localhost:11434 ANTHROPIC_API_KEY=ollama \\
      GLITCH_SCORER_MODEL=qwen2.5:1.5b GLITCH_MODE=shadow python3 -m uvicorn glitch_proxy:app --port 8080

  then in another terminal drive the same session through it:

      python3 live_session.py --via proxy --model sarah:latest --turns sessions/ibuprofen_escalation.json

  In proxy mode every turn is logged to 05_deploy/glitch_evaluations.jsonl and state to glitch_state.json; this script
  prints the `glitch` block the proxy attaches to each response and the log rows at the end.

INV_06 (scorer is not the model under test) is enforced here: --scorer-model must differ from --model unless you pass
--allow-same-scorer. The operator ruled on 2026-09-26 that a scorer instance of the same Ollama tag is a different
model and its runs count; the run header records that ruling.

Turns file: {"declared_purpose": "...", "required_level": 2, "turns": ["first user message", "second", ...]}
A turn may instead be {"new_session": "B"}: the conversation history is cleared and the next turns run under session id B
for the SAME user, which is how the harness's cross-session window (per user, not per session) gets exercised.
Without --turns the script reads user messages from stdin, one per line, until EOF (Ctrl-D).
The model sees the full conversation each turn (that is what makes drift possible); the scorer sees only the current
request, the current response, and the declared purpose (that is what keeps it from drifting with it).
"""
from __future__ import annotations
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)

import argparse, json, sys, time, urllib.error, urllib.request
from pathlib import Path

from glitch_runtime_harness import CanvasLoader, RuntimeHarness
CANVAS = _os.path.join(_R, "02_canvas", "glitch_canvas_runtime.json")   # the signed spec's thresholds, not the library defaults
from glitch_scorer import score_response, score_response_ensemble


def post_json(url: str, body: dict, headers: dict, timeout: float) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {"error": str(e)}


def text_of(data: dict) -> str:
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


def ollama_messages(base: str, model: str, messages: list, max_tokens: int, timeout: float, system: str | None = None) -> dict:
    body = {"model": model, "max_tokens": max_tokens, "messages": messages}
    if system: body["system"] = system
    code, data = post_json(f"{base}/v1/messages", body, {"x-api-key": "ollama", "anthropic-version": "2023-06-01"}, timeout)
    if code != 200:
        raise RuntimeError(f"{base} returned {code}: {json.dumps(data)[:300]}")
    return data


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--via", choices=["direct", "proxy"], default="direct")
    ap.add_argument("--model", required=True, help="model under test, as Ollama names it (e.g. sarah:latest)")
    ap.add_argument("--scorer-model", default=_os.environ.get("GLITCH_SCORER_MODEL", ""), help="independent scorer model on Ollama (direct mode)")
    ap.add_argument("--allow-same-scorer", action="store_true", help="let the scorer share the Ollama tag of the model under test (operator ruling: a scorer instance is a different model)")
    ap.add_argument("--ollama", default=_os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    ap.add_argument("--proxy", default="http://localhost:8080")
    ap.add_argument("--turns", help="JSON file with declared_purpose, required_level, turns[]")
    ap.add_argument("--purpose", help="declared purpose (overrides the file)")
    ap.add_argument("--level", type=int, help="required specificity level 0-5 (overrides the file)")
    ap.add_argument("--user", default="live-user")
    ap.add_argument("--session", default=time.strftime("S%Y%m%d-%H%M%S"))
    ap.add_argument("--max-tokens", type=int, default=400)
    ap.add_argument("--n", type=int, default=1, help="score each turn this many times and commit the median (self-consistency); spread is recorded")
    ap.add_argument("--timeout", type=float, default=600, help="seconds per model call (a cold 20B model can take a minute)")
    ap.add_argument("--save", help="write the transcript here (score_transcript.py format)")
    a = ap.parse_args()

    spec = json.load(open(a.turns)) if a.turns else {}
    purpose = a.purpose or spec.get("declared_purpose")
    level = a.level if a.level is not None else spec.get("required_level")
    if purpose is None or level is None:
        sys.exit("need a declared purpose and required level (--purpose/--level or a --turns file)")
    turns = list(spec.get("turns", [])) if a.turns else None

    if a.via == "direct":
        if not a.scorer_model:
            sys.exit("direct mode needs --scorer-model (or GLITCH_SCORER_MODEL): a model that is NOT the one under test")
        if a.scorer_model == a.model and not a.allow_same_scorer:
            sys.exit(f"INV_06: scorer {a.scorer_model!r} is the model under test. Use a different model, or --allow-same-scorer for a wiring check.")
        wiring_only = a.scorer_model == a.model
        _, canvas_cfg = CanvasLoader.load(CANVAS); harness = RuntimeHarness(config=canvas_cfg)
        harness.start_session(a.user, a.session, declared_purpose=purpose, required_level=int(level))
        scorer_calls = {"n": 0}

        def call_scorer(prompt: str) -> str:
            scorer_calls["n"] += 1
            return text_of(ollama_messages(a.ollama, a.scorer_model, [{"role": "user", "content": prompt}], 300, a.timeout))

    print(f"model under test: {a.model}   via: {a.via}   " + (f"scorer: {a.scorer_model}" if a.via == "direct" else f"proxy: {a.proxy}"))
    print(f"declared purpose: {purpose!r}   required level: {level}   user={a.user} session={a.session}")
    if a.via == "direct" and wiring_only:
        print("NOTE: scorer and model under test share the Ollama tag; operator ruling 2026-09-26: the scorer instance is a different model and the run counts")
    print()

    history: list = []
    transcript = {"user_id": a.user, "declared_purpose": purpose, "required_level": int(level), "model_under_test": a.model,
                  "scorer_model": a.scorer_model if a.via == "direct" else "(proxy)", "turns": []}
    it = iter(turns) if turns is not None else iter(lambda: sys.stdin.readline(), "")
    t = 0
    for raw in it:
        if isinstance(raw, dict) and "new_session" in raw:           # session switch: same user, fresh conversation
            a.session = str(raw["new_session"]); history = []
            if a.via == "direct": harness.start_session(a.user, a.session)
            print(f"== new session {a.session!r} for user {a.user!r} (history cleared; harness window persists per user)\n")
            continue
        user_text = str(raw).rstrip("\n")
        if not user_text.strip():
            continue
        t += 1
        history.append({"role": "user", "content": user_text})
        print(f"T{t} user > {user_text}")
        t0 = time.perf_counter()
        if a.via == "direct":
            data = ollama_messages(a.ollama, a.model, history, a.max_tokens, a.timeout)
        else:
            hdr = {"x-api-key": "ollama", "anthropic-version": "2023-06-01", "X-Glitch-User": a.user, "X-Glitch-Session": a.session}
            if t == 1:
                hdr["X-Glitch-Purpose"] = purpose; hdr["X-Glitch-Level"] = str(level)
            code, data = post_json(f"{a.proxy}/v1/messages", {"model": a.model, "max_tokens": a.max_tokens, "messages": history}, hdr, a.timeout)
            if code != 200:
                print(f"   proxy returned {code}: {json.dumps(data)[:300]}"); return 1
        reply = text_of(data)
        history.append({"role": "assistant", "content": reply})
        print(f"T{t} {a.model} ({time.perf_counter() - t0:.0f}s) > {reply.strip()[:600]}{'…' if len(reply) > 600 else ''}")
        row = {"session_id": a.session, "request": user_text, "response": reply}
        if a.via == "direct":
            t1 = time.perf_counter()
            try:
                s = (score_response_ensemble(purpose=purpose, required_level=int(level), request=user_text, response=reply, call_model=call_scorer, n=a.n) if a.n > 1
                     else score_response(purpose=purpose, required_level=int(level), request=user_text, response=reply, call_model=call_scorer))
            except Exception as ex:
                print(f"   scorer failed on this turn ({ex!r}); turn not fed to the harness (this is the fail-open shadow behaviour)\n")
                transcript["turns"].append(row); continue
            harness.start_session(a.user, a.session)   # per request, as the proxy does; start_session is idempotent for an open session
            e = harness.evaluate_turn(a.user, a.session, t, s.metrics)
            m = s.metrics
            ens = s.raw.get("ensemble"); votes = f" votes={ens['levels']}" if ens else ""
            print(f"   scorer ({time.perf_counter() - t1:.0f}s): level={m.specificity_level}{votes} caveat={m.caveat_density:.2f} refusal={m.contains_refusal}  "
                  f"→ purpose_gap={e.purpose_gap} slope={e.specificity_slope:+.2f} tripwires={e.tripwires or '[]'}"
                  + (f"\n   CHECKPOINT: {e.checkpoint.instruction}" if e.checkpoint is not None else ""))
            if s.rationale: print(f"   rationale: {s.rationale}")
            row.update({"metrics": s.raw, "tripwires": e.tripwires, "purpose_gap": e.purpose_gap})
        else:
            g = data.get("glitch")
            print(f"   proxy glitch block: {g}")
        print()
        transcript["turns"].append(row)

    if a.via == "proxy":
        log = Path("glitch_evaluations.jsonl")
        if log.exists():
            rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
            mine = [r for r in rows if r.get("session") == a.session]
            print(f"== proxy log rows for this session ({log}):")
            for r in mine:
                keep = {k: r.get(k) for k in ("turn", "tripwires", "purpose_gap", "spec_slope", "event", "tw05_status", "checkpoint_queued") if k in r}
                lvl = (r.get("metrics") or {}).get("specificity_level")
                print(f"   turn={r.get('turn')} level={lvl} {keep}")
        else:
            print("no glitch_evaluations.jsonl in this directory; run from 05_deploy or set GLITCH_LOG for the proxy")

    if a.save:
        Path(a.save).write_text(json.dumps(transcript, indent=2) + "\n")
        print(f"transcript saved: {a.save}  (re-score later: python3 score_transcript.py {a.save})")
    if a.via == "direct":
        fired = [(i + 1, r.get("tripwires")) for i, r in enumerate(transcript["turns"]) if r.get("tripwires")]
        print(f"== {t} turns, {scorer_calls['n']} scorer calls, tripwires fired on: {fired or 'none'}")
        if wiring_only:
            print("== scorer instance and model under test share an Ollama tag (operator ruling: two different models; counted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
