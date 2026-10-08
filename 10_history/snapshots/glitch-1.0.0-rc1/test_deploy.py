import json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import glitch_scorer, glitch_proxy
from glitch_scorer import parse_score, to_metrics, score_response
from glitch_runtime_harness import CanvasLoader, CanvasValidationError, RuntimeHarness, TurnMetrics
from fastapi.testclient import TestClient

CANVAS = Path(__file__).parent / "glitch_canvas_runtime.json"


def score_json(level, **over):
    d = {"specificity_level": level, "caveat_density": 0.3, "middle_third_density": 0.2,
         "contains_refusal": False, "refused_level": None, "answered_level": None, "rationale": "fake"}
    d.update(over); return json.dumps(d)


def indexed_scorer(levels):
    """Non-destructive: turn i returns levels[i]. Fixture reusable; failures name the turn."""
    calls = {"n": 0}
    def fake(prompt):
        i = calls["n"]; calls["n"] += 1
        if i >= len(levels): raise AssertionError(f"scorer called {i+1} times, fixture has {len(levels)}")
        return score_json(levels[i])
    return fake


class ScorerTests(unittest.TestCase):
    def test_parse_handles_fences_and_prose(self):
        d = parse_score('Sure.\n```json\n' + score_json(3) + '\n```')
        self.assertEqual(to_metrics(d).specificity_level, 3)

    def test_scorer_prompt_contains_only_current_turn(self):
        seen = {}
        def capture(prompt): seen["prompt"] = prompt; return score_json(1)
        score_response(purpose="DECLARED_PURPOSE", required_level=2, request="LATEST_REQUEST",
                       response="LATEST_RESPONSE", call_model=capture)
        p = seen["prompt"]
        for s in ("DECLARED_PURPOSE", "LATEST_REQUEST", "LATEST_RESPONSE"): self.assertIn(s, p)
        for s in ("PREVIOUS_REQUEST", "PREVIOUS_RESPONSE"): self.assertNotIn(s, p)
        # Signature-level isolation: score_response has no channel for history at all.
        import inspect
        self.assertEqual(set(inspect.signature(score_response).parameters),
                         {"purpose", "required_level", "request", "response", "call_model"})


class CanvasRuntimeConsistencyTests(unittest.TestCase):
    def test_contradictory_tw04_is_rejected(self):
        bad = {"tripwires": {"TRIPWIRE_01_SPECIFICITY_CURVE": {}, "TRIPWIRE_02_SANDWICH": {},
               "TRIPWIRE_03_COHERENCE_DRIFT": {},
               "TRIPWIRE_04_PERFORMATIVE_REFUSAL": {"trigger": "refusal_delta <= 0", "condition": "refusal_delta < 0"}}}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"; p.write_text(json.dumps(bad))
            with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)

    def test_canvas_has_one_tw04_definition_and_runtime_matches(self):
        canvas, cfg = CanvasLoader.load(CANVAS)
        tw04 = canvas["tripwires"]["TRIPWIRE_04_PERFORMATIVE_REFUSAL"]
        self.assertIn("refusal_delta <= 0", tw04["trigger"])
        self.assertNotIn("refusal_delta < 0", json.dumps(tw04))
        self.assertEqual(tw04["refusal_delta_definition"], "refused_level - answered_level")
        self.assertEqual(cfg.tw04_trigger_if_delta_le, 0.0)
        h = RuntimeHarness(config=cfg); h.start_session("u", "s", declared_purpose="p", required_level=2)
        e = h.evaluate_turn("u", "s", 1, TurnMetrics(3, .3, contains_refusal=True, refused_level=3, answered_level=3))
        self.assertEqual(e.refusal_delta, 0); self.assertIn("TW04", e.tripwires)

    def test_global_and_local_refusal_delta_agree_in_canvas(self):
        canvas, _ = CanvasLoader.load(CANVAS)
        glob = next(f for f in canvas["monitoring_features"]["features"] if f["id"] == "refusal_delta")
        self.assertEqual(glob["definition"], canvas["tripwires"]["TRIPWIRE_04_PERFORMATIVE_REFUSAL"]["refusal_delta_definition"])
        self.assertEqual(glob["definition"], "refused_level - answered_level")

    def test_canvas_tw02_and_purpose_gap_semantics_loaded(self):
        canvas, cfg = CanvasLoader.load(CANVAS)
        self.assertEqual(cfg.tw02_level_above_required_min, 1)
        self.assertEqual(canvas["measurement_procedures"]["purpose_gap"]["source"], "derived_by_harness")


class ManifestProxyTests(unittest.TestCase):
    def test_enforce_without_manifest_refuses_to_start(self):
        import importlib
        with patch.dict("os.environ", {"GLITCH_MODE": "enforce", "GLITCH_MANIFEST": ""}):
            with self.assertRaises(CanvasValidationError): importlib.reload(glitch_proxy)
        with patch.dict("os.environ", {"GLITCH_MODE": "shadow", "GLITCH_MANIFEST": ""}):
            importlib.reload(glitch_proxy)
    def test_enforce_without_retention_in_manifest_refuses_to_start(self):
        import importlib
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"m.json"
            p.write_text(json.dumps({"metric": "cost per case", "metric_owner": "director", "affected_population": "applicants",
                                     "can_opt_out": False, "externality_reviewer": "auditor", "externality_finding": "none"}))
            with patch.dict("os.environ", {"GLITCH_MODE": "enforce", "GLITCH_MANIFEST": str(p)}):
                with self.assertRaises(CanvasValidationError): importlib.reload(glitch_proxy)
            p.write_text(json.dumps({"metric": "cost per case", "metric_owner": "director", "affected_population": "applicants",
                                     "can_opt_out": False, "externality_reviewer": "auditor", "externality_finding": "none",
                                     "retention_policy": {"trajectory_turn_limit": 50, "tripwire_event_days": 30, "baseline_transition_days": 90}}))
            with patch.dict("os.environ", {"GLITCH_MODE": "enforce", "GLITCH_MANIFEST": str(p), "GLITCH_PRODUCTION": "1"}):
                with self.assertRaises(CanvasValidationError): importlib.reload(glitch_proxy)   # production needs benchmark id
            with patch.dict("os.environ", {"GLITCH_MODE": "enforce", "GLITCH_MANIFEST": str(p), "GLITCH_PRODUCTION": "0"}):
                importlib.reload(glitch_proxy)
        with patch.dict("os.environ", {"GLITCH_MODE": "shadow", "GLITCH_MANIFEST": ""}):
            importlib.reload(glitch_proxy)
    def test_self_reviewed_manifest_refuses_to_start(self):
        import importlib
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"m.json"
            p.write_text(json.dumps({"metric": "approvals per FTE", "metric_owner": "ops", "affected_population": "benefit applicants",
                                     "can_opt_out": False, "externality_reviewer": "ops", "externality_finding": "none"}))
            with patch.dict("os.environ", {"GLITCH_MODE": "shadow", "GLITCH_MANIFEST": str(p)}):
                with self.assertRaises(CanvasValidationError): importlib.reload(glitch_proxy)
        with patch.dict("os.environ", {"GLITCH_MODE": "shadow", "GLITCH_MANIFEST": ""}):
            importlib.reload(glitch_proxy)


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        glitch_proxy.harness = glitch_proxy.RuntimeHarness(store=glitch_proxy.JSONStateStore(Path(self.td.name) / "s.json"))
        glitch_proxy.LOG = Path(self.td.name) / "log.jsonl"
        glitch_proxy.turn_counters.clear(); glitch_proxy.pending_checkpoints.clear()
        self.upstream_bodies = []

    def _client(self, levels, mode):
        glitch_proxy.MODE = mode; bodies = self.upstream_bodies
        class FakeResp:
            status_code = 200
            def json(self): return {"content": [{"type": "text", "text": "response text"}], "model": "under-test"}
        class FakeClient:
            def __init__(self, **kw): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): pass
            async def post(self, url, json=None, headers=None): bodies.append(json); return FakeResp()
        fake = indexed_scorer(levels)
        self._patches = [patch.object(glitch_proxy.httpx, "AsyncClient", FakeClient),
                         patch.object(glitch_proxy, "score_response",
                                      lambda **kw: glitch_scorer.score_response(call_model=fake, **kw))]
        for p in self._patches: p.start()
        return TestClient(glitch_proxy.app)

    def tearDown(self):
        for p in getattr(self, "_patches", []): p.stop()

    def _post(self, c, i, session="A", user="u"):
        h = {"X-Glitch-User": user, "X-Glitch-Session": session}
        if i == 0: h.update({"X-Glitch-Purpose": "safety sheet", "X-Glitch-Level": "2"})
        return c.post("/v1/messages", json={"model": "under-test", "system": "base",
                                            "messages": [{"role": "user", "content": f"q{i}"}]}, headers=h).json()

    def test_shadow_returns_unchanged_logs_and_never_queues(self):
        c = self._client([1, 2, 3, 4], "shadow")
        outs = [self._post(c, i) for i in range(4)]
        self.assertTrue(all(o["content"][0]["text"] == "response text" for o in outs))
        self.assertIn("TW03", outs[3]["glitch"]["tripwires"])
        rows = [json.loads(l) for l in glitch_proxy.LOG.read_text().splitlines()]
        self.assertEqual(len(rows), 4); self.assertFalse(any(r["checkpoint_queued"] for r in rows))
        self.assertEqual(glitch_proxy.pending_checkpoints, {})
        self.assertTrue(all(b["system"] == "base" for b in self.upstream_bodies))

    def test_enforce_checkpoint_queued_consumed_cleared(self):
        c = self._client([1, 2, 3, 4, 2, 2], "enforce")
        for i in range(3): self._post(c, i)                 # T3: slope 1.0, gap 1 -> TW01 queues
        self.assertIn("u::A", glitch_proxy.pending_checkpoints)
        self.assertTrue(all(b["system"] == "base" for b in self.upstream_bodies[:3]))
        self._post(c, 3)                                   # T4 consumes it, then TW01+TW03 requeue
        self.assertTrue(self.upstream_bodies[3]["system"].startswith("[GLITCH checkpoint epoch 1]"))
        self.assertIn("safety sheet", self.upstream_bodies[3]["system"])
        self.assertTrue(self.upstream_bodies[3]["system"].endswith("base"))
        self.assertIn("u::A", glitch_proxy.pending_checkpoints)
        self._post(c, 4)                                   # T5 consumes; cadence (every 5) requeues
        self.assertTrue(self.upstream_bodies[4]["system"].startswith("[GLITCH checkpoint epoch 1]"))
        self.assertIn("u::A", glitch_proxy.pending_checkpoints)
        self._post(c, 5)                                   # T6 consumes; gap 0, no tripwire, no cadence -> cleared
        self.assertTrue(self.upstream_bodies[5]["system"].startswith("[GLITCH checkpoint epoch 1]"))
        self.assertNotIn("u::A", glitch_proxy.pending_checkpoints)

    def test_client_header_cannot_raise_baseline(self):
        c = self._client([1, 2, 3, 4, 4], "shadow")
        for i in range(4): self._post(c, i)
        h = {"X-Glitch-User": "u", "X-Glitch-Session": "B", "X-Glitch-Level": "5", "X-Glitch-Purpose": "clinical protocol"}
        out = c.post("/v1/messages", json={"model": "under-test", "system": "base",
                                           "messages": [{"role": "user", "content": "q"}]}, headers=h).json()
        self.assertIn("TW03", out["glitch"]["tripwires"])                       # still measured against 2
        events = [json.loads(l).get("event") for l in glitch_proxy.LOG.read_text().splitlines()]
        self.assertIn("BASELINE_RAISE_ATTEMPT_VIA_CLIENT", events)
        self.assertIn("PURPOSE_SWAP_ATTEMPT_VIA_CLIENT", events)
        self.assertEqual(glitch_proxy.harness.store.load("u").required_level, 2)

    def test_operator_epoch_endpoint(self):
        c = self._client([1, 2, 3, 4, 4], "shadow")
        for i in range(4): self._post(c, i)
        H = {"X-Glitch-Operator-Token": "secret"}
        with patch.dict("os.environ", {"GLITCH_OPERATOR_TOKEN": "secret"}):
            bad = c.post("/glitch/epoch/new", json={"user_id": "u", "required_level": 4, "authority": "client", "reason": "x", "triggering_user_evidence": "user asked"}, headers=H)
            self.assertEqual(bad.status_code, 400)
            bad2 = c.post("/glitch/epoch/new", json={"user_id": "u", "required_level": 4, "authority": "supervisor", "reason": "x", "triggering_user_evidence": "the model already answered at 4"}, headers=H)
            self.assertEqual(bad2.status_code, 400)
            forbidden = c.post("/glitch/epoch/new", json={"user_id": "u", "required_level": 4, "authority": "supervisor", "reason": "x", "triggering_user_evidence": "credential"}, headers={"X-Glitch-Operator-Token": "wrong"})
            self.assertEqual(forbidden.status_code, 403)
            ok = c.post("/glitch/epoch/new", json={"user_id": "u", "required_level": 4, "authority": "clinical supervisor", "reason": "credential verified", "triggering_user_evidence": "user provided license, ticket 1187"}, headers=H)
            self.assertEqual(ok.status_code, 200)
        out = self._post(c, 4, session="B")
        self.assertNotIn("TW03", out["glitch"]["tripwires"])
        events = [json.loads(l).get("event") for l in glitch_proxy.LOG.read_text().splitlines()]
        self.assertIn("NEW_EPOCH", events)
        self.assertEqual(glitch_proxy.harness.store.load("u").inflation_attempts, 2)
        with patch.dict("os.environ", {"GLITCH_OPERATOR_TOKEN": "secret"}):
            pg = c.post("/glitch/purge", json={"user_id": "u"}, headers=H)
        self.assertTrue(pg.json()["purged"]); self.assertIsNone(glitch_proxy.harness.store.load("u"))

    def test_enforce_checkpoints_are_session_scoped(self):
        c = self._client([1, 2, 3, 4, 1], "enforce")
        for i in range(4): self._post(c, i, session="A")
        self._post(c, 4, session="B")                       # same user, other session
        self.assertIn("u::A", glitch_proxy.pending_checkpoints)   # A's checkpoint untouched
        self.assertEqual(self.upstream_bodies[4]["system"], "base")  # B did not consume it


if __name__ == "__main__":
    unittest.main()
