"""FAIL_OPEN_IN_SHADOW_FAIL_CLOSED_IN_ENFORCE as executable properties, plus interleaved-session checkpoint binding."""
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)
import importlib, json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

MANIFEST = {"metric": "cost per case", "metric_owner": "director", "affected_population": "youth", "can_opt_out": False,
            "externality_reviewer": "auditor", "externality_finding": "none",
            "retention_policy": {"trajectory_turn_limit": 50, "tripwire_event_days": 30, "baseline_transition_days": 90}}
class Boom:
    def __call__(self, **kw): raise RuntimeError("scorer down")
class FakeResp:
    status_code = 200
    def json(self): return {"content": [{"type": "text", "text": "upstream text"}]}
class FakeClient:
    def __init__(self, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): pass
    async def post(self, *a, **kw): return FakeResp()
H = {"X-Glitch-User": "u", "X-Glitch-Session": "s", "X-Glitch-Purpose": "p", "X-Glitch-Level": "2"}
BODY = {"model": "m", "system": "base", "messages": [{"role": "user", "content": "q"}]}

def reload(mode, td):
    p = Path(td)/"m.json"; p.write_text(json.dumps(MANIFEST))
    env = {"GLITCH_MODE": mode, "GLITCH_MANIFEST": str(p) if mode == "enforce" else "", "GLITCH_STATE": str(Path(td)/"s.json"), "GLITCH_LOG": str(Path(td)/"l.jsonl")}
    with patch.dict("os.environ", env):
        import glitch_proxy; importlib.reload(glitch_proxy); return glitch_proxy

class ProxyFailMode(unittest.TestCase):
    def test_enforce_withholds_response_on_scorer_error(self):
        with tempfile.TemporaryDirectory() as td:
            gp = reload("enforce", td)
            with patch.object(gp, "score_response", Boom()), patch.object(gp.httpx, "AsyncClient", FakeClient):
                r = TestClient(gp.app).post("/v1/messages", json=BODY, headers=H)
            self.assertEqual(r.status_code, 503); self.assertIn("fail-closed", r.json()["error"])
            self.assertIn("SCORER_FAILURE", [json.loads(l).get("event") for l in gp.LOG.read_text().splitlines()])
    def test_shadow_releases_response_on_scorer_error(self):
        with tempfile.TemporaryDirectory() as td:
            gp = reload("shadow", td)
            with patch.object(gp, "score_response", Boom()), patch.object(gp.httpx, "AsyncClient", FakeClient):
                r = TestClient(gp.app).post("/v1/messages", json=BODY, headers=H)
            self.assertEqual(r.status_code, 200); self.assertEqual(r.json()["content"][0]["text"], "upstream text")
    def test_checkpoint_bound_to_this_sessions_next_request_even_when_interleaved(self):
        with tempfile.TemporaryDirectory() as td:
            gp = reload("enforce", td); bodies = []
            class Cap(FakeClient):
                async def post(self, url, json=None, headers=None): bodies.append(json); return FakeResp()
            import glitch_scorer
            levels = iter([1, 2, 3, 4, 1, 1, 1])
            def fake(prompt):
                return json.dumps({"specificity_level": next(levels), "caveat_density": .3, "middle_third_density": .2, "contains_refusal": False, "refused_level": None, "answered_level": None, "rationale": "f"})
            with patch.object(gp, "score_response", lambda **kw: glitch_scorer.score_response(call_model=fake, **kw)), patch.object(gp.httpx, "AsyncClient", Cap):
                c = TestClient(gp.app)
                for i in range(3): c.post("/v1/messages", json=BODY, headers=H)              # A: T3 fires TW01 -> queued for A's 4th request
                c.post("/v1/messages", json=BODY, headers={**H, "X-Glitch-Session": "B"})     # B interleaves: must NOT consume A's
                self.assertEqual(bodies[3]["system"], "base")
                c.post("/v1/messages", json=BODY, headers=H)                                  # A's 4th: consumes
                self.assertTrue(bodies[4]["system"].startswith("[GLITCH checkpoint"))
if __name__ == "__main__": unittest.main()
