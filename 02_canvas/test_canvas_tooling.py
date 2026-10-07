"""Adversarial tests of the canvas tooling itself (CROSS_SCOPE, FR_004): the validator that checks the canvas is checked."""
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)
import json, tempfile, unittest
from pathlib import Path
import glitch_harness as gh

class CanvasTooling(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(); d = Path(self.td.name)
        self.m = json.loads(Path("glitch_canvas_model.json").read_text()); self.r = json.loads(Path("glitch_canvas_runtime.json").read_text())
        self.mp, self.rp = d/"m.json", d/"r.json"; self.mp.write_text(json.dumps(self.m)); self.rp.write_text(json.dumps(self.r))
        self._orig = (gh.MODEL, gh.RUNTIME); gh.MODEL, gh.RUNTIME = str(self.mp), str(self.rp)
    def tearDown(self): gh.MODEL, gh.RUNTIME = self._orig; self.td.cleanup()
    def test_sign_verify_roundtrip_and_idempotent(self):
        gh.sign(); h1 = (gh.sha(gh.load(gh.MODEL)), gh.sha(gh.load(gh.RUNTIME))); gh.sign(); h2 = (gh.sha(gh.load(gh.MODEL)), gh.sha(gh.load(gh.RUNTIME)))
        self.assertEqual(h1, h2); self.assertTrue(gh.verify(strict=True))
    def test_verify_fails_on_superseded_runtime_under_strict(self):
        self.r["superseded_by"] = "1.0.3"; self.rp.write_text(json.dumps(self.r)); gh.sign()
        self.assertTrue(gh.verify()); self.assertFalse(gh.verify(strict=True))     # non-strict notices; strict fails
    def test_verify_fails_on_version_drift_under_strict(self):
        self.r["changelog"][0]["version"] = "9.9.9"; self.rp.write_text(json.dumps(self.r)); gh.sign()
        self.assertFalse(gh.verify(strict=True))
    def test_verify_fails_on_modified_hash_even_non_strict(self):
        gh.sign(); self.m["intent"] = "tampered"; self.mp.write_text(json.dumps(self.m)); self.assertFalse(gh.verify())
    def test_model_citing_stale_runtime_hash_fails(self):
        gh.sign(); self.r["intent"] = "changed after model signed"; self.rp.write_text(json.dumps(self.r))
        self.assertFalse(gh.verify())                                                   # model->runtime companion mismatch
    def test_score_command_is_wired(self):
        self.assertTrue(callable(gh.score))

class LoaderVersionGuard(unittest.TestCase):
    def test_runtime_canvas_loads_without_version_drift(self):
        from glitch_runtime_harness import CanvasLoader; CanvasLoader.load("glitch_canvas_runtime.json")
    def test_loader_rejects_drift(self):
        from glitch_runtime_harness import CanvasLoader, CanvasValidationError
        r = json.loads(Path("glitch_canvas_runtime.json").read_text()); r["harness"]["version"] = "0.1"
        p = Path(tempfile.mkdtemp())/"d.json"; p.write_text(json.dumps(r))
        with self.assertRaises(CanvasValidationError): CanvasLoader.load(p)

if __name__ == "__main__": unittest.main()
