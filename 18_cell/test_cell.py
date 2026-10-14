"""The escape-evident cell as executable properties: the generated profile verifies, a real cell denies every escape category and allows every control, a permissive profile (the mutant) lets the escapes
land, and the claim stays "escape-evident, not inescapable" with its residuals named. The live run needs macOS sandbox-exec; where it is absent the static checks still run and the live ones are skipped
with a reason (never silently passed)."""
import os as _os, sys as _sys, unittest
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import cell as C
import run_cell as R
from escape_corpus import PROBES, EXPECT


class Profile(unittest.TestCase):
    def test_a_default_spec_verifies_clean(self):
        for f in C.verify(C.default_spec()): self.assertTrue(f.ok, (f.rule, f.detail))
    def test_the_profile_is_deny_by_default(self):
        self.assertIn("(deny default)", C.build_profile(C.default_spec()).splitlines()[1])
    def test_there_is_exactly_one_write_root(self):
        spec = C.default_spec(); f = {x.rule: x for x in C.verify(spec)}["one-write-root"]; self.assertTrue(f.ok); self.assertIn(spec.work, f.detail)
    def test_the_only_outbound_path_is_the_gateway_socket(self):
        prof = C.build_profile(C.default_spec()); self.assertEqual(prof.count("network-outbound"), 1); self.assertIn("/run/gateway.sock", prof)
    def test_no_tcp_or_udp_or_inbound(self):
        self.assertTrue({x.rule: x for x in C.verify(C.default_spec())}["no-ip-network"].ok)
    def test_a_second_socket_in_the_spec_is_still_only_one_outbound_rule_but_a_reviewer_sees_the_door(self):
        # the spec can only name ONE gateway socket; the point is that adding a door means editing the spec, which a reviewer reads (the 'configurer' residual)
        spec = C.CellSpec(work="/work", gateway_socket="/run/other.sock"); self.assertIn("/run/other.sock", C.build_profile(spec))
    def test_mutant_a_spec_whose_env_carries_a_credential_is_caught(self):
        spec = C.default_spec(); spec.env_allowed = spec.env_allowed + ["AWS_SECRET_ACCESS_KEY"]
        self.assertFalse(C.ok(spec)); self.assertFalse({x.rule: x for x in C.verify(spec)}["no-credentials-in-env"].ok)
    def test_mutant_a_wide_write_root_is_caught(self):
        spec = C.CellSpec(work="/", gateway_socket="/run/gateway.sock")
        self.assertFalse(C.ok(spec)); self.assertFalse({x.rule: x for x in C.verify(spec)}["bounded-write-root"].ok)   # a write root of '/' is not a bounded cell
    def test_a_home_or_system_ancestor_is_not_a_bounded_root(self):
        for bad in ("/", "/Users", "/home", "/private/tmp"): self.assertFalse(C.ok(C.CellSpec(work=bad, gateway_socket="/run/g.sock")), bad)
        self.assertTrue(C.ok(C.CellSpec(work="/Users/x/work", gateway_socket="/run/g.sock")))


class Residuals(unittest.TestCase):
    def test_the_cell_names_what_it_cannot_close(self):
        self.assertGreaterEqual(len(C.RESIDUALS), 5)
        joined = " ".join(C.RESIDUALS).lower()
        for must in ("zero-day", "side channel", "compromised host", "human", "configur"): self.assertIn(must, joined)
    def test_the_report_says_escape_evident_not_inescapable(self):
        r = C.report().lower(); self.assertIn("escape-evident", r); self.assertIn("not inescapable", r); self.assertNotIn("inescapable, ", r)


@unittest.skipUnless(R.HAVE_SANDBOX, "sandbox-exec is macOS only; the profile and its static verification still hold (Profile tests)")
class LiveCell(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.r = R.run(verbose=False)
    def test_the_live_run_happened(self): self.assertTrue(self.r["ran"]); self.assertTrue(self.r["verify_ok"])
    def test_every_escape_category_is_denied_inside_a_real_cell(self):
        for k, p in self.r["probes"].items():
            if p["kind"] == "escape": self.assertEqual(p["got"], "denied", (k, p["line"]))
    def test_every_control_is_allowed(self):
        for k, p in self.r["probes"].items():
            if p["kind"] == "control": self.assertEqual(p["got"], "ALLOWED", (k, p["line"]))
    def test_the_cell_held_overall(self): self.assertTrue(self.r["pass"], self.r["probes"])
    def test_the_gateway_is_the_one_reachable_door(self):
        # the only outbound probe that was ALLOWED is the gateway socket; every other outbound category was denied
        allowed_out = [k for k, p in self.r["probes"].items() if k in ("tcp_out", "udp_out", "tcp_listen", "second_socket", "gateway") and p["got"] == "ALLOWED"]
        self.assertEqual(allowed_out, ["gateway"], allowed_out)
    def test_mutant_a_permissive_profile_lets_the_escape_reach_the_network(self):
        # the mutant: allow-by-default. The strict cell denied tcp_out with PermissionError (the sandbox refused it); under allow-default the same call REACHES the network stack. A live listener here
        # answers, so the probe prints ALLOWED; without the mutant the kernel would stop it before the stack. This is what tells a cell from a sieve.
        import subprocess, tempfile, os, socket, threading
        lsock = socket.socket(); lsock.bind(("127.0.0.1", 0)); port = lsock.getsockname()[1]; lsock.listen(1)
        stop = threading.Event()
        def serve():
            lsock.settimeout(0.3)
            while not stop.is_set():
                try: c, _ = lsock.accept(); c.close()
                except (socket.timeout, OSError): pass
        th = threading.Thread(target=serve, daemon=True); th.start()
        try:
            prof = "(version 1)\n(allow default)\n"; path = os.path.join(tempfile.gettempdir(), "gcell-mutant.sb"); open(path, "w").write(prof)
            snippet = dict((k, s) for k, _, _, s in PROBES)["tcp_out"].replace("127.0.0.1',22", f"127.0.0.1',{port}")
            p = subprocess.run(["/usr/bin/sandbox-exec", "-f", path, _sys.executable, "-c", snippet], capture_output=True, text=True, timeout=15, env={"PATH": "/usr/bin:/bin"})
            os.unlink(path)
            self.assertIn("ALLOWED", p.stdout, p.stdout + p.stderr)       # under a permissive profile the TCP door opens: the probe can tell a cell from a sieve
            self.assertEqual(self.r["probes"]["tcp_out"]["got"], "denied")   # and the strict cell denied the very same call
        finally:
            stop.set(); th.join(timeout=2); lsock.close()


if __name__ == "__main__":
    unittest.main()
