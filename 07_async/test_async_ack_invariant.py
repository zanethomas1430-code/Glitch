"""ACK_MUTATION_IS_NARROW — additive to the frozen 42. Real UserRecord fixtures, both adapter variants."""
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)
import copy, inspect, unittest
from async_guard import *
from async_guard import WatermarkAckStore
from alignment_guard_v343 import InMemoryRecordStore, UserRecord, GuardState, AuditCursor, _rec_to_raw

def envelope(seq, sid="s"): return {"stream_id": sid, "seq": seq, "ts": 1.0, "prev_sha256": "0"*64, "type": "turn", "sha256": f"h{seq}"}
def make_record(version=7, pending=(5, 6)):
    return UserRecord(version, {"trajectory_position": 5, "epochs": [{"epoch_id": 1}], "turns": []}, GuardState(), AuditCursor("s", 6, "h6"), [envelope(s) for s in pending], {"r1": {"x": 1}}, {"A": 3})

class ACK_MUTATION_IS_NARROW(unittest.TestCase):
    def _store(self, head_only=False, **kw):
        inner = InMemoryRecordStore(); inner.compare_and_swap("u", None, make_record(**kw)); return inner, NarrowAckStore(inner, head_only=head_only)
    def test_success_changes_only_ack_state(self):
        for head_only in (False, True):
            inner, st = self._store(head_only); before = inner.load("u"); truth = guard_truth_projection(before)
            self.assertTrue(st.ack_audit("u", 7, "s", 5)); after = inner.load("u")
            self.assertEqual(after.version, 8); self.assertEqual([e["seq"] for e in after.pending_audit], [6]); self.assertEqual(guard_truth_projection(after), truth)
            self.assertEqual(after.audit, before.audit)     # chain cursor untouched: it is the creation head, not an ack watermark
    def test_rejects_non_head_byte_identically(self):
        for head_only in (False, True):
            inner, st = self._store(head_only); before = _rec_to_raw(inner.load("u"))
            self.assertFalse(st.ack_audit("u", 7, "s", 6)); self.assertEqual(_rec_to_raw(inner.load("u")), before)
    def test_rejects_stale_version_byte_identically_narrow_only(self):
        inner, st = self._store(False); before = _rec_to_raw(inner.load("u"))
        self.assertFalse(st.ack_audit("u", 3, "s", 5)); self.assertEqual(_rec_to_raw(inner.load("u")), before)
        inner, st = self._store(True); self.assertTrue(st.ack_audit("u", 3, "s", 5))   # head-only variant ignores version BY DESIGN; documented divergence from the spec
    def test_no_full_replacement_argument(self):
        self.assertEqual(list(inspect.signature(NarrowAckStore.ack_audit).parameters), ["self", "user_id", "expected_version", "stream_id", "seq"])
    def test_mutant_unsafe_ack_is_killed(self):
        class Unsafe(NarrowAckStore):
            def ack_audit(self, user_id, expected_version, stream_id, seq, candidate=None):   # accepts a replacement record
                if candidate is not None: return self.inner.compare_and_swap(user_id, expected_version, candidate)
                return super().ack_audit(user_id, expected_version, stream_id, seq)
        self.assertNotEqual(list(inspect.signature(Unsafe.ack_audit).parameters), ["self", "user_id", "expected_version", "stream_id", "seq"])   # structural test kills it
        inner = InMemoryRecordStore(); inner.compare_and_swap("u", None, make_record()); st = Unsafe(inner)
        evil = make_record(version=8, pending=()); evil.guard.mode = GuardMode.NORMAL; evil.harness["trajectory_position"] = 999
        st.ack_audit("u", 7, "s", 5, candidate=evil)
        self.assertNotEqual(guard_truth_projection(inner.load("u")), guard_truth_projection(make_record()))   # the mutant DID corrupt truth: this is what the structural test prevents


class WATERMARK_ACK_PROTOTYPE(unittest.TestCase):
    """Not part of the frozen contract. Properties the watermark mechanism must have before it could be proposed."""
    def _st(self):
        inner = InMemoryRecordStore(); inner.compare_and_swap("u", None, make_record()); return inner, WatermarkAckStore(inner)
    def test_ack_does_not_bump_version_and_hides_head(self):
        inner, st = self._st(); self.assertTrue(st.ack_audit("u", 7, "s", 5))
        self.assertEqual(inner.load("u").version, 7); self.assertEqual([e["seq"] for e in st.load("u").pending_audit], [6])
    def test_transition_from_stale_snapshot_cannot_resurrect_acked_envelope(self):
        inner, st = self._st(); stale = st.load("u")                       # snapshot before ack: pending [5,6]
        self.assertTrue(st.ack_audit("u", 7, "s", 5))
        cand = copy.deepcopy(stale); cand.version += 1; cand.pending_audit = stale.pending_audit + [envelope(7)]
        self.assertTrue(st.compare_and_swap("u", 7, cand))                 # transition still wins (ack did not move the version)
        self.assertEqual([e["seq"] for e in st.load("u").pending_audit], [6, 7])   # 5 stays acknowledged
    def test_ack_is_monotone_and_head_only(self):
        inner, st = self._st(); self.assertFalse(st.ack_audit("u", 7, "s", 6)); self.assertTrue(st.ack_audit("u", 7, "s", 5)); self.assertFalse(st.ack_audit("u", 7, "s", 5))
    def test_guard_truth_unchanged_by_ack(self):
        inner, st = self._st(); before = guard_truth_projection(st.load("u")); st.ack_audit("u", 7, "s", 5); self.assertEqual(guard_truth_projection(st.load("u")), before)

if __name__ == "__main__": unittest.main()
