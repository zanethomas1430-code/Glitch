"""v3.4.3-async-experiment transplanted onto the FROZEN guard (alignment_guard_v343 unchanged).

Three drain topologies, identical transition semantics:
  sync        : v3.4.3 as shipped; request workers call drain_audit() as part of their op mix.
  async_narrow: the experiment as specified: DrainWorker + ack_audit(expected_version, stream_id, seq); the ack CAS still
                requires version == expected_version, so a transition landing during sink I/O voids the ack.
  async_head  : BEYOND the spec: ack precondition is head identity only (stream_id, seq), atomic under the store lock; no
                version precondition. Version still increments, but a delivered head is never re-delivered merely because
                the record moved for an unrelated reason.
"""
from __future__ import annotations
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)
import copy, threading
from typing import Any, Dict
from alignment_guard_v343 import *
from alignment_guard_v343 import _rec_to_raw
from async_audit_experiment import DrainWorker, ConcurrentStateError as ExpConcurrent


class NarrowAckStore:
    def __init__(self, inner, *, head_only: bool = False):
        self.inner, self.head_only = inner, head_only; self._lock = threading.Lock()
    def load(self, u): return self.inner.load(u)
    def compare_and_swap(self, u, v, new): return self.inner.compare_and_swap(u, v, new)   # frozen guard calls this name
    def commit_transition(self, u, v, cand): return self.inner.compare_and_swap(u, v, cand)
    def ack_audit(self, user_id, expected_version, stream_id, seq) -> bool:
        with self._lock:
            rec = self.inner.load(user_id)
            if rec is None or not rec.pending_audit: return False
            if not self.head_only and rec.version != expected_version: return False
            head = rec.pending_audit[0]
            if head["stream_id"] != stream_id or head["seq"] != seq: return False
            new = copy.deepcopy(rec); new.version += 1; new.pending_audit = new.pending_audit[1:]
            return self.inner.compare_and_swap(user_id, rec.version, new)


class WatermarkAckStore(NarrowAckStore):
    """BEYOND the spec (mechanism prototype, not frozen): acknowledgement advances an ack-only watermark and does NOT bump
    the transition version. The store owns the watermark and filters pending_audit on every commit, so a transition built
    from a pre-ack snapshot can never resurrect an acknowledged envelope. Transitions and acks commute."""
    def __init__(self, inner): super().__init__(inner, head_only=True); self.watermark = {}
    def _filter(self, u, rec):
        wm = self.watermark.get(u, 0); rec.pending_audit = [e for e in rec.pending_audit if e["seq"] > wm]; return rec
    def load(self, u):
        rec = self.inner.load(u); return None if rec is None else self._filter(u, rec)
    def compare_and_swap(self, u, v, new):
        with self._lock:
            new = copy.deepcopy(new); self._filter(u, new)       # store-side merge: never re-append acknowledged envelopes
            return self.inner.compare_and_swap(u, v, new)
    commit_transition = compare_and_swap
    def ack_audit(self, user_id, expected_version, stream_id, seq) -> bool:
        with self._lock:
            rec = self.inner.load(user_id)
            if rec is None: return False
            self._filter(user_id, rec)
            if not rec.pending_audit: return False
            head = rec.pending_audit[0]
            if head["stream_id"] != stream_id or head["seq"] != seq: return False
            self.watermark[user_id] = seq                      # monotone; no version bump; no transition invalidated
            return True


def guard_truth_projection(record) -> Dict[str, Any]:
    raw = copy.deepcopy(_rec_to_raw(record)); raw.pop("version"); raw.pop("pending_audit"); return raw


class AsyncDrainService:
    """Dedicated drain workers. Non-authoritative: deliver committed envelopes, ack the exact head, nothing else."""
    def __init__(self, store, sink, anchor, users, *, workers: int = 1, retry_bound: int = 8):
        self.w = DrainWorker(store, sink, anchor, retry_bound=retry_bound); self.users = list(users); self.n = workers
        self.stop = threading.Event(); self.lock = threading.Lock(); self.threads = []
        self.stats = {"invocations": 0, "delivered": 0, "acked": 0, "ack_conflicts": 0, "concurrency_errors": 0, "sink_errors": 0}
    def _loop(self, i):
        while not self.stop.is_set():
            idle = True
            for u in self.users[i::self.n]:
                try:
                    r = self.w.drain_once(u, delivery_bound=8)
                    with self.lock:
                        self.stats["invocations"] += 1; self.stats["delivered"] += r.delivered; self.stats["acked"] += r.acked; self.stats["ack_conflicts"] += r.ack_conflicts
                    if r.delivered: idle = False
                except IOError:
                    with self.lock: self.stats["sink_errors"] += 1
                except ExpConcurrent:
                    with self.lock: self.stats["concurrency_errors"] += 1
            if idle: self.stop.wait(0.0005)
    def start(self):
        self.threads = [threading.Thread(target=self._loop, args=(i,), daemon=True) for i in range(self.n)]; [t.start() for t in self.threads]
    def join(self):
        self.stop.set(); [t.join(timeout=5) for t in self.threads]
