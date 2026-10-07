"""Stable logical fault-key helpers for causal sync-vs-async comparison."""
from __future__ import annotations
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Tuple


def _uniform01(key: Tuple[Any, ...]) -> float:
    raw = json.dumps(key, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    n = int.from_bytes(hashlib.sha256(raw).digest()[:8], "big")
    return n / float(1 << 64)


@dataclass(frozen=True)
class StableFaultMap:
    seed: int
    cas_loss_rate: float = 0.0
    sink_failure_rate: float = 0.0

    def transition_cas_fails(self, request_id: str, retry_index: int) -> bool:
        return _uniform01((self.seed, request_id, "commit_transition", retry_index)) < self.cas_loss_rate

    def audit_ack_cas_fails(self, stream_id: str, seq: int, retry_index: int) -> bool:
        return _uniform01((self.seed, stream_id, seq, "audit_ack", retry_index)) < self.cas_loss_rate

    def sink_delivery_fails(self, stream_id: str, seq: int, attempt_index: int) -> bool:
        return _uniform01((self.seed, stream_id, seq, "sink_delivery", attempt_index)) < self.sink_failure_rate


def decision_completion_fraction(outcomes: dict, attempted: int) -> float:
    if attempted == 0:
        return 0.0
    succeeded = outcomes.get("succeeded", 0)
    policy_blocked = outcomes.get("completed_blocked_by_policy", 0)
    return (succeeded + policy_blocked) / attempted


def useful_success_fraction(outcomes: dict, attempted: int) -> float:
    if attempted == 0:
        return 0.0
    return outcomes.get("succeeded", 0) / attempted
