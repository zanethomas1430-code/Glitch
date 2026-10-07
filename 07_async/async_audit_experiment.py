"""v3.4.3-async-experiment: narrow audit acknowledgement + async drain topology.

This module is intentionally transport-only.  It does not derive guard transitions.
It is designed to be transplanted onto the frozen v3.4.3 runtime without changing
its transition semantics.

Important semantic distinction:
- the audit chain cursor (stream_id/seq/prev hash) advances when an envelope is CREATED;
- acknowledgement removes only the current pending-audit HEAD;
- acknowledgement MUST NOT rewind/advance the chain cursor unless the frozen runtime
  has a distinct acknowledgement watermark field.
"""
from __future__ import annotations
import os as _os, sys as _sys   # path fallback: works without PYTHONPATH; run_all.sh also sets it
_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)

import copy
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Protocol, Tuple


class ConcurrentStateError(RuntimeError):
    pass


class AuditDeliveryError(RuntimeError):
    pass


class OutOfOrderAuditAck(RuntimeError):
    pass


class AsyncRecordStore(Protocol):
    """Experiment store boundary.

    commit_transition is the full safety-state CAS.
    ack_audit is a deliberately narrow CAS that may only remove the current
    pending-audit head (plus explicit ack-only metadata, if such metadata exists).
    """

    def load(self, user_id: str) -> Optional[Any]:
        ...

    def commit_transition(
        self,
        user_id: str,
        expected_version: Optional[int],
        candidate: Any,
    ) -> bool:
        ...

    def ack_audit(
        self,
        user_id: str,
        expected_version: int,
        stream_id: str,
        seq: int,
    ) -> bool:
        ...


@dataclass(frozen=True)
class DrainResult:
    delivered: int = 0       # successful external deliveries (includes re-delivery)
    acked: int = 0           # envelopes durably removed from pending head
    ack_conflicts: int = 0   # narrow-CAS losses


class NarrowAckInMemoryAdapter:
    """Reference implementation for the prototype in-memory store.

    Wrap an existing store that exposes load() and compare_and_swap().  Full guard
    transitions use commit_transition(); audit acknowledgements are constructed
    internally so callers can never supply a replacement UserRecord.

    This is an experiment adapter, not a production cross-process store.
    """

    def __init__(self, inner: Any):
        self.inner = inner

    def load(self, user_id: str) -> Optional[Any]:
        return self.inner.load(user_id)

    def commit_transition(
        self,
        user_id: str,
        expected_version: Optional[int],
        candidate: Any,
    ) -> bool:
        return self.inner.compare_and_swap(user_id, expected_version, candidate)

    def ack_audit(
        self,
        user_id: str,
        expected_version: int,
        stream_id: str,
        seq: int,
    ) -> bool:
        """Atomically remove exactly the current pending head.

        No caller-provided record is accepted.  Therefore this method cannot be
        abused as a second full-state replacement path.
        """
        rec = self.inner.load(user_id)
        if rec is None or rec.version != expected_version:
            return False
        if not rec.pending_audit:
            return False

        head = rec.pending_audit[0]
        if head.get("stream_id") != stream_id or head.get("seq") != seq:
            return False

        new = copy.deepcopy(rec)
        new.version += 1
        new.pending_audit = new.pending_audit[1:]

        # DO NOT modify new.audit here.  In the reference runtime that cursor is
        # the chain-creation head, not an acknowledgement cursor.
        return self.inner.compare_and_swap(user_id, expected_version, new)


class DrainWorker:
    """Non-authoritative transport worker for committed audit envelopes.

    Authority:
      - may deliver an already-committed envelope to sink/anchor;
      - may monotonically acknowledge the pending-audit HEAD via ack_audit().

    No authority:
      - may not derive transitions;
      - may not create/regenerate audit envelopes;
      - may not modify trajectory, guard mode, epochs, capability accounting,
        request results/journal, spent-turn state, or other guard truth.

    retry_bound is an ACK-conflict bound per envelope.  delivery_bound is the
    maximum number of head envelopes considered in one invocation.
    """

    def __init__(
        self,
        store: AsyncRecordStore,
        sink: Callable[[Dict[str, Any]], None],
        anchor: Callable[[Dict[str, Any]], None],
        *,
        retry_bound: int = 8,
    ) -> None:
        if retry_bound < 1:
            raise ValueError("retry_bound must be >= 1")
        self.store = store
        self.sink = sink
        self.anchor = anchor
        self.retry_bound = retry_bound

    def drain_once(self, user_id: str, *, delivery_bound: int = 8) -> DrainResult:
        if delivery_bound < 0:
            raise ValueError("delivery_bound must be >= 0")

        delivered = 0
        acked = 0
        ack_conflicts = 0

        while acked < delivery_bound:
            rec = self.store.load(user_id)
            if rec is None:
                raise KeyError(f"user {user_id!r} not started")
            if not rec.pending_audit:
                break

            event = copy.deepcopy(rec.pending_audit[0])
            identity: Tuple[str, int] = (event["stream_id"], event["seq"])

            # External I/O occurs with no RecordStore lock held by this worker.
            # If sink/anchor raises, the envelope remains pending and no ack occurs.
            self.sink(event)
            self.anchor(
                {
                    "stream_id": event["stream_id"],
                    "seq": event["seq"],
                    "sha256": event["sha256"],
                }
            )
            delivered += 1

            # Delivery succeeded.  Ack the exact head we delivered.  A competing
            # transition or worker may have changed record.version in the meantime.
            won = self.store.ack_audit(
                user_id,
                rec.version,
                identity[0],
                identity[1],
            )
            if won:
                acked += 1
                continue

            # Bounded re-check/retry.  We intentionally DO NOT immediately redeliver
            # unless the same logical envelope is still the head after reload.
            for _ in range(self.retry_bound - 1):
                ack_conflicts += 1
                cur = self.store.load(user_id)
                if cur is None:
                    raise KeyError(f"user {user_id!r} disappeared")
                if not cur.pending_audit:
                    # Another worker already acknowledged it.  Treat this invocation
                    # as externally delivered but not locally acked.
                    return DrainResult(delivered, acked, ack_conflicts)

                head = cur.pending_audit[0]
                head_id = (head.get("stream_id"), head.get("seq"))
                if head_id != identity:
                    # Prefix advanced by another worker.  Never ack a later seq using
                    # stale delivery evidence for the old head.
                    return DrainResult(delivered, acked, ack_conflicts)

                if self.store.ack_audit(
                    user_id,
                    cur.version,
                    identity[0],
                    identity[1],
                ):
                    acked += 1
                    break
            else:
                raise ConcurrentStateError(
                    f"audit ack did not commit after {self.retry_bound} attempts "
                    f"for {identity[0]}:{identity[1]}"
                )

        return DrainResult(delivered, acked, ack_conflicts)


def guard_truth_projection(record: Any) -> Dict[str, Any]:
    """Projection used by ACK_MUTATION_IS_NARROW tests.

    Version and pending_audit are intentionally excluded.  The audit chain cursor
    remains INCLUDED because narrow acknowledgement must not mutate chain identity.
    If the frozen runtime adds explicit ack-only metadata, exclude only those named
    fields here rather than broadly excluding all audit state.
    """
    raw = copy.deepcopy(record.__dict__)
    raw.pop("version", None)
    raw.pop("pending_audit", None)
    return raw
