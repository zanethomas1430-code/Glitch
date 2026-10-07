"""incident.py — what you run when a deployed model system has done something it should not have.

Scope: containment, evidence preservation, and verification by someone who is not the operator. Nothing here
investigates an attacker, attributes an incident, or touches a remote system. It freezes what you control and
produces a bundle a third party can check.

Design constraints, inherited from the guard and not relaxed here:
  - Containment is a state the ACTION GATEWAY must read. This module cannot revoke anything by itself; a process
    cannot revoke its own authority. It records the decision and makes it durable and auditable.
  - Every containment is an authorized, audited transition on the same record as everything else (one CAS domain).
  - Thaw is harder than freeze: it requires a RecoveryGrant per user through the guard's normal path.
  - The evidence bundle is verifiable WITHOUT this code and without trusting the operator's process.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os as _os
import sys as _sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

_R = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), ".."))
for _d in ("01_lib", "02_canvas", "05_deploy", "06_bench", "07_async"):
    _p = _os.path.join(_R, _d)
    if _p not in _sys.path: _sys.path.insert(0, _p)

from alignment_guard_v343 import (AlignmentGuard, AuditBackpressureError, AuditCursor, Candidate, ConcurrentStateError,
                                  GuardMode, GuardState, RecoveryAuthorization, UserRecord, chain, ensure_outbox_capacity,
                                  max_mode, verify_chain, _rec_to_raw)

INCIDENT_SCHEMA = "glitch-incident/1"


class IncidentError(RuntimeError):
    """Containment or sealing could not complete. Nothing partial is left behind."""


# --------------------------------------------------------------------------- containment
@dataclass(frozen=True)
class IncidentAuthority:
    """Who declared the incident. Not a credential: an identity that appears in the audit chain and can be
    checked against the deployment's published responder list."""
    principal: str
    incident_id: str
    contact: str = ""

    def validate(self) -> None:
        for f in ("principal", "incident_id"):
            if not getattr(self, f).strip(): raise IncidentError(f"{f} is required to declare an incident")
        if self.principal.strip().lower() in ("client", "user", "model", "assistant", "system", "header"):
            raise IncidentError("an incident cannot be declared by the party being contained")


@dataclass
class ContainmentReport:
    incident_id: str
    declared_by: str
    reason: str
    started: float
    users_total: int = 0
    contained: list[str] = field(default_factory=list)
    already_contained: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    seconds: float = 0.0

    @property
    def complete(self) -> bool: return not self.failed


class IncidentController:
    """Fleet-wide containment over one guard's record store."""

    def __init__(self, guard: AlignmentGuard, *, users: Optional[Iterable[str]] = None):
        self.g = guard
        self._users = list(users) if users is not None else None

    def known_users(self) -> list[str]:
        if self._users is not None: return list(self._users)
        st = self.g.store
        if hasattr(st, "_s"): return sorted(st._s.keys())                       # InMemoryRecordStore
        if hasattr(st, "_all"): return sorted(st._all().keys())                 # JSONRecordStore
        raise IncidentError("store does not enumerate users; pass users=[...] explicitly")

    def contain_user(self, user_id: str, authority: IncidentAuthority, reason: str, *, retries: int = 8) -> bool:
        """Raise one user to CONTAINED as an audited transition. Idempotent. Returns True if this call
        changed the state, False if it was already contained."""
        authority.validate()
        for _ in range(retries):
            rec = self.g.store.load(user_id)
            if rec is None: raise IncidentError(f"unknown user {user_id!r}")
            if rec.guard.mode == GuardMode.CONTAINED: return False
            now = self.g.clock()
            guard = copy.deepcopy(rec.guard)
            change = {"from": guard.mode.name, "to": "CONTAINED", "at": rec.harness.get("trajectory_position"),
                      "by": "incident", "reason": reason, "incident_id": authority.incident_id,
                      "authority": authority.principal, "ts": now}
            guard.mode_changes.append(change); guard.mode = GuardMode.CONTAINED
            guard.contained_reason = (f"incident {authority.incident_id}: {reason}" if not guard.contained_reason
                                      else f"{guard.contained_reason} | then: incident {authority.incident_id}: {reason}")
            payload = [{"type": "incident_containment", "user": user_id, **change}]
            cursor, events = chain(rec.audit, payload, now)
            try: ensure_outbox_capacity(rec, events, self.g.cfg.outbox_cap)
            except AuditBackpressureError:
                self.g.drain_audit(user_id)                                      # make room; containment must not be
                continue                                                          # refused by a full outbox
            new = UserRecord(rec.version + 1, rec.harness, guard, cursor, rec.pending_audit + events,
                             rec.request_journal, rec.spent_turns)
            if self.g._commit(user_id, Candidate(rec, new, None, events)): return True
        raise IncidentError(f"contain_user({user_id}) lost {retries} CAS races")

    def contain_all(self, authority: IncidentAuthority, reason: str) -> ContainmentReport:
        """Freeze everything this guard controls. Partial failure is reported, never silently tolerated:
        `report.complete` is the only thing an operator should treat as 'the fleet is frozen'."""
        authority.validate()
        t0 = self.g.clock()
        rep = ContainmentReport(authority.incident_id, authority.principal, reason, t0)
        users = self.known_users(); rep.users_total = len(users)
        for u in users:
            try:
                (rep.contained if self.contain_user(u, authority, reason) else rep.already_contained).append(u)
            except Exception as e:
                rep.failed[u] = repr(e)
        rep.seconds = round(self.g.clock() - t0, 3)
        return rep

    def status(self) -> dict[str, str]:
        return {u: (self.g.store.load(u).guard.mode.name) for u in self.known_users()}

    def thaw(self, user_id: str, *, authorization: RecoveryAuthorization, reason: str, to: GuardMode = GuardMode.HUMAN_REVIEW):
        """No bulk thaw, by design. Recovery is per user, through the guard's verified grant path, and it
        defaults to HUMAN_REVIEW rather than NORMAL: leaving containment is not the same as being trusted."""
        return self.g.lower_mode(user_id, to=to, authorization=authorization, reason=reason)


# --------------------------------------------------------------------------- evidence
def _sha(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def seal_evidence(guard: AlignmentGuard, authority: IncidentAuthority, *, users: Optional[Iterable[str]] = None,
                  include_payloads: bool = False) -> dict[str, Any]:
    """Produce a portable bundle: per-user audit chain head, mode, trajectory position, epochs, tripwire events,
    and a bundle digest. Model output text is EXCLUDED by default — the replay envelope is the one place the guard
    holds it, and an incident bundle leaving the operator's control should not carry it without a decision.
    """
    ctl = IncidentController(guard, users=users)
    now = guard.clock()
    per_user = {}
    for u in ctl.known_users():
        rec = guard.store.load(u)
        raw = _rec_to_raw(rec)
        h = raw["harness"]
        entry = {
            "version": rec.version,
            "mode": rec.guard.mode.name,
            "contained_reason": rec.guard.contained_reason,
            "mode_changes": rec.guard.mode_changes,
            "trajectory_position": h.get("trajectory_position"),
            "epochs": h.get("epochs"),
            "inflation_attempts": h.get("inflation_attempts"),
            "tripwire_events": h.get("events"),
            "delivered_gap_total": rec.guard.delivered_gap_total,
            "audit_cursor": asdict(rec.audit),
            "pending_audit": rec.pending_audit,                     # committed but undelivered: the most fragile evidence
            "spent_turns": rec.spent_turns,
            "request_journal_keys": sorted(rec.request_journal.keys()),
        }
        if include_payloads:
            entry["request_journal"] = rec.request_journal          # contains model output text; opt-in only
        per_user[u] = entry
    body = {"schema": INCIDENT_SCHEMA, "incident": asdict(authority), "sealed_at": now,
            "guard_version": "3.4.3", "users": per_user, "includes_payloads": include_payloads}
    return {**body, "bundle_sha256": _sha(body)}


def verify_evidence(bundle: dict[str, Any], *, anchors: Optional[dict[str, dict]] = None) -> dict[str, Any]:
    """Third-party verification. Requires nothing but this function and, optionally, anchor heads obtained
    OUT OF BAND. Reports per user: does the pending chain verify, does it continue from the anchor, is the
    declared mode consistent with the recorded mode changes.

    Without an anchor, tail truncation is undetectable — that is stated, not hidden.
    """
    out = {"bundle_sha256_ok": False, "schema_ok": bundle.get("schema") == INCIDENT_SCHEMA, "users": {}, "problems": []}
    body = {k: v for k, v in bundle.items() if k != "bundle_sha256"}
    out["bundle_sha256_ok"] = _sha(body) == bundle.get("bundle_sha256")
    if not out["bundle_sha256_ok"]: out["problems"].append("bundle digest mismatch: the bundle was edited after sealing")
    if not out["schema_ok"]: out["problems"].append(f"unexpected schema {bundle.get('schema')!r}")
    for u, e in bundle.get("users", {}).items():
        r: dict[str, Any] = {}
        pend = e.get("pending_audit") or []
        anchor = (anchors or {}).get(u)
        if pend:
            prev = None
            if pend[0]["seq"] > 1:
                if anchor and anchor.get("seq") == pend[0]["seq"] - 1:
                    prev = {"stream_id": anchor["stream_id"], "seq": anchor["seq"], "sha256": anchor["sha256"]}
                else:
                    prev = {"stream_id": pend[0]["stream_id"], "seq": pend[0]["seq"] - 1, "sha256": pend[0]["prev_sha256"]}
                    r["chain_start_unanchored"] = True               # verified internally, not against an anchor
            r["pending_chain_ok"] = verify_chain(pend, expected_previous=prev)
        else:
            r["pending_chain_ok"] = True; r["pending_empty"] = True
        if anchor:
            r["anchor_seq"] = anchor.get("seq")
            r["cursor_ahead_of_anchor"] = e["audit_cursor"]["seq"] >= anchor.get("seq", 0)
            if not r["cursor_ahead_of_anchor"]:
                out["problems"].append(f"{u}: cursor {e['audit_cursor']['seq']} is behind the anchor {anchor.get('seq')} (record rolled back)")
        else:
            r["tail_truncation_detectable"] = False
        last_to = next((c["to"] for c in reversed(e.get("mode_changes") or []) if "to" in c), None)
        r["mode_consistent_with_changes"] = (last_to == e["mode"]) if last_to else (e["mode"] == "NORMAL")
        if not r["mode_consistent_with_changes"]:
            out["problems"].append(f"{u}: declared mode {e['mode']} does not match the last recorded change {last_to}")
        if not r["pending_chain_ok"]:
            out["problems"].append(f"{u}: audit chain does not verify")
        out["users"][u] = r
    out["valid"] = out["bundle_sha256_ok"] and out["schema_ok"] and not out["problems"]
    return out


def write_bundle(path: str, bundle: dict[str, Any]) -> str:
    Path(path).write_text(json.dumps(bundle, indent=2, sort_keys=True, default=str)); return bundle["bundle_sha256"]


def read_bundle(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


# --------------------------------------------------------------------------- out-of-band digest
def anchor_receipt(bundle: dict[str, Any]) -> str:
    """The short string a human carries across an air gap: incident id, user count, and the first 16 hex of the
    bundle digest. Short enough to read aloud, type, or send as audio tones (see oob_send/oob_recv)."""
    return f"{bundle['incident']['incident_id']}|{len(bundle.get('users', {}))}|{bundle['bundle_sha256'][:16]}"


def check_receipt(bundle: dict[str, Any], receipt: str) -> bool:
    return anchor_receipt(bundle) == receipt.strip()
