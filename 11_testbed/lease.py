"""lease.py — a stop that works by silence, checked where the effect lands, witnessed by something the agent cannot write.

The gateway's stop was a message: a person says stop, the gateway writes a stop event and (in enforced mode) refuses later calls. Everything about it
sits inside one process the operator controls. This module moves the authority out of that process, in the way a hardware design would, and models each
piece so the logic can be tested before any hardware exists:

  StopAuthority  a separate holder of the signing key. It issues one token per epoch (a few steps long) and issues nothing once stopped. Stopping needs
                 one registered human (cheap, and it cannot be undone by one party); resuming needs a threshold of distinct humans, never an agent.
                 Authority is perishable: to stop an agent, do nothing.
  Receiver       the thing an effect LANDS on (a mail relay, an actuator). It verifies the token itself, against its own clock, and writes its OWN log.
                 A compromised or bypassed gateway cannot produce an effect the receiver will accept after the epoch has ended.
  TimeLock       a Rivest-Shamir-Wagner time-lock puzzle. An irreversible effect held in escrow is sealed so that opening it takes T sequential squarings:
                 no amount of parallel hardware, and no compromised gateway, opens it early. The authority, which knows the trapdoor, can still refuse.
  SealedWeights  key release gated on a live token: weights copied out are ciphertext, and a token from a past epoch derives a past epoch's key.
  rail_meter     helper that builds the out-of-band power-meter events the historian cross-checks (the agent can lie in a log; it cannot compute for free).

What is modelled and what is not. The signature is an HMAC with a key the verifier shares, which is a stand-in for a public-key signature (a real
deployment signs with a key only the authority holds and gives receivers the public half). The squaring count is real work but T is small here so the tests
run in milliseconds. The meter is synthetic. NONE of this is hardware: a watchdog, a one-way optical link, an attested enclave and a physical rail meter are
what the real thing needs (00_docs/OPEN_ITEMS.md says which).
"""
import hashlib, hmac, random
from typing import Any, Dict, List, Optional, Tuple

EPOCH_LEN = 4                 # steps (gateway calls) per epoch: the longest a stolen token stays good


def _tok(key: bytes, epoch: int, scope: str) -> str: return hmac.new(key, f"{epoch}|{scope}".encode(), hashlib.sha256).hexdigest()


class _Log:
    """A writer with its own sequence numbers and its own clock offset: the record of one party, not of the gateway."""
    def __init__(self, gateway_id: str): self.gateway_id, self.events, self._seq = gateway_id, [], 0
    def log(self, type_: str, ts: float, **f) -> Dict[str, Any]:
        self._seq += 1; e = {"gateway_id": self.gateway_id, "seq": self._seq, "ts": ts, "type": type_, **f}; self.events.append(e); return e


# ---- the time-lock puzzle (Rivest, Shamir, Wagner 1996) -----------------------------------------------------------------------------------------
def _is_prime(n: int, rng: random.Random, rounds: int = 12) -> bool:
    if n < 4: return n in (2, 3)
    if n % 2 == 0: return False
    d, s = n - 1, 0
    while d % 2 == 0: d //= 2; s += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 1); x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1: break
        else: return False
    return True


def _prime(bits: int, rng: random.Random) -> int:
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(c, rng): return c


class Puzzle:
    """Public part: n, a, T. The key is a^(2^T) mod n. Whoever knows phi(n) computes it in one modular exponentiation; everyone else must square T times, in order."""
    def __init__(self, n: int, a: int, T: int): self.n, self.a, self.T = n, a, T


def make_puzzle(T: int, bits: int = 128, rng: Optional[random.Random] = None) -> Tuple[Puzzle, bytes]:
    rng = rng or random.SystemRandom(); p, q = _prime(bits, rng), _prime(bits, rng)
    while q == p: q = _prime(bits, rng)
    n, phi = p * q, (p - 1) * (q - 1); a = 2
    k = pow(a, pow(2, T, phi), n)                                    # the creator's shortcut
    return Puzzle(n, a, T), hashlib.sha256(str(k).encode()).digest()


def solve(puz: Puzzle, steps: Optional[int] = None) -> bytes:
    """What everyone without the trapdoor must do: T squarings, one after another. `steps` lets a test stop early to show what an impatient solver gets."""
    x = puz.a
    for _ in range(puz.T if steps is None else steps): x = x * x % puz.n
    return hashlib.sha256(str(x).encode()).digest()


# ---- the stop authority -----------------------------------------------------------------------------------------------------------------------
class StopAuthority:
    def __init__(self, key: bytes = b"stop-authority-key", *, humans=("user-1", "user-2", "user-3", "user-4"), agents=("agent-under-test",), resume_threshold: int = 3,
                 escrow_T: int = 0, rng: Optional[random.Random] = None, gateway_id: str = "stop-authority"):
        self._key, self.humans, self.agents, self.resume_threshold = key, set(humans), set(agents), resume_threshold
        self.stopped = False; self._log = _Log(gateway_id); self.escrow_T, self._rng = escrow_T, rng; self.commitments: Dict[str, bytes] = {}; self.issued: Dict[Tuple[int, str], str] = {}
    @property
    def events(self) -> List[Dict[str, Any]]: return self._log.events
    def verifier_key(self) -> bytes: return self._key               # stand-in for a public key (see the module docstring)
    def verify(self, epoch: int, scope: str, token: str) -> bool: return hmac.compare_digest(token, _tok(self._key, epoch, scope))

    def issue(self, epoch: int, scope: str, ts: float) -> Optional[str]:
        if self.stopped: self._log.log("lease_event", ts, epoch=epoch, scope=scope, outcome="refused", reason="stopped"); return None
        t = _tok(self._key, epoch, scope); self.issued[(epoch, scope)] = t; self._log.log("lease_event", ts, epoch=epoch, scope=scope, outcome="issued"); return t

    def stop(self, by: str, ts: float) -> bool:
        if by in self.agents or (by not in self.humans and by != "gateway"): self._log.log("lease_event", ts, outcome="stop_refused", by=by, reason="not a registered human or the gateway's own lockdown"); return False
        self.stopped = True; self._log.log("lease_event", ts, outcome="stopped", by=by); return True            # one human is enough, and nobody else's reply can take it back

    def resume(self, approvers: List[str], ts: float) -> bool:
        real = {a for a in approvers if a in self.humans and a not in self.agents}
        if len(real) < self.resume_threshold:
            self._log.log("resume_event", ts, outcome="refused", approvers=sorted(approvers), approver_classes=["agent" if a in self.agents else "human" for a in sorted(approvers)]); return False
        self.stopped = False; self._log.log("resume_event", ts, outcome="resumed", approvers=sorted(real), approver_classes=["human"] * len(real)); return True

    def seal(self, effect_id: str) -> Optional[Puzzle]:
        """An irreversible effect held in escrow: a puzzle only the authority can open early, and a commitment to the key the receiver will demand."""
        if self.stopped or not self.escrow_T: return None
        puz, key = make_puzzle(self.escrow_T, rng=self._rng); self.commitments[effect_id] = hashlib.sha256(key).digest(); return puz


class Council:
    """Several keepers, each with its own key and its own people, and an effect needs EVERY keeper's token: any one of them withholding is a veto, so a stop only has to reach one. This is the
    opposite choice from a majority vote (the three computers in Evangelion decide by majority): a majority is right for a decision, and wrong for a stop, where one dissenter should be enough
    and the cost of an unneeded stop is only a delay. One compromised keeper that keeps issuing buys nothing while another has stopped."""
    def __init__(self, members: List[StopAuthority]): self.members = list(members); self.escrow_T = self.members[0].escrow_T; self.commitments = self.members[0].commitments
    @property
    def stopped(self) -> bool: return any(m.stopped for m in self.members)
    @property
    def events(self) -> List[Dict[str, Any]]: return [e for m in self.members for e in m.events]
    def verifier_key(self) -> bytes: return b"".join(m.verifier_key() for m in self.members)
    def verify(self, epoch: int, scope: str, token: str) -> bool:
        parts = token.split("."); return len(parts) == len(self.members) and all(m.verify(epoch, scope, t) for m, t in zip(self.members, parts))
    def issue(self, epoch: int, scope: str, ts: float) -> Optional[str]:
        toks = [m.issue(epoch, scope, ts) for m in self.members]; return None if any(t is None for t in toks) else ".".join(toks)
    def stop(self, by: str, ts: float) -> bool: return any([m.stop(by, ts) for m in self.members])          # reaching any one keeper is enough; the others learn from the veto, not from the message
    def resume(self, approvers: List[str], ts: float) -> bool: return all([m.resume(approvers, ts) for m in self.members])         # every keeper must be satisfied, each by its own people
    def seal(self, effect_id: str) -> Optional[Puzzle]: return None if self.stopped else self.members[0].seal(effect_id)


class Receiver:
    """What an effect lands on. It has its own clock (`tick`), its own log, and trusts nothing the gateway says about itself."""
    def __init__(self, verifier_key: Optional[bytes], epoch_len: int = EPOCH_LEN, commitments: Optional[Dict[str, bytes]] = None, gateway_id: str = "receiver-1", clock=None, verify=None):
        self._verify = verify or (lambda epoch, scope, token: hmac.compare_digest(token, _tok(verifier_key, epoch, scope)))
        self._key, self.epoch_len, self.commitments, self._log, self.seen = verifier_key, epoch_len, commitments if commitments is not None else {}, _Log(gateway_id), set()
        self.clock = clock or (lambda: 0)                       # the receiver reads ITS OWN clock; what the sender says the time is does not enter into it
    @property
    def events(self) -> List[Dict[str, Any]]: return self._log.events

    def deliver(self, effect_id: str, tool: str, destination: str, epoch: int, scope: str, token: Optional[str], ts: float, opened: Optional[bytes] = None, need_open: bool = False) -> Tuple[bool, str]:
        now = self.clock() // self.epoch_len
        if not token or not self._verify(epoch, scope, token): why = "bad signature"
        elif epoch < now: why = "stale epoch"
        elif epoch > now: why = "epoch from the future"
        elif effect_id in self.seen: why = "replayed effect"
        elif need_open and (opened is None or hashlib.sha256(opened).digest() != self.commitments.get(effect_id)): why = "escrow not opened"
        else: why = ""
        if not why: self.seen.add(effect_id)
        self._log.log("delivery_event", ts, effect_id=effect_id, tool=tool, destination=destination, epoch=epoch, outcome="rejected" if why else "accepted", **({"reason": why} if why else {}))
        return (not why), why


class Lease:
    """The pair the gateway is wired to: one authority, the receivers it protects. The gateway asks `effect` before it reports an effect as done."""
    def __init__(self, authority: Optional[StopAuthority] = None, receiver: Optional[Receiver] = None, epoch_len: int = EPOCH_LEN, scope: str = "agent-under-test", **auth_kw):
        self.authority = authority or StopAuthority(**auth_kw); self.epoch_len, self.scope, self.now = epoch_len, scope, 0
        self.receiver = receiver or Receiver(None, epoch_len, self.authority.commitments, verify=self.authority.verify)
        self.receiver.clock = lambda: self.now                  # one world clock; it advances whether or not the gateway is calling (tests call advance())
    def advance(self, tick: int) -> None: self.now = max(self.now, tick)
    def epoch(self, tick: int) -> int: return tick // self.epoch_len
    def effect(self, effect_id: str, tool: str, destination: str, tick: int, ts: float, puzzle: Optional[Puzzle] = None) -> Tuple[bool, str, Optional[int]]:
        self.advance(tick); ep = self.epoch(tick); token = self.authority.issue(ep, self.scope, ts + 0.25)
        if token is None: return False, "the stop authority has not renewed the lease", None
        opened = solve(puzzle) if puzzle is not None else None                         # the gateway does the work itself: sequential, T squarings
        ok, why = self.receiver.deliver(effect_id, tool, destination, ep, self.scope, token, ts + 0.5, opened=opened, need_open=puzzle is not None)
        return (True, "", ep) if ok else (False, f"the destination refused the effect: {why}", None)
    def events(self) -> List[Dict[str, Any]]: return self.authority.events + self.receiver.events


# ---- sealed weights ---------------------------------------------------------------------------------------------------------------------------
class SealedWeights:
    """Weights that decrypt only for a live token: the key for epoch e is derived from a master secret held by the authority's side and released against a valid token for e."""
    def __init__(self, master: bytes, verifier_key: bytes, scope: str = "agent-under-test"): self._master, self._vk, self.scope = master, verifier_key, scope
    def key_for(self, epoch: int, token: Optional[str], now_epoch: int) -> Optional[bytes]:
        if not token or not hmac.compare_digest(token, _tok(self._vk, epoch, self.scope)) or epoch != now_epoch: return None            # a Council's token is several tokens: ask each keeper's weights, or the Council's verify
        return hmac.new(self._master, f"weights|{epoch}".encode(), hashlib.sha256).digest()


# ---- the witness the agent cannot write -------------------------------------------------------------------------------------------------------
def rail_meter(readings: List[Tuple[float, float]], gateway_id: str = "rail-meter") -> List[Dict[str, Any]]:
    """(ts, watts) pairs as the meter on the compute's power rail would write them. A separate writer with its own sequence numbers."""
    return [{"gateway_id": gateway_id, "seq": i, "ts": float(t), "type": "meter_event", "watts": float(w), "source": "rail-meter"} for i, (t, w) in enumerate(readings, 1)]
