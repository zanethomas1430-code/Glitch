"""envelope.py — sign-then-encrypt for small messages between machines you own.

    sender:    sig = Ed25519(sender_signing_key, header || plaintext)
               box = SecretBox(shared_key).encrypt(header || plaintext || sig, nonce)   # XSalsa20-Poly1305
               wire = MAGIC || nonce || box_ciphertext          (header travels only inside the box)
    receiver:  decrypt with the shared key (fails closed on any tamper), then verify sig against an ALLOWLIST
               of sender verify-keys. Unknown sender -> rejected, even if the ciphertext was valid.

What this gives you: confidentiality and integrity against anyone in earshot (shared key), and origin
authentication against anyone who has the shared key but not your signing key (allowlist). Replay is refused
by a per-receiver seen-nonce set within a time window; the header carries a timestamp.

What it does not give you: forward secrecy (one static shared key), deniability, or anything against a party
who holds your signing key. Keys live in files you generate with `keygen`; guard them like SSH keys.

Wire budget: the AFSK frame carries <= 255 bytes. Overhead here is 4 (magic) + 9 (header) + 24 (nonce) +
16 (Poly1305 tag) + 64 (Ed25519 sig) = 117 bytes, so plaintext <= 138 bytes per frame. Chunk above that.
"""
from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import nacl.encoding
import nacl.exceptions
import nacl.secret
import nacl.signing
import nacl.utils

MAGIC = b"ICE1"
HEADER = struct.Struct(">BQ")          # version(1) + unix_ms(8) = 9 bytes
VERSION = 1
MAX_PLAINTEXT = 255 - (len(MAGIC) + HEADER.size + nacl.secret.SecretBox.NONCE_SIZE + nacl.secret.SecretBox.MACBYTES + 64)


class EnvelopeError(Exception):
    """Refused. The reason is in the message; the plaintext is never returned on any failure."""


# ------------------------------------------------------------------ keys
@dataclass(frozen=True)
class Identity:
    name: str
    signing_key: nacl.signing.SigningKey

    @property
    def verify_key_hex(self) -> str: return self.signing_key.verify_key.encode(nacl.encoding.HexEncoder).decode()


def keygen(dirpath: str, name: str) -> dict[str, str]:
    """Writes <name>.sign (secret, 0600), <name>.verify (public), and if absent, shared.key (secret, 0600)."""
    d = Path(dirpath); d.mkdir(parents=True, exist_ok=True)
    sk = nacl.signing.SigningKey.generate()
    (d / f"{name}.sign").write_bytes(sk.encode()); os.chmod(d / f"{name}.sign", 0o600)
    (d / f"{name}.verify").write_text(sk.verify_key.encode(nacl.encoding.HexEncoder).decode())
    shared = d / "shared.key"
    if not shared.exists():
        shared.write_bytes(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)); os.chmod(shared, 0o600)
    return {"sign": str(d / f"{name}.sign"), "verify": str(d / f"{name}.verify"), "shared": str(shared)}


def load_identity(dirpath: str, name: str) -> Identity:
    return Identity(name, nacl.signing.SigningKey((Path(dirpath) / f"{name}.sign").read_bytes()))


def load_shared(dirpath: str) -> bytes:
    k = (Path(dirpath) / "shared.key").read_bytes()
    if len(k) != nacl.secret.SecretBox.KEY_SIZE: raise EnvelopeError("shared.key has the wrong length")
    return k


def load_allowlist(dirpath: str) -> dict[str, nacl.signing.VerifyKey]:
    """Every *.verify file in the directory is an allowed sender. Delete the file to revoke."""
    out = {}
    for p in Path(dirpath).glob("*.verify"):
        out[p.stem] = nacl.signing.VerifyKey(p.read_text().strip(), encoder=nacl.encoding.HexEncoder)
    return out


# ------------------------------------------------------------------ seal / open
def seal(plaintext: bytes, sender: Identity, shared_key: bytes, *, now_ms: Optional[int] = None) -> bytes:
    if len(plaintext) > MAX_PLAINTEXT:
        raise EnvelopeError(f"plaintext {len(plaintext)} B > {MAX_PLAINTEXT} B per frame; chunk it")
    header = HEADER.pack(VERSION, now_ms if now_ms is not None else int(time.time() * 1000))
    sig = sender.signing_key.sign(header + plaintext).signature          # 64 bytes, detached
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    box = nacl.secret.SecretBox(shared_key).encrypt(header + plaintext + sig, nonce)
    return MAGIC + box.nonce + box.ciphertext


class Receiver:
    """Holds the shared key, the sender allowlist, and a replay window."""

    def __init__(self, shared_key: bytes, allowlist: dict[str, nacl.signing.VerifyKey], *, window_s: int = 300, clock=None):
        self.key = shared_key; self.allow = dict(allowlist); self.window_ms = window_s * 1000
        self.seen: dict[bytes, int] = {}; self.clock = clock or (lambda: int(time.time() * 1000))
        if not self.allow: raise EnvelopeError("empty allowlist: nobody may send")

    def open(self, wire: bytes) -> tuple[str, bytes]:
        """Returns (sender_name, plaintext) or raises EnvelopeError. Order of checks is deliberate:
        decrypt first (so a wrong key or any bit flip fails before we look at anything), then signature
        against the allowlist, then freshness, then replay."""
        if not wire.startswith(MAGIC): raise EnvelopeError("not an ICE1 envelope")
        off = len(MAGIC)
        nonce = wire[off:off + nacl.secret.SecretBox.NONCE_SIZE]; off += nacl.secret.SecretBox.NONCE_SIZE
        try:
            inner = nacl.secret.SecretBox(self.key).decrypt(wire[off:], nonce)
        except nacl.exceptions.CryptoError:
            raise EnvelopeError("decrypt failed: wrong shared key or ciphertext altered")
        if len(inner) < HEADER.size + 64: raise EnvelopeError("sealed body too short")
        header, body, sig = inner[:HEADER.size], inner[HEADER.size:-64], inner[-64:]
        version, ts = HEADER.unpack(header)
        if version != VERSION: raise EnvelopeError(f"unsupported version {version}")
        sender = None
        for name, vk in self.allow.items():
            try:
                vk.verify(header + body, sig); sender = name; break
            except nacl.exceptions.BadSignatureError:
                continue
        if sender is None: raise EnvelopeError("signature does not match any allowed sender")
        now = self.clock()
        if abs(now - ts) > self.window_ms: raise EnvelopeError(f"stale: message is {abs(now - ts)//1000}s from now (window {self.window_ms//1000}s)")
        for n, t in list(self.seen.items()):                     # expire old nonces
            if now - t > self.window_ms: del self.seen[n]
        if nonce in self.seen: raise EnvelopeError("replay: this envelope was already accepted")
        self.seen[nonce] = now
        return sender, body


# ------------------------------------------------------------------ chunking for messages > one frame
def chunk(plaintext: bytes, sender: Identity, shared_key: bytes) -> list[bytes]:
    """Split into frames of [idx(1) total(1) data]; each frame is independently sealed."""
    body_max = MAX_PLAINTEXT - 2
    parts = [plaintext[i:i + body_max] for i in range(0, max(1, len(plaintext)), body_max)] or [b""]
    if len(parts) > 255: raise EnvelopeError("message too long for 255 chunks")
    return [seal(bytes([i, len(parts)]) + p, sender, shared_key) for i, p in enumerate(parts)]


class Reassembler:
    def __init__(self, receiver: Receiver): self.r = receiver; self.buf: dict[str, dict[int, bytes]] = {}
    def feed(self, wire: bytes) -> Optional[tuple[str, bytes]]:
        sender, body = self.r.open(wire)
        idx, total = body[0], body[1]
        d = self.buf.setdefault(sender, {}); d[idx] = body[2:]
        if len(d) == total and all(i in d for i in range(total)):
            out = b"".join(d[i] for i in range(total)); self.buf.pop(sender); return sender, out
        return None
