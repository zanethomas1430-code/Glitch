"""afsk.py — audio FSK modem core. Pure numpy; no audio device required.

Fixes the three things that make a naive AFSK script flaky:
  1. SYNC BY CORRELATION, not by sleeping. The preamble is a known chirp-free tone burst followed by a sync symbol;
     the receiver cross-correlates the tone envelope to find the sample offset of the first data symbol.
  2. CONTINUOUS SAMPLES. Demodulation runs over one contiguous array (from a stream ring buffer in afsk_io.py),
     so symbol boundaries never drift from per-call device latency.
  3. FRAMING + INTEGRITY. length byte + CRC-16/CCITT. A corrupted frame is REPORTED, never printed as garbage.

Wire format:
    [ PREAMBLE: alternating MARK/SPACE for PREAMBLE_SYMBOLS symbols ]   (bit clock + energy for detection)
    [ SYNC: one SPACE symbol then one MARK symbol ]                      (unambiguous frame start)
    [ LEN: 1 byte, payload length 0..255 ]
    [ PAYLOAD: LEN bytes ]
    [ CRC16-CCITT over LEN+PAYLOAD, big endian ]
    [ POSTAMBLE: 2 SPACE symbols ]                                       (guard: a late sync lock still has full symbols)
Bits are MSB-first within each byte.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

import numpy as np


@dataclass(frozen=True)
class Config:
    sample_rate: int = 44100
    baud: int = 100                 # 10 was needlessly slow; 100 is reliable in a quiet room
    freq_mark: int = 1800           # binary 1
    freq_space: int = 1200          # binary 0
    preamble_symbols: int = 24      # ~0.24 s at 100 baud: enough energy to detect, enough edges to lock
    amplitude: float = 0.5

    @property
    def sps(self) -> int:           # samples per symbol
        return int(round(self.sample_rate / self.baud))

    def validate(self) -> None:
        # Frequencies must be separated by at least 2 FFT bins at this symbol length, and be integer-ish
        # multiples of the symbol rate for continuous phase to matter less.
        bin_hz = self.sample_rate / self.sps
        if abs(self.freq_mark - self.freq_space) < 2 * bin_hz:
            raise ValueError(f"mark/space separation {abs(self.freq_mark - self.freq_space)} Hz < 2 bins ({2*bin_hz:.0f} Hz) at {self.baud} baud")
        if max(self.freq_mark, self.freq_space) > 0.45 * self.sample_rate:
            raise ValueError("tone above 0.45*sample_rate")


POSTAMBLE_SYMBOLS = 2
CFG = Config()


# ------------------------------------------------------------------ framing
def crc16_ccitt(data: bytes, crc: int = 0xFFFF) -> int:
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def frame(payload: bytes) -> bytes:
    if len(payload) > 255:
        raise ValueError("payload > 255 bytes; split it")
    body = bytes([len(payload)]) + payload
    return body + crc16_ccitt(body).to_bytes(2, "big")


class BadFrame(Exception):
    """Frame did not decode. Reported, never returned as text."""


def unframe(raw: bytes) -> bytes:
    if len(raw) < 3:
        raise BadFrame("short frame")
    n = raw[0]
    body, crc = raw[: 1 + n], raw[1 + n : 3 + n]
    if len(body) != 1 + n or len(crc) != 2:
        raise BadFrame(f"truncated: need {3+n} bytes, have {len(raw)}")
    want = crc16_ccitt(body)
    got = int.from_bytes(crc, "big")
    if want != got:
        raise BadFrame(f"CRC mismatch: computed {want:04x}, received {got:04x}")
    return body[1:]


def bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))          # MSB first


def bits_to_bytes(bits: np.ndarray) -> bytes:
    usable = (len(bits) // 8) * 8
    return np.packbits(bits[:usable].astype(np.uint8)).tobytes()


# ------------------------------------------------------------------ modulate
def _tones(cfg: Config, freqs: Iterable[float]) -> np.ndarray:
    """Continuous-phase FSK: phase carries across symbol boundaries, so there are no clicks and
    the demodulator sees clean single-tone symbols."""
    sps = cfg.sps
    out = np.empty(0, dtype=np.float64)
    phase = 0.0
    for f in freqs:
        t = np.arange(sps) / cfg.sample_rate
        seg = np.sin(2 * np.pi * f * t + phase)
        phase = (phase + 2 * np.pi * f * sps / cfg.sample_rate) % (2 * np.pi)
        out = np.concatenate([out, seg])
    return out


def modulate(payload: bytes, cfg: Config = CFG) -> np.ndarray:
    cfg.validate()
    bits = bytes_to_bits(frame(payload))
    preamble = [cfg.freq_mark if i % 2 == 0 else cfg.freq_space for i in range(cfg.preamble_symbols)]
    sync = [cfg.freq_space, cfg.freq_mark]
    data = [cfg.freq_mark if b else cfg.freq_space for b in bits]
    postamble = [cfg.freq_space] * POSTAMBLE_SYMBOLS
    sig = _tones(cfg, preamble + sync + data + postamble) * cfg.amplitude
    ramp = min(cfg.sps // 4, 128)                                      # short fade so speakers don't pop
    sig[:ramp] *= np.linspace(0, 1, ramp)
    sig[-ramp:] *= np.linspace(1, 0, ramp)
    return sig.astype(np.float32)


# ------------------------------------------------------------------ demodulate
def tone_power(x: np.ndarray, freq: float, sample_rate: int) -> np.ndarray:
    """Power at one frequency for each row of a block array: a single-bin DFT done as two dot products,
    so the whole sweep is BLAS, not a Python loop. (A per-sample Goertzel recurrence is the textbook
    form and is ~100x slower here; the arithmetic is equivalent for our purpose.)"""
    n = x.shape[-1]
    t = np.arange(n)
    w = 2 * np.pi * freq * t / sample_rate
    re = x @ np.cos(w)
    im = x @ np.sin(w)
    return re * re + im * im


def _symbol_decisions(sig: np.ndarray, offset: int, count: int, cfg: Config) -> tuple[np.ndarray, np.ndarray]:
    """Slice `count` symbols starting at `offset`; return (bits, confidence)."""
    sps = cfg.sps
    end = offset + count * sps
    if end > len(sig):
        count = max(0, (len(sig) - offset) // sps)
        end = offset + count * sps
    if count == 0:
        return np.empty(0, dtype=int), np.empty(0)
    blocks = sig[offset:end].reshape(count, sps) * np.hanning(sps)
    pm = tone_power(blocks, cfg.freq_mark, cfg.sample_rate)
    ps = tone_power(blocks, cfg.freq_space, cfg.sample_rate)
    bits = (pm > ps).astype(int)
    conf = np.abs(pm - ps) / (pm + ps + 1e-12)
    return bits, conf


def find_frame_start(sig: np.ndarray, cfg: Config = CFG) -> Optional[int]:
    """Correlation sync. Scores every candidate offset by how well the symbols there match the known
    preamble pattern (alternating mark/space) followed by the sync pair, and returns the sample index
    of the first DATA symbol. No sleeping, no assumed alignment."""
    sps = cfg.sps
    pattern = np.array([1 if i % 2 == 0 else 0 for i in range(cfg.preamble_symbols)] + [0, 1])
    need = (len(pattern) + 2) * sps
    if len(sig) < need:
        return None
    # Compute mark/space power ONCE on a hop grid, then score candidates by indexing into it.
    # Recomputing overlapping windows per candidate is O(candidates x symbols x sps); this is O(hops x sps).
    HOPS_PER_SYMBOL = 8
    hop = max(1, sps // HOPS_PER_SYMBOL)
    n_hops = (len(sig) - sps) // hop + 1
    if n_hops <= 0:
        return None
    starts = np.arange(n_hops) * hop
    blocks = sig[starts[:, None] + np.arange(sps)[None, :]] * np.hanning(sps)
    pm = tone_power(blocks, cfg.freq_mark, cfg.sample_rate)
    ps = tone_power(blocks, cfg.freq_space, cfg.sample_rate)
    bit_at = (pm > ps).astype(int)
    conf_at = np.abs(pm - ps) / (pm + ps + 1e-12)

    def score_hops(cands: np.ndarray) -> np.ndarray:
        idx = cands[:, None] + np.arange(len(pattern))[None, :] * HOPS_PER_SYMBOL
        ok = idx[:, -1] < n_hops
        out = np.zeros(len(cands))
        if not ok.any():
            return out
        i = idx[ok]
        out[ok] = np.mean((bit_at[i] == pattern[None, :]) * conf_at[i], axis=1)
        return out

    cands = np.arange(0, max(1, n_hops - len(pattern) * HOPS_PER_SYMBOL))
    cs = score_hops(cands)
    if len(cs) == 0 or float(np.max(cs)) < 0.5:
        return None
    best_hop = int(cands[int(np.argmax(cs))])
    best_score = float(np.max(cs))

    # Fine search at sample resolution inside the winning hop window (+/- one hop, sub-sampled for speed).
    lo = max(0, (best_hop - 1) * hop)
    hi = min(len(sig) - len(pattern) * sps - 1, (best_hop + 1) * hop)
    fine = np.arange(lo, hi + 1, max(1, (hi - lo) // 64) if hi > lo else 1)
    if len(fine):
        idx = fine[:, None, None] + (np.arange(len(pattern))[None, :, None] * sps + np.arange(sps)[None, None, :])
        b = sig[idx] * np.hanning(sps)
        m, sp = tone_power(b, cfg.freq_mark, cfg.sample_rate), tone_power(b, cfg.freq_space, cfg.sample_rate)
        bits = (m > sp).astype(int); conf = np.abs(m - sp) / (m + sp + 1e-12)
        fs = np.mean((bits == pattern[None, :]) * conf, axis=1)
        best = int(fine[int(np.argmax(fs))]) if float(np.max(fs)) >= best_score else best_hop * hop
    else:
        best = best_hop * hop
    return best + len(pattern) * sps                                   # first data symbol


def demodulate(sig: np.ndarray, cfg: Config = CFG) -> bytes:
    """Full receive: sync, read the length byte, read exactly that many bytes plus CRC, verify.
    Raises BadFrame with a reason. Never returns unverified bytes."""
    cfg.validate()
    start = find_frame_start(sig, cfg)
    if start is None:
        raise BadFrame("no preamble found")
    len_bits, _ = _symbol_decisions(sig, start, 8, cfg)
    if len(len_bits) < 8:
        raise BadFrame("truncated before length byte")
    n = int(bits_to_bytes(len_bits)[0])
    total_bits = 8 * (1 + n + 2)
    bits, _ = _symbol_decisions(sig, start, total_bits, cfg)
    if len(bits) < total_bits:
        raise BadFrame(f"truncated: need {total_bits} bits for a {n}-byte payload, have {len(bits)}")
    return unframe(bits_to_bytes(bits))


# ------------------------------------------------------------------ channel simulation (for tests, not deployment)
def simulate_channel(sig: np.ndarray, *, snr_db: float = 30.0, lead_silence_s: float = 0.31,
                     clock_ppm: float = 0.0, seed: int = 0, cfg: Config = CFG) -> np.ndarray:
    """A deliberately unkind wire: random lead-in silence (so the receiver cannot assume alignment),
    additive noise at a stated SNR, and optional sample-clock mismatch between transmitter and receiver."""
    rng = np.random.default_rng(seed)
    x = sig.astype(np.float64)
    if clock_ppm:
        n_new = int(round(len(x) * (1 + clock_ppm * 1e-6)))
        x = np.interp(np.linspace(0, len(x) - 1, n_new), np.arange(len(x)), x)
    lead = rng.normal(0, 1e-4, int(lead_silence_s * cfg.sample_rate))
    tail = rng.normal(0, 1e-4, int(0.05 * cfg.sample_rate))
    sig_power = float(np.mean(x ** 2))
    noise = rng.normal(0, np.sqrt(sig_power / (10 ** (snr_db / 10))), len(x))
    return np.concatenate([lead, x + noise, tail]).astype(np.float32)
