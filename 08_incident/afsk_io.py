"""afsk_io.py — audio in/out for the AFSK modem. The only file that touches hardware.

The naive receiver calls sd.rec() once per symbol; each call opens and closes the device, so consecutive
chunks are NOT contiguous and the error accumulates across a frame. This module keeps ONE continuous
InputStream feeding a ring buffer, and hands the demodulator a single contiguous array.

Works without sounddevice: WAV read/write covers the "play this file on one machine, record on another"
workflow, which is also how you test with two phones.
"""
from __future__ import annotations

import struct
import threading
import time
import wave
from typing import Optional

import numpy as np

from afsk import CFG, Config, BadFrame, demodulate, modulate


def _sd():
    try:
        import sounddevice as sd
        return sd
    except Exception as e:                                   # PortAudio missing, headless box, etc.
        raise RuntimeError("sounddevice/PortAudio unavailable; use WAV mode (write_wav/read_wav) instead") from e


# ------------------------------------------------------------------ WAV (no hardware needed)
def write_wav(path: str, sig: np.ndarray, cfg: Config = CFG) -> None:
    pcm = np.clip(sig, -1, 1)
    pcm = (pcm * 32767).astype("<i2")
    with wave.open(path, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(cfg.sample_rate)
        w.writeframes(pcm.tobytes())


def read_wav(path: str, cfg: Config = CFG) -> np.ndarray:
    with wave.open(path, "rb") as w:
        if w.getframerate() != cfg.sample_rate:
            raise ValueError(f"{path} is {w.getframerate()} Hz; modem expects {cfg.sample_rate}. Resample or change Config.")
        if w.getsampwidth() != 2:
            raise ValueError("expected 16-bit PCM")
        raw = w.readframes(w.getnframes())
        x = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
        if w.getnchannels() > 1:
            x = x.reshape(-1, w.getnchannels()).mean(axis=1)
        return x


# ------------------------------------------------------------------ transmit
def transmit(payload: bytes, cfg: Config = CFG, *, device=None, blocking: bool = True) -> None:
    sd = _sd()
    sig = modulate(payload, cfg)
    sd.play(sig, cfg.sample_rate, device=device)
    if blocking:
        sd.wait()


# ------------------------------------------------------------------ receive
class Listener:
    """One continuous input stream into a ring buffer. Call .snapshot() for a contiguous array of the
    last `seconds` of audio; the demodulator finds the frame inside it."""

    def __init__(self, seconds: float = 30.0, cfg: Config = CFG, device=None):
        self.cfg = cfg
        self.n = int(seconds * cfg.sample_rate)
        self.buf = np.zeros(self.n, dtype=np.float32)
        self.w = 0
        self.filled = 0
        self.lock = threading.Lock()
        self.stream = None
        self.device = device

    def _cb(self, indata, frames, time_info, status):        # runs on the audio thread; keep it cheap
        x = indata[:, 0] if indata.ndim > 1 else indata
        with self.lock:
            k = len(x)
            if k >= self.n:
                self.buf[:] = x[-self.n:]; self.w = 0; self.filled = self.n; return
            end = self.w + k
            if end <= self.n:
                self.buf[self.w:end] = x
            else:
                first = self.n - self.w
                self.buf[self.w:] = x[:first]; self.buf[:k - first] = x[first:]
            self.w = end % self.n
            self.filled = min(self.n, self.filled + k)

    def __enter__(self):
        sd = _sd()
        self.stream = sd.InputStream(samplerate=self.cfg.sample_rate, channels=1, dtype="float32",
                                     blocksize=self.cfg.sps, callback=self._cb, device=self.device)
        self.stream.start(); return self

    def __exit__(self, *a):
        if self.stream: self.stream.stop(); self.stream.close()

    def snapshot(self) -> np.ndarray:
        with self.lock:
            if self.filled < self.n:
                return self.buf[:self.w].copy()
            return np.concatenate([self.buf[self.w:], self.buf[:self.w]])


def receive(timeout: float = 30.0, cfg: Config = CFG, *, device=None, poll: float = 0.25,
            window_s: float = 30.0) -> bytes:
    """Listen until a frame verifies or the timeout expires. Returns the payload or raises BadFrame.
    A CRC failure is not fatal here: it means what we heard was not a valid frame, so we keep listening."""
    deadline = time.time() + timeout
    last_err = "nothing heard"
    with Listener(window_s, cfg, device) as lis:
        while time.time() < deadline:
            time.sleep(poll)
            snap = lis.snapshot()
            if len(snap) < (cfg.preamble_symbols + 4) * cfg.sps:
                continue
            try:
                return demodulate(snap, cfg)
            except BadFrame as e:
                last_err = str(e)
    raise BadFrame(f"timeout after {timeout}s (last: {last_err})")


def list_devices() -> str:
    try:
        return str(_sd().query_devices())
    except RuntimeError as e:
        return f"(no audio backend: {e})"
