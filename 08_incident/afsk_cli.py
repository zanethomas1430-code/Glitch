#!/usr/bin/env python3
"""afsk_cli.py — send and receive text over the air with speakers and a microphone.

  python3 afsk_cli.py tx "HELLO"                 # play it now
  python3 afsk_cli.py rx --timeout 30            # listen until a frame verifies
  python3 afsk_cli.py wav out.wav "HELLO"        # write a file to play anywhere
  python3 afsk_cli.py decode out.wav             # decode a recording
  python3 afsk_cli.py loopback "HELLO"           # no hardware: modulate -> noisy channel -> demodulate
  python3 afsk_cli.py selftest                   # characterization sweep, prints where it breaks
  python3 afsk_cli.py devices                    # what the machine can hear and speak through

Signed + encrypted (ICE1 envelope; keys in ./keys by default, see envelope.py):
  python3 afsk_cli.py keygen laptop              # once per machine; copy shared.key and *.verify between them by hand
  python3 afsk_cli.py stx laptop "FREEZE INC-1"  # seal (sign+encrypt) then transmit
  python3 afsk_cli.py srx --timeout 60           # receive, decrypt, verify sender against ./keys/*.verify
  python3 afsk_cli.py swav laptop out.wav "..."  # sealed message as a WAV file
  python3 afsk_cli.py sdecode in.wav             # decode + open a sealed recording
"""
from __future__ import annotations
import sys, time
import numpy as np
from afsk import CFG, BadFrame, demodulate, modulate, simulate_channel

def _band_noise(sig, snr_db, seed=0, lead_s=0.31):
    rng = np.random.default_rng(seed); n = len(sig)
    F = np.fft.rfft(rng.normal(0, 1, n)); f = np.fft.rfftfreq(n, 1 / CFG.sample_rate)
    F[(f < CFG.freq_space - 300) | (f > CFG.freq_mark + 300)] = 0        # noise only where the tones live
    noise = np.fft.irfft(F, n)
    noise *= np.sqrt(np.mean(sig.astype(float) ** 2) / (10 ** (snr_db / 10)) / np.mean(noise ** 2))
    return np.concatenate([rng.normal(0, 1e-4, int(lead_s * CFG.sample_rate)), sig + noise]).astype(np.float32)

def selftest() -> int:
    msg = b"HELLO WORLD"; sig = modulate(msg); fails = []
    print(f"config: {CFG.baud} baud, {CFG.freq_space}/{CFG.freq_mark} Hz, {CFG.sps} samples/symbol")
    print(f"payload {len(msg)}B -> {len(sig)/CFG.sample_rate:.2f}s of audio\n")
    print("in-band noise (the honest test; white-noise SNR flatters this modem by ~15 dB):")
    for snr in (20, 15, 10, 6, 3, 0, -3):
        ok = sum(1 for s in range(40) if _try(_band_noise(sig, snr, s)) == msg)
        print(f"   {snr:>4} dB: {ok/40:>4.0%}")
        if snr >= 3 and ok < 38: fails.append(f"in-band {snr} dB only {ok/40:.0%}")
    print("\nsample-clock mismatch between the two machines (white noise, 20 dB):")
    for ppm in (0, 500, 2000, 5000, 10000):
        ok = sum(1 for s in range(20) if _try(simulate_channel(sig, snr_db=20, clock_ppm=ppm, seed=s)) == msg)
        print(f"   {ppm:>6} ppm: {ok/20:>4.0%}")
    print("\nsync robustness (random silence before the frame):")
    for lead in (0.0, 0.137, 0.5, 1.3, 3.0):
        ok = sum(1 for s in range(20) if _try(_band_noise(sig, 15, s, lead)) == msg)
        print(f"   {lead:>5.2f}s: {ok/20:>4.0%}")
        if ok < 19: fails.append(f"lead {lead}s only {ok/20:.0%}")
    rng = np.random.default_rng(0)
    fp = sum(1 for s in range(300) if _try(rng.normal(0, 0.3, int(1.5 * CFG.sample_rate)).astype(np.float32)) is not None)
    print(f"\nframes accepted from pure noise: {fp}/300 (must be 0)")
    if fp: fails.append(f"{fp} false frames")
    silent = 0
    for s in range(60):
        out = _try(_band_noise(sig, 3, s))
        if out is not None and out != msg: silent += 1
    print(f"wrong payload accepted without an error: {silent}/60 (must be 0)")
    if silent: fails.append(f"{silent} silent corruptions")
    print("\nSELFTEST " + ("PASS" if not fails else "FAIL: " + "; ".join(fails)))
    return 0 if not fails else 1

def _try(w):
    try: return demodulate(w)
    except BadFrame: return None

def main() -> int:
    if len(sys.argv) < 2: print(__doc__); return 1
    cmd = sys.argv[1]
    if cmd == "selftest": return selftest()
    if cmd == "loopback":
        msg = (sys.argv[2] if len(sys.argv) > 2 else "HELLO").encode()
        w = _band_noise(modulate(msg), 10, 0)
        t0 = time.time()
        try: out = demodulate(w); print(f"decoded {out!r} in {1000*(time.time()-t0):.0f} ms ({len(w)/CFG.sample_rate:.2f}s audio)")
        except BadFrame as e: print(f"BadFrame: {e}"); return 1
        return 0
    if cmd == "wav":
        from afsk_io import write_wav
        path, msg = sys.argv[2], sys.argv[3].encode()
        write_wav(path, modulate(msg)); print(f"wrote {path} ({len(modulate(msg))/CFG.sample_rate:.2f}s). Play it near a listening device."); return 0
    if cmd == "decode":
        from afsk_io import read_wav
        try: print("decoded:", demodulate(read_wav(sys.argv[2]))); return 0
        except BadFrame as e: print(f"BadFrame: {e}"); return 1
    if cmd == "devices":
        from afsk_io import list_devices; print(list_devices()); return 0
    if cmd == "tx":
        from afsk_io import transmit
        msg = sys.argv[2].encode(); print(f"transmitting {msg!r} ..."); transmit(msg); print("done"); return 0
    if cmd == "rx":
        from afsk_io import receive
        t = float(sys.argv[sys.argv.index("--timeout") + 1]) if "--timeout" in sys.argv else 30.0
        print(f"listening up to {t:.0f}s ...")
        try: print("decoded:", receive(timeout=t)); return 0
        except BadFrame as e: print(e); return 1
    KEYS = "./keys"
    if cmd == "keygen":
        from envelope import keygen
        print(keygen(KEYS, sys.argv[2])); print("copy shared.key and every *.verify to the other machine BY HAND (USB, paper, typed). Never over the modem."); return 0
    if cmd in ("stx", "swav"):
        from envelope import load_identity, load_shared, seal
        me = load_identity(KEYS, sys.argv[2]); key = load_shared(KEYS)
        if cmd == "stx":
            from afsk_io import transmit
            w = seal(sys.argv[3].encode(), me, key); print(f"sealed {len(w)} B from {me.name}, transmitting ..."); transmit(w); print("done"); return 0
        from afsk_io import write_wav
        w = seal(sys.argv[4].encode(), me, key); write_wav(sys.argv[3], modulate(w)); print(f"wrote {sys.argv[3]} (sealed, {len(w)} B)"); return 0
    if cmd in ("srx", "sdecode"):
        from envelope import Receiver, load_allowlist, load_shared, EnvelopeError
        rx = Receiver(load_shared(KEYS), load_allowlist(KEYS))
        try:
            if cmd == "srx":
                from afsk_io import receive
                t = float(sys.argv[sys.argv.index("--timeout") + 1]) if "--timeout" in sys.argv else 30.0
                wire = receive(timeout=t)
            else:
                from afsk_io import read_wav
                wire = demodulate(read_wav(sys.argv[2]))
            sender, body = rx.open(wire); print(f"from {sender}: {body.decode(errors='replace')}"); return 0
        except (BadFrame, EnvelopeError) as e:
            print(f"REFUSED: {e}"); return 1
    print(__doc__); return 1

if __name__ == "__main__": sys.exit(main())
