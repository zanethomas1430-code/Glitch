"""Tests for the AFSK modem. No audio hardware required: the channel is simulated, so the DSP is
provable on any machine. Hardware paths are exercised by afsk_cli tx/rx by hand."""
import os, tempfile, unittest
import numpy as np
from afsk import *
from afsk_cli import _band_noise

MSG = b"HELLO WORLD"

class Framing(unittest.TestCase):
    def test_roundtrip(self): self.assertEqual(unframe(frame(MSG)), MSG)
    def test_crc_catches_a_flipped_bit(self):
        f = bytearray(frame(MSG)); f[3] ^= 0x01
        with self.assertRaises(BadFrame): unframe(bytes(f))
    def test_truncation_is_reported(self):
        with self.assertRaises(BadFrame): unframe(frame(MSG)[:-1])
    def test_empty_and_max_payload(self):
        self.assertEqual(unframe(frame(b"")), b"")
        self.assertEqual(unframe(frame(b"x" * 255)), b"x" * 255)
        with self.assertRaises(ValueError): frame(b"x" * 256)

class Modem(unittest.TestCase):
    def test_clean_roundtrip(self):
        self.assertEqual(demodulate(modulate(MSG)), MSG)
    def test_binary_payload(self):
        p = bytes(range(256))[:200]
        self.assertEqual(demodulate(simulate_channel(modulate(p), snr_db=20)), p)
    def test_sync_does_not_assume_alignment(self):
        for lead in (0.0, 0.137, 0.5, 1.3, 3.0):
            self.assertEqual(demodulate(_band_noise(modulate(MSG), 15, 1, lead)), MSG, f"lead {lead}s")
    def test_survives_3db_in_band_noise(self):
        ok = sum(1 for s in range(20) if _quiet(_band_noise(modulate(MSG), 3, s)) == MSG)
        self.assertGreaterEqual(ok, 19, "should be >=95% at 3 dB in-band")
    def test_tolerates_clock_mismatch_to_2000ppm(self):
        for ppm in (0, 500, 2000):
            self.assertEqual(demodulate(simulate_channel(modulate(MSG), snr_db=20, clock_ppm=ppm)), MSG, f"{ppm} ppm")
    def test_no_frames_from_pure_noise(self):
        rng = np.random.default_rng(0)
        for s in range(100):
            self.assertIsNone(_quiet(rng.normal(0, .3, int(1.5 * CFG.sample_rate)).astype(np.float32)))
    def test_never_returns_unverified_bytes(self):
        """The failure mode that matters: garbage must raise, not print as text."""
        for s in range(40):
            out = _quiet(_band_noise(modulate(MSG), -3, s))
            self.assertIn(out, (None, MSG), f"silent corruption at seed {s}: {out!r}")
    def test_config_rejects_unusable_tones(self):
        with self.assertRaises(ValueError): Config(baud=100, freq_mark=1210, freq_space=1200).validate()
        with self.assertRaises(ValueError): Config(freq_mark=21000).validate()

class Wav(unittest.TestCase):
    def test_wav_roundtrip(self):
        from afsk_io import write_wav, read_wav
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "m.wav"); write_wav(p, modulate(MSG))
            self.assertEqual(demodulate(read_wav(p)), MSG)

def _quiet(w):
    try: return demodulate(w)
    except BadFrame: return None

if __name__ == "__main__": unittest.main()
