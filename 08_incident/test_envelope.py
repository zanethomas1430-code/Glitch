"""The envelope must fail closed on every tamper class and never return plaintext on failure."""
import os, tempfile, unittest
import nacl.signing
from envelope import *
from afsk import modulate, demodulate
from afsk_cli import _band_noise

class Envelope(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(); d = self.td.name
        keygen(d, "laptop"); keygen(d, "phone"); self.d = d
        self.laptop = load_identity(d, "laptop"); self.phone = load_identity(d, "phone")
        self.key = load_shared(d); self.rx = Receiver(self.key, load_allowlist(d))
    def tearDown(self): self.td.cleanup()
    def test_roundtrip_identifies_sender(self):
        w = seal(b"contain fleet A", self.laptop, self.key)
        self.assertEqual(self.rx.open(w), ("laptop", b"contain fleet A"))
    def test_fits_one_afsk_frame(self):
        w = seal(b"x" * MAX_PLAINTEXT, self.laptop, self.key); self.assertLessEqual(len(w), 255)
        with self.assertRaises(EnvelopeError): seal(b"x" * (MAX_PLAINTEXT + 1), self.laptop, self.key)
    def test_every_bit_flip_is_refused(self):
        w = bytearray(seal(b"hello", self.laptop, self.key))
        for i in range(len(w)):
            t = bytearray(w); t[i] ^= 0x01
            with self.assertRaises(EnvelopeError, msg=f"byte {i} accepted"): self.rx.open(bytes(t))
    def test_wrong_shared_key_refused(self):
        other = Receiver(b"\x00" * 32, load_allowlist(self.d))
        with self.assertRaises(EnvelopeError): other.open(seal(b"hello", self.laptop, self.key))
    def test_unknown_sender_refused_even_with_the_shared_key(self):
        stranger = Identity("stranger", nacl.signing.SigningKey.generate())
        with self.assertRaises(EnvelopeError) as c: self.rx.open(seal(b"hello", stranger, self.key))
        self.assertIn("allowed sender", str(c.exception))
    def test_revocation_by_deleting_verify_file(self):
        os.remove(os.path.join(self.d, "phone.verify")); rx = Receiver(self.key, load_allowlist(self.d))
        with self.assertRaises(EnvelopeError): rx.open(seal(b"hi", self.phone, self.key))
        self.assertEqual(rx.open(seal(b"hi", self.laptop, self.key))[0], "laptop")
    def test_replay_refused(self):
        w = seal(b"hello", self.laptop, self.key); self.rx.open(w)
        with self.assertRaises(EnvelopeError) as c: self.rx.open(w)
        self.assertIn("replay", str(c.exception))
    def test_stale_refused(self):
        old = seal(b"hello", self.laptop, self.key, now_ms=int(time.time() * 1000) - 3_600_000)
        with self.assertRaises(EnvelopeError) as c: self.rx.open(old)
        self.assertIn("stale", str(c.exception))
    def test_empty_allowlist_refuses_construction(self):
        with self.assertRaises(EnvelopeError): Receiver(self.key, {})
    def test_chunking_reassembles_and_is_per_sender(self):
        msg = bytes(range(256)) * 3
        frames = chunk(msg, self.laptop, self.key); self.assertGreater(len(frames), 1)
        ra = Reassembler(self.rx); out = None
        for f in frames: out = ra.feed(f) or out
        self.assertEqual(out, ("laptop", msg))
    def test_over_the_air_end_to_end(self):
        """seal -> AFSK -> noisy channel -> AFSK -> open. The modem carries bytes; the envelope decides trust."""
        w = seal(b"FREEZE INC-2026-07-11", self.laptop, self.key)
        heard = demodulate(_band_noise(modulate(w), 10, 3))
        self.assertEqual(self.rx.open(heard), ("laptop", b"FREEZE INC-2026-07-11"))
    def test_secret_files_are_0600(self):
        st = os.stat(os.path.join(self.d, "laptop.sign")); self.assertEqual(st.st_mode & 0o777, 0o600)
        st = os.stat(os.path.join(self.d, "shared.key")); self.assertEqual(st.st_mode & 0o777, 0o600)

import time
if __name__ == "__main__": unittest.main()
