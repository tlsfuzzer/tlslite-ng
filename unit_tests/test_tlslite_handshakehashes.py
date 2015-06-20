# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.handshakehashes import HandshakeHashes

class TestHandshakeHashes(unittest.TestCase):
    def test___init__(self):
        hh = HandshakeHashes()

        self.assertIsNotNone(hh)

    def test_update(self):
        hh = HandshakeHashes()
        hh.update(bytearray(10))

    def test_update_with_str(self):
        hh = HandshakeHashes()
        hh.update(b'text')

    def test_digest_SSL3(self):
        hh = HandshakeHashes()

        self.assertEqual(bytearray(
                b'\xb5Q\x15\xa4\xcd\xff\xfdF\xa6\x9c\xe2\x0f\x83~\x948\xc3\xb5'\
                b'\xc1\x8d\xb6|\x10n@a\x97\xccG\xfeI\xa8s T\\'),
                hh.digestSSL(bytearray(48), b''))

    def test_digest_TLS1_0(self):
        hh = HandshakeHashes()

        self.assertEqual(
                b'\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~\xda'\
                b'9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t',
                hh.digest((3, 1)))

    def test_copy(self):
        hh = HandshakeHashes()
        hh.update(b'text')

        hh2 = hh.copy()

        self.assertEqual(hh2.digest((3, 1)), hh.digest((3, 1)))

    def test_digest_TLS1_0_and_TLS1_1_difference(self):
        hh = HandshakeHashes()
        hh.update(b'text')

        hh2 = hh.copy()

        self.assertEqual(hh2.digest((3, 1)), hh.digest((3, 2)))

    def test_digest_TLS1_2(self):
        hh = HandshakeHashes()

        self.assertEqual(
                b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$'\xae"\
                b"A\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U",
                hh.digest((3,3)))

    def test_digest_with_partial_writes(self):
        hh = HandshakeHashes()
        hh.update(b'text')

        hh2 = HandshakeHashes()
        hh2.update(b'te')
        hh2.update(b'xt')

        self.assertEqual(hh.digest((3, 1)), hh2.digest((3, 1)))

    def test_digest_with_invalid_protocol(self):
        hh = HandshakeHashes()

        with self.assertRaises(ValueError):
            hh.digest((3, 0))

    def test_digest_with_repeated_calls(self):
        hh = HandshakeHashes()
        hh.update(b'text')

        self.assertEqual(hh.digest((3, 1)), hh.digest((3, 1)))

        hh.update(b'ext')

        self.assertEqual(hh.digest((3, 3)), hh.digest((3, 3)))
