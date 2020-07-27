
try:
    import unittest2 as unittest
except  ImportError:
    import unittest

try:
    import mock
    from mock import call
except ImportError:
    import unittest.mock as mock
    from unittest.mock import call

from tlslite.utils.python_key import Python_Key
from tlslite.utils.python_dsakey import Python_DSAKey

class TestDSAKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_pem = (
            "-----BEGIN DSA PRIVATE KEY-----\n"
            "MIGXAgEAAiEAmeFbCUhVUZgVpljXObhmRaQYIQ12YSr9zlCja2kpTiUCFQCfCyag\n"
            "vEDkgK5nHqscaYlF32ekRwIgYgpNP8JjVxfJ4P3IErO07qqzWS21hSyMhsaCN0an\n"
            "0OsCICUjj3Np+JO42v8Mc8oH6T8yNd5X0ssy8XdK3Bo9nfNpAhQJkJXFuhZDER1X\n"
            "wOwvNiFYUPPZaA==\n"
            "-----END DSA PRIVATE KEY-----\n")

        cls.key = Python_DSAKey(p=69602034731989554929546346371414762967051205729581487767213360812510562307621,
                                q=907978205720450240238233398695599264980368073799,
                                g=44344860785224683582210580276798141855549498608976964582640232671615126065387,
                                x=54605271259585079176392566431938393409383029096,
                                y=16798405106129606882295006910154614336997455047535738179977898112652777747305)


        # Different key
        key = ( "-----BEGIN DSA PRIVATE KEY-----\n"
                "MIGYAgEAAiEAhOlFCxh6ZzzNUAttFeHWVe7TFplkqYsYXHeX4skwsvkCFQDqFZcN\n"
                "v+YbZamq6pHs5W0j81+qhwIgWTJjpklonHoFu37GS72Sk/6mC3Y+wR44xIuxQr1H\n"
                "ArMCIDOk+NSr13kYK8edl4fEdRhHRN8JOW/G42WB8oTvEQ7tAhUAyxDkbWXWyust\n"
                "bxHP2TPZV9kFzYY=\n"
                "-----END DSA PRIVATE KEY-----\n")

        cls.key_diff = Python_Key.parsePEM(key)

        # dsa sha1 signature of "some message to sign"
        cls.sha1_sig =(b'\x30\x2C\x02\x14\x54\x07\x13\xC9\xE6\xB4\x48\x75\x19\x4D\x88\x61'
                       b'\xBA\x73\x46\x37\xDA\x78\x1C\xB1\x02\x14\x58\x2A\xE1\x17\x20\x46'
                       b'\x5A\xD9\xA8\xC0\x5F\xEA\x1A\x1A\x3D\xE5\x41\x01\x45\xDB')

    def test_parse_from_pem(self):

        parsed_key = Python_Key.parsePEM(self.key_pem)
        self.assertIsInstance(parsed_key, Python_DSAKey)
        self.assertTrue(parsed_key.hasPrivateKey())
        self.assertEqual(parsed_key.private_key, self.key.private_key)
        self.assertEqual(parsed_key.public_key, self.key.public_key)
        self.assertEqual(parsed_key.q, self.key.q)
        self.assertEqual(parsed_key.p, self.key.p)
        self.assertEqual(parsed_key.g, self.key.g)

    def test_generate(self):
        key = Python_DSAKey.generate(1024, 160)
        self.assertIsInstance(key, Python_DSAKey)
        self.assertTrue(key.hasPrivateKey())

    def test_sign_default(self):
        msg = b'some message to sign'

        sig = self.key.hashAndSign(msg)

        self.assertTrue(sig)
    def test_verify(self):
        msg = b'some message to sign'

        self.assertTrue(self.key.hashAndVerify(self.sha1_sig, msg))

    def test_sign_verify_malformed_signature_r(self):
        msg = b'some message to sign'
        # signature with r component equal to q
        sig = (b'\x30\x2d\x02\x15\x00\x9f\x0b\x26\xa0\xbc\x40\xe4\x80\xae\x67\x1e\xab\x1c\x69'
               b'\x89\x45\xdf\x67\xa4\x47\x02\x14\x49\x27\x07\xde\x17\x27\xa5\x78\x05\xaf\x0e'
               b'\x1f\x03\x61\x10\xe4\x99\x2d\xff\x03')

        self.assertFalse(self.key_diff.hashAndVerify(sig, msg))

    def test_sign_verify_malformed_signature_s(self):
        msg = b'some message to sign'
        # signature with s component equal to q
        sig = (b'\x30\x2d\x02\x14\x1a\x6e\x40\x15\x68\xe5\xbd\x02\x65\xc2\x76\xf0\x97\x0a\xab'
               b'\x4a\xb0\xb6\xc8\x43\x02\x15\x00\x9f\x0b\x26\xa0\xbc\x40\xe4\x80\xae\x67\x1e'
               b'\xab\x1c\x69\x89\x45\xdf\x67\xa4\x47')

        self.assertFalse(self.key_diff.hashAndVerify(sig, msg))

    def test_sign_verify_malformed_signature_unrecognized(self):
        msg = b'some message to sign'
        # signature with 3 integer sequence
        sig = (b'\x30\x30\x02\x14\x1a\x6e\x40\x15\x68\xe5\xbd\x02\x65\xc2\x76\xf0\x97\x0a\xab'
               b'\x4a\xb0\xb6\xc8\x43\x02\x15\x00\x9f\x0b\x26\xa0\xbc\x40\xe4\x80\xae\x67\x1e'
               b'\xab\x1c\x69\x89\x45\xdf\x67\xa4\x47\x02\x01\x00')

        self.assertFalse(self.key_diff.hashAndVerify(sig, msg))

    def test_sign_verify_malformed_signature_garbage(self):
        msg = b'some message to sign'
        # signature with garbage byte at the end
        sig = (b'\x30\x2d\x02\x14\x1a\x6e\x40\x15\x68\xe5\xbd\x02\x65\xc2\x76\xf0\x97\x0a\xab'
               b'\x4a\xb0\xb6\xc8\x43\x02\x15\x00\x9f\x0b\x26\xa0\xbc\x40\xe4\x80\xae\x67\x1e'
               b'\xab\x1c\x69\x89\x45\xdf\x67\xa4\x47')

        self.assertFalse(self.key_diff.hashAndVerify(sig, msg))

    def test_verify_diff_key(self):
        msg = b'some message to sign'

        self.assertFalse(self.key_diff.hashAndVerify(self.sha1_sig, msg))

    def test_verify_diff_sign(self):
        msg = b'some message to sign'

        # dsa sha1 signature of "another message to sign"
        sig = (b'\x30\x2D\x02\x15\x00\x88\xE8\xAF\x9C\xDA\x6D\x0B\x4A\xC4\x0E\x52'
               b'\x49\xE2\xA5\x28\x08\x45\x8E\xD6\x1F\x02\x14\x14\x38\xE2\x92\x2B'
               b'\x16\xA7\x4B\xB2\x2D\xEA\xFC\x23\xE3\x1B\x84\xCE\x30\x98\x32')

        self.assertFalse(self.key.hashAndVerify(sig, msg))

    def test_sign_and_verify_with_md5(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="md5")

        self.assertTrue(self.key.hashAndVerify(sig, msg, hAlg="md5"))

    def test_sign_and_verify_with_sha1(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="sha1")

        self.assertTrue(self.key.hashAndVerify(sig, msg))

    def test_sign_and_verify_with_sha224(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="sha224")

        self.assertTrue(self.key.hashAndVerify(sig, msg, hAlg="sha224"))

    def test_sign_and_verify_with_sha256(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="sha256")

        self.assertTrue(self.key.hashAndVerify(sig, msg, hAlg="sha256"))

    def test_sign_and_verify_with_sha384(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="sha384")

        self.assertTrue(self.key.hashAndVerify(sig, msg, hAlg="sha384"))

    def test_sign_and_verify_with_sha512(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="sha512")

        self.assertTrue(self.key.hashAndVerify(sig, msg, hAlg="sha512"))
