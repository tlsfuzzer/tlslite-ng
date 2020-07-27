
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
        # TODO: probably change the size for faster testing
        cls.key = Python_DSAKey(p=69602034731989554929546346371414762967051205729581487767213360812510562307621,
                                q=907978205720450240238233398695599264980368073799,
                                g=44344860785224683582210580276798141855549498608976964582640232671615126065387,
                                x=54605271259585079176392566431938393409383029096,
                                y=16798405106129606882295006910154614336997455047535738179977898112652777747305)

    def test_parse_from_pem(self):
        key = (
            "-----BEGIN DSA PRIVATE KEY-----\n"
            "MIGXAgEAAiEAmeFbCUhVUZgVpljXObhmRaQYIQ12YSr9zlCja2kpTiUCFQCfCyag\n"
            "vEDkgK5nHqscaYlF32ekRwIgYgpNP8JjVxfJ4P3IErO07qqzWS21hSyMhsaCN0an\n"
            "0OsCICUjj3Np+JO42v8Mc8oH6T8yNd5X0ssy8XdK3Bo9nfNpAhQJkJXFuhZDER1X\n"
            "wOwvNiFYUPPZaA==\n"
            "-----END DSA PRIVATE KEY-----")


        parsed_key = Python_Key.parsePEM(key)
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
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg)


    def test_verify(self):
        msg = b"some message to sign"
        sig = self.key.hashAndSign(msg)
        self.assertTrue(sig)

    def test_sign_and_verify_with_md5(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="md5")

        self.key.hashAndVerify(sig, msg, hAlg="md5")

    def test_sign_and_verify_with_sha1(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="sha1")

        self.key.hashAndVerify(sig, msg)

    def test_sign_and_verify_with_sha224(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="sha224")

        self.key.hashAndVerify(sig, msg, hAlg="sha224")

    def test_sign_and_verify_with_sha256(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="sha256")

        self.key.hashAndVerify(sig, msg, hAlg="sha256")

    def test_sign_and_verify_with_sha384(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="sha384")

        self.key.hashAndVerify(sig, msg, hAlg="sha384")

    def test_sign_and_verify_with_sha512(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg, hAlg="sha512")

        self.key.hashAndVerify(sig, msg, hAlg="sha512")
