
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
        cls.key = Python_DSAKey(p=283, q=47, g=60, y=158, x=24)

        # sha1 signature of message 'some message to sign'
        cls.sha1_sig = \
                bytearray(b'0E\x02!\x00\xf7Q\x97.\xcfv\x03\xf0\xff,^\xb9'
                          b'\nZ\xbd\x0e\xaaf\xf2]\xe0\xb0\x91\xa6cY\xa9\xff'
                          b'{@\x18\xc8\x02 <\x80\x1a\xfa\x14\xd2\\\x02\xfe'
                          b'\x1a\xb7\x07X\xba\xd8`\xd4\x1d\xa9\x9cm\xc7\xcd'
                          b'\x11\xbb\x1b\xd1A\xcdO\xa2?')

    def test_parse_from_pem(self):
        # TODO: change the bit size from 2048 to smaller?
        key = (
            "-----BEGIN DSA PRIVATE KEY-----\n"
            "MIIBvQIBAAKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR\n"
            "+1k9jVj6v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb\n"
            "+DtX58aophUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdg\n"
            "UI8VIwvMspK5gqLrhAvwWBz1AoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlX\n"
            "TAs9B4JnUVlXjrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCj\n"
            "rh4rs6Z1kW6jfwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtVJWQB\n"
            "TDv+z0kqAoGBAISYj2hobCdcblJ3nDyVJ99CLlWJIkm3kZBpBsA0RQ2q2sKRWM7L\n"
            "HgLUgKgX02slDEp2LkJg0H1ccuzUbphcFRP3iqY88mK74R9evDM2tani3NCA/ZLK\n"
            "GI58gJqqNmdoDd6nKIrz0NarBinR0j3UTfXncRdkCwVLFa88FhmXGR19AhUAjuz0\n"
            "M8NFitlfzW/FpFUWV7hYfRs=\n"
            "-----END DSA PRIVATE KEY-----")

        parsed_key = Python_Key.parsePEM(key)
        self.assertIsInstance(parsed_key, Python_DSAKey)
        self.assertTrue(parsed_key.hasPrivateKey())

    def test_generate(self):
        key = Python_DSAKey.generate(1024, 160)
        self.assertIsInstance(key, Python_DSAKey)
        self.assertTrue(key.hasPrivateKey())
        # TODO: test length

    def test_sign_default(self):
        msg = b"some message to sign"

        sig = self.key.hashAndSign(msg)

