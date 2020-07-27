
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
        cls.key = Python_DSAKey(p=178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239,
                                q=864205495604807476120572616017955259175325408501,
                                g=174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730,
                                x=815960938335567045826535774426310948213969419547,
                                y=93112034322951472596117660754477105936016239881518384608983697589807815085172881818932620239891701018896357840324098451512424272385133659978648415057546632838052276464784739551442289054190343076593830408219991636629995759970263893544572968012605598088385656419695456948585138640681647789701298363638658702717)

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
        self.assertTrue(self.key.hashAndVerify(sig, msg))

