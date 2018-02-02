# Author: Anna Khaitovich (c) 2017
# see LICENCE file for legal information regarding use of this file

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.utils.compat import a2b_base64
from tlslite.utils.asn1parser import ASN1Type, ASN1Parser

class TestASN1Parser(unittest.TestCase):
    def test__init__(self):
        pass

    def test_integer(self):
        p = ASN1Parser(a2b_base64('AgEB'))
        self.assertEqual(bytearray(b'\x01'), p.value)

    def test_bitstring(self):
        p = ASN1Parser(a2b_base64('AwUAQUJDRA=='))
        self.assertEqual(bytearray(b'\x00ABCD'), p.value)

    def test_utctime(self):
        p = ASN1Parser(a2b_base64('FwsxODEyMzEyMzU5Wg=='))
        self.assertEqual(bytearray(b'1812312359Z'), p.value)

    def test_sequence(self):
        p = ASN1Parser(a2b_base64('MAMBAf8='))
        self.assertEqual(bytearray(b'\x01\x01\xff'), p.value)

    def test_explicit_string(self):
        p = ASN1Parser(a2b_base64('v5oFFAwSc29tZSByYW5kb20gc3RyaW5n'))
        self.assertEqual(bytearray(b'\x0c\x12some random string'), p.value)

if __name__ == '__main__':
    unittest.main()
