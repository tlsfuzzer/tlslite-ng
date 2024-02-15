
# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.utils.ecc import getCurveByName,getPointByteSize
import ecdsa

class TestCurveLookup(unittest.TestCase):
    def test_with_correct_name(self):
        curve = getCurveByName('secp256r1')
        self.assertIs(curve, ecdsa.NIST256p)

    def test_with_invalid_name(self):
        with self.assertRaises(ValueError):
            getCurveByName('NIST256p')

class TestGetPointByteSize(unittest.TestCase):
    def test_with_curve(self):
        self.assertEqual(getPointByteSize(ecdsa.NIST256p), 32)

    def test_with_point(self):
        self.assertEqual(getPointByteSize(ecdsa.NIST384p.generator * 10), 48)

    def test_with_invalid_argument(self):
        with self.assertRaises(ValueError):
            getPointByteSize("P-256")
