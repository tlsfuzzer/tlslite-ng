# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.constants import CipherSuite, CertificateType

class TestCertificateType(unittest.TestCase):

    def test_fields(self):
        self.assertEqual(CertificateType.x509, 0)

    def test_toStr(self):
        self.assertEqual(CertificateType.toStr(0), 'x509')

    def test_toStr_with_invalid_value(self):
        self.assertEqual(CertificateType.toStr(-1), '-1')

    def test_toRepr_with_invalid_value(self):
        self.assertIsNone(CertificateType.toRepr(-1))

class TestCipherSuite(unittest.TestCase):

    def test___init__(self):
        cipherSuites = CipherSuite()

        self.assertIsNotNone(cipherSuites)

    def test_filterForVersion_with_SSL3_ciphers(self):
        suites = [CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                  CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                  CipherSuite.TLS_RSA_WITH_RC4_128_MD5]

        filtered = CipherSuite.filterForVersion(suites, (3, 0), (3, 0))

        self.assertEqual(filtered,
                         [CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_RC4_128_MD5])

        filtered = CipherSuite.filterForVersion(suites, (3, 3), (3, 3))

        self.assertEqual(filtered,
                         [CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_RC4_128_MD5])

    def test_filterForVersion_with_unknown_ciphers(self):
        suites = [0, 0xfffe]

        filtered = CipherSuite.filterForVersion(suites, (3, 0), (3, 3))

        self.assertEqual(filtered, [])

    def test_filterForVersion_with_TLS_1_2_ciphers(self):
        suites = [CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                  CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                  CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                  CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                  CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256]

        filtered = CipherSuite.filterForVersion(suites, (3, 2), (3, 2))

        self.assertEqual(filtered,
                         [CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                          CipherSuite.TLS_RSA_WITH_RC4_128_MD5])
