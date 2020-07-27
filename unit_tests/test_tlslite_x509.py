try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import mock
    from mock import call
except ImportError:
    import unittest.mock as mock
    from unittest.mock import call

from tlslite.x509 import X509
from tlslite.utils.python_ecdsakey import Python_ECDSAKey
from tlslite.utils.python_dsakey import Python_DSAKey
from tlslite.x509certchain import X509CertChain

class TestX509(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (
                "-----BEGIN CERTIFICATE-----\n"
                "MIICADCCAb4CFHkCg9fwn/zcM/TD6B64Tswz2kY0MAsGCWCGSAFlAwQDAjBCMQsw\n"
                "CQYDVQQGEwJYWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZh\n"
                "dWx0IENvbXBhbnkgTHRkMB4XDTIwMDgyNTEzMjQwMFoXDTIwMDkyNDEzMjQwMFow\n"
                "QjELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UECgwT\n"
                "RGVmYXVsdCBDb21wYW55IEx0ZDCB8DCBqAYHKoZIzjgEATCBnAJBAMlgtp55FiZi\n"
                "qWYGfB4hPFUYOnqkk623ce+iaLwVcCbBdbyqVoKwUalRVD8T881/nQi397D1Z4In\n"
                "Gl/JldQrHL8CFQCOjvJtjMV4nGb5ba3xBMPe9eNgKQJAaJUGAJWiBCX8B3F4L/aW\n"
                "LYqtuLq5addIbqbPp/HTERrlhUVJT/q8X9pOs0XoYWQUFE8PEhQ4lg7rW8FpY2wG\n"
                "QwNDAAJAWioQxgeLlYaWUAZ5Kn50XOdTIXeei2pT2lPQJRPiLal6lbRIjWtRBUxZ\n"
                "5E8ZprqposeXmhXUD5yiH1j3QpO9tjALBglghkgBZQMEAwIDLwAwLAIUPbzET5yw\n"
                "Q2X7BhyH54TexhH3qtUCFC7xATT0yhicbIwPd5hdby48/LPE\n"
                "-----END CERTIFICATE-----")
    def test_pem(self):
        x509 = X509()
        x509.parse(self.data)

        self.assertIsNotNone(x509.publicKey)
        self.assertIsInstance(x509.publicKey, Python_DSAKey)
        self.assertEqual(x509.publicKey.public_key,
            4722288530596455996646906166695523806692613655353447223282773465832779382040438176451429757221301981512642444955162317515065524082346317409775757603093942)
        self.assertEqual(x509.publicKey.public_key.pubkey.point.y(),
            12490546948316647166662676770106859255378658810545502161335656899238893361610)
        self.assertEqual(x509.publicKey.curve_name, "NIST256p")


class TestX509(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBbTCCARSgAwIBAgIJAPM58cskyK+yMAkGByqGSM49BAEwFDESMBAGA1UEAwwJ\n"
            "bG9jYWxob3N0MB4XDTE3MTAyMzExNDI0MVoXDTE3MTEyMjExNDI0MVowFDESMBAG\n"
            "A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyDRjEAJe\n"
            "3F5T62MyZbhjoJnPLGL2nrTthLFymBupZ2IbnWYnqVWDkT/L6i8sQhf2zCLrlSjj\n"
            "1kn7ERqPx/KZyqNQME4wHQYDVR0OBBYEFPfFTUg9o3t6ehLsschSnC8Te8oaMB8G\n"
            "A1UdIwQYMBaAFPfFTUg9o3t6ehLsschSnC8Te8oaMAwGA1UdEwQFMAMBAf8wCQYH\n"
            "KoZIzj0EAQNIADBFAiA6p0YM5ZzfW+klHPRU2r13/IfKgeRfDR3dtBngmPvxUgIh\n"
            "APTeSDeJvYWVBLzyrKTeSerNDKKHU2Rt7sufipv76+7s\n"
            "-----END CERTIFICATE-----\n")

    def test_pem(self):
        x509 = X509()
        x509.parse(self.data)

        self.assertIsNotNone(x509.publicKey)
        self.assertIsInstance(x509.publicKey, Python_ECDSAKey)
        self.assertEqual(x509.publicKey.public_key.pubkey.point.x(),
            90555129468518880658937518803653422065597446465131062487534800201457796212578)
        self.assertEqual(x509.publicKey.public_key.pubkey.point.y(),
            12490546948316647166662676770106859255378658810545502161335656899238893361610)
        self.assertEqual(x509.publicKey.curve_name, "NIST256p")

    def test_hash(self):
        x509_1 = X509()
        x509_1.parse(self.data)

        x509_2 = X509()
        x509_2.parse(self.data)

        self.assertEqual(hash(x509_1), hash(x509_2))
        self.assertEqual(x509_1, x509_2)

class TestX509CertChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBbTCCARSgAwIBAgIJAPM58cskyK+yMAkGByqGSM49BAEwFDESMBAGA1UEAwwJ\n"
            "bG9jYWxob3N0MB4XDTE3MTAyMzExNDI0MVoXDTE3MTEyMjExNDI0MVowFDESMBAG\n"
            "A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyDRjEAJe\n"
            "3F5T62MyZbhjoJnPLGL2nrTthLFymBupZ2IbnWYnqVWDkT/L6i8sQhf2zCLrlSjj\n"
            "1kn7ERqPx/KZyqNQME4wHQYDVR0OBBYEFPfFTUg9o3t6ehLsschSnC8Te8oaMB8G\n"
            "A1UdIwQYMBaAFPfFTUg9o3t6ehLsschSnC8Te8oaMAwGA1UdEwQFMAMBAf8wCQYH\n"
            "KoZIzj0EAQNIADBFAiA6p0YM5ZzfW+klHPRU2r13/IfKgeRfDR3dtBngmPvxUgIh\n"
            "APTeSDeJvYWVBLzyrKTeSerNDKKHU2Rt7sufipv76+7s\n"
            "-----END CERTIFICATE-----\n")

    def test_pem(self):
        x509cc = X509CertChain()
        x509cc.parsePemList(self.data)

    def test_hash(self):
        x509cc1 = X509CertChain()
        x509cc1.parsePemList(self.data)

        x509cc2 = X509CertChain()
        x509cc2.parsePemList(self.data)

        self.assertEqual(hash(x509cc1), hash(x509cc2))
        self.assertEqual(x509cc1, x509cc2)
