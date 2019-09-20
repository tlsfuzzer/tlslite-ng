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

class TestX509(unittest.TestCase):
    def test_pem(self):
        data = (
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
        x509 = X509()
        x509.parse(data)

        self.assertIsNotNone(x509.publicKey)
        self.assertIsInstance(x509.publicKey, Python_ECDSAKey)
        self.assertEqual(x509.publicKey.public_key.pubkey.point.x(),
            90555129468518880658937518803653422065597446465131062487534800201457796212578)
        self.assertEqual(x509.publicKey.public_key.pubkey.point.y(),
            12490546948316647166662676770106859255378658810545502161335656899238893361610)
        self.assertEqual(x509.publicKey.curve_name, "NIST256p")

