# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.handshakesettings import HandshakeSettings
from tlslite.recordlayer import RecordLayer
from tlslite.messages import ServerHello, Certificate, ServerHelloDone, \
        ClientHello
from tlslite.constants import CipherSuite, CertificateType, AlertDescription
from tlslite.tlsconnection import TLSConnection
from tlslite.errors import TLSLocalAlert
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlslite.utils.keyfactory import parsePEMKey

from unit_tests.mocksock import MockSocket

class TestTLSConnection(unittest.TestCase):

    srv_raw_certificate = str(
        "-----BEGIN CERTIFICATE-----\n"\
        "MIIB9jCCAV+gAwIBAgIJAMyn9DpsTG55MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV\n"\
        "BAMMCWxvY2FsaG9zdDAeFw0xNTAxMjExNDQzMDFaFw0xNTAyMjAxNDQzMDFaMBQx\n"\
        "EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA\n"\
        "0QkEeakSyV/LMtTeARdRtX5pdbzVuUuqOIdz3lg7YOyRJ/oyLTPzWXpKxr//t4FP\n"\
        "QvYsSJiVOlPk895FNu6sNF/uJQyQGfFWYKkE6fzFifQ6s9kssskFlL1DVI/dD/Zn\n"\
        "7sgzua2P1SyLJHQTTs1MtMb170/fX2EBPkDz+2kYKN0CAwEAAaNQME4wHQYDVR0O\n"\
        "BBYEFJtvXbRmxRFXYVMOPH/29pXCpGmLMB8GA1UdIwQYMBaAFJtvXbRmxRFXYVMO\n"\
        "PH/29pXCpGmLMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAkOgC7LP/\n"\
        "Rd6uJXY28HlD2K+/hMh1C3SRT855ggiCMiwstTHACGgNM+AZNqt6k8nSfXc6k1gw\n"\
        "5a7SGjzkWzMaZC3ChBeCzt/vIAGlMyXeqTRhjTCdc/ygRv3NPrhUKKsxUYyXRk5v\n"\
        "g/g6MwxzXfQP3IyFu3a9Jia/P89Z1rQCNRY=\n"\
        "-----END CERTIFICATE-----\n"\
        )

    srv_raw_key = str(
        "-----BEGIN RSA PRIVATE KEY-----\n"\
        "MIICXQIBAAKBgQDRCQR5qRLJX8sy1N4BF1G1fml1vNW5S6o4h3PeWDtg7JEn+jIt\n"\
        "M/NZekrGv/+3gU9C9ixImJU6U+Tz3kU27qw0X+4lDJAZ8VZgqQTp/MWJ9Dqz2Syy\n"\
        "yQWUvUNUj90P9mfuyDO5rY/VLIskdBNOzUy0xvXvT99fYQE+QPP7aRgo3QIDAQAB\n"\
        "AoGAVSLbE8HsyN+fHwDbuo4I1Wa7BRz33xQWLBfe9TvyUzOGm0WnkgmKn3LTacdh\n"\
        "GxgrdBZXSun6PVtV8I0im5DxyVaNdi33sp+PIkZU386f1VUqcnYnmgsnsUQEBJQu\n"\
        "fUZmgNM+bfR+Rfli4Mew8lQ0sorZ+d2/5fsM0g80Qhi5M3ECQQDvXeCyrcy0u/HZ\n"\
        "FNjIloyXaAIvavZ6Lc6gfznCSfHc5YwplOY7dIWp8FRRJcyXkA370l5dJ0EXj5Gx\n"\
        "udV9QQ43AkEA34+RxjRk4DT7Zo+tbM/Fkoi7jh1/0hFkU5NDHweJeH/mJseiHtsH\n"\
        "KOcPGtEGBBqT2KNPWVz4Fj19LiUmmjWXiwJBAIBs49O5/+ywMdAAqVblv0S0nweF\n"\
        "4fwne4cM+5ZMSiH0XsEojGY13EkTEon/N8fRmE8VzV85YmkbtFWgmPR85P0CQQCs\n"\
        "elWbN10EZZv3+q1wH7RsYzVgZX3yEhz3JcxJKkVzRCnKjYaUi6MweWN76vvbOq4K\n"\
        "G6Tiawm0Duh/K4ZmvyYVAkBppE5RRQqXiv1KF9bArcAJHvLm0vnHPpf1yIQr5bW6\n"\
        "njBuL4qcxlaKJVGRXT7yFtj2fj0gv3914jY2suWqp8XJ\n"\
        "-----END RSA PRIVATE KEY-----\n"\
        )

    def test_client_with_server_responing_with_SHA256_on_TLSv1_1(self):
        # socket to generate the faux response
        gen_sock = MockSocket(bytearray(0))

        gen_record_layer = RecordLayer(gen_sock)
        gen_record_layer.version = (3, 2)

        server_hello = ServerHello().create(
                version=(3, 2),
                random=bytearray(32),
                session_id=bytearray(0),
                cipher_suite=CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                certificate_type=None,
                tackExt=None,
                next_protos_advertised=None)

        for res in gen_record_layer.sendRecord(server_hello):
            if res in (0, 1):
                self.assertTrue(False, "Blocking socket")
            else:
                break

        # test proper
        sock = MockSocket(gen_sock.sent[0])

        conn = TLSConnection(sock)

        with self.assertRaises(TLSLocalAlert) as err:
            conn.handshakeClientCert()

        self.assertEqual(err.exception.description,
                         AlertDescription.illegal_parameter)

    def test_server_with_client_proposing_SHA256_on_TLSv1_1(self):
        gen_sock = MockSocket(bytearray(0))

        gen_record_layer = RecordLayer(gen_sock)
        gen_record_layer.version = (3, 0)

        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                   CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                   0x88, # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]

        client_hello = ClientHello().create(version=(3, 2),
                                            random=bytearray(32),
                                            session_id=bytearray(0),
                                            cipher_suites=ciphers)

        for res in gen_record_layer.sendRecord(client_hello):
            if res in (0, 1):
                self.assertTrue(False, "Blocking socket")
            else:
                break

        # test proper
        sock = MockSocket(gen_sock.sent[0])

        conn = TLSConnection(sock)

        srv_private_key = parsePEMKey(self.srv_raw_key, private=True)
        srv_cert_chain = X509CertChain([X509().parse(self.srv_raw_certificate)])
        with self.assertRaises(TLSLocalAlert) as err:
            conn.handshakeServer(certChain=srv_cert_chain,
                                 privateKey=srv_private_key)

        self.assertEqual(err.exception.description,
                         AlertDescription.handshake_failure)
