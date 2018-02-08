# Copyright (c) 2017, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import sys

from tlslite.recordlayer import RecordLayer
from tlslite.messages import ServerHello, ClientHello, Alert, RecordHeader3
from tlslite.constants import CipherSuite, AlertDescription, ContentType, \
        ExtensionType, GroupName, ECPointFormat, HashAlgorithm, \
        SignatureAlgorithm, SignatureScheme, HandshakeType, TLS_1_3_DRAFT
from tlslite.tlsconnection import TLSConnection
from tlslite.errors import TLSLocalAlert, TLSRemoteAlert
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.handshakesettings import HandshakeSettings
from tlslite.session import Session
from tlslite.utils.codec import Parser
from tlslite.extensions import TLSExtension, SNIExtension, \
        SupportedGroupsExtension, ECPointFormatsExtension, \
        ClientKeyShareExtension, KeyShareEntry, SupportedVersionsExtension, \
        SignatureAlgorithmsExtension
from tlslite.utils.x25519 import x25519
from tlslite.utils.cryptomath import secureHMAC, HKDF_expand_label, \
        derive_secret
from tlslite.handshakehashes import HandshakeHashes
from unit_tests.mocksock import MockSocket


def str_to_bytearray(value):
    if sys.version_info < (2, 7):
        return bytearray.fromhex(unicode(value))
    else:
        return bytearray.fromhex(value)


# values from draft-ietf-tls-tls13-vectors-02
client_key_private = str_to_bytearray(
        "304546ef3c866b23 cc42b5e95282e5df"
        "16ab583ffd142c40 743dd4f306e67220")

client_key_public = str_to_bytearray(
        "da6a859ad6d2dbb5 1124fbfe6baff63d"
        "8f14365ec990d575 761e4a6164978d31")

client_hello_plaintext = str_to_bytearray(
        "010001fc0303af21 156b04db639e6615"
        "4a1fe5adfaeadf9e 413416000d57b8e1 126d4d119a8b0000"
        "3e130113031302c0 2bc02fcca9cca8c0 0ac009c013c023c0"
        "27c014009eccaa00 3300320067003900 38006b0016001300"
        "9c002f003c003500 3d000a0005000401 0001950000000b00"
        "0900000673657276 6572ff0100010000 0a00140012001d00"
        "1700180019010001 0101020103010400 0b00020100002300"
        "0000280026002400 1d0020da6a859ad6 d2dbb51124fbfe6b"
        "aff63d8f14365ec9 90d575761e4a6164 978d31002b000706"
        "7f1503030302000d 0020001e04030503 0603020308040805"
        "0806040105010601 0201040205020602 0202002d00020101"
        "001500fc00000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000")

client_hello_ciphertext = str_to_bytearray(
        "1603010200010001 fc0303af21156b04"
        "db639e66154a1fe5 adfaeadf9e413416 000d57b8e1126d4d"
        "119a8b00003e1301 13031302c02bc02f cca9cca8c00ac009"
        "c013c023c027c014 009eccaa00330032 006700390038006b"
        "00160013009c002f 003c0035003d000a 0005000401000195"
        "0000000b00090000 06736572766572ff 01000100000a0014"
        "0012001d00170018 0019010001010102 01030104000b0002"
        "0100002300000028 00260024001d0020 da6a859ad6d2dbb5"
        "1124fbfe6baff63d 8f14365ec990d575 761e4a6164978d31"
        "002b0007067f1503 030302000d002000 1e04030503060302"
        "0308040805080604 0105010601020104 0205020602020200"
        "2d00020101001500 fc00000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000000000"
        "0000000000000000 0000000000000000 0000000000")

server_hello_ciphertext = str_to_bytearray(
        "1603010052020000 4e7f15deac631669"
        "eaf28c6b128b2091 d36441e618964dd8 f0ec812e31cda7ae"
        "c1d0c11301002800 280024001d00209d 1bfe8053046d2dbd"
        "8e0e6221dad11587 584713c8cf497074 d9d26d067c432f")

server_hello_payload = str_to_bytearray(
        "0200004e7f15deac 631669eaf28c6b12"
        "8b2091d36441e618 964dd8f0ec812e31 cda7aec1d0c11301"
        "002800280024001d 00209d1bfe805304 6d2dbd8e0e6221da"
        "d11587584713c8cf 497074d9d26d067c 432f")

class TestSimple1RTTHandshakeAsClient(unittest.TestCase):
    @unittest.skipIf(True, "vectors-02 while we need -04")
    def test(self):

        sock = MockSocket(server_hello_ciphertext)

        record_layer = RecordLayer(sock)

        ext = [SNIExtension().create(bytearray(b'server')),
               TLSExtension(extType=ExtensionType.renegotiation_info)
               .create(bytearray(b'\x00')),
               SupportedGroupsExtension().create([GroupName.x25519,
                                                  GroupName.secp256r1,
                                                  GroupName.secp384r1,
                                                  GroupName.secp521r1,
                                                  GroupName.ffdhe2048,
                                                  GroupName.ffdhe3072,
                                                  GroupName.ffdhe4096,
                                                  GroupName.ffdhe6144,
                                                  GroupName.ffdhe8192]),
               ECPointFormatsExtension().create([ECPointFormat.uncompressed]),
               TLSExtension(extType=35),
               ClientKeyShareExtension().create([KeyShareEntry().create(GroupName.x25519,
                                                client_key_public,
                                                client_key_private)]),
               SupportedVersionsExtension().create([TLS_1_3_DRAFT,
                                                    (3, 3), (3, 2)]),
               SignatureAlgorithmsExtension().create([(HashAlgorithm.sha256,
                                                       SignatureAlgorithm.ecdsa),
                                                      (HashAlgorithm.sha384,
                                                       SignatureAlgorithm.ecdsa),
                                                      (HashAlgorithm.sha512,
                                                       SignatureAlgorithm.ecdsa),
                                                      (HashAlgorithm.sha1,
                                                       SignatureAlgorithm.ecdsa),
                                                      SignatureScheme.rsa_pss_sha256,
                                                      SignatureScheme.rsa_pss_sha384,
                                                      SignatureScheme.rsa_pss_sha512,
                                                      SignatureScheme.rsa_pkcs1_sha256,
                                                      SignatureScheme.rsa_pkcs1_sha384,
                                                      SignatureScheme.rsa_pkcs1_sha512,
                                                      SignatureScheme.rsa_pkcs1_sha1,
                                                      (HashAlgorithm.sha256,
                                                       SignatureAlgorithm.dsa),
                                                      (HashAlgorithm.sha384,
                                                       SignatureAlgorithm.dsa),
                                                      (HashAlgorithm.sha512,
                                                       SignatureAlgorithm.dsa),
                                                      (HashAlgorithm.sha1,
                                                       SignatureAlgorithm.dsa)]),
                TLSExtension(extType=45).create(bytearray(b'\x01\x01')),
                TLSExtension(extType=ExtensionType.client_hello_padding)
                .create(bytearray(252))
               ]
        client_hello = ClientHello()
        client_hello.create((3, 3),
                            bytearray(b'\xaf!\x15k\x04\xdbc\x9ef\x15J\x1f\xe5'
                                      b'\xad\xfa\xea\xdf\x9eA4\x16\x00\rW\xb8'
                                      b'\xe1\x12mM\x11\x9a\x8b'),
                            bytearray(b''),
                            [CipherSuite.TLS_AES_128_GCM_SHA256,
                             CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                             CipherSuite.TLS_AES_256_GCM_SHA384,
                             CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                             CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                             0xCCA9,
                             CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                             CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                             CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                             CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                             CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                             CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                             CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                             CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                             CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                             CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                             0x0032,
                             CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                             CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                             0x0038,
                             CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                             CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                             0x0013,
                             CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                             CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                             CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                             CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                             CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                             CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                             CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                             CipherSuite.TLS_RSA_WITH_RC4_128_MD5],
                            extensions=ext)

        self.assertEqual(client_hello.write(), client_hello_ciphertext[5:])

        for result in record_layer.recvRecord():
            # check if non-blocking
            self.assertNotIn(result, (0, 1))
        header, parser = result
        hs_type = parser.get(1)
        self.assertEqual(hs_type, HandshakeType.server_hello)
        server_hello = ServerHello().parse(parser)

        self.assertEqual(server_hello.server_version, TLS_1_3_DRAFT)
        self.assertEqual(server_hello.cipher_suite, CipherSuite.TLS_AES_128_GCM_SHA256)

        server_key_share = server_hello.getExtension(ExtensionType.key_share)
        server_key_share = server_key_share.server_share

        self.assertEqual(server_key_share.group, GroupName.x25519)

        # for TLS_AES_128_GCM_SHA256:
        prf_name = 'sha256'
        prf_size = 256 // 8
        secret = bytearray(prf_size)
        psk = bytearray(prf_size)

        # early secret
        secret = secureHMAC(secret, psk, prf_name)

        self.assertEqual(secret,
                         str_to_bytearray(
                             "33ad0a1c607ec03b 09e6cd9893680ce2"
                             "10adf300aa1f2660 e1b22e10f170f92a"))

        # derive secret for handshake
        secret = derive_secret(secret, b"derived", None, prf_name)

        self.assertEqual(secret,
                         str_to_bytearray(
                             "6f2615a108c702c5 678f54fc9dbab697"
                             "16c076189c48250c ebeac3576c3611ba"))

        # extract secret "handshake"
        Z = x25519(client_key_private, server_key_share.key_exchange)

        self.assertEqual(Z,
                         str_to_bytearray(
                             "f677c3cdac26a755 455b130efa9b1a3f"
                             "3cafb153544ca46a ddf670df199d996e"))

        secret = secureHMAC(secret, Z, prf_name)

        self.assertEqual(secret,
                         str_to_bytearray(
                             "0cefce00d5d29fd0 9f5de36c86fc8e72"
                             "99b4ad11ba4211c6 7063c2cc539fc4f9"))

        handshake_hashes = HandshakeHashes()
        handshake_hashes.update(client_hello_plaintext)
        handshake_hashes.update(server_hello_payload)

        # derive "tls13 c hs traffic"
        c_hs_traffic = derive_secret(secret,
                                     bytearray(b'c hs traffic'),
                                     handshake_hashes,
                                     prf_name)
        self.assertEqual(c_hs_traffic,
                         str_to_bytearray(
                             "5a63db760b817b1b da96e72832333aec"
                             "6a177deeadb5b407 501ac10c17dac0a4"))
        s_hs_traffic = derive_secret(secret,
                                     bytearray(b's hs traffic'),
                                     handshake_hashes,
                                     prf_name)
        self.assertEqual(s_hs_traffic,
                         str_to_bytearray(
                             "3aa72a3c77b791e8 f4de243f9ccce172"
                             "941f8392aeb05429 320f4b572ccfe744"))

        # derive master secret
        secret = derive_secret(secret, b"derived", None, prf_name)

        self.assertEqual(secret,
                         str_to_bytearray(
                             "32cadf38f3089048 5c54bf4f1184eaa5"
                             "569eeef15a43f3c7 6ab33965a47c9ff6"))

        # extract secret "master
        secret = secureHMAC(secret, bytearray(prf_size), prf_name)

        self.assertEqual(secret,
                         str_to_bytearray(
                             "6c6d4b3e7c925460 82d7b7a32f6ce219"
                             "3804f1bb930fed74 5c6b93c71397f424"))
