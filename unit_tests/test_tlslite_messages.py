# Author: Hubert Kario (c) 2014
# see LICENCE file for legal information regarding use of this file

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest
from tlslite.messages import ClientHello, ServerHello, RecordHeader3, Alert, \
        RecordHeader2, Message
from tlslite.utils.codec import Parser
from tlslite.constants import CipherSuite, CertificateType, ContentType, \
        AlertLevel, AlertDescription, ExtensionType
from tlslite.extensions import SNIExtension, ClientCertTypeExtension, \
    SRPExtension, TLSExtension
from tlslite.errors import TLSInternalError

class TestMessage(unittest.TestCase):
    def test___init__(self):
        msg = Message(ContentType.application_data, bytearray(0))

        self.assertEqual(ContentType.application_data, msg.contentType)
        self.assertEqual(bytearray(0), msg.data)

    def test_write(self):
        msg = Message(0, bytearray(10))

        self.assertEqual(bytearray(10), msg.write())

class TestClientHello(unittest.TestCase):
    def test___init__(self):
        client_hello = ClientHello()

        assert client_hello
        self.assertEqual(False, client_hello.ssl2)
        self.assertEqual((0,0), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([], client_hello.compression_methods)

    def test_create(self):
        client_hello = ClientHello()
        client_hello.create((3,0), bytearray(32), bytearray(0), \
                [])

        self.assertEqual((3,0), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([0], client_hello.compression_methods)

    def test_create_with_one_ciphersuite(self):
        client_hello = ClientHello()
        client_hello.create((3,0), bytearray(32), bytearray(0), \
                [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV])

        self.assertEqual((3,0), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV], \
                client_hello.cipher_suites)
        self.assertEqual([0], client_hello.compression_methods)

    def test_create_with_random(self):
        client_hello = ClientHello()
        client_hello.create((3,0), bytearray(b'\x01' + \
                b'\x00'*30 + b'\x02'), bytearray(0), \
                [])

        self.assertEqual((3,0), client_hello.client_version)
        self.assertEqual(bytearray(b'\x01' + b'\x00'*30 + b'\x02'), \
                client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([0], client_hello.compression_methods)

    def test_parse(self):
        p = Parser(bytearray(
            # we don't include the type of message as it is handled by the
            # hello protocol parser
            #b'x01' +             # type of message - client_hello
            b'\x00'*2 + b'\x26' + # length - 38 bytes
            b'\x01\x01' +         # protocol version - arbitrary (invalid)
            b'\x00'*32 +          # client random
            b'\x00' +             # session ID length
            b'\x00'*2 +           # cipher suites length
            b'\x00'               # compression methods length
            ))
        client_hello = ClientHello()
        client_hello = client_hello.parse(p)

        self.assertEqual((1,1), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([], client_hello.compression_methods)
        self.assertEqual(bytearray(0), client_hello.server_name)
        # XXX not sent
        self.assertEqual([0], client_hello.certificate_types)
        self.assertEqual(False, client_hello.supports_npn)
        self.assertEqual(False, client_hello.tack)
        self.assertEqual(None, client_hello.srp_username)
        self.assertEqual(None, client_hello.extensions)

    def test_parse_with_empty_extensions(self):
        p = Parser(bytearray(
            # we don't include the type of message as it is handled by the
            # hello protocol parser
            #b'x01' +             # type of message - client_hello
            b'\x00'*2 + b'\x28' + # length - 38 bytes
            b'\x01\x01' +         # protocol version - arbitrary (invalid)
            b'\x00'*32 +          # client random
            b'\x00' +             # session ID length
            b'\x00'*2 +           # cipher suites length
            b'\x00' +             # compression methods length
            b'\x00\x00'           # extensions length
            ))
        client_hello = ClientHello()
        client_hello = client_hello.parse(p)

        self.assertEqual((1,1), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([], client_hello.compression_methods)
        self.assertEqual([], client_hello.extensions)

    def test_parse_with_SNI_extension(self):
        p = Parser(bytearray(
            # we don't include the type of message as it is handled by the
            # hello protocol parser
            #b'x01' +             # type of message - client_hello
            b'\x00'*2 + b'\x3c' + # length - 60 bytes
            b'\x01\x01' +         # protocol version - arbitrary (invalid)
            b'\x00'*32 +          # client random
            b'\x00' +             # session ID length
            b'\x00'*2 +           # cipher suites length
            b'\x00' +             # compression methods length
            b'\x00\x14' +         # extensions length - 20 bytes
            b'\x00\x00' +         # extension type - SNI (0)
            b'\x00\x10' +         # extension length - 16 bytes
            b'\x00\x0e' +         # length of array - 14 bytes
            b'\x00' +             # type of entry - host_name (0)
            b'\x00\x0b' +         # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'
            ))
        client_hello = ClientHello()
        client_hello = client_hello.parse(p)

        self.assertEqual((1,1), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([], client_hello.compression_methods)
        self.assertEqual(bytearray(b'example.com'), client_hello.server_name)
        sni = SNIExtension().create(bytearray(b'example.com'))
        self.assertEqual([sni], client_hello.extensions)

    def test_parse_with_cert_type_extension(self):
        p = Parser(bytearray(
            # we don't include the type of message as it is handled by the
            # hello protocol parser
            #b'x01' +             # type of message - client_hello
            b'\x00'*2 + b'\x2f' + # length - 47 bytes
            b'\x01\x01' +         # protocol version - arbitrary (invalid)
            b'\x00'*32 +          # client random
            b'\x00' +             # session ID length
            b'\x00'*2 +           # cipher suites length
            b'\x00' +             # compression methods length
            b'\x00\x07' +         # extensions length - 7 bytes
            b'\x00\x09' +         # extension type - cert_types (9)
            b'\x00\x03' +         # extension length - 3 bytes
            b'\x02' +             # length of array - 2 bytes
            b'\x00' +             # type - x509 (0)
            b'\x01'               # type - opengpg (1)
            ))
        client_hello = ClientHello()
        client_hello = client_hello.parse(p)

        self.assertEqual((1,1), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([], client_hello.compression_methods)
        self.assertEqual([0,1], client_hello.certificate_types)
        cert_types = ClientCertTypeExtension().create([0,1])
        self.assertEqual([cert_types], client_hello.extensions)

    def test_parse_with_SRP_extension(self):
        p = Parser(bytearray(
            # we don't include the type of message as it is handled by the
            # hello protocol parser
            #b'x01' +             # type of message - client_hello
            b'\x00'*2 + b'\x35' + # length - 53 bytes
            b'\x01\x01' +         # protocol version - arbitrary (invalid)
            b'\x00'*32 +          # client random
            b'\x00' +             # session ID length
            b'\x00'*2 +           # cipher suites length
            b'\x00' +             # compression methods length
            b'\x00\x0d' +         # extensions length - 13 bytes
            b'\x00\x0c' +         # extension type - SRP (12)
            b'\x00\x09' +         # extension length - 9 bytes
            b'\x08' +             # length of name - 8 bytes
            b'username'           # UTF-8 encoding of "username" :)
            ))
        client_hello = ClientHello()
        client_hello = client_hello.parse(p)

        self.assertEqual((1,1), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([], client_hello.compression_methods)
        self.assertEqual(bytearray(b'username'), client_hello.srp_username)
        srp = SRPExtension().create(bytearray(b'username'))
        self.assertEqual([srp], client_hello.extensions)

    def test_parse_with_NPN_extension(self):
        p = Parser(bytearray(
            # we don't include the type of message as it is handled by the
            # hello protocol parser
            #b'x01' +             # type of message - client_hello
            b'\x00'*2 + b'\x2c' + # length - 44 bytes
            b'\x01\x01' +         # protocol version - arbitrary (invalid)
            b'\x00'*32 +          # client random
            b'\x00' +             # session ID length
            b'\x00'*2 +           # cipher suites length
            b'\x00' +             # compression methods length
            b'\x00\x04' +         # extensions length - 4 bytes
            b'\x33\x74' +         # extension type - NPN (13172)
            b'\x00\x00'           # extension length - 0 bytes
            ))
        client_hello = ClientHello()
        client_hello = client_hello.parse(p)

        self.assertEqual((1,1), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([], client_hello.compression_methods)
        self.assertEqual(True, client_hello.supports_npn)
        npn = TLSExtension().create(13172, bytearray(0))
        self.assertEqual([npn], client_hello.extensions)

    def test_parse_with_TACK_extension(self):
        p = Parser(bytearray(
            # we don't include the type of message as it is handled by the
            # hello protocol parser
            #b'x01' +             # type of message - client_hello
            b'\x00'*2 + b'\x2c' + # length - 44 bytes
            b'\x01\x01' +         # protocol version - arbitrary (invalid)
            b'\x00'*32 +          # client random
            b'\x00' +             # session ID length
            b'\x00'*2 +           # cipher suites length
            b'\x00' +             # compression methods length
            b'\x00\x04' +         # extensions length - 4 bytes
            b'\xf3\x00' +         # extension type - TACK (62208)
            b'\x00\x00'           # extension length - 0 bytes
            ))
        client_hello = ClientHello()
        client_hello = client_hello.parse(p)

        self.assertEqual((1,1), client_hello.client_version)
        self.assertEqual(bytearray(32), client_hello.random)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([], client_hello.cipher_suites)
        self.assertEqual([], client_hello.compression_methods)
        self.assertEqual(True, client_hello.tack)
        tack = TLSExtension().create(62208, bytearray(0))
        self.assertEqual([tack], client_hello.extensions)

    def test_write(self):
        # client_hello = ClientHello(ssl2)
        client_hello = ClientHello()

        self.assertEqual(list(bytearray(
            b'\x01' +               # type of message - client_hello
            b'\x00'*2 + b'\x26' +   # length - 38 bytes
            b'\x00'*2 +             # protocol version
            b'\x00'*32 +            # client random
            b'\x00' +               # session ID length
            b'\x00'*2 +             # cipher suites length
            b'\x00'                 # compression methods length
            )), list(client_hello.write()))

    def test_write_with_certificate_types(self):

        # note that ClienHello is "clever" and doesn't send the extension
        # if only x509 certificate type is present, so we pass two values
        client_hello = ClientHello().create((3,1),
                bytearray(b'\x00'*31 + b'\xff'), bytearray(0),
                [], certificate_types=[
                    CertificateType.x509, CertificateType.openpgp])

        self.assertEqual(list(bytearray(
                b'\x01' +               # type of message - client_hello
                b'\x00'*2 + b'\x30' +   # length - 48 bytes
                b'\x03\x01' +           # protocol version (TLS 1.0)
                b'\x00'*31 + b'\xff' +  # client random
                b'\x00' +               # session ID length
                b'\x00\x00' +           # cipher suites length
                b'\x01' +               # compression methods length
                b'\x00' +               # supported method - NULL
                b'\x00\x07' +           # extensions length
                b'\x00\x09' +           # cert_type extension value (9)
                b'\x00\x03' +           # size of the extension
                b'\x02' +               # length of supported types
                b'\x00' +               # type - X.509
                b'\x01'                 # type - OpenPGP
                )), list(client_hello.write()))

    def test_write_with_srp_username(self):
        client_hello = ClientHello().create((3,1),
                bytearray(b'\x00'*31 + b'\xff'), bytearray(0),
                [], srpUsername="example-test")

        self.assertEqual(list(bytearray(
                b'\x01' +               # type of message - client_hello
                b'\x00'*2 + b'\x3a' +   # length - 58 bytes
                b'\x03\x01' +           # protocol version (TLS 1.0)
                b'\x00'*31 + b'\xff' +  # client random
                b'\x00' +               # session ID length
                b'\x00\x00' +           # cipher suites length
                b'\x01' +               # compression methods length
                b'\x00' +               # supported method - NULL
                b'\x00\x11' +           # extensions length
                b'\x00\x0c' +           # srp extension value (12)
                b'\x00\x0d' +           # size of the extension
                b'\x0c' +               # length of name
                # ascii encoding of "example-test":
                b'\x65\x78\x61\x6d\x70\x6c\x65\x2d\x74\x65\x73\x74'
                )), list(client_hello.write()))

    def test_write_with_tack(self):
         client_hello = ClientHello().create((3,1),
                 bytearray(b'\x00'*31 + b'\xff'), bytearray(0),
                 [], tack=True)

         self.assertEqual(list(bytearray(
                b'\x01' +               # type of message - client_hello
                b'\x00'*2 + b'\x2d' +   # length - 45 bytes
                b'\x03\x01' +           # protocol version
                b'\x00'*31 + b'\xff' +  # client random
                b'\x00' +               # session ID length
                b'\x00\x00' +           # cipher suites length
                b'\x01' +               # compression methods length
                b'\x00' +               # supported method - NULL
                b'\x00\x04' +           # extensions length
                b'\xf3\x00' +           # TACK extension value (62208)
                b'\x00\x00'             # size of the extension
                )), list(client_hello.write()))

    def test_write_with_npn(self):
         client_hello = ClientHello().create((3,1),
                 bytearray(b'\x00'*31 + b'\xff'), bytearray(0),
                 [], supports_npn=True)

         self.assertEqual(list(bytearray(
                b'\x01' +               # type of message - client_hello
                b'\x00'*2 + b'\x2d' +   # length - 45 bytes
                b'\x03\x01' +           # protocol version
                b'\x00'*31 + b'\xff' +  # client random
                b'\x00' +               # session ID length
                b'\x00\x00' +           # cipher suites length
                b'\x01' +               # compression methods length
                b'\x00' +               # supported method - NULL
                b'\x00\x04' +           # extensions length
                b'\x33\x74' +           # NPN extension value (13172)
                b'\x00\x00'             # size of the extension
                )), list(client_hello.write()))

    def test_write_with_server_name(self):
         client_hello = ClientHello().create((3,1),
                 bytearray(b'\x00'*31 + b'\xff'), bytearray(0),
                 [], serverName="example.com")

         self.assertEqual(list(bytearray(
                b'\x01' +               # type of message - client_hello
                b'\x00'*2 + b'\x3d' +   # length - 61 bytes
                b'\x03\x01' +           # protocol version
                b'\x00'*31 + b'\xff' +  # client random
                b'\x00' +               # session ID length
                b'\x00\x00' +           # cipher suites length
                b'\x01' +               # compression methods length
                b'\x00' +               # supported method - NULL
                b'\x00\x14' +           # extensions length
                b'\x00\x00' +           # servername extension value (0)
                b'\x00\x10' +           # byte size of the extension
                b'\x00\x0e' +           # length of the list
                b'\x00' +               # name type: host_name (0)
                b'\x00\x0b' +           # length of host name
                # utf-8 encoding of "example.com"
                b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'
                )), list(client_hello.write()))

    def test___str__(self):
        client_hello = ClientHello().create((3,0), bytearray(4), bytearray(0),\
                [])

        self.assertEqual("client_hello,version(3.0),random(...),"\
                "session ID(bytearray(b'')),cipher suites([]),"\
                "compression methods([0])", str(client_hello))

    def test___str___with_all_null_session_id(self):
        client_hello = ClientHello().create((3,0), bytearray(4), bytearray(10),\
                [])

        self.assertEqual("client_hello,version(3.0),random(...),"\
                "session ID(bytearray(b'\\x00'*10)),cipher suites([]),"\
                "compression methods([0])", str(client_hello))

    def test___str___with_extensions(self):
        client_hello = ClientHello().create((3,0), bytearray(4), bytearray(0),\
                [],  extensions=[TLSExtension().create(0, bytearray(b'\x00'))])

        self.assertEqual("client_hello,version(3.0),random(...),"\
                "session ID(bytearray(b'')),cipher suites([]),"\
                "compression methods([0]),extensions(["\
                "TLSExtension(ext_type=0, ext_data=bytearray(b'\\x00'), "\
                "server_type=False)])",
                str(client_hello))

    def test___repr__(self):
        client_hello = ClientHello().create((3,3), bytearray(1), bytearray(0),\
                [], extensions=[TLSExtension().create(0, bytearray(0))])

        self.assertEqual("ClientHello(ssl2=False, client_version=(3.3), "\
                "random=bytearray(b'\\x00'), session_id=bytearray(b''), "\
                "cipher_suites=[], compression_methods=[0], "\
                "extensions=[TLSExtension(ext_type=0, "\
                "ext_data=bytearray(b''), server_type=False)])",
                repr(client_hello))

    def test_getExtension(self):
        client_hello = ClientHello().create((3, 3), bytearray(1), bytearray(0),
                [], extensions=[TLSExtension().create(0, bytearray(0))])

        ext = client_hello.getExtension(1)

        self.assertIsNone(ext)

    def test_getExtension_with_present_id(self):
        client_hello = ClientHello().create((3, 3), bytearray(1), bytearray(0),
                [], extensions=[TLSExtension().create(0, bytearray(0))])

        ext = client_hello.getExtension(0)

        self.assertEqual(ext, TLSExtension().create(0, bytearray(0)))

    def test_getExtension_with_duplicated_extensions(self):
        client_hello = ClientHello().create((3, 3), bytearray(1), bytearray(0),
                [], extensions=[TLSExtension().create(0, bytearray(0)),
                                SNIExtension().create(b'localhost')])

        with self.assertRaises(TLSInternalError):
            client_hello.getExtension(0)

    def test_certificate_types(self):
        client_hello = ClientHello().create((3, 3), bytearray(1), bytearray(0),
                [])

        self.assertEqual(client_hello.certificate_types, [0])

        client_hello.certificate_types = [0, 1]

        self.assertEqual(client_hello.certificate_types, [0, 1])

        client_hello.certificate_types = [0, 1, 2]

        self.assertEqual(client_hello.certificate_types, [0, 1, 2])

        ext = client_hello.getExtension(ExtensionType.cert_type)
        self.assertEqual(ext.cert_types, [0, 1, 2])

    def test_srp_username(self):
        client_hello = ClientHello().create((3, 3), bytearray(1), bytearray(0),
                [])

        self.assertIsNone(client_hello.srp_username)

        client_hello.srp_username = b'my-name'

        self.assertEqual(client_hello.srp_username, b'my-name')

        client_hello.srp_username = b'her-name'

        self.assertEqual(client_hello.srp_username, b'her-name')

        ext = client_hello.getExtension(ExtensionType.srp)
        self.assertEqual(ext.identity, b'her-name')

    def test_tack(self):
        client_hello = ClientHello().create((3, 3), bytearray(1), bytearray(0),
                [])

        self.assertFalse(client_hello.tack)

        client_hello.tack = True

        self.assertTrue(client_hello.tack)

        client_hello.tack = True

        self.assertTrue(client_hello.tack)

        ext = client_hello.getExtension(ExtensionType.tack)
        self.assertIsNotNone(ext)

        client_hello.tack = False

        self.assertFalse(client_hello.tack)

        ext = client_hello.getExtension(ExtensionType.tack)
        self.assertIsNone(ext)

    def test_supports_npn(self):
        client_hello = ClientHello().create((3, 3), bytearray(1), bytearray(0),
                [])

        self.assertFalse(client_hello.supports_npn)

        client_hello.supports_npn = True

        self.assertTrue(client_hello.supports_npn)

        client_hello.supports_npn = True

        self.assertTrue(client_hello.supports_npn)

        ext = client_hello.getExtension(ExtensionType.supports_npn)
        self.assertIsNotNone(ext)

        client_hello.supports_npn = False

        self.assertFalse(client_hello.supports_npn)

        ext = client_hello.getExtension(ExtensionType.supports_npn)
        self.assertIsNone(ext)

    def test_server_name(self):
        client_hello = ClientHello().create((3, 3), bytearray(1), bytearray(0),
                [])

        client_hello.server_name = b'example.com'

        self.assertEqual(client_hello.server_name, b'example.com')

        client_hello.server_name = b'example.org'

        self.assertEqual(client_hello.server_name, b'example.org')

        ext = client_hello.getExtension(ExtensionType.server_name)
        self.assertIsNotNone(ext)

    def test_server_name_other_than_dns_name(self):
        client_hello = ClientHello().create((3, 3), bytearray(1), bytearray(0),
                [])

        sni_ext = SNIExtension().create(server_names=[\
                SNIExtension.ServerName(1, b'test')])

        client_hello.extensions = [sni_ext]

        self.assertEqual(client_hello.server_name, bytearray(0))

    def test_parse_with_SSLv2_client_hello(self):
        parser = Parser(bytearray(
            # length and type is handled by hello protocol parser
            #b'\x80\x2e' +           # length - 46 bytes
            #b'\x01' +               # message type - client hello
            b'\x00\x02' +           # version - SSLv2
            b'\x00\x15' +           # cipher spec length - 21 bytes
            b'\x00\x00' +           # session ID length - 0 bytes
            b'\x00\x10' +           # challange length - 16 bytes
            b'\x07\x00\xc0' +       # cipher - SSL2_DES_192_EDE3_CBC_WITH_MD5
            b'\x05\x00\x80' +       # cipher - SSL2_IDEA_128_CBC_WITH_MD5
            b'\x03\x00\x80' +       # cipher - SSL2_RC2_CBC_128_CBC_WITH_MD5
            b'\x01\x00\x80' +       # cipher - SSL2_RC4_128_WITH_MD5
            b'\x06\x00\x40' +       # cipher - SSL2_DES_64_CBC_WITH_MD5
            b'\x04\x00\x80' +       # cipher - SSL2_RC2_CBC_128_CBC_WITH_MD5
            b'\x02\x00\x80' +       # cipher - SSL2_RC4_128_EXPORT40_WITH_MD5
            b'\x01' * 16            # challenge
            ))
        client_hello = ClientHello(ssl2=True)

        client_hello = client_hello.parse(parser)

        # XXX the value on the wire is LSB, but should be interpreted MSB for
        # SSL2
        self.assertEqual((0, 2), client_hello.client_version)
        self.assertEqual(bytearray(0), client_hello.session_id)
        self.assertEqual([458944, 327808, 196736, 65664, 393280, 262272,
                          131200],
                         client_hello.cipher_suites)
        self.assertEqual(bytearray(b'\x00'*16 + b'\x01'*16),
                         client_hello.random)
        self.assertEqual([0], client_hello.compression_methods)

class TestServerHello(unittest.TestCase):
    def test___init__(self):
        server_hello = ServerHello()

        self.assertEqual((0,0), server_hello.server_version)
        self.assertEqual(bytearray(32), server_hello.random)
        self.assertEqual(bytearray(0), server_hello.session_id)
        self.assertEqual(0, server_hello.cipher_suite)
        self.assertEqual(CertificateType.x509, server_hello.certificate_type)
        self.assertEqual(0, server_hello.compression_method)
        self.assertEqual(None, server_hello.tackExt)
        self.assertEqual(None, server_hello.next_protos_advertised)
        self.assertEqual(None, server_hello.next_protos)

    def test_create(self):
        server_hello = ServerHello().create(
                (1,1),                          # server version
                bytearray(b'\x00'*31+b'\x01'),  # random
                bytearray(0),                   # session id
                4,                              # cipher suite
                1,                              # certificate type
                None,                           # TACK ext
                None)                           # next protos advertised

        self.assertEqual((1,1), server_hello.server_version)
        self.assertEqual(bytearray(b'\x00'*31 + b'\x01'), server_hello.random)
        self.assertEqual(bytearray(0), server_hello.session_id)
        self.assertEqual(4, server_hello.cipher_suite)
        self.assertEqual(CertificateType.openpgp, server_hello.certificate_type)
        self.assertEqual(0, server_hello.compression_method)
        self.assertEqual(None, server_hello.tackExt)
        self.assertEqual(None, server_hello.next_protos_advertised)

    def test_parse(self):
        p = Parser(bytearray(
            # don't include type of message as it is handled by the hello
            # protocol layer
            # b'\x02' +                     # type of message - server_hello
            b'\x00\x00\x36' +               # length - 54 bytes
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x01' +                       # compression method (zlib)
            b'\x00\x0e' +                   # extensions length - 14 bytes
            b'\xff\x01' +                   # ext type - renegotiation_info
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x00' +                       # value - supported (0)
            b'\x00\x23' +                   # ext type - session ticket (35)
            b'\x00\x00' +                   # ext length - 0 bytes
            b'\x00\x0f' +                   # ext type - heartbeat (15)
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x01'))                       # peer allowed to send requests (1)
        server_hello = ServerHello()
        server_hello = server_hello.parse(p)

        self.assertEqual((3,3), server_hello.server_version)
        self.assertEqual(bytearray(b'\x01'*31 + b'\x02'), server_hello.random)
        self.assertEqual(bytearray(0), server_hello.session_id)
        self.assertEqual(157, server_hello.cipher_suite)
        # XXX not sent by server!
        self.assertEqual(CertificateType.x509, server_hello.certificate_type)
        self.assertEqual(1, server_hello.compression_method)
        self.assertEqual(None, server_hello.tackExt)
        self.assertEqual(None, server_hello.next_protos_advertised)

    def test_parse_with_length_short_by_one(self):
        p = Parser(bytearray(
            # don't include type of message as it is handled by the hello
            # protocol layer
            # b'\x02' +                     # type of message - server_hello
            b'\x00\x00\x25' +               # length - 37 bytes (one short)
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x01'                         # compression method (zlib)
            ))
        server_hello = ServerHello()
        with self.assertRaises(SyntaxError) as context:
            server_hello.parse(p)

        # TODO the message probably could be more descriptive...
        self.assertIsNone(context.exception.msg)

    def test_parse_with_length_long_by_one(self):
        p = Parser(bytearray(
            # don't include type of message as it is handled by the hello
            # protocol layer
            # b'\x02' +                     # type of message - server_hello
            b'\x00\x00\x27' +               # length - 39 bytes (one long)
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x01'                         # compression method (zlib)
            ))
        server_hello = ServerHello()
        with self.assertRaises(SyntaxError) as context:
            server_hello.parse(p)

        # TODO the message probably could be more descriptive...
        self.assertIsNone(context.exception.msg)

    def test_parse_with_extensions_length_short_by_one(self):
        p = Parser(bytearray(
            # don't include type of message as it is handled by the hello
            # protocol layer
            # b'\x02' +                     # type of message - server_hello
            b'\x00\x00\x36' +               # length - 54 bytes
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x01' +                       # compression method (zlib)
            b'\x00\x0d' +                   # extensions length - 13 bytes (!)
            b'\xff\x01' +                   # ext type - renegotiation_info
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x00' +                       # value - supported (0)
            b'\x00\x23' +                   # ext type - session ticket (35)
            b'\x00\x00' +                   # ext length - 0 bytes
            b'\x00\x0f' +                   # ext type - heartbeat (15)
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x01'))                       # peer allowed to send requests (1)
        server_hello = ServerHello()

        with self.assertRaises(SyntaxError) as context:
            server_hello.parse(p)

        # TODO the message could be more descriptive...
        self.assertIsNone(context.exception.msg)

    def test_parse_with_extensions_length_long_by_one(self):
        p = Parser(bytearray(
            # don't include type of message as it is handled by the hello
            # protocol layer
            # b'\x02' +                     # type of message - server_hello
            b'\x00\x00\x36' +               # length - 54 bytes
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x01' +                       # compression method (zlib)
            b'\x00\x0f' +                   # extensions length - 15 bytes (!)
            b'\xff\x01' +                   # ext type - renegotiation_info
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x00' +                       # value - supported (0)
            b'\x00\x23' +                   # ext type - session ticket (35)
            b'\x00\x00' +                   # ext length - 0 bytes
            b'\x00\x0f' +                   # ext type - heartbeat (15)
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x01'))                       # peer allowed to send requests (1)
        server_hello = ServerHello()

        with self.assertRaises(SyntaxError) as context:
            server_hello.parse(p)

        # TODO the message could be more descriptive...
        self.assertIsNone(context.exception.msg)

    def test_parse_with_cert_type_extension(self):
        p = Parser(bytearray(
            b'\x00\x00\x2d' +               # length - 45 bytes
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x00' +                       # compression method (none)
            b'\x00\x05' +                   # extensions length - 5 bytes
            b'\x00\x09' +                   # ext type - cert_type (9)
            b'\x00\x01' +                   # ext length - 1 byte
            b'\x01'                         # value - OpenPGP (1)
            ))

        server_hello = ServerHello().parse(p)
        self.assertEqual(1, server_hello.certificate_type)

    def test_parse_with_bad_cert_type_extension(self):
        p = Parser(bytearray(
            b'\x00\x00\x2e' +               # length - 46 bytes
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x00' +                       # compression method (none)
            b'\x00\x06' +                   # extensions length - 5 bytes
            b'\x00\x09' +                   # ext type - cert_type (9)
            b'\x00\x02' +                   # ext length - 2 bytes
            b'\x00\x01'                     # value - X.509 (0), OpenPGP (1)
            ))

        server_hello = ServerHello()
        with self.assertRaises(SyntaxError) as context:
            server_hello.parse(p)

    def test_parse_with_NPN_extension(self):
        p = Parser(bytearray(
            b'\x00\x00\x3c' +               # length - 60 bytes
            b'\x03\x03' +                   # version - TLS 1.2
            b'\x01'*31 + b'\x02' +          # random
            b'\x00' +                       # session id length
            b'\x00\x9d' +                   # cipher suite
            b'\x00' +                       # compression method (none)
            b'\x00\x14' +                   # extensions length - 20 bytes
            b'\x33\x74' +                   # ext type - npn
            b'\x00\x10' +                   # ext length - 16 bytes
            b'\x08' +                       # length of first name - 8 bytes
            b'http/1.1' +
            b'\x06' +                       # length of second name - 6 bytes
            b'spdy/3'
            ))

        server_hello = ServerHello().parse(p)

        self.assertEqual([bytearray(b'http/1.1'), bytearray(b'spdy/3')],
                server_hello.next_protos)

    def test_write(self):
        server_hello = ServerHello().create(
                (1,1),                          # server version
                bytearray(b'\x00'*31+b'\x02'),  # random
                bytearray(0),                   # session id
                4,                              # cipher suite
                None,                           # certificate type
                None,                           # TACK ext
                None)                           # next protos advertised

        self.assertEqual(list(bytearray(
            b'\x02' +               # type of message - server_hello
            b'\x00\x00\x26' +       # length
            b'\x01\x01' +           # proto version
            b'\x00'*31 + b'\x02' +  # random
            b'\x00' +               # session id length
            b'\x00\x04' +           # cipher suite
            b'\x00'                 # compression method
            )), list(server_hello.write()))

    def test_write_with_next_protos(self):
        server_hello = ServerHello().create(
                (1,1),                          # server version
                bytearray(b'\x00'*31+b'\x02'),  # random
                bytearray(0),                   # session id
                4,                              # cipher suite
                0,                              # certificate type
                None,                           # TACK ext
                [b'spdy/3', b'http/1.1'])       # next protos advertised

        self.assertEqual(list(bytearray(
            b'\x02' +               # type of message - server_hello
            b'\x00\x00\x3c' +       # length
            b'\x01\x01' +           # proto version
            b'\x00'*31 + b'\x02' +  # random
            b'\x00' +               # session id length
            b'\x00\x04' +           # cipher suite
            b'\x00' +               # compression method
            b'\x00\x14' +           # extensions length
            b'\x33\x74' +           # ext type - NPN (13172)
            b'\x00\x10' +           # ext length - 16 bytes
            b'\x06' +               # first entry length - 6 bytes
            # utf-8 encoding of 'spdy/3'
            b'\x73\x70\x64\x79\x2f\x33'
            b'\x08' +               # second entry length - 8 bytes
            # utf-8 endoding of 'http/1.1'
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31'
            )), list(server_hello.write()))

    def test___str__(self):
        server_hello = ServerHello()
        server_hello = server_hello.create(
                (3,0),
                bytearray(b'\x00'*32),
                bytearray(b'\x01\x20'),
                34500,
                0,
                None,
                None)

        self.assertEqual("server_hello,length(40),version(3.0),random(...),"\
                "session ID(bytearray(b'\\x01 ')),cipher(0x86c4),"\
                "compression method(0)",
                str(server_hello))

    def test___repr__(self):
        server_hello = ServerHello()
        server_hello = server_hello.create(
                (3,0),
                bytearray(b'\x00'*32),
                bytearray(0),
                34500,
                0,
                None,
                None,
                extensions=[])
        self.maxDiff = None
        self.assertEqual("ServerHello(server_version=(3.0), "\
                "random=bytearray(b'\\x00\\x00"\
                "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"\
                "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"\
                "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'), "\
                "session_id=bytearray(b''), "\
                "cipher_suite=34500, compression_method=0, _tack_ext=None, "\
                "extensions=[])", repr(server_hello))

class TestRecordHeader2(unittest.TestCase):
    def test___init__(self):
        rh = RecordHeader2()

        self.assertTrue(rh.ssl2)
        self.assertEqual(0, rh.type)
        self.assertEqual((0, 0), rh.version)

    def test_parse(self):
        parser = Parser(bytearray(
            b'\x80' +       # head
            b'\x12'         # length
            ))

        rh = RecordHeader2()
        rh = rh.parse(parser)

        self.assertTrue(rh.ssl2)
        self.assertEqual(ContentType.handshake, rh.type)
        self.assertEqual((2, 0), rh.version)
        self.assertEqual(18, rh.length)

    def test_parse_with_invalid_header(self):
        parser = Parser(bytearray(
            b'\x00' +       # header (bad)
            b'\x12'         # length
            ))

        rh = RecordHeader2()
        with self.assertRaises(SyntaxError):
            rh.parse(parser)

    def test_parse_with_very_long_message(self):
        parser = Parser(bytearray(
            b'\x82' +       # header and a nibble of length
            b'\x00'
            ))

        rh = RecordHeader2()

        #XXX can't handle two-byte length
        with self.assertRaises(SyntaxError):
            rh = rh.parse(parser)

        #self.assertEqual(512, rh.length)

class TestRecordHeader3(unittest.TestCase):
    def test___init__(self):
        rh = RecordHeader3()

        self.assertEqual(0, rh.type)
        self.assertEqual((0, 0), rh.version)
        self.assertEqual(0, rh.length)
        self.assertFalse(rh.ssl2)

    def test_create(self):
        rh = RecordHeader3()

        rh = rh.create((3, 3), ContentType.application_data, 10)

        self.assertEqual((3, 3), rh.version)
        self.assertEqual(ContentType.application_data, rh.type)
        self.assertEqual(10, rh.length)
        self.assertFalse(rh.ssl2)

    def test_write(self):
        rh = RecordHeader3()

        rh = rh.create((3, 3), ContentType.application_data, 10)

        self.assertEqual(bytearray(
            b'\x17' +       # protocol type
            b'\x03\x03' +   # protocol version
            b'\x00\x0a'     # length
            ), rh.write())

    def test_write_with_too_big_length(self):
        rh = RecordHeader3()

        rh = rh.create((3, 3), ContentType.application_data, 2**17)

        with self.assertRaises(ValueError):
            rh.write()

    def test_parse(self):
        parser = Parser(bytearray(
            b'\x17' +       # protocol type - app data
            b'\x03\x03' +   # protocol version
            b'\x00\x0f'     # length
            ))

        rh = RecordHeader3()

        rh = rh.parse(parser)

        self.assertFalse(rh.ssl2)
        self.assertEqual(ContentType.application_data, rh.type)
        self.assertEqual((3, 3), rh.version)
        self.assertEqual(15, rh.length)

    def test_type_name(self):
        rh = RecordHeader3()
        rh = rh.create((3,0), ContentType.application_data, 0)

        self.assertEqual("application_data", rh.type_name)

    def test___str__(self):
        rh = RecordHeader3()
        rh = rh.create((3,0), ContentType.handshake, 12)

        self.assertEqual("SSLv3 record,version(3.0),content type(handshake)," +\
                "length(12)", str(rh))

    def test___str___with_invalid_content_type(self):
        rh = RecordHeader3()
        rh = rh.create((3,3), 12, 0)

        self.assertEqual("SSLv3 record,version(3.3)," +\
                "content type(unknown(12)),length(0)",
                str(rh))

    def test___repr__(self):
        rh = RecordHeader3()
        rh = rh.create((3,0), ContentType.application_data, 256)

        self.assertEqual("RecordHeader3(type=23, version=(3.0), length=256)",
                repr(rh))

class TestAlert(unittest.TestCase):
    def test___init__(self):
        alert = Alert()

        self.assertEqual(alert.contentType, ContentType.alert)
        self.assertEqual(alert.level, 0)
        self.assertEqual(alert.description, 0)

    def test_level_name(self):
        alert = Alert().create(AlertDescription.record_overflow,
                AlertLevel.fatal)

        self.assertEqual("fatal", alert.level_name)

    def test_level_name_with_wrong_level(self):
        alert = Alert().create(AlertDescription.close_notify, 11)

        self.assertEqual("unknown(11)", alert.level_name)

    def test_description_name(self):
        alert = Alert().create(AlertDescription.record_overflow,
                AlertLevel.fatal)

        self.assertEqual("record_overflow", alert.description_name)

    def test_description_name_with_wrong_id(self):
        alert = Alert().create(1)

        self.assertEqual("unknown(1)", alert.description_name)

    def test___str__(self):
        alert = Alert().create(AlertDescription.record_overflow,
                AlertLevel.fatal)

        self.assertEqual("Alert, level:fatal, description:record_overflow",
                str(alert))

    def test___repr__(self):
        alert = Alert().create(AlertDescription.record_overflow,
                AlertLevel.fatal)

        self.assertEqual("Alert(level=2, description=22)", repr(alert))

    def test_parse(self):
        alert = Alert()

        parser = Parser(bytearray(
            b'\x01' +           # level
            b'\x02'             # description
            ))

        alert = alert.parse(parser)

        self.assertEqual(alert.level, 1)
        self.assertEqual(alert.description, 2)

    def test_parse_with_missing_data(self):
        alert = Alert()

        parser = Parser(bytearray(
            b'\x01'))           # level

        with self.assertRaises(SyntaxError):
            alert.parse(parser)

    def test_write(self):
        alert = Alert().create(AlertDescription.record_overflow)

        self.assertEqual(bytearray(
            b'\x02\x16'), alert.write())

if __name__ == '__main__':
    unittest.main()
