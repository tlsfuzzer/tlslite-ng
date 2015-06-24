# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest
from tlslite.extensions import TLSExtension, SNIExtension, NPNExtension,\
        SRPExtension, ClientCertTypeExtension, ServerCertTypeExtension,\
        TACKExtension
from tlslite.utils.codec import Parser
from tlslite.constants import NameType
from tlslite.errors import TLSInternalError

class TestTLSExtension(unittest.TestCase):
    def test___init__(self):
        tls_extension = TLSExtension()

        assert(tls_extension)
        self.assertIsNone(tls_extension.ext_type)
        self.assertEqual(bytearray(0), tls_extension.ext_data)

    def test_create(self):
        tls_extension = TLSExtension().create(1, bytearray(b'\x01\x00'))

        assert tls_extension
        self.assertEqual(1, tls_extension.ext_type)
        self.assertEqual(bytearray(b'\x01\x00'), tls_extension.ext_data)

    def test_write(self):
        tls_extension = TLSExtension()

        with self.assertRaises(AssertionError) as environment:
            tls_extension.write()

    def test_write_with_data(self):
        tls_extension = TLSExtension().create(44, bytearray(b'garbage'))

        self.assertEqual(bytearray(
            b'\x00\x2c' +       # type of extension - 44
            b'\x00\x07' +       # length of extension - 7 bytes
            # utf-8 encoding of "garbage"
            b'\x67\x61\x72\x62\x61\x67\x65'
            ), tls_extension.write())

    def test_parse(self):
        p = Parser(bytearray(
            b'\x00\x42' + # type of extension
            b'\x00\x01' + # length of rest of data
            b'\xff'       # value of extension
            ))
        tls_extension = TLSExtension().parse(p)

        self.assertEqual(66, tls_extension.ext_type)
        self.assertEqual(bytearray(b'\xff'), tls_extension.ext_data)

    def test_parse_with_length_long_by_one(self):
        p = Parser(bytearray(
            b'\x00\x42' + # type of extension
            b'\x00\x03' + # length of rest of data
            b'\xff\xfa'   # value of extension
            ))

        with self.assertRaises(SyntaxError) as context:
            TLSExtension().parse(p)

    def test_parse_with_sni_ext(self):
        p = Parser(bytearray(
            b'\x00\x00' +   # type of extension - SNI (0)
            b'\x00\x10' +   # length of extension - 16 bytes
            b'\x00\x0e' +   # length of array
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        tls_extension = TLSExtension().parse(p)

        self.assertIsInstance(tls_extension, SNIExtension)

        self.assertEqual(bytearray(b'example.com'), tls_extension.host_names[0])

    def test_parse_with_SRP_ext(self):
        p = Parser(bytearray(
            b'\x00\x0c' +           # ext type - 12
            b'\x00\x09' +           # overall length
            b'\x08' +               # name length
            b'username'             # name
            ))

        ext = TLSExtension().parse(p)

        self.assertIsInstance(ext, SRPExtension)

        self.assertEqual(ext.identity, b'username')

    def test_parse_with_NPN_ext(self):
        p = Parser(bytearray(
            b'\x33\x74' +   # type of extension - NPN
            b'\x00\x09' +   # overall length
            b'\x08'     +   # first name length
            b'http/1.1'
            ))

        ext = TLSExtension().parse(p)

        self.assertIsInstance(ext, NPNExtension)

        self.assertEqual(ext.protocols, [b'http/1.1'])

    def test_parse_with_elliptic_curves(self):
        p = Parser(bytearray(
            b'\x00\x0a' +   # type of extension
            b'\x00\x08' +   # overall length
            b'\x00\x06' +   # length of array
            b'\x00\x17' +   # secp256r1
            b'\x00\x18' +   # secp384r1
            b'\x00\x19'     # secp521r1
            ))

        ext = TLSExtension().parse(p)

        # XXX not supported
        self.assertIsInstance(ext, TLSExtension)

        #self.assertEqual(ext.curves, [EllipticCurves.secp256r1,
        #                              EllipticCurves.secp384r1,
        #                              EllipticCurves.secp521r1])

    def test_parse_with_ec_point_formats(self):
        p = Parser(bytearray(
            b'\x00\x0b' +   # type of extension
            b'\x00\x02' +   # overall length
            b'\x01' +       # length of array
            b'\x00'         # type - uncompressed
            ))

        ext = TLSExtension().parse(p)

        # XXX unsupported
        self.assertIsInstance(ext, TLSExtension)

        #self.assertEqual(ext.formats, [PointFormats.uncompressed])

    def test_parse_with_signature_algorithms(self):
        p = Parser(bytearray(
            b'\x00\x0d' +   # type of extension
            b'\x00\x1c' +   # overall length
            b'\x00\x1a' +   # length of array
            b'\x04\x01' +   # SHA256+RSA
            b'\x04\x02' +   # SHA256+DSA
            b'\x04\x03' +   # SHA256+ECDSA
            b'\x05\x01' +   # SHA384+RSA
            b'\x05\x03' +   # SHA384+ECDSA
            b'\x06\x01' +   # SHA512+RSA
            b'\x06\x03' +   # SHA512+ECDSA
            b'\x03\x01' +   # SHA224+RSA
            b'\x03\x02' +   # SHA224+DSA
            b'\x03\x03' +   # SHA224+ECDSA
            b'\x02\x01' +   # SHA1+RSA
            b'\x02\x02' +   # SHA1+DSA
            b'\x02\x03'     # SHA1+ECDSA
            ))

        ext = TLSExtension().parse(p)

        # XXX unsupported
        self.assertIsInstance(ext, TLSExtension)

    def test_equality(self):
        a = TLSExtension().create(0, bytearray(0))
        b = SNIExtension().create()

        self.assertTrue(a == b)

    def test_equality_with_empty_array_in_sni_extension(self):
        a = TLSExtension().create(0, bytearray(b'\x00\x00'))
        b = SNIExtension().create(server_names=[])

        self.assertTrue(a == b)

    def test_equality_with_nearly_good_object(self):
        class TestClass(object):
            def __init__(self):
                self.ext_type = 0

        a = TLSExtension().create(0, bytearray(b'\x00\x00'))
        b = TestClass()

        self.assertFalse(a == b)

    def test_parse_of_server_hello_extension(self):
        ext = TLSExtension(server=True)

        p = Parser(bytearray(
            b'\x00\x09' +       # extension type - cert_type (9)
            b'\x00\x01' +       # extension length - 1 byte
            b'\x01'             # certificate type - OpenGPG (1)
            ))

        ext = ext.parse(p)

        self.assertIsInstance(ext, ServerCertTypeExtension)

        self.assertEqual(1, ext.cert_type)

    def test_parse_with_client_cert_type_extension(self):
        ext = TLSExtension()

        p = Parser(bytearray(
            b'\x00\x09' +        # ext type
            b'\x00\x02' +       # ext length
            b'\x01' +           # length of array
            b'\x01'))           # type - opengpg (1)

        ext = ext.parse(p)

        self.assertIsInstance(ext, ClientCertTypeExtension)

        self.assertEqual([1], ext.cert_types)

    def test___repr__(self):
        ext = TLSExtension()
        ext = ext.create(0, bytearray(b'\x00\x00'))

        self.assertEqual("TLSExtension(ext_type=0, "\
                "ext_data=bytearray(b'\\x00\\x00'), server_type=False)",
                repr(ext))

class TestSNIExtension(unittest.TestCase):
    def test___init__(self):
        server_name = SNIExtension()

        self.assertEqual(None, server_name.server_names)
        self.assertEqual(tuple(), server_name.host_names)
        # properties inherited from TLSExtension:
        self.assertEqual(0, server_name.ext_type)
        self.assertEqual(bytearray(0), server_name.ext_data)

    def test_create(self):
        server_name = SNIExtension()
        server_name = server_name.create()

        self.assertEqual(None, server_name.server_names)
        self.assertEqual(tuple(), server_name.host_names)

    def test_create_with_hostname(self):
        server_name = SNIExtension()
        server_name = server_name.create(bytearray(b'example.com'))

        self.assertEqual((bytearray(b'example.com'),), server_name.host_names)
        self.assertEqual([SNIExtension.ServerName(
            NameType.host_name,
            bytearray(b'example.com')
            )], server_name.server_names)

    def test_create_with_host_names(self):
        server_name = SNIExtension()
        server_name = server_name.create(host_names=[bytearray(b'example.com'),
            bytearray(b'www.example.com')])

        self.assertEqual((
            bytearray(b'example.com'),
            bytearray(b'www.example.com')
            ), server_name.host_names)
        self.assertEqual([
            SNIExtension.ServerName(
                NameType.host_name,
                bytearray(b'example.com')),
            SNIExtension.ServerName(
                NameType.host_name,
                bytearray(b'www.example.com'))],
            server_name.server_names)

    def test_create_with_server_names(self):
        server_name = SNIExtension()
        server_name = server_name.create(server_names=[
            SNIExtension.ServerName(1, bytearray(b'example.com')),
            SNIExtension.ServerName(4, bytearray(b'www.example.com')),
            SNIExtension.ServerName(0, bytearray(b'example.net'))])

        self.assertEqual((bytearray(b'example.net'),), server_name.host_names)
        self.assertEqual([
            SNIExtension.ServerName(
                1, bytearray(b'example.com')),
            SNIExtension.ServerName(
                4, bytearray(b'www.example.com')),
            SNIExtension.ServerName(
                0, bytearray(b'example.net'))],
            server_name.server_names)

    def test_host_names(self):
        server_name = SNIExtension()
        server_name = server_name.create(server_names=[
            SNIExtension.ServerName(0, bytearray(b'example.net')),
            SNIExtension.ServerName(1, bytearray(b'example.com')),
            SNIExtension.ServerName(4, bytearray(b'www.example.com'))
            ])

        server_name.host_names = \
                [bytearray(b'example.com')]

        self.assertEqual((bytearray(b'example.com'),), server_name.host_names)
        self.assertEqual([
            SNIExtension.ServerName(0, bytearray(b'example.com')),
            SNIExtension.ServerName(1, bytearray(b'example.com')),
            SNIExtension.ServerName(4, bytearray(b'www.example.com'))],
            server_name.server_names)

    def test_host_names_delete(self):
        server_name = SNIExtension()
        server_name = server_name.create(server_names=[
            SNIExtension.ServerName(0, bytearray(b'example.net')),
            SNIExtension.ServerName(1, bytearray(b'example.com')),
            SNIExtension.ServerName(4, bytearray(b'www.example.com'))
            ])

        del server_name.host_names

        self.assertEqual(tuple(), server_name.host_names)
        self.assertEqual([
            SNIExtension.ServerName(1, bytearray(b'example.com')),
            SNIExtension.ServerName(4, bytearray(b'www.example.com'))],
            server_name.server_names)

    def test_write(self):
        server_name = SNIExtension()
        server_name = server_name.create(bytearray(b'example.com'))

        self.assertEqual(bytearray(
            b'\x00\x0e' +   # length of array - 14 bytes
            b'\x00' +       # type of element - host_name (0)
            b'\x00\x0b' +   # length of element - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'
            ), server_name.ext_data)

        self.assertEqual(bytearray(
            b'\x00\x00' +   # type of extension - SNI (0)
            b'\x00\x10' +   # length of extension - 16 bytes
            b'\x00\x0e' +   # length of array - 14 bytes
            b'\x00' +       # type of element - host_name (0)
            b'\x00\x0b' +   # length of element - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'
            ), server_name.write())

    def test_write_with_multiple_hostnames(self):
        server_name = SNIExtension()
        server_name = server_name.create(host_names=[
            bytearray(b'example.com'),
            bytearray(b'example.org')])

        self.assertEqual(bytearray(
            b'\x00\x1c' +   # lenght of array - 28 bytes
            b'\x00' +       # type of element - host_name (0)
            b'\x00\x0b' +   # length of element - 11 bytes
            # utf-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d' +
            b'\x00' +       # type of elemnt - host_name (0)
            b'\x00\x0b' +   # length of elemnet - 11 bytes
            # utf-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67'
            ), server_name.ext_data)

        self.assertEqual(bytearray(
            b'\x00\x00' +   # type of extension - SNI (0)
            b'\x00\x1e' +   # length of extension - 26 bytes
            b'\x00\x1c' +   # lenght of array - 24 bytes
            b'\x00' +       # type of element - host_name (0)
            b'\x00\x0b' +   # length of element - 11 bytes
            # utf-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d' +
            b'\x00' +       # type of elemnt - host_name (0)
            b'\x00\x0b' +   # length of elemnet - 11 bytes
            # utf-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67'
            ), server_name.write())

    def test_write_of_empty_extension(self):
        server_name = SNIExtension()

        self.assertEqual(bytearray(
            b'\x00\x00' +   # type of extension - SNI (0)
            b'\x00\x00'     # length of extension - 0 bytes
            ), server_name.write())

    def test_write_of_empty_list_of_names(self):
        server_name = SNIExtension()
        server_name = server_name.create(server_names=[])

        self.assertEqual(bytearray(
            b'\x00\x00'    # length of array - 0 bytes
            ), server_name.ext_data)

        self.assertEqual(bytearray(
            b'\x00\x00' +  # type of extension - SNI 0
            b'\x00\x02' +  # length of extension - 2 bytes
            b'\x00\x00'    # length of array of names - 0 bytes
            ), server_name.write())

    def test_parse(self):
        server_name = SNIExtension()

        p = Parser(bytearray(0))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

    def test_parse_null_length_array(self):
        server_name = SNIExtension()

        p = Parser(bytearray(b'\x00\x00'))

        server_name = server_name.parse(p)

        self.assertEqual([], server_name.server_names)

    def test_parse_with_host_name(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x0e' +   # length of array
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        server_name = server_name.parse(p)

        self.assertEqual(bytearray(b'example.com'), server_name.host_names[0])
        self.assertEqual(tuple([bytearray(b'example.com')]),
                server_name.host_names)

    def test_parse_with_multiple_host_names(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x1c' +   # length of array - 28 bytes
            b'\x0a' +       # type of entry - unassigned (10)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67' +
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        server_name = server_name.parse(p)

        self.assertEqual(bytearray(b'example.com'), server_name.host_names[0])
        self.assertEqual(tuple([bytearray(b'example.com')]),
                server_name.host_names)

        SN = SNIExtension.ServerName

        self.assertEqual([
            SN(10, bytearray(b'example.org')),
            SN(0, bytearray(b'example.com'))
            ], server_name.server_names)

    def test_parse_with_array_length_long_by_one(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x0f' +   # length of array (one too long)
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

    def test_parse_with_array_length_short_by_one(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x0d' +   # length of array (one too short)
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

    def test_parse_with_name_length_long_by_one(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x1c' +   # length of array - 28 bytes
            b'\x0a' +       # type of entry - unassigned (10)
            b'\x00\x0c' +   # length of name - 12 bytes (long by one)
            # UTF-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67' +
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x1c' +   # length of array - 28 bytes
            b'\x0a' +       # type of entry - unassigned (10)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67' +
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0c' +   # length of name - 12 bytes (long by one)
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

    def test_parse_with_name_length_short_by_one(self):
        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x1c' +   # length of array - 28 bytes
            b'\x0a' +       # type of entry - unassigned (10)
            b'\x00\x0a' +   # length of name - 10 bytes (short by one)
            # UTF-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67' +
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

        server_name = SNIExtension()

        p = Parser(bytearray(
            b'\x00\x1c' +   # length of array - 28 bytes
            b'\x0a' +       # type of entry - unassigned (10)
            b'\x00\x0b' +   # length of name - 11 bytes
            # UTF-8 encoding of example.org
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67' +
            b'\x00' +       # type of entry - host_name (0)
            b'\x00\x0a' +   # length of name - 10 bytes (short by one)
            # UTF-8 encoding of example.com
            b'\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'))

        with self.assertRaises(SyntaxError):
            server_name = server_name.parse(p)

    def test___repr__(self):
        server_name = SNIExtension()
        server_name = server_name.create(
                server_names=[
                    SNIExtension.ServerName(0, bytearray(b'example.com')),
                    SNIExtension.ServerName(1, bytearray(b'\x04\x01'))])

        self.assertEqual("SNIExtension(server_names=["\
                "ServerName(name_type=0, name=bytearray(b'example.com')), "\
                "ServerName(name_type=1, name=bytearray(b'\\x04\\x01'))])",
                repr(server_name))

class TestClientCertTypeExtension(unittest.TestCase):
    def test___init___(self):
        cert_type = ClientCertTypeExtension()

        self.assertEqual(9, cert_type.ext_type)
        self.assertEqual(bytearray(0), cert_type.ext_data)
        self.assertEqual(None, cert_type.cert_types)

    def test_create(self):
        cert_type = ClientCertTypeExtension()
        cert_type = cert_type.create()

        self.assertEqual(9, cert_type.ext_type)
        self.assertEqual(bytearray(0), cert_type.ext_data)
        self.assertEqual(None, cert_type.cert_types)

    def test_create_with_empty_list(self):
        cert_type = ClientCertTypeExtension()
        cert_type = cert_type.create([])

        self.assertEqual(bytearray(b'\x00'), cert_type.ext_data)
        self.assertEqual([], cert_type.cert_types)

    def test_create_with_list(self):
        cert_type = ClientCertTypeExtension()
        cert_type = cert_type.create([0])

        self.assertEqual(bytearray(b'\x01\x00'), cert_type.ext_data)
        self.assertEqual([0], cert_type.cert_types)

    def test_write(self):
        cert_type = ClientCertTypeExtension()
        cert_type = cert_type.create([0, 1])

        self.assertEqual(bytearray(
            b'\x00\x09' +
            b'\x00\x03' +
            b'\x02' +
            b'\x00\x01'), cert_type.write())

    def test_parse(self):
        cert_type = ClientCertTypeExtension()

        p = Parser(bytearray(b'\x00'))

        cert_type = cert_type.parse(p)

        self.assertEqual(9, cert_type.ext_type)
        self.assertEqual([], cert_type.cert_types)

    def test_parse_with_list(self):
        cert_type = ClientCertTypeExtension()

        p = Parser(bytearray(b'\x02\x01\x00'))

        cert_type = cert_type.parse(p)

        self.assertEqual([1, 0], cert_type.cert_types)

    def test_parse_with_length_long_by_one(self):
        cert_type = ClientCertTypeExtension()

        p = Parser(bytearray(b'\x03\x01\x00'))

        with self.assertRaises(SyntaxError):
            cert_type.parse(p)

    def test___repr__(self):
        cert_type = ClientCertTypeExtension()
        cert_type = cert_type.create([0, 1])

        self.assertEqual("ClientCertTypeExtension(cert_types=[0, 1])",
                repr(cert_type))

class TestServerCertTypeExtension(unittest.TestCase):
    def test___init__(self):
        cert_type = ServerCertTypeExtension()

        self.assertEqual(9, cert_type.ext_type)
        self.assertEqual(bytearray(0), cert_type.ext_data)
        self.assertEqual(None, cert_type.cert_type)

    def test_create(self):
        cert_type = ServerCertTypeExtension().create(0)

        self.assertEqual(9, cert_type.ext_type)
        self.assertEqual(bytearray(b'\x00'), cert_type.ext_data)
        self.assertEqual(0, cert_type.cert_type)

    def test_parse(self):
        p = Parser(bytearray(
            b'\x00'             # certificate type - X.509 (0)
            ))

        cert_type = ServerCertTypeExtension().parse(p)

        self.assertEqual(0, cert_type.cert_type)

    def test_parse_with_no_data(self):
        p = Parser(bytearray(0))

        cert_type = ServerCertTypeExtension()

        with self.assertRaises(SyntaxError):
            cert_type.parse(p)

    def test_parse_with_too_much_data(self):
        p = Parser(bytearray(b'\x00\x00'))

        cert_type = ServerCertTypeExtension()

        with self.assertRaises(SyntaxError):
            cert_type.parse(p)

    def test_write(self):
        cert_type = ServerCertTypeExtension().create(1)

        self.assertEqual(bytearray(
            b'\x00\x09' +       # extension type - cert_type (9)
            b'\x00\x01' +       # extension length - 1 byte
            b'\x01'             # selected certificate type - OpenPGP (1)
            ), cert_type.write())

    def test___repr__(self):
        cert_type = ServerCertTypeExtension().create(1)

        self.assertEqual("ServerCertTypeExtension(cert_type=1)",
                repr(cert_type))

class TestSRPExtension(unittest.TestCase):
    def test___init___(self):
        srp_extension = SRPExtension()

        self.assertEqual(None, srp_extension.identity)
        self.assertEqual(12, srp_extension.ext_type)
        self.assertEqual(bytearray(0), srp_extension.ext_data)

    def test_create(self):
        srp_extension = SRPExtension()
        srp_extension = srp_extension.create()

        self.assertEqual(None, srp_extension.identity)
        self.assertEqual(12, srp_extension.ext_type)
        self.assertEqual(bytearray(0), srp_extension.ext_data)

    def test_create_with_name(self):
        srp_extension = SRPExtension()
        srp_extension = srp_extension.create(bytearray(b'username'))

        self.assertEqual(bytearray(b'username'), srp_extension.identity)
        self.assertEqual(bytearray(
            b'\x08' + # length of string - 8 bytes
            b'username'), srp_extension.ext_data)

    def test_create_with_too_long_name(self):
        srp_extension = SRPExtension()

        with self.assertRaises(ValueError):
            srp_extension = srp_extension.create(bytearray(b'a'*256))

    def test_write(self):
        srp_extension = SRPExtension()
        srp_extension = srp_extension.create(bytearray(b'username'))

        self.assertEqual(bytearray(
            b'\x00\x0c' +   # type of extension - SRP (12)
            b'\x00\x09' +   # length of extension - 9 bytes
            b'\x08' +       # length of encoded name
            b'username'), srp_extension.write())

    def test_parse(self):
        srp_extension = SRPExtension()
        p = Parser(bytearray(b'\x00'))

        srp_extension = srp_extension.parse(p)

        self.assertEqual(bytearray(0), srp_extension.identity)

    def test_parse(self):
        srp_extension = SRPExtension()
        p = Parser(bytearray(
            b'\x08' +
            b'username'))

        srp_extension = srp_extension.parse(p)

        self.assertEqual(bytearray(b'username'),
                srp_extension.identity)

    def test_parse_with_length_long_by_one(self):
        srp_extension = SRPExtension()
        p = Parser(bytearray(
            b'\x09' +
            b'username'))

        with self.assertRaises(SyntaxError):
            srp_extension = srp_extension.parse(p)

    def test___repr__(self):
        srp_extension = SRPExtension()
        srp_extension = srp_extension.create(bytearray(b'user'))

        self.assertEqual("SRPExtension(identity=bytearray(b'user'))",
                repr(srp_extension))

class TestNPNExtension(unittest.TestCase):
    def test___init___(self):
        npn_extension = NPNExtension()

        self.assertEqual(None, npn_extension.protocols)
        self.assertEqual(13172, npn_extension.ext_type)
        self.assertEqual(bytearray(0), npn_extension.ext_data)

    def test_create(self):
        npn_extension = NPNExtension()
        npn_extension = npn_extension.create()

        self.assertEqual(None, npn_extension.protocols)
        self.assertEqual(13172, npn_extension.ext_type)
        self.assertEqual(bytearray(0), npn_extension.ext_data)

    def test_create_with_list_of_protocols(self):
        npn_extension = NPNExtension()
        npn_extension = npn_extension.create([
            bytearray(b'http/1.1'),
            bytearray(b'spdy/3')])

        self.assertEqual([
            bytearray(b'http/1.1'),
            bytearray(b'spdy/3')], npn_extension.protocols)
        self.assertEqual(bytearray(
            b'\x08' +   # length of name of protocol
            # utf-8 encoding of "http/1.1"
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31' +
            b'\x06' +   # length of name of protocol
            # utf-8 encoding of "http/1.1"
            b'\x73\x70\x64\x79\x2f\x33'
            ), npn_extension.ext_data)

    def test_write(self):
        npn_extension = NPNExtension().create()

        self.assertEqual(bytearray(
            b'\x33\x74' +   # type of extension - NPN
            b'\x00\x00'     # length of extension
            ), npn_extension.write())

    def test_write_with_list(self):
        npn_extension = NPNExtension()
        npn_extensnio = npn_extension.create([
            bytearray(b'http/1.1'),
            bytearray(b'spdy/3')])

        self.assertEqual(bytearray(
            b'\x33\x74' +   # type of extension - NPN
            b'\x00\x10' +   # length of extension
            b'\x08' +       # length of name of protocol
            # utf-8 encoding of "http/1.1"
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31' +
            b'\x06' +       # length of name of protocol
            # utf-8 encoding of "spdy/3"
            b'\x73\x70\x64\x79\x2f\x33'
            ), npn_extension.write())

    def test_parse(self):
        npn_extension = NPNExtension()

        p = Parser(bytearray(0))

        npn_extension = npn_extension.parse(p)

        self.assertEqual(bytearray(0), npn_extension.ext_data)
        self.assertEqual([], npn_extension.protocols)

    def test_parse_with_procotol(self):
        npn_extension = NPNExtension()

        p = Parser(bytearray(
            b'\x08' +   # length of name
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31'))

        npn_extension = npn_extension.parse(p)

        self.assertEqual([bytearray(b'http/1.1')], npn_extension.protocols)

    def test_parse_with_protocol_length_short_by_one(self):
        npn_extension = NPNExtension()

        p = Parser(bytearray(
            b'\x07' +   # length of name - 7 (short by one)
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31'))

        with self.assertRaises(SyntaxError):
            npn_extension.parse(p)

    def test_parse_with_protocol_length_long_by_one(self):
        npn_extension = NPNExtension()

        p = Parser(bytearray(
            b'\x09' +   # length of name - 9 (short by one)
            b'\x68\x74\x74\x70\x2f\x31\x2e\x31'))

        with self.assertRaises(SyntaxError):
            npn_extension.parse(p)

    def test___repr__(self):
        npn_extension = NPNExtension().create([bytearray(b'http/1.1')])

        self.assertEqual("NPNExtension(protocols=[bytearray(b'http/1.1')])",
                repr(npn_extension))

class TestTACKExtension(unittest.TestCase):
    def test___init__(self):
        tack_ext = TACKExtension()

        self.assertEqual([], tack_ext.tacks)
        self.assertEqual(0, tack_ext.activation_flags)
        self.assertEqual(62208, tack_ext.ext_type)
        self.assertEqual(bytearray(b'\x00\x00\x00'), tack_ext.ext_data)

    def test_create(self):
        tack_ext = TACKExtension().create([], 1)

        self.assertEqual([], tack_ext.tacks)
        self.assertEqual(1, tack_ext.activation_flags)

    def test_tack___init__(self):
        tack = TACKExtension.TACK()

        self.assertEqual(bytearray(64), tack.public_key)
        self.assertEqual(0, tack.min_generation)
        self.assertEqual(0, tack.generation)
        self.assertEqual(0, tack.expiration)
        self.assertEqual(bytearray(32), tack.target_hash)
        self.assertEqual(bytearray(64), tack.signature)

    def test_tack_create(self):
        tack = TACKExtension.TACK().create(
                bytearray(b'\x01'*64),
                2,
                3,
                4,
                bytearray(b'\x05'*32),
                bytearray(b'\x06'*64))

        self.assertEqual(bytearray(b'\x01'*64), tack.public_key)
        self.assertEqual(2, tack.min_generation)
        self.assertEqual(3, tack.generation)
        self.assertEqual(4, tack.expiration)
        self.assertEqual(bytearray(b'\x05'*32), tack.target_hash)
        self.assertEqual(bytearray(b'\x06'*64), tack.signature)

    def test_tack_write(self):
        tack = TACKExtension.TACK().create(
                bytearray(b'\x01'*64),
                2,
                3,
                4,
                bytearray(b'\x05'*32),
                bytearray(b'\x06'*64))

        self.assertEqual(bytearray(
            b'\x01'*64 +            # public_key
            b'\x02' +               # min_generation
            b'\x03' +               # generation
            b'\x00\x00\x00\x04' +   # expiration
            b'\x05'*32 +            # target_hash
            b'\x06'*64)             # signature
            , tack.write())

    def test_tack_write_with_bad_length_public_key(self):
        tack = TACKExtension.TACK().create(
                bytearray(b'\x01'*65),
                2,
                3,
                4,
                bytearray(b'\x05'*32),
                bytearray(b'\x06'*64))

        with self.assertRaises(TLSInternalError):
            tack.write()

    def test_tack_write_with_bad_length_target_hash(self):
        tack = TACKExtension.TACK().create(
                bytearray(b'\x01'*64),
                2,
                3,
                4,
                bytearray(b'\x05'*33),
                bytearray(b'\x06'*64))

        with self.assertRaises(TLSInternalError):
            tack.write()

    def test_tack_write_with_bad_length_signature(self):
        tack = TACKExtension.TACK().create(
                bytearray(b'\x01'*64),
                2,
                3,
                4,
                bytearray(b'\x05'*32),
                bytearray(b'\x06'*65))

        with self.assertRaises(TLSInternalError):
            tack.write()

    def test_tack_parse(self):
        p = Parser(bytearray(
            b'\x01'*64 +            # public_key
            b'\x02' +               # min_generation
            b'\x03' +               # generation
            b'\x00\x00\x00\x04' +   # expiration
            b'\x05'*32 +            # target_hash
            b'\x06'*64))            # signature

        tack = TACKExtension.TACK()

        tack = tack.parse(p)

        self.assertEqual(bytearray(b'\x01'*64), tack.public_key)
        self.assertEqual(2, tack.min_generation)
        self.assertEqual(3, tack.generation)
        self.assertEqual(4, tack.expiration)
        self.assertEqual(bytearray(b'\x05'*32), tack.target_hash)
        self.assertEqual(bytearray(b'\x06'*64), tack.signature)

    def test_tack___eq__(self):
        a = TACKExtension.TACK()
        b = TACKExtension.TACK()

        self.assertTrue(a == b)
        self.assertFalse(a == None)
        self.assertFalse(a == "test")

    def test_tack___eq___with_different_tacks(self):
        a = TACKExtension.TACK()
        b = TACKExtension.TACK().create(
                bytearray(b'\x01'*64),
                2,
                3,
                4,
                bytearray(b'\x05'*32),
                bytearray(b'\x06'*64))

        self.assertFalse(a == b)

    def test_ext_data(self):
        tack = TACKExtension.TACK().create(
                bytearray(b'\x01'*64),
                2,
                3,
                4,
                bytearray(b'\x05'*32),
                bytearray(b'\x06'*64))

        tack_ext = TACKExtension().create([tack], 1)

        self.assertEqual(bytearray(
            b'\x00\xa6' +           # length
            b'\x01'*64 +            # public_key
            b'\x02' +               # min_generation
            b'\x03' +               # generation
            b'\x00\x00\x00\x04' +   # expiration
            b'\x05'*32 +            # target_hash
            b'\x06'*64 +            # signature
            b'\x01'                 # activation flag
            ), tack_ext.ext_data)

    def test_parse(self):
        p = Parser(bytearray(3))

        tack_ext = TACKExtension().parse(p)

        self.assertEqual([], tack_ext.tacks)
        self.assertEqual(0, tack_ext.activation_flags)

    def test_parse_with_a_tack(self):
        p = Parser(bytearray(
            b'\x00\xa6' +           # length of array (166 bytes)
            b'\x01'*64 +            # public_key
            b'\x02' +               # min_generation
            b'\x03' +               # generation
            b'\x00\x00\x00\x04' +   # expiration
            b'\x05'*32 +            # target_hash
            b'\x06'*64 +            # signature
            b'\x01'))               # activation_flags

        tack_ext = TACKExtension().parse(p)

        tack = TACKExtension.TACK().create(
                bytearray(b'\x01'*64),
                2,
                3,
                4,
                bytearray(b'\x05'*32),
                bytearray(b'\x06'*64))
        self.assertEqual([tack], tack_ext.tacks)
        self.assertEqual(1, tack_ext.activation_flags)

    def test___repr__(self):
        tack = TACKExtension.TACK().create(
                bytearray(b'\x00'),
                1,
                2,
                3,
                bytearray(b'\x04'),
                bytearray(b'\x05'))
        tack_ext = TACKExtension().create([tack], 1)
        self.maxDiff = None
        self.assertEqual("TACKExtension(activation_flags=1, tacks=["\
                "TACK(public_key=bytearray(b'\\x00'), min_generation=1, "\
                "generation=2, expiration=3, target_hash=bytearray(b'\\x04'), "\
                "signature=bytearray(b'\\x05'))"\
                "])",
                repr(tack_ext))

if __name__ == '__main__':
    unittest.main()
