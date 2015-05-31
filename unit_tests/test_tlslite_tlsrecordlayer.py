# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
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

import socket
import errno
from tlslite.tlsrecordlayer import TLSRecordLayer
from tlslite.constants import ContentType
from tlslite.errors import TLSAbruptCloseError, TLSLocalAlert
from tlslite.messages import Message
from unit_tests.mocksock import MockSocket

class TestTLSRecordLayer(unittest.TestCase):
    def test___init__(self):
        record_layer = TLSRecordLayer(None)

        self.assertIsNotNone(record_layer)
        self.assertIsInstance(record_layer, TLSRecordLayer)

    def test__getNextRecord(self):
        mockSock = MockSocket(bytearray(
            b'\x16' +           # type - handshake
            b'\x03\x03' +       # TLSv1.2
            b'\x00\x04' +       # length
            b'\x00'*4
            ))
        sock = TLSRecordLayer(mockSock)

        # XXX using private method!
        for result in sock._getNextRecord():
            if result in (0, 1):
                self.assertTrue(False, "blocking socket")
            else: break

        header, data = result
        data = data.bytes

        self.assertEqual(data, bytearray(4))
        self.assertEqual(header.type, ContentType.handshake)
        self.assertEqual(header.version, (3, 3))
        self.assertEqual(header.length, 4)

    def test__getNextRecord_stops_itelf(self):
        mockSock = MockSocket(bytearray(
            b'\x16' +           # type - handshake
            b'\x03\x03' +       # TLSv1.2
            b'\x00\x04' +       # length
            b'\x00'*4
            ))
        sock = TLSRecordLayer(mockSock)

        # XXX using private method!
        for result in sock._getNextRecord():
            if result in (0, 1):
                self.assertTrue(False, "blocking socket")

        header, data = result
        data = data.bytes

        self.assertEqual(data, bytearray(4))
        self.assertEqual(header.type, ContentType.handshake)
        self.assertEqual(header.version, (3, 3))
        self.assertEqual(header.length, 4)

    def test__getNextRecord_with_trickling_socket(self):
        mockSock = MockSocket(bytearray(
            b'\x16' +           # type - handshake
            b'\x03\x03' +       # TLSv1.2
            b'\x00\x04' +       # length
            b'\x00'*4
            ), maxRet=1)

        sock = TLSRecordLayer(mockSock)

        # XXX using private method!
        for result in sock._getNextRecord():
            if result in (0, 1):
                self.assertTrue(False, "blocking socket")
            else: break

        header, data = result
        data = data.bytes

        self.assertEqual(bytearray(4), data)

    def test__getNextRecord_with_blocking_socket(self):
        mockSock = mock.MagicMock()
        mockSock.recv.side_effect = socket.error(errno.EWOULDBLOCK)

        sock = TLSRecordLayer(mockSock)

        # XXX using private method!
        gen = sock._getNextRecord()

        self.assertEqual(0, next(gen))

    def test__getNextRecord_with_errored_out_socket(self):
        mockSock = mock.MagicMock()
        mockSock.recv.side_effect = socket.error(errno.ETIMEDOUT)

        sock = TLSRecordLayer(mockSock)

        # XXX using private method!
        gen = sock._getNextRecord()

        with self.assertRaises(socket.error):
            next(gen)

    def test__getNextRecord_with_empty_socket(self):
        mockSock = mock.MagicMock()
        mockSock.recv.side_effect = [bytearray(0)]

        sock = TLSRecordLayer(mockSock)

        # XXX using private method!
        gen = sock._getNextRecord()

        with self.assertRaises(TLSAbruptCloseError):
            next(gen)

    def test__getNextRecord_with_slow_socket(self):
        mockSock = MockSocket(bytearray(
            b'\x16' +           # type - handshake
            b'\x03\x03' +       # TLSv1.2
            b'\x00\x04' +       # length
            b'\x00'*4
            ), maxRet=1, blockEveryOther=True)

        sock = TLSRecordLayer(mockSock)

        gotRetry = False
        # XXX using private method!
        for result in sock._getNextRecord():
            if result in (0, 1):
                gotRetry = True
            else: break

        header, data = result
        data = data.bytes

        self.assertTrue(gotRetry)
        self.assertEqual(bytearray(4), data)

    def test__getNextRecord_with_malformed_record(self):
        mockSock = MockSocket(bytearray(
            b'\x01' +           # wrong type
            b'\x03\x03' +       # TLSv1.2
            b'\x00\x01' +       # length
            b'\x00'))

        sock = TLSRecordLayer(mockSock)

        # XXX using private method!
        gen = sock._getNextRecord()

        with self.assertRaises(TLSLocalAlert) as context:
            next(gen)

        self.assertEqual(str(context.exception), "illegal_parameter")

    def test__getNextRecord_with_too_big_record(self):
        mockSock = MockSocket(bytearray(
            b'\x16' +           # type - handshake
            b'\x03\x03' +       # TLSv1.2
            b'\xff\xff' +       # length
            b'\x00'*65536))

        sock = TLSRecordLayer(mockSock)

        # XXX using private method!
        gen = sock._getNextRecord()

        with self.assertRaises(TLSLocalAlert) as context:
            next(gen)

        self.assertEqual(str(context.exception), "record_overflow")

    def test__getNextRecord_with_SSL2_record(self):
        mockSock = MockSocket(bytearray(
            b'\x80' +           # tag
            b'\x04' +           # length
            b'\x00'*4))

        sock = TLSRecordLayer(mockSock)

        # XXX using private method!
        for result in sock._getNextRecord():
            if result in (0, 1):
                self.assertTrue(False, "blocking socket")
            else: break

        header, data = result
        data = data.bytes

        self.assertTrue(header.ssl2)
        self.assertEqual(ContentType.handshake, header.type)
        self.assertEqual(4, header.length)
        self.assertEqual((2, 0), header.version)

        self.assertEqual(bytearray(4), data)

    def test__getNextRecord_with_not_complete_SSL2_record(self):
        mockSock = MockSocket(bytearray(
            b'\x80' +           # tag
            b'\x04' +           # length
            b'\x00'*3))

        sock = TLSRecordLayer(mockSock)

        # XXX using private method!
        for result in sock._getNextRecord():
            break

        self.assertEqual(0, result)

    def test__getNextRecord_with_SSL2_record_with_incomplete_header(self):
        mockSock = MockSocket(bytearray(
            b'\x80'             # tag
            ))

        sock = TLSRecordLayer(mockSock)

        # XXX using private method
        for result in sock._getNextRecord():
            break

        self.assertEqual(0, result)

    def test__sendMsg(self):
        mockSock = MockSocket(bytearray(0))
        sock = TLSRecordLayer(mockSock)
        sock.version = (3, 3)

        msg = Message(ContentType.handshake, bytearray(10))

        # XXX using private method
        for result in sock._sendMsg(msg, False):
            if result in (0, 1):
                self.assertTrue(False, "Blocking socket")
            else: break

        self.assertEqual(len(mockSock.sent), 1)
        self.assertEqual(bytearray(
            b'\x16' +           # handshake message
            b'\x03\x03' +       # version
            b'\x00\x0a' +       # payload length
            b'\x00'*10          # payload
            ), mockSock.sent[0])

    def test__sendMsg_with_very_slow_socket(self):
        mockSock = MockSocket(bytearray(0), maxWrite=1, blockEveryOther=True)
        sock = TLSRecordLayer(mockSock)

        msg = Message(ContentType.handshake, bytearray(b'\x32'*2))

        gotRetry = False
        # XXX using private method!
        for result in sock._sendMsg(msg, False):
            if result in (0, 1):
                gotRetry = True
            else: break

        self.assertTrue(gotRetry)
        self.assertEqual([
            bytearray(b'\x16'),  # handshake message
            bytearray(b'\x00'), bytearray(b'\x00'), # version (unset)
            bytearray(b'\x00'), bytearray(b'\x02'), # payload length
            bytearray(b'\x32'), bytearray(b'\x32')],
            mockSock.sent)

    def test__sendMsg_with_errored_out_socket(self):
        mockSock = mock.MagicMock()
        mockSock.send.side_effect = socket.error(errno.ETIMEDOUT)

        sock = TLSRecordLayer(mockSock)

        msg = Message(ContentType.handshake, bytearray(10))

        gen = sock._sendMsg(msg, False)

        with self.assertRaises(TLSAbruptCloseError):
            next(gen)
