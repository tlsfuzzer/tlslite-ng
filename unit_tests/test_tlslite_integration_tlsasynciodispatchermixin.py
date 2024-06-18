# Author: Esteban Sanchez (FosanzDev)

import sys

# This test case is skipped because it uses asyncio,
# which is not available in Python 2- asyncio is used
# in the implementation of TLSAsyncioDispatcherMixIn
try:
    from tlslite.integration.tlsasynciodispatchermixin \
        import TLSAsyncioDispatcherMixIn
    import asyncio
except ImportError:
    pass

try:
   import unittest2 as unittest
except ImportError:
   import unittest

try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock

PY_VER = sys.version_info


@unittest.skipIf(PY_VER < (3,),
                 "asyncio is not available in Python 2")
class TestTLSAsyncioDispatcherMixIn(unittest.TestCase):
    if PY_VER >= (3,):
        class MockProtocol(asyncio.Protocol):
            def connection_lost(self, exc):
                self.in_write_event()

            def in_write_event(self):
                pass

            def readable(self):
                return True

            def writable(self):
                return True

    def setUp(self):
        self.protocol = TLSAsyncioDispatcherMixIn()
        self.protocol.__class__ = type('TestProtocol',
                                       (self.MockProtocol,
                                        TLSAsyncioDispatcherMixIn), {})
        self.protocol.transport = Mock()
        self.protocol.tls_connection = Mock()

    def test_readable(self):
        self.protocol.wants_read_event = Mock(return_value=None)
        self.protocol._get_sibling_class = Mock(return_value=
                                                Mock(readable=
                                                     Mock(return_value=True)))
        self.assertTrue(self.protocol.readable())

    def test_writable(self):
        self.protocol.wants_write_event = Mock(return_value=None)
        self.protocol._get_sibling_class = Mock(return_value=
                                                Mock(writable=
                                                     Mock(return_value=True)))
        self.assertTrue(self.protocol.writable())

    def test_data_received(self):
        self.protocol.transport = Mock()
        self.protocol.sibling_class.data_received = Mock()
        self.protocol.data_received(b'test')
        self.protocol.sibling_class.data_received.assert_called_once_with(
            self.protocol, b'test'
        )

    def test_connection_lost(self):
        self.protocol.in_write_event = Mock()
        self.protocol.connection_lost(None)
        self.protocol.in_write_event.assert_called_once()

    def test_connection_made(self):
        self.protocol.transport = Mock()
        self.protocol.sibling_class.connection_made = Mock()
        self.protocol.connection_made(self.protocol.transport)
        self.protocol.sibling_class.connection_made.assert_called_once_with(
            self.protocol.transport
        )

    def test_out_close_event(self):
        self.protocol.out_close_event()
        self.protocol.transport.close.assert_called_once()

    def test_recv(self):
        self.protocol.read_buffer = b"test"
        self.assertEqual(self.protocol.recv(), b"test")
        self.assertIsNone(self.protocol.read_buffer)

    def test_send(self):
        write_buffer = b"test"
        self.protocol.set_write_op = Mock()
        self.assertEqual(self.protocol.send(write_buffer), len(write_buffer))
        self.protocol.set_write_op.assert_called_once_with(write_buffer)

    def test_close(self):
        self.protocol.set_close_op = Mock()
        self.protocol.close()
        self.protocol.set_close_op.assert_called_once()
