# Authors: 
#   Trevor Perrin
#   Google (adapted by Sam Rushing) - NPN support
#   Google - minimal padding
#   Martin von Loewis - python 3 port
#   Yngve Pettersen (ported by Paul Sokolovsky) - TLS 1.2
#   Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

"""Helper class for TLSConnection."""
from __future__ import generators

import io
import time
import socket

from .utils.compat import *
from .utils.cryptomath import *
from .utils.codec import Parser
from .utils.lists import to_str_delimiter
from .errors import *
from .messages import *
from .mathtls import *
from .constants import *
from .recordlayer import RecordLayer
from .defragmenter import Defragmenter
from .handshakehashes import HandshakeHashes
from .bufferedsocket import BufferedSocket

class TLSRecordLayer(object):
    """
    This class handles data transmission for a TLS connection.

    Its only subclass is :py:class:`~tlslite.tlsconnection.TLSConnection`.
    We've
    separated the code in this class from TLSConnection to make things
    more readable.


    :vartype sock: socket.socket
    :ivar sock: The underlying socket object.

    :vartype session: ~tlslite.Session.Session
    :ivar session: The session corresponding to this connection.
        Due to TLS session resumption, multiple connections can correspond
        to the same underlying session.

    :vartype version: tuple
    :ivar version: The TLS version being used for this connection.
        (3,0) means SSL 3.0, and (3,1) means TLS 1.0.

    :vartype closed: bool
    :ivar closed: If this connection is closed.

    :vartype resumed: bool
    :ivar resumed: If this connection is based on a resumed session.

    :vartype allegedSrpUsername: str or None
    :ivar allegedSrpUsername:  This is set to the SRP username
        asserted by the client, whether the handshake succeeded or not.
        If the handshake fails, this can be inspected to determine
        if a guessing attack is in progress against a particular user
        account.

    :vartype closeSocket: bool
    :ivar closeSocket: If the socket should be closed when the
        connection is closed, defaults to True (writable).

        If you set this to True, TLS Lite will assume the responsibility of
        closing the socket when the TLS Connection is shutdown (either
        through an error or through the user calling close()).  The default
        is False.

    :vartype ignoreAbruptClose: bool
    :ivar ignoreAbruptClose: If an abrupt close of the socket should
        raise an error (writable).

        If you set this to True, TLS Lite will not raise a
        :py:class:`~tlslite.errors.TLSAbruptCloseError` exception if the
        underlying
        socket is unexpectedly closed.  Such an unexpected closure could be
        caused by an attacker.  However, it also occurs with some incorrect
        TLS implementations.

        You should set this to True only if you're not worried about an
        attacker truncating the connection, and only if necessary to avoid
        spurious errors.  The default is False.

    :vartype encryptThenMAC: bool
    :ivar encryptThenMAC: Whether the connection uses the encrypt-then-MAC
        construct for CBC cipher suites, will be False also if connection uses
        RC4 or AEAD.

    :vartype recordSize: int
    :ivar recordSize: maimum size of data to be sent in a single record layer
        message. Note that after encryption is established (generally after
        handshake protocol has finished) the actual amount of data written to
        network socket will be larger because of the record layer header,
        padding
        or encryption overhead. It can be set to low value (so that there is no
        fragmentation on Ethernet, IP and TCP level) at the beginning of
        connection to reduce latency and set to protocol max (2**14) to
        maximise
        throughput after sending few kiB of data. Setting to values greater
        than
        2**14 will cause the connection to be dropped by RFC compliant peers.

    :vartype tickets: list of bytearray
    :ivar tickets: list of session tickets received from server, oldest first.
    """

    def __init__(self, sock):
        sock = BufferedSocket(sock)
        self.sock = sock
        self._recordLayer = RecordLayer(sock)

        #My session object (Session instance; read-only)
        self.session = None

        #Buffers for processing messages
        self._defragmenter = Defragmenter()
        self._defragmenter.add_static_size(ContentType.change_cipher_spec, 1)
        self._defragmenter.add_static_size(ContentType.alert, 2)
        self._defragmenter.add_dynamic_size(ContentType.handshake, 1, 3)
        self.clearReadBuffer()
        self.clearWriteBuffer()

        #Handshake digests
        self._handshake_hash = HandshakeHashes()
        # Handshake digest used for Certificate Verify signature and
        # also for EMS calculation, in practice, it excludes
        # CertificateVerify and all following messages (Finished)
        self._certificate_verify_handshake_hash = None
        # for PSK binders we need to be able to calculate the hash of all
        # echanged messages and a _truncated_ ClientHello message so we
        # need a copy of those hashes before CH was received
        self._pre_client_hello_handshake_hash = None

        #Is the connection open?
        self.closed = True #read-only
        self._refCount = 0 #Used to trigger closure

        #Is this a resumed session?
        self.resumed = False #read-only

        #What username did the client claim in his handshake?
        self.allegedSrpUsername = None

        #On a call to close(), do we close the socket? (writeable)
        self.closeSocket = True

        #If the socket is abruptly closed, do we ignore it
        #and pretend the connection was shut down properly? (writeable)
        self.ignoreAbruptClose = False

        #Fault we will induce, for testing purposes
        self.fault = None

        #Limit the size of outgoing records to following size
        self.recordSize = 16384 # 2**14

        # NewSessionTickets received from server
        self.tickets = []

    @property
    def _client(self):
        """Boolean stating if the endpoint acts as a client"""
        return self._recordLayer.client

    @_client.setter
    def _client(self, value):
        """Set the endpoint to act as a client or not"""
        self._recordLayer.client = value

    @property
    def version(self):
        """Get the SSL protocol version of connection"""
        return self._recordLayer.version

    @version.setter
    def version(self, value):
        """
        Set the SSL protocol version of connection

        The setter is a public method only for backwards compatibility.
        Don't use it! See at HandshakeSettings for options to set desired
        protocol version.
        """
        self._recordLayer.version = value
        if value > (3, 3):
            self._recordLayer.tls13record = True

    @property
    def encryptThenMAC(self):
        """Whether the connection uses Encrypt Then MAC (RFC 7366)"""
        return self._recordLayer.encryptThenMAC

    def clearReadBuffer(self):
        self._readBuffer = b''

    def clearWriteBuffer(self):
        self._send_writer = None


    #*********************************************************
    # Public Functions START
    #*********************************************************

    def read(self, max=None, min=1):
        """Read some data from the TLS connection.

        This function will block until at least 'min' bytes are
        available (or the connection is closed).

        If an exception is raised, the connection will have been
        automatically closed.

        :type max: int
        :param max: The maximum number of bytes to return.

        :type min: int
        :param min: The minimum number of bytes to return

        :rtype: str
        :returns: A string of no more than 'max' bytes, and no fewer
            than 'min' (unless the connection has been closed, in which
            case fewer than 'min' bytes may be returned).

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        for result in self.readAsync(max, min):
            pass
        return result

    def readAsync(self, max=None, min=1):
        """Start a read operation on the TLS connection.

        This function returns a generator which behaves similarly to
        read().  Successive invocations of the generator will return 0
        if it is waiting to read from the socket, 1 if it is waiting
        to write to the socket, or a string if the read operation has
        completed.

        :rtype: iterable
        :returns: A generator; see above for details.
        """
        if self.version > (3, 3):
            allowedTypes = (ContentType.application_data,
                            ContentType.handshake)
            allowedHsTypes = HandshakeType.new_session_ticket
        else:
            allowedTypes = ContentType.application_data
            allowedHsTypes = None
        try:
            while len(self._readBuffer) < min and not self.closed:
                try:
                    for result in self._getMsg(allowedTypes,
                                               allowedHsTypes):
                        if result in (0, 1):
                            yield result
                    if isinstance(result, NewSessionTicket):
                        result.time = time.time()
                        self.tickets.append(result)
                        continue
                    applicationData = result
                    self._readBuffer += applicationData.write()
                except TLSRemoteAlert as alert:
                    if alert.description != AlertDescription.close_notify:
                        raise
                except TLSAbruptCloseError:
                    if not self.ignoreAbruptClose:
                        raise
                    else:
                        self._shutdown(True)

            if max == None:
                max = len(self._readBuffer)

            returnBytes = self._readBuffer[:max]
            self._readBuffer = self._readBuffer[max:]
            yield bytes(returnBytes)
        except GeneratorExit:
            raise
        except:
            self._shutdown(False)
            raise

    def unread(self, b):
        """Add bytes to the front of the socket read buffer for future
        reading. Be careful using this in the context of select(...): if you
        unread the last data from a socket, that won't wake up selected waiters,
        and those waiters may hang forever.
        """
        self._readBuffer = b + self._readBuffer

    def write(self, s):
        """Write some data to the TLS connection.

        This function will block until all the data has been sent.

        If an exception is raised, the connection will have been
        automatically closed.

        :type s: str
        :param s: The data to transmit to the other party.

        :raises socket.error: If a socket error occurs.
        """
        for result in self.writeAsync(s):
            pass

    def writeAsync(self, s):
        """Start a write operation on the TLS connection.

        This function returns a generator which behaves similarly to
        write().  Successive invocations of the generator will return
        1 if it is waiting to write to the socket, or will raise
        StopIteration if the write operation has completed.

        :rtype: iterable
        :returns: A generator; see above for details.
        """
        try:
            if self.closed:
                raise TLSClosedConnectionError("attempt to write to closed connection")

            applicationData = ApplicationData().create(bytearray(s))
            for result in self._sendMsg(applicationData, \
                                        randomizeFirstBlock=True):
                yield result
        except GeneratorExit:
            raise
        except Exception:
            # Don't invalidate the session on write failure if abrupt closes are
            # okay.
            self._shutdown(self.ignoreAbruptClose)
            raise

    def close(self):
        """Close the TLS connection.

        This function will block until it has exchanged close_notify
        alerts with the other party.  After doing so, it will shut down the
        TLS connection.  Further attempts to read through this connection
        will return "".  Further attempts to write through this connection
        will raise ValueError.

        If makefile() has been called on this connection, the connection
        will be not be closed until the connection object and all file
        objects have been closed.

        Even if an exception is raised, the connection will have been
        closed.

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        if not self.closed:
            for result in self._decrefAsync():
                pass

    # Python 3 callback
    _decref_socketios = close

    def closeAsync(self):
        """Start a close operation on the TLS connection.

        This function returns a generator which behaves similarly to
        close().  Successive invocations of the generator will return 0
        if it is waiting to read from the socket, 1 if it is waiting
        to write to the socket, or will raise StopIteration if the
        close operation has completed.

        :rtype: iterable
        :returns: A generator; see above for details.
        """
        if not self.closed:
            for result in self._decrefAsync():
                yield result

    def _decrefAsync(self):
        self._refCount -= 1
        if self._refCount == 0 and not self.closed:
            try:
                for result in self._sendMsg(Alert().create(\
                        AlertDescription.close_notify, AlertLevel.warning)):
                    yield result
                alert = None
                # By default close the socket, since it's been observed
                # that some other libraries will not respond to the 
                # close_notify alert, thus leaving us hanging if we're
                # expecting it
                if self.closeSocket:
                    self._shutdown(True)
                else:
                    while not alert:
                        for result in self._getMsg((ContentType.alert, \
                                                  ContentType.application_data)):
                            if result in (0,1):
                                yield result
                        if result.contentType == ContentType.alert:
                            alert = result
                    if alert.description == AlertDescription.close_notify:
                        self._shutdown(True)
                    else:
                        raise TLSRemoteAlert(alert)
            except (socket.error, TLSAbruptCloseError):
                #If the other side closes the socket, that's okay
                self._shutdown(True)
            except GeneratorExit:
                raise
            except:
                self._shutdown(False)
                raise

    def getVersionName(self):
        """Get the name of this TLS version.

        :rtype: str
        :returns: The name of the TLS version used with this connection.
            Either None, 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2' or
            'TLS 1.3'.
        """
        ver = {(3, 0): "SSL 3.0",
               (3, 1): "TLS 1.0",
               (3, 2): "TLS 1.1",
               (3, 3): "TLS 1.2",
               (3, 4): "TLS 1.3",
               TLS_1_3_DRAFT: "TLS 1.3"}
        return ver.get(self.version)

    def getCipherName(self):
        """Get the name of the cipher used with this connection.

        :rtype: str
        :returns: The name of the cipher used with this connection.
            Either 'aes128', 'aes256', 'rc4', or '3des'.
        """
        return self._recordLayer.getCipherName()

    def getCipherImplementation(self):
        """Get the name of the cipher implementation used with
        this connection.

        :rtype: str
        :returns: The name of the cipher implementation used with
            this connection.  Either 'python', 'openssl', or 'pycrypto'.
        """
        return self._recordLayer.getCipherImplementation()

    #Emulate a socket, somewhat -
    def send(self, s):
        """Send data to the TLS connection (socket emulation).

        :raises socket.error: If a socket error occurs.
        """
        self.write(s)
        return len(s)

    def sendall(self, s):
        """Send data to the TLS connection (socket emulation).

        :raises socket.error: If a socket error occurs.
        """
        self.write(s)

    def recv(self, bufsize):
        """Get some data from the TLS connection (socket emulation).

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        """
        return self.read(bufsize)

    def recv_into(self, b):
        # XXX doc string
        data = self.read(len(b))
        if not data:
            return None
        b[:len(data)] = data
        return len(data)

    # while the SocketIO and _fileobject in socket is private we really need
    # to use it as it's what the real socket does internally

    # pylint: disable=no-member,protected-access
    def makefile(self, mode='r', bufsize=-1):
        """Create a file object for the TLS connection (socket emulation).

        :rtype: socket._fileobject
        """
        self._refCount += 1
        # So, it is pretty fragile to be using Python internal objects
        # like this, but it is probably the best/easiest way to provide
        # matching behavior for socket emulation purposes.  The 'close'
        # argument is nice, its apparently a recent addition to this
        # class, so that when fileobject.close() gets called, it will
        # close() us, causing the refcount to be decremented (decrefAsync).
        #
        # If this is the last close() on the outstanding fileobjects / 
        # TLSConnection, then the "actual" close alerts will be sent,
        # socket closed, etc.

        # for writes, we MUST buffer otherwise the lengths of headers leak
        # through record layer boundaries
        if 'w' in mode and bufsize <= 0:
            bufsize = 2**14

        if sys.version_info < (3,):
            return socket._fileobject(self, mode, bufsize, close=True)
        else:
            if 'w' in mode:
                return io.BufferedWriter(socket.SocketIO(self, mode), bufsize)
            else:
                return socket.SocketIO(self, mode)
    # pylint: enable=no-member,protected-access

    def getsockname(self):
        """Return the socket's own address (socket emulation)."""
        return self.sock.getsockname()

    def getpeername(self):
        """Return the remote address to which the socket is connected
        (socket emulation)."""
        return self.sock.getpeername()

    def settimeout(self, value):
        """Set a timeout on blocking socket operations (socket emulation)."""
        return self.sock.settimeout(value)

    def gettimeout(self):
        """Return the timeout associated with socket operations (socket
        emulation)."""
        return self.sock.gettimeout()

    def setsockopt(self, level, optname, value):
        """Set the value of the given socket option (socket emulation)."""
        return self.sock.setsockopt(level, optname, value)

    def shutdown(self, how):
        """Shutdown the underlying socket."""
        return self.sock.shutdown(how)
    	
    def fileno(self):
        """Not implement in TLS Lite."""
        raise NotImplementedError()
    	

     #*********************************************************
     # Public Functions END
     #*********************************************************

    def _shutdown(self, resumable):
        self._recordLayer.shutdown()
        self.version = (0,0)
        self.closed = True
        if self.closeSocket:
            self.sock.close()

        #Even if resumable is False, we'll never toggle this on
        if not resumable and self.session:
            self.session.resumable = False


    def _sendError(self, alertDescription, errorStr=None):
        # make sure that the message goes out
        self.sock.flush()
        self.sock.buffer_writes = False
        alert = Alert().create(alertDescription, AlertLevel.fatal)
        for result in self._sendMsg(alert):
            yield result
        self._shutdown(False)
        raise TLSLocalAlert(alert, errorStr)

    def _sendMsgs(self, msgs):
        # send messages together
        self.sock.buffer_writes = True
        randomizeFirstBlock = True
        for msg in msgs:
            for result in self._sendMsg(msg, randomizeFirstBlock):
                yield result
            randomizeFirstBlock = True
        self.sock.flush()
        self.sock.buffer_writes = False

    def _sendMsg(self, msg, randomizeFirstBlock = True):
        """Fragment and send message through socket"""
        #Whenever we're connected and asked to send an app data message,
        #we first send the first byte of the message.  This prevents
        #an attacker from launching a chosen-plaintext attack based on
        #knowing the next IV (a la BEAST).
        if randomizeFirstBlock and self.version <= (3, 1) \
                and self._recordLayer.isCBCMode() \
                and msg.contentType == ContentType.application_data:
            msgFirstByte = msg.splitFirstByte()
            for result in self._sendMsgThroughSocket(msgFirstByte):
                yield result
            if len(msg.write()) == 0:
                return

        buf = msg.write()
        contentType = msg.contentType
        #Update handshake hashes
        if contentType == ContentType.handshake:
            self._handshake_hash.update(buf)

        #Fragment big messages
        while len(buf) > self.recordSize:
            newB = buf[:self.recordSize]
            buf = buf[self.recordSize:]

            msgFragment = Message(contentType, newB)
            for result in self._sendMsgThroughSocket(msgFragment):
                yield result

        msgFragment = Message(contentType, buf)
        for result in self._sendMsgThroughSocket(msgFragment):
            yield result

    def _sendMsgThroughSocket(self, msg):
        """Send message, handle errors"""

        try:
            for result in self._recordLayer.sendRecord(msg):
                if result in (0, 1):
                    yield result
        except socket.error:
            # The socket was unexpectedly closed.  The tricky part
            # is that there may be an alert sent by the other party
            # sitting in the read buffer.  So, if we get here after
            # handshaking, we will just raise the error and let the
            # caller read more data if it would like, thus stumbling
            # upon the error.
            #
            # However, if we get here DURING handshaking, we take
            # it upon ourselves to see if the next message is an
            # Alert.
            if msg.contentType == ContentType.handshake:

                # See if there's an alert record
                # Could raise socket.error or TLSAbruptCloseError
                for result in self._getNextRecord():
                    if result in (0, 1):
                        yield result
                    else:
                        break

                # Closes the socket
                self._shutdown(False)

                # If we got an alert, raise it
                recordHeader, p = result
                if recordHeader.type == ContentType.alert:
                    alert = Alert().parse(p)
                    raise TLSRemoteAlert(alert)
            else:
                # If we got some other message who know what
                # the remote side is doing, just go ahead and
                # raise the socket.error
                raise

    def _getMsg(self, expectedType, secondaryType=None, constructorType=None):
        try:
            if not isinstance(expectedType, tuple):
                expectedType = (expectedType,)

            #Spin in a loop, until we've got a non-empty record of a type we
            #expect.  The loop will be repeated if:
            #  - we receive a renegotiation attempt; we send no_renegotiation,
            #    then try again
            #  - we receive an empty application-data fragment; we try again
            while 1:
                for result in self._getNextRecord():
                    if result in (0,1):
                        yield result
                    else:
                        break
                recordHeader, p = result

                # if this is a CCS message in TLS 1.3, sanity check and
                # continue
                if self.version > (3, 3) and \
                        ContentType.handshake in expectedType and \
                        recordHeader.type == ContentType.change_cipher_spec:
                    ccs = ChangeCipherSpec().parse(p)
                    if ccs.type != 1:
                        for result in self._sendError(
                                AlertDescription.unexpected_message,
                                "Invalid CCS message received"):
                            yield result
                    # ignore the message
                    continue

                #If we received an unexpected record type...
                if recordHeader.type not in expectedType:

                    #If we received an alert...
                    if recordHeader.type == ContentType.alert:
                        alert = Alert().parse(p)

                        #We either received a fatal error, a warning, or a
                        #close_notify.  In any case, we're going to close the
                        #connection.  In the latter two cases we respond with
                        #a close_notify, but ignore any socket errors, since
                        #the other side might have already closed the socket.
                        if alert.level == AlertLevel.warning or \
                           alert.description == AlertDescription.close_notify:

                            #If the sendMsg() call fails because the socket has
                            #already been closed, we will be forgiving and not
                            #report the error nor invalidate the "resumability"
                            #of the session.
                            try:
                                alertMsg = Alert()
                                alertMsg.create(AlertDescription.close_notify,
                                                AlertLevel.warning)
                                for result in self._sendMsg(alertMsg):
                                    yield result
                            except socket.error:
                                pass

                            if alert.description == \
                                   AlertDescription.close_notify:
                                self._shutdown(True)
                            elif alert.level == AlertLevel.warning:
                                self._shutdown(False)

                        else: #Fatal alert:
                            self._shutdown(False)

                        #Raise the alert as an exception
                        raise TLSRemoteAlert(alert)

                    #If we received a renegotiation attempt...
                    if recordHeader.type == ContentType.handshake:
                        subType = p.get(1)
                        reneg = False
                        if self._client:
                            if subType == HandshakeType.hello_request:
                                reneg = True
                        else:
                            if subType == HandshakeType.client_hello:
                                reneg = True
                        # Send no_renegotiation if we're not negotiating
                        # a connection now, then try again
                        if reneg and self.session:
                            alertMsg = Alert()
                            alertMsg.create(AlertDescription.no_renegotiation,
                                            AlertLevel.warning)
                            for result in self._sendMsg(alertMsg):
                                yield result
                            continue

                    #Otherwise: this is an unexpected record, but neither an
                    #alert nor renegotiation
                    for result in self._sendError(\
                            AlertDescription.unexpected_message,
                            "received type=%d" % recordHeader.type):
                        yield result

                #If this is an empty application-data fragment, try again
                if recordHeader.type == ContentType.application_data:
                    if p.index == len(p.bytes):
                        continue

                break

            #Parse based on content_type
            if recordHeader.type == ContentType.change_cipher_spec:
                yield ChangeCipherSpec().parse(p)
            elif recordHeader.type == ContentType.alert:
                yield Alert().parse(p)
            elif recordHeader.type == ContentType.application_data:
                yield ApplicationData().parse(p)
            elif recordHeader.type == ContentType.handshake:
                #Convert secondaryType to tuple, if it isn't already
                if not isinstance(secondaryType, tuple):
                    secondaryType = (secondaryType,)

                #If it's a handshake message, check handshake header
                if recordHeader.ssl2:
                    subType = p.get(1)
                    if subType != HandshakeType.client_hello:
                        for result in self._sendError(\
                                AlertDescription.unexpected_message,
                                "Can only handle SSLv2 ClientHello messages"):
                            yield result
                    if HandshakeType.client_hello not in secondaryType:
                        for result in self._sendError(\
                                AlertDescription.unexpected_message):
                            yield result
                    subType = HandshakeType.client_hello
                else:
                    subType = p.get(1)
                    if subType not in secondaryType:
                        exp = to_str_delimiter(HandshakeType.toStr(i) for i in
                                               secondaryType)
                        rec = HandshakeType.toStr(subType)
                        for result in self._sendError(AlertDescription
                                                      .unexpected_message,
                                                      "Expecting {0}, got {1}"
                                                      .format(exp, rec)):
                            yield result

                #Update handshake hashes
                self._handshake_hash.update(p.bytes)

                #Parse based on handshake type
                if subType == HandshakeType.client_hello:
                    yield ClientHello(recordHeader.ssl2).parse(p)
                elif subType == HandshakeType.server_hello:
                    yield ServerHello().parse(p)
                elif subType == HandshakeType.certificate:
                    yield Certificate(constructorType, self.version).parse(p)
                elif subType == HandshakeType.certificate_request:
                    yield CertificateRequest(self.version).parse(p)
                elif subType == HandshakeType.certificate_verify:
                    yield CertificateVerify(self.version).parse(p)
                elif subType == HandshakeType.server_key_exchange:
                    yield ServerKeyExchange(constructorType,
                                            self.version).parse(p)
                elif subType == HandshakeType.server_hello_done:
                    yield ServerHelloDone().parse(p)
                elif subType == HandshakeType.client_key_exchange:
                    yield ClientKeyExchange(constructorType, \
                                            self.version).parse(p)
                elif subType == HandshakeType.finished:
                    yield Finished(self.version, constructorType).parse(p)
                elif subType == HandshakeType.next_protocol:
                    yield NextProtocol().parse(p)
                elif subType == HandshakeType.encrypted_extensions:
                    yield EncryptedExtensions().parse(p)
                elif subType == HandshakeType.new_session_ticket:
                    yield NewSessionTicket().parse(p)
                else:
                    raise AssertionError()

        #If an exception was raised by a Parser or Message instance:
        except SyntaxError as e:
            for result in self._sendError(AlertDescription.decode_error,
                                         formatExceptionTrace(e)):
                yield result

    #Returns next record or next handshake message
    def _getNextRecord(self):
        """read next message from socket, defragment message"""

        while True:
            # support for fragmentation
            # (RFC 5246 Section 6.2.1)
            # Because the Record Layer is completely separate from the messages
            # that traverse it, it should handle both application data and
            # hadshake data in the same way. For that we buffer the handshake
            # messages until they are completely read.
            # This makes it possible to handle both handshake data not aligned
            # to record boundary as well as handshakes longer than single
            # record.
            while True:
                # empty message buffer
                ret = self._defragmenter.get_message()
                if ret is None:
                    break
                header = RecordHeader3().create(self.version, ret[0], 0)
                yield header, Parser(ret[1])

            # CCS can be sent before early_data but processing it will
            # remove the flag from record layer, so reset it
            early_data_ok = self._recordLayer.early_data_ok

            # when the message buffer is empty, read next record from socket
            for result in self._getNextRecordFromSocket():
                if result in (0, 1):
                    yield result
                else:
                    break

            header, parser = result

            # application data (and CCS in TLS1.3) isn't made out of messages,
            # pass it through
            if header.type == ContentType.application_data or \
                    (self.version > (3, 3) and
                     header.type == ContentType.change_cipher_spec):
                # CCS doesn't change the status of undecryptable
                # records
                if header.type == ContentType.change_cipher_spec:
                    self._recordLayer.early_data_ok = early_data_ok
                yield (header, parser)
            # If it's an SSLv2 ClientHello, we can return it as well, since
            # it's the only ssl2 type we support
            elif header.ssl2:
                yield (header, parser)
            else:
                # other types need to be put into buffers
                self._defragmenter.add_data(header.type, parser.bytes)

    def _getNextRecordFromSocket(self):
        """Read a record, handle errors"""

        try:
            # otherwise... read the next record
            for result in self._recordLayer.recvRecord():
                if result in (0, 1):
                    yield result
                else:
                    break
        except TLSUnexpectedMessage:
            for result in self._sendError(AlertDescription.unexpected_message):
                yield result
        except TLSRecordOverflow:
            for result in self._sendError(AlertDescription.record_overflow):
                yield result
        except TLSIllegalParameterException:
            for result in self._sendError(AlertDescription.illegal_parameter):
                yield result
        except TLSDecryptionFailed:
            for result in self._sendError(
                    AlertDescription.decryption_failed,
                    "Encrypted data not a multiple of blocksize"):
                yield result
        except TLSBadRecordMAC:
            for result in self._sendError(
                    AlertDescription.bad_record_mac,
                    "MAC failure (or padding failure)"):
                yield result

        header, parser = result

        # RFC5246 section 6.2.1: Implementations MUST NOT send
        # zero-length fragments of content types other than Application
        # Data.
        if header.type != ContentType.application_data \
                and parser.getRemainingLength() == 0:
            for result in self._sendError(
                    AlertDescription.unexpected_message,
                    "Received empty non-application data record"):
                yield result

        if header.type not in ContentType.all:
            for result in self._sendError(\
                    AlertDescription.unexpected_message, \
                    "Received record with unknown ContentType"):
                yield result

        yield (header, parser)

    def _handshakeStart(self, client):
        if not self.closed:
            raise ValueError("Renegotiation disallowed for security reasons")
        self._client = client
        self._handshake_hash = HandshakeHashes()
        self._certificate_verify_handshake_hash = None
        self._pre_client_hello_handshake_hash = None
        self._defragmenter.clear_buffers()
        self.allegedSrpUsername = None
        self._refCount = 1

    def _handshakeDone(self, resumed):
        self.resumed = resumed
        self.closed = False

    def _calcPendingStates(self, cipherSuite, masterSecret,
                           clientRandom, serverRandom, implementations):
        self._recordLayer.calcPendingStates(cipherSuite, masterSecret,
                                            clientRandom, serverRandom,
                                            implementations)

    def _changeWriteState(self):
        self._recordLayer.changeWriteState()

    def _changeReadState(self):
        self._recordLayer.changeReadState()
