# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

"""Implementation of the TLS Record Layer protocol"""

import socket
import errno
import hashlib
from .constants import ContentType, CipherSuite
from .messages import RecordHeader3, RecordHeader2, Message
from .utils.cipherfactory import createAES, createRC4, createTripleDES
from .utils.codec import Parser, Writer
from .utils.compat import compatHMAC
from .utils.cryptomath import getRandomBytes
from .errors import TLSRecordOverflow, TLSIllegalParameterException,\
        TLSAbruptCloseError
from .mathtls import createMAC_SSL, createHMAC, PRF_SSL, PRF, PRF_1_2

class RecordSocket(object):

    """Socket wrapper for reading and writing TLS Records"""

    def __init__(self, sock):
        """
        Assign socket to wrapper

        @type sock: socket.socket
        """
        self.sock = sock
        self.version = (0, 0)

    def _sockSendAll(self, data):
        """
        Send all data through socket

        @type data: bytearray
        @param data: data to send
        @raise socket.error: when write to socket failed
        """
        while 1:
            try:
                bytesSent = self.sock.send(data)
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 1
                    continue
                raise

            if bytesSent == len(data):
                return
            data = data[bytesSent:]
            yield 1

    def send(self, msg):
        """
        Send the message through socket.

        @type msg: bytearray
        @param msg: TLS message to send
        @raise socket.error: when write to socket failed
        """

        data = msg.write()

        header = RecordHeader3().create(self.version,
                                        msg.contentType,
                                        len(data))

        data = header.write() + data

        for result in self._sockSendAll(data):
            yield result

    def _sockRecvAll(self, length):
        """
        Read exactly the amount of bytes specified in L{length} from raw socket.

        @rtype: generator
        @return: generator that will return 0 or 1 in case the socket is non
           blocking and would block and bytearray in case the read finished
        @raise TLSAbruptCloseError: when the socket closed
        """

        buf = bytearray(0)

        if length == 0:
            yield buf

        while True:
            try:
                socketBytes = self.sock.recv(length - len(buf))
            except socket.error as why:
                if why.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
                    yield 0
                    continue
                else:
                    raise

            #if the connection closed, raise socket error
            if len(socketBytes) == 0:
                raise TLSAbruptCloseError()

            buf += bytearray(socketBytes)
            if len(buf) == length:
                yield buf

    def _recvHeader(self):
        """Read a single record header from socket"""
        #Read the next record header
        buf = bytearray(0)
        ssl2 = False
        for result in self._sockRecvAll(1):
            if result in (0, 1):
                yield result
            else: break
        buf += result

        if buf[0] in ContentType.all:
            ssl2 = False
            # SSLv3 record layer header is 5 bytes long, we already read 1
            for result in self._sockRecvAll(4):
                if result in (0, 1):
                    yield result
                else: break
            buf += result
        # XXX this should be 'buf[0] & 128', otherwise hello messages longer
        # than 127 bytes won't be properly parsed
        elif buf[0] == 128:
            ssl2 = True
            # in SSLv2 we need to read 2 bytes in total to know the size of
            # header, we already read 1
            for result in self._sockRecvAll(1):
                if result in (0, 1):
                    yield result
                else: break
            buf += result
        else:
            raise TLSIllegalParameterException(
                "Record header type doesn't specify known type")

        #Parse the record header
        if ssl2:
            record = RecordHeader2().parse(Parser(buf))
        else:
            record = RecordHeader3().parse(Parser(buf))

        yield record

    def recv(self):
        """
        Read a single record from socket, handles both SSLv2 and SSLv3 record
        layer

        @rtype: generator
        @return: generator that returns 0 or 1 in case the read would be
            blocking or a tuple containing record header (object) and record
            data (bytearray) read from socket
        @raise socket.error: In case of network error
        @raise TLSAbruptCloseError: When the socket was closed on the other
        side in middle of record receiving
        @raise TLSRecordOverflow: When the received record was longer than
        allowed by TLS
        @raise TLSIllegalParameterException: When the record header was
        malformed
        """

        for record in self._recvHeader():
            if record in (0, 1):
                yield record
            else: break

        #Check the record header fields
        # 18432 = 2**14 (basic record size limit) + 1024 (maximum compression
        # overhead) + 1024 (maximum encryption overhead)
        if record.length > 18432:
            raise TLSRecordOverflow()

        #Read the record contents
        buf = bytearray(0)
        for result in self._sockRecvAll(record.length):
            if result in (0, 1):
                yield result
            else: break
        buf += result

        yield (record, buf)

class ConnectionState(object):

    """Preserve the connection state for reading and writing data to records"""

    def __init__(self):
        """Create an instance with empty encryption and MACing contexts"""
        self.macContext = None
        self.encContext = None
        self.seqnum = 0

    def getSeqNumBytes(self):
        """Return encoded sequence number and increment it."""
        writer = Writer()
        writer.add(self.seqnum, 8)
        self.seqnum += 1
        return writer.bytes

class RecordLayer(object):

    """
    Implementation of TLS record layer protocol

    @ivar version: the TLS version to use (tuple encoded as on the wire)
    @ivar sock: underlying socket
    @ivar client: whatever the connection should use encryption
    """

    def __init__(self, sock):
        self.sock = sock
        self._recordSocket = RecordSocket(sock)
        self._version = (0, 0)

        self.client = True

        self._writeState = ConnectionState()
        self._readState = ConnectionState()
        self._pendingWriteState = ConnectionState()
        self._pendingReadState = ConnectionState()
        self.fixedIVBlock = None

    @property
    def version(self):
        """Return the TLS version used by record layer"""
        return self._version

    @version.setter
    def version(self, val):
        """Set the TLS version used by record layer"""
        self._version = val
        self._recordSocket.version = val

    #
    # sending messages
    #

    def _addPadding(self, data):
        """Add padding to data so that it is multiple of block size"""
        currentLength = len(data)
        blockLength = self._writeState.encContext.block_size
        paddingLength = blockLength - 1 - (currentLength % blockLength)

        paddingBytes = bytearray([paddingLength] * (paddingLength+1))
        data += paddingBytes
        return data

    def _macThenEncrypt(self, b, contentType):
        """MAC then encrypt data"""
        if self._writeState.macContext:
            seqnumBytes = self._writeState.getSeqNumBytes()
            mac = self._writeState.macContext.copy()
            mac.update(compatHMAC(seqnumBytes))
            mac.update(compatHMAC(bytearray([contentType])))
            assert self.version in ((3, 0), (3, 1), (3, 2), (3, 3))
            if self.version == (3, 0):
                mac.update(compatHMAC(bytearray([len(b)//256])))
                mac.update(compatHMAC(bytearray([len(b)%256])))
            else:
                mac.update(compatHMAC(bytearray([self.version[0]])))
                mac.update(compatHMAC(bytearray([self.version[1]])))
                mac.update(compatHMAC(bytearray([len(b)//256])))
                mac.update(compatHMAC(bytearray([len(b)%256])))
            mac.update(compatHMAC(b))
            macBytes = bytearray(mac.digest())

        #Encrypt for Block or Stream Cipher
        if self._writeState.encContext:
            b += macBytes
            #Add padding (for Block Cipher):
            if self._writeState.encContext.isBlockCipher:

                #Add TLS 1.1 fixed block
                if self.version >= (3, 2):
                    b = self.fixedIVBlock + b

                b = self._addPadding(b)

            #Encrypt
            b = self._writeState.encContext.encrypt(b)

        return b

    def sendMessage(self, msg, randomizeFirstBlock=True):
        """
        Encrypt, MAC and send message through socket.

        @param msg: TLS message to send
        @type msg: ApplicationData, HandshakeMessage, etc.
        @param randomizeFirstBlock: set to perform 1/n-1 record splitting in
        SSLv3 and TLSv1.0 in application data
        """

        data = msg.write()
        contentType = msg.contentType

        data = self._macThenEncrypt(data, contentType)

        encryptedMessage = Message(contentType, data)

        for result in self._recordSocket.send(encryptedMessage):
            yield result

    #
    # cryptography state methods
    #

    def changeWriteState(self):
        """
        Change the cipher state to the pending one for write operations.

        This should be done only once after a call to L{calcPendingStates} was
        performed and directly after sending a L{ChangeCipherSpec} message.
        """
        self._writeState = self._pendingWriteState
        self._pendingWriteState = ConnectionState()

    def changeReadState(self):
        """
        Change the cipher state to the pending one for read operations.

        This should be done only once after a call to L{calcPendingStates} was
        performed and directly after receiving a L{ChangeCipherSpec} message.
        """
        self._readState = self._pendingReadState
        self._pendingReadState = ConnectionState()

    def calcPendingStates(self, cipherSuite, masterSecret, clientRandom,
                          serverRandom, implementations):
        """Create pending states for encryption and decryption."""
        if cipherSuite in CipherSuite.aes128Suites:
            keyLength = 16
            ivLength = 16
            createCipherFunc = createAES
        elif cipherSuite in CipherSuite.aes256Suites:
            keyLength = 32
            ivLength = 16
            createCipherFunc = createAES
        elif cipherSuite in CipherSuite.rc4Suites:
            keyLength = 16
            ivLength = 0
            createCipherFunc = createRC4
        elif cipherSuite in CipherSuite.tripleDESSuites:
            keyLength = 24
            ivLength = 8
            createCipherFunc = createTripleDES
        else:
            raise AssertionError()

        if cipherSuite in CipherSuite.shaSuites:
            macLength = 20
            digestmod = hashlib.sha1
        elif cipherSuite in CipherSuite.sha256Suites:
            macLength = 32
            digestmod = hashlib.sha256
        elif cipherSuite in CipherSuite.md5Suites:
            macLength = 16
            digestmod = hashlib.md5

        if self.version == (3, 0):
            createMACFunc = createMAC_SSL
        elif self.version in ((3, 1), (3, 2), (3, 3)):
            createMACFunc = createHMAC

        outputLength = (macLength*2) + (keyLength*2) + (ivLength*2)

        #Calculate Keying Material from Master Secret
        if self.version == (3, 0):
            keyBlock = PRF_SSL(masterSecret,
                               serverRandom + clientRandom,
                               outputLength)
        elif self.version in ((3, 1), (3, 2)):
            keyBlock = PRF(masterSecret,
                           b"key expansion",
                           serverRandom + clientRandom,
                           outputLength)
        elif self.version == (3, 3):
            keyBlock = PRF_1_2(masterSecret,
                               b"key expansion",
                               serverRandom + clientRandom,
                               outputLength)
        else:
            raise AssertionError()

        #Slice up Keying Material
        clientPendingState = ConnectionState()
        serverPendingState = ConnectionState()
        p = Parser(keyBlock)
        clientMACBlock = p.getFixBytes(macLength)
        serverMACBlock = p.getFixBytes(macLength)
        clientKeyBlock = p.getFixBytes(keyLength)
        serverKeyBlock = p.getFixBytes(keyLength)
        clientIVBlock = p.getFixBytes(ivLength)
        serverIVBlock = p.getFixBytes(ivLength)
        clientPendingState.macContext = createMACFunc(
            compatHMAC(clientMACBlock), digestmod=digestmod)
        serverPendingState.macContext = createMACFunc(
            compatHMAC(serverMACBlock), digestmod=digestmod)
        clientPendingState.encContext = createCipherFunc(clientKeyBlock,
                                                         clientIVBlock,
                                                         implementations)
        serverPendingState.encContext = createCipherFunc(serverKeyBlock,
                                                         serverIVBlock,
                                                         implementations)

        #Assign new connection states to pending states
        if self.client:
            self._pendingWriteState = clientPendingState
            self._pendingReadState = serverPendingState
        else:
            self._pendingWriteState = serverPendingState
            self._pendingReadState = clientPendingState

        if self.version >= (3, 2) and ivLength:
            #Choose fixedIVBlock for TLS 1.1 (this is encrypted with the CBC
            #residue to create the IV for each sent block)
            self.fixedIVBlock = getRandomBytes(ivLength)
