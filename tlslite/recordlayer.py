# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

"""Implementation of the TLS Record Layer protocol"""

import socket
import errno
from .utils import tlshashlib as hashlib
from .constants import ContentType, CipherSuite
from .messages import RecordHeader3, RecordHeader2, Message
from .utils.cipherfactory import createAESGCM, createAES, createRC4, \
        createTripleDES, createCHACHA20
from .utils.codec import Parser, Writer
from .utils.compat import compatHMAC
from .utils.cryptomath import getRandomBytes, MD5
from .utils.constanttime import ct_compare_digest, ct_check_cbc_mac_and_pad
from .errors import TLSRecordOverflow, TLSIllegalParameterException,\
        TLSAbruptCloseError, TLSDecryptionFailed, TLSBadRecordMAC
from .mathtls import createMAC_SSL, createHMAC, PRF_SSL, PRF, PRF_1_2, \
        PRF_1_2_SHA384

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

    def send(self, msg, padding=0):
        """
        Send the message through socket.

        @type msg: bytearray
        @param msg: TLS message to send
        @type padding: int
        @param padding: amount of padding to specify for SSLv2
        @raise socket.error: when write to socket failed
        """
        data = msg.write()

        if self.version in ((2, 0), (0, 2)):
            header = RecordHeader2().create(len(data),
                                            padding)
        else:
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

        result = None
        for result in self._sockRecvAll(1):
            if result in (0, 1):
                yield result
            else: break
        assert result is not None

        buf += result

        if buf[0] in ContentType.all:
            ssl2 = False
            # SSLv3 record layer header is 5 bytes long, we already read 1
            result = None
            for result in self._sockRecvAll(4):
                if result in (0, 1):
                    yield result
                else: break
            assert result is not None
            buf += result
        else:
            # if header has no pading the header is 2 bytes long, 3 otherwise
            # at the same time we already read 1 byte
            ssl2 = True
            if buf[0] & 0x80:
                readLen = 1
            else:
                readLen = 2
            result = None
            for result in self._sockRecvAll(readLen):
                if result in (0, 1):
                    yield result
                else: break
            assert result is not None
            buf += result


        #Parse the record header
        if ssl2:
            record = RecordHeader2().parse(Parser(buf))
            # padding can't be longer than overall length and if it is present
            # the overall size must be a multiple of cipher block size
            if ((record.padding > record.length) or
                    (record.padding and record.length % 8)):
                raise TLSIllegalParameterException(\
                        "Malformed record layer header")
        else:
            record = RecordHeader3().parse(Parser(buf))

        yield record

    def recv(self):
        """
        Read a single record from socket, handle SSLv2 and SSLv3 record layer

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
        record = None
        for record in self._recvHeader():
            if record in (0, 1):
                yield record
            else: break
        assert record is not None

        #Check the record header fields
        # 18432 = 2**14 (basic record size limit) + 1024 (maximum compression
        # overhead) + 1024 (maximum encryption overhead)
        if record.length > 18432:
            raise TLSRecordOverflow()

        #Read the record contents
        buf = bytearray(0)

        result = None
        for result in self._sockRecvAll(record.length):
            if result in (0, 1):
                yield result
            else: break
        assert result is not None

        buf += result

        yield (record, buf)

class ConnectionState(object):

    """Preserve the connection state for reading and writing data to records"""

    def __init__(self):
        """Create an instance with empty encryption and MACing contexts"""
        self.macContext = None
        self.encContext = None
        self.fixedNonce = None
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
    @ivar client: whether the connection should use encryption
    @ivar encryptThenMAC: use the encrypt-then-MAC mechanism for record
    integrity
    @ivar handshake_finished: used in SSL2, True if handshake protocol is over
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

        self.encryptThenMAC = False

        self.handshake_finished = False

    @property
    def blockSize(self):
        """Return the size of block used by current symmetric cipher (R/O)"""
        return self._writeState.encContext.block_size

    @property
    def version(self):
        """Return the TLS version used by record layer"""
        return self._version

    @version.setter
    def version(self, val):
        """Set the TLS version used by record layer"""
        self._version = val
        self._recordSocket.version = val

    def getCipherName(self):
        """
        Return the name of the bulk cipher used by this connection

        @rtype: str
        @return: The name of the cipher, like 'aes128', 'rc4', etc.
        """
        if self._writeState.encContext is None:
            return None
        return self._writeState.encContext.name

    def getCipherImplementation(self):
        """
        Return the name of the implementation used for the connection

        'python' for tlslite internal implementation, 'openssl' for M2crypto
        and 'pycrypto' for pycrypto
        @rtype: str
        @return: Name of cipher implementation used, None if not initialised
        """
        if self._writeState.encContext is None:
            return None
        return self._writeState.encContext.implementation

    def shutdown(self):
        """Clear read and write states"""
        self._writeState = ConnectionState()
        self._readState = ConnectionState()
        self._pendingWriteState = ConnectionState()
        self._pendingReadState = ConnectionState()

    def isCBCMode(self):
        """Returns true if cipher uses CBC mode"""
        if self._writeState and self._writeState.encContext and \
                self._writeState.encContext.isBlockCipher:
            return True
        else:
            return False
    #
    # sending messages
    #

    def addPadding(self, data):
        """Add padding to data so that it is multiple of block size"""
        currentLength = len(data)
        blockLength = self.blockSize
        paddingLength = blockLength - 1 - (currentLength % blockLength)

        paddingBytes = bytearray([paddingLength] * (paddingLength+1))
        data += paddingBytes
        return data

    def calculateMAC(self, mac, seqnumBytes, contentType, data):
        """Calculate the SSL/TLS version of a MAC"""
        mac.update(compatHMAC(seqnumBytes))
        mac.update(compatHMAC(bytearray([contentType])))
        assert self.version in ((3, 0), (3, 1), (3, 2), (3, 3))
        if self.version != (3, 0):
            mac.update(compatHMAC(bytearray([self.version[0]])))
            mac.update(compatHMAC(bytearray([self.version[1]])))
        mac.update(compatHMAC(bytearray([len(data)//256])))
        mac.update(compatHMAC(bytearray([len(data)%256])))
        mac.update(compatHMAC(data))
        return bytearray(mac.digest())

    def _macThenEncrypt(self, data, contentType):
        """MAC, pad then encrypt data"""
        if self._writeState.macContext:
            seqnumBytes = self._writeState.getSeqNumBytes()
            mac = self._writeState.macContext.copy()
            macBytes = self.calculateMAC(mac, seqnumBytes, contentType, data)
            data += macBytes

        #Encrypt for Block or Stream Cipher
        if self._writeState.encContext:
            #Add padding (for Block Cipher):
            if self._writeState.encContext.isBlockCipher:

                #Add TLS 1.1 fixed block
                if self.version >= (3, 2):
                    data = self.fixedIVBlock + data

                data = self.addPadding(data)

            #Encrypt
            data = self._writeState.encContext.encrypt(data)

        return data

    def _encryptThenMAC(self, buf, contentType):
        """Pad, encrypt and then MAC the data"""
        if self._writeState.encContext:
            # add IV for TLS1.1+
            if self.version >= (3, 2):
                buf = self.fixedIVBlock + buf

            buf = self.addPadding(buf)

            buf = self._writeState.encContext.encrypt(buf)

        # add MAC
        if self._writeState.macContext:
            seqnumBytes = self._writeState.getSeqNumBytes()
            mac = self._writeState.macContext.copy()

            # append MAC
            macBytes = self.calculateMAC(mac, seqnumBytes, contentType, buf)
            buf += macBytes

        return buf

    @staticmethod
    def _getNonce(state, seqnum):
        """Calculate a nonce for a given enc/dec context"""
        # ChaCha is using the draft-TLS1.3-like nonce derivation
        if state.encContext.name == "chacha20-poly1305" and \
                len(state.fixedNonce) == 12:
            # 4 byte nonce is used by the draft cipher
            nonce = bytearray(i ^ j for i, j in zip(bytearray(4) + seqnum,
                                                    state.fixedNonce))
        else:
            nonce = state.fixedNonce + seqnum
        return nonce


    def _encryptThenSeal(self, buf, contentType):
        """Encrypt with AEAD cipher"""
        #Assemble the authenticated data.
        seqNumBytes = self._writeState.getSeqNumBytes()
        authData = seqNumBytes + bytearray([contentType,
                                            self.version[0],
                                            self.version[1],
                                            len(buf)//256,
                                            len(buf)%256])

        nonce = self._getNonce(self._writeState, seqNumBytes)

        assert len(nonce) == self._writeState.encContext.nonceLength

        buf = self._writeState.encContext.seal(nonce, buf, authData)

        #AES-GCM, has an explicit variable nonce.
        if "aes" in self._writeState.encContext.name:
            buf = seqNumBytes + buf

        return buf

    def _ssl2Encrypt(self, data):
        """Encrypt in SSL2 mode"""
        # in SSLv2 sequence numbers are incremented for plaintext records too
        seqnumBytes = self._writeState.getSeqNumBytes()

        if (self._writeState.encContext and
                self._writeState.encContext.isBlockCipher):
            plaintext_len = len(data)
            data = self.addPadding(data)
            padding = len(data) - plaintext_len
        else:
            padding = 0

        if self._writeState.macContext:
            mac = self._writeState.macContext.copy()
            mac.update(compatHMAC(data))
            mac.update(compatHMAC(seqnumBytes[-4:]))

            data = bytearray(mac.digest()) + data

        if self._writeState.encContext:
            data = self._writeState.encContext.encrypt(data)

        return data, padding

    def sendRecord(self, msg):
        """
        Encrypt, MAC and send arbitrary message as-is through socket.

        Note that if the message was not fragmented to below 2**14 bytes
        it will be rejected by the other connection side.

        @param msg: TLS message to send
        @type msg: ApplicationData, HandshakeMessage, etc.
        """
        data = msg.write()
        contentType = msg.contentType

        padding = 0
        if self.version in ((0, 2), (2, 0)):
            data, padding = self._ssl2Encrypt(data)
        elif self._writeState and \
            self._writeState.encContext and \
            self._writeState.encContext.isAEAD:
            data = self._encryptThenSeal(data, contentType)
        elif self.encryptThenMAC:
            data = self._encryptThenMAC(data, contentType)
        else:
            data = self._macThenEncrypt(data, contentType)

        encryptedMessage = Message(contentType, data)

        for result in self._recordSocket.send(encryptedMessage, padding):
            yield result

    #
    # receiving messages
    #

    def _decryptStreamThenMAC(self, recordType, data):
        """Decrypt a stream cipher and check MAC"""
        if self._readState.encContext:
            assert self.version in ((3, 0), (3, 1), (3, 2), (3, 3))

            data = self._readState.encContext.decrypt(data)

        if self._readState.macContext:
            #Check MAC
            macGood = True
            macLength = self._readState.macContext.digest_size
            endLength = macLength
            if endLength > len(data):
                macGood = False
            else:
                #Read MAC
                startIndex = len(data) - endLength
                endIndex = startIndex + macLength
                checkBytes = data[startIndex : endIndex]

                #Calculate MAC
                seqnumBytes = self._readState.getSeqNumBytes()
                data = data[:-endLength]
                mac = self._readState.macContext.copy()
                macBytes = self.calculateMAC(mac, seqnumBytes, recordType,
                                             data)

                #Compare MACs
                if not ct_compare_digest(macBytes, checkBytes):
                    macGood = False

            if not macGood:
                raise TLSBadRecordMAC()

        return data


    def _decryptThenMAC(self, recordType, data):
        """Decrypt data, check padding and MAC"""
        if self._readState.encContext:
            assert self.version in ((3, 0), (3, 1), (3, 2), (3, 3))
            assert self._readState.encContext.isBlockCipher
            assert self._readState.macContext

            #
            # decrypt the record
            #
            blockLength = self._readState.encContext.block_size
            if len(data) % blockLength != 0:
                raise TLSDecryptionFailed()
            data = self._readState.encContext.decrypt(data)
            if self.version >= (3, 2): #For TLS 1.1, remove explicit IV
                data = data[self._readState.encContext.block_size : ]

            #
            # check padding and MAC
            #
            seqnumBytes = self._readState.getSeqNumBytes()

            if not ct_check_cbc_mac_and_pad(data,
                                            self._readState.macContext,
                                            seqnumBytes,
                                            recordType,
                                            self.version):
                raise TLSBadRecordMAC()

            #
            # strip padding and MAC
            #

            endLength = data[-1] + 1 + self._readState.macContext.digest_size

            data = data[:-endLength]

        return data

    def _macThenDecrypt(self, recordType, buf):
        """
        Check MAC of data, then decrypt and remove padding

        @raise TLSBadRecordMAC: when the mac value is invalid
        @raise TLSDecryptionFailed: when the data to decrypt has invalid size
        """
        if self._readState.macContext:
            macLength = self._readState.macContext.digest_size
            if len(buf) < macLength:
                raise TLSBadRecordMAC("Truncated data")

            checkBytes = buf[-macLength:]
            buf = buf[:-macLength]

            seqnumBytes = self._readState.getSeqNumBytes()
            mac = self._readState.macContext.copy()

            macBytes = self.calculateMAC(mac, seqnumBytes, recordType, buf)

            if not ct_compare_digest(macBytes, checkBytes):
                raise TLSBadRecordMAC("MAC mismatch")

        if self._readState.encContext:
            blockLength = self._readState.encContext.block_size
            if len(buf) % blockLength != 0:
                raise TLSDecryptionFailed("data length not multiple of "\
                                          "block size")

            buf = self._readState.encContext.decrypt(buf)

            # remove explicit IV
            if self.version >= (3, 2):
                buf = buf[blockLength:]

            if len(buf) == 0:
                raise TLSBadRecordMAC("No data left after IV removal")

            # check padding
            paddingLength = buf[-1]
            if paddingLength + 1 > len(buf):
                raise TLSBadRecordMAC("Invalid padding length")

            paddingGood = True
            totalPaddingLength = paddingLength+1
            if self.version != (3, 0):
                paddingBytes = buf[-totalPaddingLength:-1]
                for byte in paddingBytes:
                    if byte != paddingLength:
                        paddingGood = False

            if not paddingGood:
                raise TLSBadRecordMAC("Invalid padding byte values")

            # remove padding
            buf = buf[:-totalPaddingLength]

        return buf

    def _decryptAndUnseal(self, recordType, buf):
        """Decrypt AEAD encrypted data"""
        seqnumBytes = self._readState.getSeqNumBytes()
        #AES-GCM, has an explicit variable nonce.
        if "aes" in self._readState.encContext.name:
            explicitNonceLength = 8
            if explicitNonceLength > len(buf):
                #Publicly invalid.
                raise TLSBadRecordMAC("Truncated nonce")
            nonce = self._readState.fixedNonce + buf[:explicitNonceLength]
            buf = buf[8:]
        else:
            nonce = self._getNonce(self._readState, seqnumBytes)

        if self._readState.encContext.tagLength > len(buf):
            #Publicly invalid.
            raise TLSBadRecordMAC("Truncated tag")

        plaintextLen = len(buf) - self._readState.encContext.tagLength
        authData = seqnumBytes + bytearray([recordType, self.version[0],
                                            self.version[1],
                                            plaintextLen//256,
                                            plaintextLen%256])

        buf = self._readState.encContext.open(nonce, buf, authData)
        if buf is None:
            raise TLSBadRecordMAC("Invalid tag, decryption failure")
        return buf

    def _decryptSSL2(self, data, padding):
        """Decrypt SSL2 encrypted data"""
        # sequence numbers are incremented for plaintext records too
        seqnumBytes = self._readState.getSeqNumBytes()

        #
        # decrypt
        #
        if self._readState.encContext:
            if self._readState.encContext.isBlockCipher:
                blockLength = self._readState.encContext.block_size
                if len(data) % blockLength:
                    raise TLSDecryptionFailed()
            data = self._readState.encContext.decrypt(data)

        #
        # strip and check MAC
        #
        if self._readState.macContext:
            macBytes = data[:16]
            data = data[16:]

            mac = self._readState.macContext.copy()
            mac.update(compatHMAC(data))
            mac.update(compatHMAC(seqnumBytes[-4:]))
            calcMac = bytearray(mac.digest())
            if macBytes != calcMac:
                raise TLSBadRecordMAC()

        #
        # strip padding
        #
        if padding:
            data = data[:-padding]
        return data

    def recvRecord(self):
        """
        Read, decrypt and check integrity of a single record

        @rtype: tuple
        @return: message header and decrypted message payload
        @raise TLSDecryptionFailed: when decryption of data failed
        @raise TLSBadRecordMAC: when record has bad MAC or padding
        @raise socket.error: when reading from socket was unsuccessful
        """
        result = None
        for result in self._recordSocket.recv():
            if result in (0, 1):
                yield result
            else: break
        assert result is not None

        (header, data) = result

        if isinstance(header, RecordHeader2):
            data = self._decryptSSL2(data, header.padding)
            if self.handshake_finished:
                header.type = ContentType.application_data
        elif self._readState and \
            self._readState.encContext and \
            self._readState.encContext.isAEAD:
            data = self._decryptAndUnseal(header.type, data)
        elif self.encryptThenMAC:
            data = self._macThenDecrypt(header.type, data)
        elif self._readState and \
                self._readState.encContext and \
                self._readState.encContext.isBlockCipher:
            data = self._decryptThenMAC(header.type, data)
        else:
            data = self._decryptStreamThenMAC(header.type, data)

        # RFC 5246, section 6.2.1
        if len(data) > 2**14:
            raise TLSRecordOverflow()

        yield (header, Parser(data))

    #
    # cryptography state methods
    #

    def changeWriteState(self):
        """
        Change the cipher state to the pending one for write operations.

        This should be done only once after a call to L{calcPendingStates} was
        performed and directly after sending a L{ChangeCipherSpec} message.
        """
        if self.version in ((0, 2), (2, 0)):
            # in SSLv2 sequence numbers carry over from plaintext to encrypted
            # context
            self._pendingWriteState.seqnum = self._writeState.seqnum
        self._writeState = self._pendingWriteState
        self._pendingWriteState = ConnectionState()

    def changeReadState(self):
        """
        Change the cipher state to the pending one for read operations.

        This should be done only once after a call to L{calcPendingStates} was
        performed and directly after receiving a L{ChangeCipherSpec} message.
        """
        if self.version in ((0, 2), (2, 0)):
            # in SSLv2 sequence numbers carry over from plaintext to encrypted
            # context
            self._pendingReadState.seqnum = self._readState.seqnum
        self._readState = self._pendingReadState
        self._pendingReadState = ConnectionState()

    @staticmethod
    def _getCipherSettings(cipherSuite):
        """Get the settings for cipher suite used"""
        if cipherSuite in CipherSuite.aes256GcmSuites:
            keyLength = 32
            ivLength = 4
            createCipherFunc = createAESGCM
        elif cipherSuite in CipherSuite.aes128GcmSuites:
            keyLength = 16
            ivLength = 4
            createCipherFunc = createAESGCM
        elif cipherSuite in CipherSuite.chacha20Suites:
            keyLength = 32
            ivLength = 12
            createCipherFunc = createCHACHA20
        elif cipherSuite in CipherSuite.chacha20draft00Suites:
            keyLength = 32
            ivLength = 4
            createCipherFunc = createCHACHA20
        elif cipherSuite in CipherSuite.aes128Suites:
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
        elif cipherSuite in CipherSuite.nullSuites:
            keyLength = 0
            ivLength = 0
            createCipherFunc = None
        else:
            raise AssertionError()

        return (keyLength, ivLength, createCipherFunc)

    @staticmethod
    def _getMacSettings(cipherSuite):
        """Get settings for HMAC used"""
        if cipherSuite in CipherSuite.aeadSuites:
            macLength = 0
            digestmod = None
        elif cipherSuite in CipherSuite.shaSuites:
            macLength = 20
            digestmod = hashlib.sha1
        elif cipherSuite in CipherSuite.sha256Suites:
            macLength = 32
            digestmod = hashlib.sha256
        elif cipherSuite in CipherSuite.sha384Suites:
            macLength = 48
            digestmod = hashlib.sha384
        elif cipherSuite in CipherSuite.md5Suites:
            macLength = 16
            digestmod = hashlib.md5
        else:
            raise AssertionError()

        return macLength, digestmod

    @staticmethod
    def _getHMACMethod(version):
        """Get the HMAC method"""
        assert version in ((3, 0), (3, 1), (3, 2), (3, 3))
        if version == (3, 0):
            createMACFunc = createMAC_SSL
        elif version in ((3, 1), (3, 2), (3, 3)):
            createMACFunc = createHMAC

        return createMACFunc

    def _calcKeyBlock(self, cipherSuite, masterSecret, clientRandom,
                      serverRandom, outputLength):
        """Calculate the overall key to slice up"""
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
            if cipherSuite in CipherSuite.sha384PrfSuites:
                keyBlock = PRF_1_2_SHA384(masterSecret,
                                          b"key expansion",
                                          serverRandom + clientRandom,
                                          outputLength)
            else:
                keyBlock = PRF_1_2(masterSecret,
                                   b"key expansion",
                                   serverRandom + clientRandom,
                                   outputLength)
        else:
            raise AssertionError()

        return keyBlock

    def calcSSL2PendingStates(self, cipherSuite, masterSecret, clientRandom,
                              serverRandom, implementations):
        """
        Create the keys for encryption and decryption in SSLv2

        While we could reuse calcPendingStates(), we need to provide the
        key-arg data for the server that needs to be passed up to handshake
        protocol.
        """
        if cipherSuite in CipherSuite.ssl2_128Key:
            key_length = 16
        elif cipherSuite in CipherSuite.ssl2_192Key:
            key_length = 24
        elif cipherSuite in CipherSuite.ssl2_64Key:
            key_length = 8
        else:
            raise ValueError("Unknown cipher specified")

        key_material = bytearray(key_length * 2)
        md5_output_size = 16
        for i, pos in enumerate(range(0, key_length * 2, md5_output_size)):
            key_material[pos:pos+md5_output_size] = MD5(\
                    masterSecret +
                    bytearray(str(i), "ascii") +
                    clientRandom + serverRandom)

        serverWriteKey = key_material[:key_length]
        clientWriteKey = key_material[key_length:]

        # specification draft says that DES key should not use the
        # incrementing label but all implementations use it anyway
        #elif cipherSuite in CipherSuite.ssl2_64Key:
        #    key_material = MD5(masterSecret + clientRandom + serverRandom)
        #    serverWriteKey = key_material[0:8]
        #    clientWriteKey = key_material[8:16]

        # RC4 cannot use initialisation vector
        if cipherSuite not in CipherSuite.ssl2rc4:
            iv = getRandomBytes(8)
        else:
            iv = bytearray(0)

        clientPendingState = ConnectionState()
        serverPendingState = ConnectionState()

        # MAC
        clientPendingState.macContext = hashlib.md5()
        clientPendingState.macContext.update(compatHMAC(clientWriteKey))
        serverPendingState.macContext = hashlib.md5()
        serverPendingState.macContext.update(compatHMAC(serverWriteKey))

        # ciphers
        if cipherSuite in CipherSuite.ssl2rc4:
            cipherMethod = createRC4
        elif cipherSuite in CipherSuite.ssl2_3des:
            cipherMethod = createTripleDES
        else:
            raise NotImplementedError("Unknown cipher")

        clientPendingState.encContext = cipherMethod(clientWriteKey, iv,
                                                     implementations)
        serverPendingState.encContext = cipherMethod(serverWriteKey, iv,
                                                     implementations)

        # Assign new connection states to pending states
        if self.client:
            self._pendingWriteState = clientPendingState
            self._pendingReadState = serverPendingState
        else:
            self._pendingWriteState = serverPendingState
            self._pendingReadState = clientPendingState

        return iv

    def calcPendingStates(self, cipherSuite, masterSecret, clientRandom,
                          serverRandom, implementations):
        """Create pending states for encryption and decryption."""
        keyLength, ivLength, createCipherFunc = \
                self._getCipherSettings(cipherSuite)

        macLength, digestmod = self._getMacSettings(cipherSuite)

        if not digestmod:
            createMACFunc = None
        else:
            createMACFunc = self._getHMACMethod(self.version)

        outputLength = (macLength*2) + (keyLength*2) + (ivLength*2)

        #Calculate Keying Material from Master Secret
        keyBlock = self._calcKeyBlock(cipherSuite, masterSecret, clientRandom,
                                      serverRandom, outputLength)

        #Slice up Keying Material
        clientPendingState = ConnectionState()
        serverPendingState = ConnectionState()
        parser = Parser(keyBlock)
        clientMACBlock = parser.getFixBytes(macLength)
        serverMACBlock = parser.getFixBytes(macLength)
        clientKeyBlock = parser.getFixBytes(keyLength)
        serverKeyBlock = parser.getFixBytes(keyLength)
        clientIVBlock = parser.getFixBytes(ivLength)
        serverIVBlock = parser.getFixBytes(ivLength)

        if digestmod:
            # Legacy cipher
            clientPendingState.macContext = createMACFunc(
                compatHMAC(clientMACBlock), digestmod=digestmod)
            serverPendingState.macContext = createMACFunc(
                compatHMAC(serverMACBlock), digestmod=digestmod)
            if createCipherFunc is not None:
                clientPendingState.encContext = \
                                            createCipherFunc(clientKeyBlock,
                                                             clientIVBlock,
                                                             implementations)
                serverPendingState.encContext = \
                                            createCipherFunc(serverKeyBlock,
                                                             serverIVBlock,
                                                             implementations)
        else:
            # AEAD
            clientPendingState.macContext = None
            serverPendingState.macContext = None
            clientPendingState.encContext = createCipherFunc(clientKeyBlock,
                                                             implementations)
            serverPendingState.encContext = createCipherFunc(serverKeyBlock,
                                                             implementations)
            clientPendingState.fixedNonce = clientIVBlock
            serverPendingState.fixedNonce = serverIVBlock

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

