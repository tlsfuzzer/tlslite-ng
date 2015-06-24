# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.
"""Handling cryptographic hashes for handshake protocol"""

from .utils.compat import compat26Str, compatHMAC
from .utils.cryptomath import MD5, SHA1
import hashlib

class HandshakeHashes(object):

    """
    Store and calculate necessary hashes for handshake protocol

    Calculates message digests of messages exchanged in handshake protocol
    of SSLv3 and TLS.
    """

    def __init__(self):
        """Create instance"""
        self._handshakeMD5 = hashlib.md5()
        self._handshakeSHA = hashlib.sha1()
        self._handshakeSHA256 = hashlib.sha256()

    def update(self, data):
        """
        Add L{data} to hash input.

        @type data: bytearray
        @param data: serialized TLS handshake message
        """
        text = compat26Str(data)
        self._handshakeMD5.update(text)
        self._handshakeSHA.update(text)
        self._handshakeSHA256.update(text)

    def digest(self, version):
        """
        Calculate and return digest for the already consumed data.

        Used for Finished and CertificateVerify messages.

        @type version: tuple
        @param version: TLS version tuple
        """
        if version in [(3, 1), (3, 2)]:
            return self._handshakeMD5.digest() + self._handshakeSHA.digest()
        elif version in [(3, 3)]:
            # TODO: return SHA384 for specific ciphers
            return self._handshakeSHA256.digest()
        else:
            raise ValueError("Unknown protocol version")

    def digestSSL(self, masterSecret, label):
        """
        Calculate and return digest for already consumed data (SSLv3 version)

        Used for Finished and CertificateVerify messages.

        @type masterSecret: bytearray
        @param masterSecret: value of the master secret
        @type label: bytearray
        @param label: label to include in the calculation
        """
        #pylint: disable=maybe-no-member
        imacMD5 = self._handshakeMD5.copy()
        imacSHA = self._handshakeSHA.copy()
        #pylint: enable=maybe-no-member

        # the below difference in input for MD5 and SHA-1 is why we can't reuse
        # digest() method
        imacMD5.update(compatHMAC(label + masterSecret + bytearray([0x36]*48)))
        imacSHA.update(compatHMAC(label + masterSecret + bytearray([0x36]*40)))

        md5Bytes = MD5(masterSecret + bytearray([0x5c]*48) + \
                         bytearray(imacMD5.digest()))
        shaBytes = SHA1(masterSecret + bytearray([0x5c]*40) + \
                         bytearray(imacSHA.digest()))

        return md5Bytes + shaBytes

    #pylint: disable=protected-access, maybe-no-member
    def copy(self):
        """
        Copy object

        Return a copy of the object with all the hashes in the same state
        as the source object.

        @rtype: HandshakeHashes
        """
        other = HandshakeHashes()
        other._handshakeMD5 = self._handshakeMD5.copy()
        other._handshakeSHA = self._handshakeSHA.copy()
        other._handshakeSHA256 = self._handshakeSHA256.copy()
        return other
