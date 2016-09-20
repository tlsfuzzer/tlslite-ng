# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Abstract class for RSA."""

from .cryptomath import *
from .poly1305 import Poly1305
from . import tlshashlib as hashlib
from ..errors import MaskTooLongError, MessageTooLongError, EncodingError, \
    InvalidSignature, UnknownRSAType


class RSAKey(object):
    """This is an abstract base class for RSA keys.

    Particular implementations of RSA keys, such as
    L{openssl_rsakey.OpenSSL_RSAKey},
    L{python_rsakey.Python_RSAKey}, and
    L{pycrypto_rsakey.PyCrypto_RSAKey},
    inherit from this.

    To create or parse an RSA key, don't use one of these classes
    directly.  Instead, use the factory functions in
    L{tlslite.utils.keyfactory}.
    """

    def __init__(self, n=0, e=0):
        """Create a new RSA key.

        If n and e are passed in, the new key will be initialized.

        @type n: int
        @param n: RSA modulus.

        @type e: int
        @param e: RSA public exponent.
        """
        raise NotImplementedError()

    def __len__(self):
        """Return the length of this key in bits.

        @rtype: int
        """
        return numBits(self.n)

    def hasPrivateKey(self):
        """Return whether or not this key has a private component.

        @rtype: bool
        """
        raise NotImplementedError()

    def hashAndSign(self, bytes, rsaScheme='PKCS1', hAlg='sha1', sLen=0):
        """Hash and sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        a PKCS1 or PSS signature on the passed-in data with selected hash
        algorithm.

        @type bytes: str or L{bytearray} of unsigned bytes
        @param bytes: The value which will be hashed and signed.

        @type rsaScheme: str
        @param rsaScheme: The type of RSA scheme that will be applied,
                          "PKCS1" for RSASSA-PKCS#1 v1.5 signature and "PSS"
                          for RSASSA-PSS with MGF1 signature method

        @type hAlg: str
        @param hAlg: The hash algorithm that will be used

        @type sLen: int
        @param sLen: The length of intended salt value, applicable only
                     for RSASSA-PSS signatures

        @rtype: L{bytearray} of unsigned bytes.
        @return: A PKCS1 or PSS signature on the passed-in data.
        """
        if rsaScheme == "PKCS1":
            hashBytes = secureHash(bytearray(bytes), hAlg)
            prefixedHashBytes = self.addPKCS1Prefix(hashBytes, hAlg)
            sigBytes = self.sign(prefixedHashBytes)
        elif rsaScheme == "PSS":
            sigBytes = self.RSASSA_PSS_sign(bytearray(bytes), hAlg, sLen)
        else:
            raise UnknownRSAType("Unknown RSA algorithm type")
        return sigBytes

    def hashAndVerify(self, sigBytes, bytes, rsaScheme='PKCS1', hAlg='sha1',
                      sLen=0):
        """Hash and verify the passed-in bytes with the signature.

        This verifies a PKCS1 or PSS signature on the passed-in data
        with selected hash algorithm.

        @type sigBytes: L{bytearray} of unsigned bytes
        @param sigBytes: A PKCS1 or PSS signature.

        @type bytes: str or L{bytearray} of unsigned bytes
        @param bytes: The value which will be hashed and verified.

        @type rsaScheme: str
        @param rsaScheme: The type of RSA scheme that will be applied,
                          "PKCS1" for RSASSA-PKCS#1 v1.5 signature and "PSS"
                          for RSASSA-PSS with MGF1 signature method

        @type hAlg: str
        @param hAlg: The hash algorithm that will be used

        @type sLen: int
        @param sLen: The length of intended salt value, applicable only
                     for RSASSA-PSS signatures

        @rtype: bool
        @return: Whether the signature matches the passed-in data.
        """
        
        # Try it with/without the embedded NULL
        if rsaScheme == "PKCS1" and hAlg == 'sha1':
            hashBytes = secureHash(bytearray(bytes), hAlg)
            prefixedHashBytes1 = self.addPKCS1SHA1Prefix(hashBytes, False)
            prefixedHashBytes2 = self.addPKCS1SHA1Prefix(hashBytes, True)
            result1 = self.verify(sigBytes, prefixedHashBytes1)
            result2 = self.verify(sigBytes, prefixedHashBytes2)
            return (result1 or result2)
        elif rsaScheme == 'PKCS1':
            hashBytes = secureHash(bytearray(bytes), hAlg)
            prefixedHashBytes = self.addPKCS1Prefix(hashBytes, hAlg)
            r = self.verify(sigBytes, prefixedHashBytes)
            return r
        elif rsaScheme == "PSS":
            r = self.RSASSA_PSS_verify(bytearray(bytes), sigBytes, hAlg, sLen)
            return r
        else:
            raise UnknownRSAType("Unknown RSA algorithm type")

    def MGF1(self, mgfSeed, maskLen, hAlg):
        """Generate mask from passed-in seed.

        This generates mask based on passed-in seed and output maskLen.

        @type mgfSeed: L{bytearray}
        @param mgfSeed: Seed from which mask will be generated.

        @type maskLen: int
        @param maskLen: Wished length of the mask, in octets

        @rtype: L{bytearray}
        @return: Mask
        """
        hashLen = getattr(hashlib, hAlg)().digest_size
        if maskLen > (2 ** 32) * hashLen:
            raise MaskTooLongError("Incorrect parameter maskLen")
        T = bytearray()
        end = (Poly1305.divceil(maskLen, hashLen))
        for x in range(0, end):
            C = numberToByteArray(x, 4)
            T += secureHash(mgfSeed + C, hAlg)
        return T[:maskLen]

    def EMSA_PSS_encode(self, M, emBits, hAlg, sLen=0):
        """Encode the passed in message

        This encodes the message using selected hash algorithm

        @type M: bytearray
        @param M: Message to be encoded

        @type emBits: int
        @param emBits: maximal length of returned EM

        @type hAlg: str
        @param hAlg: hash algorithm to be used

        @type sLen: int
        @param sLen: length of salt"""
        hashLen = getattr(hashlib, hAlg)().digest_size
        mHash = secureHash(M, hAlg)
        emLen = Poly1305.divceil(emBits, 8)
        if emLen < hashLen + sLen + 2:
            raise EncodingError("The ending limit too short for " +
                                "selected hash and salt length")
        salt = getRandomBytes(sLen)
        M2 = bytearray(8) + mHash + salt
        H = secureHash(M2, hAlg)
        PS = bytearray(emLen - sLen - hashLen - 2)
        DB = PS + bytearray(b'\x01') + salt
        dbMask = self.MGF1(H, emLen - hashLen - 1, hAlg)
        maskedDB = bytearray(i ^ j for i, j in zip(DB, dbMask))
        mLen = emLen*8 - emBits
        mask = (1 << 8 - mLen) - 1
        maskedDB[0] &= mask
        EM = maskedDB + H + bytearray(b'\xbc')
        return EM

    def RSASSA_PSS_sign(self, M, hAlg, sLen=0):
        """"Sign the passed in message

        This signs the message using selected hash algorithm

        @type M: bytearray
        @param M: Message to be signed

        @type hAlg: str
        @param hAlg: hash algorithm to be used

        @type sLen: int
        @param sLen: length of salt"""
        EM = self.EMSA_PSS_encode(M, numBits(self.n) - 1, hAlg, sLen)
        m = bytesToNumber(EM)
        if m >= self.n:
            raise MessageTooLongError("Encode output too long")
        s = self._rawPrivateKeyOp(m)
        S = numberToByteArray(s, numBytes(self.n))
        return S

    def EMSA_PSS_verify(self, M, EM, emBits, hAlg, sLen=0):
        """Verify signature in passed in encoded message

        This verifies the signature in encoded message

        @type M: bytearray
        @param M: Original not signed message

        @type EM: bytearray
        @param EM: Encoded message

        @type emBits: int
        @param emBits: Length of the encoded message in bits

        @type hAlg: str
        @param hAlg: hash algorithm to be used

        @type sLen: int
        @param sLen: Length of salt
        """
        hashLen = getattr(hashlib, hAlg)().digest_size
        mHash = secureHash(M, hAlg)
        emLen = Poly1305.divceil(emBits, 8)
        if emLen < hashLen + sLen + 2:
            raise InvalidSignature("Invalid signature")
        if EM[-1] != 0xbc:
            raise InvalidSignature("Invalid signature")
        maskedDB = EM[0:emLen - hashLen - 1]
        H = EM[emLen - hashLen - 1:emLen - hashLen - 1 + hashLen]
        DBHelpMask = 1 << 8 - (8*emLen - emBits)
        DBHelpMask -= 1
        DBHelpMask = (~DBHelpMask) & 0xff
        if maskedDB[0] & DBHelpMask != 0:
            raise InvalidSignature("Invalid signature")
        dbMask = self.MGF1(H, emLen - hashLen - 1, hAlg)
        DB = bytearray(i ^ j for i, j in zip(maskedDB, dbMask))
        mLen = emLen*8 - emBits
        mask = (1 << 8 - mLen) - 1
        DB[0] &= mask
        if any(x != 0 for x in DB[0:emLen - hashLen - sLen - 2 - 1]):
            raise InvalidSignature("Invalid signature")
        if DB[emLen - hashLen - sLen - 2] != 0x01:
            raise InvalidSignature("Invalid signature")
        if sLen != 0:
            salt = DB[-sLen:]
        else:
            salt = bytearray()
        newM = bytearray(8) + mHash + salt
        newH = secureHash(newM, hAlg)
        if H == newH:
            return True
        else:
            raise InvalidSignature("Invalid signature")

    def RSASSA_PSS_verify(self, M, S, hAlg, sLen=0):
        """Verify the signature in passed in message

        This verifies the signature in the signed message

        @type M: bytearray
        @param M: Original message

        @type S: bytearray
        @param S: Signed message

        @type hAlg: str
        @param hAlg: Hash algorithm to be used

        @type sLen: int
        @param sLen: Length of salt
        """
        if len(bytearray(S)) != len(numberToByteArray(self.n)):
            raise InvalidSignature
        s = bytesToNumber(S)
        m = self._rawPublicKeyOp(s)
        EM = numberToByteArray(m, Poly1305.divceil(numBits(self.n) - 1, 8))
        result = self.EMSA_PSS_verify(M, EM, numBits(self.n) - 1, hAlg, sLen)
        if result:
            return True
        else:
            raise InvalidSignature("Invalid signature")

    def sign(self, bytes):
        """Sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        a PKCS1 signature on the passed-in data.

        @type bytes: L{bytearray} of unsigned bytes
        @param bytes: The value which will be signed.

        @rtype: L{bytearray} of unsigned bytes.
        @return: A PKCS1 signature on the passed-in data.
        """
        if not self.hasPrivateKey():
            raise AssertionError()
        paddedBytes = self._addPKCS1Padding(bytes, 1)
        m = bytesToNumber(paddedBytes)
        if m >= self.n:
            raise ValueError()
        c = self._rawPrivateKeyOp(m)
        sigBytes = numberToByteArray(c, numBytes(self.n))
        return sigBytes

    def verify(self, sigBytes, bytes):
        """Verify the passed-in bytes with the signature.

        This verifies a PKCS1 signature on the passed-in data.

        @type sigBytes: L{bytearray} of unsigned bytes
        @param sigBytes: A PKCS1 signature.

        @type bytes: L{bytearray} of unsigned bytes
        @param bytes: The value which will be verified.

        @rtype: bool
        @return: Whether the signature matches the passed-in data.
        """
        if len(sigBytes) != numBytes(self.n):
            return False
        paddedBytes = self._addPKCS1Padding(bytes, 1)
        c = bytesToNumber(sigBytes)
        if c >= self.n:
            return False
        m = self._rawPublicKeyOp(c)
        checkBytes = numberToByteArray(m, numBytes(self.n))
        return checkBytes == paddedBytes

    def encrypt(self, bytes):
        """Encrypt the passed-in bytes.

        This performs PKCS1 encryption of the passed-in data.

        @type bytes: L{bytearray} of unsigned bytes
        @param bytes: The value which will be encrypted.

        @rtype: L{bytearray} of unsigned bytes.
        @return: A PKCS1 encryption of the passed-in data.
        """
        paddedBytes = self._addPKCS1Padding(bytes, 2)
        m = bytesToNumber(paddedBytes)
        if m >= self.n:
            raise ValueError()
        c = self._rawPublicKeyOp(m)
        encBytes = numberToByteArray(c, numBytes(self.n))
        return encBytes

    def decrypt(self, encBytes):
        """Decrypt the passed-in bytes.

        This requires the key to have a private component.  It performs
        PKCS1 decryption of the passed-in data.

        @type encBytes: L{bytearray} of unsigned bytes
        @param encBytes: The value which will be decrypted.

        @rtype: L{bytearray} of unsigned bytes or None.
        @return: A PKCS1 decryption of the passed-in data or None if
        the data is not properly formatted.
        """
        if not self.hasPrivateKey():
            raise AssertionError()
        if len(encBytes) != numBytes(self.n):
            return None
        c = bytesToNumber(encBytes)
        if c >= self.n:
            return None
        m = self._rawPrivateKeyOp(c)
        decBytes = numberToByteArray(m, numBytes(self.n))
        #Check first two bytes
        if decBytes[0] != 0 or decBytes[1] != 2:
            return None
        #Scan through for zero separator
        for x in range(1, len(decBytes)-1):
            if decBytes[x]== 0:
                break
        else:
            return None
        return decBytes[x+1:] #Return everything after the separator

    def _rawPrivateKeyOp(self, m):
        raise NotImplementedError()

    def _rawPublicKeyOp(self, c):
        raise NotImplementedError()

    def acceptsPassword(self):
        """Return True if the write() method accepts a password for use
        in encrypting the private key.

        @rtype: bool
        """
        raise NotImplementedError()

    def write(self, password=None):
        """Return a string containing the key.

        @rtype: str
        @return: A string describing the key, in whichever format (PEM)
        is native to the implementation.
        """
        raise NotImplementedError()

    def generate(bits):
        """Generate a new key with the specified bit length.

        @rtype: L{tlslite.utils.RSAKey.RSAKey}
        """
        raise NotImplementedError()
    generate = staticmethod(generate)


    # **************************************************************************
    # Helper Functions for RSA Keys
    # **************************************************************************

    @classmethod
    def addPKCS1SHA1Prefix(cls, hashBytes, withNULL=True):
        """Add PKCS#1 v1.5 algorithm identifier prefix to SHA1 hash bytes"""
        # There is a long history of confusion over whether the SHA1 
        # algorithmIdentifier should be encoded with a NULL parameter or 
        # with the parameter omitted.  While the original intention was 
        # apparently to omit it, many toolkits went the other way.  TLS 1.2
        # specifies the NULL should be included, and this behavior is also
        # mandated in recent versions of PKCS #1, and is what tlslite has
        # always implemented.  Anyways, verification code should probably 
        # accept both.
        if not withNULL:
            prefixBytes = bytearray([0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b,
                                     0x0e, 0x03, 0x02, 0x1a, 0x04, 0x14])
        else:
            prefixBytes = cls._pkcs1Prefixes['sha1']
        prefixedBytes = prefixBytes + hashBytes
        return prefixedBytes

    _pkcs1Prefixes = {'md5' : bytearray([0x30, 0x20, 0x30, 0x0c, 0x06, 0x08,
                                         0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                         0x02, 0x05, 0x05, 0x00, 0x04, 0x10]),
                      'sha1' : bytearray([0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
                                          0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
                                          0x00, 0x04, 0x14]),
                      'sha224' : bytearray([0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09,
                                            0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                            0x04, 0x02, 0x04, 0x05, 0x00, 0x04,
                                            0x1c]),
                      'sha256' : bytearray([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
                                            0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                            0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
                                            0x20]),
                      'sha384' : bytearray([0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
                                            0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                            0x04, 0x02, 0x02, 0x05, 0x00, 0x04,
                                            0x30]),
                      'sha512' : bytearray([0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
                                            0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                            0x04, 0x02, 0x03, 0x05, 0x00, 0x04,
                                            0x40])}

    @classmethod
    def addPKCS1Prefix(cls, data, hashName):
        """Add the PKCS#1 v1.5 algorithm identifier prefix to hash bytes"""
        hashName = hashName.lower()
        assert hashName in cls._pkcs1Prefixes
        prefixBytes = cls._pkcs1Prefixes[hashName]
        return prefixBytes + data

    def _addPKCS1Padding(self, bytes, blockType):
        padLength = (numBytes(self.n) - (len(bytes)+3))
        if blockType == 1: #Signature padding
            pad = [0xFF] * padLength
        elif blockType == 2: #Encryption padding
            pad = bytearray(0)
            while len(pad) < padLength:
                padBytes = getRandomBytes(padLength * 2)
                pad = [b for b in padBytes if b != 0]
                pad = pad[:padLength]
        else:
            raise AssertionError()

        padding = bytearray([0,blockType] + pad + [0])
        paddedBytes = padding + bytes
        return paddedBytes
