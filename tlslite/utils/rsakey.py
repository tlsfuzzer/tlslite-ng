# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Abstract class for RSA."""

from .cryptomath import *
from . import tlshashlib as hashlib
from ..errors import MaskTooLongError, MessageTooLongError, EncodingError, \
    InvalidSignature, UnknownRSAType


class RSAKey(object):
    """This is an abstract base class for RSA keys.

    Particular implementations of RSA keys, such as
    :py:class:`~.openssl_rsakey.OpenSSL_RSAKey`,
    :py:class:`~.python_rsakey.Python_RSAKey`, and
    :py:class:`~.pycrypto_rsakey.PyCrypto_RSAKey`,
    inherit from this.

    To create or parse an RSA key, don't use one of these classes
    directly.  Instead, use the factory functions in
    :py:class:`~tlslite.utils.keyfactory`.
    """

    def __init__(self, n=0, e=0):
        """Create a new RSA key.

        If n and e are passed in, the new key will be initialized.

        :type n: int
        :param n: RSA modulus.

        :type e: int
        :param e: RSA public exponent.
        """
        raise NotImplementedError()

    def __len__(self):
        """Return the length of this key in bits.

        :rtype: int
        """
        return numBits(self.n)

    def hasPrivateKey(self):
        """Return whether or not this key has a private component.

        :rtype: bool
        """
        raise NotImplementedError()

    def hashAndSign(self, bytes, rsaScheme='PKCS1', hAlg='sha1', sLen=0):
        """Hash and sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        a PKCS1 or PSS signature on the passed-in data with selected hash
        algorithm.

        :type bytes: bytes-like object
        :param bytes: The value which will be hashed and signed.

        :type rsaScheme: str
        :param rsaScheme: The type of RSA scheme that will be applied,
                          "PKCS1" for RSASSA-PKCS#1 v1.5 signature and "PSS"
                          for RSASSA-PSS with MGF1 signature method

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used

        :type sLen: int
        :param sLen: The length of intended salt value, applicable only
                     for RSASSA-PSS signatures

        :rtype: bytearray
        :returns: A PKCS1 or PSS signature on the passed-in data.
        """
        rsaScheme = rsaScheme.lower()
        hAlg = hAlg.lower()
        hashBytes = secureHash(bytearray(bytes), hAlg)
        return self.sign(hashBytes, padding=rsaScheme, hashAlg=hAlg,
                         saltLen=sLen)

    def hashAndVerify(self, sigBytes, bytes, rsaScheme='PKCS1', hAlg='sha1',
                      sLen=0):
        """Hash and verify the passed-in bytes with the signature.

        This verifies a PKCS1 or PSS signature on the passed-in data
        with selected hash algorithm.

        :type sigBytes: bytes-like object
        :param sigBytes: A PKCS1 or PSS signature.

        :type bytes: bytes-like object
        :param bytes: The value which will be hashed and verified.

        :type rsaScheme: str
        :param rsaScheme: The type of RSA scheme that will be applied,
                          "PKCS1" for RSASSA-PKCS#1 v1.5 signature and "PSS"
                          for RSASSA-PSS with MGF1 signature method

        :type hAlg: str
        :param hAlg: The hash algorithm that will be used

        :type sLen: int
        :param sLen: The length of intended salt value, applicable only
                     for RSASSA-PSS signatures

        :rtype: bool
        :returns: Whether the signature matches the passed-in data.
        """
        rsaScheme = rsaScheme.lower()
        hAlg = hAlg.lower()

        hashBytes = secureHash(bytearray(bytes), hAlg)
        return self.verify(sigBytes, hashBytes, rsaScheme, hAlg, sLen)

    def MGF1(self, mgfSeed, maskLen, hAlg):
        """Generate mask from passed-in seed.

        This generates mask based on passed-in seed and output maskLen.

        :type mgfSeed: bytearray
        :param mgfSeed: Seed from which mask will be generated.

        :type maskLen: int
        :param maskLen: Wished length of the mask, in octets

        :rtype: bytearray
        :returns: Mask
        """
        hashLen = getattr(hashlib, hAlg)().digest_size
        if maskLen > (2 ** 32) * hashLen:
            raise MaskTooLongError("Incorrect parameter maskLen")
        T = bytearray()
        end = divceil(maskLen, hashLen)
        for x in range(0, end):
            C = numberToByteArray(x, 4)
            T += secureHash(mgfSeed + C, hAlg)
        return T[:maskLen]

    def EMSA_PSS_encode(self, mHash, emBits, hAlg, sLen=0):
        """Encode the passed in message

        This encodes the message using selected hash algorithm

        :type mHash: bytearray
        :param mHash: Hash of message to be encoded

        :type emBits: int
        :param emBits: maximal length of returned EM

        :type hAlg: str
        :param hAlg: hash algorithm to be used

        :type sLen: int
        :param sLen: length of salt"""
        hashLen = getattr(hashlib, hAlg)().digest_size
        emLen = divceil(emBits, 8)
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

    def RSASSA_PSS_sign(self, mHash, hAlg, sLen=0):
        """"Sign the passed in message

        This signs the message using selected hash algorithm

        :type mHash: bytes-like object
        :param mHash: Hash of message to be signed

        :type hAlg: str
        :param hAlg: hash algorithm to be used

        :type sLen: int
        :param sLen: length of salt"""
        EM = self.EMSA_PSS_encode(mHash, numBits(self.n) - 1, hAlg, sLen)
        m = bytesToNumber(EM)
        if m >= self.n:
            raise MessageTooLongError("Encode output too long")
        s = self._rawPrivateKeyOp(m)
        S = numberToByteArray(s, numBytes(self.n))
        return S

    def EMSA_PSS_verify(self, mHash, EM, emBits, hAlg, sLen=0):
        """Verify signature in passed in encoded message

        This verifies the signature in encoded message

        :type mHash: bytes-like object
        :param mHash: Hash of the original not signed message

        :type EM: bytes-like object
        :param EM: Encoded message

        :type emBits: int
        :param emBits: Length of the encoded message in bits

        :type hAlg: str
        :param hAlg: hash algorithm to be used

        :type sLen: int
        :param sLen: Length of salt
        """
        hashLen = getattr(hashlib, hAlg)().digest_size
        emLen = divceil(emBits, 8)
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
        if any(x != 0 for x in DB[0:emLen - hashLen - sLen - 2]):
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

    def RSASSA_PSS_verify(self, mHash, S, hAlg, sLen=0):
        """Verify the signature in passed in message

        This verifies the signature in the signed message

        :type mHash: bytes-like object
        :param mHash: Hash of original message

        :type S: bytes-like object
        :param S: Signed message

        :type hAlg: str
        :param hAlg: Hash algorithm to be used

        :type sLen: int
        :param sLen: Length of salt
        """
        if len(bytearray(S)) != len(numberToByteArray(self.n)):
            raise InvalidSignature("Invalid signature")
        s = bytesToNumber(S)
        m = self._rawPublicKeyOp(s)
        EM = numberToByteArray(m, divceil(numBits(self.n) - 1, 8))
        result = self.EMSA_PSS_verify(mHash, EM, numBits(self.n) - 1,
                                      hAlg, sLen)
        if result:
            return True
        else:
            raise InvalidSignature("Invalid signature")

    def _raw_pkcs1_sign(self, bytes):
        """Perform signature on raw data, add PKCS#1 padding."""
        if not self.hasPrivateKey():
            raise AssertionError()
        paddedBytes = self._addPKCS1Padding(bytes, 1)
        m = bytesToNumber(paddedBytes)
        if m >= self.n:
            raise ValueError()
        c = self._rawPrivateKeyOp(m)
        sigBytes = numberToByteArray(c, numBytes(self.n))
        return sigBytes

    def sign(self, bytes, padding='pkcs1', hashAlg=None, saltLen=None):
        """Sign the passed-in bytes.

        This requires the key to have a private component.  It performs
        a PKCS1 signature on the passed-in data.

        :type bytes: bytes-like object
        :param bytes: The value which will be signed.

        :type padding: str
        :param padding: name of the rsa padding mode to use, supported:
            "pkcs1" for RSASSA-PKCS1_1_5 and "pss" for RSASSA-PSS.

        :type hashAlg: str
        :param hashAlg: name of hash to be encoded using the PKCS#1 prefix
            for "pkcs1" padding or the hash used for MGF1 in "pss". Parameter
            is mandatory for "pss" padding.

        :type saltLen: int
        :param saltLen: length of salt used for the PSS padding. Default
            is the length of the hash output used.

        :rtype: bytearray
        :returns: A PKCS1 signature on the passed-in data.
        """
        padding = padding.lower()
        if padding == 'pkcs1':
            if hashAlg is not None:
                bytes = self.addPKCS1Prefix(bytes, hashAlg)
            sigBytes = self._raw_pkcs1_sign(bytes)
        elif padding == "pss":
            sigBytes = self.RSASSA_PSS_sign(bytes, hashAlg, saltLen)
        else:
            raise UnknownRSAType("Unknown RSA algorithm type")
        return sigBytes

    def _raw_pkcs1_verify(self, sigBytes, bytes):
        """Perform verification operation on raw PKCS#1 padded signature"""
        if len(sigBytes) != numBytes(self.n):
            return False
        paddedBytes = self._addPKCS1Padding(bytes, 1)
        c = bytesToNumber(sigBytes)
        if c >= self.n:
            return False
        m = self._rawPublicKeyOp(c)
        checkBytes = numberToByteArray(m, numBytes(self.n))
        return checkBytes == paddedBytes

    def verify(self, sigBytes, bytes, padding='pkcs1', hashAlg=None,
               saltLen=None):
        """Verify the passed-in bytes with the signature.

        This verifies a PKCS1 signature on the passed-in data.

        :type sigBytes: bytes-like object
        :param sigBytes: A PKCS1 signature.

        :type bytes: bytes-like object
        :param bytes: The value which will be verified.

        :rtype: bool
        :returns: Whether the signature matches the passed-in data.
        """
        if padding == "pkcs1" and hashAlg == 'sha1':
            # Try it with/without the embedded NULL
            prefixedHashBytes1 = self.addPKCS1SHA1Prefix(bytes, False)
            prefixedHashBytes2 = self.addPKCS1SHA1Prefix(bytes, True)
            result1 = self._raw_pkcs1_verify(sigBytes, prefixedHashBytes1)
            result2 = self._raw_pkcs1_verify(sigBytes, prefixedHashBytes2)
            return (result1 or result2)
        elif padding == 'pkcs1':
            if hashAlg is not None:
                bytes = self.addPKCS1Prefix(bytes, hashAlg)
            res = self._raw_pkcs1_verify(sigBytes, bytes)
            return res
        elif padding == "pss":
            try:
                res = self.RSASSA_PSS_verify(bytes, sigBytes, hashAlg, saltLen)
            except InvalidSignature:
                res = False
            return res
        else:
            raise UnknownRSAType("Unknown RSA algorithm type")

    def encrypt(self, bytes):
        """Encrypt the passed-in bytes.

        This performs PKCS1 encryption of the passed-in data.

        :type bytes: bytes-like object
        :param bytes: The value which will be encrypted.

        :rtype: bytearray
        :returns: A PKCS1 encryption of the passed-in data.
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

        :type encBytes: bytes-like object
        :param encBytes: The value which will be decrypted.

        :rtype: bytearray or None
        :returns: A PKCS1 decryption of the passed-in data or None if
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

        :rtype: bool
        """
        raise NotImplementedError()

    def write(self, password=None):
        """Return a string containing the key.

        :rtype: str
        :returns: A string describing the key, in whichever format (PEM)
            is native to the implementation.
        """
        raise NotImplementedError()

    def generate(bits):
        """Generate a new key with the specified bit length.

        :rtype: ~tlslite.utils.RSAKey.RSAKey
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
