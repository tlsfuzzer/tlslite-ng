# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Pure-Python RSA implementation."""
import threading
from .cryptomath import *
from .asn1parser import ASN1Parser
from .rsakey import *
from .pem import *
from .deprecations import deprecated_params

class Python_RSAKey(RSAKey):
    def __init__(self, n=0, e=0, d=0, p=0, q=0, dP=0, dQ=0, qInv=0,
                 key_type="rsa"):
        """Initialise key directly from integers.

        see also generate() and parsePEM()."""
        if (n and not e) or (e and not n):
            raise AssertionError()
        self.n = n
        self.e = e
        if p and not q or not p and q:
            raise ValueError("p and q must be set or left unset together")
        if not d and p and q:
            t = lcm(p - 1, q - 1)
            d = invMod(e, t)
        self.d = d
        self.p = p
        self.q = q
        if not dP and p:
            dP = d % (p - 1)
        self.dP = dP
        if not dQ and q:
            dQ = d % (q - 1)
        self.dQ = dQ
        if not qInv:
            qInv = invMod(q, p)
        self.qInv = qInv
        self.blinder = 0
        self.unblinder = 0
        self._lock = threading.Lock()
        self.key_type = key_type

    def hasPrivateKey(self):
        """
        Does the key has the associated private key (True) or is it only
        the public part (False).
        """
        return self.d != 0

    def _rawPrivateKeyOp(self, message):
        with self._lock:
            # Create blinding values, on the first pass:
            if not self.blinder:
                self.unblinder = getRandomNumber(2, self.n)
                self.blinder = powMod(invMod(self.unblinder, self.n), self.e,
                                      self.n)
            unblinder = self.unblinder
            blinder = self.blinder

            # Update blinding values
            self.blinder = (self.blinder * self.blinder) % self.n
            self.unblinder = (self.unblinder * self.unblinder) % self.n

        # Blind the input
        message = (message * blinder) % self.n

        # Perform the RSA operation
        cipher = self._rawPrivateKeyOpHelper(message)

        # Unblind the output
        cipher = (cipher * unblinder) % self.n

        # Return the output
        return cipher

    def _rawPrivateKeyOpHelper(self, m):
        #Non-CRT version
        #c = powMod(m, self.d, self.n)

        #CRT version  (~3x faster)
        s1 = powMod(m, self.dP, self.p)
        s2 = powMod(m, self.dQ, self.q)
        h = ((s1 - s2) * self.qInv) % self.p
        c = s2 + self.q * h
        return c

    def _rawPublicKeyOp(self, ciphertext):
        msg = powMod(ciphertext, self.e, self.n)
        return msg

    def acceptsPassword(self):
        """Does it support encrypted key files."""
        return False

    @staticmethod
    def generate(bits, key_type="rsa"):
        """Generate a private key with modulus 'bits' bit big.

        key_type can be "rsa" for a universal rsaEncryption key or
        "rsa-pss" for a key that can be used only for RSASSA-PSS."""
        key = Python_RSAKey()
        p = getRandomPrime(bits//2, False)
        q = getRandomPrime(bits//2, False)
        t = lcm(p-1, q-1)
        key.n = p * q
        key.e = 65537
        key.d = invMod(key.e, t)
        key.p = p
        key.q = q
        key.dP = key.d % (p-1)
        key.dQ = key.d % (q-1)
        key.qInv = invMod(q, p)
        key.key_type = key_type
        return key

    @staticmethod
    @deprecated_params({"data": "s", "password_callback": "passwordCallback"})
    def parsePEM(data, password_callback=None):
        """Parse a string containing a PEM-encoded <privateKey>."""
        del password_callback
        if pemSniff(data, "PRIVATE KEY"):
            data = dePem(data, "PRIVATE KEY")
            return Python_RSAKey._parse_pkcs8(data)
        elif pemSniff(data, "RSA PRIVATE KEY"):
            data = dePem(data, "RSA PRIVATE KEY")
            return Python_RSAKey._parse_ssleay(data)
        else:
            raise SyntaxError("Not a PEM private key file")

    @staticmethod
    def _parse_pkcs8(data):
        """Parse data in the binary PKCS#8 format."""
        parser = ASN1Parser(data)

        # first element in PrivateKeyInfo is an INTEGER
        version = parser.getChild(0).value
        if bytesToNumber(version) != 0:
            raise SyntaxError("Unrecognized PKCS8 version")

        # second element in PrivateKeyInfo is a SEQUENCE of type
        # AlgorithmIdentifier
        alg_ident = parser.getChild(1)
        seqLen = alg_ident.getChildCount()
        # first item of AlgorithmIdentifier is an OBJECT (OID)
        oid = alg_ident.getChild(0)
        if list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 1]:
            key_type = "rsa"
        elif list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 10]:
            key_type = "rsa-pss"
        else:
            raise SyntaxError("Unrecognized AlgorithmIdentifier: {0}"
                              .format(list(oid.value)))
        # second item of AlgorithmIdentifier are parameters (defined by
        # above algorithm)
        if key_type == "rsa":
            if seqLen != 2:
                raise SyntaxError("Missing parameters for RSA algorithm ID")
            parameters = alg_ident.getChild(1)
            if parameters.value != bytearray(0):
                raise SyntaxError("RSA parameters are not NULL")
        else:  # rsa-pss
            pass  # ignore parameters - don't apply restrictions

        if seqLen > 2:
            raise SyntaxError("Invalid encoding of AlgorithmIdentifier")

        #Get the privateKey
        private_key_parser = parser.getChild(2)

        #Adjust for OCTET STRING encapsulation
        private_key_parser = ASN1Parser(private_key_parser.value)

        return Python_RSAKey._parse_asn1_private_key(private_key_parser,
                                                     key_type)

    @staticmethod
    def _parse_ssleay(data):
        """
        Parse binary structure of the old SSLeay file format used by OpenSSL.
        """
        private_key_parser = ASN1Parser(data)

        # "rsa" type as old format doesn't support rsa-pss parameters
        return Python_RSAKey._parse_asn1_private_key(private_key_parser, "rsa")

    # n, e, d, etc. are standar names for those values, keep them
    # pylint: disable=invalid-name
    @staticmethod
    def _parse_asn1_private_key(private_key_parser, key_type):
        version = private_key_parser.getChild(0).value[0]
        if version != 0:
            raise SyntaxError("Unrecognized RSAPrivateKey version")
        n = bytesToNumber(private_key_parser.getChild(1).value)
        e = bytesToNumber(private_key_parser.getChild(2).value)
        d = bytesToNumber(private_key_parser.getChild(3).value)
        p = bytesToNumber(private_key_parser.getChild(4).value)
        q = bytesToNumber(private_key_parser.getChild(5).value)
        dP = bytesToNumber(private_key_parser.getChild(6).value)
        dQ = bytesToNumber(private_key_parser.getChild(7).value)
        qInv = bytesToNumber(private_key_parser.getChild(8).value)
        return Python_RSAKey(n, e, d, p, q, dP, dQ, qInv, key_type)
    # pylint: enable=invalid-name
