# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Pure-Python RSA implementation."""
import threading
from .cryptomath import *
from .asn1parser import ASN1Parser
from .rsakey import *
from .pem import *

class Python_RSAKey(RSAKey):
    def __init__(self, n=0, e=0, d=0, p=0, q=0, dP=0, dQ=0, qInv=0):
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

    def hasPrivateKey(self):
        """
        Does the key has the associated private key (True) or is it only
        the public part (False).
        """
        return self.d != 0

    def _rawPrivateKeyOp(self, m):
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
        m = (m * blinder) % self.n

        # Perform the RSA operation
        c = self._rawPrivateKeyOpHelper(m)

        # Unblind the output
        c = (c * unblinder) % self.n

        # Return the output
        return c

    def _rawPrivateKeyOpHelper(self, m):
        #Non-CRT version
        #c = powMod(m, self.d, self.n)

        #CRT version  (~3x faster)
        s1 = powMod(m, self.dP, self.p)
        s2 = powMod(m, self.dQ, self.q)
        h = ((s1 - s2) * self.qInv) % self.p
        c = s2 + self.q * h
        return c

    def _rawPublicKeyOp(self, c):
        m = powMod(c, self.e, self.n)
        return m

    def acceptsPassword(self):
        """Does it support encrypted key files."""
        return False

    @staticmethod
    def generate(bits):
        """Generate a private key with modulus 'bits' bit big."""
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
        return key

    @staticmethod
    def parsePEM(s, passwordCallback=None):
        """Parse a string containing a PEM-encoded <privateKey>."""
        if pemSniff(s, "PRIVATE KEY"):
            data = dePem(s, "PRIVATE KEY")
            return Python_RSAKey._parsePKCS8(data)
        elif pemSniff(s, "RSA PRIVATE KEY"):
            data = dePem(s, "RSA PRIVATE KEY")
            return Python_RSAKey._parseSSLeay(data)
        else:
            raise SyntaxError("Not a PEM private key file")

    @staticmethod
    def _parsePKCS8(data):
        p = ASN1Parser(data)

        # first element in PrivateKeyInfo is an INTEGER
        version = p.getChild(0).value
        if bytesToNumber(version) != 0:
            raise SyntaxError("Unrecognized PKCS8 version")

        # second element in PrivateKeyInfo is a SEQUENCE of type
        # AlgorithmIdentifier
        algIdent = p.getChild(1)
        seqLen = algIdent.getChildCount()
        # first item of AlgorithmIdentifier is an OBJECT (OID)
        oid = algIdent.getChild(0)
        if list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 1]:
            keyType = "rsa"
        elif list(oid.value) == [42, 134, 72, 134, 247, 13, 1, 1, 10]:
            keyType = "rsa-pss"
        else:
            raise SyntaxError("Unrecognized AlgorithmIdentifier: {0}"
                              .format(list(oid.value)))
        # second item of AlgorithmIdentifier are parameters (defined by
        # above algorithm)
        if keyType == "rsa":
            if seqLen != 2:
                raise SyntaxError("Missing parameters for RSA algorithm ID")
            parameters = algIdent.getChild(1)
            if parameters.value != bytearray(0):
                raise SyntaxError("RSA parameters are not NULL")
        else:  # rsa-pss
            pass  # ignore parameters - don't apply restrictions

        if seqLen > 2:
            raise SyntaxError("Invalid encoding of AlgorithmIdentifier")

        #Get the privateKey
        privateKeyP = p.getChild(2)

        #Adjust for OCTET STRING encapsulation
        privateKeyP = ASN1Parser(privateKeyP.value)

        return Python_RSAKey._parseASN1PrivateKey(privateKeyP)

    @staticmethod
    def _parseSSLeay(data):
        privateKeyP = ASN1Parser(data)
        return Python_RSAKey._parseASN1PrivateKey(privateKeyP)

    @staticmethod
    def _parseASN1PrivateKey(privateKeyP):
        version = privateKeyP.getChild(0).value[0]
        if version != 0:
            raise SyntaxError("Unrecognized RSAPrivateKey version")
        n = bytesToNumber(privateKeyP.getChild(1).value)
        e = bytesToNumber(privateKeyP.getChild(2).value)
        d = bytesToNumber(privateKeyP.getChild(3).value)
        p = bytesToNumber(privateKeyP.getChild(4).value)
        q = bytesToNumber(privateKeyP.getChild(5).value)
        dP = bytesToNumber(privateKeyP.getChild(6).value)
        dQ = bytesToNumber(privateKeyP.getChild(7).value)
        qInv = bytesToNumber(privateKeyP.getChild(8).value)
        return Python_RSAKey(n, e, d, p, q, dP, dQ, qInv)
