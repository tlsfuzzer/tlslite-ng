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
        if (n and not e) or (e and not n):
            raise AssertionError()
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dP = dP
        self.dQ = dQ
        self.qInv = qInv
        self.blinder = 0
        self.unblinder = 0
        self._lock = threading.Lock()

    def hasPrivateKey(self):
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

    def acceptsPassword(self): return False

    def generate(bits):
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
    generate = staticmethod(generate)

    @staticmethod
    def parsePEM(s, passwordCallback=None):
        """Parse a string containing a PEM-encoded <privateKey>."""
        from .python_key import Python_Key
        return Python_Key.parsePEM(s, passwordCallback)
