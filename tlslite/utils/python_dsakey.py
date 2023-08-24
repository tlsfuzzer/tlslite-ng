# Author: Frantisek Krenzelok
"""Pure-Python RSA implementation."""
from ecdsa.der import encode_sequence, encode_integer,  \
    remove_sequence, remove_integer

from .cryptomath import getRandomNumber, getRandomPrime,    \
    powMod, numBits, bytesToNumber, invMod,   \
    secureHash, GMPY2_LOADED, gmpyLoaded

from .compat import compatHMAC

if GMPY2_LOADED:
    from gmpy2 import mpz
elif gmpyLoaded:
    from gmpy import mpz

from .dsakey import DSAKey

class Python_DSAKey(DSAKey):
    """
    Concrete implementaion of DSA object.
    for func docstring see tlslite/dsakey.py
    """
    def __init__(self, p=0, q=0, g=0, x=0, y=0):
        if gmpyLoaded or GMPY2_LOADED:
            p = mpz(p)
            q = mpz(q)
            g = mpz(g)
            x = mpz(x)
            y = mpz(y)
        self.p = p
        self.q = q
        self.g = g
        self.private_key = x
        self.public_key = y
        if self.private_key and not self.public_key:
            self.public_key = powMod(g, self.private_key, p)
        self.key_type = "dsa"

    def __len__(self):
        return numBits(self.p)

    def hasPrivateKey(self):
        return bool(self.private_key)

    @staticmethod
    def generate(L, N):
        assert (L, N) in [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
        key = Python_DSAKey()
        (q, p) = Python_DSAKey.generate_qp(L, N)

        index = getRandomNumber(1, (p-1))
        g = powMod(index, int((p-1)/q), p)
        x = getRandomNumber(1, q-1)
        y = powMod(g, x, p)
        if gmpyLoaded or GMPY2_LOADED:
            p = mpz(p)
            q = mpz(q)
            g = mpz(g)
            x = mpz(x)
            y = mpz(y)
        key.q = q
        key.p = p
        key.g = g
        key.private_key = x
        key.public_key = y
        return key

    @staticmethod
    def generate_qp(L, N):
        assert (L, N) in [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]

        q = int(getRandomPrime(N))
        while True:
            p = int(getRandomPrime(L))
            if (p-1) % q:
                break
        return (q, p)

    def hashAndSign(self, data, hAlg="sha1"):
        hashData = (secureHash(bytearray(data), hAlg))
        return self.sign(hashData)

    def sign(self, data, padding=None, hashAlg=None, saltLen=None):
        """
        :type data: bytearray
        :param data: The value which will be signed (generally a binary
            encoding of hash output.

        :type padding: str
        :param padding: Ignored, present for API compatibility with RSA

        :type hashAlg: str
        :param hashAlg: name of hash that was used for calculating the bytes

        :type saltLen: int
        :param saltLen: Ignored, present for API compatibility with RSA
        """
        N = numBits(self.q)
        digest_len = len(data) * 8
        digest = bytesToNumber(data)
        if N < digest_len:
            digest >>= digest_len - N

        k = getRandomNumber(1, (self.q-1))
        if gmpyLoaded or GMPY2_LOADED:
            k = mpz(k)
            digest = mpz(digest)
        r = powMod(self.g, k, self.p) % self.q
        s = invMod(k, self.q) * (digest + self.private_key * r) % self.q

        return encode_sequence(encode_integer(r), encode_integer(s))

    def verify(self, signature, hashData, padding=None, hashAlg=None,
               saltLen=None):
        """Verify the passed-in bytes with the signature.

        This verifies a DSA signature on the passed-in data.

        :type signature: bytearray
        :param signature: The signature.

        :type hashData: bytearray
        :param hashData: The value which will be verified.

        :type padding: str
        :param padding: Ignored, present for API compatibility with RSA

        :type hashAlg: str
        :param hashAlg: Ignored, present for API compatibility with RSA

        :type saltLen: str
        :param saltLen: Ignored, present for API compatibility with RSA

        :rtype: bool
        :returns: Whether the signature matches the passed-in data.
        """
        N = numBits(self.q)
        digest_len = len(hashData) * 8
        digest = bytesToNumber(hashData)

        if N < digest_len:
            digest >>= digest_len - N

        signature = compatHMAC(signature)

        # get r, s keys
        if not signature:
            return False
        body, rest = remove_sequence(signature)
        if rest:
            return False
        r, rest = remove_integer(body)
        s, rest = remove_integer(rest)
        if rest:
            return False

        if gmpyLoaded or GMPY2_LOADED:
            r = mpz(r)
            s = mpz(s)

        # check the signature
        if 0 < r < self.q and 0 < s < self.q:
            w = invMod(s, self.q)
            u1 = (digest * w) % self.q
            u2 = (r * w) % self.q
            v = ((powMod(self.g, u1, self.p) * \
                  powMod(self.public_key, u2, self.p)) % self.p) % self.q
            return r == v
        return False

    def hashAndVerify(self, signature, data, hAlg="sha1"):
        digest = secureHash(bytearray(data), hAlg)
        return self.verify(signature, digest)
