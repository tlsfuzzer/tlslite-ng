from .dsakey import DSAKey
from .cryptomath import *

class Python_DSAKey(DSAKey):

    def __init__(self, p = 0, q = 0, g = 0, A = 0, a = 0):
        # TODO: add asserts
        self.p = p
        self.q = q
        self.g = g
        self.private_key = a
        self.public_key = A
        self.key_type = "dsa"


    def __len__(self):
        return numBits(self.public_key)

    def hasPrivateKey(self):
        return bool(self.private_key)

    @staticmethod
    def generate(L, N):
        # TODO: add asserts
        key = Python_DSAKey()
        (q,p) = Python_DSAKey.generate_qp(L, N)

        x = getRandomNumber(1, (p-1))
        g = powMod(x,((p-1)/q),p)
        a = getRandomNumber(1,q-1)
        A = powMod(g, a, p)
        key.q = q
        key.p = p
        key.g = g
        key.private_key = a
        key.public_key = A
        return key

    @staticmethod
    def generate_qp(L, N):
        # TODO: optimize
        q = getRandomPrime(N)
        while True:
            p = getRandomPrime(L)
            if ((p-1) % q):
                break
        return (q, p)


    def hashAndSign(self, data, hAlg = "sha1"):
        # TODO: add assert for hash size < (q-1) constrain
        hashBytes = secureHash(bytearray(data), hAlg)
        k = getRandomNumber(1,(self.q-1))
        r = powMod(self.g, k, self.p) % self.q
        s = ((k ** -1) * (bytesToNumber(hashBytes) + self.private_key * r)) % self.q
        print(r,s)
        return (r, s)

    def verify(self, signature, hash_bytes):
        raise NotImplementedError

