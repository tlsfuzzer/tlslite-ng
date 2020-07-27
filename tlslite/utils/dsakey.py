

"""Abstract class for DSA."""

from .cryptomath import secureHash


class DSAKey(object):
    """This is an abstract base class for ECDSA keys.

    Particular implementations of ECDSA keys, such as
    :py:class:`~.python_ecdsakey.Python_ECDSAKey`
    ... more coming
    inherit from this.

    To create or parse an ECDSA key, don't use one of these classes
    directly.  Instead, use the factory functions in
    :py:class:`~tlslite.utils.keyfactory`.
    """

    def __init__(self, public_key, private_key):
        raise NotImplementedError()

    def __len__(self):
        raise NotImplementedError()

    def hasPrivateKey(self):
        raise NotImplementedError()

    def sign(self, data, hash_alg):
        raise NotImplementedError()

    def hashAndSign(self, data, hAlg):
        raise NotImplementedError()

    def verify(self, signature, hash_bytes):
        raise NotImplementedError()

    @staticmethod
    def generate(bits):
        raise NotImplementedError()
