
from .ecdsakey import ECDSAKey
from ecdsa.util import sigencode_der, sigdecode_der
from .tlshashlib import new, sha1, sha224, sha256, sha384, sha512
from .cryptomath import numBits

class Python_ECDSAKey(ECDSAKey):
    def __init__(self, public_key, private_key=None):
        if not public_key and private_key:
            self.public_key = private_key.get_verifying_key()
        else:
            self.public_key = public_key

        self.private_key = private_key
        self.key_type = "ecdsa"

    def __len__(self):
        return numBits(self.public_key.curve.order)

    def hasPrivateKey(self):
        return bool(self.private_key)

    def acceptsPassword(self):
        return False

    def generate(bits):
        raise NotImplementedError()

    def _sign(self, data, hAlg):
        if hAlg == "sha1":
            func = sha1
        elif hAlg == "sha224":
            func = sha224
        elif hAlg == "sha256":
            func = sha256
        elif hAlg == "sha384":
            func = sha384
        else:
            assert hAlg == "sha512"
            func = sha512

        return self.private_key.\
            sign_digest_deterministic(data,
                                      hashfunc=func,
                                      sigencode=sigencode_der)

    def _hashAndSign(self, data, hAlg):
        return self.private_key.sign_deterministic(data,
                                                   hash=new(hAlg),
                                                   sigencode=sigencode_der)

    def _verify(self, signature, hash_bytes):
        return self.public_key.verify_digest(signature, hash_bytes,
                                             sigdecode_der)
