
from .ecdsakey import ECDSAKey
from ecdsa.util import sigencode_der, sigdecode_der
from .tlshashlib import new

class Python_ECDSAKey(ECDSAKey):
    def __init__(self, public_key, private_key=None):
        if not public_key and private_key:
            self.public_key = private_key.get_verifying_key()
        else:
            self.public_key = public_key

        self.private_key = private_key

    def hasPrivateKey(self):
        return bool(self.private_key)

    def acceptsPassword(self):
        return False

    def generate(bits):
        raise NotImplementedError()

    def _sign(self, data):
        return private_key.sign_digest_deterministic(data,
                                                     sigencode=sigencode_der)

    def _hashAndSign(self, data, hAlg):
        return private_key.sign_deterministic(data,
                                              hash=new(hAlg),
                                              sigencode=sigencode_der)

    def _verify(self, signature, hash_bytes):
        return self.public_key.verify_digest(signature, hash_bytes,
                                             sigdecode_der)
