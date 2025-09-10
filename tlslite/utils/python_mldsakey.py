from .mldsakey import MLDSAKey
from ecdsa.der import UnexpectedDER
from .compat import ML_DSA_AVAILABLE


if ML_DSA_AVAILABLE:
    from dilithium_py.ml_dsa.default_parameters import ML_DSA_44, ML_DSA_65, \
            ML_DSA_87


    class Python_MLDSAKey(MLDSAKey):
        """
        Concrete implementation of MLDSA object backed by dilithium-py.
        """
        def __init__(self, public_key, private_key=None):
            self.mldsa, self.public_key = public_key
            if private_key:
                mldsa, self.private_key = private_key
                assert mldsa == self.mldsa

            if self.mldsa is ML_DSA_44:
                self.key_type = "mldsa44"
            elif self.mldsa is ML_DSA_65:
                self.key_type = "mldsa65"
            else:
                assert self.mldsa is ML_DSA_87
                self.key_type = "mldsa87"

        def __len__(self):
            return len(self.public_key)

        def hasPrivateKey(self):
            return bool(self.private_key)

        def acceptsPassword(self):
            return False

        @staticmethod
        def generate(bits):
            raise NotImplementedError()

        def _hashAndSign(self, data):
            return self.mldsa.sign(self.private_key, data)

        def _hashAndVerify(self, signature, data):
            return self.mldsa.verify(self.public_key, data, signature)
