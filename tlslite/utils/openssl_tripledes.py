# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""OpenSSL/M2Crypto 3DES implementation."""

from .cryptomath import *
from .tripledes import *

if m2cryptoLoaded:

    def new(key, mode, IV):
        return OpenSSL_TripleDES(key, mode, IV)

    class OpenSSL_TripleDES(TripleDES):

        def __init__(self, key, mode, IV):
            TripleDES.__init__(self, key, mode, IV, "openssl")
            cipherType = m2.des_ede3_cbc()
            self.encrypt_context = m2.cipher_ctx_new()
            self.decrypt_context = m2.cipher_ctx_new()
            m2.cipher_init(self.encrypt_context, cipherType, key, IV, 1)
            m2.cipher_init(self.decrypt_context, cipherType, key, IV, 0)
            m2.cipher_set_padding(self.encrypt_context, 0)
            m2.cipher_set_padding(self.decrypt_context, 0)

        def encrypt(self, plaintext):
            TripleDES.encrypt(self, plaintext)
            ciphertext = m2.cipher_update(self.encrypt_context, plaintext)
            return bytearray(ciphertext)

        def decrypt(self, ciphertext):
            TripleDES.decrypt(self, ciphertext)
            plaintext = m2.cipher_update(self.decrypt_context, ciphertext)
            return bytearray(plaintext)

        def __del__(self):
            m2.cipher_ctx_free(self.encrypt_context)
            m2.cipher_ctx_free(self.decrypt_context)
