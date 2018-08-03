# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Pure-Python AES implementation."""

from .aes import AES
from .rijndael import Rijndael


__all__ = ['new', 'Python_AES']


def new(key, mode, IV):
    return Python_AES(key, mode, IV)


class Python_AES(AES):
    def __init__(self, key, mode, IV):
        super(Python_AES, self).__init__(key, mode, IV, "python")
        self.rijndael = Rijndael(key, 16)
        self.IV = IV

    def encrypt(self, plaintext):
        super(Python_AES, self).encrypt(plaintext)

        plaintextBytes = plaintext[:]
        chainBytes = self.IV[:]

        #CBC Mode: For each block...
        for x in range(len(plaintextBytes)//16):

            #XOR with the chaining block
            blockBytes = plaintextBytes[x*16 : (x*16)+16]
            for y in range(16):
                blockBytes[y] ^= chainBytes[y]

            #Encrypt it
            encryptedBytes = self.rijndael.encrypt(blockBytes)

            #Overwrite the input with the output
            for y in range(16):
                plaintextBytes[(x*16)+y] = encryptedBytes[y]

            #Set the next chaining block
            chainBytes = encryptedBytes

        self.IV = chainBytes[:]
        return plaintextBytes

    def decrypt(self, ciphertext):
        super(Python_AES, self).decrypt(ciphertext)

        ciphertextBytes = ciphertext[:]
        chainBytes = self.IV[:]

        #CBC Mode: For each block...
        for x in range(len(ciphertextBytes)//16):

            #Decrypt it
            blockBytes = ciphertextBytes[x*16 : (x*16)+16]
            decryptedBytes = self.rijndael.decrypt(blockBytes)

            #XOR with the chaining block and overwrite the input with output
            for y in range(16):
                decryptedBytes[y] ^= chainBytes[y]
                ciphertextBytes[(x*16)+y] = decryptedBytes[y]

            #Set the next chaining block
            chainBytes = blockBytes

        self.IV = chainBytes[:]
        return ciphertextBytes
