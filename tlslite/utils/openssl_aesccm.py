# Author: Ivan Nikolchev
# See the LICENSE file for legal information regarding use of this file.

"""AESCCM with CTR and CBC from m2crypto"""

from tlslite.utils.cryptomath import m2cryptoLoaded
from tlslite.utils.aesccm import AESCCM
from tlslite.utils import openssl_aes
from tlslite.utils.rijndael import Rijndael

if m2cryptoLoaded:
    def new(key, tagLength=16):
        aesccm = AESCCM(key, "openssl", tagLength)
        aesccm._ctr = openssl_aes.new(key, 6, bytearray(b'\x00' * 16))
        aesccm._cbc = openssl_aes.new(key, 2, bytearray(b'\x00' * 16))
        return aesccm
