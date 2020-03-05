# Author: Ivan Nikolchev
# See the LICENSE file for legal information regarding use of this file.

"""AESGCM with CTR from m2crypto"""

from tlslite.utils.cryptomath import m2cryptoLoaded
from tlslite.utils.aesgcm import AESGCM
from tlslite.utils import openssl_aes
from tlslite.utils.rijndael import Rijndael

if m2cryptoLoaded:
    def new(key):
        aesgcm = AESGCM(key, "openssl", Rijndael(key, 16).encrypt)
        aesgcm._ctr = openssl_aes.new(key, 6, bytearray(b'\x00' * 16))
        return aesgcm
