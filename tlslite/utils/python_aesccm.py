# Author: Ivan Nikolchev
# See the LICENSE file for legal information regarding use of this file.

""" Pure Python AES-CCM implementation."""

from tlslite.utils.aesccm import AESCCM
from tlslite.utils.rijndael import Rijndael

def new(key, tagLength=16):
    return AESCCM(key, "python", Rijndael(key, 16).encrypt, tagLength)
