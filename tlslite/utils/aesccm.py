# Copyright (c) 2019 Ivan Nikolchev
#
# See the LICENSE file for legal information regarding use of this file.
#

from __future__ import division
from tlslite.utils.rijndael import Rijndael
from tlslite.utils.cryptomath import bytesToNumber, numberToByteArray
from tlslite.utils.python_aes import Python_AES
import struct
import binascii

class AESCCM(object):
    # AES-CCM implementation per RFC3610

    def __init__(self, key, implementation, rawAesEncrypt, tagLength=16):
        self.isBlockCipher = False
        self.isAEAD = True
        self.key = key
        if len(self.key) == 16 and tagLength == 8:
            self.name = "aes128ccm_8"
        elif len(self.key) == 16:
            self.name = "aes128ccm"
        elif len(self.key) == 32 and tagLength == 8:
            self.name = "aes256ccm_8"
        elif len(self.key) == 32:
            self.name = "aes256ccm"
        else:
            raise AssertionError()
        self.rawAesEncrypt = rawAesEncrypt
        self.implementation = implementation
        self.nonceLength = 12
        self.tagLength = tagLength


    def _pad_with_zeroes(self, data):
        if len(data) % 16 != 0:
            zeroes_to_add = 16 - (len(data) % 16)
            data += b'\x00' * zeroes_to_add

    def _cbcmac_calc(self, nonce, aad, msg):
        L = 15 - len(nonce)
        mac_data = bytearray()

        flags = 64 * (len(aad) > 0)
        flags += 8 * ((self.tagLength - 2) // 2)
        flags += 1 * (L - 1)

        # Construct B_0
        b_0 = bytearray([flags]) + nonce + numberToByteArray(len(msg), L)

        aad_len_encoded = bytearray()
        if len(aad) > 0:
            if len(aad) < (2 ** 16 - 2 ** 8):
                oct_size = 2
            elif len(aad) < (2 ** 32):
                oct_size = 4
                aad_len_encoded = b'\xFF\xFE'
            else:
                oct_size = 8
                aad_len_encoded = b'\xFF\xFF'

            aad_len_encoded += numberToByteArray(len(aad), oct_size)

        # Construct the bytearray that goes into the MAC
        mac_data += b_0
        mac_data += aad_len_encoded
        mac_data += aad

        # We need to pad with zeroes before and after msg blocks are added
        self._pad_with_zeroes(mac_data)
        mac_data += msg
        self._pad_with_zeroes(mac_data)

        # The mac data is now constructed and
        # we need to run in through AES-CBC with 0 IV

        cbc = Python_AES(self.key, 2, bytearray(b'\x00' * 16))
        cbcmac = cbc.encrypt(mac_data)

        # If the tagLength has default value 16, we return the whole last block,
        # otherwise we return only the first tagLength bytes from the last block
        if self.tagLength == 16:
            t = cbcmac[-16:]
        else:
            t = cbcmac[-16:-(16-self.tagLength)]
        return t



    def seal(self, nonce, msg, aad):
        if len(nonce) != 12:
            raise ValueError("Bad nonce length")

        L = 15 - len(nonce)
        auth_value = bytearray(self.tagLength)
        s_n = bytearray()

        # We construct the key stream blocks.
        # S_0 is not used for encrypting the message, it is only used
        # to compute the authentication value.
        # S_1..S_n are used to encrypt the message.

        flags = L - 1
        s_0 = self.rawAesEncrypt(bytearray([flags]) +
              nonce + numberToByteArray(0, L))

        if len(msg) % 16 == 0:
            counter_lmt = len(msg) / 16
        else:
            counter_lmt = (len(msg) /16) + 1

        for i in range(1, int(counter_lmt) + 1):
            s_n += self.rawAesEncrypt(bytearray([flags]) +
                   nonce + numberToByteArray(i, L))

        enc_msg = bytearray(len(msg))

        for i in range(0, len(msg)):
            enc_msg[i] = msg[i] ^ s_n[i]

        mac = self._cbcmac_calc(nonce, aad, msg)

        for i in range(0, self.tagLength):
            auth_value[i] = mac[i] ^ s_0[i]

        ciphertext = enc_msg + auth_value
        return ciphertext


    def open(self, nonce, ciphertext, aad):

        if len(nonce) != 12:
            raise ValueError("Bad nonce length")
        if len(ciphertext) < 16:
            return None

        s_n = bytearray()
        L = 15 - len(nonce)
        received_mac = bytearray(self.tagLength)
        flags = L - 1

        # Same construction as in seal function

        s_0 = self.rawAesEncrypt(bytearray([flags]) +
              nonce + numberToByteArray(0, L))

        msg = bytearray(len(ciphertext) - self.tagLength)

        if len(ciphertext) % 16 == 0:
            counter_lmt = len(ciphertext) / 16
        else:
            counter_lmt = (len(ciphertext) /16) + 1

        for i in range(1, int(counter_lmt) + 1):
            s_n += self.rawAesEncrypt(bytearray([flags]) +
                   nonce + numberToByteArray(i, L))

        # We decrypt the message
        for i in range(0, len(ciphertext) - self.tagLength):
            msg[i] = ciphertext[i] ^ s_n[i]

        auth_value = ciphertext[-self.tagLength:]
        computed_mac = self._cbcmac_calc(nonce, aad ,msg)

        # We decrypt the auth value
        for i in range(0, self.tagLength):
            received_mac[i] = auth_value[i] ^ s_0[i]

        # Compare the mac vlaue is the same as the one we computed
        if received_mac != computed_mac:
            return None
        return msg
