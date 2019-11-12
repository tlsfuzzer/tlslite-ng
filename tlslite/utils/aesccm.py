# Copyright (c) 2019 Ivan Nikolchev
#
# See the LICENSE file for legal information regarding use of this file.
#

from __future__ import division
from tlslite.utils.cryptomath import numberToByteArray, divceil
from tlslite.utils.python_aes import Python_AES
import sys
import array


class AESCCM(object):
    # AES-CCM implementation per RFC3610

    def __init__(self, key, implementation, rawAesEncrypt, tag_length=16):
        self.isBlockCipher = False
        self.isAEAD = True
        self.key = key
        self.tagLength = tag_length
        if len(self.key) == 16 and self.tagLength == 8:
            self.name = "aes128ccm_8"
        elif len(self.key) == 16 and self.tagLength == 16:
            self.name = "aes128ccm"
        elif len(self.key) == 32 and self.tagLength == 8:
            self.name = "aes256ccm_8"
        else:
            assert len(self.key) == 32 and self.tagLength == 16
            self.name = "aes256ccm"
        self._rawAesEncrypt = rawAesEncrypt
        self.implementation = implementation
        self.nonceLength = 12
        self._cbc = Python_AES(self.key, 2, bytearray(b'\x00' * 16))

    def _cbcmac_calc(self, nonce, aad, msg):
        L = 15 - len(nonce)
        mac_data = bytearray()

        # Flags constructed as in section 2.2 in the rfc
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
        self._pad_with_zeroes(mac_data, 16)
        if msg != b'':
            mac_data += msg
            self._pad_with_zeroes(mac_data, 16)

        # The mac data is now constructed and
        # we need to run in through AES-CBC with 0 IV

        self._cbc.IV = bytearray(b'\x00' * 16)
        cbcmac = self._cbc.encrypt(mac_data)

        # If the tagLength has default value 16, we return
        # the whole last block. Otherwise we return only
        # the first tagLength bytes from the last block
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

        # We construct the key stream blocks.
        # S_0 is not used for encrypting the message, it is only used
        # to compute the authentication value.
        # S_1..S_n are used to encrypt the message.

        flags = L - 1
        s_0 = self._rawAesEncrypt(bytearray([flags]) +
              nonce + numberToByteArray(0, L))

        s_n = self._construct_s_n(msg, flags, nonce, L)

        enc_msg = self._xor(msg, s_n)

        mac = self._cbcmac_calc(nonce, aad, msg)

        for i in range(self.tagLength):
            auth_value[i] = mac[i] ^ s_0[i]

        ciphertext = enc_msg + auth_value
        return ciphertext

    def open(self, nonce, ciphertext, aad):

        if len(nonce) != 12:
            raise ValueError("Bad nonce length")
        if self.tagLength == 16 and len(ciphertext) < 16:
            return None
        if self.tagLength == 8 and len(ciphertext) < 8:
            return None

        L = 15 - len(nonce)
        received_mac = bytearray(self.tagLength)
        flags = L - 1

        # Same construction as in seal function

        s_0 = self._rawAesEncrypt(bytearray([flags]) +
              nonce + numberToByteArray(0, L))

        s_n = self._construct_s_n(ciphertext, flags, nonce, L)

        msg = self._xor(ciphertext, s_n)
        msg = msg[:-self.tagLength]

        auth_value = ciphertext[-self.tagLength:]
        computed_mac = self._cbcmac_calc(nonce, aad, msg)

        # We decrypt the auth value
        for i in range(self.tagLength):
            received_mac[i] = auth_value[i] ^ s_0[i]

        # Compare the mac vlaue is the same as the one we computed
        if received_mac != computed_mac:
            return None
        return msg

    def _construct_s_n(self, ciphertext, flags, nonce, L):
        s_n = bytearray()
        counter_lmt = divceil(len(ciphertext), 16)
        for i in range(1, int(counter_lmt) + 1):
            s_n += self._rawAesEncrypt(bytearray([flags]) +
                   nonce + numberToByteArray(i, L))
        return s_n

    if sys.version_info[0] >= 3:
        def _xor(self, inp, s_n):
            inp_added = -((8 - (len(inp) % 8)) % 8) or None
            self._pad_with_zeroes(inp, 8)
            msg = self._use_memoryview(inp, s_n)[:inp_added]
            inp[:] = inp[:inp_added]
            return msg
    else:
        def _xor(self, inp, s_n):
            msg = bytearray(i ^ j for i, j in zip(inp, s_n))
            return msg

    @staticmethod
    def _pad_with_zeroes(data, size):
        if len(data) % size != 0:
            zeroes_to_add = size - (len(data) % size)
            data += b'\x00' * zeroes_to_add

    @staticmethod
    def _use_memoryview(msg, s_n):
        msg_mv = memoryview(msg).cast('Q')
        s_n_mv = memoryview(s_n).cast('Q')
        enc_arr = array.array('Q', (i ^ j for i, j in zip(msg_mv, s_n_mv)))
        enc_msg = bytearray(enc_arr.tobytes())
        return enc_msg
