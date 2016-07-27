# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest
from hypothesis import given, example
from hypothesis.strategies import integers
import math

from tlslite.utils.cryptomath import isPrime, numBits, numBytes, \
        numberToByteArray, MD5, SHA1, secureHash, HMAC_MD5, HMAC_SHA1, \
        HMAC_SHA256, HMAC_SHA384, HKDF_expand

class TestIsPrime(unittest.TestCase):
    def test_with_small_primes(self):
        self.assertTrue(isPrime(3))
        self.assertTrue(isPrime(5))
        self.assertTrue(isPrime(7))
        self.assertTrue(isPrime(11))

    def test_with_small_composites(self):
        self.assertFalse(isPrime(4))
        self.assertFalse(isPrime(6))
        self.assertFalse(isPrime(9))
        self.assertFalse(isPrime(10))

    def test_with_hard_primes_to_test(self):

        # XXX Rabin-Miller fails to properly detect following composites
        with self.assertRaises(AssertionError):
            for i in range(100):
                # OEIS A014233
                self.assertFalse(isPrime(2047))
                self.assertFalse(isPrime(1373653))
                self.assertFalse(isPrime(25326001))
                self.assertFalse(isPrime(3215031751))
                self.assertFalse(isPrime(2152302898747))
                self.assertFalse(isPrime(3474749660383))
                self.assertFalse(isPrime(341550071728321))
                self.assertFalse(isPrime(341550071728321))
                self.assertFalse(isPrime(3825123056546413051))
                self.assertFalse(isPrime(3825123056546413051))
                self.assertFalse(isPrime(3825123056546413051))

    def test_with_big_primes(self):
        # NextPrime[2^256]
        self.assertTrue(isPrime(115792089237316195423570985008687907853269984665640564039457584007913129640233))
        # NextPrime[2^1024]
        self.assertTrue(isPrime(179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137859))

    def test_with_big_composites(self):
        # NextPrime[2^256]-2 (factors: 71, 1559, 4801, 7703, 28286...8993)
        self.assertFalse(isPrime(115792089237316195423570985008687907853269984665640564039457584007913129640233-2))
        # NextPrime[2^256]+2 (factors: 3^2, 5, 7, 11, 1753, 19063..7643)
        self.assertFalse(isPrime(115792089237316195423570985008687907853269984665640564039457584007913129640233+2))
        # NextPrime[2^1024]-2
        self.assertFalse(isPrime(179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137859-2))
        # NextPrime[2^1024]+2
        self.assertFalse(isPrime(179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624224137859+2))
        # NextPrime[NextPrime[2^512]]*NextPrime[2^512]
        self.assertFalse(isPrime(179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639477074095512480796227391561801824887394139579933613278628104952355769470429079061808809522886423955917442317693387325171135071792698344550223571732405562649211))

class TestNumberToBytesFunctions(unittest.TestCase):
    def test_numberToByteArray(self):
        self.assertEqual(numberToByteArray(0x00000000000001),
                         bytearray(b'\x01'))

    def test_numberToByteArray_with_MSB_number(self):
        self.assertEqual(numberToByteArray(0xff),
                         bytearray(b'\xff'))

    def test_numberToByteArray_with_length(self):
        self.assertEqual(numberToByteArray(0xff, 2),
                         bytearray(b'\x00\xff'))

    def test_numberToByteArray_with_not_enough_length(self):
        self.assertEqual(numberToByteArray(0x0a0b0c, 2),
                         bytearray(b'\x0b\x0c'))

class TestNumBits(unittest.TestCase):

    @staticmethod
    def num_bits(number):
        if number == 0:
            return 0
        return len(bin(number).lstrip('-0b'))

    @staticmethod
    def num_bytes(number):
        if number == 0:
            return 0
        return (TestNumBits.num_bits(number) + 7) // 8

    @given(integers(min_value=0, max_value=1<<16384))
    @example(0)
    @example(255)
    @example(256)
    @example((1<<1024)-1)
    @example((1<<521)-1)
    @example(1<<8192)
    @example((1<<8192)-1)
    def test_numBits(self, number):
        self.assertEqual(numBits(number), self.num_bits(number))

    @given(integers(min_value=0, max_value=1<<16384))
    @example(0)
    @example(255)
    @example(256)
    @example((1<<1024)-1)
    @example((1<<521)-1)
    @example(1<<8192)
    @example((1<<8192)-1)
    def test_numBytes(self, number):
        self.assertEqual(numBytes(number), self.num_bytes(number))

class TestHMACMethods(unittest.TestCase):
    def test_HMAC_MD5(self):
        self.assertEqual(HMAC_MD5(b'abc', b'def'),
                         bytearray(b'\xde\xbd\xa7{|\xc3\xe7\xa1\x0e\xe7'
                                   b'\x01\x04\xe6qzk'))

    def test_HMAC_SHA1(self):
        self.assertEqual(HMAC_SHA1(b'abc', b'def'),
                         bytearray(b'\x12UN\xab\xba\xf7\xe8\xe1.G7\x02'
                                   b'\x0f\x98|\xa7\x90\x10\x16\xe5'))

    def test_HMAC_SHA256(self):
        self.assertEqual(HMAC_SHA256(b'abc', b'def'),
                         bytearray(b' \xeb\xc0\xf0\x93DG\x014\xf3P@\xf6>'
                                   b'\xa9\x8b\x1d\x8eAB\x12\x94\x9e\xe5\xc5\x00B'
                                   b'\x9d\x15\xea\xb0\x81'))

    def test_HMAC_SHA384(self):
        self.assertEqual(HMAC_SHA384(b'abc', b'def'),
                         bytearray(b'\xec\x14\xd6\x94\x86\tHp\x84\x07\xect\x0e\t~'
                                   b'\x85?\xe8\xfd\xba\xd4\x86s\x05\xaa\xe8\xfcB\xd0'
                                   b'\xe8\xaa\xa6V\xe07\x9e\xc5\xc9n\x15\x97\xe0\xbc'
                                   b'\xefZ\xa6\xdb\x05'))

    def test_HMAC_expand_1(self):
        self.assertEqual(HKDF_expand(numberToByteArray(int('0x077709362c2e32df0ddc3f0dc4'
                                                           '7bba6390b6c73bb50f9c3122ec84'
                                                           '4ad7c2b3e5', 16), 32),
                                     numberToByteArray(0xf0f1f2f3f4f5f6f7f8f9, 10), 42,
                                     'sha256'),
                         numberToByteArray(int('0x3cb25f25faacd57a90434f64d0362f2a2d2d0a'
                                               '90cf1a5a4c5db02d56ecc4c5bf34007208d5b887'
                                               '185865', 16), 42))

    def test_HMAC_expand_2(self):
        self.assertEqual(HKDF_expand(numberToByteArray(int('0x06a6b88c5853361a06104c9ceb'
                                                           '35b45cef760014904671014a193f'
                                                           '40c15fc244', 16), 32),
                                     numberToByteArray(int('0xb0b1b2b3b4b5b6b7b8b9babbbc'
                                                           'bdbebfc0c1c2c3c4c5c6c7c8c9ca'
                                                           'cbcccdcecfd0d1d2d3d4d5d6d7d8'
                                                           'd9dadbdcdddedfe0e1e2e3e4e5e6'
                                                           'e7e8e9eaebecedeeeff0f1f2f3f4'
                                                           'f5f6f7f8f9fafbfcfdfeff', 16),
                                                       80), 82, 'sha256'),
                         numberToByteArray(int('0xb11e398dc80327a1c8e7f78c596a49344f012e'
                                               'da2d4efad8a050cc4c19afa97c59045a99cac782'
                                               '7271cb41c65e590e09da3275600c2f09b8367793'
                                               'a9aca3db71cc30c58179ec3e87c14c01d5c1f343'
                                               '4f1d87', 16), 82))

    def test_HMAC_expand_3(self):
        self.assertEqual(HKDF_expand(numberToByteArray(int('0x19ef24a32c717b167f33a91d6f'
                                                           '648bdf96596776afdb6377ac434c'
                                                           '1c293ccb04', 16),
                                                       32), bytearray(), 42, 'sha256'),
                         numberToByteArray(int('0x8da4e775a563c18f715f802a063c5a31b8a11f'
                                               '5c5ee1879ec3454e5f3c738d2d9d201395faa4b6'
                                               '1a96c8', 16), 42))

    def test_HMAC_expand_4(self):
        self.assertEqual(HKDF_expand(numberToByteArray(int('0x9b6c18c432a7bf8f0e71c8eb88'
                                                           'f4b30baa2ba243', 16), 20),
                                     numberToByteArray(int('0xf0f1f2f3f4f5f6f7f8f9', 16),
                                                       10), 42, 'sha1'),
                         numberToByteArray(int('0x085a01ea1b10f36933068b56efa5ad81a4f14b'
                                               '822f5b091568a9cdd4f155fda2c22e422478d305'
                                               'f3f896', 16), 42))

    def test_HMAC_expand_5(self):
        self.assertEqual(HKDF_expand(numberToByteArray(int('0x8adae09a2a307059478d309b26'
                                                           'c4115a224cfaf6', 16), 20),
                                     numberToByteArray(int('0xb0b1b2b3b4b5b6b7b8b9babbbc'
                                                           'bdbebfc0c1c2c3c4c5c6c7c8c9ca'
                                                           'cbcccdcecfd0d1d2d3d4d5d6d7d8'
                                                           'd9dadbdcdddedfe0e1e2e3e4e5e6'
                                                           'e7e8e9eaebecedeeeff0f1f2f3f4'
                                                           'f5f6f7f8f9fafbfcfdfeff', 16),
                                                       80), 82, 'sha1'),
                         numberToByteArray(int('0x0bd770a74d1160f7c9f12cd5912a06ebff6adc'
                                               'ae899d92191fe4305673ba2ffe8fa3f1a4e5ad79'
                                               'f3f334b3b202b2173c486ea37ce3d397ed034c7f'
                                               '9dfeb15c5e927336d0441f4c4300e2cff0d0900b'
                                               '52d3b4', 16), 82))

    def test_HMAC_expand_6(self):
        self.assertEqual(HKDF_expand(numberToByteArray(int('0xda8c8a73c7fa77288ec6f5e7c2'
                                                           '97786aa0d32d01', 16), 20),
                                     bytearray(), 42, 'sha1'),
                         numberToByteArray(int('0x0ac1af7002b3d761d1e55298da9d0506b9ae52'
                                               '057220a306e07b6b87e8df21d0ea00033de03984'
                                               'd34918', 16), 42))

    def test_HMAC_expand_7(self):
        self.assertEqual(HKDF_expand(numberToByteArray(int('0x2adccada18779e7c2077ad2eb1'
                                                           '9d3f3e731385dd', 16), 20),
                                     bytearray(), 42, 'sha1'),
                         numberToByteArray(int('0x2c91117204d745f3500d636a62f64f0ab3bae5'
                                               '48aa53d423b0d1f27ebba6f5e5673a081d70cce7'
                                               'acfc48', 16), 42))

class TestHashMethods(unittest.TestCase):
    def test_MD5(self):
        self.assertEqual(MD5(b"message digest"),
                         bytearray(b'\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d'
                                   b'\x52\x5a\x2f\x31\xaa\xf1\x61\xd0'))

    def test_SHA1(self):
        self.assertEqual(SHA1(b'abc'),
                         bytearray(b'\xA9\x99\x3E\x36'
                                   b'\x47\x06\x81\x6A'
                                   b'\xBA\x3E\x25\x71'
                                   b'\x78\x50\xC2\x6C'
                                   b'\x9C\xD0\xD8\x9D'))
    def test_SHA224(self):
        self.assertEqual(secureHash(b'abc', 'sha224'),
                         bytearray(b'\x23\x09\x7D\x22'
                                   b'\x34\x05\xD8\x22'
                                   b'\x86\x42\xA4\x77'
                                   b'\xBD\xA2\x55\xB3'
                                   b'\x2A\xAD\xBC\xE4'
                                   b'\xBD\xA0\xB3\xF7'
                                   b'\xE3\x6C\x9D\xA7'))

    def test_SHA256(self):
        self.assertEqual(secureHash(b'abc', 'sha256'),
                         bytearray(b'\xBA\x78\x16\xBF'
                                   b'\x8F\x01\xCF\xEA'
                                   b'\x41\x41\x40\xDE'
                                   b'\x5D\xAE\x22\x23'
                                   b'\xB0\x03\x61\xA3'
                                   b'\x96\x17\x7A\x9C'
                                   b'\xB4\x10\xFF\x61'
                                   b'\xF2\x00\x15\xAD'))

    def test_SHA384(self):
        self.assertEqual(secureHash(b'abc', 'sha384'),
                         bytearray(b'\xCB\x00\x75\x3F'
                                   b'\x45\xA3\x5E\x8B'
                                   b'\xB5\xA0\x3D\x69'
                                   b'\x9A\xC6\x50\x07'
                                   b'\x27\x2C\x32\xAB'
                                   b'\x0E\xDE\xD1\x63'
                                   b'\x1A\x8B\x60\x5A'
                                   b'\x43\xFF\x5B\xED'
                                   b'\x80\x86\x07\x2B'
                                   b'\xA1\xE7\xCC\x23'
                                   b'\x58\xBA\xEC\xA1'
                                   b'\x34\xC8\x25\xA7'))

    def test_SHA512(self):
        self.assertEqual(secureHash(b'abc', 'sha512'),
                         bytearray(b'\xDD\xAF\x35\xA1'
                                   b'\x93\x61\x7A\xBA'
                                   b'\xCC\x41\x73\x49'
                                   b'\xAE\x20\x41\x31'
                                   b'\x12\xE6\xFA\x4E'
                                   b'\x89\xA9\x7E\xA2'
                                   b'\x0A\x9E\xEE\xE6'
                                   b'\x4B\x55\xD3\x9A'
                                   b'\x21\x92\x99\x2A'
                                   b'\x27\x4F\xC1\xA8'
                                   b'\x36\xBA\x3C\x23'
                                   b'\xA3\xFE\xEB\xBD'
                                   b'\x45\x4D\x44\x23'
                                   b'\x64\x3C\xE8\x0E'
                                   b'\x2A\x9A\xC9\x4F'
                                   b'\xA5\x4C\xA4\x9F'))
