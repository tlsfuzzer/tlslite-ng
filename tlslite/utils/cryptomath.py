# Authors: 
#   Trevor Perrin
#   Martin von Loewis - python 3 port
#   Yngve Pettersen (ported by Paul Sokolovsky) - TLS 1.2
#
# See the LICENSE file for legal information regarding use of this file.

"""cryptomath module

This module has basic math/crypto code."""
from __future__ import print_function
import os
import math
import base64
import binascii
import sys

from .compat import compat26Str, compatHMAC, compatLong, b2a_hex
from .codec import Writer


# **************************************************************************
# Load Optional Modules
# **************************************************************************

# Try to load M2Crypto/OpenSSL
try:
    from M2Crypto import m2
    m2cryptoLoaded = True

    try:
        with open('/proc/sys/crypto/fips_enabled', 'r') as fipsFile:
            if '1' in fipsFile.read():
                m2cryptoLoaded = False
    except (IOError, OSError):
        # looks like we're running in container, likely not FIPS mode
        m2cryptoLoaded = True

except ImportError:
    m2cryptoLoaded = False

#Try to load GMPY
try:
    import gmpy
    gmpyLoaded = True
except ImportError:
    gmpyLoaded = False

#Try to load pycrypto
try:
    import Crypto.Cipher.AES
    pycryptoLoaded = True
except ImportError:
    pycryptoLoaded = False


# **************************************************************************
# PRNG Functions
# **************************************************************************

# Check that os.urandom works
import zlib
assert len(zlib.compress(os.urandom(1000))) > 900

def getRandomBytes(howMany):
    b = bytearray(os.urandom(howMany))
    assert(len(b) == howMany)
    return b

prngName = "os.urandom"

# **************************************************************************
# Simple hash functions
# **************************************************************************

import hmac
from . import tlshashlib as hashlib

def MD5(b):
    """Return a MD5 digest of data"""
    return secureHash(b, 'md5')

def SHA1(b):
    """Return a SHA1 digest of data"""
    return secureHash(b, 'sha1')

def secureHash(data, algorithm):
    """Return a digest of `data` using `algorithm`"""
    hashInstance = hashlib.new(algorithm)
    hashInstance.update(compat26Str(data))
    return bytearray(hashInstance.digest())

def secureHMAC(k, b, algorithm):
    """Return a HMAC using `b` and `k` using `algorithm`"""
    k = compatHMAC(k)
    b = compatHMAC(b)
    return bytearray(hmac.new(k, b, getattr(hashlib, algorithm)).digest())

def HMAC_MD5(k, b):
    return secureHMAC(k, b, 'md5')

def HMAC_SHA1(k, b):
    return secureHMAC(k, b, 'sha1')

def HMAC_SHA256(k, b):
    return secureHMAC(k, b, 'sha256')

def HMAC_SHA384(k, b):
    return secureHMAC(k, b, 'sha384')

def HKDF_expand(PRK, info, L, algorithm):
    N = divceil(L, getattr(hashlib, algorithm)().digest_size)
    T = bytearray()
    Titer = bytearray()
    for x in range(1, N+2):
        T += Titer
        Titer = secureHMAC(PRK, Titer + info + bytearray([x]), algorithm)
    return T[:L]

def HKDF_expand_label(secret, label, hashValue, length, algorithm):
    """
    TLS1.3 key derivation function (HKDF-Expand-Label).

    :param bytearray secret: the key from which to derive the keying material
    :param bytearray label: label used to differentiate the keying materials
    :param bytearray hashValue: bytes used to "salt" the produced keying
        material
    :param int length: number of bytes to produce
    :param str algorithm: name of the secure hash algorithm used as the
        basis of the HKDF
    :rtype: bytearray
    """
    hkdfLabel = Writer()
    hkdfLabel.addTwo(length)
    hkdfLabel.addVarSeq(bytearray(b"tls13 ") + label, 1, 1)
    hkdfLabel.addVarSeq(hashValue, 1, 1)

    return HKDF_expand(secret, hkdfLabel.bytes, length, algorithm)

def derive_secret(secret, label, handshake_hashes, algorithm):
    """
    TLS1.3 key derivation function (Derive-Secret).

    :param bytearray secret: secret key used to derive the keying material
    :param bytearray label: label used to differentiate they keying materials
    :param HandshakeHashes handshake_hashes: hashes of the handshake messages
        or `None` if no handshake transcript is to be used for derivation of
        keying material
    :param str algorithm: name of the secure hash algorithm used as the
        basis of the HKDF algorithm - governs how much keying material will
        be generated
    :rtype: bytearray
    """
    if handshake_hashes is None:
        hs_hash = secureHash(bytearray(b''), algorithm)
    else:
        hs_hash = handshake_hashes.digest(algorithm)
    return HKDF_expand_label(secret, label, hs_hash,
                             getattr(hashlib, algorithm)().digest_size,
                             algorithm)

# **************************************************************************
# Converter Functions
# **************************************************************************

def bytesToNumber(b, endian="big"):
    """
    Convert a number stored in bytearray to an integer.

    By default assumes big-endian encoding of the number.
    """
    # if string is empty, consider it to be representation of zero
    # while it may be a bit unorthodox, it is the inverse of numberToByteArray
    # with default parameters
    if not b:
        return 0

    if endian == "big":
        return int(b2a_hex(b), 16)
    elif endian == "little":
        return int(b2a_hex(b[::-1]), 16)
    else:
        raise ValueError("Only 'big' and 'little' endian supported")

def numberToByteArray(n, howManyBytes=None, endian="big"):
    """
    Convert an integer into a bytearray, zero-pad to howManyBytes.

    The returned bytearray may be smaller than howManyBytes, but will
    not be larger.  The returned bytearray will contain a big- or little-endian
    encoding of the input integer (n). Big endian encoding is used by default.
    """
    if howManyBytes == None:
        howManyBytes = numBytes(n)
    if endian == "big":
        return bytearray((n >> i) & 0xff
                         for i in reversed(range(0, howManyBytes*8, 8)))
    elif endian == "little":
        return bytearray((n >> i) & 0xff
                         for i in range(0, howManyBytes*8, 8))
    else:
        raise ValueError("Only 'big' and 'little' endian supported")


def mpiToNumber(mpi):
    """Convert a MPI (OpenSSL bignum string) to an integer."""
    byte = bytearray(mpi)
    if byte[4] & 0x80:
        raise ValueError("Input must be a positive integer")
    return bytesToNumber(byte[4:])


def numberToMPI(n):
    b = numberToByteArray(n)
    ext = 0
    #If the high-order bit is going to be set,
    #add an extra byte of zeros
    if (numBits(n) & 0x7)==0:
        ext = 1
    length = numBytes(n) + ext
    b = bytearray(4+ext) + b
    b[0] = (length >> 24) & 0xFF
    b[1] = (length >> 16) & 0xFF
    b[2] = (length >> 8) & 0xFF
    b[3] = length & 0xFF
    return bytes(b)


# **************************************************************************
# Misc. Utility Functions
# **************************************************************************

def numBits(n):
    """Return number of bits necessary to represent the integer in binary"""
    if n==0:
        return 0
    if sys.version_info < (2, 7):
        # bit_length() was introduced in 2.7, and it is an order of magnitude
        # faster than the below code
        return len(bin(n))-2
    else:
        return n.bit_length()

def numBytes(n):
    """Return number of bytes necessary to represent the integer in bytes"""
    if n==0:
        return 0
    bits = numBits(n)
    return (bits + 7) // 8

# **************************************************************************
# Big Number Math
# **************************************************************************

def getRandomNumber(low, high):
    assert low < high
    howManyBits = numBits(high)
    howManyBytes = numBytes(high)
    lastBits = howManyBits % 8
    while 1:
        bytes = getRandomBytes(howManyBytes)
        if lastBits:
            bytes[0] = bytes[0] % (1 << lastBits)
        n = bytesToNumber(bytes)
        if n >= low and n < high:
            return n

def gcd(a,b):
    a, b = max(a,b), min(a,b)
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    return (a * b) // gcd(a, b)

#Returns inverse of a mod b, zero if none
#Uses Extended Euclidean Algorithm
def invMod(a, b):
    c, d = a, b
    uc, ud = 1, 0
    while c != 0:
        q = d // c
        c, d = d-(q*c), c
        uc, ud = ud - (q * uc), uc
    if d == 1:
        return ud % b
    return 0


if gmpyLoaded:
    def powMod(base, power, modulus):
        base = gmpy.mpz(base)
        power = gmpy.mpz(power)
        modulus = gmpy.mpz(modulus)
        result = pow(base, power, modulus)
        return compatLong(result)
else:
    powMod = pow


def divceil(divident, divisor):
    """Integer division with rounding up"""
    quot, r = divmod(divident, divisor)
    return quot + int(bool(r))


#Pre-calculate a sieve of the ~100 primes < 1000:
def makeSieve(n):
    sieve = list(range(n))
    for count in range(2, int(math.sqrt(n))+1):
        if sieve[count] == 0:
            continue
        x = sieve[count] * 2
        while x < len(sieve):
            sieve[x] = 0
            x += sieve[count]
    sieve = [x for x in sieve[2:] if x]
    return sieve

def isPrime(n, iterations=5, display=False, sieve=makeSieve(1000)):
    #Trial division with sieve
    for x in sieve:
        if x >= n: return True
        if n % x == 0: return False
    #Passed trial division, proceed to Rabin-Miller
    #Rabin-Miller implemented per Ferguson & Schneier
    #Compute s, t for Rabin-Miller
    if display: print("*", end=' ')
    s, t = n-1, 0
    while s % 2 == 0:
        s, t = s//2, t+1
    #Repeat Rabin-Miller x times
    a = 2 #Use 2 as a base for first iteration speedup, per HAC
    for count in range(iterations):
        v = powMod(a, s, n)
        if v==1:
            continue
        i = 0
        while v != n-1:
            if i == t-1:
                return False
            else:
                v, i = powMod(v, 2, n), i+1
        a = getRandomNumber(2, n)
    return True


def getRandomPrime(bits, display=False):
    """
    Generate a random prime number of a given size.

    the number will be 'bits' bits long (i.e. generated number will be
    larger than `(2^(bits-1) * 3 ) / 2` but smaller than 2^bits.
    """
    assert bits >= 10
    #The 1.5 ensures the 2 MSBs are set
    #Thus, when used for p,q in RSA, n will have its MSB set
    #
    #Since 30 is lcm(2,3,5), we'll set our test numbers to
    #29 % 30 and keep them there
    low = ((2 ** (bits-1)) * 3) // 2
    high = 2 ** bits - 30
    p = getRandomNumber(low, high)
    p += 29 - (p % 30)
    while 1:
        if display: print(".", end=' ')
        p += 30
        if p >= high:
            p = getRandomNumber(low, high)
            p += 29 - (p % 30)
        if isPrime(p, display=display):
            return p


#Unused at the moment...
def getRandomSafePrime(bits, display=False):
    """Generate a random safe prime.

    Will generate a prime `bits` bits long (see getRandomPrime) such that
    the (p-1)/2 will also be prime.
    """
    assert bits >= 10
    #The 1.5 ensures the 2 MSBs are set
    #Thus, when used for p,q in RSA, n will have its MSB set
    #
    #Since 30 is lcm(2,3,5), we'll set our test numbers to
    #29 % 30 and keep them there
    low = (2 ** (bits-2)) * 3//2
    high = (2 ** (bits-1)) - 30
    q = getRandomNumber(low, high)
    q += 29 - (q % 30)
    while 1:
        if display: print(".", end=' ')
        q += 30
        if (q >= high):
            q = getRandomNumber(low, high)
            q += 29 - (q % 30)
        #Ideas from Tom Wu's SRP code
        #Do trial division on p and q before Rabin-Miller
        if isPrime(q, 0, display=display):
            p = (2 * q) + 1
            if isPrime(p, display=display):
                if isPrime(q, display=display):
                    return p
