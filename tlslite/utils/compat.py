# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Miscellaneous functions to mask Python version differences."""

import sys
import os
import platform
import math
import binascii
import traceback
import ecdsa

if sys.version_info >= (3,0):

    def compat26Str(x): return x
    
    # Python 3 requires bytes instead of bytearrays for HMAC   
    
    # So, python 2.6 requires strings, python 3 requires 'bytes',
    # and python 2.7 can handle bytearrays...     
    def compatHMAC(x): return bytes(x)

    def compatAscii2Bytes(val):
        """Convert ASCII string to bytes."""
        if isinstance(val, str):
            return bytes(val, 'ascii')
        return val

    def raw_input(s):
        return input(s)
    
    # So, the python3 binascii module deals with bytearrays, and python2
    # deals with strings...  I would rather deal with the "a" part as
    # strings, and the "b" part as bytearrays, regardless of python version,
    # so...
    def a2b_hex(s):
        try:
            b = bytearray(binascii.a2b_hex(bytearray(s, "ascii")))
        except Exception as e:
            raise SyntaxError("base16 error: %s" % e) 
        return b  

    def a2b_base64(s):
        try:
            if isinstance(s, str):
                s = bytearray(s, "ascii")
            b = bytearray(binascii.a2b_base64(s))
        except Exception as e:
            raise SyntaxError("base64 error: %s" % e)
        return b

    def b2a_hex(b):
        return binascii.b2a_hex(b).decode("ascii")    
            
    def b2a_base64(b):
        return binascii.b2a_base64(b).decode("ascii") 

    def readStdinBinary():
        return sys.stdin.buffer.read()        

    def compatLong(num):
        return int(num)

    int_types = tuple([int])

    def formatExceptionTrace(e):
        """Return exception information formatted as string"""
        return str(e)

else:
    # Python 2.6 requires strings instead of bytearrays in a couple places,
    # so we define this function so it does the conversion if needed.
    # same thing with very old 2.7 versions
    # or on Jython
    if sys.version_info < (2, 7) or sys.version_info < (2, 7, 4) \
            or platform.system() == 'Java':
        def compat26Str(x): return str(x)
    else:
        def compat26Str(x): return x

    def compatAscii2Bytes(val):
        """Convert ASCII string to bytes."""
        return val

    # So, python 2.6 requires strings, python 3 requires 'bytes',
    # and python 2.7 can handle bytearrays...     
    def compatHMAC(x): return compat26Str(x)

    def a2b_hex(s):
        try:
            b = bytearray(binascii.a2b_hex(s))
        except Exception as e:
            raise SyntaxError("base16 error: %s" % e)
        return b

    def a2b_base64(s):
        try:
            b = bytearray(binascii.a2b_base64(s))
        except Exception as e:
            raise SyntaxError("base64 error: %s" % e)
        return b
        
    def b2a_hex(b):
        return binascii.b2a_hex(compat26Str(b))
        
    def b2a_base64(b):
        return binascii.b2a_base64(compat26Str(b))

    def compatLong(num):
        return long(num)

    int_types = (int, long)

    # pylint on Python3 goes nuts for the sys dereferences...

    #pylint: disable=no-member
    def formatExceptionTrace(e):
        """Return exception information formatted as string"""
        newStr = "".join(traceback.format_exception(sys.exc_type,
                                                    sys.exc_value,
                                                    sys.exc_traceback))
        return newStr
    #pylint: enable=no-member

try:
    # Fedora and Red Hat Enterprise Linux versions have small curves removed
    getattr(ecdsa, 'NIST192p')
except AttributeError:
    ecdsaAllCurves = False
else:
    ecdsaAllCurves = True
