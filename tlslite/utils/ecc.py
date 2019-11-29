# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.
"""Methods for dealing with ECC points"""

from .codec import Parser, Writer
from .cryptomath import bytesToNumber, numberToByteArray, numBytes
from .compat import ecdsaAllCurves
import ecdsa

def decodeX962Point(data, curve=ecdsa.NIST256p):
    """Decode a point from a X9.62 encoding"""
    parser = Parser(data)
    encFormat = parser.get(1)
    assert encFormat == 4
    bytelength = getPointByteSize(curve)
    xCoord = bytesToNumber(parser.getFixBytes(bytelength))
    yCoord = bytesToNumber(parser.getFixBytes(bytelength))
    return ecdsa.ellipticcurve.Point(curve.curve, xCoord, yCoord)

def encodeX962Point(point):
    """Encode a point in X9.62 format"""
    bytelength = numBytes(point.curve().p())
    writer = Writer()
    writer.add(4, 1)
    writer.bytes += numberToByteArray(point.x(), bytelength)
    writer.bytes += numberToByteArray(point.y(), bytelength)
    return writer.bytes

def getCurveByName(curveName):
    """Return curve identified by curveName"""
    curveMap = {'secp256r1':ecdsa.NIST256p,
                'secp384r1':ecdsa.NIST384p,
                'secp521r1':ecdsa.NIST521p,
                'secp256k1':ecdsa.SECP256k1}
    if ecdsaAllCurves:
        curveMap['secp224r1'] = ecdsa.NIST224p
        curveMap['secp192r1'] = ecdsa.NIST192p

    if curveName in curveMap:
        return curveMap[curveName]
    else:
        raise ValueError("Curve of name '{0}' unknown".format(curveName))

def getPointByteSize(point):
    """Convert the point or curve bit size to bytes"""
    if hasattr(point, 'curve'):
        if callable(point.curve):
            curve = point.curve()
        else:
            curve = point.curve
    else:
        raise ValueError("Parameter must be a curve or point on curve")

    if curve == ecdsa.NIST256p.curve:
        return 256//8
    if curve == ecdsa.NIST384p.curve:
        return 384//8
    if curve == ecdsa.NIST521p.curve:
        return (521+7)//8
    if curve == ecdsa.SECP256k1.curve:
        return 256//8
    if ecdsaAllCurves:
        if curve == ecdsa.NIST224p.curve:
            return 224//8
        if curve == ecdsa.NIST192p.curve:
            return 192//8
    raise ValueError("Unrecognised curve: {0}".format(curve))
