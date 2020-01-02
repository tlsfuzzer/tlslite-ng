# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.
"""Methods for dealing with ECC points"""

from .codec import Parser, Writer, DecodeError
from .cryptomath import bytesToNumber, numberToByteArray, numBytes
from .compat import ecdsaAllCurves
import ecdsa


def decodeX962Point(data, curve=ecdsa.NIST256p):
    """Decode a point from a X9.62 encoding"""
    parser = Parser(data)
    encFormat = parser.get(1)
    if encFormat != 4:
        raise DecodeError("Not an uncompressed point encoding")
    bytelength = getPointByteSize(curve)
    xCoord = bytesToNumber(parser.getFixBytes(bytelength))
    yCoord = bytesToNumber(parser.getFixBytes(bytelength))
    if parser.getRemainingLength():
        raise DecodeError("Invalid length of point encoding for curve")
    if not xCoord or not yCoord:
        raise DecodeError("Zero as key share from peer")
    if not curve.curve.contains_point(xCoord, yCoord):
        raise DecodeError("Key share from peer is not a valid point on curve")
    # pylint: disable=c-extension-no-member
    return ecdsa.ellipticcurve.PointJacobi(curve.curve, xCoord, yCoord, 1)
    # pylint: enable=c-extension-no-member

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
    curveMap = {ecdsa.NIST256p.curve: 256//8,
                ecdsa.NIST384p.curve: 384//8,
                ecdsa.NIST521p.curve: (521+7)//8,
                ecdsa.SECP256k1.curve: 256//8}
    if ecdsaAllCurves:
        curveMap[ecdsa.NIST224p.curve] = 224//8
        curveMap[ecdsa.NIST192p.curve] = 192//8

    if hasattr(point, 'curve'):
        if callable(point.curve):
            return curveMap[point.curve()]
        else:
            return curveMap[point.curve]
    raise ValueError("Parameter must be a curve or point on curve")
