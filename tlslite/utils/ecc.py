# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.
"""Methods for dealing with ECC points"""

import ecdsa
from .compat import ecdsaAllCurves


def getCurveByName(curveName):
    """Return curve identified by curveName"""
    curveMap = {'secp256r1':ecdsa.NIST256p,
                'secp384r1':ecdsa.NIST384p,
                'secp521r1':ecdsa.NIST521p,
                'secp256k1':ecdsa.SECP256k1,
                'brainpoolP256r1': ecdsa.BRAINPOOLP256r1,
                'brainpoolP384r1': ecdsa.BRAINPOOLP384r1,
                'brainpoolP512r1': ecdsa.BRAINPOOLP512r1}
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
                ecdsa.SECP256k1.curve: 256//8,
                ecdsa.BRAINPOOLP256r1.curve: 256//8,
                ecdsa.BRAINPOOLP384r1.curve: 384//8,
                ecdsa.BRAINPOOLP512r1.curve: 512//8}
    if ecdsaAllCurves:
        curveMap[ecdsa.NIST224p.curve] = 224//8
        curveMap[ecdsa.NIST192p.curve] = 192//8

    if hasattr(point, 'curve'):
        if callable(point.curve):
            return curveMap[point.curve()]
        else:
            return curveMap[point.curve]
    raise ValueError("Parameter must be a curve or point on curve")
