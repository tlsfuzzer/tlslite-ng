# Author: Trevor Perrin
# Patch from Google adding getChildBytes()
#
# See the LICENSE file for legal information regarding use of this file.

"""Abstract Syntax Notation One (ASN.1) parsing"""

from .codec import Parser

class TLVType(object):
    """
    Class that represents the Type part of a TLV based encoding.
    Consists of a class (universal(0), application(1), context-specific(2) or private(3)), 
    boolean value that indicates if a type is constructed or primitive and the
    ASN1 type itself
    
    :vartype octet: bytearray
    :ivar field: bit octet

    :vartype tagClass: int
    :ivar tagClass: type's class
    
    :vartype isConstructed: boolean
    :ivar isConstructed: is the type constructed or primitive

    :vartype tag: int
    :ivar tag: ANS1 tag number
    """

    def __init__(self, bytes):
        self.bytes = bytes
        self.parse(self.bytes)

    def parse(self, header):
        self.tagClass = (header & 0xc0) >> 6
        self.isPrimitive = (header & 0x20) >> 5
        self.tagId = header & 0x1f

class ASN1Parser(object):
    """
    Parser and storage of ASN.1 DER encoded objects.

    :vartype length: int
    :ivar length: length of the value of the tag
    :vartype value: bytearray
    :ivar value: literal value of the tag
    """

    def __init__(self, bytes):
        """Create an object from bytes.

        :type bytes: bytearray
        :param bytes: DER encoded ANS.1 object
        """
        p = Parser(bytes)
        
        #Get Type
        self.type = self._getASN1Type(p)

        #Get Length
        self.length = self._getASN1Length(p)

        #Get Value
        self.value = p.getFixBytes(self.length)

    def getChild(self, which):
        """
        Return n-th child assuming that the object is a SEQUENCE.

        :type which: int
        :param which: ordinal of the child to return

        :rtype: ASN1Parser
        :returns: decoded child object
        """
        return ASN1Parser(self.getChildBytes(which))

    def getChildCount(self):
        """
        Return number of children, assuming that the object is a SEQUENCE.

        :rtype: int
        :returns: number of children in the object
        """
        p = Parser(self.value)
        count = 0
        while True:
            if p.getRemainingLength() == 0:
                break
            p.get(1)  # skip Type
            length = self._getASN1Length(p)
            p.getFixBytes(length)  # skip value
            count += 1
        return count

    def getChildBytes(self, which):
        """
        Return raw encoding of n-th child, assume self is a SEQUENCE

        :type which: int
        :param which: ordinal of the child to return

        :rtype: bytearray
        :returns: raw child object
        """
        p = Parser(self.value)
        for _ in range(which+1):
            markIndex = p.index
            p.get(1) #skip Type
            length = self._getASN1Length(p)
            p.getFixBytes(length)
        return p.bytes[markIndex : p.index]

    @staticmethod
    def _getASN1Length(p):
        """Decode the ASN.1 DER length field"""
        firstLength = p.get(1)
        if firstLength <= 127:
            return firstLength
        else:
            lengthLength = firstLength & 0x7F
            return p.get(lengthLength)
    
    @staticmethod
    def _getASN1Type(p):
        """Decode the ASN.1 type field"""
        asn1Type = TLVType(p.get(1))
        if asn1Type.tagId >= 31:
            tag_id = 0
            while True:
                value = p.get(1)
                tag_id += value & 0x7f
                if not value & 0x80:
                    break
                tag_id <<= 7
            asn1Type.tagId = tag_id
        return asn1Type
