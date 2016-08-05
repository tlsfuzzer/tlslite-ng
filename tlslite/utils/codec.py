# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Classes for reading/writing binary data (such as TLS records)."""

from .compat import *

class Writer(object):
    """Serialisation helper for complex byte-based structures."""

    def __init__(self):
        """Initialise the serializer with no data."""
        self.bytes = bytearray(0)

    def add(self, x, length):
        """
        Add a single positive integer value x, encode it in length bytes

        Encode positive integer x in big-endian format using length bytes,
        add to the internal buffer.

        @type x: int
        @param x: value to encode

        @type length: int
        @param length: number of bytes to use for encoding the value
        """
        self.bytes += bytearray(length)
        newIndex = len(self.bytes) - 1
        for count in range(length):
            self.bytes[newIndex] = x & 0xFF
            x >>= 8
            newIndex -= 1
        if x != 0:
            raise ValueError("Can't represent value in specified length")

    def addFixSeq(self, seq, length):
        """
        Add a list of items, encode every item in length bytes

        Uses the unbounded iterable seq to produce items, each of
        which is then encoded to length bytes

        @type seq: iterable of int
        @param seq: list of positive integers to encode

        @type length: int
        @param length: number of bytes to which encode every element
        """
        for e in seq:
            self.add(e, length)

    def addVarSeq(self, seq, length, lengthLength):
        """
        Add a bounded list of same-sized values

        Create a list of specific length with all items being of the same
        size

        @type seq: list of int
        @param seq: list of positive integers to encode

        @type length: int
        @param length: amount of bytes in which to encode every item

        @type lengthLength: int
        @param lengthLength: amount of bytes in which to encode the overall
            length of the array
        """
        self.add(len(seq)*length, lengthLength)
        for e in seq:
            self.add(e, length)

    def addVarTupleSeq(self, seq, length, lengthLength):
        """
        Add a variable length list of same-sized element tuples.

        Note that all tuples must have the same size.

        Inverse of Parser.getVarTupleList()

        @type seq: enumerable
        @param seq: list of tuples

        @type length: int
        @param length: length of single element in tuple

        @type lengthLength: int
        @param lengthLength: length in bytes of overall length field
        """
        if len(seq) == 0:
            self.add(0, lengthLength)
        else:
            tupleSize = len(seq[0])
            tupleLength = tupleSize*length
            self.add(len(seq)*tupleLength, lengthLength)
            for elemTuple in seq:
                if len(elemTuple) != tupleSize:
                    raise ValueError("Tuples of different sizes")
                for elem in elemTuple:
                    self.add(elem, length)

class Parser(object):
    def __init__(self, bytes):
        self.bytes = bytes
        self.index = 0

    def get(self, length):
        if self.index + length > len(self.bytes):
            raise SyntaxError()
        x = 0
        for count in range(length):
            x <<= 8
            x |= self.bytes[self.index]
            self.index += 1
        return x

    def getFixBytes(self, lengthBytes):
        if self.index + lengthBytes > len(self.bytes):
            raise SyntaxError()
        bytes = self.bytes[self.index : self.index+lengthBytes]
        self.index += lengthBytes
        return bytes

    def getVarBytes(self, lengthLength):
        lengthBytes = self.get(lengthLength)
        return self.getFixBytes(lengthBytes)

    def getFixList(self, length, lengthList):
        l = [0] * lengthList
        for x in range(lengthList):
            l[x] = self.get(length)
        return l

    def getVarList(self, length, lengthLength):
        lengthList = self.get(lengthLength)
        if lengthList % length != 0:
            raise SyntaxError()
        lengthList = lengthList // length
        l = [0] * lengthList
        for x in range(lengthList):
            l[x] = self.get(length)
        return l

    def getVarTupleList(self, elemLength, elemNum, lengthLength):
        """Read a variable length list of same sized tuples

        @param elemLength: length in bytes of single tuple element
        @param elemNum: number of elements in tuple
        @param lengthLength: length in bytes of the list length variable
        """
        lengthList = self.get(lengthLength)
        if lengthList % (elemLength * elemNum) != 0:
            raise SyntaxError()
        tupleCount = lengthList // (elemLength * elemNum)
        tupleList = []
        for _ in range(tupleCount):
            currentTuple = []
            for _ in range(elemNum):
                currentTuple.append(self.get(elemLength))
            tupleList.append(tuple(currentTuple))
        return tupleList

    def startLengthCheck(self, lengthLength):
        self.lengthCheck = self.get(lengthLength)
        self.indexCheck = self.index

    def setLengthCheck(self, length):
        self.lengthCheck = length
        self.indexCheck = self.index

    def stopLengthCheck(self):
        if (self.index - self.indexCheck) != self.lengthCheck:
            raise SyntaxError()

    def atLengthCheck(self):
        if (self.index - self.indexCheck) < self.lengthCheck:
            return False
        elif (self.index - self.indexCheck) == self.lengthCheck:
            return True
        else:
            raise SyntaxError()

    def getRemainingLength(self):
        return len(self.bytes) - self.index
