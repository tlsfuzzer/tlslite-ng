# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Classes for reading/writing binary data (such as TLS records)."""

import sys
import struct
from struct import pack


class Writer(object):
    """Serialisation helper for complex byte-based structures."""

    def __init__(self):
        """Initialise the serializer with no data."""
        self.bytes = bytearray(0)

    def addOne(self, val):
        """Add a single-byte wide element to buffer, see add()."""
        self.bytes.append(val)

    if sys.version_info < (2, 7):
        # struct.pack on Python2.6 does not raise exception if the value
        # is larger than can fit inside the specified size
        def addTwo(self, val):
            """Add a double-byte wide element to buffer, see add()."""
            if not 0 <= val <= 0xffff:
                raise ValueError("Can't represent value in specified length")
            self.bytes += pack('>H', val)

        def addThree(self, val):
            """Add a thee-byte wide element to buffer, see add()."""
            if not 0 <= val <= 0xffffff:
                raise ValueError("Can't represent value in specified length")
            self.bytes += pack('>BH', val >> 16, val & 0xffff)

        def addFour(self, val):
            """Add a four-byte wide element to buffer, see add()."""
            if not 0 <= val <= 0xffffffff:
                raise ValueError("Can't represent value in specified length")
            self.bytes += pack('>I', val)
    else:
        def addTwo(self, val):
            """Add a double-byte wide element to buffer, see add()."""
            try:
                self.bytes += pack('>H', val)
            except struct.error:
                raise ValueError("Can't represent value in specified length")

        def addThree(self, val):
            """Add a thee-byte wide element to buffer, see add()."""
            try:
                self.bytes += pack('>BH', val >> 16, val & 0xffff)
            except struct.error:
                raise ValueError("Can't represent value in specified length")

        def addFour(self, val):
            """Add a four-byte wide element to buffer, see add()."""
            try:
                self.bytes += pack('>I', val)
            except struct.error:
                raise ValueError("Can't represent value in specified length")

    if sys.version_info >= (3, 0):
        # the method is called thousands of times, so it's better to extern
        # the version info check
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
            try:
                self.bytes += x.to_bytes(length, 'big')
            except OverflowError:
                raise ValueError("Can't represent value in specified length")
    else:
        _addMethods = {1: addOne, 2: addTwo, 3: addThree, 4: addFour}

        def add(self, x, length):
            """
            Add a single positive integer value x, encode it in length bytes

            Encode positive iteger x in big-endian format using length bytes,
            add to the internal buffer.

            @type x: int
            @param x: value to encode

            @type length: int
            @param length: number of bytes to use for encoding the value
            """
            try:
                self._addMethods[length](self, x)
            except KeyError:
                self.bytes += bytearray(length)
                newIndex = len(self.bytes) - 1
                for i in range(newIndex, newIndex - length, -1):
                    self.bytes[i] = x & 0xFF
                    x >>= 8
                if x != 0:
                    raise ValueError("Can't represent value in specified "
                                     "length")

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

    if sys.version_info < (2, 7):
        # struct.pack on Python2.6 does not raise exception if the value
        # is larger than can fit inside the specified size
        def _addVarSeqTwo(self, seq):
            """Helper method for addVarSeq"""
            if not all(0 <= i <= 0xffff for i in seq):
                raise ValueError("Can't represent value in specified "
                                 "length")
            self.bytes += pack('>' + 'H' * len(seq), *seq)

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
            if length == 1:
                self.bytes.extend(seq)
            elif length == 2:
                self._addVarSeqTwo(seq)
            else:
                for i in seq:
                    self.add(i, length)
    else:
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
            seqLen = len(seq)
            self.add(seqLen*length, lengthLength)
            if length == 1:
                self.bytes.extend(seq)
            elif length == 2:
                try:
                    self.bytes += pack('>' + 'H' * seqLen, *seq)
                except struct.error:
                    raise ValueError("Can't represent value in specified "
                                     "length")
            else:
                for i in seq:
                    self.add(i, length)

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
        if not seq:
            self.add(0, lengthLength)
        else:
            startPos = len(self.bytes)
            dataLength = len(seq) * len(seq[0]) * length
            self.add(dataLength, lengthLength)
            # since at the time of writing, all the calls encode single byte
            # elements, and it's very easy to speed up that case, give it
            # special case
            if length == 1:
                for elemTuple in seq:
                    self.bytes.extend(elemTuple)
            else:
                for elemTuple in seq:
                    self.addFixSeq(elemTuple, length)
            if startPos + dataLength + lengthLength != len(self.bytes):
                raise ValueError("Tuples of different lengths")


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
