# Copyright (c) 2014, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest
from tlslite.utils.codec import Parser, Writer

class TestParser(unittest.TestCase):
    def test___init__(self):
        p = Parser(bytearray(0))

        self.assertEqual(bytearray(0), p.bytes)
        self.assertEqual(0, p.index)

    def test_get(self):
        p = Parser(bytearray(b'\x02\x01\x00'))

        self.assertEqual(2, p.get(1))
        self.assertEqual(256, p.get(2))
        self.assertEqual(3, p.index)

    def test_get_with_too_few_bytes_left(self):
        p = Parser(bytearray(b'\x02\x01'))

        p.get(1)

        with self.assertRaises(SyntaxError):
            p.get(2)

    def test_getFixBytes(self):
        p = Parser(bytearray(b'\x02\x01\x00'))

        self.assertEqual(bytearray(b'\x02\x01'), p.getFixBytes(2))
        self.assertEqual(2, p.index)

    def test_getVarBytes(self):
        p = Parser(bytearray(b'\x02\x01\x00'))

        self.assertEqual(bytearray(b'\x01\x00'), p.getVarBytes(1))
        self.assertEqual(3, p.index)

    def test_getFixList(self):
        p = Parser(bytearray(
            b'\x00\x01' +
            b'\x00\x02' +
            b'\x00\x03'))

        self.assertEqual([1,2,3], p.getFixList(2, 3))
        self.assertEqual(6, p.index)

    def test_getVarList(self):
        p = Parser(bytearray(
            b'\x06' +
            b'\x00\x01\x00' +
            b'\x00\x00\xff'))

        self.assertEqual([256, 255], p.getVarList(3, 1))
        self.assertEqual(7, p.index)

    def test_getVarList_with_incorrect_length(self):
        p = Parser(bytearray(
            b'\x07' +
            b'\x00\x01\x00'
            b'\x00\x00\xff'
            b'\x00'))

        with self.assertRaises(SyntaxError):
            p.getVarList(3,1)

    def test_lengthCheck(self):
        p = Parser(bytearray(
            b'\x06' +
            b'\x00\x00' +
            b'\x03' +
            b'\x01\x02\x03'
            ))

        p.startLengthCheck(1)

        self.assertEqual([0,0], p.getFixList(1,2))
        self.assertEqual([1,2,3], p.getVarList(1,1))
        # should not raise exception
        p.stopLengthCheck()

    def test_lengthCheck_with_incorrect_parsing(self):
        p = Parser(bytearray(
            b'\x06' +
            b'\x00\x00' +
            b'\x02' +
            b'\x01\x02' +
            b'\x03'
            ))

        p.startLengthCheck(1)
        self.assertEqual([0,0], p.getFixList(1,2))
        self.assertEqual([1,2], p.getVarList(1,1))
        with self.assertRaises(SyntaxError):
            p.stopLengthCheck()

    def test_setLengthCheck(self):
        p = Parser(bytearray(
            b'\x06' +
            b'\x00\x01' +
            b'\x00\x02' +
            b'\x00\x03'
            ))

        p.setLengthCheck(7)
        self.assertEqual([1,2,3], p.getVarList(2,1))
        p.stopLengthCheck()

    def test_setLengthCheck_with_bad_data(self):
        p = Parser(bytearray(
            b'\x04' +
            b'\x00\x01' +
            b'\x00\x02'
            ))

        p.setLengthCheck(7)
        self.assertEqual([1,2], p.getVarList(2,1))

        with self.assertRaises(SyntaxError):
            p.stopLengthCheck()

    def test_atLengthCheck(self):
        p = Parser(bytearray(
            b'\x00\x06' +
            b'\x05' +
            b'\x01\xff' +
            b'\x07' +
            b'\x01\xf0'
            ))

        p.startLengthCheck(2)
        while not p.atLengthCheck():
            p.get(1)
            p.getVarBytes(1)
        p.stopLengthCheck()

    def test_getVarBytes_with_incorrect_data(self):
        p = Parser(bytearray(
            b'\x00\x04' +
            b'\x00\x00\x00'
            ))

        with self.assertRaises(SyntaxError):
            p.getVarBytes(2)

    def test_getFixBytes_with_incorrect_data(self):
        p = Parser(bytearray(
            b'\x00\x04'
            ))

        with self.assertRaises(SyntaxError):
            p.getFixBytes(10)

    def test_getRemainingLength(self):
        p = Parser(bytearray(
            b'\x00\x01\x05'
            ))

        self.assertEqual(1, p.get(2))
        self.assertEqual(1, p.getRemainingLength())
        self.assertEqual(5, p.get(1))
        self.assertEqual(0, p.getRemainingLength())

    def test_getVarTupleList(self):
        p = Parser(bytearray(
            b'\x00\x06' +       # length of list
            b'\x01\x00' +       # first tuple
            b'\x01\x05' +       # second tuple
            b'\x04\x00'         # third tuple
            ))

        self.assertEqual(p.getVarTupleList(1, 2, 2),
                [(1, 0),
                 (1, 5),
                 (4, 0)])

    def test_getVarTupleList_with_missing_elements(self):
        p = Parser(bytearray(
            b'\x00\x02' +
            b'\x00'))

        with self.assertRaises(SyntaxError):
            p.getVarTupleList(1, 2, 2)

    def test_getVarTupleList_with_incorrect_length(self):
        p = Parser(bytearray(
            b'\x00\x03' +
            b'\x00'*3))

        with self.assertRaises(SyntaxError):
            p.getVarTupleList(1, 2, 2)

class TestWriter(unittest.TestCase):
    def test___init__(self):
        w = Writer()

        self.assertEqual(bytearray(0), w.bytes)

    def test_add(self):
        w = Writer()
        w.add(255, 1)

        self.assertEqual(bytearray(b'\xff'), w.bytes)

    def test_add_with_multibyte_field(self):
        w = Writer()
        w.add(32, 2)

        self.assertEqual(bytearray(b'\x00\x20'), w.bytes)

    def test_add_with_multibyte_data(self):
        w = Writer()
        w.add(512, 2)

        self.assertEqual(bytearray(b'\x02\x00'), w.bytes)

    def test_add_with_overflowing_data(self):
        w = Writer()

        with self.assertRaises(ValueError):
            w.add(256, 1)

    def test_addFixSeq(self):
        w = Writer()
        w.addFixSeq([16,17,18], 2)

        self.assertEqual(bytearray(b'\x00\x10\x00\x11\x00\x12'), w.bytes)

    def test_addVarSeq(self):
        w = Writer()
        w.addVarSeq([16, 17, 18], 2, 2)

        self.assertEqual(bytearray(
            b'\x00\x06' +
            b'\x00\x10' +
            b'\x00\x11' +
            b'\x00\x12'), w.bytes)

    def test_bytes(self):
        w = Writer()
        w.bytes += bytearray(b'\xbe\xef')
        w.add(15, 1)

        self.assertEqual(bytearray(b'\xbe\xef\x0f'), w.bytes)

if __name__ == '__main__':
    unittest.main()
