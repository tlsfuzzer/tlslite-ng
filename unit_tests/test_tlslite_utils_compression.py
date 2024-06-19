# Copyright (c) 2014, George Pantelakis
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.utils.compression import compression_algo_impls, \
    choose_compression_send_algo
from tlslite.errors import TLSDecodeError

class TestCompression(unittest.TestCase):
    def setUp(self):
        class DummyExtension():
            algorithms = None

            def change_algos(self, algos):
                self.algorithms = algos

        self.extension = DummyExtension()

    def test_compression_algo_impls(self):
        self.assertIsNotNone(compression_algo_impls)
        self.assertIn("brotli_compress", compression_algo_impls)
        self.assertIn("brotli_decompress", compression_algo_impls)
        self.assertIn("brotli_accepts_limit", compression_algo_impls)
        self.assertIn("zstd_compress", compression_algo_impls)
        self.assertIn("zstd_decompress", compression_algo_impls)
        self.assertIn("zstd_accepts_limit", compression_algo_impls)

    def test_choose_compression_send_algo_sanity(self):
        self.extension.change_algos([1])
        algo = choose_compression_send_algo((3, 4), self.extension, ['zlib'])
        self.assertEqual(algo, 1)

    def test_choose_compression_send_algo_previous_tls_version(self):
        self.extension.change_algos([1])
        algo = choose_compression_send_algo((3, 2), self.extension, ['zlib'])
        self.assertIsNone(algo)

    def test_choose_compression_send_algo_no_tls_version(self):
        self.extension.change_algos([1])
        algo = choose_compression_send_algo(None, self.extension, ['zlib'])
        self.assertIsNone(algo)

    def test_choose_compression_send_algo_choose_first_common(self):
        self.extension.change_algos([1, 2])
        algo = choose_compression_send_algo(
            (3, 4), self.extension, ['zlib', 'brotli'])
        self.assertEqual(algo, 1)

    def test_choose_compression_send_algo_empty_extension_algos(self):
        self.extension.change_algos([])
        with self.assertRaises(TLSDecodeError):
            choose_compression_send_algo((3, 4), self.extension, ['zlib'])

    def test_choose_compression_send_algo_empty_accepted_algos(self):
        self.extension.change_algos([1])
        algo = choose_compression_send_algo((3, 4), self.extension, [])
        self.assertIsNone(algo)

    def test_choose_compression_send_algo_none_extension_algos(self):
        self.extension.change_algos(None)
        with self.assertRaises(TLSDecodeError):
            choose_compression_send_algo((3, 4), self.extension, ['zlib'])

    def test_choose_compression_send_algo_no_common_algos(self):
        self.extension.change_algos([2])
        algo = choose_compression_send_algo((3, 4), self.extension, ['zlib'])
        self.assertIsNone(algo)
