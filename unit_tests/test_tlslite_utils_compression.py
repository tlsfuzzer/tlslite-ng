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

class TestCompression(unittest.TestCase):
    def test_compression_algo_impls(self):
        self.assertIsNotNone(compression_algo_impls)
        self.assertIn("brotli_compress", compression_algo_impls)
        self.assertIn("brotli_decompress", compression_algo_impls)
        self.assertIn("brotli_accepts_limit", compression_algo_impls)
        self.assertIn("zstd_compress", compression_algo_impls)
        self.assertIn("zstd_decompress", compression_algo_impls)
        self.assertIn("zstd_accepts_limit", compression_algo_impls)

    def test_choose_compression_send_algo(self):
        algo = choose_compression_send_algo((3, 4), [1], ['zlib'])
        self.assertEqual(algo, 1)

        algo = choose_compression_send_algo((3, 4), [1, 2], ['zlib', 'brotli'])
        self.assertEqual(algo, 1)

        algo = choose_compression_send_algo((3, 2), [1], ['zlib'])
        self.assertIsNone(algo)

        algo = choose_compression_send_algo(None, [1], ['zlib'])
        self.assertIsNone(algo)

        algo = choose_compression_send_algo((3, 4), [], ['zlib'])
        self.assertIsNone(algo)

        algo = choose_compression_send_algo((3, 4), None, ['zlib'])
        self.assertIsNone(algo)

        algo = choose_compression_send_algo((3, 4), [50], ['zlib'])
        self.assertIsNone(algo)

        algo = choose_compression_send_algo((3, 4), [50], [])
        self.assertIsNone(algo)
