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
        class DummyExtension():
            algorithms = None

            def change_algos(self, algos):
                self.algorithms = algos

        extension = DummyExtension()

        extension.change_algos([1])
        algo = choose_compression_send_algo((3, 4), extension, ['zlib'])
        self.assertEqual(algo, 1)
        algo = choose_compression_send_algo((3, 2), extension, ['zlib'])
        self.assertIsNone(algo)
        algo = choose_compression_send_algo(None, extension, ['zlib'])
        self.assertIsNone(algo)

        extension.change_algos([1, 2])
        algo = choose_compression_send_algo(
            (3, 4), extension, ['zlib', 'brotli'])
        self.assertEqual(algo, 1)

        extension.change_algos([])
        algo = choose_compression_send_algo((3, 4), extension, ['zlib'])
        self.assertIsNone(algo)

        extension.change_algos(None)
        algo = choose_compression_send_algo((3, 4), extension, ['zlib'])
        self.assertIsNone(algo)

        extension.change_algos([50])
        algo = choose_compression_send_algo((3, 4), extension, ['zlib'])
        self.assertIsNone(algo)
        algo = choose_compression_send_algo((3, 4), extension, [])
        self.assertIsNone(algo)
