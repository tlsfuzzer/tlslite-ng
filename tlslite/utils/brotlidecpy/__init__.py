'''
This module it pure python brotli decompress.
Copied from https://github.com/sidney/brotlidecpy
'''

from __future__ import absolute_import

__version__ = "1.0.3"

# noinspection PyUnresolvedReferences
from .decode import brotli_decompress_buffer as decompress
