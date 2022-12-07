# Author: Alexander Sosedkin
# See the LICENSE file for legal information regarding use of this file.

import zlib  # pylint: disable=unused-import

try:
    import brotli  # pylint: disable=unused-import
    brotliLoaded = True
except ImportError:
    brotliLoaded = False

try:
    import zstd  # pylint: disable=unused-import
    zstdLoaded = True
except ImportError:
    zstdLoaded = False
