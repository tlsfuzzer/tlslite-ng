# Authors:
#   George Pantelakis
#
# See the LICENSE file for legal information regarding use of this file.

"""compression module

This module has basic supported compression modules."""

from ..constants import CertificateCompressionAlgorithm
from .lists import getFirstMatching
from ..errors import TLSDecodeError

compression_algo_impls = {
    "brotli_compress": None,
    "brotli_decompress": None,
    "brotli_accepts_limit": None,
    "zstd_compress": None,
    "zstd_decompress": None,
    "zstd_accepts_limit": None
}

try:
    import brotli
    compression_algo_impls["brotli_compress"] = brotli.compress
    compression_algo_impls["brotli_decompress"] = brotli.decompress
    compression_algo_impls["brotli_accepts_limit"] = False
except ImportError:
    try:
        from .brotlidecpy import decompress
        compression_algo_impls["brotli_decompress"] = decompress
        compression_algo_impls["brotli_accepts_limit"] = True
    except ImportError:
        pass

try:
    import zstandard
    compression_algo_impls["zstd_compress"] = zstandard.compress
    compression_algo_impls["zstd_decompress"] = zstandard.decompress
    compression_algo_impls["zstd_accepts_limit"] = True
except ImportError:
    try:
        import zstd
        compression_algo_impls["zstd_compress"] = zstd.compress
        compression_algo_impls["zstd_decompress"] = zstd.decompress
    except ImportError:
        pass


def choose_compression_send_algo(version, extension, valid_algos):
    if not extension or not version or version < (3, 4):
        return None

    chosen_compression_algo = None
    advertized_algos = extension.algorithms

    if not advertized_algos:
        raise TLSDecodeError("Empty algorithm list in compress_certificate "
                             "extension")

    if advertized_algos:
        supported_comp_algos = []
        for algo in valid_algos:
            try:
                supported_comp_algos.append(
                    getattr(CertificateCompressionAlgorithm, algo))
            except AttributeError:
                pass

        if supported_comp_algos:
            chosen_compression_algo = getFirstMatching(
                advertized_algos, supported_comp_algos)

    return chosen_compression_algo
