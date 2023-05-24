import zlib

from tlslite.constants import CompressionAlgorithms
from tlslite.utils.codec import BadCertificateError

_is_installed = {CompressionAlgorithms.zlib: True,
                 CompressionAlgorithms.brotli: False,
                 CompressionAlgorithms.zstd: False}

try:
    import brotli
except ModuleNotFoundError:
    pass
else:
    _is_installed[CompressionAlgorithms.brotli] = True

try:
    import zstandard
except ModuleNotFoundError:
    pass
else:
    _is_installed[CompressionAlgorithms.zstd] = True
    _zstd_compress = zstandard.ZstdCompressor()
    _zstd_decompress = zstandard.ZstdDecompressor()


def is_installed(algorithm):
    """
    Check if given algorithm's library is installed or not.

    :type algorithm: int
    :param algorithm: the algorithm to check for

    raise KeyError: if provided algorithm integer is unknown
    """
    return _is_installed[algorithm]


def decompress(chosen_algorithm, data):
    """
    Decompress given certificate data with a particular algorithm

    :type chosen_algorithm: int
    :param chosen_algorithm: the algorithm to use

    :param data: compressed data to decompress

    :raise BadCertificateError: if decompression failed
    :raise ValueError: if chosen_algorithm is unknown
    """
    if chosen_algorithm == CompressionAlgorithms.zlib:
        try:
            return zlib.decompress(data)
        except zlib.error as exc:
            raise BadCertificateError(exc)
    elif chosen_algorithm == CompressionAlgorithms.zstd:
        try:
            return _zstd_decompress.decompress(data)
        except Exception as exc:
            raise BadCertificateError(exc)
    elif chosen_algorithm == CompressionAlgorithms.brotli:
        try:
            return brotli.decompress(data)
        except brotli.error as exc:
            raise BadCertificateError(exc)
    else:
        raise ValueError("Unknown algorithm ({}) provided".format(chosen_algorithm))


def compress(chosen_algorithm, data):
    """
    Compress given certificate data with a particular algorithm

    :type chosen_algorithm: int
    :param chosen_algorithm: the algorithm to use

    :param data: data to compress

    :raise BadCertificateError: if compression failed
    :raise ValueError: if chosen_algorithm is unknown
    """

    if chosen_algorithm == CompressionAlgorithms.zlib:
        try:
            return zlib.compress(data)
        except zlib.error as exc:
            raise BadCertificateError(exc)
    elif chosen_algorithm == CompressionAlgorithms.zstd:
        try:
            return _zstd_compress.compress(data)
        except Exception as exc:
            raise BadCertificateError(exc)
    elif chosen_algorithm == CompressionAlgorithms.brotli:
        try:
            return brotli.compress(data)
        except brotli.error as exc:
            raise BadCertificateError(exc)
    else:
        raise ValueError("Unknown algorithm ({}) provided".format(chosen_algorithm))


ALL = tuple(_is_installed.keys())  # All supported algorithms
DEFAULT = (1, )                    # Default algorithms to use if user has no preference

__all__ = ["compress", "decompress", "is_installed", "ALL", "DEFAULT"]
