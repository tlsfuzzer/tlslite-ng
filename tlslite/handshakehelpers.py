# Authors:
#   Karel Srot
#
# See the LICENSE file for legal information regarding use of this file.

"""Class with various handshake helpers."""

from .extensions import PaddingExtension, PreSharedKeyExtension
from .utils.cryptomath import derive_secret, secureHMAC, HKDF_expand_label


class HandshakeHelpers(object):
    """
    This class encapsulates helper functions to be used with a TLS handshake.
    """

    @staticmethod
    def alignClientHelloPadding(clientHello):
        """
        Align ClientHello using the Padding extension to 512 bytes at least.

        :param ClientHello clientHello: ClientHello to be aligned
        """
        # Check clientHello size if padding extension should be added
        # we want to add the extension even when using just SSLv3
        # cut-off 4 bytes with the Hello header (ClientHello type + Length)
        clientHelloLength = len(clientHello.write()) - 4
        if 256 <= clientHelloLength <= 511:
            if clientHello.extensions is None:
                clientHello.extensions = []
                # we need to recalculate the size after extension list addition
                # results in extra 2 bytes, equals to
                # clientHelloLength = len(clientHello.write()) - 4
                clientHelloLength += 2
            # we want to get 512 bytes in total, including the padding
            # extension header (4B)
            paddingExtensionInstance = PaddingExtension().create(
                max(512 - clientHelloLength - 4, 0))
            clientHello.extensions.append(paddingExtensionInstance)

    @staticmethod
    def update_binders(client_hello, handshake_hashes, psk_configs):
        """
        Sign the Client Hello using TLS 1.3 PSK binders.

        note: the psk_configs should be in the same order as the ones in the
        PreSharedKeyExtension extension (extra ones are ok)

        :param client_hello: ClientHello to sign
        :param handshake_hashes: hashes of messages exchanged so far
        :param psk_configs: PSK identities and secrets
        """
        ext = client_hello.extensions[-1]
        if not isinstance(ext, PreSharedKeyExtension):
            raise ValueError("Last extension in client_hello must be "
                             "PreSharedKeyExtension")

        hh = handshake_hashes.copy()

        hh.update(client_hello.psk_truncate())

        configs_iter = iter(psk_configs)

        for i, iden in enumerate(ext.identities):
            try:
                config = next(configs_iter)
                while config[0] != iden.identity:
                    config = next(configs_iter)
            except StopIteration:
                raise ValueError("psk_configs don't match the "
                                 "PreSharedKeyExtension")

            binder_hash = config[2] if len(config) > 2 else 'sha256'
            key_len = 32 if binder_hash == 'sha256' else 48

            # HKDF-Extract(0, PSK)
            early_secret = secureHMAC(bytearray(key_len), config[1],
                                      binder_hash)

            binder_key = derive_secret(early_secret, b"ext binder", None,
                                       binder_hash)

            finished_key = HKDF_expand_label(binder_key, b"finished", b'',
                                           key_len, binder_hash)

            binder = secureHMAC(finished_key, hh.digest(binder_hash),
                                binder_hash)

            # replace the fake value with calculated one
            ext.binders[i] = binder
