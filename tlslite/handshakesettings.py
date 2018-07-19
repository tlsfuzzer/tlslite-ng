# Authors:
#   Trevor Perrin
#   Dave Baggett (Arcode Corporation) - cleanup handling of constants
#   Yngve Pettersen (ported by Paul Sokolovsky) - TLS 1.2
#
# See the LICENSE file for legal information regarding use of this file.

"""Class for setting handshake parameters."""

from .constants import CertificateType, TLS_1_3_DRAFT
from .utils import cryptomath
from .utils import cipherfactory
from .utils.compat import ecdsaAllCurves, int_types

CIPHER_NAMES = ["chacha20-poly1305",
                "aes256gcm", "aes128gcm",
                "aes256", "aes128",
                "3des"]
ALL_CIPHER_NAMES = CIPHER_NAMES + ["chacha20-poly1305_draft00",
                                   "rc4", "null"]
# Don't allow "md5" by default
MAC_NAMES = ["sha", "sha256", "sha384", "aead"]
ALL_MAC_NAMES = MAC_NAMES + ["md5"]
KEY_EXCHANGE_NAMES = ["rsa", "dhe_rsa", "ecdhe_rsa", "srp_sha", "srp_sha_rsa",
                      "ecdh_anon", "dh_anon"]
CIPHER_IMPLEMENTATIONS = ["openssl", "pycrypto", "python"]
CERTIFICATE_TYPES = ["x509"]
RSA_SIGNATURE_HASHES = ["sha512", "sha384", "sha256", "sha224", "sha1"]
ALL_RSA_SIGNATURE_HASHES = RSA_SIGNATURE_HASHES + ["md5"]
RSA_SCHEMES = ["pss", "pkcs1"]
# while secp521r1 is the most secure, it's also much slower than the others
# so place it as the last one
CURVE_NAMES = ["x25519", "x448", "secp384r1", "secp256r1",
               "secp521r1"]
ALL_CURVE_NAMES = CURVE_NAMES + ["secp256k1"]
if ecdsaAllCurves:
    ALL_CURVE_NAMES += ["secp224r1", "secp192r1"]
ALL_DH_GROUP_NAMES = ["ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144",
                      "ffdhe8192"]
KNOWN_VERSIONS = ((3, 0), (3, 1), (3, 2), (3, 3), (3, 4))
TICKET_CIPHERS = ["chacha20-poly1305", "aes256gcm", "aes128gcm"]
PSK_MODES = ["psk_dhe_ke", "psk_ke"]


class HandshakeSettings(object):
    """
    This class encapsulates various parameters that can be used with
    a TLS handshake.

    :vartype minKeySize: int
    :ivar minKeySize: The minimum bit length for asymmetric keys.

        If the other party tries to use SRP, RSA, or Diffie-Hellman
        parameters smaller than this length, an alert will be
        signalled.  The default is 1023.


    :vartype maxKeySize: int
    :ivar maxKeySize: The maximum bit length for asymmetric keys.

        If the other party tries to use SRP, RSA, or Diffie-Hellman
        parameters larger than this length, an alert will be signalled.
        The default is 8193.

    :vartype cipherNames: list
    :ivar cipherNames: The allowed ciphers.

        The allowed values in this list are 'chacha20-poly1305', 'aes256gcm',
        'aes128gcm', 'aes256', 'aes128', '3des', 'chacha20-poly1305_draft00',
        'null' and
        'rc4'.  If these settings are used with a client handshake, they
        determine the order of the ciphersuites offered in the ClientHello
        message.

        If these settings are used with a server handshake, the server will
        choose whichever ciphersuite matches the earliest entry in this
        list.

        .. note:: If '3des' is used in this list, but TLS Lite can't find an
            add-on library that supports 3DES, then '3des' will be silently
            removed.

        The default value is list that excludes 'rc4', 'null' and
        'chacha20-poly1305_draft00'.

    :vartype macNames: list
    :ivar macNames: The allowed MAC algorithms.

        The allowed values in this list are 'sha384', 'sha256', 'aead', 'sha'
        and 'md5'.

        The default value is list that excludes 'md5'.

    :vartype certificateTypes: list
    :ivar certificateTypes: The allowed certificate types.

        The only allowed certificate type is 'x509'.  This list is only used
        with a
        client handshake.  The client will advertise to the server which
        certificate
        types are supported, and will check that the server uses one of the
        appropriate types.


    :vartype minVersion: tuple
    :ivar minVersion: The minimum allowed SSL/TLS version.

        This variable can be set to (3, 0) for SSL 3.0, (3, 1) for TLS 1.0,
        (3, 2) for
        TLS 1.1, or (3, 3) for TLS 1.2.  If the other party wishes to use a
        lower
        version, a protocol_version alert will be signalled.  The default is
        (3, 1).

    :vartype maxVersion: tuple
    :ivar maxVersion: The maximum allowed SSL/TLS version.

        This variable can be set to (3, 0) for SSL 3.0, (3, 1) for TLS 1.0,
        (3, 2) for TLS 1.1, or (3, 3) for TLS 1.2.  If the other party wishes
        to use a
        higher version, a protocol_version alert will be signalled.  The
        default is (3, 3).

        .. warning:: Some servers may (improperly) reject clients which offer
            support
            for TLS 1.1 or higher.  In this case, try lowering maxVersion to
            (3, 1).

    :vartype useExperimentalTackExtension: bool
    :ivar useExperimentalTackExtension: Whether to enabled TACK support.

        Note that TACK support is not standardized by IETF and uses a temporary
        TLS Extension number, so should NOT be used in production software.

    :vartype sendFallbackSCSV: bool
    :ivar sendFallbackSCSV: Whether to, as a client, send FALLBACK_SCSV.

    :vartype rsaSigHashes: list
    :ivar rsaSigHashes: List of hashes supported (and advertised as such) for
        TLS 1.2 signatures over Server Key Exchange or Certificate Verify with
        RSA signature algorithm.

        The list is sorted from most wanted to least wanted algorithm.

        The allowed hashes are: "md5", "sha1", "sha224", "sha256",
        "sha384" and "sha512". The default list does not include md5.

    :vartype eccCurves: list
    :ivar eccCurves: List of named curves that are to be supported

    :vartype useEncryptThenMAC: bool
    :ivar useEncryptThenMAC: whether to support the encrypt then MAC extension
        from RFC 7366. True by default.

    :vartype useExtendedMasterSecret: bool
    :ivar useExtendedMasterSecret: whether to support the extended master
        secret calculation from RFC 7627. True by default.

    :vartype requireExtendedMasterSecret: bool
    :ivar requireExtendedMasterSecret: whether to require negotiation of
        extended master secret calculation for successful connection. Requires
        useExtendedMasterSecret to be set to true. False by default.

    :vartype defaultCurve: str
    :ivar defaultCurve: curve that will be used by server in case the client
        did not advertise support for any curves. It does not have to be the
        first curve for eccCurves and may be distinct from curves from that
        list.

    :vartype keyShares: list
    :ivar keyShares: list of TLS 1.3 key shares to include in Client Hello

    :vartype padding_cb: func
    :ivar padding_cb: Callback to function computing number of padding bytes
        for TLS 1.3. Signature is cb_func(msg_size, content_type, max_size).

    :vartype pskConfigs: list of tuples
    :ivar pskConfigs: list of tuples, first element of the tuple is the
        human readable, UTF-8 encoded, "identity" of the associated secret
        (bytearray, can be empty for TLS 1.2 and earlier), second element is
        the binary secret (bytearray), third is an optional parameter
        specifying the PRF hash to be used in TLS 1.3 ('sha256' or 'sha384')

    :vartype ticketKeys: list of bytearray
    :ivar ticketKeys: keys to be used for encrypting and decrypting session
        tickets. First entry is the encryption key for new tickets and the
        default decryption key, subsequent entries are the fallback keys
        allowing for key rollover. The keys need to be of size appropriate
        for a selected cipher in ticketCipher, 32 bytes for 'aes256gcm'.
        Leave empty to disable session ticket support on server side.

    :vartype ticketCipher: str
    :ivar ticketCipher: name of the cipher used for encrypting the session
        tickets. 'aes256gcm' by default

    :vartype ticketLifetime: int
    :ivar ticketLifetime: maximum allowed lifetime of ticket encryption key,
        in seconds. 1 day by default

    :vartype psk_modes: list
    :ivar psk_modes: acceptable modes for the PSK key exchange in TLS 1.3

    :ivar int max_early_data: maximum number of bytes acceptable for 0-RTT
        early_data processing. In other words, how many bytes will the server
        try to process, but ignore, in case the Client Hello includes
        early_data extension.
    """

    def _init_key_settings(self):
        """Create default variables for key-related settings."""
        self.minKeySize = 1023
        self.maxKeySize = 8193
        self.rsaSigHashes = list(RSA_SIGNATURE_HASHES)
        self.rsaSchemes = list(RSA_SCHEMES)
        # DH key settings
        self.eccCurves = list(CURVE_NAMES)
        self.dhParams = None
        self.dhGroups = list(ALL_DH_GROUP_NAMES)
        self.defaultCurve = "secp256r1"
        self.keyShares = ["secp256r1", "x25519"]
        self.padding_cb = None

    def _init_misc_extensions(self):
        """Default variables for assorted extensions."""
        self.certificateTypes = list(CERTIFICATE_TYPES)
        self.useExperimentalTackExtension = False
        self.sendFallbackSCSV = False
        self.useEncryptThenMAC = True
        self.usePaddingExtension = True
        self.useExtendedMasterSecret = True
        self.requireExtendedMasterSecret = False
        # PSKs
        self.pskConfigs = []
        self.psk_modes = list(PSK_MODES)
        # session tickets
        self.ticketKeys = []
        self.ticketCipher = "aes256gcm"
        self.ticketLifetime = 24 * 60 * 60
        self.max_early_data = 2 ** 14 + 16  # full record + tag

    def __init__(self):
        """Initialise default values for settings."""
        self._init_key_settings()
        self._init_misc_extensions()
        self.minVersion = (3, 1)
        self.maxVersion = (3, 4)
        self.versions = [TLS_1_3_DRAFT, (3, 3), (3, 2), (3, 1)]
        self.cipherNames = list(CIPHER_NAMES)
        self.macNames = list(MAC_NAMES)
        self.keyExchangeNames = list(KEY_EXCHANGE_NAMES)
        self.cipherImplementations = list(CIPHER_IMPLEMENTATIONS)

    @staticmethod
    def _sanityCheckKeySizes(other):
        """Check if key size limits are sane"""
        if other.minKeySize < 512:
            raise ValueError("minKeySize too small")
        if other.minKeySize > 16384:
            raise ValueError("minKeySize too large")
        if other.maxKeySize < 512:
            raise ValueError("maxKeySize too small")
        if other.maxKeySize > 16384:
            raise ValueError("maxKeySize too large")
        if other.maxKeySize < other.minKeySize:
            raise ValueError("maxKeySize smaller than minKeySize")

    @staticmethod
    def _not_matching(values, sieve):
        """Return list of items from values that are not in sieve."""
        return [val for val in values if val not in sieve]

    @staticmethod
    def _sanityCheckCipherSettings(other):
        """Check if specified cipher settings are known."""
        not_matching = HandshakeSettings._not_matching
        unknownCiph = not_matching(other.cipherNames, ALL_CIPHER_NAMES)
        if unknownCiph:
            raise ValueError("Unknown cipher name: {0}".format(unknownCiph))

        unknownMac = not_matching(other.macNames, ALL_MAC_NAMES)
        if unknownMac:
            raise ValueError("Unknown MAC name: {0}".format(unknownMac))

        unknownKex = not_matching(other.keyExchangeNames, KEY_EXCHANGE_NAMES)
        if unknownKex:
            raise ValueError("Unknown key exchange name: {0}"
                             .format(unknownKex))

        unknownImpl = not_matching(other.cipherImplementations,
                                   CIPHER_IMPLEMENTATIONS)
        if unknownImpl:
            raise ValueError("Unknown cipher implementation: {0}"
                             .format(unknownImpl))

    @staticmethod
    def _sanityCheckECDHSettings(other):
        """Check ECDHE settings if they are sane."""
        not_matching = HandshakeSettings._not_matching

        unknownCurve = not_matching(other.eccCurves, ALL_CURVE_NAMES)
        if unknownCurve:
            raise ValueError("Unknown ECC Curve name: {0}"
                             .format(unknownCurve))

        if other.defaultCurve not in ALL_CURVE_NAMES:
            raise ValueError("Unknown default ECC Curve name: {0}"
                             .format(other.defaultCurve))

        nonAdvertisedGroup = [val for val in other.keyShares
                              if val not in other.eccCurves and
                              val not in other.dhGroups]
        if nonAdvertisedGroup:
            raise ValueError("Key shares for not enabled groups specified: {0}"
                             .format(nonAdvertisedGroup))

        unknownDHGroup = not_matching(other.dhGroups, ALL_DH_GROUP_NAMES)
        if unknownDHGroup:
            raise ValueError("Unknown FFDHE group name: '{0}'"
                             .format(unknownDHGroup))

    @staticmethod
    def _sanityCheckDHSettings(other):
        """Check if (EC)DHE settings are sane."""
        not_matching = HandshakeSettings._not_matching

        HandshakeSettings._sanityCheckECDHSettings(other)

        unknownKeyShare = [val for val in other.keyShares
                           if val not in ALL_DH_GROUP_NAMES and
                           val not in ALL_CURVE_NAMES]
        if unknownKeyShare:
            raise ValueError("Unknown key share: '{0}'"
                             .format(unknownKeyShare))

        if other.dhParams and (len(other.dhParams) != 2 or
                               not isinstance(other.dhParams[0], int_types) or
                               not isinstance(other.dhParams[1], int_types)):
            raise ValueError("DH parameters need to be a tuple of integers")

    @staticmethod
    def _sanityCheckPrimitivesNames(other):
        """Check if specified cryptographic primitive names are known"""
        HandshakeSettings._sanityCheckCipherSettings(other)
        HandshakeSettings._sanityCheckDHSettings(other)

        not_matching = HandshakeSettings._not_matching

        unknownType = not_matching(other.certificateTypes, CERTIFICATE_TYPES)
        if unknownType:
            raise ValueError("Unknown certificate type: {0}"
                             .format(unknownType))

        unknownSigHash = not_matching(other.rsaSigHashes,
                                      ALL_RSA_SIGNATURE_HASHES)
        if unknownSigHash:
            raise ValueError("Unknown RSA signature hash: '{0}'"
                             .format(unknownSigHash))

        unknownRSAPad = not_matching(other.rsaSchemes, RSA_SCHEMES)
        if unknownRSAPad:
            raise ValueError("Unknown RSA padding mode: '{0}'"
                             .format(unknownRSAPad))

        if not other.rsaSigHashes and other.maxVersion >= (3, 3):
            raise ValueError("TLS 1.2 requires signature algorithms to be set")

    @staticmethod
    def _sanityCheckProtocolVersions(other):
        """Check if set protocol version are sane"""
        if other.minVersion > other.maxVersion:
            raise ValueError("Versions set incorrectly")
        if other.minVersion not in KNOWN_VERSIONS:
            raise ValueError("minVersion set incorrectly")
        if other.maxVersion not in KNOWN_VERSIONS:
            raise ValueError("maxVersion set incorrectly")

        if other.maxVersion < (3, 4):
            other.versions = [i for i in other.versions if i < (3, 4)]

    @staticmethod
    def _sanityCheckEMSExtension(other):
        """Check if settings for EMS are sane."""
        if other.useExtendedMasterSecret not in (True, False):
            raise ValueError("useExtendedMasterSecret must be True or False")
        if other.requireExtendedMasterSecret not in (True, False):
            raise ValueError("requireExtendedMasterSecret must be True "
                             "or False")
        if other.requireExtendedMasterSecret and \
                not other.useExtendedMasterSecret:
            raise ValueError("requireExtendedMasterSecret requires "
                             "useExtendedMasterSecret")

    @staticmethod
    def _sanityCheckExtensions(other):
        """Check if set extension settings are sane"""
        if other.useEncryptThenMAC not in (True, False):
            raise ValueError("useEncryptThenMAC can only be True or False")

        if other.usePaddingExtension not in (True, False):
            raise ValueError("usePaddingExtension must be True or False")

        HandshakeSettings._sanityCheckEMSExtension(other)

    @staticmethod
    def _not_allowed_len(values, sieve):
        """Return True if length of any item in values is not in sieve."""
        sieve = set(sieve)
        return any(len(i) not in sieve for i in values)

    @staticmethod
    def _sanityCheckPsks(other):
        """Check if the set PSKs are sane."""
        if HandshakeSettings._not_allowed_len(other.pskConfigs, [2, 3]):
            raise ValueError("pskConfigs items must be a 2 or 3-element"
                             "tuples")

        badHashes = [i[2] for i in other.pskConfigs if
                     len(i) == 3 and i[2] not in set(['sha256', 'sha384'])]
        if badHashes:
            raise ValueError("pskConfigs include invalid hash specifications: "
                             "{0}".format(badHashes))

        bad_psk_modes = [i for i in other.psk_modes if
                         i not in PSK_MODES]
        if bad_psk_modes:
            raise ValueError("psk_modes includes invalid key exchange modes: "
                             "{0}".format(bad_psk_modes))

    @staticmethod
    def _sanityCheckTicketSettings(other):
        """Check if the session ticket settings are sane."""
        if other.ticketCipher not in TICKET_CIPHERS:
            raise ValueError("Invalid cipher for session ticket encryption: "
                             "{0}".format(other.ticketCipher))

        if HandshakeSettings._not_allowed_len(other.ticketKeys, [16, 32]):
            raise ValueError("Session ticket encryption keys must be 16 or 32"
                             "bytes long")

        if not 0 < other.ticketLifetime <= 7 * 24 * 60 * 60:
            raise ValueError("Ticket lifetime must be a positive integer "
                             "smaller or equal 604800 (7 days)")

        # while not ticket setting per-se, it is related to session tickets
        if not 0 < other.max_early_data <= 2**64:
            raise ValueError("max_early_data must be between 0 and 2GiB")

    def _copy_cipher_settings(self, other):
        """Copy values related to cipher selection."""
        other.cipherNames = self.cipherNames
        other.macNames = self.macNames
        other.keyExchangeNames = self.keyExchangeNames
        other.cipherImplementations = self.cipherImplementations
        other.minVersion = self.minVersion
        other.maxVersion = self.maxVersion
        other.versions = self.versions

    def _copy_extension_settings(self, other):
        """Copy values of settings related to extensions."""
        other.useExtendedMasterSecret = self.useExtendedMasterSecret
        other.requireExtendedMasterSecret = self.requireExtendedMasterSecret
        other.sendFallbackSCSV = self.sendFallbackSCSV
        other.useEncryptThenMAC = self.useEncryptThenMAC
        other.usePaddingExtension = self.usePaddingExtension
        # session tickets
        other.padding_cb = self.padding_cb
        other.ticketKeys = self.ticketKeys
        other.ticketCipher = self.ticketCipher
        other.ticketLifetime = self.ticketLifetime
        other.max_early_data = self.max_early_data

    @staticmethod
    def _remove_all_matches(values, needle):
        """Remove all instances of needle from values."""
        values[:] = (i for i in values if i != needle)

    def _sanity_check_ciphers(self, other):
        """Remove unsupported ciphers in current configuration."""
        if not cipherfactory.tripleDESPresent:
            other.cipherNames = other.cipherNames[:]
            self._remove_all_matches(other.cipherNames, "3des")

        if not other.cipherNames:
            raise ValueError("No supported ciphers")

    def _sanity_check_implementations(self, other):
        """Remove all backends that are not loaded."""
        if not cryptomath.m2cryptoLoaded:
            self._remove_all_matches(other.cipherImplementations, "openssl")
        if not cryptomath.pycryptoLoaded:
            self._remove_all_matches(other.cipherImplementations, "pycrypto")

        if not other.cipherImplementations:
            raise ValueError("No supported cipher implementations")

    def _copy_key_settings(self, other):
        """Copy key-related settings."""
        other.minKeySize = self.minKeySize
        other.maxKeySize = self.maxKeySize
        other.certificateTypes = self.certificateTypes
        other.rsaSigHashes = self.rsaSigHashes
        other.rsaSchemes = self.rsaSchemes
        # DH key params
        other.eccCurves = self.eccCurves
        other.dhParams = self.dhParams
        other.dhGroups = self.dhGroups
        other.defaultCurve = self.defaultCurve
        other.keyShares = self.keyShares

    def validate(self):
        """
        Validate the settings, filter out unsupported ciphersuites and return
        a copy of object. Does not modify the original object.

        :rtype: HandshakeSettings
        :returns: a self-consistent copy of settings
        :raises ValueError: when settings are invalid, insecure or unsupported.
        """
        other = HandshakeSettings()

        self._copy_cipher_settings(other)
        self._copy_extension_settings(other)
        self._copy_key_settings(other)

        other.pskConfigs = self.pskConfigs
        other.psk_modes = self.psk_modes

        if not other.certificateTypes:
            raise ValueError("No supported certificate types")

        self._sanityCheckKeySizes(other)

        self._sanityCheckPrimitivesNames(other)

        self._sanityCheckProtocolVersions(other)

        self._sanityCheckExtensions(other)

        if other.maxVersion < (3, 3):
            # No sha-2 and AEAD pre TLS 1.2
            other.macNames = [e for e in self.macNames if
                              e == "sha" or e == "md5"]

        self._sanityCheckPsks(other)

        self._sanityCheckTicketSettings(other)

        self._sanity_check_implementations(other)
        self._sanity_check_ciphers(other)

        return other

    def getCertificateTypes(self):
        """Get list of certificate types as IDs"""
        ret = []
        for ct in self.certificateTypes:
            if ct == "x509":
                ret.append(CertificateType.x509)
            else:
                raise AssertionError()
        return ret
