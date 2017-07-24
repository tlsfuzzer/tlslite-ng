# Authors:
#   Hubert Kario (2015)
#
# See the LICENSE file for legal information regarding use of this file.
"""Handling of cryptographic operations for key exchange"""

from .mathtls import goodGroupParameters, makeK, makeU, makeX, \
        calcMasterSecret, paramStrength, RFC7919_GROUPS
from .errors import TLSInsufficientSecurity, TLSUnknownPSKIdentity, \
        TLSIllegalParameterException, TLSDecryptionFailed, TLSInternalError, \
        TLSDecodeError
from .messages import ServerKeyExchange, ClientKeyExchange, CertificateVerify
from .constants import SignatureAlgorithm, HashAlgorithm, CipherSuite, \
        ExtensionType, GroupName, ECCurveType, SignatureScheme
from .utils.ecc import decodeX962Point, encodeX962Point, getCurveByName, \
        getPointByteSize
from .utils.rsakey import RSAKey
from .utils.cryptomath import bytesToNumber, getRandomBytes, powMod, \
        numBits, numberToByteArray, divceil
from .utils.lists import getFirstMatching
from .utils import tlshashlib as hashlib
from .utils.x25519 import x25519, x448, X25519_G, X448_G, X25519_ORDER_SIZE, \
        X448_ORDER_SIZE
import ecdsa

class KeyExchange(object):
    """
    Common API for calculating Premaster secret

    NOT stable, will get moved from this file
    """

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey=None):
        """Initialize KeyExchange. privateKey is the signing private key"""
        self.cipherSuite = cipherSuite
        self.clientHello = clientHello
        self.serverHello = serverHello
        self.privateKey = privateKey

    def makeServerKeyExchange(self, sigHash=None):
        """
        Create a ServerKeyExchange object

        Returns a ServerKeyExchange object for the server's initial leg in the
        handshake. If the key exchange method does not send ServerKeyExchange
        (e.g. RSA), it returns None.
        """
        raise NotImplementedError()

    def makeClientKeyExchange(self):
        """
        Create a ClientKeyExchange object

        Returns a ClientKeyExchange for the second flight from client in the
        handshake.
        """
        return ClientKeyExchange(self.cipherSuite,
                                 self.serverHello.server_version)

    def processClientKeyExchange(self, clientKeyExchange):
        """
        Process ClientKeyExchange and return premaster secret

        Processes the client's ClientKeyExchange message and returns the
        premaster secret. Raises TLSLocalAlert on error.
        """
        raise NotImplementedError()

    def processServerKeyExchange(self, srvPublicKey,
                                 serverKeyExchange):
        """Process the server KEX and return premaster secret"""
        raise NotImplementedError()

    def _tls12_signSKE(self, serverKeyExchange, sigHash=None):
        """Sign a TLSv1.2 SKE message."""
        try:
            serverKeyExchange.hashAlg, serverKeyExchange.signAlg = \
                    getattr(SignatureScheme, sigHash)
            keyType = SignatureScheme.getKeyType(sigHash)
            padType = SignatureScheme.getPadding(sigHash)
            hashName = SignatureScheme.getHash(sigHash)
            saltLen = getattr(hashlib, hashName)().digest_size
        except AttributeError:
            serverKeyExchange.signAlg = SignatureAlgorithm.rsa
            serverKeyExchange.hashAlg = getattr(HashAlgorithm, sigHash)
            keyType = 'rsa'
            padType = 'pkcs1'
            hashName = sigHash
            saltLen = 0

        assert keyType == 'rsa'

        hashBytes = serverKeyExchange.hash(self.clientHello.random,
                                           self.serverHello.random)

        serverKeyExchange.signature = \
            self.privateKey.sign(hashBytes,
                                 padding=padType,
                                 hashAlg=hashName,
                                 saltLen=saltLen)

        if not serverKeyExchange.signature:
            raise TLSInternalError("Empty signature")

        if not self.privateKey.verify(serverKeyExchange.signature,
                                      hashBytes,
                                      padding=padType,
                                      hashAlg=hashName,
                                      saltLen=saltLen):
            raise TLSInternalError("Server Key Exchange signature invalid")

    def signServerKeyExchange(self, serverKeyExchange, sigHash=None):
        """
        Sign a server key exchange using default or specified algorithm

        :type sigHash: str
        :param sigHash: name of the signature hash to be used for signing
        """
        if self.serverHello.server_version < (3, 3):
            hashBytes = serverKeyExchange.hash(self.clientHello.random,
                                               self.serverHello.random)

            serverKeyExchange.signature = self.privateKey.sign(hashBytes)

            if not serverKeyExchange.signature:
                raise TLSInternalError("Empty signature")

            if not self.privateKey.verify(serverKeyExchange.signature,
                                          hashBytes):
                raise TLSInternalError("Server Key Exchange signature invalid")
        else:
            self._tls12_signSKE(serverKeyExchange, sigHash)

    @staticmethod
    def _tls12_verify_SKE(serverKeyExchange, publicKey, clientRandom,
                          serverRandom, validSigAlgs):
        """Verify TLSv1.2 version of SKE."""
        if (serverKeyExchange.hashAlg, serverKeyExchange.signAlg) not in \
                validSigAlgs:
            raise TLSIllegalParameterException("Server selected "
                                               "invalid signature "
                                               "algorithm")
        schemeID = (serverKeyExchange.hashAlg,
                    serverKeyExchange.signAlg)
        scheme = SignatureScheme.toRepr(schemeID)
        if scheme is not None:
            keyType = SignatureScheme.getKeyType(scheme)
            padType = SignatureScheme.getPadding(scheme)
            hashName = SignatureScheme.getHash(scheme)
            saltLen = getattr(hashlib, hashName)().digest_size
        else:
            if serverKeyExchange.signAlg != SignatureAlgorithm.rsa:
                raise TLSInternalError("non-RSA sigs are not supported")
            keyType = 'rsa'
            padType = 'pkcs1'
            saltLen = 0
            hashName = HashAlgorithm.toRepr(serverKeyExchange.hashAlg)
            if hashName is None:
                msg = "Unknown hash ID: {0}"\
                        .format(serverKeyExchange.hashAlg)
                raise TLSIllegalParameterException(msg)
        assert keyType == 'rsa'

        hashBytes = serverKeyExchange.hash(clientRandom, serverRandom)

        sigBytes = serverKeyExchange.signature
        if not sigBytes:
            raise TLSIllegalParameterException("Empty signature")

        if not publicKey.verify(sigBytes, hashBytes,
                                padding=padType,
                                hashAlg=hashName,
                                saltLen=saltLen):
            raise TLSDecryptionFailed("Server Key Exchange signature "
                                      "invalid")

    @staticmethod
    def verifyServerKeyExchange(serverKeyExchange, publicKey, clientRandom,
                                serverRandom, validSigAlgs):
        """Verify signature on the Server Key Exchange message

        the only acceptable signature algorithms are specified by validSigAlgs
        """
        if serverKeyExchange.version < (3, 3):
            hashBytes = serverKeyExchange.hash(clientRandom, serverRandom)
            sigBytes = serverKeyExchange.signature

            if not sigBytes:
                raise TLSIllegalParameterException("Empty signature")

            if not publicKey.verify(sigBytes, hashBytes):
                raise TLSDecryptionFailed("Server Key Exchange signature "
                                          "invalid")
        else:
            KeyExchange._tls12_verify_SKE(serverKeyExchange, publicKey,
                                          clientRandom, serverRandom,
                                          validSigAlgs)

    @staticmethod
    def calcVerifyBytes(version, handshakeHashes, signatureAlg,
                        premasterSecret, clientRandom, serverRandom):
        """Calculate signed bytes for Certificate Verify"""
        if version == (3, 0):
            masterSecret = calcMasterSecret(version,
                                            0,
                                            premasterSecret,
                                            clientRandom,
                                            serverRandom)
            verifyBytes = handshakeHashes.digestSSL(masterSecret, b"")
        elif version in ((3, 1), (3, 2)):
            verifyBytes = handshakeHashes.digest()
        elif version == (3, 3):
            scheme = SignatureScheme.toRepr(signatureAlg)
            if scheme is None:
                hashName = HashAlgorithm.toRepr(signatureAlg[0])
                padding = 'pkcs1'
            else:
                hashName = SignatureScheme.getHash(scheme)
                padding = SignatureScheme.getPadding(scheme)
            verifyBytes = handshakeHashes.digest(hashName)
            if padding == 'pkcs1':
                verifyBytes = RSAKey.addPKCS1Prefix(verifyBytes, hashName)
        return verifyBytes

    @staticmethod
    def makeCertificateVerify(version, handshakeHashes, validSigAlgs,
                              privateKey, certificateRequest, premasterSecret,
                              clientRandom, serverRandom):
        """Create a Certificate Verify message

        :param version: protocol version in use
        :param handshakeHashes: the running hash of all handshake messages
        :param validSigAlgs: acceptable signature algorithms for client side,
            applicable only to TLSv1.2 (or later)
        :param certificateRequest: the server provided Certificate Request
            message
        :param premasterSecret: the premaster secret, needed only for SSLv3
        :param clientRandom: client provided random value, needed only for
            SSLv3
        :param serverRandom: server provided random value, needed only for
            SSLv3
        """
        signatureAlgorithm = None
        # in TLS 1.2 we must decide which algorithm to use for signing
        if version == (3, 3):
            serverSigAlgs = certificateRequest.supported_signature_algs
            signatureAlgorithm = getFirstMatching(validSigAlgs, serverSigAlgs)
            # if none acceptable, do a last resort:
            if signatureAlgorithm is None:
                signatureAlgorithm = validSigAlgs[0]
        verifyBytes = KeyExchange.calcVerifyBytes(version, handshakeHashes,
                                                  signatureAlgorithm,
                                                  premasterSecret,
                                                  clientRandom,
                                                  serverRandom)
        scheme = SignatureScheme.toRepr(signatureAlgorithm)
        # for pkcs1 signatures hash is used to add PKCS#1 prefix, but
        # that was already done by calcVerifyBytes
        hashName = None
        saltLen = 0
        if scheme is None:
            padding = 'pkcs1'
        else:
            padding = SignatureScheme.getPadding(scheme)
            if padding == 'pss':
                hashName = SignatureScheme.getHash(scheme)
                saltLen = getattr(hashlib, hashName)().digest_size

        signedBytes = privateKey.sign(verifyBytes,
                                      padding,
                                      hashName,
                                      saltLen)
        if not privateKey.verify(signedBytes, verifyBytes, padding, hashName,
                                 saltLen):
            raise TLSInternalError("Certificate Verify signature invalid")
        certificateVerify = CertificateVerify(version)
        certificateVerify.create(signedBytes, signatureAlgorithm)

        return certificateVerify

class AuthenticatedKeyExchange(KeyExchange):
    """
    Common methods for key exchanges that authenticate Server Key Exchange

    Methods for signing Server Key Exchange message
    """

    def makeServerKeyExchange(self, sigHash=None):
        """Prepare server side of key exchange with selected parameters"""
        ske = super(AuthenticatedKeyExchange, self).makeServerKeyExchange()
        self.signServerKeyExchange(ske, sigHash)
        return ske


class RSAKeyExchange(KeyExchange):
    """
    Handling of RSA key exchange

    NOT stable API, do NOT use
    """

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey):
        super(RSAKeyExchange, self).__init__(cipherSuite, clientHello,
                                             serverHello, privateKey)
        self.encPremasterSecret = None

    def makeServerKeyExchange(self, sigHash=None):
        """Don't create a server key exchange for RSA key exchange"""
        return None

    def processClientKeyExchange(self, clientKeyExchange):
        """Decrypt client key exchange, return premaster secret"""
        premasterSecret = self.privateKey.decrypt(\
            clientKeyExchange.encryptedPreMasterSecret)

        # On decryption failure randomize premaster secret to avoid
        # Bleichenbacher's "million message" attack
        randomPreMasterSecret = getRandomBytes(48)
        if not premasterSecret:
            premasterSecret = randomPreMasterSecret
        elif len(premasterSecret) != 48:
            premasterSecret = randomPreMasterSecret
        else:
            versionCheck = (premasterSecret[0], premasterSecret[1])
            if versionCheck != self.clientHello.client_version:
                #Tolerate buggy IE clients
                if versionCheck != self.serverHello.server_version:
                    premasterSecret = randomPreMasterSecret
        return premasterSecret

    def processServerKeyExchange(self, srvPublicKey,
                                 serverKeyExchange):
        """Generate premaster secret for server"""
        del serverKeyExchange # not present in RSA key exchange
        premasterSecret = getRandomBytes(48)
        premasterSecret[0] = self.clientHello.client_version[0]
        premasterSecret[1] = self.clientHello.client_version[1]

        self.encPremasterSecret = srvPublicKey.encrypt(premasterSecret)
        return premasterSecret

    def makeClientKeyExchange(self):
        """Return a client key exchange with clients key share"""
        clientKeyExchange = super(RSAKeyExchange, self).makeClientKeyExchange()
        clientKeyExchange.createRSA(self.encPremasterSecret)
        return clientKeyExchange


class ADHKeyExchange(KeyExchange):
    """
    Handling of anonymous Diffie-Hellman Key exchange

    FFDHE without signing serverKeyExchange useful for anonymous DH
    """

    def __init__(self, cipherSuite, clientHello, serverHello,
                 dhParams=None, dhGroups=None):
        super(ADHKeyExchange, self).__init__(cipherSuite, clientHello,
                                             serverHello)
#pylint: enable = invalid-name
        self.dh_Xs = None
        self.dh_Yc = None
        if dhParams:
            self.dh_g, self.dh_p = dhParams
        else:
            # 2048-bit MODP Group (RFC 5054, group 3)
            self.dh_g, self.dh_p = goodGroupParameters[2]
        self.dhGroups = dhGroups

    def makeServerKeyExchange(self):
        """
        Prepare server side of anonymous key exchange with selected parameters
        """
        # Check for RFC 7919 support
        ext = self.clientHello.getExtension(ExtensionType.supported_groups)
        if ext and self.dhGroups:
            commonGroup = getFirstMatching(ext.groups, self.dhGroups)
            if commonGroup:
                self.dh_g, self.dh_p = RFC7919_GROUPS[commonGroup - 256]
            elif getFirstMatching(ext.groups, range(256, 512)):
                raise TLSInternalError("DHE key exchange attempted despite no "
                                       "overlap between supported groups")

        # Per RFC 3526, Section 1, the exponent should have double the entropy
        # of the strength of the group.
        randBytesNeeded = divceil(paramStrength(self.dh_p) * 2, 8)
        self.dh_Xs = bytesToNumber(getRandomBytes(randBytesNeeded))
        dh_Ys = powMod(self.dh_g, self.dh_Xs, self.dh_p)

        version = self.serverHello.server_version
        serverKeyExchange = ServerKeyExchange(self.cipherSuite, version)
        serverKeyExchange.createDH(self.dh_p, self.dh_g, dh_Ys)
        # No sign for anonymous ServerKeyExchange.
        return serverKeyExchange

    def processClientKeyExchange(self, clientKeyExchange):
        """Use client provided parameters to establish premaster secret"""
        dh_Yc = clientKeyExchange.dh_Yc

        # First half of RFC 2631, Section 2.1.5. Validate the client's public
        # key.
        # use of safe primes also means that the p-1 is invalid
        if not 2 <= dh_Yc < self.dh_p - 1:
            raise TLSIllegalParameterException("Invalid dh_Yc value")

        S = powMod(dh_Yc, self.dh_Xs, self.dh_p)
        if S in (1, self.dh_p - 1):
            raise TLSIllegalParameterException("Small subgroup capture")
        return numberToByteArray(S)

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Process the server key exchange, return premaster secret."""
        del srvPublicKey
        dh_p = serverKeyExchange.dh_p
        # TODO make the minimum changeable
        if dh_p < 2**1023:
            raise TLSInsufficientSecurity("DH prime too small")

        dh_g = serverKeyExchange.dh_g
        if not 2 <= dh_g < dh_p - 1:
            raise TLSIllegalParameterException("Invalid DH generator")

        dh_Xc = bytesToNumber(getRandomBytes(32))
        dh_Ys = serverKeyExchange.dh_Ys
        if not 2 <= dh_Ys < dh_p - 1:
            raise TLSIllegalParameterException("Invalid server key share")

        self.dh_Yc = powMod(dh_g, dh_Xc, dh_p)
        if self.dh_Yc in (1, dh_p - 1):
            raise TLSIllegalParameterException("Small subgroup capture")

        S = powMod(dh_Ys, dh_Xc, dh_p)
        if S in (1, dh_p - 1):
            raise TLSIllegalParameterException("Small subgroup capture")

        return numberToByteArray(S)

    def makeClientKeyExchange(self):
        """Create client key share for the key exchange"""
        cke = super(ADHKeyExchange, self).makeClientKeyExchange()
        cke.createDH(self.dh_Yc)
        return cke


# the DHE_RSA part comes from IETF ciphersuite names, we want to keep it
#pylint: disable = invalid-name
class DHE_RSAKeyExchange(AuthenticatedKeyExchange, ADHKeyExchange):
    """
    Handling of authenticated ephemeral Diffe-Hellman Key exchange.
    """

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey,
                 dhParams=None, dhGroups=None):
        """
        Create helper object for Diffie-Hellamn key exchange.

        :param dhParams: Diffie-Hellman parameters that will be used by
            server. First element of the tuple is the generator, the second
            is the prime. If not specified it will use a secure set (currently
            a 2048-bit safe prime).
        :type dhParams: 2-element tuple of int
        """
        super(DHE_RSAKeyExchange, self).__init__(cipherSuite, clientHello,
                                                 serverHello, dhParams,
                                                 dhGroups)
#pylint: enable = invalid-name
        self.privateKey = privateKey


class AECDHKeyExchange(KeyExchange):
    """
    Handling of anonymous Eliptic curve Diffie-Hellman Key exchange

    ECDHE without signing serverKeyExchange useful for anonymous ECDH
    """

    @staticmethod
    def _non_zero_check(value):
        """
        Verify using constant time operation that the bytearray is not zero

        :raises TLSIllegalParameterException: if the value is all zero
        """
        summa = 0
        for i in value:
            summa |= i
        if summa == 0:
            raise TLSIllegalParameterException("Invalid key share")

    def __init__(self, cipherSuite, clientHello, serverHello, acceptedCurves,
                 defaultCurve=GroupName.secp256r1):
        super(AECDHKeyExchange, self).__init__(cipherSuite, clientHello,
                                               serverHello)
        self.ecdhXs = None
        self.acceptedCurves = acceptedCurves
        self.group_id = None
        self.ecdhYc = None
        self.defaultCurve = defaultCurve

    def makeServerKeyExchange(self, sigHash=None):
        """Create AECDHE version of Server Key Exchange"""
        #Get client supported groups
        client_curves = self.clientHello.getExtension(
                ExtensionType.supported_groups)
        if client_curves is None:
            # in case there is no extension, we can pick any curve,
            # use the configured one
            client_curves = [self.defaultCurve]
        elif not client_curves.groups:
            # extension should have been validated before
            raise TLSInternalError("Can't do ECDHE with no client curves")
        else:
            client_curves = client_curves.groups

        #Pick first client preferred group we support
        self.group_id = getFirstMatching(client_curves, self.acceptedCurves)
        if self.group_id is None:
            raise TLSInsufficientSecurity("No mutual groups")
        if self.group_id in [GroupName.x25519, GroupName.x448]:
            if self.group_id == GroupName.x25519:
                generator = bytearray(X25519_G)
                fun = x25519
                self.ecdhXs = getRandomBytes(X25519_ORDER_SIZE)
            else:
                generator = bytearray(X448_G)
                fun = x448
                self.ecdhXs = getRandomBytes(X448_ORDER_SIZE)
            ecdhYs = fun(self.ecdhXs, generator)
        else:
            curve = getCurveByName(GroupName.toRepr(self.group_id))
            generator = curve.generator
            self.ecdhXs = ecdsa.util.randrange(generator.order())

            ecdhYs = encodeX962Point(generator * self.ecdhXs)

        version = self.serverHello.server_version
        serverKeyExchange = ServerKeyExchange(self.cipherSuite, version)
        serverKeyExchange.createECDH(ECCurveType.named_curve,
                                     named_curve=self.group_id,
                                     point=ecdhYs)
        # No sign for anonymous ServerKeyExchange
        return serverKeyExchange

    def processClientKeyExchange(self, clientKeyExchange):
        """Calculate premaster secret from previously generated SKE and CKE"""
        ecdhYc = clientKeyExchange.ecdh_Yc

        if not ecdhYc:
            raise TLSDecodeError("No key share")
        if self.group_id in [GroupName.x25519, GroupName.x448]:
            if self.group_id == GroupName.x25519:
                if len(ecdhYc) != X25519_ORDER_SIZE:
                    raise TLSIllegalParameterException("Invalid key share")
                sharedSecret = x25519(self.ecdhXs, ecdhYc)
            else:
                if len(ecdhYc) != X448_ORDER_SIZE:
                    raise TLSIllegalParameterException("Invalid key share")
                sharedSecret = x448(self.ecdhXs, ecdhYc)
            self._non_zero_check(sharedSecret)
            return sharedSecret
        else:
            curveName = GroupName.toRepr(self.group_id)
            try:
                ecdhYc = decodeX962Point(ecdhYc,
                                         getCurveByName(curveName))
            # TODO update python-ecdsa library to raise something more on point
            except AssertionError:
                raise TLSIllegalParameterException("Invalid ECC point")

            sharedSecret = ecdhYc * self.ecdhXs

            return numberToByteArray(sharedSecret.x(),
                                     getPointByteSize(ecdhYc))

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Process the server key exchange, return premaster secret"""
        del srvPublicKey

        if serverKeyExchange.curve_type != ECCurveType.named_curve \
            or serverKeyExchange.named_curve not in self.acceptedCurves:
            raise TLSIllegalParameterException("Server picked curve we "
                                               "didn't advertise")

        if serverKeyExchange.named_curve in [GroupName.x25519,
                                             GroupName.x448]:
            if serverKeyExchange.named_curve == GroupName.x25519:
                generator = bytearray(X25519_G)
                fun = x25519
                ecdhXc = getRandomBytes(X25519_ORDER_SIZE)
                if len(serverKeyExchange.ecdh_Ys) != X25519_ORDER_SIZE:
                    raise TLSIllegalParameterException("Invalid server key "
                                                       "share")
            else:
                generator = bytearray(X448_G)
                fun = x448
                ecdhXc = getRandomBytes(X448_ORDER_SIZE)
                if len(serverKeyExchange.ecdh_Ys) != X448_ORDER_SIZE:
                    raise TLSIllegalParameterException("Invalid server key "
                                                       "share")
            self.ecdhYc = fun(ecdhXc, generator)
            S = fun(ecdhXc, serverKeyExchange.ecdh_Ys)
            # check if the secret is not all-zero
            self._non_zero_check(S)
            return S
        else:
            curveName = GroupName.toStr(serverKeyExchange.named_curve)
            curve = getCurveByName(curveName)
            generator = curve.generator

            ecdhXc = ecdsa.util.randrange(generator.order())
            ecdhYs = decodeX962Point(serverKeyExchange.ecdh_Ys, curve)
            self.ecdhYc = encodeX962Point(generator * ecdhXc)
            S = ecdhYs * ecdhXc
            return numberToByteArray(S.x(), getPointByteSize(S))

    def makeClientKeyExchange(self):
        """Make client key exchange for ECDHE"""
        cke = super(AECDHKeyExchange, self).makeClientKeyExchange()
        cke.createECDH(self.ecdhYc)
        return cke


# The ECDHE_RSA part comes from the IETF names of ciphersuites, so we want to
# keep it
#pylint: disable = invalid-name
class ECDHE_RSAKeyExchange(AuthenticatedKeyExchange, AECDHKeyExchange):
    """Helper class for conducting ECDHE key exchange"""

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey,
                 acceptedCurves, defaultCurve=GroupName.secp256r1):
        super(ECDHE_RSAKeyExchange, self).__init__(cipherSuite, clientHello,
                                                   serverHello,
                                                   acceptedCurves,
                                                   defaultCurve)
#pylint: enable = invalid-name
        self.privateKey = privateKey


class SRPKeyExchange(KeyExchange):
    """Helper class for conducting SRP key exchange"""

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey,
                 verifierDB, srpUsername=None, password=None, settings=None):
        """Link Key Exchange options with verifierDB for SRP"""
        super(SRPKeyExchange, self).__init__(cipherSuite, clientHello,
                                             serverHello, privateKey)
        self.N = None
        self.v = None
        self.b = None
        self.B = None
        self.verifierDB = verifierDB
        self.A = None
        self.srpUsername = srpUsername
        self.password = password
        self.settings = settings
        if srpUsername is not None and not isinstance(srpUsername, bytearray):
            raise TypeError("srpUsername must be a bytearray object")
        if password is not None and not isinstance(password, bytearray):
            raise TypeError("password must be a bytearray object")

    def makeServerKeyExchange(self, sigHash=None):
        """Create SRP version of Server Key Exchange"""
        srpUsername = bytes(self.clientHello.srp_username)
        #Get parameters from username
        try:
            entry = self.verifierDB[srpUsername]
        except KeyError:
            raise TLSUnknownPSKIdentity("Unknown identity")
        (self.N, g, s, self.v) = entry

        #Calculate server's ephemeral DH values (b, B)
        self.b = bytesToNumber(getRandomBytes(32))
        k = makeK(self.N, g)
        self.B = (powMod(g, self.b, self.N) + (k * self.v)) % self.N

        #Create ServerKeyExchange, signing it if necessary
        serverKeyExchange = ServerKeyExchange(self.cipherSuite,
                                              self.serverHello.server_version)
        serverKeyExchange.createSRP(self.N, g, s, self.B)
        if self.cipherSuite in CipherSuite.srpCertSuites:
            self.signServerKeyExchange(serverKeyExchange, sigHash)
        return serverKeyExchange

    def processClientKeyExchange(self, clientKeyExchange):
        """Calculate premaster secret from Client Key Exchange and sent SKE"""
        A = clientKeyExchange.srp_A
        if A % self.N == 0:
            raise TLSIllegalParameterException("Invalid SRP A value")

        #Calculate u
        u = makeU(self.N, A, self.B)

        #Calculate premaster secret
        S = powMod((A * powMod(self.v, u, self.N)) % self.N, self.b, self.N)
        return numberToByteArray(S)

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Calculate premaster secret from ServerKeyExchange"""
        del srvPublicKey # irrelevant for SRP
        N = serverKeyExchange.srp_N
        g = serverKeyExchange.srp_g
        s = serverKeyExchange.srp_s
        B = serverKeyExchange.srp_B

        if (g, N) not in goodGroupParameters:
            raise TLSInsufficientSecurity("Unknown group parameters")
        if numBits(N) < self.settings.minKeySize:
            raise TLSInsufficientSecurity("N value is too small: {0}".\
                                          format(numBits(N)))
        if numBits(N) > self.settings.maxKeySize:
            raise TLSInsufficientSecurity("N value is too large: {0}".\
                                          format(numBits(N)))
        if B % N == 0:
            raise TLSIllegalParameterException("Suspicious B value")

        #Client ephemeral value
        a = bytesToNumber(getRandomBytes(32))
        self.A = powMod(g, a, N)

        #Calculate client's static DH values (x, v)
        x = makeX(s, self.srpUsername, self.password)
        v = powMod(g, x, N)

        #Calculate u
        u = makeU(N, self.A, B)

        #Calculate premaster secret
        k = makeK(N, g)
        S = powMod((B - (k*v)) % N, a+(u*x), N)
        return numberToByteArray(S)

    def makeClientKeyExchange(self):
        """Create ClientKeyExchange"""
        cke = super(SRPKeyExchange, self).makeClientKeyExchange()
        cke.createSRP(self.A)
        return cke
