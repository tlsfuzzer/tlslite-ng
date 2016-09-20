# Authors:
#   Hubert Kario (2015)
#
# See the LICENSE file for legal information regarding use of this file.
"""Handling of cryptographic operations for key exchange"""

from .mathtls import goodGroupParameters, makeK, makeU, makeX, calcMasterSecret
from .errors import TLSInsufficientSecurity, TLSUnknownPSKIdentity, \
        TLSIllegalParameterException, TLSDecryptionFailed, TLSInternalError
from .messages import ServerKeyExchange, ClientKeyExchange, CertificateVerify
from .constants import SignatureAlgorithm, HashAlgorithm, CipherSuite, \
        ExtensionType, GroupName, ECCurveType
from .utils.ecc import decodeX962Point, encodeX962Point, getCurveByName, \
        getPointByteSize
from .utils.rsakey import RSAKey
from .utils.cryptomath import bytesToNumber, getRandomBytes, powMod, \
        numBits, numberToByteArray
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

    def signServerKeyExchange(self, serverKeyExchange, sigHash=None):
        """
        Sign a server key best matching supported algorithms

        @type sigHash: str
        @param sigHash: name of the hash used for signing
        """
        if self.serverHello.server_version >= (3, 3):
            serverKeyExchange.signAlg = SignatureAlgorithm.rsa
            serverKeyExchange.hashAlg = getattr(HashAlgorithm, sigHash)
        hashBytes = serverKeyExchange.hash(self.clientHello.random,
                                           self.serverHello.random)

        if self.serverHello.server_version >= (3, 3):
            hashBytes = RSAKey.addPKCS1Prefix(hashBytes, sigHash)

        serverKeyExchange.signature = self.privateKey.sign(hashBytes)

        if not serverKeyExchange.signature:
            raise TLSInternalError("Empty signature")

        if not self.privateKey.verify(serverKeyExchange.signature, hashBytes):
            raise TLSInternalError("Server Key Exchange signature invalid")

    @staticmethod
    def verifyServerKeyExchange(serverKeyExchange, publicKey, clientRandom,
                                serverRandom, validSigAlgs):
        """Verify signature on the Server Key Exchange message

        the only acceptable signature algorithms are specified by validSigAlgs
        """
        if serverKeyExchange.version >= (3, 3):
            if (serverKeyExchange.hashAlg, serverKeyExchange.signAlg) not in \
                validSigAlgs:
                raise TLSIllegalParameterException("Server selected "
                                                   "invalid signature "
                                                   "algorithm")
            assert serverKeyExchange.signAlg == SignatureAlgorithm.rsa
            hashName = HashAlgorithm.toRepr(serverKeyExchange.hashAlg)
            if hashName is None:
                raise TLSIllegalParameterException("Unknown signature "
                                                   "algorithm")
        hashBytes = serverKeyExchange.hash(clientRandom, serverRandom)

        if serverKeyExchange.version == (3, 3):
            hashBytes = RSAKey.addPKCS1Prefix(hashBytes, hashName)

        sigBytes = serverKeyExchange.signature
        if not sigBytes:
            raise TLSIllegalParameterException("Empty signature")

        if not publicKey.verify(sigBytes, hashBytes):
            raise TLSDecryptionFailed("Server Key Exchange signature "
                                      "invalid")

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
            hashName = HashAlgorithm.toRepr(signatureAlg[0])
            verifyBytes = handshakeHashes.digest(hashName)
            verifyBytes = RSAKey.addPKCS1Prefix(verifyBytes, hashName)
        return verifyBytes

    @staticmethod
    def makeCertificateVerify(version, handshakeHashes, validSigAlgs,
                              privateKey, certificateRequest, premasterSecret,
                              clientRandom, serverRandom):
        """Create a Certificate Verify message

        @param version: protocol version in use
        @param handshakeHashes: the running hash of all handshake messages
        @param validSigAlgs: acceptable signature algorithms for client side,
        applicable only to TLSv1.2 (or later)
        @param certificateRequest: the server provided Certificate Request
        message
        @param premasterSecret: the premaster secret, needed only for SSLv3
        @param clientRandom: client provided random value, needed only for SSLv3
        @param serverRandom: server provided random value, needed only for SSLv3
        """
        signatureAlgorithm = None
        # in TLS 1.2 we must decide which algorithm to use for signing
        if version == (3, 3):
            serverSigAlgs = certificateRequest.supported_signature_algs
            signatureAlgorithm = next((sigAlg for sigAlg in validSigAlgs \
                                      if sigAlg in serverSigAlgs), None)
            # if none acceptable, do a last resort:
            if signatureAlgorithm is None:
                signatureAlgorithm = validSigAlgs[0]
        verifyBytes = KeyExchange.calcVerifyBytes(version, handshakeHashes,
                                                  signatureAlgorithm,
                                                  premasterSecret,
                                                  clientRandom,
                                                  serverRandom)
        signedBytes = privateKey.sign(verifyBytes)
        certificateVerify = CertificateVerify(version)
        certificateVerify.create(signedBytes, signatureAlgorithm)

        return certificateVerify


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

    def __init__(self, cipherSuite, clientHello, serverHello):
        super(ADHKeyExchange, self).__init__(cipherSuite, clientHello,
                                             serverHello)
#pylint: enable = invalid-name
        self.dh_Xs = None
        self.dh_Yc = None

    # 2048-bit MODP Group (RFC 3526, Section 3)
    # TODO make configurable
    dh_g, dh_p = goodGroupParameters[2]

    # RFC 3526, Section 8.
    strength = 160

    def makeServerKeyExchange(self):
        """
        Prepare server side of anonymous key exchange with selected parameters
        """
        # Per RFC 3526, Section 1, the exponent should have double the entropy
        # of the strength of the curve.
        self.dh_Xs = bytesToNumber(getRandomBytes(self.strength * 2 // 8))
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
        if not 2 <= dh_Yc <= self.dh_p - 1:
            raise TLSIllegalParameterException("Invalid dh_Yc value")

        S = powMod(dh_Yc, self.dh_Xs, self.dh_p)
        return numberToByteArray(S)

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Process the server key exchange, return premaster secret"""
        del srvPublicKey
        dh_p = serverKeyExchange.dh_p
        # TODO make the minimum changeable
        if dh_p < 2**1023:
            raise TLSInsufficientSecurity("DH prime too small")
        dh_g = serverKeyExchange.dh_g
        dh_Xc = bytesToNumber(getRandomBytes(32))
        dh_Ys = serverKeyExchange.dh_Ys
        self.dh_Yc = powMod(dh_g, dh_Xc, dh_p)

        S = powMod(dh_Ys, dh_Xc, dh_p)
        return numberToByteArray(S)

    def makeClientKeyExchange(self):
        """Create client key share for the key exchange"""
        cke = super(ADHKeyExchange, self).makeClientKeyExchange()
        cke.createDH(self.dh_Yc)
        return cke


# the DHE_RSA part comes from IETF ciphersuite names, we want to keep it
#pylint: disable = invalid-name
class DHE_RSAKeyExchange(ADHKeyExchange):
    """
    Handling of ephemeral Diffe-Hellman Key exchange

    NOT stable API, do NOT use
    """

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey):
        super(DHE_RSAKeyExchange, self).__init__(cipherSuite, clientHello,
                                                 serverHello)
#pylint: enable = invalid-name
        self.privateKey = privateKey

    def makeServerKeyExchange(self, sigHash=None):
        """Prepare server side of key exchange with selected parameters"""
        ske = super(DHE_RSAKeyExchange, self).makeServerKeyExchange()
        self.signServerKeyExchange(ske, sigHash)
        return ske


class AECDHKeyExchange(KeyExchange):
    """
    Handling of anonymous Eliptic curve Diffie-Hellman Key exchange

    ECDHE without signing serverKeyExchange useful for anonymous ECDH
    """
    def __init__(self, cipherSuite, clientHello, serverHello, acceptedCurves):
        super(AECDHKeyExchange, self).__init__(cipherSuite, clientHello,
                                               serverHello)
        self.ecdhXs = None
        self.acceptedCurves = acceptedCurves
        self.group_id = None
        self.ecdhYc = None

    def makeServerKeyExchange(self, sigHash=None):
        """Create AECDHE version of Server Key Exchange"""
        #Get client supported groups
        client_curves = self.clientHello.getExtension(\
                ExtensionType.supported_groups)
        if client_curves is None or client_curves.groups is None or \
                len(client_curves.groups) == 0:
            raise TLSInternalError("Can't do ECDHE with no client curves")
        client_curves = client_curves.groups

        #Pick first client preferred group we support
        self.group_id = next((x for x in client_curves \
                              if x in self.acceptedCurves), None)
        if self.group_id is None:
            raise TLSInsufficientSecurity("No mutual groups")
        generator = getCurveByName(GroupName.toRepr(self.group_id)).generator
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
        curveName = GroupName.toRepr(self.group_id)
        try:
            ecdhYc = decodeX962Point(clientKeyExchange.ecdh_Yc,
                                     getCurveByName(curveName))
        # TODO update python-ecdsa library to raise something more on point
        except AssertionError:
            raise TLSIllegalParameterException("Invalid ECC point")

        sharedSecret = ecdhYc * self.ecdhXs

        return numberToByteArray(sharedSecret.x(), getPointByteSize(ecdhYc))

    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange):
        """Process the server key exchange, return premaster secret"""
        del srvPublicKey

        if serverKeyExchange.curve_type != ECCurveType.named_curve \
            or serverKeyExchange.named_curve not in self.acceptedCurves:
            raise TLSIllegalParameterException("Server picked curve we "
                                               "didn't advertise")

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
class ECDHE_RSAKeyExchange(AECDHKeyExchange):
    """Helper class for conducting ECDHE key exchange"""

    def __init__(self, cipherSuite, clientHello, serverHello, privateKey,
                 acceptedCurves):
        super(ECDHE_RSAKeyExchange, self).__init__(cipherSuite, clientHello,
                                                   serverHello,
                                                   acceptedCurves)
#pylint: enable = invalid-name
        self.privateKey = privateKey

    def makeServerKeyExchange(self, sigHash=None):
        """Create ECDHE version of Server Key Exchange"""
        ske = super(ECDHE_RSAKeyExchange, self).makeServerKeyExchange()
        self.signServerKeyExchange(ske, sigHash)
        return ske


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
