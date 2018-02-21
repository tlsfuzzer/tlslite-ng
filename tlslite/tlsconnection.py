# Authors:
#   Trevor Perrin
#   Google - added reqCAs parameter
#   Google (adapted by Sam Rushing and Marcelo Fernandez) - NPN support
#   Google - FALLBACK_SCSV
#   Dimitris Moraitis - Anon ciphersuites
#   Martin von Loewis - python 3 port
#   Yngve Pettersen (ported by Paul Sokolovsky) - TLS 1.2
#   Hubert Kario - complete refactoring of key exchange methods, addition
#          of ECDH support
#
# See the LICENSE file for legal information regarding use of this file.

"""
MAIN CLASS FOR TLS LITE (START HERE!).
"""

from __future__ import division
import socket
from .utils.compat import formatExceptionTrace
from .tlsrecordlayer import TLSRecordLayer
from .session import Session
from .constants import *
from .utils.cryptomath import getRandomBytes
from .utils.dns_utils import is_valid_hostname
from .utils.lists import getFirstMatching
from .errors import *
from .messages import *
from .mathtls import *
from .handshakesettings import HandshakeSettings
from .utils.tackwrapper import *
from .utils.deprecations import deprecated_params
from .keyexchange import KeyExchange, RSAKeyExchange, DHE_RSAKeyExchange, \
        ECDHE_RSAKeyExchange, SRPKeyExchange, ADHKeyExchange, AECDHKeyExchange
from .handshakehelpers import HandshakeHelpers

class TLSConnection(TLSRecordLayer):
    """
    This class wraps a socket and provides TLS handshaking and data transfer.

    To use this class, create a new instance, passing a connected
    socket into the constructor.  Then call some handshake function.
    If the handshake completes without raising an exception, then a TLS
    connection has been negotiated.  You can transfer data over this
    connection as if it were a socket.

    This class provides both synchronous and asynchronous versions of
    its key functions.  The synchronous versions should be used when
    writing single-or multi-threaded code using blocking sockets.  The
    asynchronous versions should be used when performing asynchronous,
    event-based I/O with non-blocking sockets.

    Asynchronous I/O is a complicated subject; typically, you should
    not use the asynchronous functions directly, but should use some
    framework like asyncore or Twisted which TLS Lite integrates with
    (see
    :py:class:`~.integration.tlsasyncdispatchermixin.TLSAsyncDispatcherMixIn`).
    """

    def __init__(self, sock):
        """Create a new TLSConnection instance.

        :param sock: The socket data will be transmitted on.  The
            socket should already be connected.  It may be in blocking or
            non-blocking mode.

        :type sock: socket.socket
        """
        TLSRecordLayer.__init__(self, sock)
        self.serverSigAlg = None
        self.ecdhCurve = None
        self.dhGroupSize = None
        self.extendedMasterSecret = False
        self._clientRandom = bytearray(0)
        self._serverRandom = bytearray(0)

    def keyingMaterialExporter(self, label, length=20):
        """Return keying material as described in RFC 5705

        :type label: bytearray
        :param label: label to be provided for the exporter

        :type length: int
        :param length: number of bytes of the keying material to export
        """
        if label in (b'server finished', b'client finished',
                     b'master secret', b'key expansion'):
            raise ValueError("Forbidden label value")
        if self.version < (3, 1):
            raise ValueError("Supported only in TLSv1.0 and later")
        elif self.version < (3, 3):
            return PRF(self.session.masterSecret, label,
                       self._clientRandom + self._serverRandom,
                       length)
        elif self.version == (3, 3):
            if self.session.cipherSuite in CipherSuite.sha384PrfSuites:
                return PRF_1_2_SHA384(self.session.masterSecret, label,
                                      self._clientRandom + self._serverRandom,
                                      length)
            else:
                return PRF_1_2(self.session.masterSecret, label,
                               self._clientRandom + self._serverRandom,
                               length)
        else:
            raise AssertionError("Unknown protocol version")

    #*********************************************************
    # Client Handshake Functions
    #*********************************************************

    @deprecated_params({"async_": "async"},
                       "'{old_name}' is a keyword in Python 3.7, use"
                       "'{new_name}'")
    def handshakeClientAnonymous(self, session=None, settings=None,
                                 checker=None, serverName=None,
                                 async_=False):
        """Perform an anonymous handshake in the role of client.

        This function performs an SSL or TLS handshake using an
        anonymous Diffie Hellman ciphersuite.

        Like any handshake function, this can be called on a closed
        TLS connection, or on a TLS connection that is already open.
        If called on an open connection it performs a re-handshake.

        If the function completes without raising an exception, the
        TLS connection will be open and available for data transfer.

        If an exception is raised, the connection will have been
        automatically closed (if it was ever open).

        :type session: ~tlslite.session.Session
        :param session: A TLS session to attempt to resume.  If the
            resumption does not succeed, a full handshake will be
            performed.

        :type settings: ~tlslite.handshakesettings.HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites, certificate types, and SSL/TLS versions
            offered by the client.

        :type checker: ~tlslite.checker.Checker
        :param checker: A Checker instance.  This instance will be
            invoked to examine the other party's authentication
            credentials, if the handshake completes succesfully.

        :type serverName: string
        :param serverName: The ServerNameIndication TLS Extension.

        :type async_: bool
        :param async_: If False, this function will block until the
            handshake is completed.  If True, this function will return a
            generator.  Successive invocations of the generator will
            return 0 if it is waiting to read from the socket, 1 if it is
            waiting to write to the socket, or will raise StopIteration if
            the handshake operation is completed.

        :rtype: None or an iterable
        :returns: If 'async_' is True, a generator object will be
            returned.

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        :raises tlslite.errors.TLSAuthenticationError: If the checker
            doesn't like the other party's authentication credentials.
        """
        handshaker = self._handshakeClientAsync(anonParams=(True),
                                                session=session,
                                                settings=settings,
                                                checker=checker,
                                                serverName=serverName)
        if async_:
            return handshaker
        for result in handshaker:
            pass

    @deprecated_params({"async_": "async"},
                       "'{old_name}' is a keyword in Python 3.7, use"
                       "'{new_name}'")
    def handshakeClientSRP(self, username, password, session=None,
                           settings=None, checker=None,
                           reqTack=True, serverName=None,
                           async_=False):
        """Perform an SRP handshake in the role of client.

        This function performs a TLS/SRP handshake.  SRP mutually
        authenticates both parties to each other using only a
        username and password.  This function may also perform a
        combined SRP and server-certificate handshake, if the server
        chooses to authenticate itself with a certificate chain in
        addition to doing SRP.

        If the function completes without raising an exception, the
        TLS connection will be open and available for data transfer.

        If an exception is raised, the connection will have been
        automatically closed (if it was ever open).

        :type username: bytearray
        :param username: The SRP username.

        :type password: bytearray
        :param password: The SRP password.

        :type session: ~tlslite.session.Session
        :param session: A TLS session to attempt to resume.  This
            session must be an SRP session performed with the same username
            and password as were passed in.  If the resumption does not
            succeed, a full SRP handshake will be performed.

        :type settings: ~tlslite.handshakesettings.HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites, certificate types, and SSL/TLS versions
            offered by the client.

        :type checker: ~tlslite.checker.Checker
        :param checker: A Checker instance.  This instance will be
            invoked to examine the other party's authentication
            credentials, if the handshake completes succesfully.

        :type reqTack: bool
        :param reqTack: Whether or not to send a "tack" TLS Extension,
            requesting the server return a TackExtension if it has one.

        :type serverName: string
        :param serverName: The ServerNameIndication TLS Extension.

        :type async_: bool
        :param async_: If False, this function will block until the
            handshake is completed.  If True, this function will return a
            generator.  Successive invocations of the generator will
            return 0 if it is waiting to read from the socket, 1 if it is
            waiting to write to the socket, or will raise StopIteration if
            the handshake operation is completed.

        :rtype: None or an iterable
        :returns: If 'async_' is True, a generator object will be
            returned.

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        :raises tlslite.errors.TLSAuthenticationError: If the checker
            doesn't like the other party's authentication credentials.
        """
        # TODO add deprecation warning
        if isinstance(username, str):
            username = bytearray(username, 'utf-8')
        if isinstance(password, str):
            password = bytearray(password, 'utf-8')
        handshaker = self._handshakeClientAsync(srpParams=(username, password),
                        session=session, settings=settings, checker=checker,
                        reqTack=reqTack, serverName=serverName)
        # The handshaker is a Python Generator which executes the handshake.
        # It allows the handshake to be run in a "piecewise", asynchronous
        # fashion, returning 1 when it is waiting to able to write, 0 when
        # it is waiting to read.
        #
        # If 'async_' is True, the generator is returned to the caller,
        # otherwise it is executed to completion here.  
        if async_:
            return handshaker
        for result in handshaker:
            pass

    @deprecated_params({"async_": "async"},
                       "'{old_name}' is a keyword in Python 3.7, use"
                       "'{new_name}'")
    def handshakeClientCert(self, certChain=None, privateKey=None,
                            session=None, settings=None, checker=None,
                            nextProtos=None, reqTack=True, serverName=None,
                            async_=False, alpn=None):
        """Perform a certificate-based handshake in the role of client.

        This function performs an SSL or TLS handshake.  The server
        will authenticate itself using an X.509 certificate
        chain.  If the handshake succeeds, the server's certificate
        chain will be stored in the session's serverCertChain attribute.
        Unless a checker object is passed in, this function does no
        validation or checking of the server's certificate chain.

        If the server requests client authentication, the
        client will send the passed-in certificate chain, and use the
        passed-in private key to authenticate itself.  If no
        certificate chain and private key were passed in, the client
        will attempt to proceed without client authentication.  The
        server may or may not allow this.

        If the function completes without raising an exception, the
        TLS connection will be open and available for data transfer.

        If an exception is raised, the connection will have been
        automatically closed (if it was ever open).

        :type certChain: ~tlslite.x509certchain.X509CertChain
        :param certChain: The certificate chain to be used if the
            server requests client authentication.

        :type privateKey: ~tlslite.utils.rsakey.RSAKey
        :param privateKey: The private key to be used if the server
            requests client authentication.

        :type session: ~tlslite.session.Session
        :param session: A TLS session to attempt to resume.  If the
            resumption does not succeed, a full handshake will be
            performed.

        :type settings: ~tlslite.handshakesettings.HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites, certificate types, and SSL/TLS versions
            offered by the client.

        :type checker: ~tlslite.checker.Checker
        :param checker: A Checker instance.  This instance will be
            invoked to examine the other party's authentication
            credentials, if the handshake completes succesfully.

        :type nextProtos: list of str
        :param nextProtos: A list of upper layer protocols ordered by
            preference, to use in the Next-Protocol Negotiation Extension.

        :type reqTack: bool
        :param reqTack: Whether or not to send a "tack" TLS Extension,
            requesting the server return a TackExtension if it has one.

        :type serverName: string
        :param serverName: The ServerNameIndication TLS Extension.

        :type async_: bool
        :param async_: If False, this function will block until the
            handshake is completed.  If True, this function will return a
            generator.  Successive invocations of the generator will
            return 0 if it is waiting to read from the socket, 1 if it is
            waiting to write to the socket, or will raise StopIteration if
            the handshake operation is completed.

        :type alpn: list of bytearrays
        :param alpn: protocol names to advertise to server as supported by
            client in the Application Layer Protocol Negotiation extension.
            Example items in the array include b'http/1.1' or b'h2'.

        :rtype: None or an iterable
        :returns: If 'async_' is True, a generator object will be
            returned.

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        :raises tlslite.errors.TLSAuthenticationError: If the checker
            doesn't like the other party's authentication credentials.
        """
        handshaker = \
                self._handshakeClientAsync(certParams=(certChain, privateKey),
                                           session=session, settings=settings,
                                           checker=checker,
                                           serverName=serverName,
                                           nextProtos=nextProtos,
                                           reqTack=reqTack,
                                           alpn=alpn)
        # The handshaker is a Python Generator which executes the handshake.
        # It allows the handshake to be run in a "piecewise", asynchronous
        # fashion, returning 1 when it is waiting to able to write, 0 when
        # it is waiting to read.
        #
        # If 'async_' is True, the generator is returned to the caller,
        # otherwise it is executed to completion here.
        if async_:
            return handshaker
        for result in handshaker:
            pass


    def _handshakeClientAsync(self, srpParams=(), certParams=(), anonParams=(),
                              session=None, settings=None, checker=None,
                              nextProtos=None, serverName=None, reqTack=True,
                              alpn=None):

        handshaker = self._handshakeClientAsyncHelper(srpParams=srpParams,
                certParams=certParams,
                anonParams=anonParams,
                session=session,
                settings=settings,
                serverName=serverName,
                nextProtos=nextProtos,
                reqTack=reqTack,
                alpn=alpn)
        for result in self._handshakeWrapperAsync(handshaker, checker):
            yield result


    def _handshakeClientAsyncHelper(self, srpParams, certParams, anonParams,
                               session, settings, serverName, nextProtos,
                               reqTack, alpn):

        self._handshakeStart(client=True)

        #Unpack parameters
        srpUsername = None      # srpParams[0]
        password = None         # srpParams[1]
        clientCertChain = None  # certParams[0]
        privateKey = None       # certParams[1]

        # Allow only one of (srpParams, certParams, anonParams)
        if srpParams:
            assert(not certParams)
            assert(not anonParams)
            srpUsername, password = srpParams
        if certParams:
            assert(not srpParams)
            assert(not anonParams)            
            clientCertChain, privateKey = certParams
        if anonParams:
            assert(not srpParams)         
            assert(not certParams)

        #Validate parameters
        if srpUsername and not password:
            raise ValueError("Caller passed a username but no password")
        if password and not srpUsername:
            raise ValueError("Caller passed a password but no username")
        if clientCertChain and not privateKey:
            raise ValueError("Caller passed a certChain but no privateKey")
        if privateKey and not clientCertChain:
            raise ValueError("Caller passed a privateKey but no certChain")
        if reqTack:
            if not tackpyLoaded:
                reqTack = False
            if not settings or not settings.useExperimentalTackExtension:
                reqTack = False
        if nextProtos is not None:
            if len(nextProtos) == 0:
                raise ValueError("Caller passed no nextProtos")
        if alpn is not None and not alpn:
            raise ValueError("Caller passed empty alpn list")
        # reject invalid hostnames but accept empty/None ones
        if serverName and not is_valid_hostname(serverName):
            raise ValueError("Caller provided invalid server host name: {0}"
                             .format(serverName))

        # Validates the settings and filters out any unsupported ciphers
        # or crypto libraries that were requested        
        if not settings:
            settings = HandshakeSettings()
        settings = settings.validate()

        if clientCertChain:
            if not isinstance(clientCertChain, X509CertChain):
                raise ValueError("Unrecognized certificate type")
            if "x509" not in settings.certificateTypes:
                raise ValueError("Client certificate doesn't match "\
                                 "Handshake Settings")
                                  
        if session:
            # session.valid() ensures session is resumable and has 
            # non-empty sessionID
            if not session.valid():
                session = None #ignore non-resumable sessions...
            elif session.resumable: 
                if session.srpUsername != srpUsername:
                    raise ValueError("Session username doesn't match")
                if session.serverName != serverName:
                    raise ValueError("Session servername doesn't match")

        #Add Faults to parameters
        if srpUsername and self.fault == Fault.badUsername:
            srpUsername += bytearray(b"GARBAGE")
        if password and self.fault == Fault.badPassword:
            password += bytearray(b"GARBAGE")

        #Tentatively set the version to the client's minimum version.
        #We'll use this for the ClientHello, and if an error occurs
        #parsing the Server Hello, we'll use this version for the response
        self.version = settings.maxVersion
        
        # OK Start sending messages!
        # *****************************

        # Send the ClientHello.
        for result in self._clientSendClientHello(settings, session, 
                                        srpUsername, srpParams, certParams,
                                        anonParams, serverName, nextProtos,
                                        reqTack, alpn):
            if result in (0,1): yield result
            else: break
        clientHello = result
        
        #Get the ServerHello.
        for result in self._clientGetServerHello(settings, clientHello):
            if result in (0,1): yield result
            else: break
        serverHello = result
        cipherSuite = serverHello.cipher_suite
        
        # Choose a matching Next Protocol from server list against ours
        # (string or None)
        nextProto = self._clientSelectNextProto(nextProtos, serverHello)

        # Check if server selected encrypt-then-MAC
        if serverHello.getExtension(ExtensionType.encrypt_then_mac):
            self._recordLayer.encryptThenMAC = True

        if serverHello.getExtension(ExtensionType.extended_master_secret):
            self.extendedMasterSecret = True

        #If the server elected to resume the session, it is handled here.
        for result in self._clientResume(session, serverHello, 
                        clientHello.random, 
                        settings.cipherImplementations,
                        nextProto):
            if result in (0,1): yield result
            else: break
        if result == "resumed_and_finished":
            self._handshakeDone(resumed=True)
            self._serverRandom = serverHello.random
            self._clientRandom = clientHello.random
            # alpn protocol is independent of resumption and renegotiation
            # and needs to be negotiated every time
            alpnExt = serverHello.getExtension(ExtensionType.alpn)
            if alpnExt:
                session.appProto = alpnExt.protocol_names[0]
            return

        #If the server selected an SRP ciphersuite, the client finishes
        #reading the post-ServerHello messages, then derives a
        #premasterSecret and sends a corresponding ClientKeyExchange.
        if cipherSuite in CipherSuite.srpAllSuites:
            keyExchange = SRPKeyExchange(cipherSuite, clientHello,
                                         serverHello, None, None,
                                         srpUsername=srpUsername,
                                         password=password,
                                         settings=settings)

        #If the server selected an anonymous ciphersuite, the client
        #finishes reading the post-ServerHello messages.
        elif cipherSuite in CipherSuite.dhAllSuites:
            keyExchange = DHE_RSAKeyExchange(cipherSuite, clientHello,
                                             serverHello, None)

        elif cipherSuite in CipherSuite.ecdhAllSuites:
            acceptedCurves = self._curveNamesToList(settings)
            keyExchange = ECDHE_RSAKeyExchange(cipherSuite, clientHello,
                                               serverHello, None,
                                               acceptedCurves)

        #If the server selected a certificate-based RSA ciphersuite,
        #the client finishes reading the post-ServerHello messages. If 
        #a CertificateRequest message was sent, the client responds with
        #a Certificate message containing its certificate chain (if any),
        #and also produces a CertificateVerify message that signs the 
        #ClientKeyExchange.
        else:
            keyExchange = RSAKeyExchange(cipherSuite, clientHello,
                                         serverHello, None)

        # we'll send few messages here, send them in single TCP packet
        self.sock.buffer_writes = True
        for result in self._clientKeyExchange(settings, cipherSuite,
                                              clientCertChain,
                                              privateKey,
                                              serverHello.certificate_type,
                                              serverHello.tackExt,
                                              clientHello.random,
                                              serverHello.random,
                                              keyExchange):
            if result in (0, 1):
                yield result
            else: break
        (premasterSecret, serverCertChain, clientCertChain,
         tackExt) = result

        #After having previously sent a ClientKeyExchange, the client now
        #initiates an exchange of Finished messages.
        # socket buffering is turned off in _clientFinished
        for result in self._clientFinished(premasterSecret,
                            clientHello.random, 
                            serverHello.random,
                            cipherSuite, settings.cipherImplementations,
                            nextProto):
                if result in (0,1): yield result
                else: break
        masterSecret = result

        # check if an application layer protocol was negotiated
        alpnProto = None
        alpnExt = serverHello.getExtension(ExtensionType.alpn)
        if alpnExt:
            alpnProto = alpnExt.protocol_names[0]

        # Create the session object which is used for resumptions
        self.session = Session()
        self.session.create(masterSecret, serverHello.session_id, cipherSuite,
                            srpUsername, clientCertChain, serverCertChain,
                            tackExt, (serverHello.tackExt is not None),
                            serverName,
                            encryptThenMAC=self._recordLayer.encryptThenMAC,
                            extendedMasterSecret=self.extendedMasterSecret,
                            appProto=alpnProto)
        self._handshakeDone(resumed=False)
        self._serverRandom = serverHello.random
        self._clientRandom = clientHello.random


    def _clientSendClientHello(self, settings, session, srpUsername,
                                srpParams, certParams, anonParams,
                                serverName, nextProtos, reqTack, alpn):
        #Initialize acceptable ciphersuites
        cipherSuites = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        if srpParams:
            cipherSuites += CipherSuite.getSrpAllSuites(settings)
        elif certParams:
            cipherSuites += CipherSuite.getEcdheCertSuites(settings)
            cipherSuites += CipherSuite.getDheCertSuites(settings)
            cipherSuites += CipherSuite.getCertSuites(settings)
        elif anonParams:
            cipherSuites += CipherSuite.getEcdhAnonSuites(settings)
            cipherSuites += CipherSuite.getAnonSuites(settings)
        else:
            assert False

        #Add any SCSVs. These are not real cipher suites, but signaling
        #values which reuse the cipher suite field in the ClientHello.
        wireCipherSuites = list(cipherSuites)
        if settings.sendFallbackSCSV:
            wireCipherSuites.append(CipherSuite.TLS_FALLBACK_SCSV)

        #Initialize acceptable certificate types
        certificateTypes = settings.getCertificateTypes()

        extensions = []

        #Initialize TLS extensions
        if settings.useEncryptThenMAC:
            extensions.append(TLSExtension().\
                              create(ExtensionType.encrypt_then_mac,
                                     bytearray(0)))
        if settings.useExtendedMasterSecret:
            extensions.append(TLSExtension().create(ExtensionType.
                                                    extended_master_secret,
                                                    bytearray(0)))
        groups = []
        #Send the ECC extensions only if we advertise ECC ciphers
        if next((cipher for cipher in cipherSuites \
                if cipher in CipherSuite.ecdhAllSuites), None) is not None:
            groups.extend(self._curveNamesToList(settings))
            extensions.append(ECPointFormatsExtension().\
                              create([ECPointFormat.uncompressed]))
        # Advertise FFDHE groups if we have DHE ciphers
        if next((cipher for cipher in cipherSuites
                 if cipher in CipherSuite.dhAllSuites), None) is not None:
            groups.extend(self._groupNamesToList(settings))
        # Send the extension only if it will be non empty
        if groups:
            extensions.append(SupportedGroupsExtension().create(groups))
        # In TLS1.2 advertise support for additional signature types
        if settings.maxVersion >= (3, 3):
            sigList = self._sigHashesToList(settings)
            assert len(sigList) > 0
            extensions.append(SignatureAlgorithmsExtension().\
                              create(sigList))
        # if we know any protocols for ALPN, advertise them
        if alpn:
            extensions.append(ALPNExtension().create(alpn))
        # don't send empty list of extensions or extensions in SSLv3
        if not extensions or settings.maxVersion == (3, 0):
            extensions = None

        #Either send ClientHello (with a resumable session)...
        if session and session.sessionID:
            #If it's resumable, then its
            #ciphersuite must be one of the acceptable ciphersuites
            if session.cipherSuite not in cipherSuites:
                raise ValueError("Session's cipher suite not consistent "\
                                 "with parameters")
            else:
                clientHello = ClientHello()
                clientHello.create(settings.maxVersion, getRandomBytes(32),
                                   session.sessionID, wireCipherSuites,
                                   certificateTypes, 
                                   session.srpUsername,
                                   reqTack, nextProtos is not None,
                                   session.serverName,
                                   extensions=extensions)

        #Or send ClientHello (without)
        else:
            clientHello = ClientHello()
            clientHello.create(settings.maxVersion, getRandomBytes(32),
                               bytearray(0), wireCipherSuites,
                               certificateTypes, 
                               srpUsername,
                               reqTack, nextProtos is not None, 
                               serverName,
                               extensions=extensions)

        # Check if padding extension should be added
        # we want to add extensions even when using just SSLv3
        if settings.usePaddingExtension:
            HandshakeHelpers.alignClientHelloPadding(clientHello)

        for result in self._sendMsg(clientHello):
            yield result
        yield clientHello


    def _clientGetServerHello(self, settings, clientHello):
        for result in self._getMsg(ContentType.handshake,
                                  HandshakeType.server_hello):
            if result in (0,1): yield result
            else: break
        serverHello = result

        #Get the server version.  Do this before anything else, so any
        #error alerts will use the server's version
        self.version = serverHello.server_version

        #Check ServerHello
        if serverHello.server_version < settings.minVersion:
            for result in self._sendError(\
                AlertDescription.protocol_version,
                "Too old version: %s" % str(serverHello.server_version)):
                yield result
        if serverHello.server_version > settings.maxVersion:
            for result in self._sendError(\
                AlertDescription.protocol_version,
                "Too new version: %s" % str(serverHello.server_version)):
                yield result
        serverVer = serverHello.server_version
        cipherSuites = CipherSuite.filterForVersion(clientHello.cipher_suites,
                                                    minVersion=serverVer,
                                                    maxVersion=serverVer)
        if serverHello.cipher_suite not in cipherSuites:
            for result in self._sendError(\
                AlertDescription.illegal_parameter,
                "Server responded with incorrect ciphersuite"):
                yield result
        if serverHello.certificate_type not in clientHello.certificate_types:
            for result in self._sendError(\
                AlertDescription.illegal_parameter,
                "Server responded with incorrect certificate type"):
                yield result
        if serverHello.compression_method != 0:
            for result in self._sendError(\
                AlertDescription.illegal_parameter,
                "Server responded with incorrect compression method"):
                yield result
        if serverHello.tackExt:            
            if not clientHello.tack:
                for result in self._sendError(\
                    AlertDescription.illegal_parameter,
                    "Server responded with unrequested Tack Extension"):
                    yield result
            if not serverHello.tackExt.verifySignatures():
                for result in self._sendError(\
                    AlertDescription.decrypt_error,
                    "TackExtension contains an invalid signature"):
                    yield result
        if serverHello.next_protos and not clientHello.supports_npn:
            for result in self._sendError(\
                AlertDescription.illegal_parameter,
                "Server responded with unrequested NPN Extension"):
                yield result
        if not serverHello.getExtension(ExtensionType.extended_master_secret)\
            and settings.requireExtendedMasterSecret:
            for result in self._sendError(
                    AlertDescription.insufficient_security,
                    "Negotiation of Extended master Secret failed"):
                yield result
        alpnExt = serverHello.getExtension(ExtensionType.alpn)
        if alpnExt:
            if not alpnExt.protocol_names or \
                    len(alpnExt.protocol_names) != 1:
                for result in self._sendError(
                        AlertDescription.illegal_parameter,
                        "Server responded with invalid ALPN extension"):
                    yield result
            clntAlpnExt = clientHello.getExtension(ExtensionType.alpn)
            if not clntAlpnExt:
                for result in self._sendError(
                        AlertDescription.unsupported_extension,
                        "Server sent ALPN extension without one in "
                        "client hello"):
                    yield result
            if alpnExt.protocol_names[0] not in clntAlpnExt.protocol_names:
                for result in self._sendError(
                        AlertDescription.illegal_parameter,
                        "Server selected ALPN protocol we did not advertise"):
                    yield result
        yield serverHello

    def _clientSelectNextProto(self, nextProtos, serverHello):
        # nextProtos is None or non-empty list of strings
        # serverHello.next_protos is None or possibly-empty list of strings
        #
        # !!! We assume the client may have specified nextProtos as a list of
        # strings so we convert them to bytearrays (it's awkward to require
        # the user to specify a list of bytearrays or "bytes", and in 
        # Python 2.6 bytes() is just an alias for str() anyways...
        if nextProtos is not None and serverHello.next_protos is not None:
            for p in nextProtos:
                if bytearray(p) in serverHello.next_protos:
                    return bytearray(p)
            else:
                # If the client doesn't support any of server's protocols,
                # or the server doesn't advertise any (next_protos == [])
                # the client SHOULD select the first protocol it supports.
                return bytearray(nextProtos[0])
        return None
 
    def _clientResume(self, session, serverHello, clientRandom, 
                      cipherImplementations, nextProto):
        #If the server agrees to resume
        if session and session.sessionID and \
            serverHello.session_id == session.sessionID:

            if serverHello.cipher_suite != session.cipherSuite:
                for result in self._sendError(\
                    AlertDescription.illegal_parameter,\
                    "Server's ciphersuite doesn't match session"):
                    yield result

            #Calculate pending connection states
            self._calcPendingStates(session.cipherSuite, 
                                    session.masterSecret, 
                                    clientRandom, serverHello.random, 
                                    cipherImplementations)                                   

            #Exchange ChangeCipherSpec and Finished messages
            for result in self._getFinished(session.masterSecret,
                                            session.cipherSuite):
                yield result
            # buffer writes so that CCS and Finished go out in one TCP packet
            self.sock.buffer_writes = True
            for result in self._sendFinished(session.masterSecret,
                                             session.cipherSuite,
                                             nextProto):
                yield result
            self.sock.flush()
            self.sock.buffer_writes = False

            #Set the session for this connection
            self.session = session
            yield "resumed_and_finished"

    def _clientKeyExchange(self, settings, cipherSuite,
                           clientCertChain, privateKey,
                           certificateType,
                           tackExt, clientRandom, serverRandom,
                           keyExchange):
        """Perform the client side of key exchange"""
        # if server chose cipher suite with authentication, get the certificate
        if cipherSuite in CipherSuite.certAllSuites:
            for result in self._getMsg(ContentType.handshake,
                                       HandshakeType.certificate,
                                       certificateType):
                if result in (0, 1):
                    yield result
                else: break
            serverCertificate = result
        else:
            serverCertificate = None
        # if server chose RSA key exchange, we need to skip SKE message
        if cipherSuite not in CipherSuite.certSuites:
            for result in self._getMsg(ContentType.handshake,
                                       HandshakeType.server_key_exchange,
                                       cipherSuite):
                if result in (0, 1):
                    yield result
                else: break
            serverKeyExchange = result
        else:
            serverKeyExchange = None

        for result in self._getMsg(ContentType.handshake,
                                   (HandshakeType.certificate_request,
                                    HandshakeType.server_hello_done)):
            if result in (0, 1):
                yield result
            else: break

        certificateRequest = None
        if isinstance(result, CertificateRequest):
            certificateRequest = result

            #abort if Certificate Request with inappropriate ciphersuite
            if cipherSuite not in CipherSuite.certAllSuites \
                or cipherSuite in CipherSuite.srpAllSuites:
                for result in self._sendError(\
                        AlertDescription.unexpected_message,
                        "Certificate Request with incompatible cipher suite"):
                    yield result

            # we got CertificateRequest so now we'll get ServerHelloDone
            for result in self._getMsg(ContentType.handshake,
                                       HandshakeType.server_hello_done):
                if result in (0, 1):
                    yield result
                else: break
        serverHelloDone = result

        serverCertChain = None
        publicKey = None
        if cipherSuite in CipherSuite.certAllSuites:
            # get the certificate
            for result in self._clientGetKeyFromChain(serverCertificate,
                                                      settings,
                                                      tackExt):
                if result in (0, 1):
                    yield result
                else: break
            publicKey, serverCertChain, tackExt = result

            #Check the server's signature, if the server chose an authenticated
            # PFS-enabled ciphersuite
            if serverKeyExchange:
                validSigAlgs = self._sigHashesToList(settings,
                                                     certList=serverCertChain)
                try:
                    KeyExchange.verifyServerKeyExchange(serverKeyExchange,
                                                        publicKey,
                                                        clientRandom,
                                                        serverRandom,
                                                        validSigAlgs)
                except TLSIllegalParameterException:
                    for result in self._sendError(AlertDescription.\
                                                  illegal_parameter):
                        yield result
                except TLSDecryptionFailed:
                    for result in self._sendError(\
                            AlertDescription.decrypt_error):
                        yield result

        if serverKeyExchange:
            # store key exchange metadata for user applications
            if self.version >= (3, 3) \
                    and cipherSuite in CipherSuite.certAllSuites \
                    and cipherSuite not in CipherSuite.certSuites:
                self.serverSigAlg = (serverKeyExchange.hashAlg,
                                     serverKeyExchange.signAlg)

            if cipherSuite in CipherSuite.dhAllSuites:
                self.dhGroupSize = numBits(serverKeyExchange.dh_p)
            if cipherSuite in CipherSuite.ecdhAllSuites:
                self.ecdhCurve = serverKeyExchange.named_curve

        #Send Certificate if we were asked for it
        if certificateRequest:

            # if a peer doesn't advertise support for any algorithm in TLSv1.2,
            # support for SHA1+RSA can be assumed
            if self.version == (3, 3)\
                and not [sig for sig in \
                         certificateRequest.supported_signature_algs\
                         if sig[1] == SignatureAlgorithm.rsa]:
                for result in self._sendError(\
                        AlertDescription.handshake_failure,
                        "Server doesn't accept any sigalgs we support: " +
                        str(certificateRequest.supported_signature_algs)):
                    yield result
            clientCertificate = Certificate(certificateType)

            if clientCertChain:
                #Check to make sure we have the same type of
                #certificates the server requested
                if certificateType == CertificateType.x509 \
                    and not isinstance(clientCertChain, X509CertChain):
                    for result in self._sendError(\
                            AlertDescription.handshake_failure,
                            "Client certificate is of wrong type"):
                        yield result

                clientCertificate.create(clientCertChain)
            # we need to send the message even if we don't have a certificate
            for result in self._sendMsg(clientCertificate):
                yield result
        else:
            #Server didn't ask for cer, zeroise so session doesn't store them
            privateKey = None
            clientCertChain = None

        try:
            ske = serverKeyExchange
            premasterSecret = keyExchange.processServerKeyExchange(publicKey,
                                                                   ske)
        except TLSInsufficientSecurity as e:
            for result in self._sendError(\
                    AlertDescription.insufficient_security, e):
                yield result
        except TLSIllegalParameterException as e:
            for result in self._sendError(\
                    AlertDescription.illegal_parameter, e):
                yield result

        clientKeyExchange = keyExchange.makeClientKeyExchange()

        #Send ClientKeyExchange
        for result in self._sendMsg(clientKeyExchange):
            yield result

        # the Extended Master Secret calculation uses the same handshake
        # hashes as the Certificate Verify calculation so we need to
        # make a copy of it
        self._certificate_verify_handshake_hash = self._handshake_hash.copy()

        #if client auth was requested and we have a private key, send a
        #CertificateVerify
        if certificateRequest and privateKey:
            validSigAlgs = self._sigHashesToList(settings, privateKey,
                                                 clientCertChain)
            try:
                certificateVerify = KeyExchange.makeCertificateVerify(
                    self.version,
                    self._certificate_verify_handshake_hash,
                    validSigAlgs,
                    privateKey,
                    certificateRequest,
                    premasterSecret,
                    clientRandom,
                    serverRandom)
            except TLSInternalError as exception:
                for result in self._sendError(
                        AlertDescription.internal_error, exception):
                    yield result
            for result in self._sendMsg(certificateVerify):
                yield result

        yield (premasterSecret, serverCertChain, clientCertChain, tackExt)

    def _clientFinished(self, premasterSecret, clientRandom, serverRandom,
                        cipherSuite, cipherImplementations, nextProto):
        if self.extendedMasterSecret:
            cvhh = self._certificate_verify_handshake_hash
            # in case of session resumption, or when the handshake doesn't
            # use the certificate authentication, the hashes are the same
            if not cvhh:
                cvhh = self._handshake_hash
            masterSecret = calcExtendedMasterSecret(self.version,
                                                    cipherSuite,
                                                    premasterSecret,
                                                    cvhh)
        else:
            masterSecret = calcMasterSecret(self.version,
                                            cipherSuite,
                                            premasterSecret,
                                            clientRandom,
                                            serverRandom)
        self._calcPendingStates(cipherSuite, masterSecret, 
                                clientRandom, serverRandom, 
                                cipherImplementations)

        #Exchange ChangeCipherSpec and Finished messages
        for result in self._sendFinished(masterSecret, cipherSuite, nextProto):
            yield result
        self.sock.flush()
        self.sock.buffer_writes = False
        for result in self._getFinished(masterSecret,
                                        cipherSuite,
                                        nextProto=nextProto):
            yield result
        yield masterSecret

    def _clientGetKeyFromChain(self, certificate, settings, tackExt=None):
        #Get and check cert chain from the Certificate message
        certChain = certificate.certChain
        if not certChain or certChain.getNumCerts() == 0:
            for result in self._sendError(AlertDescription.illegal_parameter,
                    "Other party sent a Certificate message without "\
                    "certificates"):
                yield result

        #Get and check public key from the cert chain
        publicKey = certChain.getEndEntityPublicKey()
        if len(publicKey) < settings.minKeySize:
            for result in self._sendError(AlertDescription.handshake_failure,
                    "Other party's public key too small: %d" % len(publicKey)):
                yield result
        if len(publicKey) > settings.maxKeySize:
            for result in self._sendError(AlertDescription.handshake_failure,
                    "Other party's public key too large: %d" % len(publicKey)):
                yield result
        
        # If there's no TLS Extension, look for a TACK cert
        if tackpyLoaded:
            if not tackExt:
                tackExt = certChain.getTackExt()
         
            # If there's a TACK (whether via TLS or TACK Cert), check that it
            # matches the cert chain   
            if tackExt and tackExt.tacks:
                for tack in tackExt.tacks: 
                    if not certChain.checkTack(tack):
                        for result in self._sendError(  
                                AlertDescription.illegal_parameter,
                                "Other party's TACK doesn't match their public key"):
                                yield result

        yield publicKey, certChain, tackExt


    #*********************************************************
    # Server Handshake Functions
    #*********************************************************


    def handshakeServer(self, verifierDB=None,
                        certChain=None, privateKey=None, reqCert=False,
                        sessionCache=None, settings=None, checker=None,
                        reqCAs = None, 
                        tacks=None, activationFlags=0,
                        nextProtos=None, anon=False, alpn=None, sni=None):
        """Perform a handshake in the role of server.

        This function performs an SSL or TLS handshake.  Depending on
        the arguments and the behavior of the client, this function can
        perform an SRP, or certificate-based handshake.  It
        can also perform a combined SRP and server-certificate
        handshake.

        Like any handshake function, this can be called on a closed
        TLS connection, or on a TLS connection that is already open.
        If called on an open connection it performs a re-handshake.
        This function does not send a Hello Request message before
        performing the handshake, so if re-handshaking is required,
        the server must signal the client to begin the re-handshake
        through some other means.

        If the function completes without raising an exception, the
        TLS connection will be open and available for data transfer.

        If an exception is raised, the connection will have been
        automatically closed (if it was ever open).

        :type verifierDB: ~tlslite.verifierdb.VerifierDB
        :param verifierDB: A database of SRP password verifiers
            associated with usernames.  If the client performs an SRP
            handshake, the session's srpUsername attribute will be set.

        :type certChain: ~tlslite.x509certchain.X509CertChain
        :param certChain: The certificate chain to be used if the
            client requests server certificate authentication.

        :type privateKey: ~tlslite.utils.rsakey.RSAKey
        :param privateKey: The private key to be used if the client
            requests server certificate authentication.

        :type reqCert: bool
        :param reqCert: Whether to request client certificate
            authentication.  This only applies if the client chooses server
            certificate authentication; if the client chooses SRP
            authentication, this will be ignored.  If the client
            performs a client certificate authentication, the sessions's
            clientCertChain attribute will be set.

        :type sessionCache: ~tlslite.sessioncache.SessionCache
        :param sessionCache: An in-memory cache of resumable sessions.
            The client can resume sessions from this cache.  Alternatively,
            if the client performs a full handshake, a new session will be
            added to the cache.

        :type settings: ~tlslite.handshakesettings.HandshakeSettings
        :param settings: Various settings which can be used to control
            the ciphersuites and SSL/TLS version chosen by the server.

        :type checker: ~tlslite.checker.Checker
        :param checker: A Checker instance.  This instance will be
            invoked to examine the other party's authentication
            credentials, if the handshake completes succesfully.

        :type reqCAs: list of bytearray
        :param reqCAs: A collection of DER-encoded DistinguishedNames that
            will be sent along with a certificate request. This does not affect
            verification.

        :type nextProtos: list of str
        :param nextProtos: A list of upper layer protocols to expose to the
            clients through the Next-Protocol Negotiation Extension,
            if they support it.

        :type alpn: list of bytearray
        :param alpn: names of application layer protocols supported.
            Note that it will be used instead of NPN if both were advertised by
            client.

        :type sni: bytearray
        :param sni: expected virtual name hostname.

        :raises socket.error: If a socket error occurs.
        :raises tlslite.errors.TLSAbruptCloseError: If the socket is closed
            without a preceding alert.
        :raises tlslite.errors.TLSAlert: If a TLS alert is signalled.
        :raises tlslite.errors.TLSAuthenticationError: If the checker
            doesn't like the other party's authentication credentials.
        """
        for result in self.handshakeServerAsync(verifierDB,
                certChain, privateKey, reqCert, sessionCache, settings,
                checker, reqCAs,
                tacks=tacks, activationFlags=activationFlags,
                nextProtos=nextProtos, anon=anon, alpn=alpn, sni=sni):
            pass


    def handshakeServerAsync(self, verifierDB=None,
                             certChain=None, privateKey=None, reqCert=False,
                             sessionCache=None, settings=None, checker=None,
                             reqCAs=None, 
                             tacks=None, activationFlags=0,
                             nextProtos=None, anon=False, alpn=None, sni=None
                             ):
        """Start a server handshake operation on the TLS connection.

        This function returns a generator which behaves similarly to
        handshakeServer().  Successive invocations of the generator
        will return 0 if it is waiting to read from the socket, 1 if it is
        waiting to write to the socket, or it will raise StopIteration
        if the handshake operation is complete.

        :rtype: iterable
        :returns: A generator; see above for details.
        """
        handshaker = self._handshakeServerAsyncHelper(\
            verifierDB=verifierDB, certChain=certChain,
            privateKey=privateKey, reqCert=reqCert,
            sessionCache=sessionCache, settings=settings, 
            reqCAs=reqCAs, 
            tacks=tacks, activationFlags=activationFlags, 
            nextProtos=nextProtos, anon=anon, alpn=alpn, sni=sni)
        for result in self._handshakeWrapperAsync(handshaker, checker):
            yield result


    def _handshakeServerAsyncHelper(self, verifierDB,
                             certChain, privateKey, reqCert, sessionCache,
                             settings, reqCAs, 
                             tacks, activationFlags, 
                             nextProtos, anon, alpn, sni):

        self._handshakeStart(client=False)

        if (not verifierDB) and (not certChain) and not anon:
            raise ValueError("Caller passed no authentication credentials")
        if certChain and not privateKey:
            raise ValueError("Caller passed a certChain but no privateKey")
        if privateKey and not certChain:
            raise ValueError("Caller passed a privateKey but no certChain")
        if reqCAs and not reqCert:
            raise ValueError("Caller passed reqCAs but not reqCert")            
        if certChain and not isinstance(certChain, X509CertChain):
            raise ValueError("Unrecognized certificate type")
        if activationFlags and not tacks:
            raise ValueError("Nonzero activationFlags requires tacks")
        if tacks:
            if not tackpyLoaded:
                raise ValueError("tackpy is not loaded")
            if not settings or not settings.useExperimentalTackExtension:
                raise ValueError("useExperimentalTackExtension not enabled")
        if alpn is not None and not alpn:
            raise ValueError("Empty list of ALPN protocols")

        if not settings:
            settings = HandshakeSettings()
        settings = settings.validate()
        
        # OK Start exchanging messages
        # ******************************
        
        # Handle ClientHello and resumption
        for result in self._serverGetClientHello(settings, certChain,
                                                 verifierDB, sessionCache,
                                                 anon, alpn, sni):
            if result in (0,1): yield result
            elif result == None:
                self._handshakeDone(resumed=True)                
                return # Handshake was resumed, we're done 
            else: break
        (clientHello, cipherSuite) = result

        #If not a resumption...

        # Create the ServerHello message
        if sessionCache:
            sessionID = getRandomBytes(32)
        else:
            sessionID = bytearray(0)
        
        if not clientHello.supports_npn:
            nextProtos = None

        alpnExt = clientHello.getExtension(ExtensionType.alpn)
        if alpnExt and alpn:
            # if there's ALPN, don't do NPN
            nextProtos = None

        # If not doing a certificate-based suite, discard the TACK
        if not cipherSuite in CipherSuite.certAllSuites:
            tacks = None

        # Prepare a TACK Extension if requested
        if clientHello.tack:
            tackExt = TackExtension.create(tacks, activationFlags)
        else:
            tackExt = None

        extensions = []
        # Prepare other extensions if requested
        if settings.useEncryptThenMAC and \
                clientHello.getExtension(ExtensionType.encrypt_then_mac) and \
                cipherSuite not in CipherSuite.streamSuites and \
                cipherSuite not in CipherSuite.aeadSuites:
            extensions.append(TLSExtension().create(ExtensionType.
                                                    encrypt_then_mac,
                                                    bytearray(0)))
            self._recordLayer.encryptThenMAC = True

        if settings.useExtendedMasterSecret:
            if clientHello.getExtension(ExtensionType.extended_master_secret):
                extensions.append(TLSExtension().create(ExtensionType.
                                                        extended_master_secret,
                                                        bytearray(0)))
                self.extendedMasterSecret = True
            elif settings.requireExtendedMasterSecret:
                for result in self._sendError(
                        AlertDescription.insufficient_security,
                        "Failed to negotiate Extended Master Secret"):
                    yield result

        selectedALPN = None
        if alpnExt and alpn:
            for protoName in alpnExt.protocol_names:
                if protoName in alpn:
                    selectedALPN = protoName
                    ext = ALPNExtension().create([protoName])
                    extensions.append(ext)
                    break
            else:
                for result in self._sendError(
                        AlertDescription.no_application_protocol,
                        "No mutually supported application layer protocols"):
                    yield result
        # notify client that we understood its renegotiation info extension
        # or SCSV
        secureRenego = False
        renegoExt = clientHello.getExtension(ExtensionType.renegotiation_info)
        if renegoExt:
            if renegoExt.renegotiated_connection:
                for result in self._sendError(
                        AlertDescription.handshake_failure,
                        "Non empty renegotiation info extension in "
                        "initial Client Hello"):
                    yield result
            secureRenego = True
        elif CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV in \
                clientHello.cipher_suites:
            secureRenego = True
        if secureRenego:
            extensions.append(RenegotiationInfoExtension()
                              .create(bytearray(0)))

        # tell the client what point formats we support
        if clientHello.getExtension(ExtensionType.ec_point_formats):
            # even though the selected cipher may not use ECC, client may want
            # to send a CA certificate with ECDSA...
            extensions.append(ECPointFormatsExtension().create(
                [ECPointFormat.uncompressed]))

        # don't send empty list of extensions
        if not extensions:
            extensions = None

        serverHello = ServerHello()
        serverHello.create(self.version, getRandomBytes(32), sessionID, \
                           cipherSuite, CertificateType.x509, tackExt,
                           nextProtos, extensions=extensions)

        # Perform the SRP key exchange
        clientCertChain = None
        if cipherSuite in CipherSuite.srpAllSuites:
            for result in self._serverSRPKeyExchange(clientHello, serverHello,
                                                     verifierDB, cipherSuite,
                                                     privateKey, certChain,
                                                     settings):
                if result in (0, 1):
                    yield result
                else: break
            premasterSecret = result

        # Perform a certificate-based key exchange
        elif (cipherSuite in CipherSuite.certSuites or
              cipherSuite in CipherSuite.dheCertSuites or
              cipherSuite in CipherSuite.ecdheCertSuites):
            if cipherSuite in CipherSuite.certSuites:
                keyExchange = RSAKeyExchange(cipherSuite,
                                             clientHello,
                                             serverHello,
                                             privateKey)
            elif cipherSuite in CipherSuite.dheCertSuites:
                dhGroups = self._groupNamesToList(settings)
                keyExchange = DHE_RSAKeyExchange(cipherSuite,
                                                 clientHello,
                                                 serverHello,
                                                 privateKey,
                                                 settings.dhParams,
                                                 dhGroups)
            elif cipherSuite in CipherSuite.ecdheCertSuites:
                acceptedCurves = self._curveNamesToList(settings)
                defaultCurve = getattr(GroupName, settings.defaultCurve)
                keyExchange = ECDHE_RSAKeyExchange(cipherSuite,
                                                   clientHello,
                                                   serverHello,
                                                   privateKey,
                                                   acceptedCurves,
                                                   defaultCurve)
            else:
                assert(False)
            for result in self._serverCertKeyExchange(clientHello, serverHello, 
                                        certChain, keyExchange,
                                        reqCert, reqCAs, cipherSuite,
                                        settings):
                if result in (0,1): yield result
                else: break
            (premasterSecret, clientCertChain) = result

        # Perform anonymous Diffie Hellman key exchange
        elif (cipherSuite in CipherSuite.anonSuites or
              cipherSuite in CipherSuite.ecdhAnonSuites):
            if cipherSuite in CipherSuite.anonSuites:
                dhGroups = self._groupNamesToList(settings)
                keyExchange = ADHKeyExchange(cipherSuite, clientHello,
                                             serverHello, settings.dhParams,
                                             dhGroups)
            else:
                acceptedCurves = self._curveNamesToList(settings)
                defaultCurve = getattr(GroupName, settings.defaultCurve)
                keyExchange = AECDHKeyExchange(cipherSuite, clientHello,
                                               serverHello, acceptedCurves,
                                               defaultCurve)
            for result in self._serverAnonKeyExchange(serverHello, keyExchange,
                                                      cipherSuite):
                if result in (0,1): yield result
                else: break
            premasterSecret = result

        else:
            assert(False)
                        
        # Exchange Finished messages      
        for result in self._serverFinished(premasterSecret, 
                                clientHello.random, serverHello.random,
                                cipherSuite, settings.cipherImplementations,
                                nextProtos):
                if result in (0,1): yield result
                else: break
        masterSecret = result

        #Create the session object
        self.session = Session()
        if cipherSuite in CipherSuite.certAllSuites:        
            serverCertChain = certChain
        else:
            serverCertChain = None
        srpUsername = None
        serverName = None
        if clientHello.srp_username:
            srpUsername = clientHello.srp_username.decode("utf-8")
        if clientHello.server_name:
            serverName = clientHello.server_name.decode("utf-8")
        self.session.create(masterSecret, serverHello.session_id, cipherSuite,
                            srpUsername, clientCertChain, serverCertChain,
                            tackExt, (serverHello.tackExt is not None),
                            serverName,
                            encryptThenMAC=self._recordLayer.encryptThenMAC,
                            extendedMasterSecret=self.extendedMasterSecret,
                            appProto=selectedALPN)
            
        #Add the session object to the session cache
        if sessionCache and sessionID:
            sessionCache[sessionID] = self.session

        self._handshakeDone(resumed=False)
        self._serverRandom = serverHello.random
        self._clientRandom = clientHello.random


    def _serverGetClientHello(self, settings, certChain, verifierDB,
                              sessionCache, anon, alpn, sni):
        #Tentatively set version to most-desirable version, so if an error
        #occurs parsing the ClientHello, this is what we'll use for the
        #error alert
        self.version = settings.maxVersion

        #Get ClientHello
        for result in self._getMsg(ContentType.handshake,
                                   HandshakeType.client_hello):
            if result in (0,1): yield result
            else: break
        clientHello = result

        #If client's version is too low, reject it
        if clientHello.client_version < settings.minVersion:
            self.version = settings.minVersion
            for result in self._sendError(\
                  AlertDescription.protocol_version,
                  "Too old version: %s" % str(clientHello.client_version)):
                yield result

        # there MUST be at least one value in both of those
        if not clientHello.cipher_suites or \
                not clientHello.compression_methods:
            for result in self._sendError(
                    AlertDescription.decode_error,
                    "Malformed Client Hello message"):
                yield result

        # client hello MUST advertise uncompressed method
        if 0 not in clientHello.compression_methods:
            for result in self._sendError(
                    AlertDescription.illegal_parameter,
                    "Client Hello missing uncompressed method"):
                yield result

        # the list of signatures methods is defined as <2..2^16-2>, which
        # means it can't be empty, but it's only applicable to TLSv1.2 protocol
        ext = clientHello.getExtension(ExtensionType.signature_algorithms)
        if clientHello.client_version >= (3, 3) and ext and not ext.sigalgs:
            for result in self._sendError(
                    AlertDescription.decode_error,
                    "Malformed signature_algorithms extension"):
                yield result

        # Sanity check the ALPN extension
        alpnExt = clientHello.getExtension(ExtensionType.alpn)
        if alpnExt:
            if not alpnExt.protocol_names:
                for result in self._sendError(
                        AlertDescription.decode_error,
                        "Client sent empty list of ALPN names"):
                    yield result
            for protocolName in alpnExt.protocol_names:
                if not protocolName:
                    for result in self._sendError(
                            AlertDescription.decode_error,
                            "Client sent empty name in ALPN extension"):
                        yield result

        # Sanity check the SNI extension
        sniExt = clientHello.getExtension(ExtensionType.server_name)
        # check if extension is well formed
        if sniExt and (not sniExt.extData or not sniExt.serverNames):
            for result in self._sendError(
                    AlertDescription.decode_error,
                    "Recevived SNI extension is malformed"):
                yield result
        if sniExt and sniExt.hostNames:
            # RFC 6066 limitation
            if len(sniExt.hostNames) > 1:
                for result in self._sendError(
                        AlertDescription.illegal_parameter,
                        "Client sent multiple host names in SNI extension"):
                    yield result
            if not sniExt.hostNames[0]:
                for result in self._sendError(
                        AlertDescription.decode_error,
                        "Received SNI extension is malformed"):
                    yield result
            try:
                name = sniExt.hostNames[0].decode('ascii', 'strict')
            except UnicodeDecodeError:
                for result in self._sendError(
                        AlertDescription.illegal_parameter,
                        "Host name in SNI is not valid ASCII"):
                    yield result
            if not is_valid_hostname(name):
                for result in self._sendError(
                        AlertDescription.illegal_parameter,
                        "Host name in SNI is not valid DNS name"):
                    yield result
            # warn the client if the name didn't match the expected value
            if sni and sni != name:
                alert = Alert().create(AlertDescription.unrecognized_name,
                                       AlertLevel.warning)
                for result in self._sendMsg(alert):
                    yield result

        # sanity check the EMS extension
        emsExt = clientHello.getExtension(ExtensionType.extended_master_secret)
        if emsExt and emsExt.extData:
            for result in self._sendError(
                    AlertDescription.decode_error,
                    "Non empty payload of the Extended "
                    "Master Secret extension"):
                yield result

        #If client's version is too high, propose my highest version
        elif clientHello.client_version > settings.maxVersion:
            self.version = settings.maxVersion

        else:
            #Set the version to the client's version
            self.version = clientHello.client_version  

        #Detect if the client performed an inappropriate fallback.
        if clientHello.client_version < settings.maxVersion and \
            CipherSuite.TLS_FALLBACK_SCSV in clientHello.cipher_suites:
            for result in self._sendError(\
                  AlertDescription.inappropriate_fallback):
                yield result

        #Check if there's intersection between supported curves by client and
        #server
        clientGroups = clientHello.getExtension(ExtensionType.supported_groups)
        # in case the client didn't advertise any curves, we can pick any so
        # enable ECDHE
        ecGroupIntersect = True
        # if there is no extension, then enable DHE
        ffGroupIntersect = True
        if clientGroups is not None:
            clientGroups = clientGroups.groups
            if not clientGroups:
                for result in self._sendError(
                        AlertDescription.decode_error,
                        "Received malformed supported_groups extension"):
                    yield result
            serverGroups = self._curveNamesToList(settings)
            ecGroupIntersect = getFirstMatching(clientGroups, serverGroups)
            # RFC 7919 groups
            serverGroups = self._groupNamesToList(settings)
            ffGroupIntersect = getFirstMatching(clientGroups, serverGroups)
            # if there is no overlap, but there are no FFDHE groups listed,
            # allow DHE, prohibit otherwise
            if not ffGroupIntersect:
                if clientGroups and \
                        any(i for i in clientGroups if i in range(256, 512)):
                    ffGroupIntersect = False
                else:
                    ffGroupIntersect = True


        #Now that the version is known, limit to only the ciphers available to
        #that version and client capabilities.
        cipherSuites = []
        if verifierDB:
            if certChain:
                cipherSuites += \
                    CipherSuite.getSrpCertSuites(settings, self.version)
            cipherSuites += CipherSuite.getSrpSuites(settings, self.version)
        elif certChain:
            if ecGroupIntersect:
                cipherSuites += CipherSuite.getEcdheCertSuites(settings,
                                                               self.version)
            if ffGroupIntersect:
                cipherSuites += CipherSuite.getDheCertSuites(settings,
                                                             self.version)
            cipherSuites += CipherSuite.getCertSuites(settings, self.version)
        elif anon:
            cipherSuites += CipherSuite.getAnonSuites(settings, self.version)
            cipherSuites += CipherSuite.getEcdhAnonSuites(settings,
                                                          self.version)
        else:
            assert(False)
        cipherSuites = CipherSuite.filterForVersion(cipherSuites,
                                                    minVersion=self.version,
                                                    maxVersion=self.version)
        #If resumption was requested and we have a session cache...
        if clientHello.session_id and sessionCache:
            session = None

            #Check in the session cache
            if sessionCache and not session:
                try:
                    session = sessionCache[clientHello.session_id]
                    if not session.resumable:
                        raise AssertionError()
                    #Check for consistency with ClientHello
                    if session.cipherSuite not in cipherSuites:
                        for result in self._sendError(\
                                AlertDescription.handshake_failure):
                            yield result
                    if session.cipherSuite not in clientHello.cipher_suites:
                        for result in self._sendError(\
                                AlertDescription.handshake_failure):
                            yield result
                    if clientHello.srp_username:
                        if not session.srpUsername or \
                            clientHello.srp_username != bytearray(session.srpUsername, "utf-8"):
                            for result in self._sendError(\
                                    AlertDescription.handshake_failure):
                                yield result
                    if clientHello.server_name:
                        if not session.serverName or \
                            clientHello.server_name != bytearray(session.serverName, "utf-8"):
                            for result in self._sendError(\
                                    AlertDescription.handshake_failure):
                                yield result                    
                    if session.encryptThenMAC and \
                            not clientHello.getExtension(
                                    ExtensionType.encrypt_then_mac):
                        for result in self._sendError(\
                                AlertDescription.handshake_failure):
                            yield result
                    # if old session used EMS, new connection MUST use EMS
                    if session.extendedMasterSecret and \
                            not clientHello.getExtension(
                                    ExtensionType.extended_master_secret):
                        for result in self._sendError(\
                                AlertDescription.handshake_failure):
                            yield result
                    # if old session didn't use EMS but new connection
                    # advertises EMS, create a new session
                    elif not session.extendedMasterSecret and \
                            clientHello.getExtension(
                                    ExtensionType.extended_master_secret):
                        session = None
                except KeyError:
                    pass

            #If a session is found..
            if session:
                #Send ServerHello
                extensions = []
                if session.encryptThenMAC:
                    self._recordLayer.encryptThenMAC = True
                    mte = TLSExtension().create(ExtensionType.encrypt_then_mac,
                                                bytearray(0))
                    extensions.append(mte)
                if session.extendedMasterSecret:
                    ems = TLSExtension().create(ExtensionType.
                                                extended_master_secret,
                                                bytearray(0))
                    extensions.append(ems)
                secureRenego = False
                renegoExt = clientHello.\
                    getExtension(ExtensionType.renegotiation_info)
                if renegoExt:
                    if renegoExt.renegotiated_connection:
                        for result in self._sendError(
                                AlertDescription.handshake_failure):
                            yield result
                    secureRenego = True
                elif CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV in \
                        clientHello.cipher_suites:
                    secureRenego = True
                if secureRenego:
                    extensions.append(RenegotiationInfoExtension()
                                      .create(bytearray(0)))
                selectedALPN = None
                if alpn:
                    alpnExt = clientHello.getExtension(ExtensionType.alpn)
                    if alpnExt:
                        for protocolName in alpnExt.protocol_names:
                            if protocolName in alpn:
                                ext = ALPNExtension().create([protocolName])
                                extensions.append(ext)
                                selectedALPN = protocolName
                                break
                        else:
                            for result in self._sendError(
                                    AlertDescription.no_application_protocol,
                                    "No commonly supported application layer"
                                    "protocol supported"):
                                yield result

                # don't send empty extensions
                if not extensions:
                    extensions = None
                serverHello = ServerHello()
                serverHello.create(self.version, getRandomBytes(32),
                                   session.sessionID, session.cipherSuite,
                                   CertificateType.x509, None, None,
                                   extensions=extensions)
                for result in self._sendMsg(serverHello):
                    yield result

                #Calculate pending connection states
                self._calcPendingStates(session.cipherSuite, 
                                        session.masterSecret,
                                        clientHello.random, 
                                        serverHello.random,
                                        settings.cipherImplementations)

                #Exchange ChangeCipherSpec and Finished messages
                for result in self._sendFinished(session.masterSecret,
                                                 session.cipherSuite):
                    yield result
                for result in self._getFinished(session.masterSecret,
                                                session.cipherSuite):
                    yield result

                #Set the session
                self.session = session
                self._clientRandom = clientHello.random
                self._serverRandom = serverHello.random
                self.session.appProto = selectedALPN
                yield None # Handshake done!

        #Calculate the first cipher suite intersection.
        #This is the 'privileged' ciphersuite.  We'll use it if we're
        #doing a new negotiation.  In fact,
        #the only time we won't use it is if we're resuming a
        #session, in which case we use the ciphersuite from the session.
        #
        #Given the current ciphersuite ordering, this means we prefer SRP
        #over non-SRP.
        for cipherSuite in cipherSuites:
            if cipherSuite in clientHello.cipher_suites:
                break
        else:
            if clientGroups and \
                    any(i in range(256, 512) for i in clientGroups) and \
                    any(i in CipherSuite.dhAllSuites
                        for i in clientHello.cipher_suites):
                for result in self._sendError(
                        AlertDescription.insufficient_security,
                        "FFDHE groups not acceptable and no other common "
                        "ciphers"):
                    yield result
            else:
                for result in self._sendError(\
                        AlertDescription.handshake_failure,
                        "No mutual ciphersuite"):
                    yield result
        if cipherSuite in CipherSuite.srpAllSuites and \
                            not clientHello.srp_username:
            for result in self._sendError(\
                    AlertDescription.unknown_psk_identity,
                    "Client sent a hello, but without the SRP username"):
                yield result

        #If an RSA suite is chosen, check for certificate type intersection
        if cipherSuite in CipherSuite.certAllSuites and CertificateType.x509 \
                                not in clientHello.certificate_types:
            for result in self._sendError(\
                    AlertDescription.handshake_failure,
                    "the client doesn't support my certificate type"):
                yield result

        # If resumption was not requested, or
        # we have no session cache, or
        # the client's session_id was not found in cache:
        yield (clientHello, cipherSuite)

    def _serverSRPKeyExchange(self, clientHello, serverHello, verifierDB,
                              cipherSuite, privateKey, serverCertChain,
                              settings):
        """Perform the server side of SRP key exchange"""
        keyExchange = SRPKeyExchange(cipherSuite,
                                     clientHello,
                                     serverHello,
                                     privateKey,
                                     verifierDB)

        try:
            sigHash = self._pickServerKeyExchangeSig(settings, clientHello,
                                                     serverCertChain)
        except TLSHandshakeFailure as alert:
            for result in self._sendError(
                    AlertDescription.handshake_failure,
                    str(alert)):
                yield result

        #Create ServerKeyExchange, signing it if necessary
        try:
            serverKeyExchange = keyExchange.makeServerKeyExchange(sigHash)
        except TLSUnknownPSKIdentity:
            for result in self._sendError(\
                    AlertDescription.unknown_psk_identity):
                yield result

        #Send ServerHello[, Certificate], ServerKeyExchange,
        #ServerHelloDone
        msgs = []
        msgs.append(serverHello)
        if cipherSuite in CipherSuite.srpCertSuites:
            certificateMsg = Certificate(CertificateType.x509)
            certificateMsg.create(serverCertChain)
            msgs.append(certificateMsg)
        msgs.append(serverKeyExchange)
        msgs.append(ServerHelloDone())
        for result in self._sendMsgs(msgs):
            yield result

        #Get and check ClientKeyExchange
        for result in self._getMsg(ContentType.handshake,
                                  HandshakeType.client_key_exchange,
                                  cipherSuite):
            if result in (0,1): yield result
            else: break
        try:
            premasterSecret = keyExchange.processClientKeyExchange(result)
        except TLSIllegalParameterException:
            for result in self._sendError(AlertDescription.illegal_parameter,
                                          "Suspicious A value"):
                yield result
        except TLSDecodeError as alert:
            for result in self._sendError(AlertDescription.decode_error,
                                          str(alert)):
                yield result

        yield premasterSecret

    def _serverCertKeyExchange(self, clientHello, serverHello, 
                                serverCertChain, keyExchange,
                                reqCert, reqCAs, cipherSuite,
                                settings):
        #Send ServerHello, Certificate[, ServerKeyExchange]
        #[, CertificateRequest], ServerHelloDone
        msgs = []

        # If we verify a client cert chain, return it
        clientCertChain = None

        msgs.append(serverHello)
        msgs.append(Certificate(CertificateType.x509).create(serverCertChain))
        try:
            sigHashAlg = self._pickServerKeyExchangeSig(settings, clientHello,
                                                        serverCertChain)
        except TLSHandshakeFailure as alert:
            for result in self._sendError(
                    AlertDescription.handshake_failure,
                    str(alert)):
                yield result
        serverKeyExchange = keyExchange.makeServerKeyExchange(sigHashAlg)
        if serverKeyExchange is not None:
            msgs.append(serverKeyExchange)
        if reqCert:
            certificateRequest = CertificateRequest(self.version)
            if not reqCAs:
                reqCAs = []
            validSigAlgs = self._sigHashesToList(settings)
            certificateRequest.create([ClientCertificateType.rsa_sign],
                                      reqCAs,
                                      validSigAlgs)
            msgs.append(certificateRequest)
        msgs.append(ServerHelloDone())
        for result in self._sendMsgs(msgs):
            yield result

        #Get [Certificate,] (if was requested)
        if reqCert:
            if self.version == (3,0):
                for result in self._getMsg((ContentType.handshake,
                                           ContentType.alert),
                                           HandshakeType.certificate,
                                           CertificateType.x509):
                    if result in (0,1): yield result
                    else: break
                msg = result

                if isinstance(msg, Alert):
                    #If it's not a no_certificate alert, re-raise
                    alert = msg
                    if alert.description != \
                            AlertDescription.no_certificate:
                        self._shutdown(False)
                        raise TLSRemoteAlert(alert)
                elif isinstance(msg, Certificate):
                    clientCertificate = msg
                    if clientCertificate.certChain and \
                            clientCertificate.certChain.getNumCerts()!=0:
                        clientCertChain = clientCertificate.certChain
                else:
                    raise AssertionError()
            elif self.version in ((3,1), (3,2), (3,3)):
                for result in self._getMsg(ContentType.handshake,
                                          HandshakeType.certificate,
                                          CertificateType.x509):
                    if result in (0,1): yield result
                    else: break
                clientCertificate = result
                if clientCertificate.certChain and \
                        clientCertificate.certChain.getNumCerts()!=0:
                    clientCertChain = clientCertificate.certChain
            else:
                raise AssertionError()

        #Get ClientKeyExchange
        for result in self._getMsg(ContentType.handshake,
                                  HandshakeType.client_key_exchange,
                                  cipherSuite):
            if result in (0,1): yield result
            else: break
        clientKeyExchange = result

        #Process ClientKeyExchange
        try:
            premasterSecret = \
                keyExchange.processClientKeyExchange(clientKeyExchange)
        except TLSIllegalParameterException as alert:
            for result in self._sendError(AlertDescription.illegal_parameter,
                                          str(alert)):
                yield result
        except TLSDecodeError as alert:
            for result in self._sendError(AlertDescription.decode_error,
                                          str(alert)):
                yield result

        #Get and check CertificateVerify, if relevant
        self._certificate_verify_handshake_hash = self._handshake_hash.copy()
        if clientCertChain:
            for result in self._getMsg(ContentType.handshake,
                                       HandshakeType.certificate_verify):
                if result in (0, 1):
                    yield result
                else: break
            certificateVerify = result
            signatureAlgorithm = None
            if self.version == (3, 3):
                validSigAlgs = self._sigHashesToList(settings)
                if certificateVerify.signatureAlgorithm not in validSigAlgs:
                    for result in self._sendError(\
                            AlertDescription.decryption_failed,
                            "Invalid signature on Certificate Verify"):
                        yield result
                signatureAlgorithm = certificateVerify.signatureAlgorithm

            cvhh = self._certificate_verify_handshake_hash
            verifyBytes = KeyExchange.calcVerifyBytes(self.version,
                                                      cvhh,
                                                      signatureAlgorithm,
                                                      premasterSecret,
                                                      clientHello.random,
                                                      serverHello.random)
            publicKey = clientCertChain.getEndEntityPublicKey()
            if len(publicKey) < settings.minKeySize:
                for result in self._sendError(\
                        AlertDescription.handshake_failure,
                        "Client's public key too small: %d" % len(publicKey)):
                    yield result

            if len(publicKey) > settings.maxKeySize:
                for result in self._sendError(\
                        AlertDescription.handshake_failure,
                        "Client's public key too large: %d" % len(publicKey)):
                    yield result

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

            if not publicKey.verify(certificateVerify.signature,
                                    verifyBytes,
                                    padding,
                                    hashName,
                                    saltLen):
                for result in self._sendError(\
                        AlertDescription.decrypt_error,
                        "Signature failed to verify"):
                    yield result
        yield (premasterSecret, clientCertChain)


    def _serverAnonKeyExchange(self, serverHello, keyExchange, cipherSuite):

        # Create ServerKeyExchange
        serverKeyExchange = keyExchange.makeServerKeyExchange()

        # Send ServerHello[, Certificate], ServerKeyExchange,
        # ServerHelloDone
        msgs = []
        msgs.append(serverHello)
        msgs.append(serverKeyExchange)
        msgs.append(ServerHelloDone())
        for result in self._sendMsgs(msgs):
            yield result

        # Get and check ClientKeyExchange
        for result in self._getMsg(ContentType.handshake,
                                   HandshakeType.client_key_exchange,
                                   cipherSuite):
            if result in (0,1):
                yield result
            else:
                break
        cke = result
        try:
            premasterSecret = keyExchange.processClientKeyExchange(cke)
        except TLSIllegalParameterException as alert:
            for result in self._sendError(AlertDescription.illegal_parameter,
                                          str(alert)):
                yield result
        except TLSDecodeError as alert:
            for result in self._sendError(AlertDescription.decode_error,
                                          str(alert)):
                yield result

        yield premasterSecret


    def _serverFinished(self,  premasterSecret, clientRandom, serverRandom,
                        cipherSuite, cipherImplementations, nextProtos):
        if self.extendedMasterSecret:
            cvhh = self._certificate_verify_handshake_hash
            # in case of resumption or lack of certificate authentication,
            # the CVHH won't be initialised, but then it would also be equal
            # to regular handshake hash
            if not cvhh:
                cvhh = self._handshake_hash
            masterSecret = calcExtendedMasterSecret(self.version,
                                                    cipherSuite,
                                                    premasterSecret,
                                                    cvhh)
        else:
            masterSecret = calcMasterSecret(self.version,
                                            cipherSuite,
                                            premasterSecret,
                                            clientRandom,
                                            serverRandom)

        #Calculate pending connection states
        self._calcPendingStates(cipherSuite, masterSecret, 
                                clientRandom, serverRandom,
                                cipherImplementations)

        #Exchange ChangeCipherSpec and Finished messages
        for result in self._getFinished(masterSecret,
                                        cipherSuite,
                                   expect_next_protocol=nextProtos is not None):
            yield result

        for result in self._sendFinished(masterSecret, cipherSuite):
            yield result
        
        yield masterSecret        


    #*********************************************************
    # Shared Handshake Functions
    #*********************************************************


    def _sendFinished(self, masterSecret, cipherSuite=None, nextProto=None):
        # send the CCS and Finished in single TCP packet
        self.sock.buffer_writes = True
        #Send ChangeCipherSpec
        for result in self._sendMsg(ChangeCipherSpec()):
            yield result

        #Switch to pending write state
        self._changeWriteState()

        if nextProto is not None:
            nextProtoMsg = NextProtocol().create(nextProto)
            for result in self._sendMsg(nextProtoMsg):
                yield result

        #Calculate verification data
        verifyData = calcFinished(self.version,
                                  masterSecret,
                                  cipherSuite,
                                  self._handshake_hash,
                                  self._client)
        if self.fault == Fault.badFinished:
            verifyData[0] = (verifyData[0]+1)%256

        #Send Finished message under new state
        finished = Finished(self.version).create(verifyData)
        for result in self._sendMsg(finished):
            yield result
        self.sock.flush()
        self.sock.buffer_writes = False

    def _getFinished(self, masterSecret, cipherSuite=None,
                     expect_next_protocol=False, nextProto=None):
        #Get and check ChangeCipherSpec
        for result in self._getMsg(ContentType.change_cipher_spec):
            if result in (0,1):
                yield result
        changeCipherSpec = result

        if changeCipherSpec.type != 1:
            for result in self._sendError(AlertDescription.illegal_parameter,
                                         "ChangeCipherSpec type incorrect"):
                yield result

        #Switch to pending read state
        self._changeReadState()

        #Server Finish - Are we waiting for a next protocol echo? 
        if expect_next_protocol:
            for result in self._getMsg(ContentType.handshake, HandshakeType.next_protocol):
                if result in (0,1):
                    yield result
            if result is None:
                for result in self._sendError(AlertDescription.unexpected_message,
                                             "Didn't get NextProtocol message"):
                    yield result

            self.next_proto = result.next_proto
        else:
            self.next_proto = None

        #Client Finish - Only set the next_protocol selected in the connection
        if nextProto:
            self.next_proto = nextProto

        #Calculate verification data
        verifyData = calcFinished(self.version,
                                  masterSecret,
                                  cipherSuite,
                                  self._handshake_hash,
                                  not self._client)

        #Get and check Finished message under new state
        for result in self._getMsg(ContentType.handshake,
                                  HandshakeType.finished):
            if result in (0,1):
                yield result
        finished = result
        if finished.verify_data != verifyData:
            for result in self._sendError(AlertDescription.decrypt_error,
                                         "Finished message is incorrect"):
                yield result

    def _handshakeWrapperAsync(self, handshaker, checker):
        try:
            for result in handshaker:
                yield result
            if checker:
                try:
                    checker(self)
                except TLSAuthenticationError:
                    alert = Alert().create(AlertDescription.close_notify,
                                           AlertLevel.fatal)
                    for result in self._sendMsg(alert):
                        yield result
                    raise
        except GeneratorExit:
            raise
        except TLSAlert as alert:
            if not self.fault:
                raise
            if alert.description not in Fault.faultAlerts[self.fault]:
                raise TLSFaultError(str(alert))
            else:
                pass
        except:
            self._shutdown(False)
            raise

    @staticmethod
    def _pickServerKeyExchangeSig(settings, clientHello, certList=None):
        """Pick a hash that matches most closely the supported ones"""
        hashAndAlgsExt = clientHello.getExtension(\
                ExtensionType.signature_algorithms)

        if hashAndAlgsExt is None or hashAndAlgsExt.sigalgs is None:
            # RFC 5246 states that if there are no hashes advertised,
            # sha1 should be picked
            return "sha1"

        supported = TLSConnection._sigHashesToList(settings,
                                                   certList=certList)

        for schemeID in supported:
            if schemeID in hashAndAlgsExt.sigalgs:
                name = SignatureScheme.toRepr(schemeID)
                if not name and schemeID[1] == SignatureAlgorithm.rsa:
                    name = HashAlgorithm.toRepr(schemeID[0])

                if name:
                    return name

        # if no match, we must abort per RFC 5246
        raise TLSHandshakeFailure("No common signature algorithms")

    @staticmethod
    def _sigHashesToList(settings, privateKey=None, certList=None):
        """Convert list of valid signature hashes to array of tuples"""
        certType = None
        if certList:
            certType = certList.x509List[0].certAlg

        sigAlgs = []
        for schemeName in settings.rsaSchemes:
            for hashName in settings.rsaSigHashes:
                # rsa-pss certificates can't be used to make PKCS#1 v1.5
                # signatures
                if certType == "rsa-pss" and schemeName == "pkcs1":
                    continue
                try:
                    # 1024 bit keys are too small to create valid
                    # rsa-pss-SHA512 signatures
                    if schemeName == 'pss' and hashName == 'sha512'\
                            and privateKey and privateKey.n < 2**2047:
                        continue
                    sigAlgs.append(getattr(SignatureScheme,
                                           "rsa_{0}_{1}".format(schemeName,
                                                                hashName)))
                except AttributeError:
                    if schemeName == 'pkcs1':
                        sigAlgs.append((getattr(HashAlgorithm, hashName),
                                        SignatureAlgorithm.rsa))
                    continue
        return sigAlgs

    @staticmethod
    def _curveNamesToList(settings):
        """Convert list of acceptable curves to array identifiers"""
        return [getattr(GroupName, val) for val in settings.eccCurves]

    @staticmethod
    def _groupNamesToList(settings):
        """Convert list of acceptable ff groups to TLS identifiers."""
        return [getattr(GroupName, val) for val in settings.dhGroups]
