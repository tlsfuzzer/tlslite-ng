#!/usr/bin/env python

# Authors:
#   Trevor Perrin
#   Marcelo Fernandez - bugfix and NPN support
#   Martin von Loewis - python 3 port
#
# See the LICENSE file for legal information regarding use of this file.
from __future__ import print_function
import sys
import os
import os.path
import socket
import struct
import getopt
import binascii
import hashlib
import time

from tlslite.utils.codec import Parser
from tlslite.utils.ecdsakey import ECDSAKey
from tlslite.utils.eddsakey import EdDSAKey
from tlslite.utils.rsakey import RSAKey
from tlslite.x509 import Credential, DelegatedCredential
try:
    import httplib
    from SocketServer import *
    from BaseHTTPServer import *
    from SimpleHTTPServer import *
except ImportError:
    # Python 3.x
    from http import client as httplib
    from socketserver import *
    from http.server import *
    from http.server import SimpleHTTPRequestHandler

if __name__ != "__main__":
    raise Exception("This must be run as a command, not used as a module!")

from tlslite.api import *
from tlslite.constants import CipherSuite, HashAlgorithm, SignatureAlgorithm, \
        GroupName, SignatureScheme
from tlslite.handshakesettings import Keypair, VirtualHost
from tlslite import __version__
from tlslite.utils.compat import b2a_hex, a2b_hex, time_stamp, \
        ML_KEM_AVAILABLE, ML_DSA_AVAILABLE
from tlslite.utils.dns_utils import is_valid_hostname
from tlslite.utils.cryptomath import getRandomBytes
from tlslite.constants import KeyUpdateMessageType, TLS_1_3_BRAINPOOL_SIG_SCHEMES
from tlslite.utils.compression import compression_algo_impls
from tlslite.utils.pem import dePem, pem
from tlslite.handshakesettings import DELEGETED_CREDENTIAL_FORBIDDEN_ALG, \
        DC_VALID_TIME
from tlslite.utils.cryptomath import numberToByteArray
from tlslite.utils.ecc import curve_name_to_hash_name

try:
    from tack.structures.Tack import Tack

except ImportError:
    pass

def printUsage(s=None):
    if s:
        print("ERROR: %s" % s)

    print("")
    print("Version: %s" % __version__)
    print("")
    print("RNG: %s" % prngName)
    print("")
    print("Modules:")
    if tackpyLoaded:
        print("  tackpy      : Loaded")
    else:
        print("  tackpy      : Not Loaded")
    if m2cryptoLoaded:
        print("  M2Crypto    : Loaded")
    else:
        print("  M2Crypto    : Not Loaded")
    if pycryptoLoaded:
        print("  pycrypto    : Loaded")
    else:
        print("  pycrypto    : Not Loaded")
    if gmpyLoaded:
        print("  GMPY        : Loaded")
    else:
        print("  GMPY        : Not Loaded")
    if GMPY2_LOADED:
        print("  GMPY2       : Loaded")
    else:
        print("  GMPY2       : Not Loaded")
    if ML_KEM_AVAILABLE:
        print("  Kyber-py    : Loaded")
    else:
        print("  Kyber-py    : Not Loaded")
    if ML_DSA_AVAILABLE:
        print("  Dilithium-py: Loaded")
    else:
        print("  Dilithium-py: Not Loaded")

    print("")
    print("Certificate compression algorithms:")
    print("  zlib compress      : Loaded")
    print("  zlib decompress    : Loaded")
    print("  brotli compress    : {0}".format(
        "Loaded" if compression_algo_impls["brotli_compress"]
        else "Not Loaded"
    ))
    print("  brotli decompress  : {0}".format(
        "Loaded" if compression_algo_impls["brotli_decompress"]
        else "Not Loaded"
    ))
    print("  zstd decompress    : {0}".format(
        "Loaded" if compression_algo_impls["zstd_compress"]
        else "Not Loaded"
    ))
    print("  zstd decompress    : {0}".format(
        "Loaded" if compression_algo_impls["zstd_decompress"]
        else "Not Loaded"
    ))
    print("")
    print("""Commands:

  server
    [-c CERT] [-k KEY] [-t TACK] [-v VERIFIERDB] [-d DIR] [-l LABEL] [-L LENGTH]
    [--reqcert] [--param DHFILE] [--psk PSK] [--psk-ident IDENTITY]
    [--psk-sha384] [--ssl3] [--max-ver VER] [--tickets COUNT] [--cipherlist]
    [--request-pha] [--require-pha] [--echo] [--groups GROUPS] [--dc-key KEY]
    [--dc-pub KEY] [--dc-sig-scheme SIG]
    [--dc-file DCFILE]
    HOST:PORT

  client
    [-c CERT] [-k KEY] [-u USER] [-p PASS] [-l LABEL] [-L LENGTH] [-a ALPN]
    [--psk PSK] [--psk-ident IDENTITY] [--psk-sha384] [--resumption] [--ssl3]
    [--max-ver VER] [--cipherlist]
    HOST:PORT

  credential
    [-c CERT] [-k KEY] [--dc-pub KEY] [--dc-sig-scheme SIG]
    [--dc-file DCFILE]

  LABEL - TLS exporter label
  LENGTH - amount of info to export using TLS exporter
  ALPN - name of protocol for ALPN negotiation, can be present multiple times
         in client to specify multiple protocols supported
  DHFILE - file that includes Diffie-Hellman parameters to be used with DHE
           key exchange
  PSK - hex encoded (without starting 0x) shared key to be used for connection
  IDENTITY - name associated with the PSK key
  --ssl3 - enable support for SSLv3
  VER - TLS version as a string, "ssl3", "tls1.0", "tls1.1", "tls1.2" or
        "tls1.3"
  SIG - signature scheme name to be used for signing,
        e.g. ecdsa_secp256r1_sha256, ed25519, rsa_pss_pss_sha256
  DCFILE - the file to store/load from the delegated credenial
  --tickets COUNT - how many tickets should server send after handshake is
                    finished
  --cipherlist - comma separated ciphers to enable. For ex. aes128ccm,3des
                 You can specify this option multiple times.
  --request-pha - ask client for post-handshake authentication
  --require-pha - abort connection if client didn't provide certificate in
                  post-handshake authentication
  --echo - function as an echo server
  --groups - specify what key exchange groups should be supported
  --dc-key KEY - the private key of the delegated credential
  --dc-pub KEY - the public key of the delegated credential
  --dc-sig-scheme SIG - delegated credential signature scheme for signing
  --dc-file DCFILE - the file from which to load or to store
                     the delegated credential
  GROUPS - comma-separated list of enabled key exchange groups
  CERT, KEY - the file with key and certificates that will be used by client or
        server. The server can accept multiple pairs of `-c` and `-k` options
        to configure different certificates (like RSA and ECDSA)

""")
    sys.exit(-1)


def ver_to_tuple(name):
    vers = {"ssl3": (3, 0),
            "tls1.0": (3, 1),
            "tls1.1": (3, 2),
            "tls1.2": (3, 3),
            "tls1.3": (3, 4)}
    try:
        return vers[name]
    except KeyError:
        raise ValueError("Unknown protocol name: {0}".format(name))


def printError(s):
    """Print error message and exit"""
    sys.stderr.write("ERROR: %s\n" % s)
    sys.exit(-1)


def handleArgs(argv, argString, flagsList=[], expect_address=True):
    # Convert to getopt argstring format:
    # Add ":" after each arg, ie "abc" -> "a:b:c:"
    getOptArgString = ":".join(argString) + ":"
    try:
        opts, argv = getopt.getopt(argv, getOptArgString, flagsList)
    except getopt.GetoptError as e:
        printError(e)
    # Default values if arg not present
    privateKey = None
    cert_chain = None
    virtual_hosts = []
    v_host_cert = None
    username = None
    password = None
    tacks = None
    verifierDB = None
    reqCert = False
    directory = None
    expLabel = None
    expLength = 20
    alpn = []
    dhparam = None
    psk = None
    psk_ident = None
    psk_hash = 'sha256'
    resumption = False
    ssl3 = False
    max_ver = None
    tickets = None
    ciphers = []
    request_pha = False
    require_pha = False
    echo = False
    groups = None
    dc_key = None
    dc_pub = None
    dc_sig_scheme = None
    dc_file = None

    for opt, arg in opts:
        if opt == "-k":
            s = open(arg, "rb").read()
            if sys.version_info[0] >= 3:
                s = str(s, 'utf-8')
            # OpenSSL/m2crypto does not support RSASSA-PSS certificates
            if not privateKey:
                privateKey = parsePEMKey(s, private=True,
                                         implementations=["python"])
            else:
                if not v_host_cert:
                    raise ValueError("Virtual host certificate missing "
                                     "(must be listed before key)")
                p_key = parsePEMKey(s, private=True,
                                    implementations=["python"])
                if not virtual_hosts:
                    virtual_hosts.append(VirtualHost())
                virtual_hosts[0].keys.append(
                    Keypair(p_key, v_host_cert.x509List))
                v_host_cert = None
        elif opt == "-c":
            s = open(arg, "rb").read()
            if sys.version_info[0] >= 3:
                s = str(s, 'utf-8')
            if not cert_chain:
                cert_chain = X509CertChain()
                cert_chain.parsePemList(s)
            else:
                v_host_cert = X509CertChain()
                v_host_cert.parsePemList(s)
        elif opt == "--dc-key":
            s = open(arg, "rb").read()
            if sys.version_info[0] >= 3:
                s = str(s, 'utf-8')
            if not cert_chain:
                raise ValueError("Certificate is missing (must be listed "
                                 "before the delegated credentials)")
            dc_key = parsePEMKey(s, private=True,
                                      implementations=["python"])
        elif opt == "--dc-pub":
            dc_pub = arg
        elif opt == "--dc-sig-scheme":
            dc_sig_scheme = getattr(SignatureScheme, arg)
        elif opt == "--dc-file":
            dc_file = arg
        elif opt == "-u":
            username = arg
        elif opt == "-p":
            password = arg
        elif opt == "-t":
            if tackpyLoaded:
                s = open(arg, "rU").read()
                tacks = Tack.createFromPemList(s)
        elif opt == "-v":
            verifierDB = VerifierDB(arg)
            verifierDB.open()
        elif opt == "-d":
            directory = arg
        elif opt == "--reqcert":
            reqCert = True
        elif opt == "-l":
            expLabel = arg
        elif opt == "-L":
            expLength = int(arg)
        elif opt == "-a":
            alpn.append(bytearray(arg, 'utf-8'))
        elif opt == "--param":
            s = open(arg, "rb").read()
            if sys.version_info[0] >= 3:
                s = str(s, 'utf-8')
            dhparam = parseDH(s)
        elif opt == "--psk":
            psk = a2b_hex(arg)
        elif opt == "--psk-ident":
            psk_ident = bytearray(arg, 'utf-8')
        elif opt == "--psk-sha384":
            psk_hash = 'sha384'
        elif opt == "--resumption":
            resumption = True
        elif opt == "--ssl3":
            ssl3 = True
        elif opt == "--max-ver":
            max_ver = ver_to_tuple(arg)
        elif opt == "--tickets":
            tickets = int(arg)
        elif opt == "--cipherlist":
            ciphers.append(arg)
        elif opt == "--groups":
            groups = arg.split(',')
        elif opt == "--request-pha":
            request_pha = True
        elif opt == "--require-pha":
            require_pha = True
        elif opt == "--echo":
            echo = True
        else:
            assert(False)

    # when no names provided, don't return array
    if not alpn:
        alpn = None
    if (psk and not psk_ident) or (not psk and psk_ident):
        printError("PSK and IDENTITY must be set together")
    if not argv and expect_address:
        printError("Missing address")
    if len(argv)>1:
        printError("Too many arguments")

    #Split address into hostname/port tuple
    if expect_address:
        address = argv[0]
        address = address.split(":")
        if len(address) != 2:
            raise SyntaxError("Must specify <host>:<port>")
        address = ( address[0], int(address[1]) )

    # Populate the return list
    retList = [] if not expect_address else [address]
    if "k" in argString:
        retList.append(privateKey)
    if "c" in argString:
        retList.append(cert_chain)
        retList.append(virtual_hosts)
    if "u" in argString:
        retList.append(username)
    if "p" in argString:
        retList.append(password)
    if "t" in argString:
        retList.append(tacks)
    if "v" in argString:
        retList.append(verifierDB)
    if "d" in argString:
        retList.append(directory)
    if "reqcert" in flagsList:
        retList.append(reqCert)
    if "l" in argString:
        retList.append(expLabel)
    if "L" in argString:
        retList.append(expLength)
    if "a" in argString:
        retList.append(alpn)
    if "param=" in flagsList:
        retList.append(dhparam)
    if "psk=" in flagsList:
        retList.append(psk)
    if "psk-ident=" in flagsList:
        retList.append(psk_ident)
    if "psk-sha384" in flagsList:
        retList.append(psk_hash)
    if "resumption" in flagsList:
        retList.append(resumption)
    if "ssl3" in flagsList:
        retList.append(ssl3)
    if "max-ver=" in flagsList:
        retList.append(max_ver)
    if "tickets=" in flagsList:
        retList.append(tickets)
    if "cipherlist=" in flagsList:
        retList.append(ciphers)
    if "request-pha" in flagsList:
        retList.append(request_pha)
    if "require-pha" in flagsList:
        retList.append(require_pha)
    if "echo" in flagsList:
        retList.append(echo)
    if "groups=" in flagsList:
        retList.append(groups)
    if "dc-key=" in flagsList:
        retList.append(dc_key)
    if "dc-pub=" in flagsList:
        retList.append(dc_pub)
    if "dc-sig-scheme=" in flagsList:
        retList.append(dc_sig_scheme)
    if "dc-file=" in flagsList:
        retList.append(dc_file)
    return retList


def printGoodConnection(connection, seconds):
    print("  Handshake time: %.3f seconds" % seconds)
    print("  Version: %s" % connection.getVersionName())
    print("  Cipher: %s %s" % (connection.getCipherName(),
        connection.getCipherImplementation()))
    print("  Ciphersuite: {0}".\
            format(CipherSuite.ietfNames[connection.session.cipherSuite]))
    if connection.session.srpUsername:
        print("  Client SRP username: %s" % connection.session.srpUsername)
    if connection.session.clientCertChain:
        print("  Client X.509 SHA1 fingerprint: %s" %
            connection.session.clientCertChain.getFingerprint())
    else:
        print("  No client certificate provided by peer")
    if connection.session.serverCertChain:
        print("  Server X.509 SHA1 fingerprint: %s" %
            connection.session.serverCertChain.getFingerprint())
    if connection.version >= (3, 3) and connection.serverSigAlg is not None:
        scheme = SignatureScheme.toRepr(connection.serverSigAlg)
        if scheme is None:
            scheme = "{1}+{0}".format(
                HashAlgorithm.toStr(connection.serverSigAlg[0]),
                SignatureAlgorithm.toStr(connection.serverSigAlg[1]))
        print("  Key exchange signature: {0}".format(scheme))
    if connection.ecdhCurve is not None:
        print("  Group used for key exchange: {0}".format(\
                GroupName.toStr(connection.ecdhCurve)))
    if connection.dhGroupSize is not None:
        print("  DH group size: {0} bits".format(connection.dhGroupSize))
    if connection.session.serverName:
        print("  SNI: %s" % connection.session.serverName)
    if connection.session.tackExt:
        if connection.session.tackInHelloExt:
            emptyStr = "\n  (via TLS Extension)"
        else:
            emptyStr = "\n  (via TACK Certificate)"
        print("  TACK: %s" % emptyStr)
        print(str(connection.session.tackExt))
    if connection.session.appProto:
        print("  Application Layer Protocol negotiated: {0}".format(
            connection.session.appProto.decode('utf-8')))
    print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    print("  Encrypt-then-MAC: {0}".format(connection.encryptThenMAC))
    print("  Extended Master Secret: {0}".format(
                                               connection.extendedMasterSecret))
    print("  Session Resumed: {0}".format(connection.resumed))
    if connection.client_cert_compression_algo:
        print("  Client compression algorithm used: {0}".format(
            connection.client_cert_compression_algo))
    if connection.server_cert_compression_algo:
        print("  Server compression algorithm used: {0}".format(
            connection.server_cert_compression_algo))
    print("  Session used ec point format extension: {0}".format(connection.session.ec_point_format))

def printExporter(connection, expLabel, expLength):
    if expLabel is None:
        return
    expLabel = bytearray(expLabel, "utf-8")
    exp = connection.keyingMaterialExporter(expLabel, expLength)
    exp = b2a_hex(exp).upper()
    print("  Exporter label: {0}".format(expLabel))
    print("  Exporter length: {0}".format(expLength))
    print("  Keying material: {0}".format(exp))


def clientCmd(argv):
    (address, privateKey, cert_chain, virtual_hosts, username, password,
            expLabel,
            expLength, alpn, psk, psk_ident, psk_hash, resumption, ssl3,
            max_ver, cipherlist) = \
        handleArgs(argv, "kcuplLa", ["psk=", "psk-ident=", "psk-sha384",
                                     "resumption", "ssl3", "max-ver=",
                                     "cipherlist="])

    if (cert_chain and not privateKey) or (not cert_chain and privateKey):
        raise SyntaxError("Must specify CERT and KEY together")
    if (username and not password) or (not username and password):
        raise SyntaxError("Must specify USER with PASS")
    if cert_chain and username:
        raise SyntaxError("Can use SRP or client cert for auth, not both")
    if expLabel is not None and not expLabel:
        raise ValueError("Label must be non-empty")

    #Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(address)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    connection = TLSConnection(sock)

    settings = HandshakeSettings()
    if psk:
        settings.pskConfigs = [(psk_ident, psk, psk_hash)]
    settings.useExperimentalTackExtension = True
    if ssl3:
        settings.minVersion = (3, 0)
    if max_ver:
        settings.maxVersion = max_ver
    if cipherlist:
        settings.cipherNames = [item for cipher in cipherlist
                                for item in cipher.split(',')]
    try:
        start = time_stamp()
        if username and password:
            connection.handshakeClientSRP(username, password,
                settings=settings, serverName=address[0])
        else:
            connection.handshakeClientCert(cert_chain, privateKey,
                settings=settings, serverName=address[0], alpn=alpn)
        stop = time_stamp()
        print("Handshake success")
    except TLSLocalAlert as a:
        if a.description == AlertDescription.user_canceled:
            print(str(a))
        else:
            raise
        sys.exit(-1)
    except TLSRemoteAlert as a:
        if a.description == AlertDescription.unknown_psk_identity:
            if username:
                print("Unknown username")
            else:
                raise
        elif a.description == AlertDescription.bad_record_mac:
            if username:
                print("Bad username or password")
            else:
                raise
        elif a.description == AlertDescription.handshake_failure:
            print("Unable to negotiate mutually acceptable parameters")
        else:
            raise
        sys.exit(-1)
    printGoodConnection(connection, stop-start)
    printExporter(connection, expLabel, expLength)
    session = connection.session
    connection.send(b"GET / HTTP/1.0\r\n\r\n")
    while True:
        try:
            r = connection.recv(10240)
            if not r:
                break
        except socket.timeout:
            break
        except TLSAbruptCloseError:
            break
    connection.close()
    # we're expecting an abrupt close error which marks the session as
    # unreasumable, override it
    session.resumable = True

    print("Received {0} ticket[s]".format(len(connection.tickets) + len(connection.tls_1_0_tickets)))
    assert connection.tickets is session.tickets

    if not resumption:
        return

    print("Trying resumption handshake")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(address)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    connection = TLSConnection(sock)
    try:
        start = time_stamp()
        connection.handshakeClientCert(serverName=address[0], alpn=alpn,
            session=session, settings=settings)
        stop = time_stamp()
        print("Handshake success")
    except TLSLocalAlert as a:
        if a.description == AlertDescription.user_canceled:
            print(str(a))
        else:
            raise
        sys.exit(-1)
    except TLSRemoteAlert as a:
        if a.description == AlertDescription.unknown_psk_identity:
            if username:
                print("Unknown username")
            else:
                raise
        elif a.description == AlertDescription.bad_record_mac:
            if username:
                print("Bad username or password")
            else:
                raise
        elif a.description == AlertDescription.handshake_failure:
            print("Unable to negotiate mutually acceptable parameters")
        else:
            raise
        sys.exit(-1)
    printGoodConnection(connection, stop-start)
    printExporter(connection, expLabel, expLength)
    connection.close()


def serverCmd(argv):
    (address, privateKey, cert_chain, virtual_hosts, tacks, verifierDB,
            directory, reqCert,
            expLabel, expLength, dhparam, psk, psk_ident, psk_hash, ssl3,
            max_ver, tickets, cipherlist, request_pha, require_pha, echo,
            groups, dc_key, dc_pub, dc_sig_scheme, dc_file) = \
        handleArgs(argv, "kctbvdlL",
                   ["reqcert", "param=", "psk=",
                    "psk-ident=", "psk-sha384", "ssl3", "max-ver=",
                    "tickets=", "cipherlist=", "request-pha", "require-pha",
                    "echo", "groups=", "dc-key=", "dc-pub=",
                    "dc-sig-scheme=", "dc-file="])

    # The authentication of the certificate will rely on the DC
    if cert_chain and not privateKey:
        if not dc_file or not dc_key:
            raise SyntaxError("If certificate is provided without its " \
                              "private key, a pre-existing delegated " \
                              "credential must be supplied for server authentication.")

    # Creating a delegated credential option
    if (dc_key and dc_pub) and (not cert_chain or not privateKey):
        raise SyntaxError("To generate a delegated credential the main " \
                          "server certificate and its private key must be provided.")
    if (dc_key and not dc_file and not dc_pub):
        raise SyntaxError("To create the delegated credential, " \
                          "both - public and private key - must be provided "
                          "OR the private key for the provided delegated " \
                          "credential must be present.")
    if dc_file:
        s = open(dc_file, "rb").read()
        if os.path.splitext(dc_file)[1] == ".pem":
            if sys.version_info[0] >= 3:
                s = str(s, 'utf-8')
            s = dePem(s, "DELEGATED CREDENTIAL")
        dc_parser = Parser(s)
        delegated_credential = DelegatedCredential().parse(dc_parser)
        certificate = cert_chain.x509List[0]
        sig_context = DelegatedCredential.compute_certificate_dc_sig_context(
            certificate.bytes,
            delegated_credential.cred.bytes,
            delegated_credential.algorithm)
        cert_pub_key = certificate.publicKey
        sig_scheme = delegated_credential.algorithm
        if sig_scheme in (SignatureScheme.ed25519,
                                SignatureScheme.ed448):
            pad_type = None
            hash_name = "intrinsic"
            salt_len = None
            method = cert_pub_key.hashAndVerify
        elif sig_scheme[1] == SignatureAlgorithm.ecdsa:
            pad_type = None
            hash_name = HashAlgorithm.toRepr(sig_scheme[0])
            matching_hash = curve_name_to_hash_name(
                cert_pub_key.curve_name)
            if hash_name != matching_hash:
                raise TLSIllegalParameterException(
                    "server selected signature method invalid for the "
                    "certificate it presented (curve mismatch)")

            salt_len = None
            method = cert_pub_key.hashAndVerify
        elif sig_scheme in TLS_1_3_BRAINPOOL_SIG_SCHEMES:
            scheme = SignatureScheme.toRepr(sig_scheme)
            pad_type = None
            hash_name = SignatureScheme.getHash(scheme)
            salt_len = None
            method = cert_pub_key.hashAndVerify
        else:
            scheme = SignatureScheme.toRepr(sig_scheme)
            pad_type = SignatureScheme.getPadding(scheme)
            hash_name = SignatureScheme.getHash(scheme)
            salt_len = getattr(hashlib, hash_name)().digest_size
            method = cert_pub_key.hashAndVerify
        if not method(delegated_credential.signature,
                        sig_context,
                        pad_type,
                        hash_name,
                        salt_len):
            raise TLSDecryptionFailed("server Delegated Credential " \
            "signature verification failed.")


    elif dc_key and dc_pub and cert_chain and privateKey:
        delegated_credential = _create_delegated_credential_object(privateKey,
                                                                   cert_chain,
                                                                   dc_pub,
                                                                   dc_sig_scheme)
    else:
        delegated_credential = None

    if (cert_chain and (not privateKey and not delegated_credential)) or \
       (not cert_chain and (privateKey or delegated_credential)):
        raise SyntaxError("Must specify CERT and KEY together or CERT and DC")
    if tacks and not cert_chain:
        raise SyntaxError("Must specify CERT with Tacks")

    print("I am an {2} test server, I will listen on {0}:{1}".format(
        address[0], address[1], "echo" if echo else "HTTP"))

    if directory:
        os.chdir(directory)
    if not echo:
        print("Serving files from %s" % os.getcwd())

    if cert_chain and privateKey:
        print("Using certificate and private key...")
    if verifierDB:
        print("Using verifier DB...")
    if tacks:
        print("Using Tacks...")
    if reqCert:
        print("Asking for client certificates...")
    if (dc_key and delegated_credential):
        print("Usage of delegated credential is available...")

    #############
    sessionCache = SessionCache()
    username = None
    sni = None
    if is_valid_hostname(address[0]):
        sni = address[0]
    settings = HandshakeSettings()
    settings.useExperimentalTackExtension=True
    settings.dhParams = dhparam
    if tickets is not None:
        settings.ticket_count = tickets
    if psk:
        settings.pskConfigs = [(psk_ident, psk, psk_hash)]
    settings.ticketKeys = [getRandomBytes(32)]
    if ssl3:
        settings.minVersion = (3, 0)
    if max_ver:
        settings.maxVersion = max_ver
    settings.virtual_hosts = virtual_hosts
    if cipherlist:
        settings.cipherNames = [item for cipher in cipherlist
                                for item in cipher.split(',')]
    if groups:
        dh_groups = []
        ecc_groups = []
        for item in groups:
            if "ffdh" in item:
                dh_groups.append(item)
            else:
                ecc_groups.append(item)
        settings.dhGroups = dh_groups
        settings.eccCurves = ecc_groups
        settings.keyShares = []

    class MySimpleEchoHandler(BaseRequestHandler):
        def handle(self):
            while True:
                data = self.request.recv(2**14)  # max TLS ApplicationData
                if not data:
                    break
                self.request.send(data)

    class MySimpleHTTPHandler(SimpleHTTPRequestHandler, object):
        """Buffer the header and body of HTTP message."""
        wbufsize = -1

        def do_GET(self):
            """Simple override to send KeyUpdate to client."""
            if self.path.startswith('/keyupdate'):
                for i in self.connection.send_keyupdate_request(
                        KeyUpdateMessageType.update_requested):
                    if i in (0, 1):
                        continue
                    else:
                        raise ValueError("Invalid return from "
                                         "send_keyupdate_request")
            if self.path.startswith('/secret') and not request_pha:
                try:
                    for i in self.connection.request_post_handshake_auth():
                        pass
                except ValueError:
                    self.wfile.write(b'HTTP/1.0 401 Certificate authentication'
                                     b' required\r\n')
                    self.wfile.write(b'Connection: close\r\n')
                    self.wfile.write(b'Content-Length: 0\r\n\r\n')
                    return
                self.connection.read(0, 0)
                if self.connection.session.clientCertChain:
                    print("   Got client certificate in post-handshake auth: "
                          "{0}".format(self.connection.session
                                       .clientCertChain.getFingerprint()))
                else:
                    print("   No certificate from client received")
                    self.wfile.write(b'HTTP/1.0 401 Certificate authentication'
                                     b' required\r\n')
                    self.wfile.write(b'Connection: close\r\n')
                    self.wfile.write(b'Content-Length: 0\r\n\r\n')
                    return
            return super(MySimpleHTTPHandler, self).do_GET()

    if echo:
        mixin = TCPServer
        handler = MySimpleEchoHandler
    else:
        mixin = HTTPServer
        handler = MySimpleHTTPHandler

    class MyServer(ThreadingMixIn, TLSSocketServerMixIn, mixin):
        def handshake(self, connection):
            print("About to handshake...")
            activationFlags = 0
            if tacks:
                if len(tacks) == 1:
                    activationFlags = 1
                elif len(tacks) == 2:
                    activationFlags = 3

            try:
                start = time_stamp()
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,
                                      1)
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                      struct.pack('ii', 1, 5))
                connection.client_cert_required = require_pha
                connection.handshakeServer(certChain=cert_chain,
                                              privateKey=privateKey,
                                              verifierDB=verifierDB,
                                              tacks=tacks,
                                              activationFlags=activationFlags,
                                              sessionCache=sessionCache,
                                              settings=settings,
                                              nextProtos=[b"http/1.1"],
                                              alpn=[bytearray(b'http/1.1')],
                                              reqCert=reqCert,
                                              sni=sni,
                                              dc_key=dc_key,
                                              del_cred=delegated_credential)
                                              # As an example (does not work here):
                                              #nextProtos=[b"spdy/3", b"spdy/2", b"http/1.1"])
                try:
                    if request_pha:
                        for i in connection.request_post_handshake_auth():
                            pass
                except ValueError:
                    # if we can't do PHA, we can't do it
                    pass
                stop = time_stamp()
            except TLSRemoteAlert as a:
                if a.description == AlertDescription.user_canceled:
                    print(str(a))
                    return False
                else:
                    raise
            except TLSLocalAlert as a:
                if a.description == AlertDescription.unknown_psk_identity:
                    if username:
                        print("Unknown username")
                        return False
                    else:
                        raise
                elif a.description == AlertDescription.bad_record_mac:
                    if username:
                        print("Bad username or password")
                        return False
                    else:
                        raise
                elif a.description == AlertDescription.handshake_failure:
                    print("Unable to negotiate mutually acceptable parameters")
                    return False
                else:
                    raise

            connection.ignoreAbruptClose = True
            printGoodConnection(connection, stop-start)
            printExporter(connection, expLabel, expLength)
            return True

    server = MyServer(address, handler)
    server.serve_forever()


def credential_cmd(argv):
    """
    Tool to create delegated credential.
    The output will be written into the provided file.
    """
    (private_key, cert_chain, virtual_hosts, dc_pub,
            dc_sig_scheme, dc_file) = \
        handleArgs(argv, "kc", ["dc-pub=", "dc-sig-scheme=", "dc-file="],
                                     expect_address=False)
    if (cert_chain and not private_key) or (not cert_chain and private_key):
        raise SyntaxError("Must specify CERT and KEY together")
    if not dc_file:
        raise SyntaxError("Must provide the file to write the output to")


    delegated_credential = _create_delegated_credential_object(private_key,
                                                               cert_chain,
                                                               dc_pub,
                                                               dc_sig_scheme)

    del_cred_bytes = delegated_credential.write()
    with open(dc_file, "w") as file:
        dc_bytes_pem = pem(del_cred_bytes, "DELEGATED CREDENTIAL")
        file.write(dc_bytes_pem)

    print("The delegated credential was successully written " \
          "into {0}".format(dc_file))


def _create_delegated_credential_object(
        private_key, cert_chain, dc_pub, dc_sig_scheme):

    cert_type = cert_chain.x509List[0].certAlg
    s = open(dc_pub, "rb").read()
    if sys.version_info[0] >= 3:
        s = str(s, 'utf-8')
    dc_pub_byte = dePem(s, "PUBLIC KEY")
    cred = Credential(subject_public_key_info=dc_pub_byte)

    cred.parse_pub_key()
    dc_pub = cred.pub_key

    if cert_type == "Ed25519" or cert_type == "Ed448":
        cert_type = cert_type.lower()
        sig_alg = getattr(SignatureScheme, cert_type)
    elif cert_type == "ecdsa":
        cert_key_curve = private_key.curve_name
        if "BRAINPOOL" in cert_key_curve:
            # brainpool in TLS 1.3 uses special signature schemes
            if cert_key_curve == "BRAINPOOLP256r1":
                sig_alg = SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256
            elif cert_key_curve == "BRAINPOOLP384r1":
                sig_alg = SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384
            else:
                assert cert_key_curve == "BRAINPOOLP512r1"
                sig_alg = SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512
        else:
            hash_name = saltLen = getattr(HashAlgorithm,
                                            curve_name_to_hash_name(cert_key_curve))
            sig_alg = (hash_name, SignatureAlgorithm.ecdsa)

    elif cert_type == "dsa":
        sig_alg = SignatureScheme.dsa_sha256
    elif cert_type in ("rsa", "rsa-pss"):
        sig_alg = SignatureScheme.rsa_pss_pss_sha256

    scheme = SignatureScheme.toRepr(sig_alg)

    if dc_sig_scheme in DELEGETED_CREDENTIAL_FORBIDDEN_ALG:
        raise ValueError("When using RSA, the public key MUST NOT" \
                         " use the rsaEncryption OID.")
    if not dc_sig_scheme:
        if isinstance(dc_pub, RSAKey):
            dc_sig_scheme = SignatureScheme.rsa_pss_pss_sha256
        elif isinstance(dc_pub, ECDSAKey):
            curve = dc_pub.curve_name
            if "BRAINPOOL" in curve:
                if curve == "BRAINPOOLP256r1":
                    dc_sig_scheme = SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256
                elif curve == "BRAINPOOLP384r1":
                    dc_sig_scheme = SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384
                else:
                    assert curve == "BRAINPOOLP512r1"
                    dc_sig_scheme = SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512
            else:
                curve = (dc_pub.curve_name)
                hash_name = saltLen = getattr(HashAlgorithm,
                                              curve_name_to_hash_name(curve))
                dc_sig_scheme = (hash_name, SignatureAlgorithm.ecdsa)

        elif isinstance(dc_pub, EdDSAKey):
            curve = (dc_pub.curve_name).lower()
            dc_sig_scheme = getattr(SignatureScheme, curve)

    cert_bytes = cert_chain.x509List[0].bytes
    valid_time = int(time.time()) + DC_VALID_TIME
    cred_raw_bytes = Credential.marshal(valid_time,
                                        dc_sig_scheme,
                                        dc_pub_byte)
    cred = Credential(valid_time=valid_time,
                      dc_cert_verify_algorithm=dc_sig_scheme,
                      subject_public_key_info=dc_pub_byte,
                      bytes=cred_raw_bytes)

    bytes_to_sign = DelegatedCredential.compute_certificate_dc_sig_context(
        cert_bytes,
        cred.bytes,
        sig_alg)

    if sig_alg in (SignatureScheme.ed25519,
                SignatureScheme.ed448):
        hashName = "intrinsic"
        padType = None
        saltLen = None
        sig_func = private_key.hashAndSign
        ver_func = private_key.hashAndVerify
    elif sig_alg[1] == SignatureAlgorithm.ecdsa:
        hashName = HashAlgorithm.toRepr(sig_alg[0])
        padType = None
        saltLen = None
        sig_func = private_key.hashAndSign
        ver_func = private_key.hashAndVerify
    elif sig_alg in TLS_1_3_BRAINPOOL_SIG_SCHEMES:
        hashName = SignatureScheme.getHash(scheme)
        padType = None
        saltLen = None
        sig_func = private_key.hashAndSign
        ver_func = private_key.hashAndVerify
    else:
        padType = SignatureScheme.getPadding(scheme)
        hashName = SignatureScheme.getHash(scheme)
        saltLen = getattr(hashlib, hashName)().digest_size
        sig_func = private_key.hashAndSign
        ver_func = private_key.hashAndVerify

    signature = sig_func(bytes_to_sign,
                        padType,
                        hashName,
                        saltLen)
    if not ver_func(signature, bytes_to_sign,
                    padType,
                    hashName,
                    saltLen):
        raise ValueError("Delegated Credential signature failed")

    delegated_credential = DelegatedCredential(cred=cred,
                                                algorithm=sig_alg,
                                                signature=signature)
    return delegated_credential


if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing command")
    elif sys.argv[1] == "client"[:len(sys.argv[1])]:
        clientCmd(sys.argv[2:])
    elif sys.argv[1] == "server"[:len(sys.argv[1])]:
        serverCmd(sys.argv[2:])
    elif sys.argv[1] == "credential"[:len(sys.argv[1])]:
        credential_cmd(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])
