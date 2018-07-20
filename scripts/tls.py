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
import time
import getopt
import binascii
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
from tlslite import __version__
from tlslite.utils.compat import b2a_hex, a2b_hex
from tlslite.utils.dns_utils import is_valid_hostname
from tlslite.utils.cryptomath import getRandomBytes

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
    
    print("")
    print("""Commands:

  server  
    [-k KEY] [-c CERT] [-t TACK] [-v VERIFIERDB] [-d DIR] [-l LABEL] [-L LENGTH]
    [--reqcert] [--param DHFILE] [--psk PSK] [--psk-ident IDENTITY]
    [--psk-sha384] [--ssl3]
    HOST:PORT

  client
    [-k KEY] [-c CERT] [-u USER] [-p PASS] [-l LABEL] [-L LENGTH] [-a ALPN]
    [--psk PSK] [--psk-ident IDENTITY] [--psk-sha384] [--resumption] [--ssl3]
    HOST:PORT

  LABEL - TLS exporter label
  LENGTH - amount of info to export using TLS exporter
  ALPN - name of protocol for ALPN negotiation, can be present multiple times
         in client to specify multiple protocols supported
  DHFILE - file that includes Diffie-Hellman parameters to be used with DHE
           key exchange
  PSK - hex encoded (without starting 0x) shared key to be used for connection
  IDENTITY - name associated with the PSK key
  --ssl3 - enable support for SSLv3
""")
    sys.exit(-1)

def printError(s):
    """Print error message and exit"""
    sys.stderr.write("ERROR: %s\n" % s)
    sys.exit(-1)


def handleArgs(argv, argString, flagsList=[]):
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

    for opt, arg in opts:
        if opt == "-k":
            s = open(arg, "rb").read()
            if sys.version_info[0] >= 3:
                s = str(s, 'utf-8')
            # OpenSSL/m2crypto does not support RSASSA-PSS certificates
            privateKey = parsePEMKey(s, private=True,
                                     implementations=["python"])
        elif opt == "-c":
            s = open(arg, "rb").read()
            if sys.version_info[0] >= 3:
                s = str(s, 'utf-8')
            x509 = X509()
            x509.parse(s)
            cert_chain = X509CertChain([x509])
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
        else:
            assert(False)

    # when no names provided, don't return array
    if not alpn:
        alpn = None
    if (psk and not psk_ident) or (not psk and psk_ident):
        printError("PSK and IDENTITY must be set together")
    if not argv:
        printError("Missing address")
    if len(argv)>1:
        printError("Too many arguments")
    #Split address into hostname/port tuple
    address = argv[0]
    address = address.split(":")
    if len(address) != 2:
        raise SyntaxError("Must specify <host>:<port>")
    address = ( address[0], int(address[1]) )

    # Populate the return list
    retList = [address]
    if "k" in argString:
        retList.append(privateKey)
    if "c" in argString:
        retList.append(cert_chain)
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
    (address, privateKey, cert_chain, username, password, expLabel,
            expLength, alpn, psk, psk_ident, psk_hash, resumption, ssl3) = \
        handleArgs(argv, "kcuplLa", ["psk=", "psk-ident=", "psk-sha384",
                                     "resumption", "ssl3"])
        
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
    
    try:
        start = time.clock()
        if username and password:
            connection.handshakeClientSRP(username, password, 
                settings=settings, serverName=address[0])
        else:
            connection.handshakeClientCert(cert_chain, privateKey,
                settings=settings, serverName=address[0], alpn=alpn)
        stop = time.clock()        
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
    connection.send("GET / HTTP/1.0\r\n\r\n")
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

    print("Received {0} ticket[s]".format(len(connection.tickets)))
    assert connection.tickets is session.tickets

    if not session.tickets:
        return

    if not resumption:
        return

    print("Trying resumption handshake")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(address)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    connection = TLSConnection(sock)

    try:
        start = time.clock()
        connection.handshakeClientCert(serverName=address[0], alpn=alpn,
            session=session)
        stop = time.clock()
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
    (address, privateKey, cert_chain, tacks, verifierDB, directory, reqCert,
            expLabel, expLength, dhparam, psk, psk_ident, psk_hash, ssl3) = \
        handleArgs(argv, "kctbvdlL",
                   ["reqcert", "param=", "psk=",
                    "psk-ident=", "psk-sha384", "ssl3"])


    if (cert_chain and not privateKey) or (not cert_chain and privateKey):
        raise SyntaxError("Must specify CERT and KEY together")
    if tacks and not cert_chain:
        raise SyntaxError("Must specify CERT with Tacks")
    
    print("I am an HTTPS test server, I will listen on %s:%d" % 
            (address[0], address[1]))    
    if directory:
        os.chdir(directory)
    print("Serving files from %s" % os.getcwd())
    
    if cert_chain and privateKey:
        print("Using certificate and private key...")
    if verifierDB:
        print("Using verifier DB...")
    if tacks:
        print("Using Tacks...")
    if reqCert:
        print("Asking for client certificates...")
        
    #############
    sessionCache = SessionCache()
    username = None
    sni = None
    if is_valid_hostname(address[0]):
        sni = address[0]
    settings = HandshakeSettings()
    settings.useExperimentalTackExtension=True
    settings.dhParams = dhparam
    if psk:
        settings.pskConfigs = [(psk_ident, psk, psk_hash)]
    settings.ticketKeys = [getRandomBytes(32)]
    if ssl3:
        settings.minVersion = (3, 0)

    class MySimpleHTTPHandler(SimpleHTTPRequestHandler):
        """Buffer the header and body of HTTP message."""
        wbufsize = -1

    class MyHTTPServer(ThreadingMixIn, TLSSocketServerMixIn, HTTPServer):
        def handshake(self, connection):
            print("About to handshake...")
            activationFlags = 0
            if tacks:
                if len(tacks) == 1:
                    activationFlags = 1
                elif len(tacks) == 2:
                    activationFlags = 3

            try:
                start = time.clock()
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,
                                      1)
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                      struct.pack('ii', 1, 5))
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
                                              sni=sni)
                                              # As an example (does not work here):
                                              #nextProtos=[b"spdy/3", b"spdy/2", b"http/1.1"])
                stop = time.clock()
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

    httpd = MyHTTPServer(address, MySimpleHTTPHandler)
    httpd.serve_forever()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing command")
    elif sys.argv[1] == "client"[:len(sys.argv[1])]:
        clientCmd(sys.argv[2:])
    elif sys.argv[1] == "server"[:len(sys.argv[1])]:
        serverCmd(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])

