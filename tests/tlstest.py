#!/usr/bin/env python

# Authors: 
#   Trevor Perrin
#   Kees Bos - Added tests for XML-RPC
#   Dimitris Moraitis - Anon ciphersuites
#   Marcelo Fernandez - Added test for NPN
#   Martin von Loewis - python 3 port
#   Hubert Kario - several improvements
#   Google - FALLBACK_SCSV test
#   Efthimis Iosifidis - improvemnts of time measurement in Throughput Test
#
#
# See the LICENSE file for legal information regarding use of this file.
from __future__ import print_function
import sys
import os
import os.path
import socket
import time
import timeit
import getopt
from tempfile import mkstemp
try:
    from BaseHTTPServer import HTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler
except ImportError:
    from http.server import HTTPServer, SimpleHTTPRequestHandler

from tlslite import TLSConnection, Fault, HandshakeSettings, \
    X509, X509CertChain, IMAP4_TLS, VerifierDB, Session, SessionCache, \
    parsePEMKey, constants, \
    AlertDescription, HTTPTLSConnection, TLSSocketServerMixIn, \
    POP3_TLS, m2cryptoLoaded, pycryptoLoaded, gmpyLoaded, tackpyLoaded, \
    Checker, __version__

from tlslite.errors import *
from tlslite.utils.cryptomath import prngName, getRandomBytes
try:
    import xmlrpclib
except ImportError:
    # Python 3
    from xmlrpc import client as xmlrpclib
import ssl
from tlslite import *

try:
    from tack.structures.Tack import Tack
    
except ImportError:
    pass

def printUsage(s=None):
    if m2cryptoLoaded:
        crypto = "M2Crypto/OpenSSL"
    else:
        crypto = "Python crypto"        
    if s:
        print("ERROR: %s" % s)
    print("""\ntls.py version %s (using %s)  

Commands:
  server HOST:PORT DIRECTORY

  client HOST:PORT DIRECTORY
""" % (__version__, crypto))
    sys.exit(-1)
    

def testConnClient(conn):
    b1 = os.urandom(1)
    b10 = os.urandom(10)
    b100 = os.urandom(100)
    b1000 = os.urandom(1000)
    conn.write(b1)
    conn.write(b10)
    conn.write(b100)
    conn.write(b1000)
    assert(conn.read(min=1, max=1) == b1)
    assert(conn.read(min=10, max=10) == b10)
    assert(conn.read(min=100, max=100) == b100)
    assert(conn.read(min=1000, max=1000) == b1000)

def clientTestCmd(argv):
    
    address = argv[0]
    dir = argv[1]    

    #Split address into hostname/port tuple
    address = address.split(":")
    address = ( address[0], int(address[1]) )

    #open synchronisation FIFO
    synchro = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    synchro.settimeout(60)
    synchro.connect((address[0], address[1]-1))

    def connect():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect(address)
        c = TLSConnection(sock)
        return c

    test_no = 0

    badFault = False

    print("Test {0} - anonymous handshake".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientAnonymous(settings=settings)
    testConnClient(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good X509 (plus SNI)".format(test_no))
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(serverName=address[0])
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(connection.session.cipherSuite in constants.CipherSuite.aeadSuites)
    assert(connection.encryptThenMAC == False)
    assert connection.session.appProto is None
    connection.close()

    test_no += 1

    print("Test {0} - good X509 TLSv1.2 (plus ALPN)".format(test_no))
    synchro.recv(1)
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection = connect()
    connection.handshakeClientCert(serverName=address[0],
                                   alpn=[b'http/1.1'],
                                   settings=settings)
    testConnClient(connection)
    assert isinstance(connection.session.serverCertChain, X509CertChain)
    assert connection.session.serverName == address[0]
    assert connection.session.cipherSuite in constants.CipherSuite.aeadSuites
    assert connection.encryptThenMAC == False
    assert connection.session.appProto == b'http/1.1'
    connection.close()

    test_no += 1

    print("Test {0} - good X509 TLSv1.3 (plus ALPN)".format(test_no))
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(serverName=address[0],
                                   alpn=[b'http/1.1'])
    testConnClient(connection)
    assert isinstance(connection.session.serverCertChain, X509CertChain)
    assert connection.session.serverName == address[0]
    assert connection.session.cipherSuite in constants.CipherSuite.aeadSuites
    assert connection.encryptThenMAC == False
    assert connection.session.appProto == b'http/1.1'
    connection.close()

    test_no += 1

    print("Test {0} - good X.509/w RSA-PSS cert".format(test_no))
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(serverName=address[0])
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(connection.session.cipherSuite in constants.CipherSuite.aeadSuites)
    assert(connection.encryptThenMAC == False)
    connection.close()

    test_no += 1

    print("Test {0} - good X.509/w RSA-PSS sig".format(test_no))
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(serverName=address[0])
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(connection.session.cipherSuite in constants.CipherSuite.aeadSuites)
    assert(connection.encryptThenMAC == False)
    connection.close()

    test_no += 1

    print("Test {0} - good X509, SSLv3".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeClientCert(settings=settings)
    testConnClient(connection)    
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    test_no += 1

    print("Test {0} - good X.509, mismatched key_share".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.keyShares = ["x25519"]
    connection.handshakeClientCert(settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    test_no += 1

    print("Test {0} - good X509, RC4-MD5".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.macNames = ["md5"]
    settings.cipherNames = ["rc4"]
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(settings=settings)
    testConnClient(connection)    
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.cipherSuite == constants.CipherSuite.TLS_RSA_WITH_RC4_128_MD5)
    assert(connection.encryptThenMAC == False)
    connection.close()

    if tackpyLoaded:

        settings = HandshakeSettings()
        settings.useExperimentalTackExtension = True
        settings.maxVersion = (3, 3)

        test_no += 1

        print("Test {0} - good X.509, TACK".format(test_no))
        synchro.recv(1)
        connection = connect()
        connection.handshakeClientCert(settings=settings)
        assert(connection.session.tackExt.tacks[0].getTackId() == "5lcbe.eyweo.yxuan.rw6xd.jtoz7")
        assert(connection.session.tackExt.activation_flags == 1)        
        testConnClient(connection)    
        connection.close()

        test_no += 1

        print("Test {0} - good X.509, TACK unrelated to cert chain".\
              format(test_no))
        synchro.recv(1)
        connection = connect()
        try:
            connection.handshakeClientCert(settings=settings)
            assert(False)
        except TLSLocalAlert as alert:
            if alert.description != AlertDescription.illegal_parameter:
                raise        
        connection.close()
    else:
        test_no += 1

        print("Test {0} - good X.509, TACK...skipped (no tackpy)".\
              format(test_no))

        test_no += 1

        print("Test {0} - good X.509, TACK unrelated to cert chain...skipped"
              " (no tackpy)".\
              format(test_no))

    test_no += 1

    print("Test {0} - good PSK".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.pskConfigs = [(b'test', b'\x00secret', 'sha384')]
    connection.handshakeClientCert(settings=settings)
    assert connection.session.serverCertChain is None
    assert connection.ecdhCurve is not None
    testConnClient(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good PSK, no DH".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.psk_modes = ["psk_ke"]
    settings.pskConfigs = [(b'test', b'\x00secret', 'sha384')]
    connection.handshakeClientCert(settings=settings)
    assert connection.session.serverCertChain is None
    assert connection.ecdhCurve is None
    testConnClient(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good PSK, no DH, no cert".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.psk_modes = ["psk_ke"]
    settings.pskConfigs = [(b'test', b'\x00secret', 'sha384')]
    connection.handshakeClientCert(settings=settings)
    assert connection.session.serverCertChain is None
    assert connection.ecdhCurve is None
    testConnClient(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good SRP (db)".format(test_no))
    print("client {0} - waiting for synchro".format(time.time()))
    try:
        synchro.recv(1)
    except Exception:
        print("client {0} - wait abort".format(time.time()))
        raise
    print("client {0} - synchro received".format(time.time()))
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientSRP("test", "password", settings=settings)
    testConnClient(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good SRP".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientSRP("test", "password", settings=settings)
    testConnClient(connection)
    connection.close()

    test_no += 1

    print("Test {0} - SRP faults".format(test_no))
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        synchro.recv(1)
        connection = connect()
        connection.fault = fault
        settings = HandshakeSettings()
        settings.maxVersion = (3, 3)
        try:
            connection.handshakeClientSRP("test", "password",
                                          settings=settings)
            print("  Good Fault %s" % (Fault.faultNames[fault]))
        except TLSFaultError as e:
            print("  BAD FAULT %s: %s" % (Fault.faultNames[fault], str(e)))
            badFault = True

    test_no += 1

    print("Test {0} - good SRP: with X.509 certificate, TLSv1.0".format(test_no))
    settings = HandshakeSettings()
    settings.minVersion = (3,1)
    settings.maxVersion = (3,1)    
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientSRP("test", "password", settings=settings)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    testConnClient(connection)
    connection.close()

    test_no += 1

    print("Test {0} - X.509 with SRP faults".format(test_no))
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        synchro.recv(1)
        connection = connect()
        connection.fault = fault
        settings = HandshakeSettings()
        settings.maxVersion = (3, 3)
        try:
            connection.handshakeClientSRP("test", "password",
                                          settings=settings)
            print("  Good Fault %s" % (Fault.faultNames[fault]))
        except TLSFaultError as e:
            print("  BAD FAULT %s: %s" % (Fault.faultNames[fault], str(e)))
            badFault = True

    test_no += 1

    print("Test {0} - X.509 faults".format(test_no))
    for fault in Fault.clientNoAuthFaults + Fault.genericFaults:
        synchro.recv(1)
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeClientCert()
            print("  Good Fault %s" % (Fault.faultNames[fault]))
        except TLSFaultError as e:
            print("  BAD FAULT %s: %s" % (Fault.faultNames[fault], str(e)))
            badFault = True

    test_no += 1

    print("Test {0} - good mutual X509".format(test_no))
    x509Cert = X509().parse(open(os.path.join(dir, "clientX509Cert.pem")).read())
    x509Chain = X509CertChain([x509Cert])
    s = open(os.path.join(dir, "clientX509Key.pem")).read()
    x509Key = parsePEMKey(s, private=True)

    synchro.recv(1)
    connection = connect()
    # TODO add client certificate support in TLS 1.3
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(x509Chain, x509Key, settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    test_no += 1

    print("Test {0} - good mutual X509, TLSv1.1".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,2)
    settings.maxVersion = (3,2)
    connection.handshakeClientCert(x509Chain, x509Key, settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    test_no += 1

    print("Test {0} - good mutual X509, SSLv3".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeClientCert(x509Chain, x509Key, settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    test_no += 1

    print("Test {0} - mutual X.509 faults".format(test_no))
    for fault in Fault.clientCertFaults + Fault.genericFaults:
        synchro.recv(1)
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeClientCert(x509Chain, x509Key)
            print("  Good Fault %s" % (Fault.faultNames[fault]))
        except TLSFaultError as e:
            print("  BAD FAULT %s: %s" % (Fault.faultNames[fault], str(e)))
            badFault = True

    test_no += 1

    print("Test {0} - good SRP, prepare to resume... (plus SNI)".\
          format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientSRP("test", "password", serverName=address[0],
                                  settings=settings)
    testConnClient(connection)
    connection.close()
    session = connection.session

    test_no += 1

    print("Test {0} - resumption (plus SNI)".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientSRP("test", "garbage", serverName=address[0], 
                                  session=session, settings=settings)
    testConnClient(connection)
    #Don't close! -- see below

    test_no += 1

    print("Test {0} - invalidated resumption (plus SNI)".format(test_no))
    synchro.recv(1)
    connection.sock.close() #Close the socket without a close_notify!
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    try:
        connection.handshakeClientSRP("test", "garbage",
                                      serverName=address[0],
                                      session=session, settings=settings)
        assert(False)
    except TLSRemoteAlert as alert:
        if alert.description != AlertDescription.bad_record_mac:
            raise
    connection.close()

    test_no += 1

    print("Test {0} - HTTPS test X.509".format(test_no))
    address = address[0], address[1]+1
    if hasattr(socket, "timeout"):
        timeoutEx = socket.timeout
    else:
        timeoutEx = socket.error
    while 1:
        try:
            htmlBody = bytearray(open(os.path.join(dir, "index.html")).read(), "utf-8")
            fingerprint = None
            for y in range(2):
                checker =Checker(x509Fingerprint=fingerprint)
                h = HTTPTLSConnection(\
                        address[0], address[1], checker=checker)
                for x in range(3):
                    synchro.recv(1)
                    h.request("GET", "/index.html")
                    r = h.getresponse()
                    assert(r.status == 200)
                    b = bytearray(r.read())
                    assert(b == htmlBody)
                fingerprint = h.tlsSession.serverCertChain.getFingerprint()
                assert(fingerprint)
            break
        except timeoutEx:
            print("timeout, retrying...")
            pass

    address = address[0], address[1]+1

    implementations = []
    if m2cryptoLoaded:
        implementations.append("openssl")
    if pycryptoLoaded:
        implementations.append("pycrypto")
    implementations.append("python")

    test_no += 1

    print("Test {0} - different ciphers, TLSv1.0".format(test_no))
    for implementation in implementations:
        for cipher in ["aes128", "aes256", "rc4"]:

            test_no += 1

            print("Test {0}:".format(test_no), end=' ')
            synchro.recv(1)
            connection = connect()

            settings = HandshakeSettings()
            settings.cipherNames = [cipher]
            settings.cipherImplementations = [implementation, "python"]
            settings.minVersion = (3,1)
            settings.maxVersion = (3,1)            
            connection.handshakeClientCert(settings=settings)
            testConnClient(connection)
            print("%s %s" % (connection.getCipherName(), connection.getCipherImplementation()))
            connection.close()

    test_no += 1

    print("Test {0} - throughput test".format(test_no))
    for implementation in implementations:
        for cipher in ["aes128gcm", "aes256gcm", "aes128", "aes256", "3des",
                       "rc4", "chacha20-poly1305_draft00",
                       "chacha20-poly1305"]:
            # skip tests with implementations that don't support them
            if cipher == "3des" and implementation not in ("openssl",
                                                           "pycrypto"):
                continue
            if cipher in ("aes128gcm", "aes256gcm") and \
                    implementation not in ("pycrypto",
                                           "python"):
                continue
            if cipher in ("chacha20-poly1305_draft00", "chacha20-poly1305") \
                    and implementation not in ("python", ):
                continue

            test_no += 1

            print("Test {0}:".format(test_no), end=' ')
            synchro.recv(1)
            connection = connect()

            settings = HandshakeSettings()
            settings.cipherNames = [cipher]
            settings.cipherImplementations = [implementation, "python"]
            if cipher not in ("aes128gcm", "aes256gcm", "chacha20-poly1305"):
                settings.maxVersion = (3, 3)
            connection.handshakeClientCert(settings=settings)
            print("%s %s:" % (connection.getCipherName(), connection.getCipherImplementation()), end=' ')

            startTime = timeit.default_timer()
            connection.write(b"hello"*10000)
            h = connection.read(min=50000, max=50000)
            stopTime = timeit.default_timer()
            sizeofdata = len(h)*2
            if stopTime-startTime:
                print("100K exchanged at rate of %d bytes/sec" % int(sizeofdata/(stopTime-startTime)))
            else:
                print("100K exchanged very fast")

            assert(h == b"hello"*10000)
            connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Client Negotiation".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(nextProtos=[b"http/1.1"], settings=settings)
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'http/1.1')
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Client Negotiation".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(nextProtos=[b"spdy/2", b"http/1.1"],
                                   settings=settings)
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'spdy/2')
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Client Negotiation".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(nextProtos=[b"spdy/2", b"http/1.1"],
                                   settings=settings)
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'spdy/2')
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Client Negotiation".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(nextProtos=[b"spdy/3", b"spdy/2",
                                               b"http/1.1"],
                                   settings=settings)
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'spdy/2')
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Client Negotiation".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(nextProtos=[b"spdy/3", b"spdy/2",
                                               b"http/1.1"],
                                   settings=settings)
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'spdy/3')
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Client Negotiation".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(nextProtos=[b"http/1.1"], settings=settings)
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'http/1.1')
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Client Negotiation".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(nextProtos=[b"spdy/2", b"http/1.1"],
                                   settings=settings)
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'spdy/2')
    connection.close()

    test_no += 1

    print("Test {0} - FALLBACK_SCSV".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.sendFallbackSCSV = True
    settings.maxVersion = (3, 3)
    # TODO fix FALLBACK_SCSV with TLS 1.3
    connection.handshakeClientCert(settings=settings)
    testConnClient(connection)
    connection.close()

    test_no += 1

    print("Test {0} - FALLBACK_SCSV".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.sendFallbackSCSV = True
    settings.maxVersion = (3, 2)
    try:
        connection.handshakeClientCert(settings=settings)
        assert()
    except TLSRemoteAlert as alert:
        if alert.description != AlertDescription.inappropriate_fallback:
            raise
    connection.close()

    test_no += 1

    print("Test {0} - no EtM server side".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.macNames.remove("aead")
    settings.maxVersion = (3, 3)
    assert(settings.useEncryptThenMAC)
    connection.handshakeClientCert(serverName=address[0], settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(not connection.encryptThenMAC)
    connection.close()

    test_no += 1

    print("Test {0} - no EtM client side".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.macNames.remove("aead")
    settings.useEncryptThenMAC = False
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(serverName=address[0], settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(not connection.encryptThenMAC)
    connection.close()

    test_no += 1

    print("Test {0} - resumption with EtM".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.macNames.remove("aead")
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(serverName=address[0], settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(not connection.resumed)
    assert(connection.encryptThenMAC)
    connection.close()
    session = connection.session

    # resume
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(serverName=address[0], session=session,
                                   settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(connection.resumed)
    assert(connection.encryptThenMAC)
    connection.close()

    test_no += 1

    print("Test {0} - resumption with no EtM in 2nd handshake".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.macNames.remove("aead")
    settings.maxVersion = (3, 3)
    connection.handshakeClientCert(serverName=address[0], settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(not connection.resumed)
    assert(connection.encryptThenMAC)
    connection.close()
    session = connection.session

    # resume
    synchro.recv(1)
    settings = HandshakeSettings()
    settings.useEncryptThenMAC = False
    settings.macNames.remove("aead")
    settings.maxVersion = (3, 3)
    connection = connect()
    try:
        connection.handshakeClientCert(serverName=address[0], session=session,
                                       settings=settings)
    except TLSRemoteAlert as e:
        assert(str(e) == "handshake_failure")
    else:
        raise AssertionError("No exception raised")
    connection.close()

    test_no += 1

    print("Test {0} - resumption in TLSv1.3".format(test_no))
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    # force HRR
    settings.keyShares = []
    connection.handshakeClientCert(serverName=address[0], settings=settings)
    testConnClient(connection)
    assert isinstance(connection.session.serverCertChain, X509CertChain)
    assert connection.session.serverName == address[0]
    assert not connection.resumed
    assert connection.session.tickets
    connection.close()
    session = connection.session

    # resume
    synchro.recv(1)
    settings = HandshakeSettings()
    settings.keyShares = []
    connection = connect()
    connection.handshakeClientCert(serverName=address[0], session=session,
                                   settings=settings)
    testConnClient(connection)
    assert connection.resumed
    connection.close()

    test_no += 1

    print("Test {0} - Heartbeat extension response callback in TLSv1.2".format(test_no))
    heartbeat_payload = os.urandom(50)
    def heartbeat_response_check(message):
        global received_payload
        received_payload = message.payload
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    settings.heartbeat_response_callback = heartbeat_response_check
    connection.handshakeClientCert(serverName=address[0], settings=settings)
    connection.send_heartbeat_request(heartbeat_payload, 16)
    testConnClient(connection)
    testConnClient(connection)
    connection.close()
    assert heartbeat_payload == received_payload

    test_no += 1

    print("Test {0} - Heartbeat extension in TLSv1.3".format(test_no))
    heartbeat_payload = os.urandom(50)
    def heartbeat_response_check(message):
        global received_payload
        received_payload = message.payload
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 4)
    settings.heartbeat_response_callback = heartbeat_response_check
    connection.handshakeClientCert(serverName=address[0], settings=settings)
    connection.send_heartbeat_request(heartbeat_payload, 16)
    testConnClient(connection)
    testConnClient(connection)
    connection.close()
    assert heartbeat_payload == received_payload

    test_no += 1

    print('Test {0} - good standard XMLRPC https client'.format(test_no))
    address = address[0], address[1]+1
    synchro.recv(1)
    try:
        # python 2.7.9 introduced certificate verification (context option)
        # python 3.4.2 doesn't have it though
        context = ssl.create_default_context(\
                cafile=os.path.join(dir, "serverX509Cert.pem"))
        server = xmlrpclib.Server('https://%s:%s' % address, context=context)
    except (TypeError, AttributeError):
        server = xmlrpclib.Server('https://%s:%s' % address)

    synchro.recv(1)
    assert server.add(1,2) == 3
    synchro.recv(1)
    assert server.pow(2,4) == 16

    test_no += 1

    print('Test {0} - good tlslite XMLRPC client'.format(test_no))
    transport = XMLRPCTransport(ignoreAbruptClose=True)
    server = xmlrpclib.Server('https://%s:%s' % address, transport)
    synchro.recv(1)
    assert server.add(1,2) == 3
    synchro.recv(1)
    assert server.pow(2,4) == 16

    test_no += 1

    print('Test {0} - good XMLRPC ignored protocol'.format(test_no))
    server = xmlrpclib.Server('http://%s:%s' % address, transport)
    synchro.recv(1)
    assert server.add(1,2) == 3
    synchro.recv(1)
    assert server.pow(2,4) == 16

    test_no += 1

    print("Test {0} - Internet servers test".format(test_no))
    try:
        i = IMAP4_TLS("cyrus.andrew.cmu.edu")
        i.login("anonymous", "anonymous@anonymous.net")
        i.logout()

        test_no += 1

        print("Test {0}: IMAP4 good".format(test_no))
        p = POP3_TLS("pop.gmail.com")
        p.quit()

        test_no += 1

        print("Test {0}: POP3 good".format(test_no))
    except (socket.error, socket.timeout) as e:
        print("Non-critical error: socket error trying to reach internet server: ", e)   

    synchro.close()

    if not badFault:
        print("Test succeeded, {0} good".format(test_no))
    else:
        print("Test failed")



def testConnServer(connection):
    count = 0
    while 1:
        s = connection.read()
        count += len(s)
        if len(s) == 0:
            break
        connection.write(s)
        if count == 1111:
            break

def serverTestCmd(argv):

    address = argv[0]
    dir = argv[1]
    
    #Split address into hostname/port tuple
    address = address.split(":")
    address = ( address[0], int(address[1]) )

    #Create synchronisation FIFO
    synchroSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    synchroSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    synchroSocket.bind((address[0], address[1]-1))
    synchroSocket.listen(2)

    #Connect to server
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(address)
    lsock.listen(5)

    # following is blocking until the other side doesn't open
    synchro = synchroSocket.accept()[0]

    def connect():
        s = lsock.accept()[0]
        s.settimeout(15)
        return TLSConnection(s)

    x509Cert = X509().parse(open(os.path.join(dir, "serverX509Cert.pem")).read())
    x509Chain = X509CertChain([x509Cert])
    s = open(os.path.join(dir, "serverX509Key.pem")).read()
    x509Key = parsePEMKey(s, private=True)

    with open(os.path.join(dir, "serverRSAPSSSigCert.pem")) as f:
        x509CertRSAPSSSig = X509().parse(f.read())
    x509ChainRSAPSSSig = X509CertChain([x509CertRSAPSSSig])
    with open(os.path.join(dir, "serverRSAPSSSigKey.pem")) as f:
        x509KeyRSAPSSSig = parsePEMKey(f.read(), private=True)

    with open(os.path.join(dir, "serverRSAPSSCert.pem")) as f:
        x509CertRSAPSS = X509().parse(f.read())
    x509ChainRSAPSS = X509CertChain([x509CertRSAPSS])
    assert x509CertRSAPSS.certAlg == "rsa-pss"
    with open(os.path.join(dir, "serverRSAPSSKey.pem")) as f:
        x509KeyRSAPSS = parsePEMKey(f.read(), private=True,
                                    implementations=["python"])

    test_no = 0

    print("Test {0} - Anonymous server handshake".format(test_no))
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(anon=True)
    testConnServer(connection)    
    connection.close()

    test_no += 1

    print("Test {0} - good X.509 (plus SNI)".format(test_no))
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
    assert connection.session.serverName == address[0]
    assert connection.extendedMasterSecret
    assert connection.session.appProto is None
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good X.509 TLSv1.2 (plus ALPN)".format(test_no))
    synchro.send(b'R')
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               alpn=[b'http/1.1', b'http/1.0'],
                               settings=settings)
    assert connection.session.serverName == address[0]
    assert connection.extendedMasterSecret
    assert connection.session.appProto == b'http/1.1'
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good X.509 TLSv1.3 (plus ALPN)".format(test_no))
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               alpn=[b'http/1.1', b'http/1.0'])
    assert connection.session.serverName == address[0]
    assert connection.extendedMasterSecret
    assert connection.session.appProto == b'http/1.1'
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good X.509/w RSA-PSS sig".format(test_no))
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509ChainRSAPSSSig,
                               privateKey=x509KeyRSAPSSSig)
    assert(connection.extendedMasterSecret)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good X.509/w RSA-PSS cert".format(test_no))
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509ChainRSAPSS,
                               privateKey=x509KeyRSAPSS)
    assert(connection.session.serverName == address[0])
    assert(connection.extendedMasterSecret)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good X.509, SSL v3".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, settings=settings)
    assert(not connection.extendedMasterSecret)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good X.509, mismatched key_share".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.eccCurves = ["secp256r1", "secp384r1", "secp521r1"]
    settings.keyShares = ["secp256r1"]
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, settings=settings)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good X.509, RC4-MD5".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.macNames = ["sha", "md5"]
    settings.cipherNames = ["rc4"]
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, settings=settings)
    testConnServer(connection)
    connection.close()

    if tackpyLoaded:
        tack = Tack.createFromPem(
            open(os.path.join(dir, "TACK1.pem"), "rU").read())
        tackUnrelated = Tack.createFromPem(
            open(os.path.join(dir, "TACKunrelated.pem"), "rU").read())

        settings = HandshakeSettings()
        settings.useExperimentalTackExtension = True

        test_no += 1

        print("Test {0} - good X.509, TACK".format(test_no))
        synchro.send(b'R')
        connection = connect()
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
            tacks=[tack], activationFlags=1, settings=settings)
        testConnServer(connection)
        connection.close()

        test_no += 1

        print("Test {0} - good X.509, TACK unrelated to cert chain".\
              format(test_no))
        synchro.send(b'R')
        connection = connect()
        try:
            connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                tacks=[tackUnrelated], settings=settings)
            assert(False)
        except TLSRemoteAlert as alert:
            if alert.description != AlertDescription.illegal_parameter:
                raise
    else:
        test_no += 1

        print("Test {0} - good X.509, TACK...skipped (no tackpy)".\
              format(test_no))

        test_no += 1

        print("Test {0} - good X.509, TACK unrelated to cert chain"
              "...skipped (no tackpy)".format(test_no))

    test_no += 1

    print("Test {0} - good PSK".format(test_no))
    synchro.send(b'R')
    settings = HandshakeSettings()
    settings.pskConfigs = [(b'test', b'\x00secret', 'sha384')]
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               settings=settings)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good PSK, no DH".format(test_no))
    synchro.send(b'R')
    settings = HandshakeSettings()
    settings.psk_modes = ["psk_ke"]
    settings.pskConfigs = [(b'test', b'\x00secret', 'sha384')]
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               settings=settings)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good PSK, no DH, no cert".format(test_no))
    synchro.send(b'R')
    settings = HandshakeSettings()
    settings.psk_modes = ["psk_ke"]
    settings.pskConfigs = [(b'test', b'\x00secret', 'sha384')]
    connection = connect()
    connection.handshakeServer(settings=settings)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - good SRP (db)".format(test_no))
    try:
        import logging
        logging.basicConfig(level=logging.DEBUG)
        (db_file, db_name) = mkstemp()
        print("server {0} - tmp file created".format(time.time()))
        os.close(db_file)
        print("server {0} - tmp file closed".format(time.time()))
        # this is race'y but the interface dbm interface is stupid like that...
        os.remove(db_name)
        print("server {0} - tmp file removed".format(time.time()))
        verifierDB = VerifierDB(db_name)
        print("server {0} - verifier initialised".format(time.time()))
        verifierDB.create()
        print("server {0} - verifier created".format(time.time()))
        entry = VerifierDB.makeVerifier("test", "password", 1536)
        print("server {0} - entry created".format(time.time()))
        verifierDB[b"test"] = entry
        print("server {0} - entry added".format(time.time()))

        synchro.send(b'R')
        print("server {0} - synchro sent".format(time.time()))
        connection = connect()
        connection.handshakeServer(verifierDB=verifierDB)
        testConnServer(connection)
        connection.close()
    finally:
        try:
            os.remove(db_name)
        except FileNotFoundError:
            # dbm module may create files with different names depending on
            # platform
            os.remove(db_name + ".dat")

    test_no += 1

    print("Test {0} - good SRP".format(test_no))
    verifierDB = VerifierDB()
    verifierDB.create()
    entry = VerifierDB.makeVerifier("test", "password", 1536)
    verifierDB[b"test"] = entry

    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - SRP faults".format(test_no))
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        synchro.send(b'R')
        connection = connect()
        connection.fault = fault
        connection.handshakeServer(verifierDB=verifierDB)
        connection.close()

    test_no += 1

    print("Test {0} - good SRP: with X.509 cert".format(test_no))
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB, \
                               certChain=x509Chain, privateKey=x509Key)
    testConnServer(connection)    
    connection.close()

    test_no += 1

    print("Test {0} - X.509 with SRP faults".format(test_no))
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        synchro.send(b'R')
        connection = connect()
        connection.fault = fault
        connection.handshakeServer(verifierDB=verifierDB, \
                                   certChain=x509Chain, privateKey=x509Key)
        connection.close()

    test_no += 1

    print("Test {0} - X.509 faults".format(test_no))
    for fault in Fault.clientNoAuthFaults + Fault.genericFaults:
        synchro.send(b'R')
        connection = connect()
        connection.fault = fault
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
        connection.close()

    test_no += 1

    print("Test {0} - good mutual X.509".format(test_no))
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, reqCert=True)
    testConnServer(connection)
    assert(isinstance(connection.session.clientCertChain, X509CertChain))
    connection.close()

    test_no += 1

    print("Test {0} - good mutual X.509, TLSv1.1".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,2)
    settings.maxVersion = (3,2)
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, reqCert=True, settings=settings)
    testConnServer(connection)
    assert(isinstance(connection.session.clientCertChain, X509CertChain))
    connection.close()

    test_no += 1

    print("Test {0} - good mutual X.509, SSLv3".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, reqCert=True, settings=settings)
    testConnServer(connection)
    assert(isinstance(connection.session.clientCertChain, X509CertChain))
    connection.close()

    test_no += 1

    print("Test {0} - mutual X.509 faults".format(test_no))
    for fault in Fault.clientCertFaults + Fault.genericFaults:
        synchro.send(b'R')
        connection = connect()
        connection.fault = fault
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, reqCert=True)
        connection.close()

    test_no += 1

    print("Test {0} - good SRP, prepare to resume".format(test_no))
    synchro.send(b'R')
    sessionCache = SessionCache()
    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB, sessionCache=sessionCache)
    assert(connection.session.serverName == address[0])    
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - resumption".format(test_no))
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB, sessionCache=sessionCache)
    assert(connection.session.serverName == address[0])
    testConnServer(connection)    
    #Don't close! -- see next test

    test_no += 1

    print("Test {0} - invalidated resumption".format(test_no))
    synchro.send(b'R')
    try:
        connection.read(min=1, max=1)
        assert() #Client is going to close the socket without a close_notify
    except TLSAbruptCloseError as e:
        pass
    synchro.send(b'R')
    connection = connect()
    try:
        connection.handshakeServer(verifierDB=verifierDB, sessionCache=sessionCache)
    except TLSLocalAlert as alert:
        if alert.description != AlertDescription.bad_record_mac:
            raise
    connection.close()

    test_no += 1

    print("Test {0} - HTTPS test X.509".format(test_no))

    #Close the current listening socket
    lsock.close()

    #Create and run an HTTP Server using TLSSocketServerMixIn
    class MyHTTPServer(TLSSocketServerMixIn,
                       HTTPServer):
        def handshake(self, tlsConnection):
                tlsConnection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
                return True
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            HTTPServer.server_bind(self)
    cd = os.getcwd()
    os.chdir(dir)
    address = address[0], address[1]+1
    httpd = MyHTTPServer(address, SimpleHTTPRequestHandler)
    for x in range(6):
        synchro.send(b'R')
        httpd.handle_request()
    httpd.server_close()
    cd = os.chdir(cd)

    #Re-connect the listening socket
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    address = address[0], address[1]+1
    lsock.bind(address)
    lsock.listen(5)

    implementations = []
    if m2cryptoLoaded:
        implementations.append("openssl")
    if pycryptoLoaded:
        implementations.append("pycrypto")
    implementations.append("python")

    test_no += 1

    print("Test {0} - different ciphers".format(test_no))
    for implementation in ["python"] * len(implementations):
        for cipher in ["aes128", "aes256", "rc4"]:

            test_no += 1

            print("Test {0}:".format(test_no), end=' ')
            synchro.send(b'R')
            connection = connect()

            settings = HandshakeSettings()
            settings.cipherNames = [cipher]
            settings.cipherImplementations = [implementation, "python"]

            connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                                        settings=settings)
            print(connection.getCipherName(), connection.getCipherImplementation())
            testConnServer(connection)
            connection.close()

    test_no += 1

    print("Test {0} - throughput test".format(test_no))
    for implementation in implementations:
        for cipher in ["aes128gcm", "aes256gcm", "aes128", "aes256", "3des",
                       "rc4", "chacha20-poly1305_draft00",
                       "chacha20-poly1305"]:
            # skip tests with implementations that don't support them
            if cipher == "3des" and implementation not in ("openssl",
                                                           "pycrypto"):
                continue
            if cipher in ("aes128gcm", "aes256gcm") and \
                    implementation not in ("pycrypto",
                                           "python"):
                continue
            if cipher in ("chacha20-poly1305_draft00", "chacha20-poly1305") \
                    and implementation not in ("python", ):
                continue

            test_no += 1

            print("Test {0}:".format(test_no), end=' ')
            synchro.send(b'R')
            connection = connect()

            settings = HandshakeSettings()
            settings.cipherNames = [cipher]
            settings.cipherImplementations = [implementation, "python"]

            connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                                        settings=settings)
            print(connection.getCipherName(), connection.getCipherImplementation())
            h = connection.read(min=50000, max=50000)
            assert(h == b"hello"*10000)
            connection.write(h)
            connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Server Negotiation".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"http/1.1"])
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Server Negotiation".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"spdy/2", b"http/1.1"])
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Server Negotiation".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"http/1.1", b"spdy/2"])
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Server Negotiation".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"spdy/2", b"http/1.1"])
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Server Negotiation".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"http/1.1", b"spdy/2", b"spdy/3"])
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Server Negotiation".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"spdy/3", b"spdy/2"])
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - Next-Protocol Server Negotiation".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[])
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - FALLBACK_SCSV".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    # TODO fix FALLBACK with TLS1.3
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               settings=settings)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - FALLBACK_SCSV".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    # TODO fix FALLBACK with TLS1.3
    settings.maxVersion = (3, 3)
    try:
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                                   settings=settings)
        assert()
    except TLSLocalAlert as alert:
        if alert.description != AlertDescription.inappropriate_fallback:
            raise
    connection.close()

    test_no += 1

    print("Test {0} - no EtM server side".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.useEncryptThenMAC = False
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               settings=settings)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - no EtM client side".format(test_no))
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - resumption with EtM".format(test_no))
    synchro.send(b'R')
    sessionCache = SessionCache()
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               sessionCache=sessionCache)
    testConnServer(connection)
    connection.close()

    # resume
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               sessionCache=sessionCache)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - resumption with no EtM in 2nd handshake".format(test_no))
    synchro.send(b'R')
    sessionCache = SessionCache()
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               sessionCache=sessionCache)
    testConnServer(connection)
    connection.close()

    # resume
    synchro.send(b'R')
    connection = connect()
    try:
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                                   sessionCache=sessionCache)
    except TLSLocalAlert as e:
        assert(str(e) == "handshake_failure")
    else:
        raise AssertionError("no exception raised")
    connection.close()

    test_no += 1

    print("Test {0} - resumption in TLSv1.3".format(test_no))
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.ticketKeys = [getRandomBytes(32)]
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               settings=settings)
    testConnServer(connection)
    connection.close()

    # resume
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               settings=settings)
    testConnServer(connection)
    connection.close()

    test_no += 1

    print("Test {0} - Heartbeat extension response callback in TLSv1.2".format(test_no))
    heartbeat_payload = os.urandom(50)
    def heartbeat_response_check(message):
        global received_payload
        received_payload = message.payload
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 3)
    settings.heartbeat_response_callback = heartbeat_response_check
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               settings=settings)
    connection.send_heartbeat_request(heartbeat_payload, 16)
    testConnServer(connection)
    testConnServer(connection)
    connection.close()
    assert heartbeat_payload == received_payload

    test_no += 1

    print("Test {0} - Heartbeat extension in TLSv1.3".format(test_no))
    heartbeat_payload = os.urandom(50)
    def heartbeat_response_check(message):
        global received_payload
        received_payload = message.payload
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.maxVersion = (3, 4)
    settings.heartbeat_response_callback = heartbeat_response_check
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               settings=settings)
    connection.send_heartbeat_request(heartbeat_payload, 16)
    testConnServer(connection)
    testConnServer(connection)
    connection.close()
    assert heartbeat_payload == received_payload

    test_no += 1

    print("Tests {0}-{1} - XMLRPXC server".format(test_no, test_no + 2))
    test_no += 2

    address = address[0], address[1]+1
    class Server(TLSXMLRPCServer):

        def handshake(self, tlsConnection):
          try:
              tlsConnection.handshakeServer(certChain=x509Chain,
                                            privateKey=x509Key,
                                            sessionCache=sessionCache)
              tlsConnection.ignoreAbruptClose = True
              return True
          except TLSError as error:
              print("Handshake failure:", str(error))
              return False

    class MyFuncs:
        def pow(self, x, y): return pow(x, y)
        def add(self, x, y): return x + y

    server = Server(address)
    server.register_instance(MyFuncs())
    synchro.send(b'R')
    #sa = server.socket.getsockname()
    #print "Serving HTTPS on", sa[0], "port", sa[1]
    for i in range(6):
        synchro.send(b'R')
        server.handle_request()

    synchro.close()
    synchroSocket.close()

    print("Test succeeded")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing command")
    elif sys.argv[1] == "client"[:len(sys.argv[1])]:
        clientTestCmd(sys.argv[2:])
    elif sys.argv[1] == "server"[:len(sys.argv[1])]:
        serverTestCmd(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])
