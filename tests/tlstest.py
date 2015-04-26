#!/usr/bin/env python

# Authors: 
#   Trevor Perrin
#   Kees Bos - Added tests for XML-RPC
#   Dimitris Moraitis - Anon ciphersuites
#   Marcelo Fernandez - Added test for NPN
#   Martin von Loewis - python 3 port
#   Hubert Kario - several improvements
#   Google - FALLBACK_SCSV test
#
# See the LICENSE file for legal information regarding use of this file.
from __future__ import print_function
import sys
import os
import os.path
import socket
import time
import getopt
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
from tlslite.utils.cryptomath import prngName
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
    synchro.settimeout(5)
    synchro.connect((address[0], address[1]-1))

    def connect():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(sock, 'settimeout'): #It's a python 2.3 feature
            sock.settimeout(5)
        sock.connect(address)
        c = TLSConnection(sock)
        return c

    test = 0

    badFault = False

    print("Test 0 - anonymous handshake")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientAnonymous()
    testConnClient(connection)
    connection.close()
        
    print("Test 1 - good X509 (plus SNI)")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(serverName=address[0])
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(connection.encryptThenMAC == True)
    connection.close()

    print("Test 1.a - good X509, SSLv3")
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeClientCert(settings=settings)
    testConnClient(connection)    
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()    

    print("Test 1.b - good X509, RC4-MD5")
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.macNames = ["md5"]
    connection.handshakeClientCert(settings=settings)
    testConnClient(connection)    
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.cipherSuite == constants.CipherSuite.TLS_RSA_WITH_RC4_128_MD5)
    connection.close()

    if tackpyLoaded:
                    
        settings = HandshakeSettings()
        settings.useExperimentalTackExtension = True

        print("Test 2.a - good X.509, TACK")
        synchro.recv(1)
        connection = connect()
        connection.handshakeClientCert(settings=settings)
        assert(connection.session.tackExt.tacks[0].getTackId() == "5lcbe.eyweo.yxuan.rw6xd.jtoz7")
        assert(connection.session.tackExt.activation_flags == 1)        
        testConnClient(connection)    
        connection.close()    

        print("Test 2.b - good X.509, TACK unrelated to cert chain")
        synchro.recv(1)
        connection = connect()
        try:
            connection.handshakeClientCert(settings=settings)
            assert(False)
        except TLSLocalAlert as alert:
            if alert.description != AlertDescription.illegal_parameter:
                raise        
        connection.close()

    print("Test 3 - good SRP")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientSRP("test", "password")
    testConnClient(connection)
    connection.close()

    print("Test 4 - SRP faults")
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        synchro.recv(1)
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeClientSRP("test", "password")
            print("  Good Fault %s" % (Fault.faultNames[fault]))
        except TLSFaultError as e:
            print("  BAD FAULT %s: %s" % (Fault.faultNames[fault], str(e)))
            badFault = True

    print("Test 6 - good SRP: with X.509 certificate, TLSv1.0")
    settings = HandshakeSettings()
    settings.minVersion = (3,1)
    settings.maxVersion = (3,1)    
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientSRP("test", "password", settings=settings)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    testConnClient(connection)
    connection.close()

    print("Test 7 - X.509 with SRP faults")
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        synchro.recv(1)
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeClientSRP("test", "password")
            print("  Good Fault %s" % (Fault.faultNames[fault]))
        except TLSFaultError as e:
            print("  BAD FAULT %s: %s" % (Fault.faultNames[fault], str(e)))
            badFault = True

    print("Test 11 - X.509 faults")
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

    print("Test 14 - good mutual X509")
    x509Cert = X509().parse(open(os.path.join(dir, "clientX509Cert.pem")).read())
    x509Chain = X509CertChain([x509Cert])
    s = open(os.path.join(dir, "clientX509Key.pem")).read()
    x509Key = parsePEMKey(s, private=True)

    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(x509Chain, x509Key)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    print("Test 14.a - good mutual X509, TLSv1.1")
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,2)
    settings.maxVersion = (3,2)
    connection.handshakeClientCert(x509Chain, x509Key, settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    print("Test 14.b - good mutual X509, SSLv3")
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeClientCert(x509Chain, x509Key, settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    print("Test 15 - mutual X.509 faults")
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

    print("Test 18 - good SRP, prepare to resume... (plus SNI)")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientSRP("test", "password", serverName=address[0])
    testConnClient(connection)
    connection.close()
    session = connection.session

    print("Test 19 - resumption (plus SNI)")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientSRP("test", "garbage", serverName=address[0], 
                                    session=session)
    testConnClient(connection)
    #Don't close! -- see below

    print("Test 20 - invalidated resumption (plus SNI)")
    synchro.recv(1)
    connection.sock.close() #Close the socket without a close_notify!
    synchro.recv(1)
    connection = connect()
    try:
        connection.handshakeClientSRP("test", "garbage", 
                        serverName=address[0], session=session)
        assert(False)
    except TLSRemoteAlert as alert:
        if alert.description != AlertDescription.bad_record_mac:
            raise
    connection.close()
    
    print("Test 21 - HTTPS test X.509")
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

    print("Test 22 - different ciphers, TLSv1.0")
    for implementation in implementations:
        for cipher in ["aes128", "aes256", "rc4"]:

            print("Test 22:", end=' ')
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

    print("Test 23 - throughput test")
    for implementation in implementations:
        for cipher in ["aes128", "aes256", "3des", "rc4"]:
            if cipher == "3des" and implementation not in ("openssl", "pycrypto"):
                continue

            print("Test 23:", end=' ')
            synchro.recv(1)
            connection = connect()

            settings = HandshakeSettings()
            settings.cipherNames = [cipher]
            settings.cipherImplementations = [implementation, "python"]
            connection.handshakeClientCert(settings=settings)
            print("%s %s:" % (connection.getCipherName(), connection.getCipherImplementation()), end=' ')

            startTime = time.clock()
            connection.write(b"hello"*10000)
            h = connection.read(min=50000, max=50000)
            stopTime = time.clock()
            if stopTime-startTime:
                print("100K exchanged at rate of %d bytes/sec" % int(100000/(stopTime-startTime)))
            else:
                print("100K exchanged very fast")

            assert(h == b"hello"*10000)
            connection.close()
    
    print("Test 24.a - Next-Protocol Client Negotiation")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(nextProtos=[b"http/1.1"])
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'http/1.1')
    connection.close()

    print("Test 24.b - Next-Protocol Client Negotiation")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(nextProtos=[b"spdy/2", b"http/1.1"])
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'spdy/2')
    connection.close()
    
    print("Test 24.c - Next-Protocol Client Negotiation")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(nextProtos=[b"spdy/2", b"http/1.1"])
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'spdy/2')
    connection.close()
    
    print("Test 24.d - Next-Protocol Client Negotiation")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(nextProtos=[b"spdy/3", b"spdy/2", b"http/1.1"])
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'spdy/2')
    connection.close()
    
    print("Test 24.e - Next-Protocol Client Negotiation")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(nextProtos=[b"spdy/3", b"spdy/2", b"http/1.1"])
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'spdy/3')
    connection.close()

    print("Test 24.f - Next-Protocol Client Negotiation")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(nextProtos=[b"http/1.1"])
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'http/1.1')
    connection.close()

    print("Test 24.g - Next-Protocol Client Negotiation")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(nextProtos=[b"spdy/2", b"http/1.1"])
    #print("  Next-Protocol Negotiated: %s" % connection.next_proto)
    assert(connection.next_proto == b'spdy/2')
    connection.close()

    print("Test 25.a - FALLBACK_SCSV")
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.sendFallbackSCSV = True
    connection.handshakeClientCert(settings=settings)
    testConnClient(connection)
    connection.close()

    print("Test 25.b - FALLBACK_SCSV")
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

    print("Test 26.a - no EtM server side")
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    assert(settings.useEncryptThenMAC)
    connection.handshakeClientCert(serverName=address[0], settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(not connection.encryptThenMAC)
    connection.close()

    print("Test 26.b - no EtM client side")
    synchro.recv(1)
    connection = connect()
    settings = HandshakeSettings()
    settings.useEncryptThenMAC = False
    connection.handshakeClientCert(serverName=address[0], settings=settings)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(not connection.encryptThenMAC)
    connection.close()

    print("Test 26.c - resumption with EtM")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(serverName=address[0])
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
    connection.handshakeClientCert(serverName=address[0], session=session)
    testConnClient(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    assert(connection.session.serverName == address[0])
    assert(connection.resumed)
    assert(connection.encryptThenMAC)
    connection.close()

    print("Test 26.d - resumption with no EtM in 2nd handshake")
    synchro.recv(1)
    connection = connect()
    connection.handshakeClientCert(serverName=address[0])
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
    connection = connect()
    try:
        connection.handshakeClientCert(serverName=address[0], session=session,
                                       settings=settings)
    except TLSRemoteAlert as e:
        assert(str(e) == "handshake_failure")
    else:
        raise AssertionError("No exception raised")
    connection.close()

    print('Test 27 - good standard XMLRPC https client')
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

    print('Test 28 - good tlslite XMLRPC client')
    transport = XMLRPCTransport(ignoreAbruptClose=True)
    server = xmlrpclib.Server('https://%s:%s' % address, transport)
    synchro.recv(1)
    assert server.add(1,2) == 3
    synchro.recv(1)
    assert server.pow(2,4) == 16

    print('Test 29 - good XMLRPC ignored protocol')
    server = xmlrpclib.Server('http://%s:%s' % address, transport)
    synchro.recv(1)
    assert server.add(1,2) == 3
    synchro.recv(1)
    assert server.pow(2,4) == 16

    print("Test 30 - Internet servers test")
    try:
        i = IMAP4_TLS("cyrus.andrew.cmu.edu")
        i.login("anonymous", "anonymous@anonymous.net")
        i.logout()
        print("Test 31: IMAP4 good")
        p = POP3_TLS("pop.gmail.com")
        p.quit()
        print("Test 32: POP3 good")
    except socket.error as e:
        print("Non-critical error: socket error trying to reach internet server: ", e)   

    synchro.close()

    if not badFault:
        print("Test succeeded")
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
        return TLSConnection(lsock.accept()[0])

    x509Cert = X509().parse(open(os.path.join(dir, "serverX509Cert.pem")).read())
    x509Chain = X509CertChain([x509Cert])
    s = open(os.path.join(dir, "serverX509Key.pem")).read()
    x509Key = parsePEMKey(s, private=True)

    print("Test 0 - Anonymous server handshake")
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(anon=True)
    testConnServer(connection)    
    connection.close() 
    
    print("Test 1 - good X.509")
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
    assert(connection.session.serverName == address[0])    
    testConnServer(connection)    
    connection.close()

    print("Test 1.a - good X.509, SSL v3")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, settings=settings)
    testConnServer(connection)
    connection.close()            

    print("Test 1.b - good X.509, RC4-MD5")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.macNames = ["sha", "md5"]
    settings.cipherNames = ["rc4"]
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, settings=settings)
    testConnServer(connection)
    connection.close()            
    
    if tackpyLoaded:
        tack = Tack.createFromPem(open("./TACK1.pem", "rU").read())
        tackUnrelated = Tack.createFromPem(open("./TACKunrelated.pem", "rU").read())    
            
        settings = HandshakeSettings()
        settings.useExperimentalTackExtension = True

        print("Test 2.a - good X.509, TACK")
        synchro.send(b'R')
        connection = connect()
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
            tacks=[tack], activationFlags=1, settings=settings)
        testConnServer(connection)    
        connection.close()        

        print("Test 2.b - good X.509, TACK unrelated to cert chain")
        synchro.send(b'R')
        connection = connect()
        try:
            connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                tacks=[tackUnrelated], settings=settings)
            assert(False)
        except TLSRemoteAlert as alert:
            if alert.description != AlertDescription.illegal_parameter:
                raise        
    
    print("Test 3 - good SRP")
    verifierDB = VerifierDB()
    verifierDB.create()
    entry = VerifierDB.makeVerifier("test", "password", 1536)
    verifierDB["test"] = entry

    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB)
    testConnServer(connection)
    connection.close()

    print("Test 4 - SRP faults")
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        synchro.send(b'R')
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeServer(verifierDB=verifierDB)
            assert()
        except:
            pass
        connection.close()

    print("Test 6 - good SRP: with X.509 cert")
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB, \
                               certChain=x509Chain, privateKey=x509Key)
    testConnServer(connection)    
    connection.close()

    print("Test 7 - X.509 with SRP faults")
    for fault in Fault.clientSrpFaults + Fault.genericFaults:
        synchro.send(b'R')
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeServer(verifierDB=verifierDB, \
                                       certChain=x509Chain, privateKey=x509Key)
            assert()
        except:
            pass
        connection.close()

    print("Test 11 - X.509 faults")
    for fault in Fault.clientNoAuthFaults + Fault.genericFaults:
        synchro.send(b'R')
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
            assert()
        except:
            pass
        connection.close()

    print("Test 14 - good mutual X.509")
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, reqCert=True)
    testConnServer(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    print("Test 14a - good mutual X.509, TLSv1.1")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,2)
    settings.maxVersion = (3,2)
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, reqCert=True, settings=settings)
    testConnServer(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    print("Test 14b - good mutual X.509, SSLv3")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.minVersion = (3,0)
    settings.maxVersion = (3,0)
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, reqCert=True, settings=settings)
    testConnServer(connection)
    assert(isinstance(connection.session.serverCertChain, X509CertChain))
    connection.close()

    print("Test 15 - mutual X.509 faults")
    for fault in Fault.clientCertFaults + Fault.genericFaults:
        synchro.send(b'R')
        connection = connect()
        connection.fault = fault
        try:
            connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, reqCert=True)
            assert()
        except:
            pass
        connection.close()

    print("Test 18 - good SRP, prepare to resume")
    synchro.send(b'R')
    sessionCache = SessionCache()
    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB, sessionCache=sessionCache)
    assert(connection.session.serverName == address[0])    
    testConnServer(connection)
    connection.close()

    print("Test 19 - resumption")
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(verifierDB=verifierDB, sessionCache=sessionCache)
    assert(connection.session.serverName == address[0])
    testConnServer(connection)    
    #Don't close! -- see next test

    print("Test 20 - invalidated resumption")
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

    print("Test 21 - HTTPS test X.509")

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

    print("Test 22 - different ciphers")
    for implementation in ["python"] * len(implementations):
        for cipher in ["aes128", "aes256", "rc4"]:

            print("Test 22:", end=' ')
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

    print("Test 23 - throughput test")
    for implementation in implementations:
        for cipher in ["aes128", "aes256", "3des", "rc4"]:
            if cipher == "3des" and implementation not in ("openssl", "pycrypto"):
                continue

            print("Test 23:", end=' ')
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

    print("Test 24.a - Next-Protocol Server Negotiation")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"http/1.1"])
    testConnServer(connection)
    connection.close()

    print("Test 24.b - Next-Protocol Server Negotiation")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"spdy/2", b"http/1.1"])
    testConnServer(connection)
    connection.close()
    
    print("Test 24.c - Next-Protocol Server Negotiation")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"http/1.1", b"spdy/2"])
    testConnServer(connection)
    connection.close()

    print("Test 24.d - Next-Protocol Server Negotiation")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"spdy/2", b"http/1.1"])
    testConnServer(connection)
    connection.close()
    
    print("Test 24.e - Next-Protocol Server Negotiation")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"http/1.1", b"spdy/2", b"spdy/3"])
    testConnServer(connection)
    connection.close()
    
    print("Test 24.f - Next-Protocol Server Negotiation")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[b"spdy/3", b"spdy/2"])
    testConnServer(connection)
    connection.close()
    
    print("Test 24.g - Next-Protocol Server Negotiation")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key, 
                               settings=settings, nextProtos=[])
    testConnServer(connection)
    connection.close()

    print("Test 25.a - FALLBACK_SCSV")
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
    testConnServer(connection)
    connection.close()

    print("Test 25.b - FALLBACK_SCSV")
    synchro.send(b'R')
    connection = connect()
    try:
        connection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
        assert()
    except TLSLocalAlert as alert:
        if alert.description != AlertDescription.inappropriate_fallback:
            raise
    connection.close()

    print("Test 26.a - no EtM server side")
    synchro.send(b'R')
    connection = connect()
    settings = HandshakeSettings()
    settings.useEncryptThenMAC = False
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key,
                               settings=settings)
    testConnServer(connection)
    connection.close()

    print("Test 26.b - no EtM client side")
    synchro.send(b'R')
    connection = connect()
    connection.handshakeServer(certChain=x509Chain, privateKey=x509Key)
    testConnServer(connection)
    connection.close()

    print("Test 26.c - resumption with EtM")
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

    print("Test 26.d - resumption with no EtM in 2nd handshake")
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

    print("Tests 27-29 - XMLRPXC server")
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
