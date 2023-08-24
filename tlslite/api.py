# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

__version__ = "0.8.0-beta1"
# the whole module is about importing most commonly used methods, for use
# by other applications
# pylint: disable=unused-import
from .constants import AlertLevel, AlertDescription, Fault
from .errors import *
from .checker import Checker
from .handshakesettings import HandshakeSettings
from .session import Session
from .sessioncache import SessionCache
from .tlsconnection import TLSConnection
from .verifierdb import VerifierDB
from .x509 import X509
from .x509certchain import X509CertChain

from .integration.httptlsconnection import HTTPTLSConnection
from .integration.tlssocketservermixin import TLSSocketServerMixIn
try:
    from .integration.tlsasyncdispatchermixin import TLSAsyncDispatcherMixIn
except ModuleNotFoundError:
    # asyncore was removed in 3.12, I don't use use it, so don't know how
    # to fix it
    pass
from .integration.pop3_tls import POP3_TLS
from .integration.imap4_tls import IMAP4_TLS
from .integration.smtp_tls import SMTP_TLS
from .integration.xmlrpctransport import XMLRPCTransport
from .integration.xmlrpcserver import TLSXMLRPCRequestHandler, \
                                      TLSXMLRPCServer, \
                                      MultiPathTLSXMLRPCServer

from .utils.cryptomath import m2cryptoLoaded, gmpyLoaded, \
                             pycryptoLoaded, prngName, GMPY2_LOADED
from .utils.keyfactory import generateRSAKey, parsePEMKey, \
                             parseAsPublicKey, parsePrivateKey
from .utils.tackwrapper import tackpyLoaded
from .dh import parse as parseDH
