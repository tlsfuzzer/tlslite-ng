# Authors:
#   Trevor Perrin
#   Esteban Sanchez (FosanzDev) - python 3.12 port
#
# See the LICENSE file for legal information regarding use of this file.

__version__ = "0.8.2"
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
    from .integration.tlsasynciodispatchermixin \
        import TLSAsyncioDispatcherMixIn

except ImportError:
    # NOTE: asyncio is not available in base python 2, so this try-except
    # block is necessary to avoid breaking the import of the
    # rest of the module.
    pass

try:
    from .integration.tlsasyncdispatchermixin import TLSAsyncDispatcherMixIn
except ImportError:
    # NOTE: Left this try-except block as is, due to the possibility to use
    # both asyncore and asyncio in the same project no matter the python
    # version (if the asyncore module is available).
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
