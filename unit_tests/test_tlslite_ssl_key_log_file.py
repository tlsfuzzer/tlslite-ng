try:
    import unittest2 as unittest
except ImportError:
    import unittest

import os
import socket
from threading import Thread
import tempfile
import unittest

from tlslite.sslkeylogging import SSLKeyLogger
from tlslite.utils.compat import b2a_hex


class TestSslKeyLogFile(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestSslKeyLogFile, self).__init__(*args, **kwargs)

    def setUp(self):
        self.temp_log_file = tempfile.NamedTemporaryFile(delete=False)
        if self._testMethodName != "test_logfile_override":
            os.environ['SSLKEYLOGFILE'] = self.temp_log_file.name

    def tearDown(self):
        os.remove(self.temp_log_file.name)
        if os.environ.get('SSLKEYLOGFILE'):
            del os.environ['SSLKEYLOGFILE']

    def test_pre_13(self):
        logger_count = 3

        loggers = []
        for i in range(logger_count):
            loggers.append(SSLKeyLogger())

        threads = []
        expected_labels = []
        for i in range(logger_count):
            client_random = os.urandom(32)
            master_secret = os.urandom(48)
            labels = [("CLIENT_RANDOM", client_random, master_secret)]
            expected_labels.extend(labels)
            logger = loggers[i]
            threads.append(
                Thread(target=logger.log_session_keys, args=(labels,))
            )

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(10)

        self.validate_log_file(expected_labels)

    def test_13(self):
        logger_count = 3

        loggers = []
        for i in range(logger_count):
            loggers.append(SSLKeyLogger())

        threads = []
        expected_labels = []
        for i in range(logger_count):
            client_random = os.urandom(32)
            labels = [
                (
                    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                    client_random,
                    os.urandom(32)
                ),
                (
                    "EXPORTER_SECRET",
                    client_random,
                    os.urandom(32)
                ),
                (
                    "SERVER_TRAFFIC_SECRET_0",
                    client_random,
                    os.urandom(32)
                ),
                (
                    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                    client_random,
                    os.urandom(32)
                ),
                (
                    "CLIENT_TRAFFIC_SECRET_0",
                    client_random,
                    os.urandom(32)
                )
            ]
            expected_labels.extend(labels)
            logger = loggers[i]
            threads.append(
                Thread(target=logger.log_session_keys, args=(labels,))
            )

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(10)

        self.validate_log_file(expected_labels)

    def test_logfile_override(self):
        logger_count = 3

        loggers = []
        for i in range(logger_count):
            loggers.append(
                SSLKeyLogger(logfile_override=self.temp_log_file.name)
            )

        threads = []
        expected_labels = []
        for i in range(logger_count):
            client_random = os.urandom(32)
            labels = [
                (
                    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                    client_random,
                    os.urandom(32)
                ),
                (
                    "EXPORTER_SECRET",
                    client_random,
                    os.urandom(32)
                ),
                (
                    "SERVER_TRAFFIC_SECRET_0",
                    client_random,
                    os.urandom(32)
                ),
                (
                    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                    client_random,
                    os.urandom(32)
                ),
                (
                    "CLIENT_TRAFFIC_SECRET_0",
                    client_random,
                    os.urandom(32)
                )
            ]
            expected_labels.extend(labels)
            logger = loggers[i]
            threads.append(
                Thread(target=logger.log_session_keys, args=(labels,))
            )

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(10)

        self.validate_log_file(expected_labels)


    def load_cert_chain(self):
        from tlslite import X509, X509CertChain, parsePEMKey
        x509 = X509()
        with open("/Users/nick/selfsigned.pem") as s:
            x509.parse(s.read())

        certChain = X509CertChain([x509])
        with open("/Users/nick/selfsigned.key") as s:
            privateKey = parsePEMKey(s.read(), private=True)
        return certChain, privateKey

    def new_server_connection(self, sock):
        from tlslite import TLSConnection
        tls_connection = TLSConnection(sock)
        certChain, privateKey = self.load_cert_chain()
        tls_connection.handshakeServer(
            certChain=certChain, privateKey=privateKey
        )

    def new_client_connection(self, sock, ver=(3, 4)):
        from tlslite import TLSConnection, HandshakeSettings
        tls_connection = TLSConnection(sock)
        settings = HandshakeSettings()
        settings.maxVersion = ver
        tls_connection.handshakeClientCert(settings=settings)
        return tls_connection

    def connect_socket_pair(self, ver):
        client_sock, server_sock = socket.socketpair()
        server_thread = Thread(
            target=self.new_server_connection,
            args=(server_sock,)
        )
        server_thread.start()
        tls_connection = self.new_client_connection(client_sock, ver)

        server_thread.join(10)

        if ver == (3, 4):
            shts = tls_connection.session.sr_handshake_traffic_secret
            chts = tls_connection.session.cl_handshake_traffic_secret
            es = tls_connection.session.exporterMasterSecret
            cas = tls_connection.session.cl_app_secret
            sas = tls_connection.session.sr_app_secret
            tls_connection.close()
            client_sock.close()
            server_sock.close()
            return tls_connection._clientRandom, shts, chts, es, cas, sas
        elif ver < (3, 4):
            cr = tls_connection._clientRandom
            ms = tls_connection.session.masterSecret
            tls_connection.close()
            client_sock.close()
            server_sock.close()
            return cr, ms

    def test_socket_pair_12(self):
        ver = (3, 3)
        cr, ms = self.connect_socket_pair(ver)
        expected_labels = [
            ("CLIENT_RANDOM", cr, ms)
        ]
        self.validate_log_file(expected_labels)

    def test_socket_pair_13(self):
        ver = (3, 4)
        cr, shts, chts, es, cas, sas = self.connect_socket_pair(ver)
        expected_labels = [
            ("SERVER_HANDSHAKE_TRAFFIC_SECRET", cr, shts),
            ("EXPORTER_SECRET", cr, es),
            ("SERVER_TRAFFIC_SECRET_0", cr, sas),
            ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", cr, chts),
            ("CLIENT_TRAFFIC_SECRET_0", cr, cas)
        ]
        self.validate_log_file(expected_labels)

    def validate_log_file(self, all_labels):
        # Validates lines in SSLKEYLOGFILE for both TLS 1.2 and TLS 1.3
        with open(self.temp_log_file.name, 'r') as log_file:
            lines = [log_line.strip() for log_line in log_file.readlines()]
            for label_name, client_random, secret in all_labels:
                expected_label = "{0} {1} {2}".format(
                    label_name,
                    b2a_hex(client_random).upper(),
                    b2a_hex(secret).upper()
                )
                self.assertTrue(
                    expected_label in lines,
                    "Didn't find expected: {0}".format(expected_label)
                )


if __name__ == "__main__":
    unittest.main()
