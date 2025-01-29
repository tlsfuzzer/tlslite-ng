try:
    import unittest2 as unittest
except ImportError:
    import unittest

import tempfile
from socket import socket, AF_INET, SOCK_STREAM
import os

import unittest

from tlslite.api import TLSConnection, HandshakeSettings
from tlslite.errors import TLSRemoteAlert


def create_connection(hostname='www.example.com', port=443, settings=HandshakeSettings()):
    raw_socket = socket(AF_INET, SOCK_STREAM)
    raw_socket.connect((hostname, port))
    connection = TLSConnection(raw_socket)
    connection.handshakeClientCert(settings=settings)
    return connection


def validate_log_file(log_file_name, labels):
    """
    TLS1.3 labels
    ------------------
    SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
    EXPORTER_SECRET <client_random> <secret>
    SERVER_TRAFFIC_SECRET_0  <client_random> <secret>
    CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
    CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>

    TLS1.2 (and below)
    ----------------
    CLIENT_RANDOM <client_random> <secret>
    """
    with open(log_file_name, 'r') as log_file:
        for line in log_file.readlines():
            entry = line.split()
            label, client_random, secret = entry[0], entry[1], entry[2]
            if label in labels and labels[label][1] == client_random and labels[label][2] != secret:
                return False

        return True


class TestSslKeyLogFile(unittest.TestCase):
    def setUp(self):
        self.temp_log_file = tempfile.NamedTemporaryFile(delete=False)
        os.environ['SSLKEYLOGFILE'] = self.temp_log_file.name

    def tearDown(self):
        # Clean up the temporary file
        os.remove(self.temp_log_file.name)
        if os.environ.get('SSLKEYLOGFILE'):
            del os.environ['SSLKEYLOGFILE']

    def test_tlsv1_1(self):
        settings = HandshakeSettings()
        settings.minVersion = (3,2)
        settings.maxVersion = (3,2)

        try:
            connection = create_connection('www.example.com', 443, settings)
            expected_labels = {
                'CLIENT_RANDOM': connection._clientRandom
            }
            self.assertTrue(validate_log_file(self.temp_log_file.name, expected_labels))
            connection.close()
        except TLSRemoteAlert as alert:
            print("TLS Remote Alert: {0}".format(alert))


    def test_tlsv1_2(self):
        settings = HandshakeSettings()
        settings.minVersion = (3,3)
        settings.maxVersion = (3,3)

        try:
            connection = create_connection('www.example.com', 443, settings)
            expected_labels = {
                'CLIENT_RANDOM': connection._clientRandom
            }
            self.assertTrue(validate_log_file(self.temp_log_file.name, expected_labels))
            connection.close()
        except TLSRemoteAlert as alert:
            print("TLS Remote Alert: {0}".format(alert))

    def test_tlsv1_3(self):
        settings = HandshakeSettings()
        settings.minVersion = (3, 4)
        settings.maxVersion = (3, 4)

        try:
            connection = create_connection('www.example.com', 443, settings)
            expected_labels = {
                "SERVER_HANDSHAKE_TRAFFIC_SECRET": connection.session.sr_handshake_traffic_secret,
                "EXPORTER_SECRET": connection.session.exporterMasterSecret,
                "SERVER_TRAFFIC_SECRET_0": connection.session.sr_app_secret,
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET": connection.session.cl_handshake_traffic_secret,
                "CLIENT_TRAFFIC_SECRET_0": connection.session.cl_app_secret
            }
            self.assertTrue(validate_log_file(self.temp_log_file.name, expected_labels))
            connection.close()
        except TLSRemoteAlert as alert:
            print("TLS Remote Alert: {0}".format(alert))


if __name__ == "__main__":
    unittest.main()
