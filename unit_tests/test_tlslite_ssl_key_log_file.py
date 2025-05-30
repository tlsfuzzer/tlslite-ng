try:
    import unittest2 as unittest
except ImportError:
    import unittest

import os
from threading import Thread
import tempfile
import random
import unittest

from tlslite.sslkeylogging import SSLKeyLogger
from tlslite.utils.compat import b2a_hex


class TestSslKeyLogFile(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestSslKeyLogFile, self).__init__(*args, **kwargs)

    def setUp(self):
        self.temp_log_file = tempfile.NamedTemporaryFile(delete=False)
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
            client_random = random.randbytes(32)
            master_secret = random.randbytes(48)
            label = ("CLIENT_RANDOM", client_random, master_secret)
            expected_labels.append(label)
            logger = loggers[i]
            threads.append(Thread(target=logger.log_session_keys, args=(label,)))

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
            client_random = random.randbytes(32)
            labels = [
                ("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, random.randbytes(32)),
                ("EXPORTER_SECRET", client_random, random.randbytes(32)),
                ("SERVER_TRAFFIC_SECRET_0", client_random, random.randbytes(32)),
                ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, random.randbytes(32)),
                ("CLIENT_TRAFFIC_SECRET_0", client_random, random.randbytes(32))
            ]
            expected_labels.append(labels)
            logger = loggers[i]
            threads.append(Thread(target=logger.log_session_keys, args=(labels,)))

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(10)

        self.validate_log_file(expected_labels)

    def validate_log_file(self, all_labels):
        """
        Validates lines in SSLKEYLOGFILE for both TLS 1.2 and TLS 1.3
        """
        with open(self.temp_log_file.name, 'r') as log_file:
            lines = [log_line.strip() for log_line in log_file.readlines()]
            for labels in all_labels:
                if isinstance(labels, tuple):
                    client_random = b2a_hex(labels[1]).upper()
                    master_secret = b2a_hex(labels[2]).upper()
                    expected_label = "{0} {1} {2}".format(labels[0], client_random, master_secret)
                    self.assertTrue(expected_label in lines, "Expected: {0}".format(expected_label))
                elif isinstance(labels, list):
                    for label_name, client_random, secret in labels:
                        expected_label = "{0} {1} {2}".format(
                            label_name, b2a_hex(client_random).upper(), b2a_hex(secret).upper()
                        )
                        self.assertTrue(expected_label in lines, "Didn't find expected: {0}".format(expected_label))


if __name__ == "__main__":
    unittest.main()
