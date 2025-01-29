import os
import sys
import threading
from .utils.compat import b2a_hex


def posix_lock_write(file_path, lines):
    import fcntl
    with open(file_path, 'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.writelines(lines)
            f.flush()
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def unsafe_write(file_path, lines):
    with open(file_path, 'a') as f:
        f.writelines(lines)
        f.flush()


class SSLKeyLogger:
    """
    Write session secrets to the SSLKEYLOGFILE environment variable. Implemented to be thread-safe at the class
    level and uses OS level file-locking. The file-locking implementation is a function assigned to self.lock_write
    and determined by the value of sys.platform. Currently, POSIX is supported.

    :param enabled: sets the logger to enabled
    :type enabled: bool
    """
    _lock = threading.Lock()

    def __init__(self, enabled=False):
        self.enabled = enabled
        self.ssl_key_logfile = os.environ.get('SSLKEYLOGFILE')
        self.platform = sys.platform
        if self.platform in ['darwin', 'linux']:
            self.lock_write = posix_lock_write
        else:
            # TODO warn user of unsafe?
            self.lock_write = unsafe_write

    def log_session_keys(self, keys):
        # no-op if not enabled or if SSLKEYLOGFILE env variable isn't set
        if self.ssl_key_logfile is None or not self.enabled:
            return

        if isinstance(keys, tuple):
            keys = [keys]

        lines = [
            "{0} {1} {2}\n".format(
                label,
                b2a_hex(client_random).upper(),
                b2a_hex(secret).upper()
            )
            for label, client_random, secret in keys
        ]

        with self._lock:
            self.lock_write(self.ssl_key_logfile, lines)