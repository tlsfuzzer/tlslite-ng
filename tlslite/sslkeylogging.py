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
    Write session secrets to the file pointed to by the SSLKEYLOGFILE
    environment variable. Implemented to be thread-safe at the class level and
    uses OS level file-locking. The file-locking implementation is a function
    assigned to self.lock_write and determined by the value of sys.platform.

    Currently, POSIX is supported for thread and process safety. If enabled for
    other systems, safety is not guaranteed.

    :param logfile_override: specify the filepath for logging
    :type logfile_override: str
    """
    _lock = threading.Lock()

    def __init__(self, logfile_override=None):
        self.ssl_key_logfile = os.environ.get('SSLKEYLOGFILE')
        if logfile_override:
            self.ssl_key_logfile = logfile_override
        self.platform = sys.platform
        if self.platform in ['darwin', 'linux']:
            self.lock_write = posix_lock_write
        else:
            self.lock_write = unsafe_write

    def log_session_keys(self, keys):
        # no-op if SSLKEYLOGFILE env variable or logfile_override isn't set
        if not self.ssl_key_logfile:
            return

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
