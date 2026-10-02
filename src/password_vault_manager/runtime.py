"""Single-process vault state shared by Django views."""
import fcntl
import os
import secrets
import stat
import threading
import time
from pathlib import Path

from .vault import VaultStore


class VaultRuntime:
    def __init__(self, path):
        self.store = VaultStore(path)
        self.mutex = threading.RLock()
        self.session = None
        self.last_activity = 0.0
        self.idle_timeout = 300
        self.failures = 0
        self.retry_after = 0.0
        self.stopping = threading.Event()
        self.store._check_directory()
        self.store._check_file()
        lock_fd = os.open(str(self.store.path) + ".lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise PermissionError("Vault lock must be a regular file owned by you")
            os.fchmod(lock_fd, 0o600)
            self.file_lock = os.fdopen(lock_fd, "a")
        except BaseException:
            os.close(lock_fd)
            raise
        try:
            fcntl.flock(self.file_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.file_lock.close()
            raise
        self.reaper = threading.Thread(target=self.expire_sessions, daemon=True)
        self.reaper.start()

    def expire_sessions(self):
        while not self.stopping.wait(1):
            with self.mutex:
                if self.session and time.monotonic() - self.last_activity > self.idle_timeout:
                    self.lock_vault()

    def lock_vault(self):
        self.store.lock()
        self.session = None

    def authenticated(self, token):
        if self.session and time.monotonic() - self.last_activity > self.idle_timeout:
            self.lock_vault()
        valid = bool(token and self.session and secrets.compare_digest(token, self.session))
        if valid:
            self.last_activity = time.monotonic()
        return valid

    def close(self):
        self.stopping.set()
        self.reaper.join()
        with self.mutex:
            self.lock_vault()
        self.file_lock.close()


_runtime = None


def configure(path: str | Path):
    global _runtime
    if _runtime is not None:
        raise RuntimeError("Vault runtime is already configured")
    _runtime = VaultRuntime(path)
    return _runtime


def get_runtime():
    if _runtime is None:
        raise RuntimeError("Start the vault with the password-vault-manager command")
    return _runtime


def reset_for_tests():
    global _runtime
    if _runtime is not None:
        _runtime.close()
        _runtime = None
