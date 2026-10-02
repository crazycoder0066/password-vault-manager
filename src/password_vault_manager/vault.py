"""Authenticated encrypted storage for a single local vault."""
import base64
import hashlib
import json
import os
import secrets
import stat
import string
import tempfile
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_password(length: int = 24) -> str:
    if not 16 <= length <= 128:
        raise ValueError("Password length must be between 16 and 128")
    groups = (string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*-_=+")
    while True:
        value = "".join(secrets.choice("".join(groups)) for _ in range(length))
        if all(any(c in group for c in value) for group in groups):
            return value


@dataclass(frozen=True)
class VaultEntry:
    id: str
    title: str
    username: str = field(repr=False)
    password: str = field(repr=False)
    url: str = ""
    rotated_at: str = field(default_factory=now)
    rotation_days: int = 90

    def summary(self) -> dict:
        result = asdict(self)
        del result["password"]
        due = datetime.fromisoformat(self.rotated_at) + timedelta(days=self.rotation_days)
        result.update(due_at=due.isoformat(), overdue=due <= datetime.now(timezone.utc))
        return result


class VaultLockedError(Exception):
    """An operation requires an unlocked vault."""


class VaultAuthenticationError(ValueError):
    """The password is incorrect or the vault failed authentication."""


class VaultStore:
    """Single-process store. Callers serialize access; writes replace files atomically."""
    AAD = b"password-vault-manager:v1:scrypt-n32768-r8-p1"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._key = None
        self._salt = None
        self._entries: dict[str, VaultEntry] = {}

    @property
    def initialized(self) -> bool:
        return self.path.exists() or self.path.is_symlink()

    def _check_directory(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = self.path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError("Vault directory must be owned by you and private (mode 0700)")

    def _check_file(self) -> None:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError("Vault file must be a private regular file (mode 0600)")

    def _read_blob(self) -> bytes:
        self._check_directory()
        self._check_file()
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise PermissionError("Vault file must be a private regular file (mode 0600)")
            blob = source.read(8 * 1024 * 1024 + 1)
        if not blob or len(blob) > 8 * 1024 * 1024:
            raise ValueError("Vault size is invalid")
        return blob

    @property
    def locked(self) -> bool:
        return self._key is None

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        if not isinstance(password, str) or not password or len(password) > 1024:
            raise ValueError("Enter a master password of at most 1024 characters")
        return hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1,
                              dklen=32, maxmem=64 * 1024 * 1024)

    def initialize(self, master_password: str) -> None:
        if self.initialized:
            raise ValueError("Vault already exists; unlock it instead")
        if len(master_password) < 12:
            raise ValueError("Use a master password with at least 12 characters")
        salt = secrets.token_bytes(16)
        key = self._derive(master_password, salt)
        self._write({}, key, salt)
        self._key, self._salt, self._entries = key, salt, {}

    def unlock(self, master_password: str) -> None:
        self.lock()
        if not self.initialized:
            raise ValueError("Create a vault first")
        try:
            blob = self._read_blob()
            key, salt, entries = self._decrypt_blob(blob, master_password)
        except OSError:
            raise
        self._key, self._salt, self._entries = key, salt, entries

    @classmethod
    def _decrypt_blob(cls, blob: bytes, master_password: str):
        try:
            if not blob or len(blob) > 8 * 1024 * 1024:
                raise ValueError("Vault size is invalid")
            envelope = json.loads(blob)
            if envelope["version"] != 1:
                raise ValueError("Unsupported vault format")
            salt = base64.b64decode(envelope["salt"], validate=True)
            nonce = base64.b64decode(envelope["nonce"], validate=True)
            if len(salt) != 16 or len(nonce) != 12:
                raise ValueError("Invalid vault format")
            key = cls._derive(master_password, salt)
            data = AESGCM(key).decrypt(nonce, base64.b64decode(envelope["ciphertext"], validate=True), cls.AAD)
            decoded = json.loads(data)
            if not isinstance(decoded, list) or len(decoded) > 10000:
                raise ValueError("Invalid entries")
            entries = {}
            for item in decoded:
                entry = VaultEntry(**item)
                cls._validate_entry(entry)
                if entry.id in entries:
                    raise ValueError("Duplicate entry ID")
                entries[entry.id] = entry
        except (InvalidTag, ValueError, KeyError, TypeError, UnicodeError, AttributeError) as exc:
            raise VaultAuthenticationError("Incorrect master password or damaged vault") from exc
        return key, salt, entries

    def export_encrypted(self) -> bytes:
        self._require_unlocked()
        return self._read_blob()

    def import_encrypted(self, blob: bytes, master_password: str) -> int:
        """Merge authenticated entries; keep existing IDs and contents unchanged."""
        self._require_unlocked()
        _, _, imported = self._decrypt_blob(blob, master_password)
        merged = dict(self._entries)
        added = 0
        for entry in imported.values():
            if entry.id in merged:
                if merged[entry.id] == entry:
                    continue
                entry = replace(entry, id=secrets.token_hex(16))
                while entry.id in merged:
                    entry = replace(entry, id=secrets.token_hex(16))
            merged[entry.id] = entry
            added += 1
        if added:
            self._commit(merged)
        return added

    def lock(self) -> None:
        self._key, self._salt, self._entries = None, None, {}

    def _require_unlocked(self) -> None:
        if self.locked:
            raise VaultLockedError("Unlock the vault first")

    def _write(self, entries: dict[str, VaultEntry], key: bytes, salt: bytes) -> None:
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps([asdict(entry) for entry in entries.values()]).encode()
        envelope = {"version": 1, "salt": base64.b64encode(salt).decode(),
                    "nonce": base64.b64encode(nonce).decode(),
                    "ciphertext": base64.b64encode(AESGCM(key).encrypt(nonce, plaintext, self.AAD)).decode()}
        body = json.dumps(envelope).encode()
        if len(body) > 8 * 1024 * 1024:
            raise ValueError("Vault size limit reached")
        self._check_directory()
        self._check_file()
        fd, name = tempfile.mkstemp(prefix=".vault-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def list_ids(self) -> list[str]:
        self._require_unlocked()
        return list(self._entries)

    def get(self, entry_id: str) -> VaultEntry:
        self._require_unlocked()
        return self._entries[entry_id]

    def _commit(self, entries: dict[str, VaultEntry]) -> None:
        self._require_unlocked()
        self._write(entries, self._key, self._salt)
        self._entries = entries

    @staticmethod
    def _validate_entry(entry: VaultEntry) -> None:
        if any(not isinstance(value, str) or len(value) > 4096
               for value in (entry.id, entry.title, entry.username, entry.password, entry.url)):
            raise ValueError("Entry fields must be text of at most 4096 characters")
        if not entry.id:
            raise ValueError("Entry ID is required")
        if not entry.title.strip() or not entry.password:
            raise ValueError("Title and password are required")
        if type(entry.rotation_days) is not int or not 1 <= entry.rotation_days <= 3650:
            raise ValueError("Rotation interval must be between 1 and 3650 days")
        if not isinstance(entry.rotated_at, str) or len(entry.rotated_at) > 64:
            raise ValueError("Invalid rotation timestamp")
        rotated_at = datetime.fromisoformat(entry.rotated_at)
        if rotated_at.tzinfo is None:
            raise ValueError("Rotation timestamp needs a timezone")

    def save(self, entry: VaultEntry) -> None:
        self._require_unlocked()
        self._validate_entry(entry)
        self._commit({**self._entries, entry.id: entry})

    def delete(self, entry_id: str) -> None:
        self.get(entry_id)
        entries = dict(self._entries)
        del entries[entry_id]
        self._commit(entries)

    def rotate(self, entry_id: str, password: str = "") -> VaultEntry:
        entry = replace(self.get(entry_id), password=password or generate_password(), rotated_at=now())
        self.save(entry)
        return entry

    def change_master_password(self, password: str) -> None:
        self._require_unlocked()
        if len(password) < 12:
            raise ValueError("Use a master password with at least 12 characters")
        salt = secrets.token_bytes(16)
        key = self._derive(password, salt)
        self._write(self._entries, key, salt)
        self._key, self._salt = key, salt
