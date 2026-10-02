import base64
import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from password_vault_manager.vault import VaultAuthenticationError, VaultEntry, VaultLockedError, VaultStore, generate_password


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'passwords.vault'
        self.store = VaultStore(self.path)
        self.master = 'long master passphrase'

    def entry(self):
        return VaultEntry('1', 'Email', 'private-user', 'private-secret', 'https://example.com')

    def test_round_trip_and_encrypted_storage(self):
        self.store.initialize(self.master)
        entry = self.entry()
        self.store.save(entry)
        raw = self.path.read_bytes()
        for secret in ('private-user', 'private-secret', 'Email', self.master):
            self.assertNotIn(secret.encode(), raw)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        reopened = VaultStore(self.path)
        with self.assertRaises(VaultLockedError):
            reopened.list_ids()
        reopened.unlock(self.master)
        self.assertEqual(reopened.get('1'), entry)
        reopened.delete('1')
        reopened.lock()
        reopened.unlock(self.master)
        self.assertEqual(reopened.list_ids(), [])

    def test_wrong_password_and_tampering_leave_vault_locked(self):
        self.store.initialize(self.master)
        self.store.save(self.entry())
        with self.assertRaises(VaultAuthenticationError):
            self.store.unlock('incorrect password')
        self.assertTrue(self.store.locked)
        envelope = json.loads(self.path.read_bytes())
        ciphertext = bytearray(base64.b64decode(envelope['ciphertext']))
        ciphertext[-1] ^= 1
        envelope['ciphertext'] = base64.b64encode(ciphertext).decode()
        self.path.write_text(json.dumps(envelope))
        with self.assertRaises(VaultAuthenticationError):
            self.store.unlock(self.master)
        self.assertTrue(self.store.locked)

    def test_rotation_due_and_master_password_change(self):
        self.store.initialize(self.master)
        old = replace(self.entry(), rotated_at=(datetime.now(timezone.utc) - timedelta(days=100)).isoformat())
        self.store.save(old)
        self.assertTrue(old.summary()['overdue'])
        rotated = self.store.rotate('1')
        self.assertNotEqual(rotated.password, old.password)
        self.assertEqual(len(rotated.password), 24)
        self.assertFalse(rotated.summary()['overdue'])
        self.store.change_master_password('a new master passphrase')
        self.store.lock()
        with self.assertRaises(VaultAuthenticationError):
            self.store.unlock(self.master)
        self.store.unlock('a new master passphrase')
        self.assertEqual(self.store.get('1').password, rotated.password)
        self.assertNotIn('password', self.store.get('1').summary())

    def test_failed_write_preserves_memory_and_disk(self):
        self.store.initialize(self.master)
        self.store.save(self.entry())
        before = self.path.read_bytes()
        with patch('password_vault_manager.vault.os.replace', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):
                self.store.rotate('1')
        self.assertEqual(self.store.get('1').password, 'private-secret')
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.path.parent.glob('.vault-*')), [])

    def test_validation_and_generation(self):
        with self.assertRaises(ValueError):
            self.store.initialize('short')
        self.assertFalse(self.path.exists())
        self.store.initialize(self.master)
        with self.assertRaises(ValueError):
            self.store.initialize(self.master)
        for days in (0, 3651, True, '90'):
            with self.subTest(days=days), self.assertRaises(ValueError):
                self.store.save(replace(self.entry(), rotation_days=days))
        self.assertEqual(len(generate_password()), 24)
        with self.assertRaises(ValueError):
            generate_password(8)

    def test_entry_repr_omits_credentials(self):
        self.assertNotIn('private-user', repr(self.entry()))
        self.assertNotIn('private-secret', repr(self.entry()))

    def test_encrypted_export_and_import_merge(self):
        self.store.initialize(self.master)
        self.store.save(self.entry())
        backup = self.store.export_encrypted()
        self.assertNotIn(b'private-secret', backup)
        self.assertEqual(self.store.import_encrypted(backup, self.master), 0)
        other_path = Path(self.temp.name) / 'other.vault'
        other = VaultStore(other_path)
        other.initialize('another master password')
        other.save(replace(self.entry(), password='other-secret'))
        imported = other.export_encrypted()
        before = self.path.read_bytes()
        with self.assertRaises(VaultAuthenticationError):
            self.store.import_encrypted(imported, 'wrong password')
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.store.import_encrypted(imported, 'another master password'), 1)
        ids = self.store.list_ids()
        self.assertEqual(len(ids), 2)
        self.assertEqual(self.store.get('1').password, 'private-secret')
        self.assertEqual(self.store.get(next(key for key in ids if key != '1')).password, 'other-secret')
        self.store.lock()
        self.store.unlock(self.master)
        self.assertEqual(len(self.store.list_ids()), 2)

    def test_invalid_import_keeps_current_vault(self):
        self.store.initialize(self.master)
        self.store.save(self.entry())
        before = self.path.read_bytes()
        for blob in (b'', b'not json', b'{}', b'x' * (8 * 1024 * 1024 + 1)):
            with self.subTest(blob=blob[:20]), self.assertRaises(VaultAuthenticationError):
                self.store.import_encrypted(blob, self.master)
            self.assertEqual(self.path.read_bytes(), before)

    def test_rejects_public_and_symlinked_vault_paths(self):
        self.store.initialize(self.master)
        self.store.lock()
        self.path.chmod(0o644)
        with self.assertRaises(PermissionError):
            self.store.unlock(self.master)
        self.path.chmod(0o600)
        other = Path(self.temp.name) / 'other.vault'
        self.path.rename(other)
        self.path.symlink_to(other)
        with self.assertRaises(PermissionError):
            self.store.unlock(self.master)

    def test_rejects_public_vault_directory(self):
        self.path.parent.chmod(0o755)
        with self.assertRaises(PermissionError):
            self.store.initialize(self.master)
        self.path.parent.chmod(0o700)
