import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "password_vault_manager.settings")
import django
django.setup()
from django.test import Client
from django.core.files.uploadedfile import SimpleUploadedFile

from password_vault_manager.runtime import VaultRuntime, configure, reset_for_tests


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runtime = configure(Path(self.temp.name) / "test.vault")
        self.client = Client(HTTP_HOST="127.0.0.1:8000")

    def tearDown(self):
        reset_for_tests()
        self.temp.cleanup()

    def post(self, action, data=None, client=None, **headers):
        headers = {"HTTP_X_VAULT_REQUEST": "1", **headers}
        return (client or self.client).post("/api/" + action, data=json.dumps(data or {}),
                    content_type="application/json", **headers)

    def create(self):
        self.assertEqual(self.post("create", {"master_password": "long master passphrase"}).status_code, 200)

    def test_health_and_static_page(self):
        self.assertEqual(self.client.get("/health").json()["status"], "ok")
        page = self.client.get("/")
        self.assertContainsReactRoot(page)
        assets = re.findall(r'(?:src|href)="(/assets/[^"\s]+)"', page.content.decode())
        self.assertTrue(any(path.endswith('.js') for path in assets))
        self.assertTrue(any(path.endswith('.css') for path in assets))
        for path in ("/", *assets):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response["Cache-Control"], "no-store")
            expected = 'text/javascript' if path.endswith('.js') else 'text/css' if path.endswith('.css') else 'text/html'
            self.assertEqual(response['Content-Type'], expected + '; charset=utf-8')

    def assertContainsReactRoot(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertIn('<div id="root"></div>', response.content.decode())
        self.assertIn('type="module"', response.content.decode())

    def test_bundled_asset_not_found_and_method_validation(self):
        for path in ('/assets/missing.js', '/assets/../views.py', '/assets/%2e%2e%2fviews.py',
                     '/assets/index.html', '/assets/views.py'):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)
        self.assertEqual(self.client.post('/').status_code, 405)
        self.assertEqual(self.client.post('/assets/missing.js').status_code, 405)

    def test_lifecycle_and_session_isolation(self):
        self.assertEqual(self.post("entries").status_code, 401)
        self.create()
        saved = self.post("save", {"title": "Email", "username": "user", "password": "old-secret"})
        self.assertEqual(saved.status_code, 201)
        key = saved.json()["entry"]["id"]
        self.assertNotIn("password", saved.json()["entry"])
        self.assertEqual(self.post("entries", client=Client(HTTP_HOST="127.0.0.1:8000")).status_code, 401)
        self.assertEqual(self.post("reveal", {"id": key}).json()["password"], "old-secret")
        self.assertNotIn("old-secret", self.post("entries").content.decode())
        self.assertEqual(self.post("rotate", {"id": key, "password": "new-secret"}).status_code, 200)
        self.assertEqual(self.post("lock").status_code, 200)
        self.assertEqual(self.post("reveal", {"id": key}).status_code, 401)
        self.assertEqual(self.post("unlock", {"master_password": "wrong"}).status_code, 401)
        self.assertEqual(self.post("unlock", {"master_password": "long master passphrase"}).status_code, 200)
        self.assertEqual(self.post("reveal", {"id": key}).json()["password"], "new-secret")
        self.assertEqual(self.post("delete", {"id": key}).status_code, 200)
        self.assertEqual(self.post("entries").json()["entries"], [])

    def test_rejects_cross_origin_and_rebinding(self):
        for headers in ({"HTTP_ORIGIN": "https://evil.example"}, {"HTTP_HOST": "evil.example"},
                        {"HTTP_HOST": "127.0.0.1.evil.example"},
                        {"HTTP_HOST": "localhost:99999"},
                        {"HTTP_X_VAULT_REQUEST": ""}, {"HTTP_SEC_FETCH_SITE": "cross-site"},
                        {"HTTP_SEC_FETCH_SITE": "same-site"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.post("create", {"master_password": "long master passphrase"},
                                           **headers).status_code, 403)
        self.assertFalse(self.runtime.store.initialized)

    def test_private_lock_file_and_response_headers(self):
        lock_path = Path(str(self.runtime.store.path) + '.lock')
        self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
        response = self.client.get('/')
        self.assertEqual(response['X-Frame-Options'], 'DENY')
        self.assertEqual(response['Cross-Origin-Resource-Policy'], 'same-origin')
        self.assertIn("object-src 'none'", response['Content-Security-Policy'])

    def test_validation_and_missing_entry(self):
        self.create()
        self.assertEqual(self.post("save", {"title": "Empty"}).status_code, 400)
        self.assertEqual(self.post("save", {"title": "Test", "password": "test",
                                            "rotation_days": True}).status_code, 400)
        self.assertEqual(self.post("reveal", {"id": "missing"}).status_code, 404)
        self.assertEqual(self.client.post("/api/save", data="[]", content_type="application/json",
                                          HTTP_X_VAULT_REQUEST="1").status_code, 400)

    def test_idle_lock_and_exclusive_writer(self):
        self.create()
        with self.assertRaises(BlockingIOError):
            other = VaultRuntime(self.runtime.store.path)
            other.close()
        self.runtime.last_activity = time.monotonic() - 301
        self.assertTrue(self.client.get("/api/status").json()["locked"])
        self.assertTrue(self.runtime.store.locked)

    def test_background_lock_and_rate_limit(self):
        self.create()
        self.runtime.last_activity = time.monotonic() - 301
        deadline = time.monotonic() + 3
        while not self.runtime.store.locked and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(self.runtime.store.locked)
        self.assertIsNone(self.runtime.session)
        for _ in range(5):
            self.assertEqual(self.post("unlock", {"master_password": "wrong"}).status_code, 401)
        self.assertEqual(self.post("unlock", {"master_password": "long master passphrase"}).status_code, 429)

    def test_encrypted_export_and_import(self):
        self.assertEqual(self.post('export').status_code, 401)
        self.create()
        self.post('save', {'title': 'Email', 'username': 'user', 'password': 'secret'})
        response = self.post('export')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')
        self.assertIn('attachment', response['Content-Disposition'])
        backup = response.content
        self.assertNotIn(b'secret', backup)
        self.post('delete', {'id': self.post('entries').json()['entries'][0]['id']})
        self.assertEqual(self.post('entries').json()['entries'], [])
        upload = lambda: SimpleUploadedFile('backup.vault', backup, content_type='application/octet-stream')
        bad = self.client.post('/api/import', {'vault_file': upload(), 'master_password': 'wrong'},
                               HTTP_X_VAULT_REQUEST='1')
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(self.post('entries').json()['entries'], [])
        good = self.client.post('/api/import', {'vault_file': upload(),
                                'master_password': 'long master passphrase'}, HTTP_X_VAULT_REQUEST='1')
        self.assertEqual(good.status_code, 200)
        self.assertEqual(good.json()['imported'], 1)
        self.assertEqual(len(self.post('entries').json()['entries']), 1)
        again = self.client.post('/api/import', {'vault_file': upload(),
                                 'master_password': 'long master passphrase'}, HTTP_X_VAULT_REQUEST='1')
        self.assertEqual(again.json()['imported'], 0)
