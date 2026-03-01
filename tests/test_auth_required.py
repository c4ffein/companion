#!/usr/bin/env python3
"""
E2E tests verifying that all data endpoints require authentication.

An unauthenticated client must receive 401 on every endpoint that serves or
mutates data, and the server must never crash (return 5xx) in the process.
"""

import hashlib
import json
import secrets
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

sys.path.insert(0, "src")
import companion


def _make_client_entry(client_secret, admin=True, name="test"):
    salt = secrets.token_hex(16)
    secret_hash = hashlib.sha256((salt + client_secret).encode()).hexdigest()
    return {
        "salt": salt,
        "secret_hash": secret_hash,
        "admin": admin,
        "name": name,
        "registered": "2026-01-01T00:00:00",
    }


class TestAuthRequired(unittest.TestCase):
    """Verify unauthenticated requests get 401 (not 500) on all protected endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.port = 8895
        cls.client_id = "auth-test-client"
        cls.client_secret = secrets.token_hex(32)
        cls.auth_token = f"{cls.client_id}:{cls.client_secret}"
        cls.base_url = f"http://localhost:{cls.port}"

        companion.FILES.clear()
        companion.PREVIEW_STATE = {"file_id": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}
        companion.RATE_LIMIT_STORE.clear()

        with companion.CLIENTS_LOCK:
            companion.CLIENTS.clear()
            companion.CLIENTS[cls.client_id] = _make_client_entry(cls.client_secret)

        def run_server():
            server_address = ("127.0.0.1", cls.port)
            httpd = companion.http.server.HTTPServer(server_address, companion.FileShareHandler)
            httpd.allow_reuse_address = True
            cls.httpd = httpd
            httpd.serve_forever()

        cls.server_thread = threading.Thread(target=run_server, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "httpd"):
            cls.httpd.shutdown()
            cls.httpd.server_close()

    def setUp(self):
        with companion.RATE_LIMIT_LOCK:
            companion.RATE_LIMIT_STORE.clear()
        self.request_log = []
        patcher = patch.object(
            companion.FileShareHandler,
            "log_message",
            lambda self_, fmt, *a: self.request_log.append(fmt % a),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _assert_401(self, req, label):
        """Assert that the request returns HTTP 401, not 5xx or success."""
        try:
            urllib.request.urlopen(req)
            self.fail(f"{label}: expected 401 but got 200")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 401, f"{label}: expected 401, got {e.code}")

    # -- GET endpoints (no auth header at all) --

    def test_get_file_list_no_auth(self):
        req = urllib.request.Request(f"{self.base_url}/api/files")
        self._assert_401(req, "GET /api/files")

    def test_get_pad_no_auth(self):
        req = urllib.request.Request(f"{self.base_url}/api/pad")
        self._assert_401(req, "GET /api/pad")

    def test_get_preview_no_auth(self):
        req = urllib.request.Request(f"{self.base_url}/api/preview/current")
        self._assert_401(req, "GET /api/preview/current")

    def test_get_clients_no_auth(self):
        req = urllib.request.Request(f"{self.base_url}/api/clients")
        self._assert_401(req, "GET /api/clients")

    def test_download_no_auth(self):
        req = urllib.request.Request(f"{self.base_url}/download/nonexistent-id")
        self._assert_401(req, "GET /download/<id>")

    # -- POST endpoints (no auth header at all) --

    def test_post_upload_no_auth(self):
        boundary = "----TestBoundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"hello\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/upload",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        self._assert_401(req, "POST /api/upload")

    def test_post_pad_no_auth(self):
        data = json.dumps({"content": "test"}).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/pad",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        self._assert_401(req, "POST /api/pad")

    def test_post_preview_set_no_auth(self):
        data = json.dumps({"file_id": "fake"}).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/preview/set",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        self._assert_401(req, "POST /api/preview/set")

    def test_post_register_no_auth(self):
        data = json.dumps({"client_id": "x", "client_secret": "y"}).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/clients/register",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        self._assert_401(req, "POST /api/clients/register")

    # -- DELETE endpoints (no auth header at all) --

    def test_delete_client_no_auth(self):
        req = urllib.request.Request(
            f"{self.base_url}/api/clients/some-id",
            method="DELETE",
        )
        self._assert_401(req, "DELETE /api/clients/<id>")

    # -- Bad credentials (garbage token) --

    def test_get_files_bad_token(self):
        req = urllib.request.Request(f"{self.base_url}/api/files")
        req.add_header("Authorization", "Bearer badid:badsecret")
        self._assert_401(req, "GET /api/files with bad token")

    def test_get_files_malformed_token(self):
        """Non-hex secret, should be rejected by charset validation."""
        req = urllib.request.Request(f"{self.base_url}/api/files")
        req.add_header("Authorization", "Bearer id:not!hex@chars")
        self._assert_401(req, "GET /api/files with malformed token")

    def test_get_files_no_colon(self):
        req = urllib.request.Request(f"{self.base_url}/api/files")
        req.add_header("Authorization", "Bearer tokenwithnocolon")
        self._assert_401(req, "GET /api/files with no colon in token")

    def test_get_files_empty_bearer(self):
        req = urllib.request.Request(f"{self.base_url}/api/files")
        req.add_header("Authorization", "Bearer ")
        self._assert_401(req, "GET /api/files with empty bearer")

    # -- Verify index page is still public --

    def test_index_page_no_auth(self):
        """The HTML index page should remain publicly accessible."""
        req = urllib.request.Request(f"{self.base_url}/")
        with urllib.request.urlopen(req) as response:
            self.assertEqual(response.status, 200)
            body = response.read().decode()
            self.assertIn("Companion", body)


class TestTokenCharsetValidation(unittest.TestCase):
    """Verify _authenticate rejects malformed tokens before CLIENTS lookup."""

    @classmethod
    def setUpClass(cls):
        cls.port = 8896
        cls.client_id = "charset-test"
        cls.client_secret = secrets.token_hex(32)
        cls.auth_token = f"{cls.client_id}:{cls.client_secret}"
        cls.base_url = f"http://localhost:{cls.port}"

        companion.FILES.clear()
        companion.PREVIEW_STATE = {"file_id": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}
        companion.RATE_LIMIT_STORE.clear()

        with companion.CLIENTS_LOCK:
            companion.CLIENTS.clear()
            companion.CLIENTS[cls.client_id] = _make_client_entry(cls.client_secret)

        def run_server():
            server_address = ("127.0.0.1", cls.port)
            httpd = companion.http.server.HTTPServer(server_address, companion.FileShareHandler)
            httpd.allow_reuse_address = True
            cls.httpd = httpd
            httpd.serve_forever()

        cls.server_thread = threading.Thread(target=run_server, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "httpd"):
            cls.httpd.shutdown()
            cls.httpd.server_close()

    def setUp(self):
        with companion.RATE_LIMIT_LOCK:
            companion.RATE_LIMIT_STORE.clear()
        patcher = patch.object(companion.FileShareHandler, "log_message", lambda self_, fmt, *a: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _get_files(self, auth_value):
        req = urllib.request.Request(f"{self.base_url}/api/files")
        req.add_header("Authorization", auth_value)
        return urllib.request.urlopen(req)

    def test_valid_credentials_succeed(self):
        resp = self._get_files(f"Bearer {self.auth_token}")
        self.assertEqual(resp.status, 200)

    def test_uppercase_hex_rejected(self):
        """Secrets are lowercase hex; uppercase must fail."""
        bad_secret = self.client_secret.upper()
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get_files(f"Bearer {self.client_id}:{bad_secret}")
        self.assertEqual(cm.exception.code, 401)

    def test_special_chars_in_id_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get_files(f"Bearer id_with spaces:{self.client_secret}")
        self.assertEqual(cm.exception.code, 401)

    def test_sql_injection_in_id_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get_files(f"Bearer ' OR 1=1--:{self.client_secret}")
        self.assertEqual(cm.exception.code, 401)

    def test_empty_id_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get_files(f"Bearer :{self.client_secret}")
        self.assertEqual(cm.exception.code, 401)

    def test_empty_secret_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get_files(f"Bearer {self.client_id}:")
        self.assertEqual(cm.exception.code, 401)


if __name__ == "__main__":
    unittest.main()
