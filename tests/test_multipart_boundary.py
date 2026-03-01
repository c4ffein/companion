#!/usr/bin/env python3
"""
Unit tests for multipart boundary parsing
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

# Import the companion module
sys.path.insert(0, "src")
import companion


def _make_client_entry(client_secret, admin=True, name="test"):
    """Create a properly hashed client entry for CLIENTS."""
    salt = secrets.token_hex(16)
    secret_hash = hashlib.sha256((salt + client_secret).encode()).hexdigest()
    return {
        "salt": salt,
        "secret_hash": secret_hash,
        "admin": admin,
        "name": name,
        "registered": "2026-01-01T00:00:00",
    }


class TestMultipartBoundary(unittest.TestCase):
    """Test multipart boundary parsing in upload handler"""

    @classmethod
    def setUpClass(cls):
        """Start server in background thread"""
        cls.port = 8893
        cls.client_id = "test-boundary-id"
        cls.client_secret = secrets.token_hex(32)
        cls.auth_token = f"{cls.client_id}:{cls.client_secret}"
        cls.base_url = f"http://localhost:{cls.port}"

        # Reset global state
        companion.FILES.clear()
        companion.PREVIEW_STATE = {"file_id": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}
        companion.RATE_LIMIT_STORE.clear()

        with companion.CLIENTS_LOCK:
            companion.CLIENTS.clear()
            companion.CLIENTS[cls.client_id] = _make_client_entry(cls.client_secret, admin=True, name="test-boundary")

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
        companion.FILES.clear()
        with companion.RATE_LIMIT_LOCK:
            companion.RATE_LIMIT_STORE.clear()
        self.request_log = []
        patcher = patch.object(
            companion.FileShareHandler, "log_message", lambda self_, fmt, *a: self.request_log.append(fmt % a)
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _upload_with_boundary(self, boundary_in_body, content_type_boundary):
        """Upload a file with explicit control over boundary in body vs Content-Type header."""
        content = b"test file content"
        body = (
            (
                f"--{boundary_in_body}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
                f"Content-Type: text/plain\r\n\r\n"
            ).encode()
            + content
            + f"\r\n--{boundary_in_body}--\r\n".encode()
        )
        req = urllib.request.Request(
            f"{self.base_url}/api/upload",
            data=body,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": f"multipart/form-data; boundary={content_type_boundary}",
            },
        )
        return urllib.request.urlopen(req)

    # --- Bare boundary (token form) ---

    def test_bare_boundary(self):
        """boundary=abcdef — standard bare token"""
        response = self._upload_with_boundary("abcdef", "abcdef")
        result = json.loads(response.read().decode())
        self.assertTrue(result["success"])

    def test_bare_boundary_with_dashes(self):
        """boundary=----WebKitFormBoundary — typical browser boundary"""
        b = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        response = self._upload_with_boundary(b, b)
        result = json.loads(response.read().decode())
        self.assertTrue(result["success"])

    # --- Quoted boundary ---

    def test_quoted_boundary(self):
        """boundary="abcdef" — quoted form, value is abcdef"""
        response = self._upload_with_boundary("abcdef", '"abcdef"')
        result = json.loads(response.read().decode())
        self.assertTrue(result["success"])

    def test_quoted_boundary_with_tspecials(self):
        """boundary="gc0pJq0M:08jU534c0p" — colon requires quoting per RFC 2045"""
        b = "gc0pJq0M:08jU534c0p"
        response = self._upload_with_boundary(b, f'"{b}"')
        result = json.loads(response.read().decode())
        self.assertTrue(result["success"])

    # --- Malformed boundary ---

    def test_malformed_boundary_unclosed_quote(self):
        """boundary="abcdef — unclosed quote, should return 400"""
        body = (
            b"--abcdef\r\n"
            b'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n"
            b"content\r\n"
            b"--abcdef--\r\n"
        )
        req = urllib.request.Request(
            f"{self.base_url}/api/upload",
            data=body,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": 'multipart/form-data; boundary="abcdef',
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)
        error = json.loads(cm.exception.read().decode())
        self.assertIn("Malformed boundary", error["error"])

    def test_malformed_boundary_garbage_after_quote(self):
        """boundary="abc"def" — garbage after closing quote, should return 400"""
        body = (
            b"--abcdef\r\n"
            b'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n"
            b"content\r\n"
            b"--abcdef--\r\n"
        )
        req = urllib.request.Request(
            f"{self.base_url}/api/upload",
            data=body,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": 'multipart/form-data; boundary="abc"def"',
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)
        error = json.loads(cm.exception.read().decode())
        self.assertIn("Malformed boundary", error["error"])

    def test_no_boundary(self):
        """No boundary parameter at all — should return 400 with 'No boundary found'"""
        body = b"some data"
        req = urllib.request.Request(
            f"{self.base_url}/api/upload",
            data=body,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "multipart/form-data",
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)
        error = json.loads(cm.exception.read().decode())
        self.assertEqual(error["error"], "No boundary found")


if __name__ == "__main__":
    unittest.main()
