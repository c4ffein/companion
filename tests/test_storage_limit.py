#!/usr/bin/env python3
"""
Unit tests for per-client storage limits
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


class TestStorageLimit(unittest.TestCase):
    """Test per-client storage limits"""

    @classmethod
    def setUpClass(cls):
        """Start server in background thread"""
        cls.port = 8891
        cls.client_id = "test-storage-id"
        cls.client_secret = "test-storage-secret"
        cls.auth_token = f"{cls.client_id}:{cls.client_secret}"
        cls.base_url = f"http://localhost:{cls.port}"

        # Reset global state
        companion.FILES.clear()
        companion.PREVIEW_STATE = {"file_id": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}
        companion.RATE_LIMIT_STORE.clear()

        with companion.CLIENTS_LOCK:
            companion.CLIENTS.clear()
            companion.CLIENTS[cls.client_id] = _make_client_entry(cls.client_secret, admin=True, name="test-storage")

        # Set a very small storage limit for testing
        cls._original_limit = companion.MAX_STORAGE_PER_CLIENT
        companion.MAX_STORAGE_PER_CLIENT = 1024  # 1KB

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
        companion.MAX_STORAGE_PER_CLIENT = cls._original_limit
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

    def _upload(self, filename, content):
        """Helper to upload a file via multipart"""
        boundary = "----TestBoundary123"
        body = (
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + content
            + f"\r\n--{boundary}--\r\n".encode()
        )
        req = urllib.request.Request(
            f"{self.base_url}/api/upload",
            data=body,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        return urllib.request.urlopen(req)

    def test_upload_within_limit(self):  # TODO review
        """Test that upload within storage limit succeeds"""
        response = self._upload("small.bin", b"x" * 500)
        result = json.loads(response.read().decode())
        self.assertTrue(result["success"])

    def test_upload_exceeds_limit(self):  # TODO review
        """Test that upload exceeding storage limit returns 413"""
        # First upload fills most of the limit
        self._upload("first.bin", b"x" * 800)

        # Second upload should exceed the 1KB limit
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._upload("second.bin", b"x" * 500)
        self.assertEqual(cm.exception.code, 413)


if __name__ == "__main__":
    unittest.main()
