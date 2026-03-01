#!/usr/bin/env python3
"""
Unit tests for rate limiting
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


class TestRateLimit(unittest.TestCase):
    """Test rate limiting by manipulating RATE_LIMIT_STORE directly"""

    @classmethod
    def setUpClass(cls):
        """Start server in background thread"""
        cls.port = 8890
        cls.client_id = "test-rate-id"
        cls.client_secret = secrets.token_hex(32)
        cls.auth_token = f"{cls.client_id}:{cls.client_secret}"
        cls.base_url = f"http://localhost:{cls.port}"

        # Reset global state
        companion.FILES.clear()
        companion.PREVIEW_STATE = {"file_id": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}

        with companion.CLIENTS_LOCK:
            companion.CLIENTS.clear()
            companion.CLIENTS[cls.client_id] = _make_client_entry(cls.client_secret, admin=True, name="test-rate")

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
            companion.FileShareHandler, "log_message", lambda self_, fmt, *a: self.request_log.append(fmt % a)
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_rate_limit_triggers_429(self):  # TODO review
        """Test that exceeding rate limit returns 429"""
        # Pre-fill the rate limit store for 127.0.0.1 with max entries
        now = time.monotonic()
        with companion.RATE_LIMIT_LOCK:
            companion.RATE_LIMIT_STORE["127.0.0.1"] = [now] * companion.RATE_LIMIT_MAX

        # Next request should be rejected
        data = json.dumps({"content": "rate limited"}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 429)

    def test_rate_limit_allows_under_max(self):  # TODO review
        """Test that requests under the limit succeed"""
        data = json.dumps({"content": "ok"}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])


if __name__ == "__main__":
    unittest.main()
