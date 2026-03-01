#!/usr/bin/env python3
"""
Unit tests for pad API and CLI
"""

import hashlib
import io
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


class TestPadAPI(unittest.TestCase):
    """Test pad API endpoints"""

    @classmethod
    def setUpClass(cls):
        """Start server in background thread"""
        cls.port = 8888
        cls.client_id = "test-client-id"
        cls.client_secret = secrets.token_hex(32)
        cls.auth_token = f"{cls.client_id}:{cls.client_secret}"
        cls.base_url = f"http://localhost:{cls.port}"

        # Reset global state
        companion.FILES.clear()
        companion.PREVIEW_STATE = {"file_id": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}
        companion.RATE_LIMIT_STORE.clear()

        # Set up test client in CLIENTS with proper hashed secret
        with companion.CLIENTS_LOCK:
            companion.CLIENTS.clear()
            companion.CLIENTS[cls.client_id] = _make_client_entry(cls.client_secret, admin=True, name="test-pad")

        # Start server in thread
        def run_server():
            server_address = ("127.0.0.1", cls.port)
            httpd = companion.http.server.HTTPServer(server_address, companion.FileShareHandler)
            httpd.allow_reuse_address = True
            cls.httpd = httpd
            httpd.serve_forever()

        cls.server_thread = threading.Thread(target=run_server, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)  # Give server time to start

    @classmethod
    def tearDownClass(cls):
        """Stop server"""
        if hasattr(cls, "httpd"):
            cls.httpd.shutdown()
            cls.httpd.server_close()

    def setUp(self):
        """Reset pad state before each test"""
        with companion.WORKSPACE_LOCK:
            companion.PAD_STATE["content"] = ""
            companion.PAD_STATE["timestamp"] = 0
        with companion.RATE_LIMIT_LOCK:
            companion.RATE_LIMIT_STORE.clear()
        self.request_log = []
        patcher = patch.object(
            companion.FileShareHandler, "log_message", lambda self_, fmt, *a: self.request_log.append(fmt % a)
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_get_pad_empty(self):
        """Test getting empty pad content"""
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        req = urllib.request.Request(f"{self.base_url}/api/pad", headers=headers)
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertEqual(result["content"], "")
            self.assertEqual(result["timestamp"], 0)

    def test_post_pad_success(self):
        """Test posting pad content with valid credentials"""
        data = json.dumps({"content": "Hello, World!"}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")

        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])
            self.assertGreater(result["timestamp"], 0)
            self.assertEqual(result["size"], 13)

    def test_post_pad_unauthorized(self):
        """Test posting pad content with invalid credentials"""
        data = json.dumps({"content": "Should fail"}).encode("utf-8")
        headers = {
            "Authorization": "Bearer wrong_id:wrong_secret",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")

        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 401)

    def test_post_and_get_pad(self):
        """Test posting content and retrieving it"""
        content = "Test content for pad"
        data = json.dumps({"content": content}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }

        # Post content
        req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            timestamp = result["timestamp"]

        # Get content
        get_headers = {"Authorization": f"Bearer {self.auth_token}"}
        req = urllib.request.Request(f"{self.base_url}/api/pad", headers=get_headers)
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertEqual(result["content"], content)
            self.assertEqual(result["timestamp"], timestamp)

    def test_pad_timestamp_increments(self):
        """Test that pad timestamp increments on each update"""
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }

        timestamps = []
        for i in range(3):
            data = json.dumps({"content": f"Content {i}"}).encode("utf-8")
            req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode())
                timestamps.append(result["timestamp"])

        # Verify timestamps are strictly monotonically increasing
        for i in range(1, len(timestamps)):
            self.assertGreater(
                timestamps[i],
                timestamps[i - 1],
                f"Timestamps should be strictly increasing: {timestamps}",
            )

    def test_pad_size_limit(self):
        """Test that pad rejects content over size limit"""
        # Create content larger than 10MB
        large_content = "x" * (10 * 1024 * 1024 + 1)
        data = json.dumps({"content": large_content}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")

        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 413)  # Request Entity Too Large

    def test_pad_size_exactly_at_limit(self):
        """Test that pad accepts content exactly at the 10MB limit"""
        content = "x" * (10 * 1024 * 1024)
        data = json.dumps({"content": content}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])
            self.assertEqual(result["size"], 10 * 1024 * 1024)

    def test_pad_body_rejected_before_full_read(self):
        """Test that an oversized request body is rejected at the HTTP level (413)
        via Content-Length check, not just after parsing the JSON content."""
        import http.client

        # Claim a Content-Length larger than PAD_MAX_SIZE + 1KB overhead —
        # _read_body should reject based on Content-Length before reading
        oversized_length = 10 * 1024 * 1024 + 2048
        conn = http.client.HTTPConnection("localhost", self.port)
        conn.putrequest("POST", "/api/pad")
        conn.putheader("Authorization", f"Bearer {self.auth_token}")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(oversized_length))
        conn.endheaders(b"")  # send headers only, no body
        resp = conn.getresponse()
        self.assertEqual(resp.status, 413)
        conn.close()

    def test_pad_unicode_content(self):
        """Test pad with unicode characters"""
        content = "Hello 世界! 🌍 émojis and spëcial çhars"
        data = json.dumps({"content": content}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }

        # Post unicode content
        req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])

        # Get and verify unicode content
        get_headers = {"Authorization": f"Bearer {self.auth_token}"}
        req = urllib.request.Request(f"{self.base_url}/api/pad", headers=get_headers)
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertEqual(result["content"], content)

    def test_pad_empty_content(self):
        """Test posting empty content to clear pad"""
        # First post some content
        data = json.dumps({"content": "Some content"}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")
        urllib.request.urlopen(req)

        # Clear with empty content
        data = json.dumps({"content": ""}).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])
            self.assertEqual(result["size"], 0)

        # Verify empty
        get_headers = {"Authorization": f"Bearer {self.auth_token}"}
        req = urllib.request.Request(f"{self.base_url}/api/pad", headers=get_headers)
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertEqual(result["content"], "")


class TestPadCLI(unittest.TestCase):
    """Test pad CLI commands"""

    @classmethod
    def setUpClass(cls):
        """Start server in background thread"""
        cls.port = 8889
        cls.client_id = "test-cli-id"
        cls.client_secret = secrets.token_hex(32)
        cls.auth_token = f"{cls.client_id}:{cls.client_secret}"
        cls.base_url = f"http://localhost:{cls.port}"

        # Reset global state
        companion.FILES.clear()
        companion.PREVIEW_STATE = {"file_id": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}
        companion.RATE_LIMIT_STORE.clear()

        # Set up test client in CLIENTS with proper hashed secret
        with companion.CLIENTS_LOCK:
            companion.CLIENTS.clear()
            companion.CLIENTS[cls.client_id] = _make_client_entry(cls.client_secret, admin=True, name="test-pad-cli")

        # Start server in thread
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
        """Stop server"""
        if hasattr(cls, "httpd"):
            cls.httpd.shutdown()
            cls.httpd.server_close()

    def setUp(self):
        """Reset pad state before each test"""
        with companion.WORKSPACE_LOCK:
            companion.PAD_STATE["content"] = ""
            companion.PAD_STATE["timestamp"] = 0
        with companion.RATE_LIMIT_LOCK:
            companion.RATE_LIMIT_STORE.clear()
        self.request_log = []
        patcher = patch.object(
            companion.FileShareHandler, "log_message", lambda self_, fmt, *a: self.request_log.append(fmt % a)
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_get_pad_cli(self, mock_stdout):
        """Test get-pad CLI command"""
        # First set some content via API
        content = "CLI test content"
        data = json.dumps({"content": content}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(f"{self.base_url}/api/pad", data=data, headers=headers, method="POST")
        urllib.request.urlopen(req)

        # Test get-pad CLI
        result = companion.get_pad(self.base_url, self.auth_token)
        self.assertTrue(result)

    @patch("sys.stdout", new_callable=io.StringIO)
    def test_set_pad_cli(self, mock_stdout):
        """Test set-pad CLI command"""
        content = "Content from CLI"
        result = companion.set_pad(self.base_url, content, self.auth_token)
        self.assertTrue(result)

        # Verify via API
        get_headers = {"Authorization": f"Bearer {self.auth_token}"}
        req = urllib.request.Request(f"{self.base_url}/api/pad", headers=get_headers)
        with urllib.request.urlopen(req) as response:
            api_result = json.loads(response.read().decode())
            self.assertEqual(api_result["content"], content)


if __name__ == "__main__":
    unittest.main()
