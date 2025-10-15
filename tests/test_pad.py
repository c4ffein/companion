#!/usr/bin/env python3
"""
Unit tests for Companion
"""

import json
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from io import BytesIO

# Import the companion module
sys.path.insert(0, "src")
import companion


class TestPadAPI(unittest.TestCase):
    """Test pad API endpoints"""

    @classmethod
    def setUpClass(cls):
        """Start server in background thread"""
        cls.port = 8888
        cls.api_key = "test_key_123"
        cls.base_url = f"http://localhost:{cls.port}"

        # Reset global state
        companion.FILES.clear()
        companion.PREVIEW_STATE = {"filename": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}

        # Start server in thread
        def run_server():
            companion.API_KEY = cls.api_key
            server_address = ("127.0.0.1", cls.port)
            httpd = companion.http.server.HTTPServer(
                server_address, companion.FileShareHandler
            )
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

    def setUp(self):
        """Reset pad state before each test"""
        with companion.PAD_LOCK:
            companion.PAD_STATE["content"] = ""
            companion.PAD_STATE["timestamp"] = 0

    def test_get_pad_empty(self):
        """Test getting empty pad content"""
        req = urllib.request.Request(f"{self.base_url}/api/pad")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertEqual(result["content"], "")
            self.assertEqual(result["timestamp"], 0)

    def test_post_pad_success(self):
        """Test posting pad content with valid API key"""
        data = json.dumps({"content": "Hello, World!"}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(
            f"{self.base_url}/api/pad", data=data, headers=headers, method="POST"
        )

        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])
            self.assertEqual(result["timestamp"], 1)
            self.assertEqual(result["size"], 13)

    def test_post_pad_unauthorized(self):
        """Test posting pad content with invalid API key"""
        data = json.dumps({"content": "Should fail"}).encode("utf-8")
        headers = {
            "Authorization": "Bearer wrong_key",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(
            f"{self.base_url}/api/pad", data=data, headers=headers, method="POST"
        )

        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 401)

    def test_post_and_get_pad(self):
        """Test posting content and retrieving it"""
        content = "Test content for pad"
        data = json.dumps({"content": content}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        # Post content
        req = urllib.request.Request(
            f"{self.base_url}/api/pad", data=data, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            timestamp = result["timestamp"]

        # Get content
        req = urllib.request.Request(f"{self.base_url}/api/pad")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertEqual(result["content"], content)
            self.assertEqual(result["timestamp"], timestamp)

    def test_pad_timestamp_increments(self):
        """Test that pad timestamp increments on each update"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        timestamps = []
        for i in range(3):
            data = json.dumps({"content": f"Content {i}"}).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/pad", data=data, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode())
                timestamps.append(result["timestamp"])

        # Verify timestamps increment
        self.assertEqual(timestamps, [1, 2, 3])

    def test_pad_size_limit(self):
        """Test that pad rejects content over size limit"""
        # Create content larger than 10MB
        large_content = "x" * (10 * 1024 * 1024 + 1)
        data = json.dumps({"content": large_content}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(
            f"{self.base_url}/api/pad", data=data, headers=headers, method="POST"
        )

        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 413)  # Request Entity Too Large

    def test_pad_unicode_content(self):
        """Test pad with unicode characters"""
        content = "Hello 世界! 🌍 émojis and spëcial çhars"
        data = json.dumps({"content": content}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        # Post unicode content
        req = urllib.request.Request(
            f"{self.base_url}/api/pad", data=data, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])

        # Get and verify unicode content
        req = urllib.request.Request(f"{self.base_url}/api/pad")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertEqual(result["content"], content)

    def test_pad_empty_content(self):
        """Test posting empty content to clear pad"""
        # First post some content
        data = json.dumps({"content": "Some content"}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(
            f"{self.base_url}/api/pad", data=data, headers=headers, method="POST"
        )
        urllib.request.urlopen(req)

        # Clear with empty content
        data = json.dumps({"content": ""}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/pad", data=data, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])
            self.assertEqual(result["size"], 0)

        # Verify empty
        req = urllib.request.Request(f"{self.base_url}/api/pad")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertEqual(result["content"], "")


class TestPadCLI(unittest.TestCase):
    """Test pad CLI commands"""

    @classmethod
    def setUpClass(cls):
        """Start server in background thread"""
        cls.port = 8889
        cls.api_key = "test_key_456"
        cls.base_url = f"http://localhost:{cls.port}"

        # Reset global state
        companion.FILES.clear()
        companion.PREVIEW_STATE = {"filename": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}

        # Start server in thread
        def run_server():
            companion.API_KEY = cls.api_key
            server_address = ("127.0.0.1", cls.port)
            httpd = companion.http.server.HTTPServer(
                server_address, companion.FileShareHandler
            )
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

    def setUp(self):
        """Reset pad state before each test"""
        with companion.PAD_LOCK:
            companion.PAD_STATE["content"] = ""
            companion.PAD_STATE["timestamp"] = 0

    def test_get_pad_cli(self):
        """Test get-pad CLI command"""
        # First set some content via API
        content = "CLI test content"
        data = json.dumps({"content": content}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(
            f"{self.base_url}/api/pad", data=data, headers=headers, method="POST"
        )
        urllib.request.urlopen(req)

        # Test get-pad CLI
        result = companion.get_pad(self.base_url)
        self.assertTrue(result)

    def test_set_pad_cli(self):
        """Test set-pad CLI command"""
        content = "Content from CLI"
        result = companion.set_pad(self.base_url, content, self.api_key)
        self.assertTrue(result)

        # Verify via API
        req = urllib.request.Request(f"{self.base_url}/api/pad")
        with urllib.request.urlopen(req) as response:
            api_result = json.loads(response.read().decode())
            self.assertEqual(api_result["content"], content)


if __name__ == "__main__":
    unittest.main()
