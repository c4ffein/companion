#!/usr/bin/env python3
"""
End-to-end tests for companion.py
Tests orchestrate a real server and multiple clients
"""

import json
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import urllib.error
from pathlib import Path


class FileShareE2ETest(unittest.TestCase):
    """End-to-end tests with real server and clients"""

    @classmethod
    def setUpClass(cls):
        """Start the file share server"""
        cls.port = 8765
        cls.api_key = "test-api-key-123"
        cls.server_url = f"http://localhost:{cls.port}"

        # Start server in background
        cls.server_process = subprocess.Popen(
            [
                sys.executable,
                "companion.py",
                "server",
                "--port",
                str(cls.port),
                "--api-key",
                cls.api_key,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for server to be ready
        max_retries = 20
        for i in range(max_retries):
            try:
                urllib.request.urlopen(f"{cls.server_url}/", timeout=1)
                print(f"✓ Server ready on port {cls.port}")
                break
            except (urllib.error.URLError, OSError):
                if i == max_retries - 1:
                    cls.server_process.kill()
                    raise Exception("Server failed to start")
                time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        """Stop the server"""
        cls.server_process.terminate()
        cls.server_process.wait(timeout=5)
        print("✓ Server stopped")

    def test_01_server_responds_to_index(self):
        """Test that server serves the main page"""
        response = urllib.request.urlopen(f"{self.server_url}/")
        html = response.read().decode()

        self.assertEqual(response.status, 200)
        self.assertIn("Companion", html)
        self.assertIn("Upload File", html)
        self.assertIn("Available Files", html)

    def test_02_empty_file_list(self):
        """Test that file list is initially empty"""
        response = urllib.request.urlopen(f"{self.server_url}/api/files")
        files = json.loads(response.read().decode())

        self.assertEqual(response.status, 200)
        self.assertEqual(files, [])

    def test_03_upload_via_client(self):
        """Test uploading a file using the client command"""
        # Create a temporary test file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Hello from client test!")
            test_file = f.name

        try:
            # Upload using client
            result = subprocess.run(
                [
                    sys.executable,
                    "companion.py",
                    "client",
                    self.server_url,
                    test_file,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, f"Client failed: {result.stderr}")
            self.assertIn("Upload successful", result.stdout)

            # Verify file appears in file list
            response = urllib.request.urlopen(f"{self.server_url}/api/files")
            files = json.loads(response.read().decode())

            self.assertEqual(len(files), 1)
            self.assertEqual(files[0]["name"], Path(test_file).name)
            self.assertGreater(files[0]["size"], 0)
            self.assertIn("uploaded", files[0])

        finally:
            Path(test_file).unlink()

    def test_04_upload_with_wrong_api_key(self):
        """Test that upload fails with wrong API key"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("This should not upload")
            test_file = f.name

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "companion.py",
                    "client",
                    self.server_url,
                    test_file,
                    "--api-key",
                    "wrong-key",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("failed", result.stdout.lower())

        finally:
            Path(test_file).unlink()

    def test_05_download_uploaded_file(self):
        """Test downloading a file that was uploaded"""
        test_content = b"Test content for download"
        test_filename = "test_download.bin"

        # Inject file directly into server's memory (simulate upload)
        # We'll use the upload API for this
        boundary = "----TestBoundary123"
        body = (
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{test_filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + test_content
            + f"\r\n--{boundary}--\r\n".encode()
        )

        req = urllib.request.Request(
            f"{self.server_url}/api/upload",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )

        response = urllib.request.urlopen(req)
        result = json.loads(response.read().decode())
        self.assertTrue(result["success"])

        # Now download it
        download_url = f"{self.server_url}/download/{test_filename}"
        response = urllib.request.urlopen(download_url)
        downloaded_content = response.read()

        self.assertEqual(downloaded_content, test_content)
        self.assertEqual(response.status, 200)

    def test_06_download_nonexistent_file(self):
        """Test that downloading nonexistent file returns 404"""
        try:
            urllib.request.urlopen(f"{self.server_url}/download/does-not-exist.txt")
            self.fail("Should have raised HTTPError")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)

    def test_07_multiple_clients_upload(self):
        """Test multiple clients uploading simultaneously"""
        num_clients = 3
        test_files = []

        # Create test files
        for i in range(num_clients):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=f"_client{i}.txt", delete=False
            ) as f:
                f.write(f"Content from client {i}")
                test_files.append(f.name)

        try:
            # Upload from multiple clients in parallel
            processes = []
            for test_file in test_files:
                proc = subprocess.Popen(
                    [
                        sys.executable,
                        "companion.py",
                        "client",
                        self.server_url,
                        test_file,
                        "--api-key",
                        self.api_key,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                processes.append(proc)

            # Wait for all to complete
            results = [proc.wait(timeout=10) for proc in processes]

            # All should succeed
            for i, returncode in enumerate(results):
                self.assertEqual(returncode, 0, f"Client {i} failed")

            # Verify all files are present
            time.sleep(0.5)  # Give server a moment
            response = urllib.request.urlopen(f"{self.server_url}/api/files")
            files = json.loads(response.read().decode())

            filenames = [f["name"] for f in files]
            for test_file in test_files:
                self.assertIn(Path(test_file).name, filenames)

        finally:
            for test_file in test_files:
                Path(test_file).unlink()

    def test_08_upload_binary_file(self):
        """Test uploading a binary file with various byte values"""
        # Create binary file with full byte range
        test_content = bytes(range(256)) * 100  # 25.6 KB

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(test_content)
            test_file = f.name

        try:
            # Upload
            result = subprocess.run(
                [
                    sys.executable,
                    "companion.py",
                    "client",
                    self.server_url,
                    test_file,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0)

            # Download and verify
            filename = Path(test_file).name
            download_url = f"{self.server_url}/download/{filename}"
            response = urllib.request.urlopen(download_url)
            downloaded_content = response.read()

            self.assertEqual(downloaded_content, test_content)
            self.assertEqual(len(downloaded_content), len(test_content))

        finally:
            Path(test_file).unlink()

    def test_09_special_characters_in_filename(self):
        """Test uploading files with special characters in filename"""
        special_names = [
            "file with spaces.txt",
            "file-with-dashes.txt",
            "file_with_underscores.txt",
            "file.multiple.dots.txt",
        ]

        created_files = []

        try:
            for name in special_names:
                # Create file
                filepath = Path(tempfile.gettempdir()) / name
                filepath.write_text(f"Content of {name}")
                created_files.append(filepath)

                # Upload
                result = subprocess.run(
                    [
                        sys.executable,
                        "companion.py",
                        "client",
                        self.server_url,
                        str(filepath),
                        "--api-key",
                        self.api_key,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                self.assertEqual(result.returncode, 0, f"Failed to upload {name}")

            # Verify all files are listed
            response = urllib.request.urlopen(f"{self.server_url}/api/files")
            files = json.loads(response.read().decode())
            filenames = [f["name"] for f in files]

            for name in special_names:
                self.assertIn(name, filenames)

        finally:
            for filepath in created_files:
                filepath.unlink(missing_ok=True)

    def test_10_file_metadata(self):
        """Test that file metadata (size, mimetype, timestamp) is correct"""
        test_content = "Test metadata content"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(test_content)
            test_file = f.name

        try:
            # Upload
            result = subprocess.run(
                [
                    sys.executable,
                    "companion.py",
                    "client",
                    self.server_url,
                    test_file,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0)

            # Check metadata
            response = urllib.request.urlopen(f"{self.server_url}/api/files")
            files = json.loads(response.read().decode())

            uploaded_file = next(f for f in files if f["name"] == Path(test_file).name)

            self.assertEqual(uploaded_file["size"], len(test_content.encode()))
            self.assertIn("mimetype", uploaded_file)
            self.assertIn("uploaded", uploaded_file)

            # Verify timestamp is recent (within last minute)
            from datetime import datetime

            upload_time = datetime.fromisoformat(uploaded_file["uploaded"])
            now = datetime.now()
            self.assertLess((now - upload_time).total_seconds(), 60)

        finally:
            Path(test_file).unlink()


def run_tests():
    """Run the test suite"""
    # Change to script directory
    import os

    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    # Run tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(FileShareE2ETest)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    import sys

    success = run_tests()
    sys.exit(0 if success else 1)
