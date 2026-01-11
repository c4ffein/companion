#!/usr/bin/env python3
"""
End-to-end tests for companion.py
Tests orchestrate a real server and multiple clients
"""

import json
import os
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

    # Environment with UTF-8 encoding for subprocesses
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    @classmethod
    def setUpClass(cls):
        """Start the file share server"""
        cls.port = 8765
        cls.api_key = "test-api-key-123"
        cls.server_url = f"http://localhost:{cls.port}"

        # Determine which version to test (dev or built)
        # TEST_VERSION env var can be 'dev' or 'built' (default: 'dev')
        test_version = os.environ.get("TEST_VERSION", "dev")
        if test_version == "built":
            cls.companion_script = "companion.py"
            print("🧪 Testing BUILT version (companion.py)")
        else:
            cls.companion_script = "src/companion.py"
            print("🧪 Testing DEV version (src/companion.py)")

        # Start server in background
        cls.server_process = subprocess.Popen(
            [
                "python3",
                cls.companion_script,
                "server",
                "--port",
                str(cls.port),
                "--api-key",
                cls.api_key,
                "--debug",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=cls.env,
        )

        # Wait for server to be ready
        max_retries = 20
        for i in range(max_retries):
            # Check if process has died
            if cls.server_process.poll() is not None:
                stdout, stderr = cls.server_process.communicate()
                raise Exception(
                    f"Server process exited with code {cls.server_process.returncode}\n"
                    f"Stdout: {stdout}\n"
                    f"Stderr: {stderr}"
                )

            try:
                urllib.request.urlopen(f"{cls.server_url}/", timeout=1)
                print(f"✓ Server ready on port {cls.port}")
                break
            except (urllib.error.URLError, OSError):
                if i == max_retries - 1:
                    cls.server_process.kill()
                    stdout, stderr = cls.server_process.communicate(timeout=1)
                    raise Exception(
                        f"Server failed to start (still running but not responding)\nStdout: {stdout}\nStderr: {stderr}"
                    )
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
                    "python3",
                    self.companion_script,
                    "upload",
                    test_file,
                    "--server-url",
                    self.server_url,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
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
                    "python3",
                    self.companion_script,
                    "upload",
                    test_file,
                    "--server-url",
                    self.server_url,
                    "--api-key",
                    "wrong-key",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
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
            with tempfile.NamedTemporaryFile(mode="w", suffix=f"_client{i}.txt", delete=False) as f:
                f.write(f"Content from client {i}")
                test_files.append(f.name)

        try:
            # Upload from multiple clients in parallel
            processes = []
            for test_file in test_files:
                proc = subprocess.Popen(
                    [
                        "python3",
                        "src/companion.py",
                        "upload",
                        test_file,
                        "--server-url",
                        self.server_url,
                        "--api-key",
                        self.api_key,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    env=self.env,
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
                    "python3",
                    self.companion_script,
                    "upload",
                    test_file,
                    "--server-url",
                    self.server_url,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
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
                        "python3",
                        "src/companion.py",
                        "upload",
                        str(filepath),
                        "--server-url",
                        self.server_url,
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
                    "python3",
                    self.companion_script,
                    "upload",
                    test_file,
                    "--server-url",
                    self.server_url,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
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

    def test_11_preview_state_initial(self):
        """Test that initial preview state is empty"""
        response = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
        state = json.loads(response.read().decode())

        self.assertEqual(response.status, 200)
        self.assertEqual(state["filename"], None)
        self.assertEqual(state["timestamp"], 0)
        self.assertNotIn("mimetype", state)

    def test_12_set_preview_via_cli(self):
        """Test setting preview using the CLI command"""
        # First upload a file
        test_content = "Test content for preview"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(test_content)
            test_file = f.name

        try:
            # Upload file first
            upload_result = subprocess.run(
                [
                    "python3",
                    self.companion_script,
                    "upload",
                    test_file,
                    "--server-url",
                    self.server_url,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )
            self.assertEqual(upload_result.returncode, 0)

            filename = Path(test_file).name

            # Set preview using CLI
            result = subprocess.run(
                [
                    "python3",
                    self.companion_script,
                    "set-preview",
                    filename,
                    "--server-url",
                    self.server_url,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )

            self.assertEqual(result.returncode, 0, f"set-preview failed: {result.stderr}")
            self.assertIn("Preview set successfully", result.stdout)
            self.assertIn(filename, result.stdout)
            self.assertIn("Timestamp: 1", result.stdout)

            # Verify preview state via API
            response = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
            state = json.loads(response.read().decode())

            self.assertEqual(state["filename"], filename)
            self.assertEqual(state["timestamp"], 1)
            self.assertIn("mimetype", state)
            self.assertTrue(state["mimetype"].startswith("text/"))

        finally:
            Path(test_file).unlink()

    def test_13_set_preview_nonexistent_file(self):
        """Test that setting preview for nonexistent file fails"""
        result = subprocess.run(
            [
                "python3",
                "src/companion.py",
                "set-preview",
                "nonexistent-file.txt",
                "--server-url",
                self.server_url,
                "--api-key",
                self.api_key,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            env=self.env,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("File not found", result.stdout)

    def test_14_set_preview_wrong_api_key(self):
        """Test that setting preview with wrong API key fails"""
        result = subprocess.run(
            [
                "python3",
                "src/companion.py",
                "set-preview",
                "any-file.txt",
                "--server-url",
                self.server_url,
                "--api-key",
                "wrong-key",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            env=self.env,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid API key", result.stdout)

    def test_15_preview_timestamp_increments(self):
        """Test that preview timestamp increments atomically on each update"""
        # Get current timestamp first
        response_initial = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
        state_initial = json.loads(response_initial.read().decode())
        initial_timestamp = state_initial["timestamp"]

        # Upload two test files
        test_files = []
        for i in range(2):
            with tempfile.NamedTemporaryFile(mode="w", suffix=f"_preview{i}.txt", delete=False) as f:
                f.write(f"Preview content {i}")
                test_files.append(f.name)

        try:
            # Upload both files
            for test_file in test_files:
                result = subprocess.run(
                    [
                        "python3",
                        "src/companion.py",
                        "upload",
                        test_file,
                        "--server-url",
                        self.server_url,
                        "--api-key",
                        self.api_key,
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=10,
                    env=self.env,
                )
                self.assertEqual(result.returncode, 0)

            # Set preview to first file
            filename1 = Path(test_files[0]).name
            result1 = subprocess.run(
                [
                    "python3",
                    self.companion_script,
                    "set-preview",
                    filename1,
                    "--server-url",
                    self.server_url,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )
            self.assertEqual(result1.returncode, 0)

            # Check timestamp incremented by 1
            response1 = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
            state1 = json.loads(response1.read().decode())
            self.assertEqual(state1["timestamp"], initial_timestamp + 1)
            self.assertEqual(state1["filename"], filename1)

            # Set preview to second file
            filename2 = Path(test_files[1]).name
            result2 = subprocess.run(
                [
                    "python3",
                    self.companion_script,
                    "set-preview",
                    filename2,
                    "--server-url",
                    self.server_url,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )
            self.assertEqual(result2.returncode, 0)

            # Check timestamp incremented by 2 from initial
            response2 = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
            state2 = json.loads(response2.read().decode())
            self.assertEqual(state2["timestamp"], initial_timestamp + 2)
            self.assertEqual(state2["filename"], filename2)

        finally:
            for test_file in test_files:
                Path(test_file).unlink()

    def test_16_preview_direct_api_call(self):
        """Test setting preview via direct API call"""
        # Upload a test file
        test_content = "Direct API test"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(test_content)
            test_file = f.name
        try:
            # Upload
            result = subprocess.run(
                [
                    "python3",
                    self.companion_script,
                    "upload",
                    test_file,
                    "--server-url",
                    self.server_url,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )
            self.assertEqual(result.returncode, 0)
            filename = Path(test_file).name
            # Set preview via direct API call
            preview_data = json.dumps({"filename": filename}).encode()
            req = urllib.request.Request(
                f"{self.server_url}/api/preview/set",
                data=preview_data,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            response = urllib.request.urlopen(req)
            result_json = json.loads(response.read().decode())
            self.assertEqual(response.status, 200)
            self.assertTrue(result_json["success"])
            self.assertEqual(result_json["filename"], filename)
            self.assertGreater(result_json["timestamp"], 0)
            # Verify state
            state_response = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
            state = json.loads(state_response.read().decode())
            self.assertEqual(state["filename"], filename)
            self.assertEqual(state["timestamp"], result_json["timestamp"])
        finally:
            Path(test_file).unlink()

    def test_17_preview_multiple_updates(self):
        """Test that multiple rapid preview updates maintain timestamp consistency"""
        # Upload multiple files
        test_files = []
        for i in range(5):
            with tempfile.NamedTemporaryFile(mode="w", suffix=f"_rapid{i}.txt", delete=False) as f:
                f.write(f"Rapid update {i}")
                test_files.append(f.name)

        try:
            # Upload all files
            filenames = []
            for test_file in test_files:
                result = subprocess.run(
                    [
                        "python3",
                        "src/companion.py",
                        "upload",
                        test_file,
                        "--server-url",
                        self.server_url,
                        "--api-key",
                        self.api_key,
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=10,
                    env=self.env,
                )
                self.assertEqual(result.returncode, 0)
                filenames.append(Path(test_file).name)
            # Set preview rapidly for each file
            timestamps = []
            for filename in filenames:
                preview_data = json.dumps({"filename": filename}).encode()
                req = urllib.request.Request(
                    f"{self.server_url}/api/preview/set",
                    data=preview_data,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                response = urllib.request.urlopen(req)
                result_json = json.loads(response.read().decode())
                timestamps.append(result_json["timestamp"])
            # Verify timestamps increment monotonically
            for i in range(1, len(timestamps)):
                self.assertEqual(
                    timestamps[i],
                    timestamps[i - 1] + 1,
                    f"Timestamp should increment by 1: {timestamps}",
                )
            # Verify final state
            state_response = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
            state = json.loads(state_response.read().decode())
            self.assertEqual(state["filename"], filenames[-1])
            self.assertEqual(state["timestamp"], timestamps[-1])
        finally:
            for test_file in test_files:
                Path(test_file).unlink()

    def test_18_deps_pdfjs_lib_serves_exact_file(self):
        """Test that /deps/pdf.min.mjs serves the exact cached PDF.js library (built version only)"""
        # Skip this test for dev version (it uses CDN)
        test_version = os.environ.get("TEST_VERSION", "dev")
        if test_version != "built":
            self.skipTest("This test only applies to the built version")
        # Read the cached PDF.js library file
        cache_path = Path("js_deps/pdf.min.mjs")
        self.assertTrue(cache_path.exists(), "Cached PDF.js library not found")

        with open(cache_path, "r", encoding="utf-8") as f:
            expected_content = f.read()
        # Fetch from /deps/ endpoint
        response = urllib.request.urlopen(f"{self.server_url}/deps/pdf.min.mjs")
        served_content = response.read().decode("utf-8")
        # Verify they match exactly
        self.assertEqual(response.status, 200)
        self.assertEqual(
            len(served_content),
            len(expected_content),
            f"Size mismatch: served {len(served_content)} bytes, expected {len(expected_content)} bytes",
        )
        self.assertEqual(
            served_content,
            expected_content,
            "Served PDF.js library does not match cached file",
        )
        # Verify content type header
        content_type = response.headers.get("Content-Type")
        self.assertIn("javascript", content_type.lower())

    def test_19_deps_pdfjs_worker_serves_exact_file(self):
        """Test that /deps/pdf.worker.min.mjs serves the exact cached PDF.js worker (built version only)"""
        # Skip this test for dev version (it uses CDN)
        test_version = os.environ.get("TEST_VERSION", "dev")
        if test_version != "built":
            self.skipTest("This test only applies to the built version")
        # Read the cached PDF.js worker file
        cache_path = Path("js_deps/pdf.worker.min.mjs")
        self.assertTrue(cache_path.exists(), "Cached PDF.js worker not found")
        with open(cache_path, "r", encoding="utf-8") as f:
            expected_content = f.read()
        # Fetch from /deps/ endpoint
        response = urllib.request.urlopen(f"{self.server_url}/deps/pdf.worker.min.mjs")
        served_content = response.read().decode("utf-8")
        # Verify they match exactly
        self.assertEqual(response.status, 200)
        self.assertEqual(
            len(served_content),
            len(expected_content),
            f"Size mismatch: served {len(served_content)} bytes, expected {len(expected_content)} bytes",
        )
        self.assertEqual(
            served_content,
            expected_content,
            "Served PDF.js worker does not match cached file",
        )
        # Verify content type header
        content_type = response.headers.get("Content-Type")
        self.assertIn("javascript", content_type.lower())

    def test_20_download_file_via_cli(self):
        """Test downloading a file using the download command"""
        # First upload a file
        test_content = "Download test content"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(test_content)
            test_file = f.name
        try:
            # Upload
            upload_result = subprocess.run(
                [
                    "python3",
                    self.companion_script,
                    "upload",
                    test_file,
                    "--server-url",
                    self.server_url,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )
            self.assertEqual(upload_result.returncode, 0)
            filename = Path(test_file).name
            # Download to temp directory
            with tempfile.TemporaryDirectory() as download_dir:
                result = subprocess.run(
                    [
                        "python3",
                        self.companion_script,
                        "download",
                        filename,
                        "-o",
                        download_dir,
                        "--server-url",
                        self.server_url,
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=10,
                    env=self.env,
                )
                self.assertEqual(result.returncode, 0, f"Download failed: {result.stderr}")
                self.assertIn("Downloaded successfully", result.stdout)
                # Verify file exists and content matches
                downloaded_file = Path(download_dir) / filename
                self.assertTrue(downloaded_file.exists())
                self.assertEqual(downloaded_file.read_text(), test_content)
        finally:
            Path(test_file).unlink()

    def test_21_download_nonexistent_file(self):
        """Test that downloading nonexistent file fails gracefully"""
        with tempfile.TemporaryDirectory() as download_dir:
            result = subprocess.run(
                [
                    "python3",
                    self.companion_script,
                    "download",
                    "nonexistent-file.txt",
                    "-o",
                    download_dir,
                    "--server-url",
                    self.server_url,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not found", result.stderr.lower())

    def test_22_download_no_overwrite(self):
        """Test that download refuses to overwrite existing files"""
        # First upload a file
        test_content = "Original content"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(test_content)
            test_file = f.name
        try:
            # Upload
            upload_result = subprocess.run(
                [
                    "python3",
                    self.companion_script,
                    "upload",
                    test_file,
                    "--server-url",
                    self.server_url,
                    "--api-key",
                    self.api_key,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )
            self.assertEqual(upload_result.returncode, 0)
            filename = Path(test_file).name
            # Create existing file in download dir
            with tempfile.TemporaryDirectory() as download_dir:
                existing_file = Path(download_dir) / filename
                existing_file.write_text("Existing content - should not be overwritten")
                # Try to download (should fail)
                result = subprocess.run(
                    [
                        "python3",
                        self.companion_script,
                        "download",
                        filename,
                        "-o",
                        download_dir,
                        "--server-url",
                        self.server_url,
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=10,
                    env=self.env,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("already exists", result.stderr)
                # Verify original content was preserved
                self.assertEqual(existing_file.read_text(), "Existing content - should not be overwritten")
        finally:
            Path(test_file).unlink()

    def test_23_download_sanitizes_filename(self):
        """Test that download sanitizes filenames with special characters"""
        # Upload a file with special characters in name via API
        test_content = b"Sanitize test content"
        original_filename = "test file (copy).txt"
        sanitized_filename = "test_file__copy_.txt"
        # Upload via API with special filename
        boundary = "----TestBoundary123"
        body = (
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{original_filename}"\r\n'
                f"Content-Type: text/plain\r\n\r\n"
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
        urllib.request.urlopen(req)
        # Download to temp directory
        with tempfile.TemporaryDirectory() as download_dir:
            result = subprocess.run(
                [
                    "python3",
                    self.companion_script,
                    "download",
                    original_filename,
                    "-o",
                    download_dir,
                    "--server-url",
                    self.server_url,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )
            self.assertEqual(result.returncode, 0, f"Download failed: {result.stderr}")
            # Verify sanitized filename was used
            downloaded_file = Path(download_dir) / sanitized_filename
            self.assertTrue(downloaded_file.exists(), f"Expected {sanitized_filename} but it doesn't exist")
            self.assertEqual(downloaded_file.read_bytes(), test_content)


class ConfigTest(unittest.TestCase):
    """Tests for config file functionality"""
    # Environment with UTF-8 encoding for subprocesses
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    def setUp(self):
        """Create a temporary config directory"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir) / ".config" / "companion"
        self.config_dir.mkdir(parents=True)
        self.config_file = self.config_dir / "config.json"
        # Determine which version to test
        test_version = os.environ.get("TEST_VERSION", "dev")
        if test_version == "built":
            self.companion_script = "companion.py"
        else:
            self.companion_script = "src/companion.py"

    def tearDown(self):
        """Clean up temporary directory"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _run_with_home(self, args):
        """Run companion with custom HOME directory"""
        env = self.env.copy()
        env["HOME"] = self.temp_dir
        return subprocess.run(
            ["python3", self.companion_script] + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            env=env,
        )

    def test_01_no_config_no_server_shows_error(self):
        """Test that missing config and no --server-url shows helpful error"""
        result = self._run_with_home(["list"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No server specified", result.stderr)
        self.assertIn("config.json", result.stderr)
        self.assertIn("--server-url", result.stderr)

    def test_02_config_with_default_server(self):
        """Test that config with default-server is used"""
        config = {
            "default-server": "test",
            "servers": {"test": {"url": "http://localhost:9999", "api-key": "testkey"}},
        }
        self.config_file.write_text(json.dumps(config))
        # This will fail to connect, but we can verify it used the config
        result = self._run_with_home(["list"])
        # Should fail with connection error, not "no server specified"
        self.assertNotIn("No server specified", result.stderr)
        # The error should be about connection (Connection refused or similar)
        self.assertIn("Failed to list files", result.stdout)

    def test_03_server_flag_overrides_default(self):
        """Test that --server flag overrides default-server"""
        config = {
            "default-server": "default",
            "servers": {
                "default": {"url": "http://localhost:1111", "api-key": "defaultkey"},
                "other": {"url": "http://localhost:2222", "api-key": "otherkey"},
            },
        }
        self.config_file.write_text(json.dumps(config))
        result = self._run_with_home(["list", "--server", "other"])
        # Should fail with connection error (server resolved from config)
        self.assertNotIn("No server specified", result.stderr)
        self.assertIn("Failed to list files", result.stdout)

    def test_04_server_url_flag_overrides_config(self):
        """Test that --server-url flag overrides config entirely"""
        config = {
            "default-server": "default",
            "servers": {"default": {"url": "http://localhost:1111", "api-key": "defaultkey"}},
        }
        self.config_file.write_text(json.dumps(config))
        result = self._run_with_home(["list", "--server-url", "http://localhost:3333"])
        # Should fail with connection error (using --server-url)
        self.assertNotIn("No server specified", result.stderr)
        self.assertIn("Failed to list files", result.stdout)

    def test_05_api_key_flag_overrides_config(self):
        """Test that --api-key flag overrides config api-key"""
        # Start a real server for this test
        port = 8766
        api_key = "real-api-key"
        server_url = f"http://localhost:{port}"
        config = {
            "default-server": "test",
            "servers": {"test": {"url": server_url, "api-key": "wrong-key-in-config"}},
        }
        self.config_file.write_text(json.dumps(config))
        # Start server
        server_process = subprocess.Popen(
            [
                "python3",
                self.companion_script,
                "server",
                "--port",
                str(port),
                "--api-key",
                api_key,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=self.env,
        )
        try:
            # Wait for server to start
            time.sleep(1)
            # Create a test file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("Test content")
                test_file = f.name
            try:
                # Upload with --api-key override (should succeed)
                result = self._run_with_home(["upload", test_file, "--api-key", api_key])
                self.assertEqual(result.returncode, 0, f"Upload failed: {result.stderr}")
                self.assertIn("Upload successful", result.stdout)
            finally:
                Path(test_file).unlink()
        finally:
            server_process.terminate()
            server_process.wait(timeout=5)

    def test_06_nonexistent_server_name_shows_error(self):
        """Test that --server with nonexistent name shows error"""
        config = {
            "default-server": "default",
            "servers": {"default": {"url": "http://localhost:1111", "api-key": "key"}},
        }
        self.config_file.write_text(json.dumps(config))
        result = self._run_with_home(["list", "--server", "nonexistent"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not found", result.stderr)
        self.assertIn("nonexistent", result.stderr)
        self.assertIn("default", result.stderr)  # Should show available servers

    def test_07_missing_api_key_for_protected_command(self):
        """Test that protected commands fail without api-key"""
        config = {
            "default-server": "test",
            "servers": {"test": {"url": "http://localhost:9999"}},  # No api-key
        }
        self.config_file.write_text(json.dumps(config))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Test")
            test_file = f.name
        try:
            result = self._run_with_home(["upload", test_file])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("API key required", result.stderr)
        finally:
            Path(test_file).unlink()

    def test_08_invalid_config_json_shows_warning(self):
        """Test that invalid JSON in config shows warning but continues"""
        self.config_file.write_text("{ invalid json }")
        result = self._run_with_home(["list"])
        # Should show warning about config
        self.assertIn("Warning", result.stderr)
        # Should still fail with "no server specified"
        self.assertIn("No server specified", result.stderr)

    def test_09_server_mode_uses_config(self):
        """Test that server mode uses config for port and api-key"""
        config = {
            "default-server": "test",
            "servers": {"test": {"url": "http://localhost:8767", "api-key": "configkey"}},
        }
        self.config_file.write_text(json.dumps(config))
        # Start server using config (no --port or --api-key)
        server_process = subprocess.Popen(
            ["python3", self.companion_script, "server"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env={**self.env, "HOME": self.temp_dir},
        )
        try:
            # Wait for server to start
            time.sleep(1)
            # Verify server is running on port 8767 with the config api-key
            response = urllib.request.urlopen("http://localhost:8767/api/files")
            self.assertEqual(response.status, 200)
            # Test upload with config api-key
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("Test")
                test_file = f.name
            try:
                # Upload should work with config api-key
                result = self._run_with_home(["upload", test_file])
                self.assertEqual(result.returncode, 0, f"Upload failed: {result.stderr}")
            finally:
                Path(test_file).unlink()
        finally:
            server_process.terminate()
            server_process.wait(timeout=5)

    def test_10_server_mode_no_config_no_apikey_fails(self):
        """Test that server mode without config or --api-key shows error"""
        result = self._run_with_home(["server"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("API key required", result.stderr)

    def test_11_server_mode_cli_overrides_config(self):
        """Test that CLI args override config in server mode"""
        config = {
            "default-server": "test",
            "servers": {"test": {"url": "http://localhost:8888", "api-key": "configkey"}},
        }
        self.config_file.write_text(json.dumps(config))
        # Start server with CLI overrides
        server_process = subprocess.Popen(
            ["python3", self.companion_script, "server", "--port", "8768", "--api-key", "clikey"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env={**self.env, "HOME": self.temp_dir},
        )
        try:
            time.sleep(1)
            # Should be on port 8768, not 8888
            response = urllib.request.urlopen("http://localhost:8768/api/files")
            self.assertEqual(response.status, 200)
            # Port 8888 should not be running
            try:
                urllib.request.urlopen("http://localhost:8888/api/files", timeout=1)
                self.fail("Server should not be on port 8888")
            except urllib.error.URLError:
                pass  # Expected
        finally:
            server_process.terminate()
            server_process.wait(timeout=5)


def run_tests():
    """Run the test suite"""
    # Change to project root directory (parent of tests/)
    import os
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    # Run tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(FileShareE2ETest))
    suite.addTests(loader.loadTestsFromTestCase(ConfigTest))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    # Force UTF-8 encoding on Windows for emoji support
    if sys.platform == "win32":
        import codecs

        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
        sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())

    success = run_tests()
    sys.exit(0 if success else 1)
