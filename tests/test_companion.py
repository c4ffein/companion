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
import threading
import time
import unittest
import urllib.request
import urllib.error
from pathlib import Path


def _setup_server_config(companion_script, port, env, server_name="default", client_id=None, client_secret=None):
    """Run server-setup with flags to create config, return (client_id, client_secret)."""
    if not client_id:
        import secrets as _secrets

        client_id = _secrets.token_hex(16)
    if not client_secret:
        import secrets as _secrets

        client_secret = _secrets.token_hex(32)
    result = subprocess.run(
        [
            "python3",
            companion_script,
            "server-setup",
            "--server",
            server_name,
            "--url",
            f"http://localhost:{port}",
            "--client-id",
            client_id,
            "--client-secret",
            client_secret,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=10,
        env=env,
    )
    if result.returncode != 0:
        raise Exception(f"server-setup failed: {result.stderr}\n{result.stdout}")
    return client_id, client_secret


def _start_server(companion_script, port, env, extra_args=None):
    """Start server (config must already exist), wait for ready, return process."""
    args = [
        "python3",
        "-u",
        companion_script,
        "server",
        "--port",
        str(port),
        "--debug",
    ]
    if extra_args is not None:
        args = ["python3", "-u", companion_script, "server"] + extra_args + ["--debug"]
    server_env = env.copy()
    server_env["PYTHONUNBUFFERED"] = "1"
    server_env["COMPANION_RATE_LIMIT_MAX"] = "10000"
    server_process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=server_env,
    )

    # Use a background thread to collect stdout (avoids blocking on readline)
    stdout_lines = []

    def _reader():
        for line in server_process.stdout:
            stdout_lines.append(line)

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    # Wait for server to be ready
    server_url = f"http://localhost:{port}"
    max_retries = 20
    for i in range(max_retries):
        # Check if process has died
        if server_process.poll() is not None:
            reader_thread.join(timeout=2)
            stderr = server_process.stderr.read()
            collected = "".join(stdout_lines)
            raise Exception(
                f"Server process exited with code {server_process.returncode}\nStdout: {collected}\nStderr: {stderr}"
            )
        try:
            urllib.request.urlopen(f"{server_url}/", timeout=1)
            time.sleep(0.3)
            break
        except (urllib.error.URLError, OSError):
            if i == max_retries - 1:
                server_process.kill()
                reader_thread.join(timeout=2)
                stderr = server_process.stderr.read()
                collected = "".join(stdout_lines)
                raise Exception(f"Server failed to start\nStdout: {collected}\nStderr: {stderr}")
            time.sleep(0.5)

    return server_process


class FileShareE2ETest(unittest.TestCase):
    """End-to-end tests with real server and clients"""

    # Environment with UTF-8 encoding for subprocesses
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    @classmethod
    def setUpClass(cls):
        """Set up config via server-setup, then start the server"""
        cls.port = 8765
        cls.server_url = f"http://localhost:{cls.port}"

        # TEST_VERSION env var can be 'dev' or 'built' (default: 'dev')
        test_version = os.environ.get("TEST_VERSION", "dev")
        if test_version == "built":
            cls.companion_script = "companion.py"
        else:
            cls.companion_script = "src/companion.py"

        # Use a temp HOME so we don't pollute real config
        cls.temp_home = tempfile.mkdtemp()

        server_env = cls.env.copy()
        server_env["HOME"] = cls.temp_home

        # Set up server config with admin credentials
        cls.client_id, cls.client_secret = _setup_server_config(
            cls.companion_script,
            cls.port,
            server_env,
        )
        cls.auth_token = f"{cls.client_id}:{cls.client_secret}"

        # Start the server
        cls.server_process = _start_server(cls.companion_script, cls.port, server_env)

    @classmethod
    def tearDownClass(cls):
        """Stop the server"""
        cls.server_process.terminate()
        cls.server_process.communicate(timeout=5)
        import shutil

        shutil.rmtree(cls.temp_home, ignore_errors=True)

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
                    "--client-id",
                    self.client_id,
                    "--client-secret",
                    self.client_secret,
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

    def test_04_upload_with_wrong_credentials(self):
        """Test that upload fails with wrong credentials"""
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
                    "--client-id",
                    "wrong-id",
                    "--client-secret",
                    "wrong-secret",
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
        # Upload file via API
        test_content = b"Test content for download"
        test_filename = "test_download.bin"

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
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )

        response = urllib.request.urlopen(req)
        result = json.loads(response.read().decode())
        self.assertTrue(result["success"])
        self.assertIn("id", result)

        # Download and verify using file_id
        download_url = f"{self.server_url}/download/{result['id']}"
        response = urllib.request.urlopen(download_url)
        downloaded_content = response.read()

        self.assertEqual(downloaded_content, test_content)
        self.assertEqual(response.status, 200)

    def test_06_download_nonexistent_file(self):
        """Test that downloading nonexistent file returns 404"""
        try:
            urllib.request.urlopen(f"{self.server_url}/download/00000000-0000-0000-0000-000000000000")
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
                        self.companion_script,
                        "upload",
                        test_file,
                        "--server-url",
                        self.server_url,
                        "--client-id",
                        self.client_id,
                        "--client-secret",
                        self.client_secret,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    env=self.env,
                )
                processes.append(proc)

            # Wait for all to complete
            for proc in processes:
                proc.communicate(timeout=10)
            results = [proc.returncode for proc in processes]

            # All should succeed
            for i, returncode in enumerate(results):
                self.assertEqual(returncode, 0, f"Client {i} failed")

            # Verify all files present
            response = urllib.request.urlopen(f"{self.server_url}/api/files")
            files = json.loads(response.read().decode())
            filenames = [f["name"] for f in files]

            for test_file in test_files:
                self.assertIn(Path(test_file).name, filenames)

        finally:
            for test_file in test_files:
                Path(test_file).unlink()

    def test_08_same_name_creates_separate_entries(self):
        """Test that uploading a file with the same name creates separate entries (UUID keys)"""
        test_filename = "overwrite_test.txt"
        content1 = b"Version 1"
        content2 = b"Version 2 - updated content"

        file_ids = []
        for content in [content1, content2]:
            boundary = "----TestBoundary456"
            body = (
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{test_filename}"\r\n'
                    f"Content-Type: text/plain\r\n\r\n"
                ).encode()
                + content
                + f"\r\n--{boundary}--\r\n".encode()
            )
            req = urllib.request.Request(
                f"{self.server_url}/api/upload",
                data=body,
                headers={
                    "Authorization": f"Bearer {self.auth_token}",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
            )
            response = urllib.request.urlopen(req)
            result = json.loads(response.read().decode())
            file_ids.append(result["id"])

        # Both entries should exist with different IDs
        self.assertNotEqual(file_ids[0], file_ids[1])

        # Both should be downloadable with correct content
        resp1 = urllib.request.urlopen(f"{self.server_url}/download/{file_ids[0]}")
        self.assertEqual(resp1.read(), content1)

        resp2 = urllib.request.urlopen(f"{self.server_url}/download/{file_ids[1]}")
        self.assertEqual(resp2.read(), content2)

    def test_08b_upload_binary_file(self):
        """Test uploading a binary file with various byte values"""
        # Create binary file with full byte range
        test_content = bytes(range(256)) * 100  # 25.6 KB

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(test_content)
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
                    "--client-id",
                    self.client_id,
                    "--client-secret",
                    self.client_secret,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )
            self.assertEqual(result.returncode, 0)

            # Get file_id from file list
            response = urllib.request.urlopen(f"{self.server_url}/api/files")
            files = json.loads(response.read().decode())
            uploaded = next(f for f in files if f["name"] == Path(test_file).name)

            # Download and verify byte-for-byte equality
            download_url = f"{self.server_url}/download/{uploaded['id']}"
            response = urllib.request.urlopen(download_url)
            downloaded_content = response.read()

            self.assertEqual(downloaded_content, test_content)
            self.assertEqual(len(downloaded_content), len(test_content))

        finally:
            Path(test_file).unlink()

    def test_09_special_characters_in_filename(self):
        """Test files with special characters in name"""
        special_names = ["hello world.txt", "café.txt", "file (2).txt"]
        created_files = []

        try:
            for name in special_names:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="test_") as f:
                    f.write(f"Content for {name}")
                    created_files.append(Path(f.name))

                # Rename to desired name
                new_path = created_files[-1].parent / name
                created_files[-1].rename(new_path)
                created_files[-1] = new_path

                result = subprocess.run(
                    [
                        "python3",
                        self.companion_script,
                        "upload",
                        str(new_path),
                        "--server-url",
                        self.server_url,
                        "--client-id",
                        self.client_id,
                        "--client-secret",
                        self.client_secret,
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=10,
                    env=self.env,
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
                    "--client-id",
                    self.client_id,
                    "--client-secret",
                    self.client_secret,
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
        self.assertEqual(state["file_id"], None)
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
                    "--client-id",
                    self.client_id,
                    "--client-secret",
                    self.client_secret,
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
                    "--client-id",
                    self.client_id,
                    "--client-secret",
                    self.client_secret,
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

    def test_13_set_preview_nonexistent_file_cli(self):
        """Test that setting preview for nonexistent file fails via CLI"""
        result = subprocess.run(
            [
                "python3",
                self.companion_script,
                "set-preview",
                "nonexistent-file.txt",
                "--server-url",
                self.server_url,
                "--client-id",
                self.client_id,
                "--client-secret",
                self.client_secret,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            env=self.env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not found", result.stdout.lower() + result.stderr.lower())

    def test_13c_set_preview_nonexistent_file_api(self):
        """Test that setting preview for nonexistent file_id returns 404"""
        preview_data = json.dumps({"file_id": "00000000-0000-0000-0000-000000000000"}).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/preview/set",
            data=preview_data,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("Should have raised HTTPError")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)

    def test_13b_set_preview_wrong_credentials(self):
        """Test that setting preview with wrong credentials fails"""
        # Upload a file first so we have a valid file_id
        test_content = b"Preview auth test"
        test_filename = "preview_auth_test.txt"
        boundary = "----TestBoundaryAuth"
        body = (
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{test_filename}"\r\n'
                f"Content-Type: text/plain\r\n\r\n"
            ).encode()
            + test_content
            + f"\r\n--{boundary}--\r\n".encode()
        )
        req = urllib.request.Request(
            f"{self.server_url}/api/upload",
            data=body,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        upload_response = urllib.request.urlopen(req)
        upload_result = json.loads(upload_response.read().decode())
        file_id = upload_result["id"]

        preview_data = json.dumps({"file_id": file_id}).encode()

        # Wrong client id
        req = urllib.request.Request(
            f"{self.server_url}/api/preview/set",
            data=preview_data,
            headers={
                "Authorization": f"Bearer wrong-id:{self.client_secret}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("Should have raised HTTPError for wrong client id")
        except urllib.error.HTTPError as e:
            self.assertIn(e.code, (401, 403))

        # Wrong client secret
        req = urllib.request.Request(
            f"{self.server_url}/api/preview/set",
            data=preview_data,
            headers={
                "Authorization": f"Bearer {self.client_id}:wrong-secret",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("Should have raised HTTPError for wrong client secret")
        except urllib.error.HTTPError as e:
            self.assertIn(e.code, (401, 403))

    def test_14_upload_and_set_preview_combo(self):
        """Test upload with --set-preview flag"""
        test_content = "Content for preview combo test"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(test_content)
            test_file = f.name

        try:
            result = subprocess.run(
                [
                    "python3",
                    self.companion_script,
                    "upload",
                    test_file,
                    "--set-preview",
                    "--server-url",
                    self.server_url,
                    "--client-id",
                    self.client_id,
                    "--client-secret",
                    self.client_secret,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )

            self.assertEqual(result.returncode, 0, f"Upload with preview failed: {result.stderr}")
            self.assertIn("Upload successful", result.stdout)
            self.assertIn("Preview set", result.stdout)

            # Verify preview state
            response = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
            state = json.loads(response.read().decode())
            self.assertEqual(state["filename"], Path(test_file).name)

        finally:
            Path(test_file).unlink()

    def test_15_preview_state_includes_mimetype(self):
        """Test that preview state includes correct mimetype"""
        # Upload a .txt file
        test_content = "Plain text content"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(test_content)
            test_file = f.name

        try:
            result = subprocess.run(
                [
                    "python3",
                    self.companion_script,
                    "upload",
                    test_file,
                    "--set-preview",
                    "--server-url",
                    self.server_url,
                    "--client-id",
                    self.client_id,
                    "--client-secret",
                    self.client_secret,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=self.env,
            )
            self.assertEqual(result.returncode, 0)

            # Check mimetype in preview state
            response = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
            state = json.loads(response.read().decode())
            self.assertTrue(state["mimetype"].startswith("text/"))

        finally:
            Path(test_file).unlink()

    def test_15b_preview_timestamp_increments(self):
        """Test that preview timestamp increments atomically on each update"""
        # Get current timestamp first
        response_initial = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
        state_initial = json.loads(response_initial.read().decode())
        initial_timestamp = state_initial["timestamp"]

        # Upload two test files via API
        file_ids = []
        filenames = []
        for i in range(2):
            test_content = f"Preview timestamp {i}".encode()
            test_filename = f"ts_preview{i}.txt"
            boundary = "----TestBoundaryTS"
            body = (
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{test_filename}"\r\n'
                    f"Content-Type: text/plain\r\n\r\n"
                ).encode()
                + test_content
                + f"\r\n--{boundary}--\r\n".encode()
            )
            req = urllib.request.Request(
                f"{self.server_url}/api/upload",
                data=body,
                headers={
                    "Authorization": f"Bearer {self.auth_token}",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
            )
            response = urllib.request.urlopen(req)
            result = json.loads(response.read().decode())
            self.assertEqual(response.status, 200)
            file_ids.append(result["id"])
            filenames.append(test_filename)

        # Set preview to first file
        preview_data = json.dumps({"file_id": file_ids[0]}).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/preview/set",
            data=preview_data,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        urllib.request.urlopen(req)

        # Check timestamp incremented by 1
        response1 = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
        state1 = json.loads(response1.read().decode())
        self.assertEqual(state1["timestamp"], initial_timestamp + 1)
        self.assertEqual(state1["filename"], filenames[0])
        self.assertEqual(state1["file_id"], file_ids[0])

        # Set preview to second file
        preview_data = json.dumps({"file_id": file_ids[1]}).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/preview/set",
            data=preview_data,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        urllib.request.urlopen(req)

        # Check timestamp incremented by 2 from initial
        response2 = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
        state2 = json.loads(response2.read().decode())
        self.assertEqual(state2["timestamp"], initial_timestamp + 2)
        self.assertEqual(state2["filename"], filenames[1])
        self.assertEqual(state2["file_id"], file_ids[1])

    def test_16_preview_via_direct_api(self):
        """Test setting preview via direct API call"""
        # Upload a test file via API to get file_id
        test_content = b"Direct API test"
        test_filename = "direct_api_preview.txt"
        boundary = "----TestBoundary789"
        body = (
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{test_filename}"\r\n'
                f"Content-Type: text/plain\r\n\r\n"
            ).encode()
            + test_content
            + f"\r\n--{boundary}--\r\n".encode()
        )
        req = urllib.request.Request(
            f"{self.server_url}/api/upload",
            data=body,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        upload_response = urllib.request.urlopen(req)
        upload_result = json.loads(upload_response.read().decode())
        self.assertTrue(upload_result["success"])
        file_id = upload_result["id"]

        # Set preview via direct API call using file_id
        preview_data = json.dumps({"file_id": file_id}).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/preview/set",
            data=preview_data,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        response = urllib.request.urlopen(req)
        result_json = json.loads(response.read().decode())
        self.assertEqual(response.status, 200)
        self.assertTrue(result_json["success"])
        self.assertEqual(result_json["file_id"], file_id)
        self.assertEqual(result_json["filename"], test_filename)
        self.assertGreater(result_json["timestamp"], 0)
        # Verify state
        state_response = urllib.request.urlopen(f"{self.server_url}/api/preview/current")
        state = json.loads(state_response.read().decode())
        self.assertEqual(state["file_id"], file_id)
        self.assertEqual(state["filename"], test_filename)
        self.assertEqual(state["timestamp"], result_json["timestamp"])

    def test_17_preview_multiple_updates(self):
        """Test that multiple rapid preview updates maintain timestamp consistency"""
        # Upload multiple files via API to get file_ids
        file_ids = []
        filenames = []
        for i in range(5):
            test_content = f"Rapid update {i}".encode()
            test_filename = f"rapid{i}.txt"
            boundary = "----TestBoundaryRapid"
            body = (
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{test_filename}"\r\n'
                    f"Content-Type: text/plain\r\n\r\n"
                ).encode()
                + test_content
                + f"\r\n--{boundary}--\r\n".encode()
            )
            req = urllib.request.Request(
                f"{self.server_url}/api/upload",
                data=body,
                headers={
                    "Authorization": f"Bearer {self.auth_token}",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
            )
            response = urllib.request.urlopen(req)
            result = json.loads(response.read().decode())
            file_ids.append(result["id"])
            filenames.append(test_filename)

        # Set preview rapidly for each file
        timestamps = []
        for file_id in file_ids:
            preview_data = json.dumps({"file_id": file_id}).encode()
            req = urllib.request.Request(
                f"{self.server_url}/api/preview/set",
                data=preview_data,
                headers={
                    "Authorization": f"Bearer {self.auth_token}",
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
        self.assertEqual(state["file_id"], file_ids[-1])
        self.assertEqual(state["filename"], filenames[-1])
        self.assertEqual(state["timestamp"], timestamps[-1])

    def test_18_deps_pdfjs_lib_serves_exact_file(self):
        """Test that /deps/pdf.min.mjs serves the exact cached PDF.js library (built version only)"""
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
                    "--client-id",
                    self.client_id,
                    "--client-secret",
                    self.client_secret,
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
                    "--client-id",
                    self.client_id,
                    "--client-secret",
                    self.client_secret,
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
                "Authorization": f"Bearer {self.auth_token}",
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

    def test_24_setup_admin_exists(self):
        """Test that admin client from server-setup exists and is admin"""
        req = urllib.request.Request(
            f"{self.server_url}/api/clients",
            headers={"Authorization": f"Bearer {self.auth_token}"},
        )
        with urllib.request.urlopen(req) as response:
            clients = json.loads(response.read().decode())
            admin_client = next(c for c in clients if c["client_id"] == self.client_id)
            self.assertTrue(admin_client["admin"])

    def test_25_unauthenticated_registration_always_rejected(self):
        """Test that unauthenticated registration is always rejected"""
        import uuid

        new_id = str(uuid.uuid4())
        new_secret = str(uuid.uuid4())

        register_data = json.dumps(
            {
                "client_id": new_id,
                "client_secret": new_secret,
                "name": "unauthorized",
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/clients/register",
            data=register_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("Should have raised HTTPError")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 401)

    def test_26_admin_can_register_others(self):
        """Test that admin can register new clients"""
        import uuid

        new_id = str(uuid.uuid4())
        new_secret = str(uuid.uuid4())

        register_data = json.dumps(
            {
                "client_id": new_id,
                "client_secret": new_secret,
                "name": "second-client",
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/clients/register",
            data=register_data,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])
            self.assertFalse(result["admin"])  # new clients are never admin

        # Verify the new client can upload
        test_content = b"Second client upload"
        test_filename = "second_client_test.bin"
        boundary = "----TestBoundary999"
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
                "Authorization": f"Bearer {new_id}:{new_secret}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])

        # Verify the new client cannot register others
        another_id = str(uuid.uuid4())
        another_secret = str(uuid.uuid4())
        register_data = json.dumps(
            {
                "client_id": another_id,
                "client_secret": another_secret,
                "name": "third-client",
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/clients/register",
            data=register_data,
            headers={
                "Authorization": f"Bearer {new_id}:{new_secret}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("Non-admin should not be able to register")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

    def test_28_delete_client_by_admin(self):
        """Test that admin can delete a registered client"""
        import uuid

        # Register a client to delete
        new_id = str(uuid.uuid4())
        new_secret = str(uuid.uuid4())
        register_data = json.dumps(
            {
                "client_id": new_id,
                "client_secret": new_secret,
                "name": "to-delete",
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/clients/register",
            data=register_data,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])

        # Delete the client
        delete_req = urllib.request.Request(
            f"{self.server_url}/api/clients/{new_id}",
            headers={"Authorization": f"Bearer {self.auth_token}"},
            method="DELETE",
        )
        with urllib.request.urlopen(delete_req) as response:
            result = json.loads(response.read().decode())
            self.assertTrue(result["success"])
            self.assertEqual(result["deleted"], new_id)

        # Verify client is gone
        list_req = urllib.request.Request(
            f"{self.server_url}/api/clients",
            headers={"Authorization": f"Bearer {self.auth_token}"},
        )
        with urllib.request.urlopen(list_req) as response:
            clients = json.loads(response.read().decode())
            client_ids = [c["client_id"] for c in clients]
            self.assertNotIn(new_id, client_ids)

    def test_29_cannot_delete_self(self):
        """Test that admin cannot delete their own client"""
        delete_req = urllib.request.Request(
            f"{self.server_url}/api/clients/{self.client_id}",
            headers={"Authorization": f"Bearer {self.auth_token}"},
            method="DELETE",
        )
        try:
            urllib.request.urlopen(delete_req)
            self.fail("Should have raised HTTPError")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_30_non_admin_cannot_delete(self):
        """Test that non-admin cannot delete clients"""
        import uuid

        # Register a non-admin client
        non_admin_id = str(uuid.uuid4())
        non_admin_secret = str(uuid.uuid4())
        register_data = json.dumps(
            {
                "client_id": non_admin_id,
                "client_secret": non_admin_secret,
                "name": "non-admin-deleter",
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/clients/register",
            data=register_data,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        urllib.request.urlopen(req)

        # Non-admin tries to delete someone else
        target_id = str(uuid.uuid4())
        target_secret = str(uuid.uuid4())
        register_data2 = json.dumps(
            {
                "client_id": target_id,
                "client_secret": target_secret,
                "name": "delete-target",
            }
        ).encode()
        req2 = urllib.request.Request(
            f"{self.server_url}/api/clients/register",
            data=register_data2,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        urllib.request.urlopen(req2)

        delete_req = urllib.request.Request(
            f"{self.server_url}/api/clients/{target_id}",
            headers={"Authorization": f"Bearer {non_admin_id}:{non_admin_secret}"},
            method="DELETE",
        )
        try:
            urllib.request.urlopen(delete_req)
            self.fail("Non-admin should not be able to delete")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

    def test_31_delete_nonexistent_client(self):
        """Test that deleting a nonexistent client returns 404"""
        delete_req = urllib.request.Request(
            f"{self.server_url}/api/clients/nonexistent-id",
            headers={"Authorization": f"Bearer {self.auth_token}"},
            method="DELETE",
        )
        try:
            urllib.request.urlopen(delete_req)
            self.fail("Should have raised HTTPError")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)

    def test_27_invalid_credentials_rejected(self):
        """Test that invalid credentials are rejected"""
        # Upload attempt with bad credentials
        boundary = "----TestBoundary000"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="bad.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"bad content"
            f"\r\n--{boundary}--\r\n"
        ).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/upload",
            data=body,
            headers={
                "Authorization": "Bearer bad-id:bad-secret",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        try:
            urllib.request.urlopen(req)
            self.fail("Should have raised HTTPError")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 401)

    def test_32_input_validation_rejects_bad_client_id(self):
        """Test that registration rejects invalid client_id"""
        # client_id with spaces
        register_data = json.dumps(
            {
                "client_id": "has spaces",
                "client_secret": "some-secret",
                "name": "test",
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/clients/register",
            data=register_data,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("Should have raised HTTPError for spaces in client_id")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

        # client_id too long (>64 chars)
        register_data = json.dumps(
            {
                "client_id": "a" * 65,
                "client_secret": "some-secret",
                "name": "test",
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/clients/register",
            data=register_data,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("Should have raised HTTPError for too-long client_id")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_33_input_validation_rejects_bad_name(self):
        """Test that registration rejects invalid name"""
        import uuid

        # name with non-printable chars
        register_data = json.dumps(
            {
                "client_id": str(uuid.uuid4()),
                "client_secret": "some-secret",
                "name": "test\x00name",
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.server_url}/api/clients/register",
            data=register_data,
            headers={
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("Should have raised HTTPError for non-printable chars in name")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)


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
            "servers": {
                "test": {
                    "url": "http://localhost:9999",
                    "client-id": "test-id",
                    "client-secret": "test-secret",
                }
            },
        }
        self.config_file.write_text(json.dumps(config))
        result = self._run_with_home(["list"])
        self.assertNotIn("No server specified", result.stderr)
        self.assertIn("Failed to list files", result.stdout)

    def test_03_server_flag_overrides_default(self):
        """Test that --server flag overrides default-server"""
        config = {
            "default-server": "default",
            "servers": {
                "default": {"url": "http://localhost:1111", "client-id": "id1", "client-secret": "s1"},
                "other": {"url": "http://localhost:2222", "client-id": "id2", "client-secret": "s2"},
            },
        }
        self.config_file.write_text(json.dumps(config))
        result = self._run_with_home(["list", "--server", "other"])
        self.assertNotIn("No server specified", result.stderr)
        self.assertIn("Failed to list files", result.stdout)

    def test_04_server_url_flag_overrides_config(self):
        """Test that --server-url flag overrides config entirely"""
        config = {
            "default-server": "default",
            "servers": {"default": {"url": "http://localhost:1111", "client-id": "id1", "client-secret": "s1"}},
        }
        self.config_file.write_text(json.dumps(config))
        result = self._run_with_home(["list", "--server-url", "http://localhost:3333"])
        self.assertNotIn("No server specified", result.stderr)
        self.assertIn("Failed to list files", result.stdout)

    def test_05_credentials_flag_overrides_config(self):
        """Test that --client-id/--client-secret flags override config credentials"""
        port = 8766

        # Set up server config with known admin credentials
        server_env = self.env.copy()
        server_env["HOME"] = self.temp_dir
        client_id, client_secret = _setup_server_config(
            self.companion_script,
            port,
            server_env,
            server_name="test",
        )

        # Overwrite config to have wrong CLI credentials but keep the server clients
        config = json.loads(self.config_file.read_text())
        config["servers"]["test"]["client-id"] = "wrong-id"
        config["servers"]["test"]["client-secret"] = "wrong-secret"
        self.config_file.write_text(json.dumps(config))

        # Start server with temp home
        server_process = _start_server(self.companion_script, port, server_env)
        try:
            # Create a test file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("Test content")
                test_file = f.name
            try:
                # Upload with --client-id/--client-secret override (should succeed)
                result = self._run_with_home(
                    [
                        "upload",
                        test_file,
                        "--client-id",
                        client_id,
                        "--client-secret",
                        client_secret,
                    ]
                )
                self.assertEqual(result.returncode, 0, f"Upload failed: {result.stderr}")
                self.assertIn("Upload successful", result.stdout)
            finally:
                Path(test_file).unlink()
        finally:
            server_process.terminate()
            server_process.communicate(timeout=5)

    def test_06_nonexistent_server_name_shows_error(self):
        """Test that --server with nonexistent name shows error"""
        config = {
            "default-server": "default",
            "servers": {"default": {"url": "http://localhost:1111", "client-id": "id", "client-secret": "s"}},
        }
        self.config_file.write_text(json.dumps(config))
        result = self._run_with_home(["list", "--server", "nonexistent"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not found", result.stderr)
        self.assertIn("nonexistent", result.stderr)
        self.assertIn("default", result.stderr)

    def test_07_missing_credentials_for_protected_command(self):
        """Test that protected commands fail without credentials"""
        config = {
            "default-server": "test",
            "servers": {"test": {"url": "http://localhost:9999"}},  # No credentials
        }
        self.config_file.write_text(json.dumps(config))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Test")
            test_file = f.name
        try:
            result = self._run_with_home(["upload", test_file])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Credentials required", result.stderr)
        finally:
            Path(test_file).unlink()

    def test_08_invalid_config_json_shows_warning(self):
        """Test that invalid JSON in config shows warning but continues"""
        self.config_file.write_text("{ invalid json }")
        result = self._run_with_home(["list"])
        self.assertIn("Warning", result.stderr)
        self.assertIn("No server specified", result.stderr)

    def test_09_server_mode_uses_config(self):
        """Test that server mode uses config for port"""
        server_env = {**self.env, "HOME": self.temp_dir}

        # Set up server config via server-setup (creates admin + config)
        client_id, client_secret = _setup_server_config(
            self.companion_script,
            8767,
            server_env,
            server_name="test",
        )

        server_process = _start_server(self.companion_script, 8767, server_env, extra_args=[])
        try:
            response = urllib.request.urlopen("http://localhost:8767/api/files")
            self.assertEqual(response.status, 200)

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("Test")
                test_file = f.name
            try:
                result = self._run_with_home(["upload", test_file])
                self.assertEqual(result.returncode, 0, f"Upload failed: {result.stderr}")
            finally:
                Path(test_file).unlink()
        finally:
            server_process.terminate()
            server_process.communicate(timeout=5)

    def test_10_server_fails_without_clients(self):
        """Test that server mode fails if no clients are configured"""
        server_env = {**self.env, "HOME": self.temp_dir}
        result = subprocess.run(
            ["python3", self.companion_script, "server", "--port", "8769"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            env=server_env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No clients configured", result.stderr)

    def test_11_server_mode_cli_overrides_config(self):
        """Test that CLI args override config in server mode"""
        server_env = {**self.env, "HOME": self.temp_dir}

        # Set up config pointing to port 8888 (config URL)
        _setup_server_config(
            self.companion_script,
            8888,
            server_env,
            server_name="test",
        )

        # Start server with --port 8768 override
        server_process = _start_server(self.companion_script, 8768, server_env, extra_args=["--port", "8768"])
        try:
            response = urllib.request.urlopen("http://localhost:8768/api/files")
            self.assertEqual(response.status, 200)
            try:
                urllib.request.urlopen("http://localhost:8888/api/files", timeout=1)
                self.fail("Server should not be on port 8888")
            except urllib.error.URLError:
                pass
        finally:
            server_process.terminate()
            server_process.communicate(timeout=5)


def run_tests():
    """Run the test suite"""
    import os

    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
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
