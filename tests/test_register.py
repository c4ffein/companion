#!/usr/bin/env python3
"""
Unit tests for client registration API and CLI
"""

import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

# Import the companion module
sys.path.insert(0, "src")
import companion


def _companion_script():
    test_version = os.environ.get("TEST_VERSION", "dev")
    if test_version == "built":
        return "companion.py"
    return "src/companion.py"


def _run(args, *, env, stdin_text=None, timeout=10):
    """Run the companion CLI, return CompletedProcess."""
    return subprocess.run(
        ["python3", _companion_script()] + args,
        input=stdin_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        env=env,
    )


def _make_env(tmp_home):
    env = os.environ.copy()
    env["HOME"] = tmp_home
    return env


def _write_config(tmp_home, config):
    config_path = Path(tmp_home) / ".config" / "companion" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)


def _read_config(tmp_home):
    config_path = Path(tmp_home) / ".config" / "companion" / "config.json"
    with open(config_path) as f:
        return json.load(f)


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


class TestRegisterNonRunningServer(unittest.TestCase):
    """Standalone test — no server needed."""

    def test_register_non_running_server(self):
        """register_client() against a refused port returns (None, None)."""
        client_id, client_secret = companion.register_client(
            "http://localhost:1", "test-name", auth_token="fake-id:fake-secret"
        )
        self.assertIsNone(client_id)
        self.assertIsNone(client_secret)


class TestRegisterAPI(unittest.TestCase):
    """Test /api/clients/register endpoint with a running server."""

    @classmethod
    def setUpClass(cls):
        cls.port = 8891
        cls.admin_id = "admin-reg-id"
        cls.admin_secret = secrets.token_hex(32)
        cls.admin_token = f"{cls.admin_id}:{cls.admin_secret}"
        cls.nonadmin_id = "nonadmin-reg-id"
        cls.nonadmin_secret = secrets.token_hex(32)
        cls.nonadmin_token = f"{cls.nonadmin_id}:{cls.nonadmin_secret}"
        cls.base_url = f"http://localhost:{cls.port}"

        # Reset global state
        companion.FILES.clear()
        companion.PREVIEW_STATE = {"file_id": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}
        companion.RATE_LIMIT_STORE.clear()

        with companion.CLIENTS_LOCK:
            companion.CLIENTS.clear()
            companion.CLIENTS[cls.admin_id] = _make_client_entry(cls.admin_secret, admin=True, name="admin")
            companion.CLIENTS[cls.nonadmin_id] = _make_client_entry(cls.nonadmin_secret, admin=False, name="nonadmin")

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

    def _register(self, auth_token, *, client_id=None, client_secret=None, name="new-client"):
        """POST to /api/clients/register and return the response or raise HTTPError."""
        cid = client_id or secrets.token_hex(16)
        csecret = client_secret or secrets.token_hex(32)
        data = json.dumps({"client_id": cid, "client_secret": csecret, "name": name}).encode()
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(f"{self.base_url}/api/clients/register", data=data, headers=headers, method="POST")
        return cid, csecret, urllib.request.urlopen(req)

    def test_register_wrong_credentials(self):
        """Invalid auth token returns 401."""
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._register("bad-id:bad-secret")
        self.assertEqual(cm.exception.code, 401)

    def test_register_non_admin(self):
        """Non-admin client returns 403."""
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._register(self.nonadmin_token)
        self.assertEqual(cm.exception.code, 403)

    def test_register_success(self):
        """Admin can register a new client; new client appears in CLIENTS and can authenticate."""
        cid, csecret, resp = self._register(self.admin_token, name="fresh")
        result = json.loads(resp.read().decode())
        self.assertTrue(result["success"])
        self.assertEqual(result["client_id"], cid)
        self.assertFalse(result["admin"])

        # New client exists in CLIENTS
        with companion.CLIENTS_LOCK:
            self.assertIn(cid, companion.CLIENTS)
            self.assertEqual(companion.CLIENTS[cid]["name"], "fresh")

        # New client can authenticate (GET /api/pad succeeds)
        new_token = f"{cid}:{csecret}"
        headers = {"Authorization": f"Bearer {new_token}"}
        req = urllib.request.Request(f"{self.base_url}/api/pad", headers=headers)
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 200)

        # Cleanup
        with companion.CLIENTS_LOCK:
            companion.CLIENTS.pop(cid, None)

    def test_register_with_provided_id(self):
        """Admin can register a client with a specific chosen client_id."""
        chosen_id = "my-chosen-id"
        # Ensure it doesn't already exist
        with companion.CLIENTS_LOCK:
            companion.CLIENTS.pop(chosen_id, None)

        cid, csecret, resp = self._register(self.admin_token, client_id=chosen_id, name="chosen")
        result = json.loads(resp.read().decode())
        self.assertTrue(result["success"])
        self.assertEqual(result["client_id"], chosen_id)

        with companion.CLIENTS_LOCK:
            self.assertIn(chosen_id, companion.CLIENTS)

        # Cleanup
        with companion.CLIENTS_LOCK:
            companion.CLIENTS.pop(chosen_id, None)

    def test_register_duplicate_id(self):
        """Registering the same client_id twice returns 409 CONFLICT."""
        dup_id = "duplicate-test-id"
        # Ensure clean state
        with companion.CLIENTS_LOCK:
            companion.CLIENTS.pop(dup_id, None)

        # First registration succeeds
        _cid, _csecret, resp = self._register(self.admin_token, client_id=dup_id, name="first")
        self.assertEqual(resp.status, 200)

        # Second registration with same id fails
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._register(self.admin_token, client_id=dup_id, name="second")
        self.assertEqual(cm.exception.code, 409)

        # Cleanup
        with companion.CLIENTS_LOCK:
            companion.CLIENTS.pop(dup_id, None)


class TestRegisterCLI(unittest.TestCase):
    """Test the 'register' CLI command against a running server."""

    @classmethod
    def setUpClass(cls):
        cls.port = 8892
        cls.admin_id = "cli-admin-id"
        cls.admin_secret = secrets.token_hex(32)
        cls.nonadmin_id = "cli-nonadmin-id"
        cls.nonadmin_secret = secrets.token_hex(32)
        cls.base_url = f"http://localhost:{cls.port}"

        # Reset global state
        companion.FILES.clear()
        companion.PREVIEW_STATE = {"file_id": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}
        companion.RATE_LIMIT_STORE.clear()

        with companion.CLIENTS_LOCK:
            companion.CLIENTS.clear()
            companion.CLIENTS[cls.admin_id] = _make_client_entry(cls.admin_secret, admin=True, name="cli-admin")
            companion.CLIENTS[cls.nonadmin_id] = _make_client_entry(
                cls.nonadmin_secret, admin=False, name="cli-nonadmin"
            )

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
        self.tmp_home = tempfile.mkdtemp()
        self.env = _make_env(self.tmp_home)
        # Config with admin creds pointing at our running server
        _write_config(
            self.tmp_home,
            {
                "default-server": "testserver",
                "servers": {
                    "testserver": {
                        "url": self.base_url,
                        "client-id": self.admin_id,
                        "client-secret": self.admin_secret,
                    }
                },
            },
        )
        self.initial_config = _read_config(self.tmp_home)
        with companion.RATE_LIMIT_LOCK:
            companion.RATE_LIMIT_STORE.clear()

    def _assert_config_unchanged(self):
        """Verify register_cmd did not modify the client-side config file."""
        self.assertEqual(_read_config(self.tmp_home), self.initial_config)

    def _parse_credentials(self, stdout):
        """Extract client_id and client_secret from register output."""
        id_match = re.search(r"Client ID:\s+(\S+)", stdout)
        secret_match = re.search(r"Client Secret:\s+(\S+)", stdout)
        self.assertIsNotNone(id_match, f"Could not find Client ID in output:\n{stdout}")
        self.assertIsNotNone(secret_match, f"Could not find Client Secret in output:\n{stdout}")
        return id_match.group(1), secret_match.group(1)

    def _verify_client_on_server(self, client_id, client_secret):
        """Verify the registered client can authenticate against the running server."""
        token = f"{client_id}:{client_secret}"
        headers = {"Authorization": f"Bearer {token}"}
        req = urllib.request.Request(f"{self.base_url}/api/pad", headers=headers)
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 200)

    def _cleanup_client(self, client_id):
        with companion.CLIENTS_LOCK:
            companion.CLIENTS.pop(client_id, None)

    # --- Non-interactive credential tests ---

    def test_without_id_without_secret_non_interactive(self):
        """Non-interactive, no id/secret flags: both auto-generated."""
        result = _run(["register", "--server", "testserver", "--name", "auto-both"], env=self.env)
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        client_id, client_secret = self._parse_credentials(result.stdout)
        self.assertEqual(len(client_id), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in client_id))
        self._verify_client_on_server(client_id, client_secret)
        self._assert_config_unchanged()
        self._cleanup_client(client_id)

    def test_with_id_without_secret_non_interactive(self):
        """Non-interactive, --new-client-id only: secret auto-generated."""
        chosen_id = "ni-id-only"
        self._cleanup_client(chosen_id)
        result = _run(
            ["register", "--server", "testserver", "--name", "id-only", "--new-client-id", chosen_id], env=self.env
        )
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        client_id, client_secret = self._parse_credentials(result.stdout)
        self.assertEqual(client_id, chosen_id)
        self._verify_client_on_server(client_id, client_secret)
        self._assert_config_unchanged()
        self._cleanup_client(chosen_id)

    def test_without_id_with_secret_non_interactive(self):
        """Non-interactive, --new-client-secret only: id auto-generated."""
        chosen_secret = "deadbeef" * 8
        result = _run(
            ["register", "--server", "testserver", "--name", "sec-only", "--new-client-secret", chosen_secret],
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        client_id, client_secret = self._parse_credentials(result.stdout)
        self.assertEqual(client_secret, chosen_secret)
        self._verify_client_on_server(client_id, client_secret)
        self._assert_config_unchanged()
        self._cleanup_client(client_id)

    def test_with_id_with_secret_non_interactive(self):
        """Non-interactive, both flags provided."""
        chosen_id = "ni-full-id"
        chosen_secret = "cafebabe" * 8
        self._cleanup_client(chosen_id)
        result = _run(
            [
                "register",
                "--server",
                "testserver",
                "--name",
                "full",
                "--new-client-id",
                chosen_id,
                "--new-client-secret",
                chosen_secret,
            ],
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        client_id, client_secret = self._parse_credentials(result.stdout)
        self.assertEqual(client_id, chosen_id)
        self.assertEqual(client_secret, chosen_secret)
        self._verify_client_on_server(client_id, client_secret)
        self._assert_config_unchanged()
        self._cleanup_client(chosen_id)

    # --- Interactive credential tests ---

    def test_without_id_without_secret_interactive(self):
        """Interactive, no flags: prompted for both id and secret via stdin."""
        chosen_id = "int-both-id"
        chosen_secret = "abcd1234" * 8
        self._cleanup_client(chosen_id)
        # stdin: name, id, secret
        stdin_text = f"int-client\n{chosen_id}\n{chosen_secret}\n"
        result = _run(["register", "--server", "testserver", "--interactive"], env=self.env, stdin_text=stdin_text)
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        client_id, client_secret = self._parse_credentials(result.stdout)
        self.assertEqual(client_id, chosen_id)
        self.assertEqual(client_secret, chosen_secret)
        self._verify_client_on_server(client_id, client_secret)
        self._assert_config_unchanged()
        self._cleanup_client(chosen_id)

    def test_with_id_without_secret_interactive(self):
        """Interactive, --new-client-id flag: prompted for secret via stdin."""
        chosen_id = "int-id-flag"
        chosen_secret = "11223344" * 8
        self._cleanup_client(chosen_id)
        # stdin: name, secret (id already provided via flag)
        stdin_text = f"int-client\n{chosen_secret}\n"
        result = _run(
            ["register", "--server", "testserver", "--interactive", "--new-client-id", chosen_id],
            env=self.env,
            stdin_text=stdin_text,
        )
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        client_id, client_secret = self._parse_credentials(result.stdout)
        self.assertEqual(client_id, chosen_id)
        self.assertEqual(client_secret, chosen_secret)
        self._verify_client_on_server(client_id, client_secret)
        self._assert_config_unchanged()
        self._cleanup_client(chosen_id)

    def test_without_id_with_secret_interactive(self):
        """Interactive, --new-client-secret flag: prompted for id via stdin."""
        chosen_id = "int-sec-flag"
        chosen_secret = "55667788" * 8
        self._cleanup_client(chosen_id)
        # stdin: name, id (secret already provided via flag)
        stdin_text = f"int-client\n{chosen_id}\n"
        result = _run(
            ["register", "--server", "testserver", "--interactive", "--new-client-secret", chosen_secret],
            env=self.env,
            stdin_text=stdin_text,
        )
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        client_id, client_secret = self._parse_credentials(result.stdout)
        self.assertEqual(client_id, chosen_id)
        self.assertEqual(client_secret, chosen_secret)
        self._verify_client_on_server(client_id, client_secret)
        self._assert_config_unchanged()
        self._cleanup_client(chosen_id)

    def test_with_id_with_secret_interactive(self):
        """Interactive, both flags: no credential prompts."""
        chosen_id = "int-full-flag"
        chosen_secret = "aabbccdd" * 8
        self._cleanup_client(chosen_id)
        # stdin: name only (both creds provided via flags)
        stdin_text = "int-client\n"
        result = _run(
            [
                "register",
                "--server",
                "testserver",
                "--interactive",
                "--new-client-id",
                chosen_id,
                "--new-client-secret",
                chosen_secret,
            ],
            env=self.env,
            stdin_text=stdin_text,
        )
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        client_id, client_secret = self._parse_credentials(result.stdout)
        self.assertEqual(client_id, chosen_id)
        self.assertEqual(client_secret, chosen_secret)
        self._verify_client_on_server(client_id, client_secret)
        self._assert_config_unchanged()
        self._cleanup_client(chosen_id)

    # --- Server validation tests ---

    def test_no_server_flag_errors(self):
        """No --server flag, non-interactive: error mentioning --server."""
        result = _run(["register"], env=self.env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--server", result.stderr)

    def test_unknown_server_errors(self):
        """--server nosuch: error mentioning not found."""
        result = _run(["register", "--server", "nosuch"], env=self.env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not found", result.stderr)

    def test_interactive_blank_server_uses_default(self):
        """Interactive, blank server via stdin: uses default-server from config."""
        # stdin: blank server (use default), name, blank id (auto), blank secret (auto)
        stdin_text = "\nint-default\n\n\n"
        result = _run(["register", "--interactive"], env=self.env, stdin_text=stdin_text)
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        client_id, client_secret = self._parse_credentials(result.stdout)
        self._verify_client_on_server(client_id, client_secret)
        self._assert_config_unchanged()
        self._cleanup_client(client_id)

    # --- Existing tests (kept) ---

    def test_register_cli_duplicate(self):
        """register same --new-client-id twice: second fails."""
        dup_id = "cli-dup-id"
        self._cleanup_client(dup_id)
        result = _run(["register", "--server", "testserver", "--new-client-id", dup_id], env=self.env)
        self.assertEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        result = _run(["register", "--server", "testserver", "--new-client-id", dup_id], env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already exists", result.stdout)
        self._cleanup_client(dup_id)

    def test_register_cli_non_admin(self):
        """register with non-admin credentials prints 403 error, no changes on server."""
        with companion.CLIENTS_LOCK:
            clients_before = set(companion.CLIENTS.keys())
        _write_config(
            self.tmp_home,
            {
                "default-server": "testserver",
                "servers": {
                    "testserver": {
                        "url": self.base_url,
                        "client-id": self.nonadmin_id,
                        "client-secret": self.nonadmin_secret,
                    }
                },
            },
        )
        result = _run(["register", "--server", "testserver", "--name", "should-fail"], env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Registration failed", result.stdout)
        self.assertIn("Admin access required", result.stdout)
        # No client was added on the server
        with companion.CLIENTS_LOCK:
            self.assertEqual(set(companion.CLIENTS.keys()), clients_before)


if __name__ == "__main__":
    unittest.main()
