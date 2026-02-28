#!/usr/bin/env python3
"""Tests for server-setup and server-add-user CLI commands.

Covers both non-interactive (strict, default) and --interactive modes.
Each test uses a temp HOME so it never touches real config.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


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


def _read_config(tmp_home):
    config_path = Path(tmp_home) / ".config" / "companion" / "config.json"
    with open(config_path) as f:
        return json.load(f)


class TestServerSetupNonInteractive(unittest.TestCase):
    """server-setup in default (non-interactive) mode."""

    def setUp(self):
        self.tmp_home = tempfile.mkdtemp()
        self.env = _make_env(self.tmp_home)

    def test_missing_url_exits_with_error(self):
        """server-setup without --url should exit 1 and mention --url and --interactive."""
        result = _run(["server-setup"], env=self.env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--url", result.stderr)
        self.assertIn("--interactive", result.stderr)

    def test_url_only_auto_generates_credentials(self):
        """server-setup --url <url> should succeed and auto-generate client-id/secret."""
        result = _run(["server-setup", "--url", "http://example.com:8080"], env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        server = config["servers"]["default"]
        self.assertEqual(server["url"], "http://example.com:8080")
        self.assertTrue(len(server["client-id"]) > 0)
        self.assertTrue(len(server["client-secret"]) > 0)
        self.assertIn(server["client-id"], server["clients"])
        self.assertEqual(config["default-server"], "default")

    def test_all_flags_uses_exact_values(self):
        """server-setup with all flags should store the exact provided values."""
        result = _run(
            [
                "server-setup",
                "--server",
                "myserver",
                "--url",
                "http://my.host:9090",
                "--client-id",
                "my-id-123",
                "--client-secret",
                "my-secret-456",
                "--client-name",
                "Admin Bob",
            ],
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        server = config["servers"]["myserver"]
        self.assertEqual(server["url"], "http://my.host:9090")
        self.assertEqual(server["client-id"], "my-id-123")
        self.assertEqual(server["client-secret"], "my-secret-456")
        client = server["clients"]["my-id-123"]
        self.assertTrue(client["admin"])
        self.assertEqual(client["name"], "Admin Bob")

    def test_default_server_name(self):
        """Without --server, the server name defaults to 'default'."""
        result = _run(["server-setup", "--url", "http://localhost:8080"], env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        self.assertIn("default", config["servers"])


class TestServerAddUserNonInteractive(unittest.TestCase):
    """server-add-user in default (non-interactive) mode."""

    def setUp(self):
        self.tmp_home = tempfile.mkdtemp()
        self.env = _make_env(self.tmp_home)

    def _setup_server(self):
        result = _run(
            ["server-setup", "--url", "http://localhost:8080", "--server", "default"],
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_config_exits_with_error(self):
        """server-add-user without any config should exit 1."""
        result = _run(["server-add-user"], env=self.env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("No config file found", result.stderr)

    def test_after_setup_auto_generates(self):
        """server-add-user after setup should succeed with auto-generated credentials."""
        self._setup_server()
        result = _run(["server-add-user"], env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        server = config["servers"]["default"]
        clients = server["clients"]
        # Should have 2 clients: the admin from setup + the new user
        self.assertEqual(len(clients), 2)
        # The admin client is keyed by server["client-id"]
        admin_id = server["client-id"]
        self.assertIn(admin_id, clients)
        self.assertTrue(clients[admin_id]["admin"])
        # The other client is the newly added user
        user_ids = [cid for cid in clients if cid != admin_id]
        self.assertEqual(len(user_ids), 1)
        user = clients[user_ids[0]]
        self.assertFalse(user["admin"])
        self.assertIn("salt", user)
        self.assertIn("secret_hash", user)
        self.assertIn("registered", user)

    def test_explicit_credentials(self):
        """server-add-user with explicit flags stores those values."""
        self._setup_server()
        result = _run(
            [
                "server-add-user",
                "--client-id",
                "user-id-abc",
                "--client-secret",
                "user-secret-xyz",
                "--client-name",
                "Alice",
            ],
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        client = config["servers"]["default"]["clients"]["user-id-abc"]
        self.assertFalse(client["admin"])
        self.assertEqual(client["name"], "Alice")

    def test_admin_flag(self):
        """server-add-user --admin grants admin privileges."""
        self._setup_server()
        result = _run(
            ["server-add-user", "--admin", "--client-id", "admin2"],
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        self.assertTrue(config["servers"]["default"]["clients"]["admin2"]["admin"])


class TestServerSetupInteractive(unittest.TestCase):
    """server-setup with --interactive flag."""

    def setUp(self):
        self.tmp_home = tempfile.mkdtemp()
        self.env = _make_env(self.tmp_home)

    def test_prompts_for_all_fields(self):
        """--interactive with stdin providing all fields should succeed."""
        stdin_lines = "myserver\nhttp://test.local:5000\ncustom-id\ncustom-secret\nMy Admin\n"
        result = _run(["server-setup", "--interactive"], env=self.env, stdin_text=stdin_lines)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        server = config["servers"]["myserver"]
        self.assertEqual(server["url"], "http://test.local:5000")
        self.assertEqual(server["client-id"], "custom-id")
        self.assertEqual(server["client-secret"], "custom-secret")
        client = server["clients"]["custom-id"]
        self.assertEqual(client["name"], "My Admin")

    def test_blanks_auto_generate(self):
        """--interactive with blank inputs for auto-gen fields should auto-generate."""
        # server name blank -> "default", url provided, client-id blank, secret blank, name blank
        stdin_lines = "\nhttp://auto.local:8080\n\n\n\n"
        result = _run(["server-setup", "--interactive"], env=self.env, stdin_text=stdin_lines)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        server = config["servers"]["default"]
        self.assertEqual(server["url"], "http://auto.local:8080")
        # Client ID and secret should be auto-generated (hex strings)
        self.assertEqual(len(server["client-id"]), 32)  # token_hex(16) = 32 chars
        self.assertEqual(len(server["client-secret"]), 64)  # token_hex(32) = 64 chars

    def test_url_flag_skips_url_prompt(self):
        """--interactive --url <url> should not prompt for URL."""
        # Only prompts for: server name, client-id, client-secret, client-name
        stdin_lines = "srv1\nmy-cid\nmy-csecret\nBob\n"
        result = _run(
            ["server-setup", "--interactive", "--url", "http://flagged.local:3000"],
            env=self.env,
            stdin_text=stdin_lines,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        server = config["servers"]["srv1"]
        self.assertEqual(server["url"], "http://flagged.local:3000")
        self.assertEqual(server["client-id"], "my-cid")
        self.assertEqual(server["client-secret"], "my-csecret")


class TestServerAddUserInteractive(unittest.TestCase):
    """server-add-user with --interactive flag."""

    def setUp(self):
        self.tmp_home = tempfile.mkdtemp()
        self.env = _make_env(self.tmp_home)
        # Pre-create config via non-interactive setup
        result = _run(
            ["server-setup", "--url", "http://localhost:8080"],
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_interactive_provides_values(self):
        """--interactive with stdin providing all values should succeed."""
        stdin_lines = "new-client-id\nnew-client-secret\nNew User\n"
        result = _run(
            ["server-add-user", "--interactive"],
            env=self.env,
            stdin_text=stdin_lines,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        client = config["servers"]["default"]["clients"]["new-client-id"]
        self.assertFalse(client["admin"])
        self.assertEqual(client["name"], "New User")

    def test_interactive_blanks_auto_generate(self):
        """--interactive with blank inputs should auto-generate client-id/secret."""
        stdin_lines = "\n\n\n"
        result = _run(
            ["server-add-user", "--interactive"],
            env=self.env,
            stdin_text=stdin_lines,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        clients = config["servers"]["default"]["clients"]
        self.assertEqual(len(clients), 2)


class TestConnectNonInteractive(unittest.TestCase):
    """connect in default (non-interactive) mode."""

    def setUp(self):
        self.tmp_home = tempfile.mkdtemp()
        self.env = _make_env(self.tmp_home)

    def test_missing_all_required_flags(self):
        """connect with no flags should exit 1 and list all missing flags + --interactive."""
        result = _run(["connect"], env=self.env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--url", result.stderr)
        self.assertIn("--client-id", result.stderr)
        self.assertIn("--client-secret", result.stderr)
        self.assertIn("--interactive", result.stderr)

    def test_missing_url_only(self):
        """connect with --client-id and --client-secret but no --url should mention --url."""
        result = _run(
            ["connect", "--client-id", "cid", "--client-secret", "csec"],
            env=self.env,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("--url", result.stderr)

    def test_all_flags_saves_config(self):
        """connect with all required flags should save credentials and set default-server."""
        result = _run(
            [
                "connect",
                "--url",
                "http://example.com:8080",
                "--client-id",
                "my-id",
                "--client-secret",
                "my-secret",
            ],
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        server = config["servers"]["default"]
        self.assertEqual(server["url"], "http://example.com:8080")
        self.assertEqual(server["client-id"], "my-id")
        self.assertEqual(server["client-secret"], "my-secret")
        self.assertEqual(config["default-server"], "default")

    def test_custom_server_name(self):
        """connect --server myname should use that name."""
        result = _run(
            [
                "connect",
                "--server",
                "myname",
                "--url",
                "http://host:9090",
                "--client-id",
                "cid",
                "--client-secret",
                "csec",
            ],
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        self.assertIn("myname", config["servers"])


class TestConnectInteractive(unittest.TestCase):
    """connect with --interactive flag."""

    def setUp(self):
        self.tmp_home = tempfile.mkdtemp()
        self.env = _make_env(self.tmp_home)

    def test_interactive_all_fields(self):
        """--interactive with stdin providing all fields should succeed."""
        stdin_lines = "http://test.local:5000\nmy-cid\nmy-csecret\n"
        result = _run(["connect", "--interactive"], env=self.env, stdin_text=stdin_lines)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        server = config["servers"]["default"]
        self.assertEqual(server["url"], "http://test.local:5000")
        self.assertEqual(server["client-id"], "my-cid")
        self.assertEqual(server["client-secret"], "my-csecret")

    def test_interactive_with_url_pre_provided(self):
        """--interactive --url <url> should only prompt for client-id and client-secret."""
        stdin_lines = "prompted-cid\nprompted-csecret\n"
        result = _run(
            ["connect", "--interactive", "--url", "http://flagged.local:3000"],
            env=self.env,
            stdin_text=stdin_lines,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        config = _read_config(self.tmp_home)
        server = config["servers"]["default"]
        self.assertEqual(server["url"], "http://flagged.local:3000")
        self.assertEqual(server["client-id"], "prompted-cid")
        self.assertEqual(server["client-secret"], "prompted-csecret")


class TestRegisterNonInteractive(unittest.TestCase):
    """register in default (non-interactive) mode."""

    def setUp(self):
        self.tmp_home = tempfile.mkdtemp()
        self.env = _make_env(self.tmp_home)

    def test_no_config_no_flags_exits_with_error(self):
        """register with no config and no flags should exit 1 and list missing flags."""
        result = _run(["register"], env=self.env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("--server-url", result.stderr)
        self.assertIn("--client-id", result.stderr)
        self.assertIn("--client-secret", result.stderr)
        self.assertIn("--interactive", result.stderr)

    def test_missing_server_url_only(self):
        """register with --client-id and --client-secret but no --server-url should mention --server-url."""
        result = _run(
            ["register", "--client-id", "admin-id", "--client-secret", "admin-secret"],
            env=self.env,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("--server-url", result.stderr)

    def test_all_flags_passes_validation(self):
        """register with all flags should pass validation (fail at network, not 'Missing')."""
        result = _run(
            [
                "register",
                "--server-url",
                "http://localhost:99999",
                "--client-id",
                "admin-id",
                "--client-secret",
                "admin-secret",
                "--name",
                "test-client",
            ],
            env=self.env,
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Missing", result.stderr)


class TestRegisterInteractive(unittest.TestCase):
    """register with --interactive flag."""

    def setUp(self):
        self.tmp_home = tempfile.mkdtemp()
        self.env = _make_env(self.tmp_home)

    def test_interactive_all_fields(self):
        """--interactive with stdin providing all fields should pass validation."""
        stdin_lines = "http://localhost:99999\nadmin-id\nadmin-secret\ntest-client\n"
        result = _run(["register", "--interactive"], env=self.env, stdin_text=stdin_lines)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Missing", result.stderr)

    def test_interactive_with_server_url_pre_provided(self):
        """--interactive --server-url <url> should only prompt for remaining fields."""
        stdin_lines = "admin-id\nadmin-secret\ntest-client\n"
        result = _run(
            ["register", "--interactive", "--server-url", "http://localhost:99999"],
            env=self.env,
            stdin_text=stdin_lines,
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Missing", result.stderr)


if __name__ == "__main__":
    unittest.main()
