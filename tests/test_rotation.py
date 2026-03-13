#!/usr/bin/env python3
"""
E2E tests for token rotation endpoints and blocking logic.
"""

import contextlib
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

sys.path.insert(0, "src")
import companion


def _make_client_entry(client_secret, admin=False, name="test"):
    salt = secrets.token_hex(16)
    secret_hash = hashlib.sha256((salt + client_secret).encode()).hexdigest()
    return {
        "tokens": [{"salt": salt, "secret_hash": secret_hash}],
        "admin": admin,
        "name": name,
        "registered": "2026-01-01T00:00:00",
    }


def _make_legacy_client_entry(client_secret, admin=False, name="test"):
    """Create a client entry in the old flat salt/secret_hash format."""
    salt = secrets.token_hex(16)
    secret_hash = hashlib.sha256((salt + client_secret).encode()).hexdigest()
    return {
        "salt": salt,
        "secret_hash": secret_hash,
        "admin": admin,
        "name": name,
        "registered": "2026-01-01T00:00:00",
    }


@contextlib.contextmanager
def _fake_config_locked(in_memory_config):
    """A mock _config_locked that uses an in-memory dict instead of the filesystem.

    On exit, it rebuilds ACTIVE_SERVER_CLIENTS from the in-memory config
    just like the real _config_locked does.
    """
    yield in_memory_config
    if companion._ACTIVE_SERVER_NAME:
        companion.ACTIVE_SERVER_CLIENTS = dict(companion._get_clients_from_config(in_memory_config))


class TestTokenRotation(unittest.TestCase):
    """E2E tests for /api/token/start-client-rotation and /api/token/complete-client-rotation."""

    @classmethod
    def setUpClass(cls):
        cls.port = 8920
        cls.base_url = f"http://localhost:{cls.port}"
        # Admin client (for registration endpoint test)
        cls.admin_id = "rotation-admin"
        cls.admin_secret = secrets.token_hex(32)
        cls.admin_token = f"{cls.admin_id}:{cls.admin_secret}"
        # Regular client (main test subject)
        cls.client_id = "rotation-client"
        cls.client_secret = secrets.token_hex(32)
        cls.client_token = f"{cls.client_id}:{cls.client_secret}"
        # Legacy client
        cls.legacy_id = "legacy-client"
        cls.legacy_secret = secrets.token_hex(32)
        cls.legacy_token = f"{cls.legacy_id}:{cls.legacy_secret}"
        # Build all clients
        cls._build_initial_clients()
        # Store originals for reset
        cls._original_clients = json.loads(json.dumps(companion.ACTIVE_SERVER_CLIENTS))
        companion._ACTIVE_SERVER_NAME = "test-rotation"
        # Build the in-memory config that mirrors ACTIVE_SERVER_CLIENTS
        cls._in_memory_config = {
            "servers": {
                "test-rotation": {
                    "url": f"http://localhost:{cls.port}",
                    "clients": json.loads(json.dumps(companion.ACTIVE_SERVER_CLIENTS)),
                }
            }
        }

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
    def _build_initial_clients(cls):
        companion.FILES.clear()
        companion.PREVIEW_STATE = {"file_id": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}
        companion.RATE_LIMIT_STORE.clear()
        companion.ACTIVE_SERVER_CLIENTS.clear()
        companion.ACTIVE_SERVER_CLIENTS[cls.admin_id] = _make_client_entry(cls.admin_secret, admin=True)
        companion.ACTIVE_SERVER_CLIENTS[cls.client_id] = _make_client_entry(cls.client_secret)
        companion.ACTIVE_SERVER_CLIENTS[cls.legacy_id] = _make_legacy_client_entry(cls.legacy_secret)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "httpd"):
            cls.httpd.shutdown()
            cls.httpd.server_close()
        companion._ACTIVE_SERVER_NAME = None

    def setUp(self):
        with companion.RATE_LIMIT_LOCK:
            companion.RATE_LIMIT_STORE.clear()
        # Reset clients and in-memory config to initial state
        companion.ACTIVE_SERVER_CLIENTS.update(json.loads(json.dumps(self._original_clients)))
        self._in_memory_config["servers"]["test-rotation"]["clients"] = json.loads(json.dumps(self._original_clients))
        # Patch _config_locked to use in-memory config
        config_patcher = patch(
            "companion._config_locked",
            lambda: _fake_config_locked(self._in_memory_config),
        )
        config_patcher.start()
        self.addCleanup(config_patcher.stop)
        # Silence request logging
        log_patcher = patch.object(companion.FileShareHandler, "log_message", lambda self_, fmt, *a: None)
        log_patcher.start()
        self.addCleanup(log_patcher.stop)

    def _post_rotation(self, endpoint, auth_token):
        """POST to a rotation endpoint, return parsed JSON or raise HTTPError."""
        url = f"{self.base_url}{endpoint}"
        req = urllib.request.Request(
            url,
            data=b"",
            headers={"Authorization": f"Bearer {auth_token}", "Content-Length": "0"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())

    def _get_files(self, auth_token):
        """GET /api/files — a representative regular endpoint."""
        url = f"{self.base_url}/api/files"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {auth_token}"})
        with urllib.request.urlopen(req) as resp:
            return resp.status

    # ── 1. start-client-rotation returns new secret, server now has 2 tokens ──

    def test_start_rotation_returns_new_secret(self):
        result = self._post_rotation("/api/token/start-client-rotation", self.client_token)
        self.assertTrue(result["success"])
        self.assertEqual(result["client_id"], self.client_id)
        new_secret = result["new_secret"]
        self.assertEqual(len(new_secret), 64)  # token_hex(32)
        # Server should now have 2 tokens
        entry = companion.ACTIVE_SERVER_CLIENTS[self.client_id]
        self.assertEqual(len(entry["tokens"]), 2)

    # ── 2. start-client-rotation fails 409 if already rotating ──

    def test_start_rotation_fails_if_already_rotating(self):
        self._post_rotation("/api/token/start-client-rotation", self.client_token)
        # Second start should fail
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post_rotation("/api/token/start-client-rotation", self.client_token)
        self.assertEqual(cm.exception.code, 409)

    # ── 3. start-client-rotation fails 401 if token is invalid ──

    def test_start_rotation_fails_invalid_token(self):
        bad_token = f"{self.client_id}:{secrets.token_hex(32)}"
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post_rotation("/api/token/start-client-rotation", bad_token)
        self.assertEqual(cm.exception.code, 401)

    # ── 4. complete-client-rotation with new token — keeps new, drops old ──

    def test_complete_rotation_with_new_token(self):
        result = self._post_rotation("/api/token/start-client-rotation", self.client_token)
        new_secret = result["new_secret"]
        new_token = f"{self.client_id}:{new_secret}"
        result = self._post_rotation("/api/token/complete-client-rotation", new_token)
        self.assertTrue(result["success"])
        entry = companion.ACTIVE_SERVER_CLIENTS[self.client_id]
        self.assertEqual(len(entry["tokens"]), 1)
        # New token should work
        self.assertEqual(self._get_files(new_token), 200)
        # Old token should NOT work
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get_files(self.client_token)
        self.assertEqual(cm.exception.code, 401)

    # ── 5. complete-client-rotation with old token — keeps old, drops new ──

    def test_complete_rotation_with_old_token(self):
        self._post_rotation("/api/token/start-client-rotation", self.client_token)
        result = self._post_rotation("/api/token/complete-client-rotation", self.client_token)
        self.assertTrue(result["success"])
        entry = companion.ACTIVE_SERVER_CLIENTS[self.client_id]
        self.assertEqual(len(entry["tokens"]), 1)
        # Old token should still work
        self.assertEqual(self._get_files(self.client_token), 200)

    # ── 6. complete-client-rotation is a no-op if only 1 token ──

    def test_complete_rotation_noop_single_token(self):
        result = self._post_rotation("/api/token/complete-client-rotation", self.client_token)
        self.assertTrue(result["success"])
        entry = companion.ACTIVE_SERVER_CLIENTS[self.client_id]
        self.assertEqual(len(entry["tokens"]), 1)
        # Still works
        self.assertEqual(self._get_files(self.client_token), 200)

    # ── 7. Regular endpoints return 409 when client has 2 tokens ──

    def test_regular_endpoints_blocked_during_rotation(self):
        self._post_rotation("/api/token/start-client-rotation", self.client_token)
        # GET /api/files should be blocked
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get_files(self.client_token)
        self.assertEqual(cm.exception.code, 409)
        body = json.loads(cm.exception.read().decode())
        self.assertIn("rotation in progress", body["error"].lower())
        # POST /api/pad should be blocked
        url = f"{self.base_url}/api/pad"
        data = json.dumps({"content": "test"}).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.client_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 409)

    # ── 8. All endpoints return 401 when token is completely invalid ──

    def test_invalid_token_always_401(self):
        bogus_token = f"nonexistent:{secrets.token_hex(32)}"
        # Regular endpoint
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get_files(bogus_token)
        self.assertEqual(cm.exception.code, 401)
        # Rotation endpoints
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post_rotation("/api/token/start-client-rotation", bogus_token)
        self.assertEqual(cm.exception.code, 401)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post_rotation("/api/token/complete-client-rotation", bogus_token)
        self.assertEqual(cm.exception.code, 401)

    # ── 9. Rotation endpoints still work during 2-token state ──

    def test_rotation_endpoints_not_blocked_during_rotation(self):
        self._post_rotation("/api/token/start-client-rotation", self.client_token)
        # complete should still work (rotation_ok=True)
        result = self._post_rotation("/api/token/complete-client-rotation", self.client_token)
        self.assertTrue(result["success"])

    # ── 10. Auth works with single-element tokens list ──

    def test_auth_single_token_list(self):
        self.assertEqual(self._get_files(self.client_token), 200)

    # ── 11. Auth works with either token during rotation ──

    def test_auth_either_token_during_rotation(self):
        result = self._post_rotation("/api/token/start-client-rotation", self.client_token)
        # Old token should authenticate on rotation endpoints
        result_old = self._post_rotation("/api/token/complete-client-rotation", self.client_token)
        self.assertTrue(result_old["success"])
        # Reset and start again to test new token
        companion.ACTIVE_SERVER_CLIENTS[self.client_id] = json.loads(json.dumps(self._original_clients[self.client_id]))
        result = self._post_rotation("/api/token/start-client-rotation", self.client_token)
        new_secret = result["new_secret"]
        new_token = f"{self.client_id}:{new_secret}"
        # New token should also authenticate on rotation endpoints
        result_new = self._post_rotation("/api/token/complete-client-rotation", new_token)
        self.assertTrue(result_new["success"])

    # ── 12. Auth rejects wrong secret even during rotation ──

    def test_wrong_secret_rejected_during_rotation(self):
        self._post_rotation("/api/token/start-client-rotation", self.client_token)
        wrong_token = f"{self.client_id}:{secrets.token_hex(32)}"
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post_rotation("/api/token/complete-client-rotation", wrong_token)
        self.assertEqual(cm.exception.code, 401)

    # ── 13. Legacy format still authenticates ──

    def test_legacy_format_authenticates(self):
        self.assertEqual(self._get_files(self.legacy_token), 200)

    # ── 14. Happy path: start → complete with new → old stops working ──

    def test_full_rotation_old_revoked(self):
        result = self._post_rotation("/api/token/start-client-rotation", self.client_token)
        new_secret = result["new_secret"]
        new_token = f"{self.client_id}:{new_secret}"
        self._post_rotation("/api/token/complete-client-rotation", new_token)
        # New works
        self.assertEqual(self._get_files(new_token), 200)
        # Old is dead
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get_files(self.client_token)
        self.assertEqual(cm.exception.code, 401)

    # ── 15. Start → complete with old → new stops working ──

    def test_full_rotation_new_revoked(self):
        result = self._post_rotation("/api/token/start-client-rotation", self.client_token)
        new_secret = result["new_secret"]
        new_token = f"{self.client_id}:{new_secret}"
        self._post_rotation("/api/token/complete-client-rotation", self.client_token)
        # Old works
        self.assertEqual(self._get_files(self.client_token), 200)
        # New is dead
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get_files(new_token)
        self.assertEqual(cm.exception.code, 401)

    # ── 16. start-client-rotation migrates legacy format ──

    def test_start_rotation_migrates_legacy(self):
        entry = companion.ACTIVE_SERVER_CLIENTS[self.legacy_id]
        # Verify it's legacy format
        self.assertNotIn("tokens", entry)
        self.assertIn("salt", entry)
        result = self._post_rotation("/api/token/start-client-rotation", self.legacy_token)
        self.assertTrue(result["success"])
        entry = companion.ACTIVE_SERVER_CLIENTS[self.legacy_id]
        self.assertIn("tokens", entry)
        self.assertEqual(len(entry["tokens"]), 2)
        # Legacy flat fields should be gone
        self.assertNotIn("salt", entry)
        self.assertNotIn("secret_hash", entry)

    # ── 17. complete-client-rotation migrates legacy format ──

    def test_complete_rotation_migrates_legacy(self):
        """complete-client-rotation on a legacy client should migrate to tokens format."""
        entry = companion.ACTIVE_SERVER_CLIENTS[self.legacy_id]
        # Verify it's legacy format
        self.assertNotIn("tokens", entry)
        self.assertIn("salt", entry)
        self.assertIn("secret_hash", entry)

        result = self._post_rotation("/api/token/complete-client-rotation", self.legacy_token)
        self.assertTrue(result["success"])

        entry = companion.ACTIVE_SERVER_CLIENTS[self.legacy_id]
        self.assertIn("tokens", entry)
        self.assertEqual(len(entry["tokens"]), 1)
        self.assertNotIn("salt", entry)
        self.assertNotIn("secret_hash", entry)

        # Token still works after migration
        self.assertEqual(self._get_files(self.legacy_token), 200)

    # ── 18. Full rotation cycle on legacy client ──

    def test_full_rotation_legacy_client(self):
        """start → complete on a legacy client should end with new-format single token."""
        result = self._post_rotation("/api/token/start-client-rotation", self.legacy_token)
        new_secret = result["new_secret"]
        new_token = f"{self.legacy_id}:{new_secret}"

        self._post_rotation("/api/token/complete-client-rotation", new_token)

        entry = companion.ACTIVE_SERVER_CLIENTS[self.legacy_id]
        self.assertIn("tokens", entry)
        self.assertEqual(len(entry["tokens"]), 1)
        self.assertNotIn("salt", entry)
        self.assertNotIn("secret_hash", entry)

        # New token works, old doesn't
        self.assertEqual(self._get_files(new_token), 200)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get_files(self.legacy_token)
        self.assertEqual(cm.exception.code, 401)

    # ── 19. Non-rotation 409 (duplicate client_id) is distinct ──

    def test_non_rotation_409_not_confused(self):
        """A 409 from duplicate client_id on register should not contain rotation error message."""
        # Register a client
        url = f"{self.base_url}/api/clients/register"
        data = json.dumps({"client_id": "dup-test", "client_secret": secrets.token_hex(32), "name": "dup"}).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self.admin_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        urllib.request.urlopen(req)
        # Try to register the same client_id again
        data2 = json.dumps({"client_id": "dup-test", "client_secret": secrets.token_hex(32), "name": "dup2"}).encode()
        req2 = urllib.request.Request(
            url,
            data=data2,
            headers={
                "Authorization": f"Bearer {self.admin_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req2)
        self.assertEqual(cm.exception.code, 409)
        body = json.loads(cm.exception.read().decode())
        # This 409 is about duplicate client_id, NOT about rotation
        self.assertNotIn("rotation", body["error"].lower())
        self.assertIn("already exists", body["error"])


class _RotateCmdTestBase(unittest.TestCase):
    """Shared infrastructure for rotate_cmd and complete_rotation_cmd tests.

    Spins up a test server on a dedicated port. Provides helpers to set up
    server state, mock local config, and run CLI commands.
    """

    port = None  # Subclasses must set

    @classmethod
    def setUpClass(cls):
        cls.base_url = f"http://localhost:{cls.port}"
        cls.server_name = f"test-cmd-{cls.port}"
        cls.client_id = f"cmd-client-{cls.port}"

        companion.FILES.clear()
        companion.PREVIEW_STATE = {"file_id": None, "timestamp": 0}
        companion.PAD_STATE = {"content": "", "timestamp": 0}
        companion.RATE_LIMIT_STORE.clear()

        # Start with a dummy entry — each test resets it
        dummy_secret = secrets.token_hex(32)
        companion.ACTIVE_SERVER_CLIENTS[cls.client_id] = _make_client_entry(dummy_secret)
        companion._ACTIVE_SERVER_NAME = cls.server_name

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
        companion._ACTIVE_SERVER_NAME = None

    def _reset_server_client(self, secret):
        """Reset the server client to a single-token state with the given secret."""
        companion.ACTIVE_SERVER_CLIENTS[self.client_id] = _make_client_entry(secret)

    def _server_config(self):
        """Build an in-memory config for server-side _config_locked."""
        return {
            "servers": {
                self.server_name: {
                    "url": self.base_url,
                    "clients": {
                        self.client_id: json.loads(json.dumps(companion.ACTIVE_SERVER_CLIENTS[self.client_id]))
                    },
                }
            },
        }

    def _start_server_rotation(self, auth_token):
        """Start rotation on the server via HTTP, returning the new secret."""
        config = self._server_config()
        with patch("companion._config_locked", lambda: _fake_config_locked(config)):
            url = f"{self.base_url}/api/token/start-client-rotation"
            req = urllib.request.Request(
                url,
                data=b"",
                headers={"Authorization": f"Bearer {auth_token}", "Content-Length": "0"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read().decode())["new_secret"]

    def _build_config(self, local_secrets):
        """Build an in-memory config with the given client-secrets list."""
        return {
            "default-server": self.server_name,
            "servers": {
                self.server_name: {
                    "url": self.base_url,
                    "client-id": self.client_id,
                    "client-secrets": list(local_secrets),
                    "clients": json.loads(json.dumps(companion.ACTIVE_SERVER_CLIENTS)),
                }
            },
        }

    def _run_cmd(self, cmd_func, local_secrets):
        """Run a rotate/complete command with mocked config.

        Returns (exit_code, final_client_secrets).
        """
        config = self._build_config(local_secrets)

        with patch("companion.load_config", return_value=config), patch(
            "companion._config_locked", lambda: _fake_config_locked(config)
        ), patch.object(companion.FileShareHandler, "log_message", lambda self_, fmt, *a: None):
            try:
                mock_args = type("Args", (), {"server": self.server_name, "url": None, "auth_token": None})()
                cmd_func(mock_args)
                exit_code = 0
            except SystemExit as e:
                exit_code = e.code if e.code is not None else 0

            final_secrets = config["servers"][self.server_name].get("client-secrets", [])
            return exit_code, final_secrets

    def _assert_success_with_valid_secret(self, exit_code, final_secrets):
        """Assert command succeeded and exactly 1 valid secret remains."""
        self.assertIn(exit_code, (0, None), "command should succeed")
        self.assertEqual(len(final_secrets), 1, "should end with exactly 1 local secret")
        # The surviving secret should authenticate against the server
        token = f"{self.client_id}:{final_secrets[0]}"
        url = f"{self.base_url}/api/files"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)

    def _assert_failure(self, exit_code):
        """Assert command failed."""
        self.assertEqual(exit_code, 1, "command should fail")


class TestRotateCmd(_RotateCmdTestBase):
    """Test rotate_cmd (full rotation) — local config has exactly 1 secret.

    Server states: [ours], [invalid], [invalid, ours], [ours, invalid]
    """

    port = 8921

    def _run(self, local_secrets):
        return self._run_cmd(companion.rotate_cmd, local_secrets)

    # ── Server has 1 token ──

    def test_server_has_ours(self):
        """Server=[ours]. Happy path: start rotation, complete it."""
        ours = secrets.token_hex(32)
        self._reset_server_client(ours)
        exit_code, final = self._run([ours])
        self._assert_success_with_valid_secret(exit_code, final)
        # The surviving secret should be different from the original (rotated)
        self.assertNotEqual(final[0], ours)

    def test_server_has_invalid(self):
        """Server=[invalid]. Our secret doesn't match — should fail."""
        ours = secrets.token_hex(32)
        other = secrets.token_hex(32)
        self._reset_server_client(other)
        exit_code, _final = self._run([ours])
        self._assert_failure(exit_code)

    # ── Server has 2 tokens (stale rotation) ──

    def test_server_has_invalid_ours(self):
        """Server=[invalid, ours]. 409 on start — complete with ours, then re-run would rotate."""
        previous = secrets.token_hex(32)
        self._reset_server_client(previous)
        ours = self._start_server_rotation(f"{self.client_id}:{previous}")
        # Now server has [previous, ours]. Local only has [ours].
        exit_code, final = self._run([ours])
        self._assert_success_with_valid_secret(exit_code, final)

    def test_server_has_ours_invalid(self):
        """Server=[ours, invalid]. 409 on start — complete with ours."""
        ours = secrets.token_hex(32)
        self._reset_server_client(ours)
        _next = self._start_server_rotation(f"{self.client_id}:{ours}")
        # Now server has [ours, next]. Local only has [ours].
        exit_code, final = self._run([ours])
        self._assert_success_with_valid_secret(exit_code, final)

    # ── Rejects 2 local secrets ──

    def test_rejects_two_local_secrets(self):
        """rotate_cmd should refuse to run when local config has 2 secrets."""
        ours = secrets.token_hex(32)
        self._reset_server_client(ours)
        exit_code, _final = self._run([ours, secrets.token_hex(32)])
        self._assert_failure(exit_code)


class TestCompleteRotationCmd(_RotateCmdTestBase):
    """Test complete_rotation_cmd — local config has exactly 2 secrets.

    Tries each local secret against the server, converges to 1.
    Server states with local=[first, last]:
      [invalid], [first], [last], [first,last], [first,invalid],
      [invalid,last], [last,first], [invalid,invalid]
    """

    port = 8922

    def _run(self, local_secrets):
        return self._run_cmd(companion.complete_rotation_cmd, local_secrets)

    # ── Server has 1 token ──

    def test_server_has_first(self):
        """Server=[first]. Only first local secret is valid."""
        first = secrets.token_hex(32)
        last = secrets.token_hex(32)
        self._reset_server_client(first)
        exit_code, final = self._run([first, last])
        self._assert_success_with_valid_secret(exit_code, final)
        self.assertEqual(final[0], first)

    def test_server_has_last(self):
        """Server=[last]. Only last local secret is valid."""
        first = secrets.token_hex(32)
        last = secrets.token_hex(32)
        self._reset_server_client(last)
        exit_code, final = self._run([first, last])
        self._assert_success_with_valid_secret(exit_code, final)
        self.assertEqual(final[0], last)

    def test_server_has_invalid(self):
        """Server=[invalid]. Neither local secret matches — should fail."""
        first = secrets.token_hex(32)
        last = secrets.token_hex(32)
        other = secrets.token_hex(32)
        self._reset_server_client(other)
        exit_code, _final = self._run([first, last])
        self._assert_failure(exit_code)

    # ── Server has 2 tokens ──

    def test_server_has_first_last(self):
        """Server=[first, last]. Both match, keep last (newest local)."""
        first = secrets.token_hex(32)
        self._reset_server_client(first)
        last = self._start_server_rotation(f"{self.client_id}:{first}")
        exit_code, final = self._run([first, last])
        self._assert_success_with_valid_secret(exit_code, final)
        self.assertEqual(final[0], last)

    def test_server_has_first_invalid(self):
        """Server=[first, invalid]. First matches, invalid doesn't."""
        first = secrets.token_hex(32)
        self._reset_server_client(first)
        _server_next = self._start_server_rotation(f"{self.client_id}:{first}")
        # local has [first, random] — random doesn't match server's next
        random_secret = secrets.token_hex(32)
        exit_code, final = self._run([first, random_secret])
        self._assert_success_with_valid_secret(exit_code, final)
        self.assertEqual(final[0], first)

    def test_server_has_invalid_last(self):
        """Server=[invalid, last]. Last matches."""
        first = secrets.token_hex(32)
        self._reset_server_client(first)
        last = self._start_server_rotation(f"{self.client_id}:{first}")
        # local has [random, last]
        random_secret = secrets.token_hex(32)
        exit_code, final = self._run([random_secret, last])
        self._assert_success_with_valid_secret(exit_code, final)
        self.assertEqual(final[0], last)

    def test_server_has_last_first(self):
        """Server=[last, first] (reversed order). Both match, keep last (newest local)."""
        # Create server with "last" first, then rotate to get "first" as second
        last = secrets.token_hex(32)
        self._reset_server_client(last)
        first = self._start_server_rotation(f"{self.client_id}:{last}")
        # Server has [last, first]. Local has [first, last].
        # "last" is our newest local secret — should keep it.
        exit_code, final = self._run([first, last])
        self._assert_success_with_valid_secret(exit_code, final)
        self.assertEqual(final[0], last)

    def test_server_has_invalid_invalid(self):
        """Server=[invalid, invalid]. Neither local secret matches — should fail."""
        other1 = secrets.token_hex(32)
        self._reset_server_client(other1)
        _other2 = self._start_server_rotation(f"{self.client_id}:{other1}")
        # local has two secrets that match neither server token
        exit_code, _final = self._run([secrets.token_hex(32), secrets.token_hex(32)])
        self._assert_failure(exit_code)

    # ── Rejects 1 local secret ──

    def test_rejects_one_local_secret(self):
        """complete_rotation_cmd should refuse to run when local config has only 1 secret."""
        ours = secrets.token_hex(32)
        self._reset_server_client(ours)
        exit_code, _final = self._run([ours])
        self._assert_failure(exit_code)


if __name__ == "__main__":
    unittest.main()
