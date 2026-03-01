#!/usr/bin/env python3
"""Tests for _config_locked context manager and caller validation.

Each test patches CONFIG_PATH / _CONFIG_LOCK_PATH to a temp dir so it
never touches real config.
"""

import fcntl
import glob
import json
import os
import subprocess
import tempfile
import threading
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


def _write_config(tmp_home, config):
    config_path = Path(tmp_home) / ".config" / "companion" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)


def _import_companion():
    """Import companion module with CONFIG_PATH pointed at a temp dir."""
    import importlib
    import sys

    script = _companion_script()
    spec = importlib.util.spec_from_file_location("companion", script)
    mod = importlib.util.module_from_spec(spec)
    # Don't pollute sys.modules for other tests
    old = sys.modules.get("companion")
    sys.modules["companion"] = mod
    spec.loader.exec_module(mod)
    if old is not None:
        sys.modules["companion"] = old
    else:
        del sys.modules["companion"]
    return mod


def _patch_paths(mod, tmp_dir):
    """Point CONFIG_PATH and _CONFIG_LOCK_PATH at tmp_dir."""
    mod.CONFIG_PATH = Path(tmp_dir) / ".config" / "companion" / "config.json"
    mod._CONFIG_LOCK_PATH = mod.CONFIG_PATH.with_suffix(".lock")


# ---------------------------------------------------------------------------
# Context manager tests (unit-level, import the module directly)
# ---------------------------------------------------------------------------


class TestConfigLockedContextManager(unittest.TestCase):
    """Test _config_locked() directly."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.mod = _import_companion()
        _patch_paths(self.mod, self.tmp_dir)

    def _assert_no_dangling(self):
        """Assert no .tmp files remain and the lock file is released."""
        config_dir = str(self.mod.CONFIG_PATH.parent)
        dangling = glob.glob(os.path.join(config_dir, "*.tmp"))
        self.assertEqual(dangling, [], f"Dangling .tmp files found: {dangling}")
        lock_path = str(self.mod._CONFIG_LOCK_PATH)
        if os.path.exists(lock_path):
            fd = os.open(lock_path, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
            except BlockingIOError:
                self.fail("Lock file is still held after _config_locked() exited")
            finally:
                os.close(fd)

    def test_config_locked_reads_and_writes(self):
        """Write initial config, mutate via _config_locked, verify file updated."""
        config_path = self.mod.CONFIG_PATH
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump({"key": "old"}, f)
        with self.mod._config_locked() as cfg:
            self.assertEqual(cfg["key"], "old")
            cfg["key"] = "new"
            cfg["added"] = True
        with open(config_path) as f:
            result = json.load(f)
        self._assert_no_dangling()
        self.assertEqual(result["key"], "new")
        self.assertTrue(result["added"])

    def test_config_locked_no_write_on_exception(self):
        """If an exception is raised inside the with-block, config is unchanged."""
        config_path = self.mod.CONFIG_PATH
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump({"key": "original"}, f)
        with self.assertRaises(ValueError):
            with self.mod._config_locked() as cfg:
                cfg["key"] = "modified"
                raise ValueError("boom")
        with open(config_path) as f:
            result = json.load(f)
        self._assert_no_dangling()
        self.assertEqual(result["key"], "original")

    def test_config_locked_no_write_on_sys_exit(self):
        """sys.exit() inside the with-block should not write config."""
        config_path = self.mod.CONFIG_PATH
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump({"key": "original"}, f)
        with self.assertRaises(SystemExit):
            with self.mod._config_locked() as cfg:
                cfg["key"] = "modified"
                raise SystemExit(1)
        with open(config_path) as f:
            result = json.load(f)
        self._assert_no_dangling()
        self.assertEqual(result["key"], "original")

    def test_config_locked_serializes_concurrent_writes(self):
        """16 threads each add a unique key; verify no data loss.

        Without locking threads would read stale config and overwrite
        each other's keys, so a high thread count makes that likely.
        Verified: fails (4/16 keys) with _lock_file disabled.
        """
        config_path = self.mod.CONFIG_PATH
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump({"counters": {}}, f)
        mod = self.mod

        def worker(name):
            with mod._config_locked() as cfg:
                counters = cfg.setdefault("counters", {})
                counters[name] = True

        n_threads = 16
        threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        with open(config_path) as f:
            result = json.load(f)
        self.assertEqual(len(result["counters"]), n_threads)
        for i in range(n_threads):
            self.assertIn(f"t{i}", result["counters"])

    def test_config_locked_read_modify_write_concurrent(self):
        """16 threads each read a counter, increment, write back; final value must be 16.

        This is a classic read-modify-write race: without locking multiple
        threads would read the same value and the final count would be less
        than 16.
        Verified: fails (4/16 increments) with _lock_file disabled.
        """
        config_path = self.mod.CONFIG_PATH
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump({"counter": 0}, f)
        mod = self.mod

        def increment():
            with mod._config_locked() as cfg:
                cfg["counter"] = cfg.get("counter", 0) + 1

        n_threads = 16
        threads = [threading.Thread(target=increment) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        with open(config_path) as f:
            result = json.load(f)
        self._assert_no_dangling()
        self.assertEqual(result["counter"], n_threads)


# ---------------------------------------------------------------------------
# Caller validation tests (subprocess-based, matching test_setup_commands.py)
# ---------------------------------------------------------------------------


class TestSaveClientsMissingServer(unittest.TestCase):
    """_save_clients_to_config with server not in config."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.mod = _import_companion()
        _patch_paths(self.mod, self.tmp_dir)

    def test_save_clients_fails_if_server_missing(self):
        """_save_clients_to_config logs error and doesn't write when server missing."""
        config_path = self.mod.CONFIG_PATH
        config_path.parent.mkdir(parents=True, exist_ok=True)
        initial = {"servers": {"other": {"url": "http://localhost"}}}
        with open(config_path, "w") as f:
            json.dump(initial, f)
        self.mod._ACTIVE_SERVER_NAME = "nonexistent"
        self.mod.CLIENTS = {"c1": {"salt": "s", "secret_hash": "h", "admin": False}}
        with self.assertLogs("companion", level="ERROR") as cm:
            self.mod._save_clients_to_config()
        self.assertIn("not found in config", cm.output[0])
        # Config should still be written (context manager completes cleanly after return)
        # but the server entry should NOT have been created
        with open(config_path) as f:
            result = json.load(f)
        config_dir = str(config_path.parent)
        dangling = glob.glob(os.path.join(config_dir, "*.tmp"))
        self.assertEqual(dangling, [], f"Dangling .tmp files found: {dangling}")
        lock_path = str(self.mod._CONFIG_LOCK_PATH)
        if os.path.exists(lock_path):
            fd = os.open(lock_path, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
            except BlockingIOError:
                self.fail("Lock file is still held after _save_clients_to_config()")
            finally:
                os.close(fd)
        self.assertNotIn("nonexistent", result["servers"])


class TestAddUserFailsIfServerMissing(unittest.TestCase):
    """server-add-user with server not in config gives clean error."""

    def setUp(self):
        self.tmp_home = tempfile.mkdtemp()
        self.env = _make_env(self.tmp_home)

    def test_add_user_fails_if_server_missing(self):
        """server-add-user with nonexistent --server should print error, not KeyError."""
        # Create config with one server
        _write_config(
            self.tmp_home,
            {
                "default-server": "myserver",
                "servers": {"myserver": {"url": "http://localhost:8080"}},
            },
        )
        result = _run(["server-add-user", "--server", "nosuchserver"], env=self.env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not found", result.stderr)
        self.assertNotIn("KeyError", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        config_dir = Path(self.tmp_home) / ".config" / "companion"
        dangling = glob.glob(str(config_dir / "*.tmp"))
        self.assertEqual(dangling, [], f"Dangling .tmp files found: {dangling}")


class TestConnectFailsIfServerExists(unittest.TestCase):
    """connect with server already in config gives error."""

    def setUp(self):
        self.tmp_home = tempfile.mkdtemp()
        self.env = _make_env(self.tmp_home)

    def test_connect_fails_if_server_exists(self):
        """connect when server name already exists should error."""
        # First connect succeeds
        result = _run(
            ["connect", "--url", "http://a.com", "--client-id", "c1", "--client-secret", "s1"],
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        # Second connect to same server name should fail
        result = _run(
            ["connect", "--url", "http://b.com", "--client-id", "c2", "--client-secret", "s2"],
            env=self.env,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("already exists", result.stderr)
        config_dir = Path(self.tmp_home) / ".config" / "companion"
        dangling = glob.glob(str(config_dir / "*.tmp"))
        self.assertEqual(dangling, [], f"Dangling .tmp files found: {dangling}")


if __name__ == "__main__":
    unittest.main()
