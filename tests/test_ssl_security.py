#!/usr/bin/env python3
"""Tests for the paranoid SSL/TLS layer: cert pinning + context resolution."""

import io
import ssl
import subprocess
import sys
import unittest
from contextlib import redirect_stderr
from hashlib import sha256
from unittest.mock import patch

sys.path.insert(0, "src")
import companion


def _args(**kwargs):
    """Build a flat object that mimics argparse.Namespace for _build_ssl_context tests."""

    class A:
        pass

    obj = A()
    for k, v in kwargs.items():
        setattr(obj, k, v)
    return obj


class TestBuildSSLContext(unittest.TestCase):
    """_build_ssl_context resolution rules — paranoid by default."""

    def setUp(self):
        # The "warned once" flag is process-global; reset it between tests.
        companion._INSECURE_WARNED = False

    def test_http_url_returns_none(self):
        """Plain http:// with no TLS knobs needs no TLS context."""
        self.assertIsNone(companion._build_ssl_context("http://localhost:8080", _args(), None))

    def test_empty_url_returns_none(self):
        self.assertIsNone(companion._build_ssl_context("", _args(), None))

    def test_https_without_pin_refuses_by_default(self):
        """require-pin defaults to True; no cert-sha256 → CertVerificationConfigError."""
        with self.assertRaises(companion.CertVerificationConfigError):
            companion._build_ssl_context("https://example.com", _args(), None)

    def test_https_without_pin_with_allow_unpinned(self):
        """The fingerprint command bypasses the pin requirement via allow_unpinned."""
        ctx = companion._build_ssl_context("https://example.com", _args(), None, allow_unpinned=True)
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_https_with_pin_returns_pinned_context(self):
        ctx = companion._build_ssl_context("https://example.com", _args(cert_sha256="a" * 64), None)
        self.assertIsInstance(ctx, ssl.SSLContext)
        # Pinning is in place via a custom socket subclass.
        self.assertIsNot(ctx.sslsocket_class, ssl.SSLSocket)

    def test_insecure_disables_verification_and_warns_once(self):
        captured = io.StringIO()
        with redirect_stderr(captured):
            ctx = companion._build_ssl_context("https://example.com", _args(insecure=True), None)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)
        self.assertIn("--insecure", captured.getvalue())

        # Second call: still insecure, but no second warning.
        captured2 = io.StringIO()
        with redirect_stderr(captured2):
            companion._build_ssl_context("https://other.example", _args(insecure=True), None)
        self.assertEqual(captured2.getvalue(), "")

    def test_invalid_pin_format_rejected(self):
        for bad in ["not-hex-at-all-of-this-length-padding-pad-pad-pad-pad-pad-pad-pad", "a" * 63, "a" * 65]:
            with self.assertRaises(companion.CertVerificationConfigError):
                companion._build_ssl_context("https://x", _args(cert_sha256=bad), None)

    def test_per_server_config_provides_pin(self):
        """Pin comes from server_config when no CLI flag is set."""
        ctx = companion._build_ssl_context("https://x", _args(), {"url": "https://x", "cert-sha256": "b" * 64})
        self.assertIsInstance(ctx, ssl.SSLContext)

    def test_per_server_require_pin_false_allows_unpinned(self):
        """require-pin: false in server_config relaxes the policy."""
        ctx = companion._build_ssl_context("https://x", _args(), {"url": "https://x", "require-pin": False})
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)  # still verifies CA chain

    def test_cli_insecure_overrides_config_pin(self):
        """CLI flag > config: --insecure wins over a configured pin."""
        ctx = companion._build_ssl_context("https://x", _args(insecure=True), {"cert-sha256": "a" * 64})
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_cli_pin_overrides_config_pin(self):
        """CLI --cert-sha256 wins over a config-provided pin."""
        cli_pin = "c" * 64
        ctx = companion._build_ssl_context("https://x", _args(cert_sha256=cli_pin), {"cert-sha256": "a" * 64})
        # Just confirm we got a pinned context (different socket class).
        self.assertIsNot(ctx.sslsocket_class, ssl.SSLSocket)


class TestRefuseTLSSettingsOnNonHTTPS(unittest.TestCase):
    """_refuse_tls_settings_on_non_https: catches the http+TLS-knobs footgun before urlopen.

    A TLS knob on a non-https URL is silently ignored (and a 30x redirect to https
    silently falls back to the system CA bundle), so refuse upfront with a clear
    error rather than letting the user hit "CERTIFICATE_VERIFY_FAILED" downstream.
    """

    def test_https_url_does_not_refuse(self):
        """https URLs always pass through — TLS knobs are valid there."""
        companion._refuse_tls_settings_on_non_https(
            "https://x", _args(ca_cert="/c", cert_sha256="a" * 64, insecure=True), None
        )

    def test_clean_http_url_does_not_refuse(self):
        """Plain http with zero TLS knobs is legit (local dev, no redirects)."""
        companion._refuse_tls_settings_on_non_https("http://x", _args(), None)

    def test_http_with_ca_cert_refuses(self):
        with self.assertRaises(companion.CertVerificationConfigError) as cm:
            companion._refuse_tls_settings_on_non_https("http://x", _args(ca_cert="/path/to/ca"), None)
        self.assertIn("scheme is 'http'", str(cm.exception))
        self.assertIn("ca-cert", str(cm.exception))

    def test_http_with_insecure_refuses(self):
        with self.assertRaises(companion.CertVerificationConfigError) as cm:
            companion._refuse_tls_settings_on_non_https("http://x", _args(insecure=True), None)
        self.assertIn("insecure", str(cm.exception))

    def test_http_with_cert_sha256_refuses(self):
        with self.assertRaises(companion.CertVerificationConfigError) as cm:
            companion._refuse_tls_settings_on_non_https("http://x", _args(cert_sha256="a" * 64), None)
        self.assertIn("cert-sha256", str(cm.exception))

    def test_http_with_tls_setting_in_server_config_refuses(self):
        """TLS settings nested in server_config also trigger refusal on http URLs."""
        with self.assertRaises(companion.CertVerificationConfigError):
            companion._refuse_tls_settings_on_non_https("http://x", _args(), {"url": "http://x", "ca-cert": "/ca"})


class TestMakePinnedSSLContext(unittest.TestCase):
    """make_pinned_ssl_context: verbatim port from c4ffein/bank — pin is required."""

    def test_strict_defaults(self):
        ctx = companion.make_pinned_ssl_context("a" * 64)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertTrue(ctx.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_pinned_context_uses_subclass(self):
        ctx = companion.make_pinned_ssl_context("a" * 64)
        # Pinning is implemented via a custom socket subclass.
        self.assertIsNot(ctx.sslsocket_class, ssl.SSLSocket)
        self.assertTrue(issubclass(ctx.sslsocket_class, ssl.SSLSocket))

    def test_unpinned_strict_path_uses_stdlib(self):
        """When require-pin is off, _build_ssl_context returns a vanilla strict context (not pinned)."""
        ctx = companion._build_ssl_context("https://x", _args(), {"url": "https://x", "require-pin": False})
        # Not a pinning subclass — stdlib default
        self.assertIs(type(ctx), ssl.SSLContext)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)


class TestCommandFunctionsThreadSSLContext(unittest.TestCase):
    """Regression guard: every CLI command function must actually pass *its*
    ssl_context kwarg through to urlopen. If someone removes `context=ssl_context`
    from a call site, this test catches it before users hit CERT_VERIFY_FAILED."""

    def setUp(self):
        companion._INSECURE_WARNED = False

    def _capture_urlopen_context(self, callable_fn, ssl_context):
        """Patch urlopen to capture the context it receives; return it."""
        captured = {}

        class _FakeResp:
            status = 200

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

            def read(self_inner):
                return b"[]"

        def fake_urlopen(req, *args, **kwargs):
            captured["ctx"] = kwargs.get("context")
            return _FakeResp()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            callable_fn()
        return captured.get("ctx", "NOT_CALLED")

    def test_list_files_threads_insecure_context(self):
        """list_files(..., ssl_context=insecure_ctx) → urlopen sees the same insecure ctx."""
        insecure_ctx = companion._build_ssl_context("https://example.com", _args(insecure=True), None)
        self.assertEqual(insecure_ctx.verify_mode, ssl.CERT_NONE)
        got = self._capture_urlopen_context(
            lambda: companion.list_files("https://example.com", "id:secret", ssl_context=insecure_ctx),
            insecure_ctx,
        )
        self.assertIs(got, insecure_ctx, "list_files must pass ssl_context to urlopen")

    def test_get_pad_threads_insecure_context(self):
        insecure_ctx = companion._build_ssl_context("https://example.com", _args(insecure=True), None)
        got = self._capture_urlopen_context(
            lambda: companion.get_pad("https://example.com", "id:secret", ssl_context=insecure_ctx),
            insecure_ctx,
        )
        self.assertIs(got, insecure_ctx, "get_pad must pass ssl_context to urlopen")

    def test_list_clients_cmd_threads_insecure_context(self):
        insecure_ctx = companion._build_ssl_context("https://example.com", _args(insecure=True), None)
        got = self._capture_urlopen_context(
            lambda: companion.list_clients_cmd("https://example.com", "id:secret", ssl_context=insecure_ctx),
            insecure_ctx,
        )
        self.assertIs(got, insecure_ctx, "list_clients_cmd must pass ssl_context to urlopen")

    def test_resolve_file_id_threads_insecure_context(self):
        insecure_ctx = companion._build_ssl_context("https://example.com", _args(insecure=True), None)
        got = self._capture_urlopen_context(
            lambda: companion.resolve_file_id("https://example.com", "file.txt", "id:secret", ssl_context=insecure_ctx),
            insecure_ctx,
        )
        self.assertIs(got, insecure_ctx, "resolve_file_id must pass ssl_context to urlopen")

    def test_rotation_request_threads_insecure_context(self):
        insecure_ctx = companion._build_ssl_context("https://example.com", _args(insecure=True), None)
        got = self._capture_urlopen_context(
            lambda: companion._rotation_request(
                "https://example.com", "/api/token/start-client-rotation", "id:secret", ssl_context=insecure_ctx
            ),
            insecure_ctx,
        )
        self.assertIs(got, insecure_ctx, "_rotation_request must pass ssl_context to urlopen")


class TestFingerprintCmd(unittest.TestCase):
    """fingerprint subcommand error paths (full roundtrip lives in TestTLSEndToEnd)."""

    def setUp(self):
        companion._INSECURE_WARNED = False

    def test_no_url_errors(self):
        with patch("companion.resolve_server", return_value=(None, None)):
            with self.assertRaises(SystemExit) as cm:
                companion.fingerprint_cmd(_args())
            self.assertEqual(cm.exception.code, 1)

    def test_http_url_rejected(self):
        with self.assertRaises(SystemExit) as cm:
            with redirect_stderr(io.StringIO()):
                companion.fingerprint_cmd(_args(server_url="http://example.com"))
        self.assertEqual(cm.exception.code, 1)

    def test_no_ca_cert_and_no_insecure_errors(self):
        """Refuses to fingerprint without an explicit trust choice (--ca-cert or --insecure)."""
        captured = io.StringIO()
        with self.assertRaises(SystemExit) as cm:
            with redirect_stderr(captured):
                companion.fingerprint_cmd(_args(server_url="https://example.com"))
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("--ca-cert", captured.getvalue())
        self.assertIn("--insecure", captured.getvalue())

    def test_localhost_unreachable_errors(self):
        """With --insecure set, an unreachable port fails at connect-time (exit 1)."""
        with self.assertRaises(SystemExit) as cm:
            with redirect_stderr(io.StringIO()):
                companion.fingerprint_cmd(_args(server_url="https://127.0.0.1:1", insecure=True))
        self.assertEqual(cm.exception.code, 1)


class TestPinnedHandshakeEndToEnd(unittest.TestCase):
    """End-to-end: stand up a self-signed TLS server and exercise both pin paths
    (right pin → handshake succeeds, wrong pin → rejected).

    Skipped if openssl isn't available on PATH (we use it to mint the test cert).
    The cert + server are minted once per class for both tests.
    """

    @classmethod
    def setUpClass(cls):
        import os
        import tempfile

        try:
            subprocess.run(["openssl", "version"], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            raise unittest.SkipTest("openssl not available")

        cert_fd, cls.cert_path = tempfile.mkstemp(suffix=".pem")
        key_fd, cls.key_path = tempfile.mkstemp(suffix=".key")
        os.close(cert_fd)
        os.close(key_fd)
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                cls.key_path,
                "-out",
                cls.cert_path,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ],
            capture_output=True,
            check=True,
        )
        # Compute the cert's DER SHA-256 — this is the value pinning expects.
        with open(cls.cert_path) as f:
            pem = f.read()
        der = ssl.PEM_cert_to_DER_cert(pem)
        cls.correct_pin = sha256(der).hexdigest()

    @classmethod
    def tearDownClass(cls):
        import os

        for p in (cls.cert_path, cls.key_path):
            try:
                os.unlink(p)
            except OSError:
                pass

    def _serve_once(self):
        """Spin up a one-shot TLS server bound on a random port. Returns (port, thread)."""
        import socket
        import threading

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(self.cert_path, self.key_path)
        server_sock = socket.socket()
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(1)
        self.addCleanup(server_sock.close)

        def accept_once():
            try:
                client, _ = server_sock.accept()
                # Try the handshake; if the client tears down we just exit.
                try:
                    with server_ctx.wrap_socket(client, server_side=True):
                        pass
                except (ssl.SSLError, OSError):
                    pass
            except OSError:
                pass

        t = threading.Thread(target=accept_once, daemon=True)
        t.start()
        return port, t

    def test_correct_pin_accepted(self):
        """Pinning the cert's actual DER SHA-256 → handshake succeeds."""
        import socket

        port, t = self._serve_once()
        client_ctx = companion.make_pinned_ssl_context(self.correct_pin, cafile=self.cert_path)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            with client_ctx.wrap_socket(sock, server_hostname="localhost") as ss:
                # If we get here, the handshake completed (no SSLCertVerificationError raised).
                self.assertIsNotNone(ss.getpeercert(binary_form=True))
        t.join(timeout=2)

    def test_mismatched_pin_rejected(self):
        """Pinning a wrong SHA-256 → SSLCertVerificationError on handshake."""
        import socket

        port, t = self._serve_once()
        wrong_pin = "f" * 64
        client_ctx = companion.make_pinned_ssl_context(wrong_pin, cafile=self.cert_path)
        with self.assertRaises(ssl.SSLCertVerificationError):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                with client_ctx.wrap_socket(sock, server_hostname="localhost"):
                    pass
        t.join(timeout=2)

    # ── fingerprint_cmd end-to-end paths against the same self-signed server ──

    def test_fingerprint_with_correct_cafile_prints_hash(self):
        """fingerprint --ca-cert <ca that signed the cert> succeeds and prints the SHA-256."""
        from contextlib import redirect_stdout

        port, t = self._serve_once()
        companion._INSECURE_WARNED = False
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            companion.fingerprint_cmd(_args(server_url=f"https://localhost:{port}", ca_cert=self.cert_path))
        self.assertEqual(out.getvalue().strip(), self.correct_pin)
        self.assertEqual(err.getvalue(), "")  # no warnings on the trusted path
        t.join(timeout=2)

    def test_fingerprint_with_insecure_prints_hash_and_warns(self):
        """fingerprint --insecure succeeds without a CA, prints the hash, and warns once."""
        from contextlib import redirect_stdout

        port, t = self._serve_once()
        companion._INSECURE_WARNED = False
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            companion.fingerprint_cmd(_args(server_url=f"https://localhost:{port}", insecure=True))
        self.assertEqual(out.getvalue().strip(), self.correct_pin)
        self.assertIn("--insecure", err.getvalue())
        t.join(timeout=2)

    def test_fingerprint_with_wrong_cafile_rejected(self):
        """fingerprint --ca-cert <unrelated CA> fails the handshake and exits 1, no hash printed."""
        import os
        import tempfile
        from contextlib import redirect_stdout

        # Mint a second, unrelated self-signed cert to use as the (wrong) CA.
        other_cert_fd, other_cert_path = tempfile.mkstemp(suffix=".pem")
        other_key_fd, other_key_path = tempfile.mkstemp(suffix=".key")
        os.close(other_cert_fd)
        os.close(other_key_fd)
        try:
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    other_key_path,
                    "-out",
                    other_cert_path,
                    "-days",
                    "1",
                    "-nodes",
                    "-subj",
                    "/CN=otherca",
                ],
                capture_output=True,
                check=True,
            )
            port, t = self._serve_once()
            out, err = io.StringIO(), io.StringIO()
            with self.assertRaises(SystemExit) as cm:
                with redirect_stdout(out), redirect_stderr(err):
                    companion.fingerprint_cmd(_args(server_url=f"https://localhost:{port}", ca_cert=other_cert_path))
            self.assertEqual(cm.exception.code, 1)
            self.assertEqual(out.getvalue(), "")  # hash NOT printed on failure
            self.assertIn("failed to connect", err.getvalue().lower())
            t.join(timeout=2)
        finally:
            for p in (other_cert_path, other_key_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
