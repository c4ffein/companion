#!/usr/bin/env python3
"""
Companion - Simple file sharing server and client
Usage:
    Server:        python companion.py server [--port PORT] [--server NAME]
    Server setup:  python companion.py server-setup [--server NAME] [--url URL]
    Add user:      python companion.py server-add-user [--name NAME] [--admin]
    Upload:        python companion.py upload <file_path> [--set-preview]
    Download:      python companion.py download <filename> [-o DIR]
    List files:    python companion.py list
    Set preview:   python companion.py set-preview <filename>
    Get pad:       python companion.py get-pad
    Set pad:       python companion.py set-pad <content>
    Connect:       python companion.py connect --url URL --client-id ID --client-secret SECRET
    Register:      python companion.py register [--name NAME] [--interactive]
    Clients:       python companion.py clients
    Delete client: python companion.py delete-client <client_id>

Config file (~/.config/companion/config.json):
    All commands use default-server from config if available.
    Override with --server <name> or --server-url <url>
"""

import argparse
import contextlib
import hashlib
import hmac
import http.server
import io
import json
import logging
import mimetypes
import os
import secrets
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Tuple

# Platform-conditional file locking
if sys.platform == "win32":
    import msvcrt

    def _lock_file(fd):
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
else:
    import fcntl

    def _lock_file(fd):
        fcntl.flock(fd, fcntl.LOCK_EX)


@dataclass
class FileEntry:
    filename: str
    content: bytes
    mimetype: str
    upload_time: str
    client_id: str


# In-memory file storage: {file_id (UUID): FileEntry}
FILES: Dict[str, FileEntry] = {}
WORKSPACE_LOCK = Lock()

# Per-client token auth: {client_id: {salt, secret_hash, admin, name, registered}}
CLIENTS: Dict[str, dict] = {}
CLIENTS_LOCK = Lock()
_ACTIVE_SERVER_NAME: Optional[str] = None

# Preview state: current preview for all clients
PREVIEW_STATE = {"file_id": None, "timestamp": 0}

# Pad state: shared text pad content
PAD_STATE = {"content": "", "timestamp": 0}
PAD_MAX_SIZE = 10 * 1024 * 1024  # 10MB character limit

# Per-client storage limit
MAX_STORAGE_PER_CLIENT = 4 * 1024 * 1024 * 1024  # 4GB

# Maximum request body size (applies to all POST endpoints).
# Separate from per-client storage: this caps a single request to prevent
# memory exhaustion from a malicious Content-Length header.
MAX_REQUEST_BODY = int(os.environ.get("COMPANION_MAX_REQUEST_BODY", str(MAX_STORAGE_PER_CLIENT)))

# CORS allowed origin.
# Default "*" is intentionally broad: authentication is purely token-based
# (Bearer header), not cookie/session-based, so the browser never attaches
# ambient credentials.  A malicious page cannot forge the Authorization
# header, making CSRF via CORS impossible.  Override via env var if you want
# to restrict to a specific origin anyway (e.g. "https://myhost.example").
CORS_ALLOW_ORIGIN = os.environ.get("COMPANION_CORS_ORIGIN", "*")

# Rate limiting (per-client sliding window)
RATE_LIMIT_STORE: Dict[str, List[float]] = {}
RATE_LIMIT_LOCK = Lock()
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = int(os.environ.get("COMPANION_RATE_LIMIT_MAX", "30"))

# Config file path
CONFIG_PATH = Path.home() / ".config" / "companion" / "config.json"
_CONFIG_LOCK_PATH = CONFIG_PATH.with_suffix(".lock")

# Setup logger
logger = logging.getLogger("companion")


def load_config() -> Optional[dict]:
    """Load config from ~/.config/companion/config.json if it exists."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Failed to load config from {CONFIG_PATH}: {e}", file=sys.stderr)
    return None


@contextlib.contextmanager
def _config_locked():
    """Acquire file lock, yield fresh config dict. On clean exit, atomic-write back."""
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(str(_CONFIG_LOCK_PATH), os.O_CREAT | os.O_RDWR)
    try:
        _lock_file(lock_fd)
        config = load_config() or {}
        yield config
        # Only reached if the with-block didn't raise
        fd, tmp_path = tempfile.mkstemp(dir=str(CONFIG_PATH.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(config, f, indent=2)
            os.replace(tmp_path, str(CONFIG_PATH))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:  # TODO Better handling ? Let the caller handle?
                logger.warning("Failed to clean up temp file: %s", tmp_path)
            raise
    finally:
        os.close(lock_fd)  # TODO Should secure?


def resolve_server(args) -> Tuple[str, Optional[str]]:
    """
    Resolve server URL and auth token from args and config.
    Returns (url, auth_token) where auth_token is 'client_id:client_secret' or None.

    Priority order:
    1. --server-url (explicit URL, credentials from --client-id/--client-secret or None)
    2. --server (named server from config)
    3. default-server from config
    """
    config = load_config()

    # Build auth token from CLI flags if provided
    cli_client_id = getattr(args, "client_id", None)
    cli_client_secret = getattr(args, "client_secret", None)
    cli_auth_token = f"{cli_client_id}:{cli_client_secret}" if cli_client_id and cli_client_secret else None

    def _get_auth_token(server_config):
        if cli_auth_token:
            return cli_auth_token
        cid = server_config.get("client-id")
        csecret = server_config.get("client-secret")
        if cid and csecret:
            return f"{cid}:{csecret}"
        return None

    # Priority 1: Explicit --server-url
    if hasattr(args, "server_url") and args.server_url:
        return args.server_url, cli_auth_token

    # Priority 2: Named --server from config
    if hasattr(args, "server") and args.server:
        if not config:
            print(f"Error: --server '{args.server}' specified but no config file found.", file=sys.stderr)
            print(f"\nCreate a config file at {CONFIG_PATH} with:", file=sys.stderr)
            _print_config_help()
            sys.exit(1)

        servers = config.get("servers", {})
        if args.server not in servers:
            available = ", ".join(servers.keys()) if servers else "(none)"
            print(f"Error: Server '{args.server}' not found in config.", file=sys.stderr)
            print(f"Available servers: {available}", file=sys.stderr)
            sys.exit(1)

        server_config = servers[args.server]
        url = server_config.get("url")
        return url, _get_auth_token(server_config)

    # Priority 3: default-server from config
    if config:
        default_name = config.get("default-server")
        if default_name:
            servers = config.get("servers", {})
            if default_name in servers:
                server_config = servers[default_name]
                url = server_config.get("url")
                return url, _get_auth_token(server_config)
            else:
                print(f"Error: default-server '{default_name}' not found in servers.", file=sys.stderr)
                sys.exit(1)

    # No server could be resolved - show helpful error
    print("Error: No server specified.", file=sys.stderr)
    print("\nTo fix this, either:", file=sys.stderr)
    print(f"  1. Create a config file at {CONFIG_PATH} with:", file=sys.stderr)
    _print_config_help()
    print("\n  2. Or specify a server explicitly:", file=sys.stderr)
    print("     companion upload --server-url http://localhost:8080 file.pdf", file=sys.stderr)
    sys.exit(1)


def _print_config_help():
    """Print example config file structure."""
    example = """{
  "default-server": "myserver",
  "servers": {
    "myserver": {
      "url": "http://localhost:8080",
      "client-id": "<hex>",
      "client-secret": "<hex>"
    }
  }
}"""
    for line in example.split("\n"):
        print(f"     {line}", file=sys.stderr)


def _save_clients_to_config():
    """Persist CLIENTS dict to the active server entry in config (file-locked atomic write)."""
    if not _ACTIVE_SERVER_NAME:
        return
    with _config_locked() as config:
        servers = config.get("servers", {})
        if _ACTIVE_SERVER_NAME not in servers:
            logger.error("Server '%s' not found in config, cannot persist clients", _ACTIVE_SERVER_NAME)
            return
        server_entry = servers[_ACTIVE_SERVER_NAME]
        with CLIENTS_LOCK:
            server_entry["clients"] = {
                cid: {
                    "salt": info["salt"],
                    "secret_hash": info["secret_hash"],
                    "admin": info["admin"],
                    "name": info.get("name", ""),
                    "registered": info.get("registered", ""),
                }
                for cid, info in CLIENTS.items()
            }


def resolve_server_config(args) -> int:
    """
    Resolve server port from args and config for server mode.
    Loads registered clients into CLIENTS global.
    Returns port or exits with helpful error message.

    Priority order:
    1. CLI args (--port) override config
    2. --server (named server from config)
    3. default-server from config
    4. Default port 8080
    """
    global _ACTIVE_SERVER_NAME
    config = load_config()

    # Start with CLI values (may be None)
    port = getattr(args, "port", None)

    # Try to get config values
    server_config = None
    server_name = getattr(args, "server", None)

    if server_name:
        # Explicit --server flag
        if not config:
            print(f"Error: --server '{server_name}' specified but no config file found.", file=sys.stderr)
            sys.exit(1)
        servers = config.get("servers", {})
        if server_name not in servers:
            available = ", ".join(servers.keys()) if servers else "(none)"
            print(f"Error: Server '{server_name}' not found in config.", file=sys.stderr)
            print(f"Available servers: {available}", file=sys.stderr)
            sys.exit(1)
        server_config = servers[server_name]
        _ACTIVE_SERVER_NAME = server_name
    elif config:
        # Try default-server
        default_name = config.get("default-server")
        if default_name:
            servers = config.get("servers", {})
            if default_name in servers:
                server_config = servers[default_name]
                _ACTIVE_SERVER_NAME = default_name

    # If no server name resolved, set a default for config persistence
    if not _ACTIVE_SERVER_NAME:
        _ACTIVE_SERVER_NAME = "default"

    # Apply config values where CLI didn't override
    if server_config:
        if port is None:
            # Parse port from URL
            url = server_config.get("url", "")
            parsed = urllib.parse.urlparse(url)
            if parsed.port:
                port = parsed.port
        # Load registered clients
        clients_data = server_config.get("clients", {})
        with CLIENTS_LOCK:
            CLIENTS.update(clients_data)

    # Fail if no clients configured
    if not CLIENTS:
        print("Error: No clients configured.", file=sys.stderr)
        print("Run 'companion server-setup' to configure the server first.", file=sys.stderr)
        sys.exit(1)

    # Apply defaults
    if port is None:
        port = 8080

    return port


class FileShareHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for file sharing server"""

    def _set_headers(self, status=HTTPStatus.OK, content_type="text/html"):
        self.send_response(status)
        self.send_header("Content-type", content_type)
        self.send_header("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN)
        self.end_headers()

    # Allowed charset for client_id: alphanumeric + hyphens (matches registration validation).
    _VALID_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
    # Allowed charset for client_secret: hex digits (generated by secrets.token_hex).
    _VALID_SECRET_CHARS = frozenset("0123456789abcdef")

    def _authenticate(self) -> Optional[dict]:
        """Parse Bearer client_id:client_secret, verify against salted hash, return client info or None.

        TODO: credential rotation — option for auto-renew after configurable timeout,
        option to set the renewal period (e.g. 30 days). On rotation, old secret stays
        valid for a grace period while the new one is issued.
        """
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header[7:]
        if ":" not in token:
            return None
        client_id, client_secret = token.split(":", 1)
        # Validate charset: reject obviously malformed tokens early.
        if not client_id or not all(c in self._VALID_ID_CHARS for c in client_id):
            return None
        if not client_secret or not all(c in self._VALID_SECRET_CHARS for c in client_secret):
            return None
        with CLIENTS_LOCK:
            client = CLIENTS.get(client_id)
            if not client:
                return None
            expected = hashlib.sha256((client["salt"] + client_secret).encode()).hexdigest()
            if hmac.compare_digest(client["secret_hash"], expected):
                return {"client_id": client_id, **client}
        return None

    def _require_auth(self) -> Optional[dict]:
        """Authenticate or send 401. Returns client info or None (already sent error)."""
        client = self._authenticate()
        if not client:
            self._set_headers(HTTPStatus.UNAUTHORIZED, "application/json")
            self.wfile.write(json.dumps({"error": "Invalid credentials"}).encode())
            return None
        return client

    def _require_admin(self) -> Optional[dict]:
        """Authenticate + require admin, or send 401/403. Returns client info or None."""
        client = self._authenticate()
        if not client:
            self._set_headers(HTTPStatus.UNAUTHORIZED, "application/json")
            self.wfile.write(json.dumps({"error": "Invalid credentials"}).encode())
            return None
        if not client.get("admin"):
            self._set_headers(HTTPStatus.FORBIDDEN, "application/json")
            self.wfile.write(json.dumps({"error": "Admin access required"}).encode())
            return None
        return client

    def _check_rate_limit(self, client_id: str) -> bool:
        """Per-client sliding window rate limit. Returns True if allowed, sends 429 if not."""
        now = time.monotonic()
        with RATE_LIMIT_LOCK:
            # Cleanup when store gets large
            if len(RATE_LIMIT_STORE) > 1000:  # TODO parameterize and calculate good sweet-spot
                cutoff = now - RATE_LIMIT_WINDOW
                to_delete = [k for k, v in RATE_LIMIT_STORE.items() if not v or v[-1] < cutoff]
                for k in to_delete:
                    del RATE_LIMIT_STORE[k]
            timestamps = RATE_LIMIT_STORE.setdefault(client_id, [])
            # Remove expired entries
            cutoff = now - RATE_LIMIT_WINDOW
            timestamps[:] = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= RATE_LIMIT_MAX:
                self._set_headers(HTTPStatus.TOO_MANY_REQUESTS, "application/json")
                self.wfile.write(json.dumps({"error": "Rate limit exceeded"}).encode())
                return False
            timestamps.append(now)
        return True

    def _read_body(self, max_bytes: int = MAX_REQUEST_BODY) -> Optional[bytes]:
        """Read request body up to *max_bytes*.  Sends 411/413/400 on error and returns None."""
        raw = self.headers.get("Content-Length")
        if raw is None:
            self._set_headers(HTTPStatus.LENGTH_REQUIRED, "application/json")
            self.wfile.write(json.dumps({"error": "Content-Length header is required"}).encode())
            return None
        try:
            length = int(raw)
        except (ValueError, TypeError):
            self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
            self.wfile.write(json.dumps({"error": "Invalid Content-Length"}).encode())
            return None
        if length < 0 or length > max_bytes:
            self._set_headers(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "application/json")
            self.wfile.write(json.dumps({"error": f"Request body too large (max {max_bytes} bytes)"}).encode())
            return None
        return self.rfile.read(length)

    def do_GET(self):
        """Handle GET requests"""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/":
            self._serve_index()
        elif path == "/api/files":
            self._serve_file_list()
        elif path == "/api/preview/current":
            self._serve_preview_state()
        elif path == "/api/pad":
            self._serve_pad_content()
        elif path == "/api/clients":
            self._handle_list_clients()
        elif path.startswith("/download/"):
            file_id = urllib.parse.unquote(path[10:])
            self._serve_file(file_id)
        else:
            self._set_headers(HTTPStatus.NOT_FOUND)
            self.wfile.write(b"Not found")

    def do_POST(self):
        """Handle POST requests (file uploads)"""
        if self.path == "/api/clients/register":
            self._handle_register_client()
        elif self.path == "/api/preview/set":
            self._handle_preview_set()
        elif self.path == "/api/pad":
            self._handle_pad_update()
        elif self.path == "/api/upload":
            client = self._require_auth()
            if not client:
                return
            if not self._check_rate_limit(client["client_id"]):
                return

            body = self._read_body()
            if body is None:
                return

            # Parse multipart form data manually (simple version)
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" in content_type:
                self._handle_multipart_upload(body, content_type, client["client_id"])
            else:
                self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
                self.wfile.write(json.dumps({"error": "Expected multipart/form-data"}).encode())
        else:
            self._set_headers(HTTPStatus.NOT_FOUND)
            self.wfile.write(b"Not found")

    def _handle_multipart_upload(self, body: bytes, content_type: str, client_id: str = ""):
        """Parse multipart form data and store file.

        Simplified multipart parser — intentionally not a full RFC 2046 implementation.
        This is sufficient because the only real clients are:
        - The web UI (browser FormData — always well-formed)
        - The CLI upload_file() function (generates correct multipart)
        - curl / standard HTTP tools (also well-formed)

        Known simplifications:
        - Boundary is extracted by splitting Content-Type on ";", then on
          "boundary=". Quoted boundaries (required by RFC 2045 when the
          value contains tspecials like : , / ( ) = ?) are handled by
          stripping quotes. ";" is in tspecials but not in RFC 2046's
          bchars, so a valid boundary never contains ";" and the split
          is safe. In practice browsers/curl only generate alphanumeric +
          dash boundaries that don't need quoting at all.
        - body.split(boundary) assumes the boundary doesn't appear in file
          content. This is always true in practice: the sender picks a boundary
          specifically to avoid collisions.
        - Filename is extracted by splitting on "filename=", not by parsing
          Content-Disposition per RFC 6266. Works for all browser/curl output.
        """
        # Extract boundary
        boundary = None
        for part in content_type.split(";"):
            if "boundary=" in part:
                raw = part.split("boundary=")[1].strip()
                if '"' in raw:
                    if not raw.startswith('"') or not raw.endswith('"') or len(raw) < 2 or '"' in raw[1:-1]:
                        self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
                        self.wfile.write(json.dumps({"error": "Malformed boundary in Content-Type"}).encode())
                        return
                    boundary = raw[1:-1]
                else:
                    boundary = raw
                break

        if not boundary:
            self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
            self.wfile.write(json.dumps({"error": "No boundary found"}).encode())
            return

        # Split by boundary
        parts = body.split(f"--{boundary}".encode())

        for part in parts:
            if b"Content-Disposition" in part and b"filename=" in part:
                # Extract filename
                headers_end = part.find(b"\r\n\r\n")
                if headers_end == -1:
                    continue

                headers = part[:headers_end].decode("utf-8", errors="ignore")
                content = part[headers_end + 4 :]

                # Remove trailing \r\n
                if content.endswith(b"\r\n"):
                    content = content[:-2]

                # Parse filename
                filename = None
                for line in headers.split("\n"):
                    if "filename=" in line:
                        filename_part = line.split("filename=")[1]
                        filename = filename_part.strip().strip('"').strip("'")
                        break

                if filename:
                    # Guess mimetype
                    mimetype, _ = mimetypes.guess_type(filename)
                    if not mimetype:
                        mimetype = "application/octet-stream"

                    upload_time = datetime.now().isoformat()
                    file_id = str(uuid.uuid4())

                    # Check per-client storage limit and insert atomically
                    with WORKSPACE_LOCK:
                        current_usage = sum(len(f.content) for f in FILES.values() if f.client_id == client_id)
                        if current_usage + len(content) > MAX_STORAGE_PER_CLIENT:
                            self._set_headers(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "application/json")
                            self.wfile.write(json.dumps({"error": "Storage limit exceeded for this client"}).encode())
                            return
                        FILES[file_id] = FileEntry(filename, content, mimetype, upload_time, client_id)

                    self._set_headers(HTTPStatus.OK, "application/json")
                    self.wfile.write(
                        json.dumps(
                            {
                                "success": True,
                                "id": file_id,
                                "filename": filename,
                                "normalized_name": sanitize_filename(filename),
                                "size": len(content),
                            }
                        ).encode()
                    )
                    return

        self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
        self.wfile.write(json.dumps({"error": "No file found in upload"}).encode())

    def _serve_index(self):
        """Serve the main HTML page"""
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
        try:
            with open(html_path, "r", encoding="utf-8") as f:
                html = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"index.html not found at {html_path}")
        self._set_headers()
        self.wfile.write(html.encode())

    def _serve_file_list(self):
        """Serve JSON list of available files"""
        if not self._require_auth():
            return
        with WORKSPACE_LOCK:
            files = [
                {
                    "id": file_id,
                    "name": entry.filename,
                    "normalized_name": sanitize_filename(entry.filename),
                    "size": len(entry.content),
                    "mimetype": entry.mimetype,
                    "uploaded": entry.upload_time,
                    "uploaded_by": entry.client_id,
                }
                for file_id, entry in FILES.items()
            ]

        self._set_headers(content_type="application/json")
        self.wfile.write(json.dumps(files).encode())

    def _serve_file(self, file_id: str):
        """Serve a file for download or inline preview"""
        if not self._require_auth():
            return
        with WORKSPACE_LOCK:
            if file_id not in FILES:
                self._set_headers(HTTPStatus.NOT_FOUND)
                self.wfile.write(b"File not found")
                return

            entry = FILES[file_id]

        # Send headers manually (don't use _set_headers because we need additional headers)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", entry.mimetype)
        # Use inline for preview support (PDFs, images, etc.), but keep filename for downloads
        # RFC 5987: normalized name for ASCII-safe filename=, original via filename*=UTF-8
        safe_name = sanitize_filename(entry.filename)
        utf8_name = urllib.parse.quote(entry.filename)
        self.send_header("Content-Disposition", f"inline; filename=\"{safe_name}\"; filename*=UTF-8''{utf8_name}")
        self.send_header("Content-Length", str(len(entry.content)))
        self.send_header("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN)
        self.end_headers()
        self.wfile.write(entry.content)

    def _serve_preview_state(self):
        """Serve current preview state"""
        if not self._require_auth():
            return
        with WORKSPACE_LOCK:
            state = PREVIEW_STATE.copy()

            # If there's a file_id, get its filename and mimetype
            if state["file_id"]:
                if state["file_id"] in FILES:
                    entry = FILES[state["file_id"]]
                    state["filename"] = entry.filename
                    state["mimetype"] = entry.mimetype
                else:
                    # File was deleted, clear preview
                    state["file_id"] = None
                    state["filename"] = None
                    state["mimetype"] = None

        self._set_headers(content_type="application/json")
        self.wfile.write(json.dumps(state).encode())

    def _handle_preview_set(self):
        """Handle setting the preview state"""
        client = self._require_auth()
        if not client:
            return
        if not self._check_rate_limit(client["client_id"]):
            return

        body = self._read_body()
        if body is None:
            return

        try:
            data = json.loads(body.decode())
            file_id = data.get("file_id")

            if not file_id:
                self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
                self.wfile.write(json.dumps({"error": "file_id is required"}).encode())
                return

            # Check file exists and update preview state atomically
            with WORKSPACE_LOCK:
                if file_id not in FILES:
                    self._set_headers(HTTPStatus.NOT_FOUND, "application/json")
                    self.wfile.write(json.dumps({"error": "File not found"}).encode())
                    return
                filename = FILES[file_id].filename
                PREVIEW_STATE["file_id"] = file_id
                PREVIEW_STATE["timestamp"] = _next_timestamp(PREVIEW_STATE["timestamp"])
                timestamp = PREVIEW_STATE["timestamp"]

            self._set_headers(HTTPStatus.OK, "application/json")
            self.wfile.write(
                json.dumps(
                    {
                        "success": True,
                        "file_id": file_id,
                        "filename": filename,
                        "timestamp": timestamp,
                    }
                ).encode()
            )

        except (json.JSONDecodeError, KeyError):
            self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())

    def _serve_pad_content(self):
        """Serve current pad content"""
        if not self._require_auth():
            return
        with WORKSPACE_LOCK:
            state = PAD_STATE.copy()

        self._set_headers(content_type="application/json")
        self.wfile.write(json.dumps(state).encode())

    def _handle_pad_update(self):
        """Handle updating the pad content"""
        client = self._require_auth()
        if not client:
            return
        if not self._check_rate_limit(client["client_id"]):
            return

        body = self._read_body(max_bytes=PAD_MAX_SIZE + 1024)
        if body is None:
            return

        try:
            data = json.loads(body.decode())
            content = data.get("content", "")

            # Check size limit
            if len(content) > PAD_MAX_SIZE:
                self._set_headers(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "application/json")
                self.wfile.write(
                    json.dumps({"error": f"Content exceeds maximum size of {PAD_MAX_SIZE} bytes"}).encode()
                )
                return

            # Update pad state atomically
            with WORKSPACE_LOCK:
                PAD_STATE["content"] = content
                PAD_STATE["timestamp"] = _next_timestamp(PAD_STATE["timestamp"])
                timestamp = PAD_STATE["timestamp"]

            self._set_headers(HTTPStatus.OK, "application/json")
            self.wfile.write(
                json.dumps(
                    {
                        "success": True,
                        "timestamp": timestamp,
                        "size": len(content),
                    }
                ).encode()
            )

        except (json.JSONDecodeError, KeyError):
            self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())

    def _handle_register_client(self):
        """Handle client registration. Always requires admin auth."""
        client = self._require_admin()
        if not client:
            return
        if not self._check_rate_limit(client["client_id"]):
            return

        # Registration payloads are small JSON; cap at 4KB.
        body = self._read_body(max_bytes=4096)
        if body is None:
            return

        try:
            data = json.loads(body.decode())
            client_id = data.get("client_id")
            client_secret = data.get("client_secret")
            name = data.get("name", "")

            if not client_id or not client_secret:
                self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
                self.wfile.write(json.dumps({"error": "client_id and client_secret are required"}).encode())
                return

            # Validate client_id: 1-64 chars, alphanumeric + hyphens only
            VALID_CLIENT_ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
            if len(client_id) > 64 or not client_id or not all(c in VALID_CLIENT_ID_CHARS for c in client_id):
                self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
                self.wfile.write(
                    json.dumps({"error": "client_id must be 1-64 characters, alphanumeric and hyphens only"}).encode()
                )
                return

            # Validate name: 0-128 chars, printable ASCII (32-126) only  # TODO limit charset
            if len(name) > 128 or any(ord(c) < 32 or ord(c) > 126 for c in name):
                self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
                self.wfile.write(json.dumps({"error": "name must be 0-128 printable ASCII characters"}).encode())
                return

            salt = secrets.token_hex(16)
            secret_hash = hashlib.sha256((salt + client_secret).encode()).hexdigest()

            with CLIENTS_LOCK:
                if client_id in CLIENTS:
                    self._set_headers(HTTPStatus.CONFLICT, "application/json")
                    self.wfile.write(json.dumps({"error": "client_id already exists"}).encode())
                    return

                CLIENTS[client_id] = {
                    "salt": salt,
                    "secret_hash": secret_hash,
                    "admin": False,
                    "name": name,
                    "registered": datetime.now().isoformat(),
                }

            _save_clients_to_config()

            self._set_headers(HTTPStatus.OK, "application/json")
            self.wfile.write(
                json.dumps(
                    {
                        "success": True,
                        "client_id": client_id,
                        "admin": False,
                        "name": name,
                    }
                ).encode()
            )

        except (json.JSONDecodeError, KeyError):
            self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())

    def do_DELETE(self):
        """Handle DELETE requests"""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/clients/"):
            target_client_id = urllib.parse.unquote(path[len("/api/clients/") :])
            if not target_client_id or "/" in target_client_id:
                self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
                self.wfile.write(json.dumps({"error": "Invalid client ID"}).encode())
                return
            self._handle_delete_client(target_client_id)
        else:
            self._set_headers(HTTPStatus.NOT_FOUND)
            self.wfile.write(b"Not found")

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def _handle_delete_client(self, target_client_id: str):
        """Handle deleting a registered client (admin only, no self-deletion)."""
        client = self._require_admin()
        if not client:
            return

        if client["client_id"] == target_client_id:
            self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
            self.wfile.write(json.dumps({"error": "Cannot delete yourself"}).encode())
            return

        with CLIENTS_LOCK:
            if target_client_id not in CLIENTS:
                self._set_headers(HTTPStatus.NOT_FOUND, "application/json")
                self.wfile.write(json.dumps({"error": "Client not found"}).encode())
                return
            del CLIENTS[target_client_id]

        _save_clients_to_config()

        self._set_headers(HTTPStatus.OK, "application/json")
        self.wfile.write(json.dumps({"success": True, "deleted": target_client_id}).encode())

    def _handle_list_clients(self):
        """Handle listing registered clients (admin only, secrets excluded)"""
        if not self._require_admin():
            return

        with CLIENTS_LOCK:
            clients_list = [
                {
                    "client_id": cid,
                    "admin": info["admin"],
                    "name": info.get("name", ""),
                    "registered": info.get("registered", ""),
                }
                for cid, info in CLIENTS.items()
            ]

        self._set_headers(HTTPStatus.OK, "application/json")
        self.wfile.write(json.dumps(clients_list).encode())

    def log_message(self, format, *args):
        """Override to customize logging"""
        print(f"[{self.log_date_time_string()}] {format % args}")


def run_server(port: int):
    """Run the file sharing server"""

    logger.debug(f"Starting server on port {port}...")
    logger.debug(f"Binding to 0.0.0.0:{port}")

    server_address = ("0.0.0.0", port)

    class FastHTTPServer(http.server.HTTPServer):
        """HTTPServer that skips slow getfqdn() call during binding and ensures socket reuse"""

        allow_reuse_address = True  # Enable SO_REUSEADDR for instant socket reuse

        def server_bind(self):
            """Override server_bind to avoid slow getfqdn() call on macOS/Windows"""
            import socket

            logger.debug("Binding socket...")
            # Explicitly set SO_REUSEADDR to allow immediate port reuse
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(self.server_address)
            self.server_address = self.socket.getsockname()
            # Skip the slow socket.getfqdn() call - just use the host directly
            host, port = self.server_address[:2]
            self.server_name = host
            self.server_port = port
            logger.debug(f"Socket bound to {host}:{port}")

    logger.debug("Creating HTTPServer instance...")
    httpd = FastHTTPServer(server_address, FileShareHandler)

    client_count = len(CLIENTS)
    logger.debug("Server bound successfully")
    logger.info(f"File sharing server running on http://0.0.0.0:{port}")
    logger.info(f"Registered clients: {client_count}")

    print(f"🚀 File sharing server running on http://0.0.0.0:{port}")
    print(f"👥 Registered clients: {client_count}")
    print(f"📝 Open http://localhost:{port} in your browser")
    print("Press Ctrl+C to stop\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped")
    finally:
        httpd.server_close()


def upload_file(server_url: str, file_path: str, auth_token: str, set_preview: bool = False):
    """Upload a file to the server"""
    if not os.path.isfile(file_path):
        print(f"❌ Error: File not found: {file_path}")
        return False

    filename = os.path.basename(file_path)

    # Read file
    with open(file_path, "rb") as f:
        file_content = f.read()

    # Prepare multipart form data
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = io.BytesIO()

    body.write(f"--{boundary}\r\n".encode())
    body.write(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode())
    body.write(b"Content-Type: application/octet-stream\r\n\r\n")
    body.write(file_content)
    body.write(f"\r\n--{boundary}--\r\n".encode())

    # Upload
    url = f"{server_url.rstrip('/')}/api/upload"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }

    try:
        print(f"📤 Uploading {filename} ({len(file_content)} bytes)...")
        req = urllib.request.Request(url, data=body.getvalue(), headers=headers)

        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            print("✅ Upload successful!")
            print(f"   Filename: {result['filename']}")
            print(f"   Size: {result['size']} bytes")

            # Auto-set preview if requested
            if set_preview:
                print()
                return set_preview_func(server_url, result["id"], auth_token)

            return True

    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        try:
            error_json = json.loads(error_body)
            print(f"❌ Upload failed: {error_json.get('error', 'Unknown error')}")
        except (json.JSONDecodeError, KeyError):
            print(f"❌ Upload failed: HTTP {e.code}")
        return False
    except Exception as e:
        print(f"❌ Upload failed: {e}")
        return False


def set_preview_func(server_url: str, file_id: str, auth_token: str):
    """Set the current preview for all clients"""
    url = f"{server_url.rstrip('/')}/api/preview/set"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
    }
    data = json.dumps({"file_id": file_id}).encode()

    try:
        print(f"📺 Setting preview to: {file_id}")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            print("✅ Preview set successfully!")
            print(f"   Filename: {result['filename']}")
            print(f"   Timestamp: {result['timestamp']}")
            return True

    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        try:
            error_json = json.loads(error_body)
            print(f"❌ Failed to set preview: {error_json.get('error', 'Unknown error')}")
        except (json.JSONDecodeError, KeyError):
            print(f"❌ Failed to set preview: HTTP {e.code}")
        return False
    except Exception as e:
        print(f"❌ Failed to set preview: {e}")
        return False


def list_files(server_url: str, auth_token: str):
    """List all available files on the server"""
    url = f"{server_url.rstrip('/')}/api/files"
    headers = {"Authorization": f"Bearer {auth_token}"}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response:
            files = json.loads(response.read().decode())

            if not files:
                print("📋 No files available")
                return True

            print(f"📋 Available files ({len(files)}):\n")
            for file in files:
                size_str = format_file_size(file["size"])
                print(f"  • {file['name']}")
                print(f"    ID: {file['id']}")
                print(f"    Size: {size_str}")
                print(f"    Type: {file['mimetype']}")
                print(f"    Uploaded: {file['uploaded']}")
                print()

            return True

    except urllib.error.HTTPError as e:
        print(f"❌ Failed to list files: HTTP {e.code}")
        return False
    except Exception as e:
        print(f"❌ Failed to list files: {e}")
        return False


def _next_timestamp(current: int) -> int:
    """Return a monotonically increasing millisecond timestamp."""
    now = int(time.time() * 1000)
    return now if now > current else current + 1


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 Bytes"
    k = 1024
    sizes = ["Bytes", "KB", "MB", "GB"]
    i = 0
    size = float(size_bytes)
    while size >= k and i < len(sizes) - 1:
        size /= k
        i += 1
    return f"{size:.2f} {sizes[i]}"


SAFE_FILENAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789_.-")


def sanitize_filename(filename: str) -> str:
    """Normalize filename to lowercase a-z, 0-9, underscore, dash, and dot only."""
    return "".join((c if c in SAFE_FILENAME_CHARS else "_") for c in filename.lower())


def resolve_file_id(server_url: str, filename: str, auth_token: str) -> Optional[str]:
    """Resolve a filename to a file_id via the file list API, matching by normalized name."""
    url = f"{server_url.rstrip('/')}/api/files"
    normalized = sanitize_filename(filename)
    headers = {"Authorization": f"Bearer {auth_token}"}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as response:
        files = json.loads(response.read().decode())
    for f in files:
        if f["normalized_name"] == normalized:
            return f["id"]
    return None


def download_file(server_url: str, filename: str, auth_token: str, output_dir: Optional[str] = None) -> bool:
    """Download a file from the server"""
    # Determine output directory
    if output_dir:
        dest_dir = Path(output_dir)
        if not dest_dir.is_dir():
            print(f"❌ Error: Output path is not a directory: {output_dir}", file=sys.stderr)
            return False
    else:
        dest_dir = Path.cwd()
    # Sanitize filename for safe local storage
    safe_filename = sanitize_filename(filename)
    dest_path = dest_dir / safe_filename
    # Check if file already exists (no overwriting)
    if dest_path.exists():
        print(f"❌ Error: File already exists: {dest_path}", file=sys.stderr)
        print("   Remove the existing file or use a different output directory.", file=sys.stderr)
        return False
    # Resolve filename to file_id
    try:
        file_id = resolve_file_id(server_url, filename, auth_token)
    except Exception as e:
        print(f"❌ Failed to resolve file: {e}", file=sys.stderr)
        return False
    if not file_id:
        print(f"❌ Error: File not found on server: {filename}", file=sys.stderr)
        return False
    # Download the file
    url = f"{server_url.rstrip('/')}/download/{urllib.parse.quote(file_id)}"
    headers = {"Authorization": f"Bearer {auth_token}"}
    try:
        print(f"📥 Downloading {filename}...")
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response:
            content = response.read()
            # Write to file
            with open(dest_path, "wb") as f:
                f.write(content)
            print("✅ Downloaded successfully!")
            print(f"   Saved to: {dest_path}")
            print(f"   Size: {format_file_size(len(content))}")
            return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"❌ Error: File not found on server: {filename}", file=sys.stderr)
        else:
            print(f"❌ Failed to download: HTTP {e.code}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"❌ Failed to download: {e}", file=sys.stderr)
        return False


def get_pad(server_url: str, auth_token: str):
    """Get the current pad content from the server"""
    url = f"{server_url.rstrip('/')}/api/pad"
    headers = {"Authorization": f"Bearer {auth_token}"}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            content = result.get("content", "")
            if content:
                print(content)
            else:
                print("📋 Pad is empty")
            return True
    except urllib.error.HTTPError as e:
        print(f"❌ Failed to get pad: HTTP {e.code}")
        return False
    except Exception as e:
        print(f"❌ Failed to get pad: {e}")
        return False


def set_pad(server_url: str, content: str, auth_token: str):
    """Set the pad content on the server"""
    url = f"{server_url.rstrip('/')}/api/pad"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
    }
    data = json.dumps({"content": content}).encode()
    try:
        print(f"📝 Setting pad content ({len(content)} characters)...")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            print("✅ Pad content updated successfully!")
            print(f"   Timestamp: {result['timestamp']}")
            print(f"   Size: {result['size']} characters")
            return True
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        try:
            error_json = json.loads(error_body)
            print(f"❌ Failed to set pad: {error_json.get('error', 'Unknown error')}")
        except (json.JSONDecodeError, KeyError):
            print(f"❌ Failed to set pad: HTTP {e.code}")
        return False
    except Exception as e:
        print(f"❌ Failed to set pad: {e}")
        return False


def register_client(
    server_url: str,
    name: str,
    auth_token: Optional[str] = None,
    new_client_id: Optional[str] = None,
    new_client_secret: Optional[str] = None,
):
    """Register a new client with the server, save credentials to config."""
    if not auth_token:
        print("❌ Admin credentials required to register new clients.", file=sys.stderr)
        print("   Provide --client-id and --client-secret of an admin account.", file=sys.stderr)
        return None, None

    client_id = new_client_id or secrets.token_hex(16)
    client_secret = new_client_secret or secrets.token_hex(32)

    url = f"{server_url.rstrip('/')}/api/clients/register"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {auth_token}",
    }

    data = json.dumps(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "name": name,
        }
    ).encode()

    try:
        print(f"🔑 Registering client '{name}'...")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            is_admin = result.get("admin", False)
            print("✅ Registration successful!")
            print(f"   Client ID:     {client_id}")
            print(f"   Client Secret: {client_secret}")
            print(f"   Admin:         {is_admin}")
            print("\n   Save these credentials — the secret cannot be retrieved later.")
            return client_id, client_secret
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        try:
            error_json = json.loads(error_body)
            print(f"❌ Registration failed: {error_json.get('error', 'Unknown error')}")
        except (json.JSONDecodeError, KeyError):
            print(f"❌ Registration failed: HTTP {e.code}")
        return None, None
    except Exception as e:
        print(f"❌ Registration failed: {e}")
        return None, None


def list_clients_cmd(server_url: str, auth_token: str):
    """List registered clients on the server."""
    url = f"{server_url.rstrip('/')}/api/clients"
    headers = {"Authorization": f"Bearer {auth_token}"}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response:
            clients = json.loads(response.read().decode())
            if not clients:
                print("👥 No clients registered")
                return True
            print(f"👥 Registered clients ({len(clients)}):\n")
            for c in clients:
                admin_str = " (admin)" if c.get("admin") else ""
                print(f"  • {c['client_id']}{admin_str}")
                if c.get("name"):
                    print(f"    Name: {c['name']}")
                if c.get("registered"):
                    print(f"    Registered: {c['registered']}")
                print()
            return True
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        try:
            error_json = json.loads(error_body)
            print(f"❌ Failed to list clients: {error_json.get('error', 'Unknown error')}")
        except (json.JSONDecodeError, KeyError):
            print(f"❌ Failed to list clients: HTTP {e.code}")
        return False
    except Exception as e:
        print(f"❌ Failed to list clients: {e}")
        return False


def delete_client_cmd(server_url: str, target_client_id: str, auth_token: str):
    """Delete a registered client on the server (admin only)."""
    url = f"{server_url.rstrip('/')}/api/clients/{urllib.parse.quote(target_client_id)}"
    headers = {"Authorization": f"Bearer {auth_token}"}

    try:
        print(f"🗑️  Deleting client {target_client_id}...")
        req = urllib.request.Request(url, headers=headers, method="DELETE")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            print("✅ Client deleted successfully!")
            print(f"   Deleted: {result['deleted']}")
            return True
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        try:
            error_json = json.loads(error_body)
            print(f"❌ Failed to delete client: {error_json.get('error', 'Unknown error')}")
        except (json.JSONDecodeError, KeyError):
            print(f"❌ Failed to delete client: HTTP {e.code}")
        return False
    except Exception as e:
        print(f"❌ Failed to delete client: {e}")
        return False


def server_setup_cmd(args):
    """First-time server setup. Writes admin client to config.

    Default (non-interactive): errors if --url is missing; auto-generates
    client-id/secret; defaults server name to "default".

    With --interactive: prompts for each un-provided field in order.
    """
    interactive = getattr(args, "interactive", False)
    config = load_config() or {}
    servers = config.get("servers", {})

    # Show existing servers
    if servers:
        print("Existing servers:")
        for name, srv in servers.items():
            print(f"  {name}: {srv.get('url', '(no url)')}")
        print()

    # Resolve server name
    server_name = getattr(args, "server", None)
    if not server_name:
        if interactive:
            server_name = input("Server name [default]: ").strip() or "default"
        else:
            server_name = "default"

    # Resolve URL
    url = getattr(args, "url", None)
    if not url:
        if interactive:
            hint = ""
            if server_name in servers and servers[server_name].get("url"):
                hint = servers[server_name]["url"]
            url = input(f"Server URL [{hint or 'http://localhost:8080'}]: ").strip()
            if not url:
                url = hint or "http://localhost:8080"
        else:
            # Non-interactive: --url is required
            print("Error: missing required flag: --url", file=sys.stderr)
            print("  Tip: use --interactive to be prompted for missing fields.", file=sys.stderr)
            sys.exit(1)

    # Resolve client ID
    client_id = getattr(args, "client_id", None)
    if not client_id:
        if interactive:
            client_id = input("Admin client ID (blank to auto-generate) [auto-generate]: ").strip()
        if not client_id:
            client_id = secrets.token_hex(16)
            print(f"  Generated client ID: {client_id}")

    # Resolve client secret
    client_secret = getattr(args, "client_secret", None)
    if not client_secret:
        if interactive:
            client_secret = input("Admin client secret (blank to auto-generate) [auto-generate]: ").strip()
        if not client_secret:
            client_secret = secrets.token_hex(32)
            print(f"  Generated client secret: {client_secret}")

    # Resolve client name
    client_name = getattr(args, "client_name", "") or ""
    if not client_name and interactive:
        client_name = input("Admin client name (blank for none): ").strip()

    # Compute salted hash
    salt = secrets.token_hex(16)
    secret_hash = hashlib.sha256((salt + client_secret).encode()).hexdigest()

    with _config_locked() as cfg:
        srvs = cfg.setdefault("servers", {})
        entry = srvs.setdefault(server_name, {})
        entry["url"] = url
        clients = entry.setdefault("clients", {})
        clients[client_id] = {
            "salt": salt,
            "secret_hash": secret_hash,
            "admin": True,
            "name": client_name,
            "registered": datetime.now().isoformat(),
        }
        if "default-server" not in cfg:
            cfg["default-server"] = server_name
        entry["client-id"] = client_id
        entry["client-secret"] = client_secret

    print(f"\n✅ Server '{server_name}' configured at {url}")
    print(f"   Admin client ID:     {client_id}")
    print(f"   Admin client secret: {client_secret}")
    print(f"   Config saved to {CONFIG_PATH}")
    print("\n   Save these credentials — the secret cannot be retrieved later.")


def server_add_user_cmd(args):
    """Add a user client to a configured server's config.

    Default (non-interactive): auto-generates client-id/secret, uses config
    defaults.  With --interactive: prompts for each un-provided field.
    """
    interactive = getattr(args, "interactive", False)
    server_name = getattr(args, "server", None)
    is_admin = getattr(args, "admin", False)

    # Resolve client ID
    client_id = getattr(args, "client_id", None)
    if not client_id:
        if interactive:
            client_id = input("Client ID (blank to auto-generate) [auto-generate]: ").strip()
        if not client_id:
            client_id = secrets.token_hex(16)
            print(f"  Generated client ID: {client_id}")

    # Resolve client secret
    client_secret = getattr(args, "client_secret", None)
    if not client_secret:
        if interactive:
            client_secret = input("Client secret (blank to auto-generate) [auto-generate]: ").strip()
        if not client_secret:
            client_secret = secrets.token_hex(32)
            print(f"  Generated client secret: {client_secret}")

    # Resolve client name
    client_name = getattr(args, "client_name", "") or ""
    if not client_name and interactive:
        client_name = input("Client name (blank for none): ").strip()

    # Compute salted hash
    salt = secrets.token_hex(16)
    secret_hash = hashlib.sha256((salt + client_secret).encode()).hexdigest()

    with _config_locked() as cfg:
        if not cfg:
            print("Error: No config file found.", file=sys.stderr)
            print("Run 'companion server-setup' first.", file=sys.stderr)
            sys.exit(1)
        if not server_name:
            server_name = cfg.get("default-server")
        if not server_name:
            print("Error: No server specified and no default-server in config.", file=sys.stderr)
            sys.exit(1)
        servers = cfg.get("servers", {})
        if server_name not in servers:
            available = ", ".join(servers.keys()) if servers else "(none)"
            print(f"Error: Server '{server_name}' not found. Available: {available}", file=sys.stderr)
            sys.exit(1)
        entry = servers[server_name]
        clients = entry.setdefault("clients", {})
        if client_id in clients:
            print(f"Error: Client '{client_id}' already exists on server '{server_name}'.", file=sys.stderr)
            sys.exit(1)
        clients[client_id] = {
            "salt": salt,
            "secret_hash": secret_hash,
            "admin": is_admin,
            "name": client_name,
            "registered": datetime.now().isoformat(),
        }

    role = "admin" if is_admin else "user"
    print(f"\n✅ Added {role} client to server '{server_name}'")
    print(f"   Client ID:     {client_id}")
    print(f"   Client secret: {client_secret}")
    print(f"   Config saved to {CONFIG_PATH}")
    print("\n   Save these credentials — the secret cannot be retrieved later.")


def connect_cmd(args):
    """Save server connection credentials locally (no server contact).

    Default (non-interactive): all of --url, --client-id, --client-secret are
    required.  With --interactive: prompts for each un-provided field.
    """
    interactive = getattr(args, "interactive", False)
    server_name = getattr(args, "server", None) or "default"

    url = getattr(args, "url", None)
    client_id = getattr(args, "client_id", None)
    client_secret = getattr(args, "client_secret", None)

    if interactive:
        if not url:
            url = input("Server URL: ").strip()
        if not client_id:
            client_id = input("Client ID: ").strip()
        if not client_secret:
            client_secret = input("Client secret: ").strip()

    # Validate required fields
    missing = []
    if not url:
        missing.append("--url")
    if not client_id:
        missing.append("--client-id")
    if not client_secret:
        missing.append("--client-secret")
    if missing:
        print(f"Error: Missing required flags: {', '.join(missing)}", file=sys.stderr)
        print("Provide all flags or use --interactive to be prompted.", file=sys.stderr)
        sys.exit(1)

    with _config_locked() as config:
        servers = config.setdefault("servers", {})
        if server_name in servers:
            print(f"Error: Server '{server_name}' already exists. Use a different name.", file=sys.stderr)
            sys.exit(1)
        servers[server_name] = {
            "url": url,
            "client-id": client_id,
            "client-secret": client_secret,
        }
        if "default-server" not in config:
            config["default-server"] = server_name
    print(f"\n✅ Saved connection for server '{server_name}'")
    print(f"   URL:           {url}")
    print(f"   Client ID:     {client_id}")
    print(f"   Config saved to {CONFIG_PATH}")


def register_cmd(args):
    """Register a new client on a server using admin credentials from config."""
    interactive = getattr(args, "interactive", False)

    # Server resolution: --server is mandatory
    server_name = getattr(args, "server", None)
    if not server_name:
        if not interactive:
            print("Error: --server is required. Provide --server or use --interactive.", file=sys.stderr)
            sys.exit(1)
        config = load_config()
        default_server = config.get("default-server", "") if config else ""
        prompt = f"Server name [{default_server}]: " if default_server else "Server name: "
        server_name = input(prompt).strip() or default_server
        if not server_name:
            print("Error: No server name provided.", file=sys.stderr)
            sys.exit(1)
        args.server = server_name

    server_url, auth_token = resolve_server(args)
    if not auth_token:
        print("Error: No admin credentials found for this server.", file=sys.stderr)
        sys.exit(1)

    # New-client fields
    name = getattr(args, "name", "") or ""
    new_client_id = getattr(args, "new_client_id", None)
    new_client_secret = getattr(args, "new_client_secret", None)

    if interactive:
        if not name:
            name = input("Client name (blank for none): ").strip()
        if not new_client_id:
            new_client_id = input("New client ID (blank to auto-generate): ").strip() or None
        if not new_client_secret:
            new_client_secret = input("New client secret (blank to auto-generate): ").strip() or None

    new_client_id, new_client_secret = register_client(
        server_url, name, auth_token, new_client_id=new_client_id, new_client_secret=new_client_secret
    )
    if new_client_id:
        print("\n   Share the credentials above with the new client.")
    sys.exit(0 if new_client_id else 1)


COMMAND_GROUPS = [
    ("Server", ["server", "server-setup", "server-add-user"]),
    ("Client", ["connect", "upload", "download", "list", "set-preview", "get-pad", "set-pad"]),
    ("Admin", ["register", "clients", "delete-client"]),
]


def _build_grouped_help(subparsers_action):
    """Build grouped help text from COMMAND_GROUPS, reading descriptions from the subparsers."""
    # Read help strings from the registered subparsers
    choices = {}
    for choice in subparsers_action._choices_actions:
        choices[choice.dest] = choice.help or ""

    # Verify groups match registered subparsers (minus "help" which is internal)
    grouped = {cmd for _, cmds in COMMAND_GROUPS for cmd in cmds}
    registered = set(choices.keys()) - {"help"}
    if grouped != registered:
        missing = registered - grouped
        extra = grouped - registered
        parts = []
        if missing:
            parts.append(f"not in COMMAND_GROUPS: {missing}")
        if extra:
            parts.append(f"not registered as subparsers: {extra}")
        raise RuntimeError(f"COMMAND_GROUPS out of sync with subparsers: {', '.join(parts)}")

    # Suppress the default flat listing now that we've read from it
    subparsers_action._choices_actions.clear()

    max_cmd = max(len(cmd) for _, cmds in COMMAND_GROUPS for cmd in cmds)
    lines = []
    for group_name, cmds in COMMAND_GROUPS:
        lines.append(f"\n{group_name}:")
        for cmd in cmds:
            lines.append(f"  {cmd:<{max_cmd}}  {choices.get(cmd, '')}")
    lines.append("\nRun 'companion.py <command> --help' for more info on a command.")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Companion - Simple file sharing server and client",
        usage="companion.py <command> [options]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="mode", metavar="", title=None)
    # Help mode
    subparsers.add_parser("help", add_help=False)
    # Server mode
    server_parser = subparsers.add_parser("server", help="Run in server mode")
    server_parser.add_argument("--port", type=int, help="Port to listen on (default: 8080 or from config)")
    server_parser.add_argument("--server", help="Named server from config file")
    server_parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    # Server setup mode
    setup_parser = subparsers.add_parser("server-setup", help="First-time server setup")
    setup_parser.add_argument("--server", help="Server name (default: 'default')")
    setup_parser.add_argument("--url", help="Server URL (required in non-interactive mode)")
    setup_parser.add_argument("--client-id", help="Admin client ID (auto-generated if blank)")
    setup_parser.add_argument("--client-secret", help="Admin client secret (auto-generated if blank)")
    setup_parser.add_argument("--client-name", default="", help="Friendly name for the admin client")
    setup_parser.add_argument("--interactive", action="store_true", help="Prompt for missing fields")
    # Server add-user mode
    add_user_parser = subparsers.add_parser("server-add-user", help="Add a user to a configured server")
    add_user_parser.add_argument("--server", help="Named server from config file")
    add_user_parser.add_argument("--client-name", default="", help="Friendly name for this client")
    add_user_parser.add_argument("--admin", action="store_true", help="Grant admin privileges")
    add_user_parser.add_argument("--client-id", help="Client ID (auto-generated if blank)")
    add_user_parser.add_argument("--client-secret", help="Client secret (auto-generated if blank)")
    add_user_parser.add_argument("--interactive", action="store_true", help="Prompt for missing fields")
    # Connect mode
    connect_parser = subparsers.add_parser("connect", help="Save server connection credentials locally")
    connect_parser.add_argument("--server", help="Server name (default: 'default')")
    connect_parser.add_argument("--url", help="Server URL")
    connect_parser.add_argument("--client-id", help="Client ID")
    connect_parser.add_argument("--client-secret", help="Client secret")
    connect_parser.add_argument("--interactive", action="store_true", help="Prompt for missing fields")

    # Helper to add common server selection args to client subparsers
    def add_server_args(subparser, needs_auth=True):
        subparser.add_argument("--server", help="Named server from config file")
        subparser.add_argument("--server-url", help="Explicit server URL (e.g., http://localhost:8080)")
        if needs_auth:
            subparser.add_argument("--client-id", help="Client ID (overrides config)")
            subparser.add_argument("--client-secret", help="Client secret (overrides config)")

    # Upload mode
    upload_parser = subparsers.add_parser("upload", help="Upload a file to the server")
    upload_parser.add_argument("file_path", help="Path to file to upload")
    upload_parser.add_argument(
        "--set-preview",
        action="store_true",
        help="Automatically set this file as preview for all clients after upload",
    )
    add_server_args(upload_parser, needs_auth=True)
    # List mode
    list_parser = subparsers.add_parser("list", help="List all available files")
    add_server_args(list_parser, needs_auth=True)
    # Download mode
    download_parser = subparsers.add_parser("download", help="Download a file from the server")
    download_parser.add_argument("filename", help="Name of the file to download")
    download_parser.add_argument("-o", "--output", help="Output directory (default: current directory)")
    add_server_args(download_parser, needs_auth=True)
    # Set preview mode
    preview_parser = subparsers.add_parser("set-preview", help="Set the current preview for all clients")
    preview_parser.add_argument("filename", help="Filename to preview")
    add_server_args(preview_parser, needs_auth=True)
    # Get pad mode
    get_pad_parser = subparsers.add_parser("get-pad", help="Get the current pad content")
    add_server_args(get_pad_parser, needs_auth=True)
    # Set pad mode
    set_pad_parser = subparsers.add_parser("set-pad", help="Set the pad content")
    set_pad_parser.add_argument("content", help="Content to set in the pad")
    add_server_args(set_pad_parser, needs_auth=True)
    # Register mode
    register_parser = subparsers.add_parser("register", help="Register a new client with the server")
    register_parser.add_argument("--name", default="", help="Friendly name for this client")
    register_parser.add_argument("--new-client-id", help="Client ID for the new client (auto-generated if blank)")
    register_parser.add_argument(
        "--new-client-secret", help="Client secret for the new client (auto-generated if blank)"
    )
    register_parser.add_argument("--interactive", action="store_true", help="Prompt for missing fields")
    add_server_args(register_parser, needs_auth=True)
    # Clients mode
    clients_parser = subparsers.add_parser("clients", help="List registered clients on the server")
    add_server_args(clients_parser, needs_auth=True)
    # Delete client mode
    delete_client_parser = subparsers.add_parser("delete-client", help="Delete a registered client (admin only)")
    delete_client_parser.add_argument("client_id_to_delete", help="Client ID to delete")
    add_server_args(delete_client_parser, needs_auth=True)
    # Build grouped help and attach as epilog
    parser.epilog = _build_grouped_help(subparsers)
    # Remove the empty positional arguments section from output
    parser._action_groups = [g for g in parser._action_groups if g.title is not None]

    # Parse args
    args = parser.parse_args()
    if not args.mode or args.mode == "help":
        parser.print_help()
        sys.exit(0 if args.mode == "help" else 1)
    if args.mode == "server-setup":
        server_setup_cmd(args)
    elif args.mode == "server-add-user":
        server_add_user_cmd(args)
    elif args.mode == "connect":
        connect_cmd(args)
    elif args.mode == "server":
        # Configure logging
        log_level = logging.DEBUG if args.debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format="[%(asctime)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        port = resolve_server_config(args)
        run_server(port)
    elif args.mode == "upload":
        server_url, auth_token = resolve_server(args)
        if not auth_token:
            print("Error: Credentials required for upload.", file=sys.stderr)
            print("Run 'companion server-add-user' first, or provide --client-id and --client-secret.", file=sys.stderr)
            sys.exit(1)
        success = upload_file(
            server_url,
            args.file_path,
            auth_token,
            set_preview=args.set_preview,
        )
        sys.exit(0 if success else 1)
    elif args.mode == "list":
        server_url, auth_token = resolve_server(args)
        if not auth_token:
            print("Error: Credentials required to list files.", file=sys.stderr)
            print("Run 'companion server-add-user' first, or provide --client-id and --client-secret.", file=sys.stderr)
            sys.exit(1)
        success = list_files(server_url, auth_token)
        sys.exit(0 if success else 1)
    elif args.mode == "download":
        server_url, auth_token = resolve_server(args)
        if not auth_token:
            print("Error: Credentials required to download files.", file=sys.stderr)
            print("Run 'companion server-add-user' first, or provide --client-id and --client-secret.", file=sys.stderr)
            sys.exit(1)
        success = download_file(server_url, args.filename, auth_token, args.output)
        sys.exit(0 if success else 1)
    elif args.mode == "set-preview":
        server_url, auth_token = resolve_server(args)
        if not auth_token:
            print("Error: Credentials required for set-preview.", file=sys.stderr)
            print("Run 'companion server-add-user' first, or provide --client-id and --client-secret.", file=sys.stderr)
            sys.exit(1)
        file_id = resolve_file_id(server_url, args.filename, auth_token)
        if not file_id:
            print(f"Error: File not found on server: {args.filename}", file=sys.stderr)
            sys.exit(1)
        success = set_preview_func(server_url, file_id, auth_token)
        sys.exit(0 if success else 1)
    elif args.mode == "get-pad":
        server_url, auth_token = resolve_server(args)
        if not auth_token:
            print("Error: Credentials required to get pad.", file=sys.stderr)
            print("Run 'companion server-add-user' first, or provide --client-id and --client-secret.", file=sys.stderr)
            sys.exit(1)
        success = get_pad(server_url, auth_token)
        sys.exit(0 if success else 1)
    elif args.mode == "set-pad":
        server_url, auth_token = resolve_server(args)
        if not auth_token:
            print("Error: Credentials required for set-pad.", file=sys.stderr)
            print("Run 'companion server-add-user' first, or provide --client-id and --client-secret.", file=sys.stderr)
            sys.exit(1)
        success = set_pad(server_url, args.content, auth_token)
        sys.exit(0 if success else 1)
    elif args.mode == "register":
        register_cmd(args)
    elif args.mode == "clients":
        server_url, auth_token = resolve_server(args)
        if not auth_token:
            print("Error: Credentials required to list clients.", file=sys.stderr)
            print("Run 'companion server-add-user' first, or provide --client-id and --client-secret.", file=sys.stderr)
            sys.exit(1)
        success = list_clients_cmd(server_url, auth_token)
        sys.exit(0 if success else 1)
    elif args.mode == "delete-client":
        server_url, auth_token = resolve_server(args)
        if not auth_token:
            print("Error: Credentials required to delete a client.", file=sys.stderr)
            print("Run 'companion server-add-user' first, or provide --client-id and --client-secret.", file=sys.stderr)
            sys.exit(1)
        success = delete_client_cmd(server_url, args.client_id_to_delete, auth_token)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    # Force UTF-8 encoding on Windows for emoji support
    if sys.platform == "win32":
        import codecs

        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
        sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())
    main()
