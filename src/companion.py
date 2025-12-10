#!/usr/bin/env python3
"""
Companion - Simple file sharing server and client
Usage:
    Server:      python companion.py server [--port PORT] [--api-key KEY] [--server NAME]
    Upload:      python companion.py upload <file_path> [--set-preview]
    List files:  python companion.py list
    Set preview: python companion.py set-preview <filename>
    Get pad:     python companion.py get-pad
    Set pad:     python companion.py set-pad <content>

Config file (~/.config/companion/config.json):
    All commands use default-server from config if available.
    Override with --server <name> or --server-url <url> --api-key <key>
"""

import argparse
import http.server
import io
import json
import logging
import mimetypes
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from http import HTTPStatus
from pathlib import Path
from threading import Lock
from typing import Dict, Optional, Tuple

# In-memory file storage: {filename: (content_bytes, mimetype, upload_time)}
FILES: Dict[str, Tuple[bytes, str, str]] = {}
FILES_LOCK = Lock()
API_KEY = None  # Must be set via command line

# Preview state: current preview for all clients
PREVIEW_STATE = {"filename": None, "timestamp": 0}
PREVIEW_LOCK = Lock()

# Pad state: shared text pad content
PAD_STATE = {"content": "", "timestamp": 0}
PAD_LOCK = Lock()
PAD_MAX_SIZE = 10 * 1024 * 1024  # 10MB character limit

# Config file path
CONFIG_PATH = Path.home() / ".config" / "companion" / "config.json"

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


def resolve_server(args) -> Tuple[str, Optional[str]]:
    """
    Resolve server URL and API key from args and config.
    Returns (url, api_key) or exits with helpful error message.

    Priority order:
    1. --server-url (explicit URL, api-key from --api-key or None)
    2. --server (named server from config)
    3. default-server from config
    """
    config = load_config()

    # Priority 1: Explicit --server-url
    if hasattr(args, "server_url") and args.server_url:
        api_key = getattr(args, "api_key", None)
        return args.server_url, api_key

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
        api_key = getattr(args, "api_key", None) or server_config.get("api-key")
        return url, api_key

    # Priority 3: default-server from config
    if config:
        default_name = config.get("default-server")
        if default_name:
            servers = config.get("servers", {})
            if default_name in servers:
                server_config = servers[default_name]
                url = server_config.get("url")
                api_key = getattr(args, "api_key", None) or server_config.get("api-key")
                return url, api_key
            else:
                print(f"Error: default-server '{default_name}' not found in servers.", file=sys.stderr)
                sys.exit(1)

    # No server could be resolved - show helpful error
    print("Error: No server specified.", file=sys.stderr)
    print(f"\nTo fix this, either:", file=sys.stderr)
    print(f"  1. Create a config file at {CONFIG_PATH} with:", file=sys.stderr)
    _print_config_help()
    print(f"\n  2. Or specify a server explicitly:", file=sys.stderr)
    print(f"     companion upload --server-url http://localhost:8080 --api-key yourkey file.pdf", file=sys.stderr)
    sys.exit(1)


def _print_config_help():
    """Print example config file structure."""
    example = """{
  "default-server": "myserver",
  "servers": {
    "myserver": {
      "url": "http://localhost:8080",
      "api-key": "yourkey"
    }
  }
}"""
    for line in example.split("\n"):
        print(f"     {line}", file=sys.stderr)


def resolve_server_config(args) -> Tuple[int, str]:
    """
    Resolve server port and API key from args and config for server mode.
    Returns (port, api_key) or exits with helpful error message.

    Priority order:
    1. CLI args (--port, --api-key) override config
    2. --server (named server from config)
    3. default-server from config
    4. Defaults (port 8080, but api-key required)
    """
    config = load_config()

    # Start with CLI values (may be None)
    port = getattr(args, "port", None)
    api_key = getattr(args, "api_key", None)

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
    elif config:
        # Try default-server
        default_name = config.get("default-server")
        if default_name:
            servers = config.get("servers", {})
            if default_name in servers:
                server_config = servers[default_name]

    # Apply config values where CLI didn't override
    if server_config:
        if api_key is None:
            api_key = server_config.get("api-key")
        if port is None:
            # Parse port from URL
            url = server_config.get("url", "")
            parsed = urllib.parse.urlparse(url)
            if parsed.port:
                port = parsed.port

    # Apply defaults
    if port is None:
        port = 8080

    # API key is required
    if not api_key:
        print("Error: API key required for server mode.", file=sys.stderr)
        print("\nTo fix this, either:", file=sys.stderr)
        print(f"  1. Add api-key to your config at {CONFIG_PATH}", file=sys.stderr)
        print("  2. Or specify --api-key on the command line", file=sys.stderr)
        sys.exit(1)

    return port, api_key


class FileShareHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for file sharing server"""

    def _set_headers(self, status=HTTPStatus.OK, content_type="text/html"):
        self.send_response(status)
        self.send_header("Content-type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def _check_api_key(self) -> bool:
        """Check if API key in Authorization header is valid"""
        auth_header = self.headers.get("Authorization", "")
        return auth_header == f"Bearer {API_KEY}"

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
        elif path.startswith("/download/"):
            filename = urllib.parse.unquote(path[10:])
            self._serve_file(filename)
        else:
            self._set_headers(HTTPStatus.NOT_FOUND)
            self.wfile.write(b"Not found")

    def do_POST(self):
        """Handle POST requests (file uploads)"""
        if self.path == "/api/preview/set":
            self._handle_preview_set()
        elif self.path == "/api/pad":
            self._handle_pad_update()
        elif self.path == "/api/upload":
            if not self._check_api_key():
                self._set_headers(HTTPStatus.UNAUTHORIZED, "application/json")
                self.wfile.write(json.dumps({"error": "Invalid API key"}).encode())
                return

            content_length = int(self.headers["Content-Length"])
            body = self.rfile.read(content_length)

            # Parse multipart form data manually (simple version)
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" in content_type:
                self._handle_multipart_upload(body, content_type)
            else:
                self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
                self.wfile.write(json.dumps({"error": "Expected multipart/form-data"}).encode())
        else:
            self._set_headers(HTTPStatus.NOT_FOUND)
            self.wfile.write(b"Not found")

    def _handle_multipart_upload(self, body: bytes, content_type: str):
        """Parse multipart form data and store file"""
        # Extract boundary
        boundary = None
        for part in content_type.split(";"):
            if "boundary=" in part:
                boundary = part.split("boundary=")[1].strip()
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

                    with FILES_LOCK:
                        FILES[filename] = (content, mimetype, upload_time)

                    self._set_headers(HTTPStatus.OK, "application/json")
                    self.wfile.write(
                        json.dumps(
                            {
                                "success": True,
                                "filename": filename,
                                "size": len(content),
                            }
                        ).encode()
                    )
                    return

        self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
        self.wfile.write(json.dumps({"error": "No file found in upload"}).encode())

    def _serve_index(self):
        """Serve the main HTML page"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Companion</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- PDF.js CDN - will be inlined in build -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/5.4.149/pdf.min.mjs" type="module"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; max-width: 900px; margin: 40px auto 80px; padding: 0 20px; background: #f5f5f5; }
        h1 { color: #333; }
        .tab-content { display: none; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .tab-content.active { display: block; }
        .upload-form { margin: 0; }
        .file-list { margin: 0; }
        .file-item { padding: 12px; margin: 8px 0; border: 1px solid #e0e0e0; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }
        .file-info { flex: 1; }
        .file-name { font-weight: 600; color: #333; }
        .file-meta { font-size: 12px; color: #666; margin-top: 4px; }
        .file-actions { display: flex; gap: 8px; }
        button, input[type="submit"] { background: #007bff; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 14px; }
        button:hover, input[type="submit"]:hover { background: #0056b3; }
        .btn-secondary { background: #6c757d; }
        .btn-secondary:hover { background: #545b62; }
        input[type="file"] { margin: 10px 0; }
        input[type="text"] { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 300px; font-size: 14px; }
        .status { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .status.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .empty-state { text-align: center; color: #999; padding: 40px; }
        .progress-container { display: none; margin: 10px 0; }
        .progress-container.active { display: block; }
        .progress-bar-bg { width: 100%; height: 24px; background: #e0e0e0; border-radius: 12px; overflow: hidden; }
        .progress-bar { height: 100%; background: linear-gradient(90deg, #007bff, #0056b3); transition: width 0.3s ease; display: flex; align-items: center; justify-content: center; color: white; font-size: 12px; font-weight: 600; }
        .preview-container { max-width: 100%; }
        .preview-container img { max-width: 100%; height: auto; border-radius: 4px; }
        .preview-container video { max-width: 100%; height: auto; border-radius: 4px; }
        .preview-container audio { width: 100%; }
        .preview-container pre { background: #f5f5f5; padding: 15px; border-radius: 4px; overflow-x: auto; max-height: 500px; }
        .preview-container iframe { width: 100%; height: 600px; border: 1px solid #e0e0e0; border-radius: 4px; }
        .bottom-nav { position: fixed; bottom: 0; left: 0; right: 0; background: white; border-top: 1px solid #e0e0e0; display: flex; box-shadow: 0 -2px 10px rgba(0,0,0,0.1); }
        .nav-button { flex: 1; padding: 16px; text-align: center; background: white; border: none; cursor: pointer; font-size: 16px; color: #666; transition: background 0.2s, color 0.2s; }
        .nav-button:hover { background: #f5f5f5; }
        .nav-button.active { color: #007bff; background: #f0f8ff; border-top: 3px solid #007bff; }
        .nav-button:not(:last-child) { border-right: 1px solid #e0e0e0; }
    </style>
</head>
<body>
    <h1>📁 Companion</h1>

    <div id="uploadTab" class="tab-content active">
        <div class="upload-form">
            <h2>Upload File</h2>
            <form id="uploadForm">
                <div>
                    <input type="text" id="apiKey" placeholder="API Key" required>
                </div>
                <div>
                    <input type="file" id="fileInput" required>
                </div>
                <input type="submit" value="Upload">
            </form>
            <div id="progressContainer" class="progress-container">
                <div class="progress-bar-bg">
                    <div id="progressBar" class="progress-bar" style="width: 0%">0%</div>
                </div>
            </div>
            <div id="uploadStatus"></div>
        </div>
    </div>

    <div id="filesTab" class="tab-content">
        <div class="file-list">
            <h2>Available Files</h2>
            <div id="fileList">
                <div class="empty-state">Loading...</div>
            </div>
            <div style="margin-top: 15px;">
                <button id="refreshBtn" class="btn-secondary" style="display: none;">Refresh</button>
                <label style="margin-left: 15px;">
                    <input type="checkbox" id="autoRefresh" checked>
                    Auto-refresh
                </label>
            </div>
        </div>
    </div>

    <div id="previewTab" class="tab-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <h2 id="previewFileName" style="margin: 0;">Preview</h2>
            <button id="previewDownloadBtn" style="display: none;">Download</button>
        </div>
        <div id="previewContent" class="preview-container">
            <div class="empty-state">Select a file to preview</div>
        </div>
    </div>

    <div id="padTab" class="tab-content">
        <h2>Shared Pad</h2>
        <div>
            <input type="text" id="padApiKey" placeholder="API Key (required for editing)" style="width: 100%; max-width: 400px; margin-bottom: 10px;">
        </div>
        <textarea id="padContent" placeholder="Type or paste text here to share between devices..." style="width: 100%; height: 400px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-family: monospace; font-size: 14px; resize: vertical;"></textarea>
        <div style="margin-top: 10px; display: flex; justify-content: space-between; align-items: center;">
            <div id="padStatus" style="font-size: 12px; color: #666;"></div>
            <div style="font-size: 12px; color: #999;">
                <span id="padCharCount">0</span> characters
            </div>
        </div>
    </div>

    <div class="bottom-nav">
        <button class="nav-button active" data-tab="upload">Upload</button>
        <button class="nav-button" data-tab="files">Files</button>
        <button class="nav-button" data-tab="preview">Preview</button>
        <button class="nav-button" data-tab="pad">Pad</button>
    </div>

    <script type="module">
        // PDF.js setup
        import * as pdfjsLib from 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/5.4.149/pdf.min.mjs';
        pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/5.4.149/pdf.worker.min.mjs';

        // PDF state (module-level)
        let pdfDoc = null;
        let pageNum = 1;
        let pageRendering = false;
        let pageNumPending = null;

        let autoRefreshInterval = null;
        let localPreviewTimestamp = 0;
        let currentPreviewFilename = null;

        // Pad state
        let padSaveTimeout = null;
        let localPadTimestamp = 0;
        let isUpdatingPad = false;

        // Tab switching
        function switchTab(tab) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-button').forEach(el => el.classList.remove('active'));

            // Show selected tab
            if (tab === 'upload') {
                document.getElementById('uploadTab').classList.add('active');
                document.querySelector('[data-tab="upload"]').classList.add('active');
            } else if (tab === 'files') {
                document.getElementById('filesTab').classList.add('active');
                document.querySelector('[data-tab="files"]').classList.add('active');
            } else if (tab === 'preview') {
                document.getElementById('previewTab').classList.add('active');
                document.querySelector('[data-tab="preview"]').classList.add('active');
            } else if (tab === 'pad') {
                document.getElementById('padTab').classList.add('active');
                document.querySelector('[data-tab="pad"]').classList.add('active');
            }
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }

        function formatDate(isoString) {
            const date = new Date(isoString);
            return date.toLocaleString();
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        async function loadFiles() {
            try {
                const response = await fetch('/api/files');
                const files = await response.json();

                const fileListDiv = document.getElementById('fileList');

                if (files.length === 0) {
                    fileListDiv.innerHTML = '<div class="empty-state">No files uploaded yet</div>';
                    return;
                }

                fileListDiv.innerHTML = files.map(file => `
                    <div class="file-item">
                        <div class="file-info">
                            <div class="file-name">${escapeHtml(file.name)}</div>
                            <div class="file-meta">${formatBytes(file.size)} • ${formatDate(file.uploaded)}</div>
                        </div>
                        <div class="file-actions">
                            <button data-action="preview" data-filename="${escapeHtml(file.name)}" data-mimetype="${escapeHtml(file.mimetype)}">Preview</button>
                            <button data-action="download" data-filename="${escapeHtml(file.name)}">Download</button>
                        </div>
                    </div>
                `).join('');
            } catch (error) {
                document.getElementById('fileList').innerHTML =
                    '<div class="empty-state">Error loading files</div>';
            }
        }

        function downloadFile(filename) {
            window.location.href = '/download/' + encodeURIComponent(filename);
        }

        function previewFile(filename, mimetype) {
            const previewContent = document.getElementById('previewContent');
            const previewFileName = document.getElementById('previewFileName');
            const previewDownloadBtn = document.getElementById('previewDownloadBtn');
            const url = '/download/' + encodeURIComponent(filename);

            currentPreviewFilename = filename;
            previewFileName.textContent = 'Preview: ' + filename;
            previewDownloadBtn.style.display = 'block';

            // Determine how to preview based on mimetype
            if (mimetype.startsWith('image/')) {
                // Image preview
                previewContent.innerHTML = `<img src="${url}" alt="${escapeHtml(filename)}">`;
            } else if (mimetype.startsWith('video/')) {
                // Video preview
                previewContent.innerHTML = `<video controls><source src="${url}" type="${mimetype}">Your browser does not support video playback.</video>`;
            } else if (mimetype.startsWith('audio/')) {
                // Audio preview
                previewContent.innerHTML = `<audio controls><source src="${url}" type="${mimetype}">Your browser does not support audio playback.</audio>`;
            } else if (mimetype === 'application/pdf') {
                // PDF preview using PDF.js
                previewContent.innerHTML = `<canvas id="pdfCanvas" style="max-width: 100%; height: auto;"></canvas>
                    <div style="margin-top: 10px; text-align: center;">
                        <button data-action="pdf-prev" class="btn-secondary">Previous</button>
                        <span style="margin: 0 15px;">Page <span id="pageNum"></span> / <span id="pageCount"></span></span>
                        <button data-action="pdf-next" class="btn-secondary">Next</button>
                    </div>`;
                renderPDF(url);
            } else if (mimetype.startsWith('text/') || mimetype === 'application/json' || mimetype === 'application/javascript') {
                // Text preview
                fetch(url)
                    .then(response => response.text())
                    .then(text => {
                        previewContent.innerHTML = `<pre>${escapeHtml(text)}</pre>`;
                    })
                    .catch(error => {
                        previewContent.innerHTML = '<div class="empty-state">Error loading file preview</div>';
                    });
            } else {
                // Unsupported type
                previewContent.innerHTML = `<div class="empty-state">Preview not available for this file type<br><small>${escapeHtml(mimetype)}</small></div>`;
            }

            switchTab('preview');
        }

        function downloadCurrentPreview() {
            if (currentPreviewFilename) {
                downloadFile(currentPreviewFilename);
            }
        }

        function showStatus(message, isError = false) {
            const statusDiv = document.getElementById('uploadStatus');
            statusDiv.className = 'status ' + (isError ? 'error' : 'success');
            statusDiv.textContent = message;
            setTimeout(() => {
                statusDiv.className = '';
                statusDiv.textContent = '';
            }, 5000);
        }

        function toggleAutoRefresh() {
            const checkbox = document.getElementById('autoRefresh');
            const refreshBtn = document.getElementById('refreshBtn');

            if (checkbox.checked) {
                autoRefreshInterval = setInterval(loadFiles, 1000);
                refreshBtn.style.display = 'none';
            } else {
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                    autoRefreshInterval = null;
                }
                refreshBtn.style.display = 'inline-block';
            }
        }

        // Upload form handler
        document.getElementById('uploadForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const apiKey = document.getElementById('apiKey').value;
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];

            if (!file) {
                showStatus('Please select a file', true);
                return;
            }

            const formData = new FormData();
            formData.append('file', file);

            // Show progress bar
            const progressContainer = document.getElementById('progressContainer');
            const progressBar = document.getElementById('progressBar');
            progressContainer.classList.add('active');
            progressBar.style.width = '0%';
            progressBar.textContent = '0%';

            try {
                // Use XMLHttpRequest for progress tracking
                const xhr = new XMLHttpRequest();

                xhr.upload.addEventListener('progress', (e) => {
                    if (e.lengthComputable) {
                        const percentComplete = Math.round((e.loaded / e.total) * 100);
                        progressBar.style.width = percentComplete + '%';
                        progressBar.textContent = percentComplete + '%';
                    }
                });

                xhr.addEventListener('load', () => {
                    progressContainer.classList.remove('active');

                    if (xhr.status >= 200 && xhr.status < 300) {
                        const result = JSON.parse(xhr.responseText);
                        showStatus('File uploaded successfully!');
                        fileInput.value = '';
                        loadFiles();
                        // Switch to files tab after successful upload
                        setTimeout(() => switchTab('files'), 500);
                    } else {
                        try {
                            const result = JSON.parse(xhr.responseText);
                            showStatus(result.error || 'Upload failed', true);
                        } catch {
                            showStatus('Upload failed', true);
                        }
                    }
                });

                xhr.addEventListener('error', () => {
                    progressContainer.classList.remove('active');
                    showStatus('Upload failed: Network error', true);
                });

                xhr.open('POST', '/api/upload');
                xhr.setRequestHeader('Authorization', 'Bearer ' + apiKey);
                xhr.send(formData);

            } catch (error) {
                progressContainer.classList.remove('active');
                showStatus('Upload failed: ' + error.message, true);
            }
        });

        async function checkPreviewUpdate() {
            try {
                const response = await fetch('/api/preview/current');
                const state = await response.json();

                // If server timestamp is newer than our local timestamp, update preview
                if (state.timestamp > localPreviewTimestamp && state.filename) {
                    localPreviewTimestamp = state.timestamp;

                    // Load the preview and switch to preview tab
                    previewFile(state.filename, state.mimetype);
                }
            } catch (error) {
                // Silently fail - don't spam console with errors
            }
        }

        // Pad functions
        async function loadPadContent() {
            try {
                const response = await fetch('/api/pad');
                const state = await response.json();

                // Only update if server has newer content and we're not currently typing
                if (state.timestamp > localPadTimestamp && !isUpdatingPad) {
                    const padContent = document.getElementById('padContent');
                    padContent.value = state.content;
                    localPadTimestamp = state.timestamp;
                    updatePadCharCount();
                }
            } catch (error) {
                // Silently fail
            }
        }

        async function savePadContent() {
            const padContent = document.getElementById('padContent');
            const padApiKey = document.getElementById('padApiKey');
            const padStatus = document.getElementById('padStatus');

            if (!padApiKey.value) {
                padStatus.textContent = 'API key required';
                padStatus.style.color = '#d32f2f';
                return;
            }

            try {
                padStatus.textContent = 'Saving...';
                padStatus.style.color = '#666';

                const response = await fetch('/api/pad', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + padApiKey.value,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ content: padContent.value })
                });

                const result = await response.json();

                if (response.ok) {
                    localPadTimestamp = result.timestamp;
                    padStatus.textContent = 'Saved';
                    padStatus.style.color = '#4caf50';
                    setTimeout(() => {
                        padStatus.textContent = '';
                    }, 2000);
                } else {
                    padStatus.textContent = 'Error: ' + (result.error || 'Save failed');
                    padStatus.style.color = '#d32f2f';
                }
            } catch (error) {
                padStatus.textContent = 'Network error';
                padStatus.style.color = '#d32f2f';
            }
        }

        function updatePadCharCount() {
            const padContent = document.getElementById('padContent');
            const padCharCount = document.getElementById('padCharCount');
            padCharCount.textContent = padContent.value.length.toLocaleString();
        }

        function handlePadInput() {
            isUpdatingPad = true;
            updatePadCharCount();

            // Clear existing timeout
            if (padSaveTimeout) {
                clearTimeout(padSaveTimeout);
            }

            // Set new timeout for 2 seconds
            padSaveTimeout = setTimeout(() => {
                isUpdatingPad = false;
                savePadContent();
            }, 2000);
        }

        // PDF.js rendering functions
        function renderPage(num) {
            pageRendering = true;
            pdfDoc.getPage(num).then(function(page) {
                const canvas = document.getElementById('pdfCanvas');
                const ctx = canvas.getContext('2d');
                const viewport = page.getViewport({scale: 1.5});

                canvas.height = viewport.height;
                canvas.width = viewport.width;

                const renderContext = {
                    canvasContext: ctx,
                    viewport: viewport
                };

                const renderTask = page.render(renderContext);

                renderTask.promise.then(function() {
                    pageRendering = false;
                    if (pageNumPending !== null) {
                        renderPage(pageNumPending);
                        pageNumPending = null;
                    }
                });
            });

            document.getElementById('pageNum').textContent = num;
        }

        function queueRenderPage(num) {
            if (pageRendering) {
                pageNumPending = num;
            } else {
                renderPage(num);
            }
        }

        function prevPage() {
            if (pageNum <= 1) {
                return;
            }
            pageNum--;
            queueRenderPage(pageNum);
        }

        function nextPage() {
            if (pageNum >= pdfDoc.numPages) {
                return;
            }
            pageNum++;
            queueRenderPage(pageNum);
        }

        function renderPDF(url) {
            const loadingTask = pdfjsLib.getDocument(url);
            loadingTask.promise.then(function(pdfDoc_) {
                pdfDoc = pdfDoc_;
                document.getElementById('pageCount').textContent = pdfDoc.numPages;

                // Initial/first page rendering
                pageNum = 1;
                renderPage(pageNum);
            }).catch(function(error) {
                console.error('Error loading PDF:', error);
                document.getElementById('previewContent').innerHTML =
                    '<div class="empty-state">Error loading PDF. Try downloading the file instead.</div>';
            });
        }

        // Event delegation for all button clicks
        document.addEventListener('click', (e) => {
            const target = e.target;

            // Tab switching
            if (target.classList.contains('nav-button') && target.dataset.tab) {
                switchTab(target.dataset.tab);
                return;
            }

            // File actions (preview/download)
            if (target.dataset.action === 'preview') {
                e.preventDefault();
                previewFile(target.dataset.filename, target.dataset.mimetype);
                return;
            }

            if (target.dataset.action === 'download') {
                e.preventDefault();
                downloadFile(target.dataset.filename);
                return;
            }

            // PDF navigation
            if (target.dataset.action === 'pdf-prev') {
                e.preventDefault();
                prevPage();
                return;
            }

            if (target.dataset.action === 'pdf-next') {
                e.preventDefault();
                nextPage();
                return;
            }

            // Preview download button
            if (target.id === 'previewDownloadBtn') {
                e.preventDefault();
                downloadCurrentPreview();
                return;
            }

            // Refresh button
            if (target.id === 'refreshBtn') {
                e.preventDefault();
                loadFiles();
                return;
            }
        });

        // Auto-refresh checkbox
        document.getElementById('autoRefresh').addEventListener('change', toggleAutoRefresh);

        // Pad textarea input handler
        document.getElementById('padContent').addEventListener('input', handlePadInput);

        // Load files on page load
        loadFiles();
        // Start auto-refresh by default
        toggleAutoRefresh();
        // Start preview polling
        setInterval(checkPreviewUpdate, 1000);
        // Load pad content and start polling
        loadPadContent();
        setInterval(loadPadContent, 2000);
    </script>
</body>
</html>"""
        self._set_headers()
        self.wfile.write(html.encode())

    def _serve_file_list(self):
        """Serve JSON list of available files"""
        with FILES_LOCK:
            files = [
                {
                    "name": name,
                    "size": len(content),
                    "mimetype": mimetype,
                    "uploaded": upload_time,
                }
                for name, (content, mimetype, upload_time) in FILES.items()
            ]

        self._set_headers(content_type="application/json")
        self.wfile.write(json.dumps(files).encode())

    def _serve_file(self, filename: str):
        """Serve a file for download or inline preview"""
        with FILES_LOCK:
            if filename not in FILES:
                self._set_headers(HTTPStatus.NOT_FOUND)
                self.wfile.write(b"File not found")
                return

            content, mimetype, _ = FILES[filename]

        # Send headers manually (don't use _set_headers because we need additional headers)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetype)
        # Use inline for preview support (PDFs, images, etc.), but keep filename for downloads
        self.send_header("Content-Disposition", f'inline; filename="{filename}"')
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def _serve_preview_state(self):
        """Serve current preview state"""
        with PREVIEW_LOCK:
            state = PREVIEW_STATE.copy()

        # If there's a filename, get its mimetype
        if state["filename"]:
            with FILES_LOCK:
                if state["filename"] in FILES:
                    _, mimetype, _ = FILES[state["filename"]]
                    state["mimetype"] = mimetype
                else:
                    # File was deleted, clear preview
                    state["filename"] = None
                    state["mimetype"] = None

        self._set_headers(content_type="application/json")
        self.wfile.write(json.dumps(state).encode())

    def _handle_preview_set(self):
        """Handle setting the preview state"""
        if not self._check_api_key():
            self._set_headers(HTTPStatus.UNAUTHORIZED, "application/json")
            self.wfile.write(json.dumps({"error": "Invalid API key"}).encode())
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body.decode())
            filename = data.get("filename")

            if not filename:
                self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
                self.wfile.write(json.dumps({"error": "filename is required"}).encode())
                return

            # Check if file exists
            with FILES_LOCK:
                if filename not in FILES:
                    self._set_headers(HTTPStatus.NOT_FOUND, "application/json")
                    self.wfile.write(json.dumps({"error": "File not found"}).encode())
                    return

            # Update preview state atomically
            with PREVIEW_LOCK:
                PREVIEW_STATE["filename"] = filename
                PREVIEW_STATE["timestamp"] += 1

            self._set_headers(HTTPStatus.OK, "application/json")
            self.wfile.write(
                json.dumps(
                    {
                        "success": True,
                        "filename": filename,
                        "timestamp": PREVIEW_STATE["timestamp"],
                    }
                ).encode()
            )

        except (json.JSONDecodeError, KeyError):
            self._set_headers(HTTPStatus.BAD_REQUEST, "application/json")
            self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())

    def _serve_pad_content(self):
        """Serve current pad content"""
        with PAD_LOCK:
            state = PAD_STATE.copy()

        self._set_headers(content_type="application/json")
        self.wfile.write(json.dumps(state).encode())

    def _handle_pad_update(self):
        """Handle updating the pad content"""
        if not self._check_api_key():
            self._set_headers(HTTPStatus.UNAUTHORIZED, "application/json")
            self.wfile.write(json.dumps({"error": "Invalid API key"}).encode())
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

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
            with PAD_LOCK:
                PAD_STATE["content"] = content
                PAD_STATE["timestamp"] += 1
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

    def log_message(self, format, *args):
        """Override to customize logging"""
        print(f"[{self.log_date_time_string()}] {format % args}")


def run_server(port: int, api_key: str):
    """Run the file sharing server"""
    global API_KEY
    API_KEY = api_key

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

    logger.debug("Server bound successfully")
    logger.info(f"File sharing server running on http://0.0.0.0:{port}")
    logger.info(f"API Key: {api_key}")

    print(f"🚀 File sharing server running on http://0.0.0.0:{port}")
    print(f"🔑 API Key: {api_key}")
    print(f"📝 Open http://localhost:{port} in your browser")
    print("Press Ctrl+C to stop\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped")
    finally:
        httpd.server_close()


def upload_file(server_url: str, file_path: str, api_key: str, set_preview: bool = False):
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
        "Authorization": f"Bearer {api_key}",
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
                return set_preview_func(server_url, result["filename"], api_key)

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


def set_preview_func(server_url: str, filename: str, api_key: str):
    """Set the current preview for all clients"""
    url = f"{server_url.rstrip('/')}/api/preview/set"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    data = json.dumps({"filename": filename}).encode()

    try:
        print(f"📺 Setting preview to: {filename}")
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


def list_files(server_url: str):
    """List all available files on the server"""
    url = f"{server_url.rstrip('/')}/api/files"

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as response:
            files = json.loads(response.read().decode())

            if not files:
                print("📋 No files available")
                return True

            print(f"📋 Available files ({len(files)}):\n")
            for file in files:
                size_str = format_file_size(file["size"])
                print(f"  • {file['name']}")
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


def get_pad(server_url: str):
    """Get the current pad content from the server"""
    url = f"{server_url.rstrip('/')}/api/pad"

    try:
        req = urllib.request.Request(url)
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


def set_pad(server_url: str, content: str, api_key: str):
    """Set the pad content on the server"""
    url = f"{server_url.rstrip('/')}/api/pad"
    headers = {
        "Authorization": f"Bearer {api_key}",
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


def main():
    parser = argparse.ArgumentParser(description="Simple file sharing server and client")
    subparsers = parser.add_subparsers(dest="mode", help="Available commands")
    # Server mode
    server_parser = subparsers.add_parser("server", help="Run in server mode")
    server_parser.add_argument("--port", type=int, help="Port to listen on (default: 8080 or from config)")
    server_parser.add_argument("--api-key", help="API key for uploads (required, can be from config)")
    server_parser.add_argument("--server", help="Named server from config file")
    server_parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    # Helper to add common server selection args to client subparsers
    def add_server_args(subparser, needs_api_key=True):
        subparser.add_argument("--server", help="Named server from config file")
        subparser.add_argument("--server-url", help="Explicit server URL (e.g., http://localhost:8080)")
        if needs_api_key:
            subparser.add_argument("--api-key", help="API key (overrides config)")

    # Upload mode
    upload_parser = subparsers.add_parser("upload", help="Upload a file to the server")
    upload_parser.add_argument("file_path", help="Path to file to upload")
    upload_parser.add_argument(
        "--set-preview",
        action="store_true",
        help="Automatically set this file as preview for all clients after upload",
    )
    add_server_args(upload_parser, needs_api_key=True)
    # List mode
    list_parser = subparsers.add_parser("list", help="List all available files")
    add_server_args(list_parser, needs_api_key=False)
    # Set preview mode
    preview_parser = subparsers.add_parser("set-preview", help="Set the current preview for all clients")
    preview_parser.add_argument("filename", help="Filename to preview")
    add_server_args(preview_parser, needs_api_key=True)
    # Get pad mode
    get_pad_parser = subparsers.add_parser("get-pad", help="Get the current pad content")
    add_server_args(get_pad_parser, needs_api_key=False)
    # Set pad mode
    set_pad_parser = subparsers.add_parser("set-pad", help="Set the pad content")
    set_pad_parser.add_argument("content", help="Content to set in the pad")
    add_server_args(set_pad_parser, needs_api_key=True)
    # Parse args
    args = parser.parse_args()
    if not args.mode:
        parser.print_help()
        sys.exit(1)

    if args.mode == "server":
        # Configure logging
        log_level = logging.DEBUG if args.debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format="[%(asctime)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        port, api_key = resolve_server_config(args)
        run_server(port, api_key)
    elif args.mode == "upload":
        server_url, api_key = resolve_server(args)
        if not api_key:
            print("Error: API key required for upload.", file=sys.stderr)
            print("Provide --api-key or configure api-key in config file.", file=sys.stderr)
            sys.exit(1)
        success = upload_file(
            server_url,
            args.file_path,
            api_key,
            set_preview=args.set_preview,
        )
        sys.exit(0 if success else 1)
    elif args.mode == "list":
        server_url, _ = resolve_server(args)
        success = list_files(server_url)
        sys.exit(0 if success else 1)
    elif args.mode == "set-preview":
        server_url, api_key = resolve_server(args)
        if not api_key:
            print("Error: API key required for set-preview.", file=sys.stderr)
            print("Provide --api-key or configure api-key in config file.", file=sys.stderr)
            sys.exit(1)
        success = set_preview_func(server_url, args.filename, api_key)
        sys.exit(0 if success else 1)
    elif args.mode == "get-pad":
        server_url, _ = resolve_server(args)
        success = get_pad(server_url)
        sys.exit(0 if success else 1)
    elif args.mode == "set-pad":
        server_url, api_key = resolve_server(args)
        if not api_key:
            print("Error: API key required for set-pad.", file=sys.stderr)
            print("Provide --api-key or configure api-key in config file.", file=sys.stderr)
            sys.exit(1)
        success = set_pad(server_url, args.content, api_key)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    # Force UTF-8 encoding on Windows for emoji support
    if sys.platform == "win32":
        import codecs

        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
        sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())
    main()
