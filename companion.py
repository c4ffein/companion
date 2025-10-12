#!/usr/bin/env python3
"""
Companion - Simple file sharing server/client
Usage:
    Server mode: python companion.py server [--port PORT] [--api-key KEY]
    Client mode: python companion.py client <server_url> <file_path> [--api-key KEY]
"""

import argparse
import http.server
import io
import json
import mimetypes
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from http import HTTPStatus
from threading import Lock
from typing import Dict, Tuple

# In-memory file storage: {filename: (content_bytes, mimetype, upload_time)}
FILES: Dict[str, Tuple[bytes, str, str]] = {}
FILES_LOCK = Lock()
API_KEY = None  # Must be set via command line


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
        elif path.startswith("/download/"):
            filename = urllib.parse.unquote(path[10:])
            self._serve_file(filename)
        else:
            self._set_headers(HTTPStatus.NOT_FOUND)
            self.wfile.write(b"Not found")

    def do_POST(self):
        """Handle POST requests (file uploads)"""
        if self.path == "/api/upload":
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
                self.wfile.write(
                    json.dumps({"error": "Expected multipart/form-data"}).encode()
                )
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
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; background: #f5f5f5; }
        h1 { color: #333; }
        .upload-form { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .file-list { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
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
    </style>
</head>
<body>
    <h1>📁 Companion</h1>

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
        <div id="uploadStatus"></div>
    </div>

    <div class="file-list">
        <h2>Available Files</h2>
        <div id="fileList">
            <div class="empty-state">Loading...</div>
        </div>
        <div style="margin-top: 15px;">
            <button onclick="loadFiles()" class="btn-secondary">Refresh</button>
            <label style="margin-left: 15px;">
                <input type="checkbox" id="autoRefresh" onchange="toggleAutoRefresh()">
                Auto-refresh (5s)
            </label>
        </div>
    </div>

    <script>
        let autoRefreshInterval = null;

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
                            <button onclick="downloadFile('${escapeHtml(file.name)}')">Download</button>
                        </div>
                    </div>
                `).join('');
            } catch (error) {
                document.getElementById('fileList').innerHTML =
                    '<div class="empty-state">Error loading files</div>';
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function downloadFile(filename) {
            window.location.href = '/download/' + encodeURIComponent(filename);
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

            try {
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + apiKey
                    },
                    body: formData
                });

                const result = await response.json();

                if (response.ok) {
                    showStatus('File uploaded successfully!');
                    fileInput.value = '';
                    loadFiles();
                } else {
                    showStatus(result.error || 'Upload failed', true);
                }
            } catch (error) {
                showStatus('Upload failed: ' + error.message, true);
            }
        });

        function toggleAutoRefresh() {
            const checkbox = document.getElementById('autoRefresh');
            if (checkbox.checked) {
                autoRefreshInterval = setInterval(loadFiles, 5000);
            } else {
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                    autoRefreshInterval = null;
                }
            }
        }

        // Load files on page load
        loadFiles();
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
        """Serve a file for download"""
        with FILES_LOCK:
            if filename not in FILES:
                self._set_headers(HTTPStatus.NOT_FOUND)
                self.wfile.write(b"File not found")
                return

            content, mimetype, _ = FILES[filename]

        # Send headers manually (don't use _set_headers because we need additional headers)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetype)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        """Override to customize logging"""
        print(f"[{self.log_date_time_string()}] {format % args}")


def run_server(port: int, api_key: str):
    """Run the file sharing server"""
    global API_KEY
    API_KEY = api_key

    server_address = ("", port)
    httpd = http.server.HTTPServer(server_address, FileShareHandler)

    print(f"🚀 File sharing server running on http://0.0.0.0:{port}")
    print(f"🔑 API Key: {api_key}")
    print(f"📝 Open http://localhost:{port} in your browser")
    print("Press Ctrl+C to stop\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped")
        httpd.shutdown()


def upload_file(server_url: str, file_path: str, api_key: str):
    """Upload a file to the server (client mode)"""
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
    body.write(
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    )
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


def main():
    parser = argparse.ArgumentParser(description="Simple file sharing server/client")
    subparsers = parser.add_subparsers(dest="mode", help="Mode: server or client")

    # Server mode
    server_parser = subparsers.add_parser("server", help="Run in server mode")
    server_parser.add_argument(
        "--port", type=int, default=8080, help="Port to listen on (default: 8080)"
    )
    server_parser.add_argument(
        "--api-key", required=True, help="API key for uploads (required)"
    )

    # Client mode
    client_parser = subparsers.add_parser(
        "client", help="Run in client mode (upload file)"
    )
    client_parser.add_argument(
        "server_url", help="Server URL (e.g., http://localhost:8080)"
    )
    client_parser.add_argument("file_path", help="Path to file to upload")
    client_parser.add_argument(
        "--api-key", required=True, help="API key for upload (required)"
    )

    args = parser.parse_args()

    if not args.mode:
        parser.print_help()
        sys.exit(1)

    if args.mode == "server":
        run_server(args.port, args.api_key)
    elif args.mode == "client":
        success = upload_file(args.server_url, args.file_path, args.api_key)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
