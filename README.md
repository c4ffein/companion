# Companion

A minimal, single-file Python tool for ephemeral file sharing on local networks. Share files seamlessly between your devices - your phone, TV, laptop, and more.

## Features

- **Single file**: Just `companion.py` - easy to audit and deploy, works as both server and client
- **Zero dependencies**: Python 3.7+ standard library only
- **In-memory storage**: Ephemeral by design - files disappear on restart
- **Per-client auth**: Bearer token authentication with per-client salted SHA-256 hashing
- **Web interface**: Clean, responsive UI with tab navigation and auto-refresh
- **File preview**: Preview images, videos, audio, PDFs, and text files in-browser
- **Presentation mode**: Control what all clients see from the CLI
- **Shared pad**: Real-time shared text pad between all clients
- **CLI client**: Upload files, list files, and control previews from command line
- **Rate limiting**: Per-IP sliding window rate limiting on write endpoints
- **Storage limits**: Per-client storage caps (4GB default)
- **Tested**: Comprehensive E2E test suite included

## Quick Start

### Start Server

```bash
# First-time setup: creates config with admin credentials
python companion.py server-setup --url http://localhost:8080

# Start the server
python companion.py server

# Custom port
python companion.py server --port 9000
```

Open http://localhost:8080 in your browser to see the web interface.

### Add Users

```bash
# Add a user to the server (generates credentials)
python companion.py server-add-user

# Add an admin user
python companion.py server-add-user --admin
```

### Upload Files

**Via Web Interface:**
1. Open the server URL in your browser
2. Enter your client ID and secret in the Settings tab
3. Select a file and click Upload

**Via Command Line:**
```bash
# Save connection credentials locally
python companion.py connect --url http://localhost:8080 --client-id ID --client-secret SECRET

# Upload a file
python companion.py upload myfile.pdf

# Upload and automatically set as preview for all clients
python companion.py upload slides.pdf --set-preview
```

### List Files

```bash
python companion.py list
```

### Control Presentation Mode

```bash
# Set what all connected clients see
python companion.py set-preview slides.pdf
```

## Use Cases

- **Local network file transfer**: Share files between devices on the same network
- **Quick demos**: Temporarily share files during presentations
- **Development**: Test file uploads/downloads in your application
- **Air-gapped environments**: No internet required
- **Privacy-focused**: Files never leave your network

## Installation

No installation needed! Just download the built `companion.py` (includes inlined PDF.js for offline use):

```bash
curl -LO https://raw.githubusercontent.com/c4ffein/companion/master/companion.py
chmod +x companion.py
```

Or clone the repository for development:

```bash
git clone https://github.com/c4ffein/companion.git
cd companion
# Use src/companion.py for development (requires internet for PDF preview)
# Or run 'make build' to create companion.py at root with inlined PDF.js
```

## Development

### Running Tests

```bash
make test       # Run all tests (dev version)
make test-built # Run all tests (built version)
make test-all   # Run both
```

### Code Quality

```bash
make format  # Format code
make lint    # Lint code
make check   # Run all checks
```

### Project Structure

```
companion/
├── src/
│   └── companion.py       # Development version (uses CDN for PDF.js)
├── tests/
│   ├── test_companion.py  # Main E2E test suite
│   ├── test_auth_required.py
│   ├── test_config_lock.py
│   ├── test_pad.py
│   ├── test_rate_limit.py
│   ├── test_setup_commands.py
│   └── test_storage_limit.py
├── js_deps/               # JavaScript dependencies cache
│   ├── pdf.min.mjs        # PDF.js library
│   └── pdf.worker.min.mjs # PDF.js worker
├── companion.py           # Built version (generated, includes inlined PDF.js)
├── build.py               # Build tool to create companion.py from src/
└── Makefile               # Build commands
```

### Building for Distribution

The repository uses a two-version approach:

- **Development**: `src/companion.py` uses CDN-hosted PDF.js (requires internet for PDF preview)
- **Distribution**: `companion.py` at root includes inlined PDF.js (~1.5MB, works offline)

To build the distribution version:

```bash
make build  # Creates companion.py at root with inlined PDF.js
```

The build process:
1. Reads `src/companion.py`
2. Fetches PDF.js (~400KB) and PDF.js Worker (~1MB) from CDN (or uses cached versions in `js_deps/`)
3. Base64-encodes and inlines them into the Python source as string constants
4. Adds a marker to the docstring indicating it's a built version
5. Writes `companion.py` to the root directory

**Notes:**
- **⚠️ Committing Generated Files**: Both `companion.py` (built file) and `js_deps/` (dependencies) are committed to git. This is intentionally against typical best practices, but is an acceptable tradeoff for this project
- The built file is automatically generated - don't edit it directly, edit `src/companion.py` instead
- JavaScript dependencies are cached in `js_deps/` for faster rebuilds
- First build downloads from CDN, subsequent builds use the cache
- To force re-download, delete files in `js_deps/`

## Security Notes

**⚠️ Currently, this tool is designed for temporary, trusted, local network use only.**

- Files are stored in memory without encryption (E2E encryption planned for future)
- Per-client Bearer token authentication with salted SHA-256 hashing (timing-attack safe)
- Per-IP rate limiting on write endpoints (30 requests/60s sliding window)
- Per-client storage caps (4GB default)
- No HTTPS support (use a reverse proxy if needed)
- Not intended for production or internet-facing deployments
- Only use on trusted networks with trusted users

## API Reference

All authenticated endpoints require `Authorization: Bearer <client_id>:<client_secret>`.

### Endpoints

**GET /** - Web interface HTML

**GET /api/files** - List uploaded files (auth required)

**POST /api/upload** - Upload a file via multipart/form-data (auth required)

**GET /download/\<file_id\>** - Download or preview a file (auth required)

**GET /api/preview/current** - Get current shared preview state (auth required)

**POST /api/preview/set** - Set the shared preview for all clients (auth required)

**GET /api/pad** - Get shared pad content (auth required)

**POST /api/pad** - Update shared pad content (auth required, 10MB limit)

**POST /api/clients/register** - Register a new client (admin required)

**GET /api/clients** - List registered clients (admin required)

**DELETE /api/clients/\<id\>** - Delete a client (admin required)

## Roadmap

- [x] PDF.js integration for better mobile Safari support (with build tool to inline assets)
- [ ] End-to-end encryption
- [ ] File deletion API
- [ ] Password-protected downloads
- [ ] Optional persistence (save to disk)
- [ ] WebSocket support for real-time updates
- [ ] Multi-file upload support
- [ ] Optional FastAPI version for production use

## License

**Companion is licensed under the MIT License - Copyright (c) 2025 c4ffein**

The built distribution file (`companion.py`) includes:
- **Companion code**: MIT License (Copyright (c) 2025 c4ffein)
- **Embedded PDF.js library**: Apache License 2.0 (Copyright Mozilla Foundation)

Both licenses are permissive and allow commercial and non-commercial use. The combination is fully legal and compliant.

**For users**: You can use, modify, and distribute Companion (including the built version with embedded PDF.js) under the terms of the MIT License. The embedded PDF.js library is Apache 2.0 licensed, which is compatible with MIT.

**For developers**: See [LICENSE](LICENSE) for the full MIT license text. See [js_deps/LICENSE](js_deps/LICENSE) for PDF.js license details.

## Acknowledgments

Claude Code again, want to see how far I can go building all the tools I need from scratch, with their help 👀
