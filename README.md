# Companion

A minimal, single-file Python tool for ephemeral file sharing on local networks. Share files seamlessly between your devices - your phone, TV, laptop, and more.

## Features

- **Single file**: Just `companion.py` - easy to audit and deploy, works as both server and client
- **Zero dependencies**: Python 3.7+ standard library only
- **In-memory storage**: Ephemeral by design - files disappear on restart
- **API key auth**: Simple Bearer token authentication for allowing uploads
- **Web interface**: Clean, responsive UI with tab navigation and auto-refresh
- **File preview**: Preview images, videos, audio, PDFs, and text files in-browser
- **Presentation mode**: Control what all clients see from the CLI
- **CLI client**: Upload files, list files, and control previews from command line
- **Tested**: Comprehensive E2E test suite included

## Quick Start

### Start Server

```bash
# Default: http://localhost:8080
python companion.py server --api-key mySecretKey123

# Custom port and API key
python companion.py server --port 9000 --api-key mySecretKey123
```

Open http://localhost:8080 in your browser to see the web interface.

### Upload Files

**Via Web Interface:**
1. Open the server URL in your browser
2. Enter your API key
3. Select a file and click Upload

**Via Command Line:**
```bash
# Upload a file
python companion.py upload http://localhost:8080 myfile.pdf --api-key mySecretKey123

# Upload and automatically set as preview for all clients
python companion.py upload http://localhost:8080 slides.pdf --api-key mySecretKey123 --set-preview
```

### List Files

```bash
# List all available files
python companion.py list http://localhost:8080
```

### Control Presentation Mode

```bash
# Set what all connected clients see
python companion.py set-preview http://localhost:8080 slides.pdf --api-key mySecretKey123
```

## Use Cases

- **Local network file transfer**: Share files between devices on the same network
- **Quick demos**: Temporarily share files during presentations
- **Development**: Test file uploads/downloads in your application
- **Air-gapped environments**: No internet required
- **Privacy-focused**: Files never leave your network

## Installation

No installation needed! Just download `companion.py`:

```bash
curl -LO https://raw.githubusercontent.com/c4ffein/companion/master/companion.py
chmod +x companion.py
```

Or clone the repository:

```bash
git clone https://github.com/c4ffein/companion.git
cd companion
```

## Development

### Running Tests

```bash
make test  # Run all tests
python test_companion.py  # Or directly with Python
```

### Code Quality

```bash
make format  # Format code
make lint    # Lint code
make check   # Run all checks
```

## Security Notes

**⚠️ Currently, this tool is designed for temporary, trusted, local network use only.**

- Files are stored in memory without encryption (E2E encryption planned for future)
- Uses simple Bearer token authentication
- No HTTPS support (use a reverse proxy if needed)
- No rate limiting or DOS protection
- Not intended for production or internet-facing deployments
- Only use on trusted networks with trusted users

## API Reference

### Endpoints

**GET /**
- Returns the web interface HTML

**GET /api/files**
- Returns JSON array of uploaded files
- Response: `[{"name": "file.txt", "size": 1234, "mimetype": "text/plain", "uploaded": "2025-01-01T12:00:00"}]`

**POST /api/upload**
- Upload a file (multipart/form-data)
- Requires `Authorization: Bearer <api-key>` header
- Returns: `{"success": true, "filename": "file.txt", "size": 1234}`

**GET /download/<filename>**
- Download or preview a file
- Returns file content with appropriate Content-Type and inline disposition

**GET /api/preview/current**
- Get current preview state for all clients
- Response: `{"filename": "file.txt", "timestamp": 1, "mimetype": "application/pdf"}`

**POST /api/preview/set**
- Set the current preview for all clients (presentation mode)
- Requires `Authorization: Bearer <api-key>` header
- Body: `{"filename": "file.txt"}`
- Returns: `{"success": true, "filename": "file.txt", "timestamp": 1}`

## Roadmap

- [ ] PDF.js integration for better mobile Safari support (with build tool to inline assets)
- [ ] End-to-end encryption
- [ ] File deletion API
- [ ] Password-protected downloads
- [ ] Optional persistence (save to disk)
- [ ] WebSocket support for real-time updates
- [ ] Multi-file upload support
- [ ] Optional FastAPI version for production use

## License

MIT License - Copyright (c) 2025 c4ffein

See [LICENSE](LICENSE) file for details.

## Acknowledgments

Claude Code again, want to see how far I can go building all the tools I need from scratch, with their help 👀
