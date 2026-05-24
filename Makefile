.PHONY: help test test-dev test-built test-all test-browser test-base64 format lint check clean run build verify-build docker-build docker-secret

# Default target
help:
	@echo "Available targets:"
	@echo "  make test         - Run tests on dev version (default)"
	@echo "  make test-dev     - Run tests on dev version (src/companion.py)"
	@echo "  make test-built   - Run tests on built version (companion.py)"
	@echo "  make test-all     - Run tests on both dev and built versions"
	@echo "  make test-browser - Run browser E2E tests with Playwright"
	@echo "  make test-base64  - Validate base64 format of embedded PDF.js"
	@echo "  make format       - Format code with ruff"
	@echo "  make lint         - Lint code with ruff"
	@echo "  make check        - Run format, lint, and tests"
	@echo "  make build        - Build companion.py with inlined PDF.js"
	@echo "  make verify-build - Verify that companion.py matches src/companion.py"
	@echo "  make run          - Start the server (default port 8080)"
	@echo "  make docker-build - Rebuild companion.py and build the Docker image (companion:dev)"
	@echo "  make docker-secret- Print a fresh hex secret for COMPANION_BOOTSTRAP_ADMIN"
	@echo "  make clean        - Remove Python cache files"

# Run tests on dev version (default)
test: test-dev

# Run tests on dev version
test-dev:
	@echo "🧪 Running tests on DEV version..."
	TEST_VERSION=dev python3 -m unittest discover -s tests -p "test_*.py"

# Run tests on built version
test-built:
	@echo "🧪 Running tests on BUILT version..."
	TEST_VERSION=built python3 -m unittest discover -s tests -p "test_*.py"

# Run tests on both versions
test-all: test-dev test-built
	@echo "✅ All tests passed on both versions!"

# Run browser E2E tests with Playwright (using uvx)
test-browser:
	@echo "🌐 Running browser E2E tests..."
	@echo "📦 Installing Playwright browsers (first time only)..."
	uvx --from playwright --with playwright playwright install chromium 2>/dev/null || true
	uvx --from playwright --with playwright python tests/e2e_test_browser.py

# Validate base64 format of embedded PDF.js libraries
test-base64:
	@python3 -c "import sys; \
from pathlib import Path; \
print('🔍 Validating base64 format of embedded PDF.js...'); \
path = Path('companion.py'); \
not path.exists() and (print('❌ companion.py not found. Run make build first.') or sys.exit(1)); \
lines = path.read_text().split('\n'); \
base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='); \
[(print(f'📋 Checking {var} format...'), \
  (count := len([line for line in lines if line.startswith(var)])), \
  (print(f'❌ Found {count} lines starting with {var}, expected exactly 1') or sys.exit(1)) if count != 1 else None, \
  (matching := [line for line in lines if line.startswith(var)][0]), \
  (prefix := f'{var} = base64.b64decode(\"'), \
  (print(f'❌ {var} line must start with {repr(prefix)}') or sys.exit(1)) if not matching.startswith(prefix) else None, \
  (print(f'❌ {var} line must end with \")\"') or sys.exit(1)) if not matching.endswith('\")') else None, \
  (content := matching[len(prefix):-2]), \
  (print(f'❌ {var} contains invalid base64 characters') or print(f'   Got: {content[:80]}...') or sys.exit(1)) if not all(c in base64_chars for c in content) else None, \
  print(f'✅ {var} format valid')) \
for var in ['_PDFJS_LIB', '_PDFJS_WORKER']]; \
print('🎉 All base64 format checks passed!')"

# Format code with ruff
format:
	@echo "Formatting code..."
	ruff format src/companion.py tests/ build.py

# Lint code with ruff
lint:
	@echo "Linting code..."
	ruff check src/companion.py tests/ build.py

# Run all checks (format, lint, test)
check: format lint test
	@echo "✅ All checks passed!"

# Start the server (development version from src/)
run:
	python3 src/companion.py server

# Build companion.py with inlined PDF.js
build:
	@echo "Building companion with inlined PDF.js..."
	python3 build.py

# Verify that companion.py matches the current source
verify-build:
	@echo "🔍 Verifying built file integrity..."
	@if [ ! -f companion.py ]; then \
		echo "❌ companion.py not found. Run 'make build' first."; \
		exit 1; \
	fi; \
	echo "📊 Computing SHA256 of current companion.py..."; \
	ORIGINAL_HASH=$$(sha256sum companion.py | cut -d' ' -f1); \
	echo "   Hash: $$ORIGINAL_HASH"; \
	echo "🔨 Rebuilding from src/companion.py..."; \
	python3 build.py > /dev/null 2>&1; \
	echo "📊 Computing SHA256 of rebuilt companion.py..."; \
	NEW_HASH=$$(sha256sum companion.py | cut -d' ' -f1); \
	echo "   Hash: $$NEW_HASH"; \
	if [ "$$ORIGINAL_HASH" = "$$NEW_HASH" ]; then \
		echo "✅ Build verification passed! companion.py is up to date."; \
	else \
		echo "❌ Build verification failed!"; \
		echo "   The built file does not match the source."; \
		echo "   Run 'make build' to rebuild."; \
		exit 1; \
	fi

# Build the Docker image (always against a freshly-built companion.py)
docker-build: build
	docker build -t companion:latest .

# Print a fresh hex secret suitable for COMPANION_BOOTSTRAP_ADMIN=<id>:<secret>
docker-secret:
	@python3 -c 'import secrets; print(secrets.token_hex(32))'

# Clean up Python cache files and built file
clean:
	@echo "Cleaning up..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	rm -f companion.py
	@echo "✅ Cleanup complete!"
