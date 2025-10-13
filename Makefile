.PHONY: help test format lint check clean run build verify-build

# Default target
help:
	@echo "Available targets:"
	@echo "  make test         - Run all tests"
	@echo "  make format       - Format code with ruff"
	@echo "  make lint         - Lint code with ruff"
	@echo "  make check        - Run format, lint, and tests"
	@echo "  make build        - Build companion.py with inlined PDF.js"
	@echo "  make verify-build - Verify that companion.py matches src/companion.py"
	@echo "  make run          - Start the server (default port 8080)"
	@echo "  make clean        - Remove Python cache files"

# Run tests
test:
	@echo "Running tests..."
	python3 test_companion.py

# Format code with ruff
format:
	@echo "Formatting code..."
	ruff format src/companion.py test_companion.py build.py

# Lint code with ruff
lint:
	@echo "Linting code..."
	ruff check src/companion.py test_companion.py build.py

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

# Clean up Python cache files and built file
clean:
	@echo "Cleaning up..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	rm -f companion.py
	@echo "✅ Cleanup complete!"
