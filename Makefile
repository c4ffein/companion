.PHONY: help test format lint check clean run

# Default target
help:
	@echo "Available targets:"
	@echo "  make test      - Run all tests"
	@echo "  make format    - Format code with ruff"
	@echo "  make lint      - Lint code with ruff"
	@echo "  make check     - Run format, lint, and tests"
	@echo "  make run       - Start the server (default port 8080)"
	@echo "  make clean     - Remove Python cache files"

# Run tests
test:
	@echo "Running tests..."
	python3 test_companion.py

# Format code with ruff
format:
	@echo "Formatting code..."
	ruff format companion.py test_companion.py

# Lint code with ruff
lint:
	@echo "Linting code..."
	ruff check companion.py test_companion.py

# Run all checks (format, lint, test)
check: format lint test
	@echo "✅ All checks passed!"

# Start the server
run:
	python3 companion.py server

# Clean up Python cache files
clean:
	@echo "Cleaning up..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	@echo "✅ Cleanup complete!"
