# pRoxy Development Makefile

.PHONY: help install test test-fast test-coverage test-security test-api test-rules test-proxy clean lint format

# Default target
help:
	@echo "🔧 pRoxy Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  install          Install dependencies in virtual environment"
	@echo "  install-dev      Install development dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  test             Run all tests"
	@echo "  test-fast        Run fast tests only (skip slow ones)"
	@echo "  test-coverage    Run tests with coverage report"
	@echo "  test-security    Run security tests only"
	@echo "  test-api         Run API tests only"
	@echo "  test-rules       Run rule validation tests only"
	@echo "  test-proxy       Run proxy core tests only"
	@echo "  test-parallel    Run tests in parallel"
	@echo ""
	@echo "Quality:"
	@echo "  lint             Run linting (flake8, mypy)"
	@echo "  format           Format code (black, isort)"
	@echo "  clean            Clean up temporary files"
	@echo ""
	@echo "Development:"
	@echo "  run              Start pRoxy server"
	@echo "  run-debug        Start pRoxy with debug logging"

# Setup commands
install:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt

install-dev: install
	.venv/bin/pip install black isort flake8 mypy

# Testing commands
test:
	@python run_tests.py --type all

test-fast:
	@python run_tests.py --type fast

test-coverage:
	@python run_tests.py --type all --coverage

test-security:
	@python run_tests.py --type security --verbose

test-api:
	@python run_tests.py --type api --verbose

test-rules:
	@python run_tests.py --type rules --verbose

test-proxy:
	@python run_tests.py --type proxy --verbose

test-parallel:
	@python run_tests.py --type all --parallel 4

# Quality commands
lint:
	@echo "🔍 Running linters..."
	@.venv/bin/flake8 api/ state/ pRoxy/ --max-line-length=100 --ignore=E203,W503 || true
	@.venv/bin/mypy api/ state/ --ignore-missing-imports || true

format:
	@echo "✨ Formatting code..."
	@.venv/bin/black api/ state/ pRoxy/ --line-length=100
	@.venv/bin/isort api/ state/ pRoxy/ --profile black

clean:
	@echo "🧹 Cleaning up..."
	@rm -rf htmlcov/
	@rm -rf .coverage
	@rm -rf .pytest_cache/
	@rm -rf __pycache__/
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name ".DS_Store" -delete

# Development commands
run:
	@echo "🚀 Starting pRoxy..."
	@source .venv/bin/activate && python main.py

run-debug:
	@echo "🐛 Starting pRoxy with debug logging..."
	@export DEBUG=1 && source .venv/bin/activate && python main.py

# CI/CD helpers
ci-test: install
	@echo "🤖 Running CI test suite..."
	@python run_tests.py --type all --coverage --parallel 2

ci-security: install
	@echo "🛡️ Running security test suite..."
	@python run_tests.py --type security --verbose

# Documentation
docs:
	@echo "📚 Generating documentation..."
	@echo "API Documentation: http://localhost:8081/docs (when server is running)"
	@echo "Test Coverage: htmlcov/index.html (after running test-coverage)"

# Docker helpers (if using Docker)
docker-build:
	@echo "🐳 Building Docker image..."
	@docker build -t proxy:latest .

docker-test:
	@echo "🐳 Running tests in Docker..."
	@docker run --rm -v $(PWD):/app -w /app proxy:latest make ci-test