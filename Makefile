.PHONY: install dev test coverage lint clean

# Install package in editable mode with dev dependencies
install:
	pip install -e ".[dev]"

# Alias
dev: install

# Run test suite
test:
	python -m pytest tests/ -v

# Run tests with coverage report
coverage:
	python -m pytest tests/ --cov=securegitx --cov-report=term-missing --cov-fail-under=80

# Validate rule bundle
rules:
	securegitx rules validate
	securegitx rules list

# Remove build artifacts and caches
clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -name "*.pyc" -delete
	find . -name ".coverage" -delete
	find . -name "coverage.xml" -delete