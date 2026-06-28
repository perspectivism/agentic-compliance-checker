.PHONY: help venv format test-local lint-local build test test-all ingest assess eval shell lint clean

IMAGE  := agentic-compliance-checker:latest
PYTHON ?= .venv/bin/python
REPO   ?=

help:
	@echo "Agentic compliance checker — make targets:"
	@echo "  Local (venv):"
	@echo "    make venv                Create .venv and install dev deps (Python 3.12+)"
	@echo "    make format              Auto-format + autofix with ruff"
	@echo "    make test-local          Fast test suite in the venv (pytest -m 'not agent')"
	@echo "    make lint-local          Lint + format-check with ruff (no changes)"
	@echo "  Docker:"
	@echo "    make build               Build the image"
	@echo "    make test                Fast test suite  (pytest -m 'not agent')"
	@echo "    make test-all            Full test suite  (requires API keys in .env)"
	@echo "    make ingest              Build the controls knowledge base   [M3+]"
	@echo "    make assess REPO=<url>   Assess a public GitHub repo         [M5+]"
	@echo "    make eval                Run the evaluation harness          [M7+]"
	@echo "    make shell               Open a bash shell in the container"
	@echo "    make lint                Lint + format-check with ruff"
	@echo "    make clean               Remove local KB / artifacts / caches"

# --- Local (venv) --- no Python version is hardcoded here; the floor is enforced by
# requires-python. The guard fails early (before building a venv from the wrong interpreter)
# with a clean message if python3 is older than 3.12.
venv:
	@python3 -c "import sys; ok = sys.version_info >= (3, 12); print('Error: Python 3.12+ required (found %d.%d). Install Python 3.12+ or use Docker.' % sys.version_info[:2], file=sys.stderr) if not ok else None; sys.exit(0 if ok else 1)"
	python3 -m venv .venv
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

format:
	$(PYTHON) -m ruff format src tests scripts
	$(PYTHON) -m ruff check --fix src tests scripts

test-local:
	$(PYTHON) -m pytest -m "not agent" -q

lint-local:
	$(PYTHON) -m ruff check src tests scripts
	$(PYTHON) -m ruff format --check src tests scripts

# --- Docker ---
build:
	docker compose build

test: build
	docker compose run --rm test

test-all: build
	docker compose run --rm test-all

ingest: build
	docker compose run --rm app ingest-controls

assess: build
	@test -n "$(REPO)" || { echo "Usage: make assess REPO=https://github.com/OWNER/REPO"; exit 1; }
	docker compose run --rm app assess --repo-url $(REPO)

eval: build
	docker compose run --rm app eval

shell: build
	docker compose run --rm --entrypoint bash app

lint: build
	docker compose run --rm --entrypoint ruff app check src tests scripts
	docker compose run --rm --entrypoint ruff app format --check src tests scripts

clean:
	rm -rf chroma_db artifacts .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
