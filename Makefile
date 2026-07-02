.PHONY: help venv install-agent format test-local test-all-local lint-local ingest-local assess-local golden-local eval-local build test test-all ingest assess golden eval shell lint export-artifacts clean

IMAGE      := agentic-compliance-checker:latest
PYTHON     ?= .venv/bin/python
REPO       ?=
EXPORT_DIR ?= artifacts/docker

# Optional overrides for assess / assess-local. Left empty by default so an
# unset CONTROLS/TOP_K/FORMAT falls through to the CLI's own defaults in
# cli.py (single source of truth, not duplicated here). --controls and
# --top-k-controls stay mutually exclusive — the CLI already enforces that
# with a clear error, so it isn't re-checked here. OUT is handled per-target
# below (assess vs. assess-local want different fallback behavior).
CONTROLS  ?=
TOP_K     ?=
OUT       ?=
FORMAT    ?=
REPO_PATH ?= tests/fixtures/repos/secure_terraform_app

CONTROLS_FLAG := $(if $(CONTROLS),--controls $(CONTROLS))
TOP_K_FLAG    := $(if $(TOP_K),--top-k-controls $(TOP_K))
FORMAT_FLAG   := $(if $(FORMAT),--format $(FORMAT))

# golden / golden-local: generate candidate golden-set cases (scripts/generate_golden.py).
# GOLDEN_OUT is a separate var from OUT (assess's own output var) since they write
# different kinds of files and shouldn't share a default. FIXTURE restricts
# generation to one fixture directory name — for adding a new fixture's cases
# without re-labeling (and re-billing) the whole set.
GOLDEN_OUT ?= artifacts/golden_candidates.yaml
FIXTURE    ?=

GOLDEN_FLAGS := $(if $(FIXTURE),--fixture $(FIXTURE))

# eval / eval-local: run the evaluation harness (verdict accuracy vs the frozen
# golden set). THRESHOLD overrides the macro-F1 gate; left empty it falls through
# to the CLI's own resolution (EVAL_MACRO_F1_THRESHOLD env var, then 0.70).
THRESHOLD ?=

THRESHOLD_FLAG := $(if $(THRESHOLD),--threshold $(THRESHOLD))

help:
	@echo "Agentic compliance checker — make targets:"
	@echo "  Local (venv):"
	@echo "    make venv                Create .venv and install dev deps (Python 3.12+)"
	@echo "    make install-agent       Add the agent stack (MCP, LangGraph, RAG) — needed for"
	@echo "                             ingest-local / assess-local / eval-local"
	@echo "    make format              Auto-format + autofix with ruff"
	@echo "    make test-local          Fast test suite in the venv (pytest -m 'not agent')"
	@echo "    make test-all-local      Full test suite in the venv (pytest; local embeddings by"
	@echo "                             default — API keys only needed if configured otherwise)"
	@echo "    make lint-local          Lint + format-check with ruff (no changes)"
	@echo "    make ingest-local        Build the controls knowledge base in the venv"
	@echo "    make assess-local        Assess a repo locally, no Docker (default: bundled fixture via"
	@echo "                             REPO_PATH=; REPO=<url> to assess a public repo instead; plus"
	@echo "                             optional CONTROLS/TOP_K/OUT/FORMAT)"
	@echo "    make golden-local        Generate candidate golden-set cases in the venv (writes to"
	@echo "                             GOLDEN_OUT=artifacts/golden_candidates.yaml; FIXTURE=<name> to"
	@echo "                             add one fixture only — needs GOLDEN_LABEL_MODEL in .env)"
	@echo "    make eval-local          Run the evaluation harness in the venv (real LLM graph vs"
	@echo "                             the frozen golden set; optional THRESHOLD=<macro-F1 gate>)"
	@echo "  Docker:"
	@echo "    make build               Build the image"
	@echo "    make test                Fast test suite  (pytest -m 'not agent')"
	@echo "    make test-all            Full test suite  (local embeddings by default — see test-all-local)"
	@echo "    make ingest              Build the controls knowledge base"
	@echo "    make assess REPO=<url>   Assess a public GitHub repo (optional CONTROLS/TOP_K/OUT/FORMAT,"
	@echo "                             e.g. CONTROLS=AC-6,SC-8 for explicit control selection)"
	@echo "    make golden              Generate candidate golden-set cases (writes inside the"
	@echo "                             artifacts volume; use export-artifacts to copy it out)"
	@echo "    make eval                Run the evaluation harness (writes inside the artifacts"
	@echo "                             volume; optional THRESHOLD=<macro-F1 gate>)"
	@echo "    make shell               Open a bash shell in the container"
	@echo "    make lint                Lint + format-check with ruff"
	@echo "    make export-artifacts    Copy Docker's artifacts volume to ./artifacts/docker on the"
	@echo "                             host (EXPORT_DIR=<path> to choose a different destination)"
	@echo "    make clean               Remove local caches + the Docker-side KB/artifacts volumes"

# --- Local (venv) --- no Python version is hardcoded here; the floor is enforced by
# requires-python. The guard fails early (before building a venv from the wrong interpreter)
# with a clean message if python3 is older than 3.12.
venv:
	@python3 -c "import sys; ok = sys.version_info >= (3, 12); print('Error: Python 3.12+ required (found %d.%d). Install Python 3.12+ or use Docker.' % sys.version_info[:2], file=sys.stderr) if not ok else None; sys.exit(0 if ok else 1)"
	python3 -m venv .venv
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"

# venv only installs the [dev] extra (fast lane, no agent stack — matches
# AGENTS.md's staged M1 -> M2+ install order). ingest-local / assess-local /
# eval-local all need the agent stack, hence this as a separate step.
install-agent:
	$(PYTHON) -m pip install -e ".[dev,agent]"

format:
	$(PYTHON) -m ruff format src tests scripts
	$(PYTHON) -m ruff check --fix src tests scripts

test-local:
	$(PYTHON) -m pytest -m "not agent" -q

# Full suite in the venv. Mostly free — the @pytest.mark.agent tests largely
# need no model (MCP import checks) or use local embeddings (EMBEDDINGS_MODEL=
# local, the default). The one exception: test_eval.py's live-eval test makes a
# handful of real chat-model calls when CHAT_MODEL is configured in .env, and
# skips cleanly when it isn't.
test-all-local:
	$(PYTHON) -m pytest -q

lint-local:
	$(PYTHON) -m ruff check src tests scripts
	$(PYTHON) -m ruff format --check src tests scripts

ingest-local:
	$(PYTHON) -m agentic_compliance.cli ingest-controls

# REPO_PATH defaults to a bundled fixture so `make assess-local` works with no
# args — the fast local loop for trying/debugging a control or scanner change
# without a Docker rebuild. Set REPO=<url> instead to assess a public repo
# locally (no Docker needed) — REPO takes precedence over REPO_PATH when set,
# same as the Docker assess target. OUT defaults to artifacts/local_report.json
# (NOT the CLI's own artifacts/report.json default) so repeated local runs here
# never silently overwrite a "real" local assessment written to the CLI's
# default path — same overwrite-avoidance reasoning as
# EXPORT_DIR=artifacts/docker below, one layer earlier.
assess-local:
	$(PYTHON) -m agentic_compliance.cli assess \
		$(if $(REPO),--repo-url $(REPO),--repo-path $(REPO_PATH)) \
		$(CONTROLS_FLAG) $(TOP_K_FLAG) $(FORMAT_FLAG) \
		--out $(if $(OUT),$(OUT),artifacts/local_report.json)

# Writes to artifacts/golden_candidates.yaml by default — a review workspace, not
# the frozen data/golden_set.yaml. Needs GOLDEN_LABEL_MODEL set in .env to a model
# different from CHAT_MODEL (see docs/DECISIONS.md D8); the script fails clearly
# if it's unset. See docs/EVAL_PLAN.md for the full generate -> review -> freeze
# workflow.
golden-local:
	$(PYTHON) scripts/generate_golden.py --out $(GOLDEN_OUT) $(GOLDEN_FLAGS)

eval-local:
	$(PYTHON) scripts/run_eval.py $(THRESHOLD_FLAG)

# --- Docker ---
# All compose services use the same Dockerfile and publish the same local image tag.
# `make build` builds only app to avoid repeating the same image export for test/test-all.
#
# Keep `build: .` on test/test-all in docker-compose.yml anyway: if someone bypasses
# Make and runs raw Compose, those services should build locally rather than try to
# pull the unpublished image tag from a registry.
build:
	docker compose build app

test: build
	docker compose run --rm test

test-all: build
	docker compose run --rm test-all

ingest: build
	docker compose run --rm app ingest-controls

assess: build
	@test -n "$(REPO)" || { echo "Usage: make assess REPO=https://github.com/OWNER/REPO [CONTROLS=AC-6,SC-8]"; exit 1; }
	docker compose run --rm app assess --repo-url $(REPO) \
		$(CONTROLS_FLAG) $(TOP_K_FLAG) $(FORMAT_FLAG) $(if $(OUT),--out $(OUT))

# Writes inside the artifacts named volume (like assess/eval), not directly to the
# host — use `make export-artifacts` afterward to copy it out. Entrypoint override
# is needed since the image's default ENTRYPOINT expects a CLI subcommand
# (assess/ingest-controls/eval), not an arbitrary script path.
golden: build
	docker compose run --rm --entrypoint python app scripts/generate_golden.py \
		--out $(GOLDEN_OUT) $(GOLDEN_FLAGS)

eval: build
	docker compose run --rm app eval $(THRESHOLD_FLAG)

shell: build
	docker compose run --rm --entrypoint bash app

lint: build
	docker compose run --rm --entrypoint ruff app check src tests scripts
	docker compose run --rm --entrypoint ruff app format --check src tests scripts

# Copies the artifacts named volume out to a host directory (default:
# ./artifacts/docker — a subdirectory, not merged into ./artifacts itself, so
# a Docker-origin report never silently overwrites a same-named local venv
# report with no warning). `docker cp` isn't enough here because `app` runs
# with --rm (the container is gone once a run exits) — this binds a host
# directory alongside the volume in a throwaway invocation instead. Runs as
# the host UID/GID (only for this one-off, no-Python `cp`, not the app service
# generally) so the copy lands writable on the host without needing any
# permanent UID/GID wiring in docker-compose.yml.
export-artifacts: build
	@mkdir -p $(EXPORT_DIR)
	docker compose run --rm --user "$$(id -u):$$(id -g)" --entrypoint sh \
		-v "$(abspath $(EXPORT_DIR)):/export" \
		app -c "cp -a /app/artifacts/. /export/"
	@echo "Exported Docker's artifacts volume to $(EXPORT_DIR)/"

clean:
	rm -rf chroma_db artifacts .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	# chroma_db/artifacts are named Docker volumes (see docker-compose.yml), not
	# bind mounts — rm -rf above only clears local-venv leftovers, not the
	# Docker-side KB. -v removes them too; "-" tolerates Docker being unavailable.
	-docker compose down -v
