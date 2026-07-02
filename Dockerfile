# syntax=docker/dockerfile:1
#
# Single-image build for the agentic compliance checker.
#
# The MCP server is NOT a separate container: the same image can run it over stdio
# (python -m agentic_compliance.mcp_server) for MCP clients. The CLI assess path
# calls the scanner functions in-process and does not need it (DECISIONS.md D3).

FROM python:3.12-slim AS base
# Python 3.12 is the project floor (requires-python >=3.12) and has full, mature wheel
# support across the ML/vector stack (chromadb, onnxruntime, scikit-learn, etc.).
# Bump this slim image only if you raise the floor in pyproject.toml.

# git is needed ONLY to clone the target repo under analysis. That clone is
# read-only, shallow, and never executed. Git has had clone-time RCE CVEs
# (CVE-2024-32002, CVE-2025-48384) whose mitigation is: never use --recursive,
# never run repo contents, keep git patched. We also harden git defaults below.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Defense-in-depth against the submodule/symlink clone vectors at the git level.
RUN git config --system protocol.ext.allow never \
 && git config --system core.symlinks false

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first for layer caching — and, critically, decoupled
# from source/README changes. pip install -e . pulls in the full ML/vector
# stack (torch, transformers, chromadb, ...) and takes ~5 minutes; without
# this split, editing a single source file or a README typo invalidates this
# layer and forces the whole multi-minute reinstall on every build. pip
# install -e . needs *a* discoverable package plus a readable README
# (referenced by `readme = "README.md"` in pyproject.toml) — not necessarily
# the real ones, so stubs stand in here. The real files land via the "rest of
# the project" COPY below and take effect with no re-install, since an
# editable install is a path-pointer resolved at import time, not a static
# copy baked in at install time. Net effect: only a pyproject.toml change
# (new/updated dependency) re-triggers the slow install; source/README edits
# hit only the cheap COPY below.
COPY pyproject.toml ./
RUN mkdir -p src/agentic_compliance \
 && touch src/agentic_compliance/__init__.py README.md
RUN pip install --upgrade pip && pip install -e ".[dev,agent]"

# Copy the rest of the project (src, README, docs, data, scripts, tests).
COPY . .

# Run as non-root. (Fittingly, this is the exact CM-2/CM-6 control the tool checks for.)
RUN useradd --create-home --uid 10001 appuser \
 && mkdir -p /app/chroma_db /app/artifacts \
 && chown -R appuser:appuser /app
USER appuser

# Persisted controls KB and generated reports/eval output are mounted as volumes.
VOLUME ["/app/chroma_db", "/app/artifacts"]

# Thin CLI dispatcher (see src/agentic_compliance/cli.py). Heavy imports are lazy,
# so the image builds and runs from day one even before milestones are implemented.
ENTRYPOINT ["python", "-m", "agentic_compliance.cli"]
CMD ["--help"]
