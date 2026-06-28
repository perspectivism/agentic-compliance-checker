# syntax=docker/dockerfile:1
#
# Single-image build for the agentic compliance checker.
#
# The MCP server is NOT a separate container: langchain-mcp-adapters spawns it as
# a stdio subprocess inside this image, so one image runs the whole workflow.

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

# Install dependencies first for layer caching. The package uses a src/ layout,
# so the package dir must exist at install time (editable install).
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --upgrade pip && pip install -e ".[dev,agent]"

# Copy the rest of the project (docs, data, scripts, tests).
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
