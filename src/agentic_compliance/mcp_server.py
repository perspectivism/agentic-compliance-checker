"""FastMCP server exposing the five read-only compliance tools over stdio.

Run as a subprocess:
    python -m agentic_compliance.mcp_server

The server receives requests via stdio (MCP protocol). Each tool accepts
repo_root as a string parameter and delegates to the pure-Python functions
in tools.py. No tool makes network calls or executes repo content.

This module requires the [agent] extras (mcp>=1.0). The tool logic in
tools.py has no MCP dependency and can be imported and tested without it.
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .tools import (
    list_repo_files as _list_repo_files,
    read_file_slice as _read_file_slice,
    scan_ci_security as _scan_ci_security,
    scan_iac_security as _scan_iac_security,
    scan_secrets as _scan_secrets,
)

mcp = FastMCP("agentic-compliance")


@mcp.tool()
def list_repo_files(repo_root: str) -> list[dict]:
    """Return metadata for every allowed text file in the repository.

    repo_root: absolute path to the local repository root (already cloned).
    Returns a list of {path, size, extension} dicts (repo-relative paths).
    """
    return [f.model_dump() for f in _list_repo_files(Path(repo_root))]


@mcp.tool()
def read_file_slice(
    repo_root: str,
    path: str,
    start_line: int = 1,
    end_line: int | None = None,
) -> dict:
    """Return a bounded, line-cited excerpt from a single file.

    repo_root: absolute path to the repository root.
    path: repo-relative file path.
    start_line / end_line: 1-indexed, inclusive. Stops at EOF if end_line
    exceeds file length.
    """
    result = _read_file_slice(Path(repo_root), path, start_line, end_line)
    return {
        "path": result.path,
        "start_line": result.start_line,
        "end_line": result.end_line,
        "content": result.content,
    }


@mcp.tool()
def scan_secrets(repo_root: str) -> list[dict]:
    """Scan for hardcoded credentials. Secret values are masked in output.

    repo_root: absolute path to the repository root.
    Returns a list of ToolFinding dicts with check_family='secrets' and
    redacted=True. The raw secret value never appears in the output.
    """
    return [f.model_dump() for f in _scan_secrets(Path(repo_root))]


@mcp.tool()
def scan_iac_security(repo_root: str) -> list[dict]:
    """Scan IaC files for security misconfigurations.

    repo_root: absolute path to the repository root.
    Checks Terraform, Dockerfile, Kubernetes YAML, and logging/monitoring
    configuration. Returns a list of ToolFinding dicts.
    """
    return [f.model_dump() for f in _scan_iac_security(Path(repo_root))]


@mcp.tool()
def scan_ci_security(repo_root: str) -> list[dict]:
    """Scan CI workflow files for security tool presence/absence.

    repo_root: absolute path to the repository root.
    Checks .github/workflows for dependency scanners, container scanners,
    and SAST tools. Returns a list of ToolFinding dicts.
    """
    return [f.model_dump() for f in _scan_ci_security(Path(repo_root))]


if __name__ == "__main__":
    mcp.run(transport="stdio")
