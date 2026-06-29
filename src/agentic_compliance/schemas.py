"""Shared output schemas for MCP tool results.

ToolFinding is returned by scanner tools (scan_secrets, scan_iac_security,
scan_ci_security). The Evidence Collector normalizes these into EvidenceRef
entries before the Synthesizer reasons over them.

RepoFileListing is returned by the list_repo_files tool.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class ToolFinding(BaseModel):
    """Single finding produced by a scanner tool.

    excerpt always has the secret value masked when redacted=True — the raw
    value must never appear in tool output.
    """

    path: str  # repo-relative file path
    start_line: int | None = None
    end_line: int | None = None
    finding_type: str  # e.g. "public_ingress", "aws_access_key"
    check_family: Literal[
        "terraform",
        "dockerfile",
        "kubernetes_yaml",
        "logging_monitoring",
        "ci",
        "secrets",
    ]
    severity: Literal["high", "medium", "low", "info"]
    message: str
    control_hints: list[str]  # NIST control IDs this finding maps to
    excerpt: str  # matched text; secret value masked when redacted=True
    redacted: bool = False  # True when excerpt value was masked
    limitations: list[str] = []  # what this scanner cannot determine


class RepoFileListing(BaseModel):
    """Single file entry returned by the list_repo_files tool."""

    path: str  # repo-relative path
    size: int  # bytes
    extension: str  # file extension, empty string for extension-less files
