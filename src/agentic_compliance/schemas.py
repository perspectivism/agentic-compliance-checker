"""Shared output schemas for MCP tool results and evidence normalization.

ToolFinding is returned by scanner tools (scan_secrets, scan_iac_security,
scan_ci_security). The Evidence Collector normalizes these into EvidenceRef
entries before the Synthesizer reasons over them.

RepoFileListing is returned by the list_repo_files tool.
EvidenceRef and CollectionResult are produced by the Evidence Collector.
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


class EvidenceRef(BaseModel):
    """A single normalised piece of evidence for a control assessment.

    Produced by the Evidence Collector from ToolFinding records or read_file_slice
    excerpts. The Synthesizer reasons over these; it must not invent EvidenceRef
    entries that did not originate from the Collector.

    source_type distinguishes scanner findings ("tool_result"), direct file reads
    ("repo_file"), and control-KB references ("control_kb").
    """

    source_type: Literal["repo_file", "control_kb", "tool_result"]
    path_or_id: str  # repo-relative path for repo_file/tool_result; control ID for control_kb
    start_line: int | None = None
    end_line: int | None = None
    excerpt: str  # already redacted if the source was a secrets finding


class CollectionResult(BaseModel):
    """Output of one Evidence Collector run for a single control.

    errors and limitations are kept separate so M5 can distinguish a tool
    failure (→ not_assessable) from a clean run that found nothing (→ gap or
    not_assessable depending on control type). Neither field produces a verdict
    directly — that is M5's responsibility.
    """

    control_id: str
    evidence: list[EvidenceRef]
    errors: list[str]  # tool/scanner failures; non-empty signals not_assessable to M5
    limitations: list[str]  # "no relevant files", "heuristic only", etc.
