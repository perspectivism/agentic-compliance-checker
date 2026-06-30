"""Shared output schemas for MCP tool results, evidence normalization, and graph verdicts.

ToolFinding is returned by scanner tools (scan_secrets, scan_iac_security,
scan_ci_security). The Evidence Collector normalizes these into EvidenceRef
entries before the Synthesizer reasons over them.

RepoFileListing is returned by the list_repo_files tool.
EvidenceRef and CollectionResult are produced by the Evidence Collector.
VerdictClass, SynthesizerOutput, VerifierDecision, ControlVerdict, and FinalReport
are produced by the LangGraph supervisor and verifier loop (graph.py).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


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
    errors: list[str]  # tool/scanner failures; non-empty signals not_assessable to Synthesizer
    limitations: list[str]  # "no relevant files", "heuristic only", etc.


# ── Graph verdict schemas ──────────────────────────────────────────────────────


class VerdictClass(StrEnum):
    """The four possible outcomes for a control assessment."""

    satisfied = "satisfied"
    partial = "partial"
    gap = "gap"
    not_assessable = "not_assessable"


class SynthesizerOutput(BaseModel):
    """Verdict and reasoning produced by the Synthesizer LLM node.

    Evidence is NOT included here — it is taken directly from CollectionResult
    so it can never be hallucinated by the LLM.
    """

    verdict: VerdictClass
    rationale: str  # must reference only the provided scanner evidence
    confidence: float = 0.0  # 0.0–1.0; LLM self-report, not calibrated


class VerifierDecision(BaseModel):
    """Approve/reject decision produced by the Verifier LLM node."""

    approved: bool
    notes: str  # rejection rationale (for retry prompt) or approval confirmation


class ControlVerdict(BaseModel):
    """Complete verdict for one control, combining LLM reasoning and scanner evidence.

    evidence is always sourced from the Evidence Collector, never invented by the LLM.
    Any non-not_assessable verdict MUST have non-empty evidence and no collection errors.
    The deterministic fail-closed guard in finalize_control_node enforces this in code,
    not just in the prompt.
    """

    control_id: str
    verdict: VerdictClass
    evidence: list[EvidenceRef]  # from the scanner, never LLM-invented
    rationale: str
    confidence: float = 0.0
    verifier_status: Literal["passed", "failed", "not_run"] = "not_run"
    verifier_notes: str = ""
    attempt: int = 1  # which synthesis attempt produced this verdict


class SelectedControl(BaseModel):
    """One control in a SelectionResult, with optional retrieval relevance score.

    relevance_score is None for explicit mode (no retrieval performed).
    For dynamic mode it is in [0, 1], higher means more relevant to the query.
    """

    control_id: str
    relevance_score: float | None = None


class SelectionResult(BaseModel):
    """Describes how controls were chosen for an assessment run.

    Stored as a typed first-class field on FinalReport (not buried in audit) so
    eval code can inspect mode, query, and per-control scores without parsing
    freeform metadata.

    Explicit mode: top_k, detected_features, and selection_query are empty/None;
    every SelectedControl has relevance_score=None.
    Dynamic mode: all fields are populated; selected_controls is in ranking order
    (highest relevance first).
    """

    mode: Literal["dynamic", "explicit"]
    top_k: int | None = None  # requested k; only meaningful for dynamic mode
    detected_features: list[str] = []
    selection_query: str = ""
    selected_controls: list[SelectedControl]


class FinalReport(BaseModel):
    """Complete assessment report for one repository run."""

    repo_path: str
    verdicts: list[ControlVerdict]
    selection: SelectionResult = Field(
        default_factory=lambda: SelectionResult(mode="explicit", selected_controls=[])
    )
    audit: dict[str, Any]  # run_id, started_at, model_id, verdict counts
