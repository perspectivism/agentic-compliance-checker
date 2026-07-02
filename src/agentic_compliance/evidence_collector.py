"""Evidence collector node — selects tools from scanner_hints, runs them, normalises output.

Public API:
    collect_evidence(repo_root, control)  — run applicable tools; return CollectionResult
    finding_to_evidence(finding)          — normalise one ToolFinding → EvidenceRef
    file_excerpt_to_evidence(repo_root, path, start_line, end_line)
                                          — read_file_slice → EvidenceRef (repo-relative path)

Design constraints:
- Calls only deterministic MCP tools; no LLM and no direct filesystem access.
- Does NOT draft verdicts — verdict classes are the graph's responsibility.
- On any tool error or timeout, records the failure in CollectionResult.errors
  (fail-closed: the graph treats a non-empty errors list as grounds for not_assessable).
- "No relevant evidence found" goes in limitations, not errors, so the graph can
  distinguish a clean run-and-found-nothing from a tool failure.
- Filters findings by check_family (tool routing) AND control_hints (relevance) so
  only evidence mapped to the current control reaches the Synthesizer.
"""

from __future__ import annotations

from pathlib import Path

from .kb import ControlEntry
from .schemas import CollectionResult, EvidenceRef, ToolFinding

# IaC check families served by scan_iac_security.
_IAC_FAMILIES: frozenset[str] = frozenset(
    {"terraform", "dockerfile", "kubernetes_yaml", "logging_monitoring"}
)


def _control_id_parts(control_id: str) -> frozenset[str]:
    """Split compound control IDs like 'SI-2/RA-5' into {'SI-2', 'RA-5'}.

    Used for relevance matching: a finding is relevant if any of its control_hints
    overlaps with any part of the current control's ID.
    """
    return frozenset(control_id.split("/"))


def _is_relevant(finding: ToolFinding, id_parts: frozenset[str]) -> bool:
    """Return True if the finding is mapped to at least one part of the control ID."""
    return bool(id_parts & set(finding.control_hints))


def collect_evidence(repo_root: Path, control: ControlEntry) -> CollectionResult:
    """Run the tools indicated by control.scanner_hints; return normalised EvidenceRef records.

    Tool selection is driven by scanner_hints; within each tool's output, findings are
    further filtered by control_hints so only evidence relevant to this specific control
    is returned. This prevents SC-8, AC-6, and SC-28 from all receiving the same broad
    Terraform finding set.
    """
    hints: set[str] = set(control.scanner_hints)
    id_parts = _control_id_parts(control.id)
    evidence: list[EvidenceRef] = []
    errors: list[str] = []
    limitations: list[str] = []

    run_iac = bool(hints & _IAC_FAMILIES)
    run_ci = "ci" in hints
    run_secrets = "secrets" in hints

    if not (run_iac or run_ci or run_secrets):
        limitations.append(
            f"No applicable tools for control {control.id!r} "
            f"(scanner_hints: {control.scanner_hints!r})"
        )
        return CollectionResult(
            control_id=control.id,
            evidence=evidence,
            errors=errors,
            limitations=limitations,
        )

    if run_iac:
        iac_hints = hints & _IAC_FAMILIES
        try:
            from .tools import scan_iac_security  # noqa: PLC0415

            findings = scan_iac_security(repo_root)
            # Two-stage filter: check_family routes to the right tool family,
            # control_hints ensures relevance to this specific control.
            relevant = [
                f for f in findings if f.check_family in iac_hints and _is_relevant(f, id_parts)
            ]
            evidence.extend(finding_to_evidence(f) for f in relevant)
            if not relevant:
                limitations.append(
                    f"scan_iac_security found no findings for {control.id!r} "
                    f"in families {sorted(iac_hints)}"
                )
        except Exception as exc:  # noqa: BLE001 — fail-closed: record, don't raise
            errors.append(f"scan_iac_security failed: {exc}")

    if run_ci:
        try:
            from .tools import scan_ci_security  # noqa: PLC0415

            findings = scan_ci_security(repo_root)
            relevant = [f for f in findings if _is_relevant(f, id_parts)]
            evidence.extend(finding_to_evidence(f) for f in relevant)
            if not relevant:
                limitations.append(f"scan_ci_security found no findings for {control.id!r}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"scan_ci_security failed: {exc}")

    if run_secrets:
        try:
            from .tools import scan_secrets  # noqa: PLC0415

            findings = scan_secrets(repo_root)
            relevant = [f for f in findings if _is_relevant(f, id_parts)]
            evidence.extend(finding_to_evidence(f) for f in relevant)
            if not relevant:
                limitations.append(f"scan_secrets found no findings for {control.id!r}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"scan_secrets failed: {exc}")

    return CollectionResult(
        control_id=control.id,
        evidence=evidence,
        errors=errors,
        limitations=limitations,
    )


def finding_to_evidence(finding: ToolFinding) -> EvidenceRef:
    """Normalise a ToolFinding into an EvidenceRef with source_type 'tool_result'.

    The excerpt is already redacted at the tool layer when finding.redacted is True,
    so no further masking is needed here.

    Absence findings (e.g. container_scan_missing) have no matched text, so their
    excerpt is empty — for those, the finding's message IS the evidence. Without
    this fallback the Synthesizer sees a bare file path with no content and cannot
    tell a gap finding from nothing (the first evaluation runs showed it then either
    degrades a real gap to not_assessable or, worse, overclaims satisfied on mixed
    evidence — see docs/EVAL_PLAN.md "First real run results").
    """
    return EvidenceRef(
        source_type="tool_result",
        path_or_id=finding.path,
        start_line=finding.start_line,
        end_line=finding.end_line,
        excerpt=finding.excerpt or finding.message,
    )


def file_excerpt_to_evidence(
    repo_root: Path,
    path: str,
    start_line: int = 1,
    end_line: int | None = None,
) -> EvidenceRef:
    """Read a bounded file excerpt and return it as an EvidenceRef with source_type 'repo_file'.

    path_or_id is normalised to a repo-relative path so the EvidenceRef is portable
    and does not leak the local filesystem layout.

    Delegates to tools.read_file_slice so the allowlist and size cap are enforced.
    Callers catch exceptions and record them as errors — this function does not swallow them.
    """
    from .tools import read_file_slice  # noqa: PLC0415

    slc = read_file_slice(repo_root, path, start_line, end_line)
    try:
        rel_path = str(Path(slc.path).relative_to(repo_root.resolve()))
    except ValueError:
        rel_path = slc.path  # path outside root is rejected upstream; fallback is safe
    return EvidenceRef(
        source_type="repo_file",
        path_or_id=rel_path,
        start_line=slc.start_line,
        end_line=slc.end_line,
        excerpt=slc.content,
    )
