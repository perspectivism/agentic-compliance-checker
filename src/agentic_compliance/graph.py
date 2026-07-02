"""LangGraph StateGraph: supervisor → collect → synthesize → verify loop → final report.

Topology:
    START → supervisor → collect → synthesize → verify ─┬─(approved / exhausted)→ finalize_control → supervisor
                                                         └─(rejected, retries remain)→ synthesize
    supervisor → final → END  (when all controls are done)

Fail-closed invariants:
- Any affirmative (non-not_assessable) verdict requires non-empty scanner evidence
  and no tool errors — enforced deterministically in finalize_control_node, not just
  via prompt instruction.
- If the verifier rejects MAX_VERIFIER_ATTEMPTS times, the verdict is downgraded to
  'not_assessable' with verifier failure notes — the loop cannot run forever.
- GRAPH_RECURSION_LIMIT provides a hard LangGraph-level backstop.
"""

from __future__ import annotations

import operator
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, TypedDict, cast

from langchain.chat_models import init_chat_model
from langgraph.graph import END, START, StateGraph

from .control_selection import explicit_selection, select_controls
from .evidence_collector import collect_evidence
from .kb import ControlEntry
from .retriever import ControlsRetriever
from .run_log import JSONLRunLogger, NoopRunLogger, RunLogger, instrument_node, safe_error_fields
from .schemas import (
    CollectionResult,
    ControlVerdict,
    FinalReport,
    SelectionResult,
    SynthesizerOutput,
    VerdictClass,
    VerifierDecision,
)


def _parse_max_verifier_attempts() -> int:
    """Read MAX_VERIFIER_ATTEMPTS from env, validating it is a positive integer."""
    raw = os.environ.get("MAX_VERIFIER_ATTEMPTS", "3")
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"MAX_VERIFIER_ATTEMPTS must be a positive integer, got {raw!r}") from None
    if value < 1:
        raise ValueError(f"MAX_VERIFIER_ATTEMPTS must be >= 1, got {value}")
    return value


# Verifier attempts cap per control. After this many rejections the verdict is
# force-downgraded to not_assessable so the loop cannot run forever.
# Configurable via MAX_VERIFIER_ATTEMPTS env var (positive integer); defaults to 3.
MAX_VERIFIER_ATTEMPTS: int = _parse_max_verifier_attempts()

# Hard backstop: total node invocations for the whole run.
# Worst case per control: 1 supervisor + 1 collect + MAX*synthesize + MAX*verify + 1 finalize = 9
# With 14 controls: 14*9 + 1 supervisor(initial) + 1 final = 128. 200 gives comfortable headroom.
GRAPH_RECURSION_LIMIT: int = 200

_SYNTHESIZER_SYSTEM = (
    "You are a compliance synthesizer. Given evidence from automated scanners, "
    "produce a structured verdict, scoped strictly to what the scanners actually checked — "
    "not the control's full theoretical scope. Emit 'satisfied' when at least one concrete "
    "scanner evidence item directly confirms the control for the resource(s) it covers; you "
    "do not need evidence for every resource type the control could theoretically apply to "
    "(e.g. one correctly-configured S3 bucket is sufficient evidence even if the repo also "
    "has RDS/EBS resources with no evidence either way — unless there is contradictory gap "
    "evidence or a tool error for those resources, which changes the verdict to "
    "'partial'/'gap' or 'not_assessable' respectively). 'Positive evidence' and 'gap "
    "evidence' below list illustrative example categories, not a required checklist — one "
    "matching category is enough, you do not need all of them. Emit 'gap' when findings show "
    "a control failure. Emit 'partial' when the evidence is genuinely mixed: at least one "
    "concrete finding confirms the control AND at least one concrete finding shows a failure "
    "for another resource, tier, or evidence category under the same control (e.g. one tier's ingress is "
    "correctly scoped while another tier is open to the internet, or one scanning category is "
    "configured while another required category is confirmed missing) — do not collapse mixed "
    "evidence into 'satisfied' or 'gap'. Emit 'not_assessable' when evidence is insufficient "
    "or tool errors occurred. Base reasoning strictly on the provided evidence — do not "
    "invent claims."
)

_VERIFIER_SYSTEM = (
    "You are a compliance verifier. Review the draft verdict against the collected evidence. "
    "Reject any verdict whose rationale goes beyond or contradicts the provided scanner evidence. "
    "Reject 'satisfied' or 'partial' verdicts that lack concrete supporting evidence. "
    "Do not reject a 'satisfied' verdict merely because the evidence does not cover every "
    "example category listed for the control, or every resource type the control could "
    "theoretically apply to — one concrete, on-point evidence item for the resource(s) "
    "actually present is sufficient. When the evidence contains both a concrete positive "
    "finding and a concrete gap finding for the same control, the correct verdict is "
    "'partial' — reject a 'satisfied' or 'gap' verdict that ignores the other side of "
    "genuinely mixed evidence. Approve otherwise."
)


def _require_chat_model() -> str:
    """Return CHAT_MODEL or raise a clear, actionable error.

    The CLI pre-checks this before any clone/embedding work for a fast, friendly
    failure, but the graph is also callable directly (tests, langgraph dev,
    programmatic use) — those callers bypass the CLI check entirely, so this is
    the real backstop. A bare os.environ["CHAT_MODEL"] KeyError here would be
    opaque to anyone not already familiar with this module's internals.
    """
    model_id = os.environ.get("CHAT_MODEL")
    if not model_id:
        raise RuntimeError(
            "CHAT_MODEL is not set. Copy .env.example to .env and fill in CHAT_MODEL "
            "plus the matching provider API key (e.g. ANTHROPIC_API_KEY), or export "
            "CHAT_MODEL directly in your environment."
        )
    return model_id


# ── State ──────────────────────────────────────────────────────────────────────


class ComplianceState(TypedDict):
    """Typed state threaded through every node in the compliance graph.

    verdicts uses operator.add so finalize_control appends without overwriting
    prior controls' completed verdicts.
    """

    repo_root: str  # absolute path string; loaded once, never mutated
    controls: list[dict]  # serialized ControlEntry (model_dump); immutable after START
    control_idx: int  # index of the control currently being assessed
    collection: dict | None  # CollectionResult.model_dump() for current control
    draft_verdict: dict | None  # ControlVerdict.model_dump() pending verifier approval
    verifier_attempts: int  # how many times verify has run for the current control
    verifier_notes: list[str]  # rejection notes accumulated from the verifier (cleared per control)
    verdicts: Annotated[list[dict], operator.add]  # finalized ControlVerdict dicts, one per control
    selection: dict  # SelectionResult.model_dump(); how controls were chosen for this run
    run_id: str
    started_at: str
    model_id: str
    final_report: dict | None  # FinalReport.model_dump(); set by final_node


# ── Prompt helpers ─────────────────────────────────────────────────────────────


def _synthesizer_human(
    control: ControlEntry,
    collection: CollectionResult,
    verifier_notes: list[str],
    attempt: int,
) -> str:
    """Build the human turn for the Synthesizer node."""
    parts = [
        f"Control: {control.id} — {control.name}",
        f"Positive evidence: {control.positive_evidence}",
        f"Gap evidence: {control.gap_evidence}",
        "",
        f"Scanner evidence ({len(collection.evidence)} items):",
    ]
    for ref in collection.evidence:
        excerpt = ref.excerpt[:200].replace("\n", " ")
        parts.append(f"  [{ref.source_type}] {ref.path_or_id}: {excerpt}")
    if not collection.evidence:
        parts.append("  (none)")
    if collection.errors:
        parts.append(
            f"\nTool errors (treat as not_assessable signal): {'; '.join(collection.errors)}"
        )
    if collection.limitations:
        parts.append(f"Limitations: {'; '.join(collection.limitations)}")
    if verifier_notes and attempt > 1:
        parts.append(f"\nVerifier rejected attempt {attempt - 1}: {'; '.join(verifier_notes)}")
        parts.append("Please revise your verdict to address the feedback.")
    parts.append("\nProduce a SynthesizerOutput (verdict + rationale + confidence).")
    return "\n".join(parts)


def _verifier_human(draft: ControlVerdict, collection: CollectionResult) -> str:
    """Build the human turn for the Verifier node."""
    parts = [
        f"Draft verdict for {draft.control_id}: {draft.verdict.value}",
        f"Reasoning: {draft.rationale}",
        "",
        f"Full scanner evidence ({len(collection.evidence)} items):",
    ]
    for ref in collection.evidence:
        excerpt = ref.excerpt[:200].replace("\n", " ")
        parts.append(f"  [{ref.source_type}] {ref.path_or_id}: {excerpt}")
    if not collection.evidence:
        parts.append("  (none)")
    if collection.errors:
        parts.append(f"\nTool errors: {'; '.join(collection.errors)}")
    parts.append(
        "\nApprove if the verdict is grounded in the evidence. "
        "Reject any affirmative verdict whose rationale is not supported by the scanner evidence above."
    )
    return "\n".join(parts)


# ── Graph builder ──────────────────────────────────────────────────────────────


def _build_graph(synthesizer: Any = None, verifier: Any = None, logger: RunLogger | None = None):
    """Build and compile the compliance StateGraph.

    synthesizer and verifier are already-structured models (after with_structured_output).
    Pass them explicitly for testing; leave None for production (lazy init from CHAT_MODEL).

    logger defaults to NoopRunLogger — existing callers (tests, langgraph dev) get no
    log file unless they opt in. run_assessment() supplies a real JSONLRunLogger.

    The LLMs are only initialized on first node invocation, so importing this module
    or calling _build_graph() itself does not require CHAT_MODEL to be set.
    """
    log = logger if logger is not None else NoopRunLogger()

    def _get_synthesizer():
        if synthesizer is not None:
            return synthesizer
        return init_chat_model(_require_chat_model()).with_structured_output(SynthesizerOutput)

    def _get_verifier():
        if verifier is not None:
            return verifier
        return init_chat_model(_require_chat_model()).with_structured_output(VerifierDecision)

    # ── Nodes ──────────────────────────────────────────────────────────────────

    def supervisor_node(state: ComplianceState) -> dict:
        """Routing checkpoint — no side effects; conditional edge does all routing."""
        return {}

    def collect_node(state: ComplianceState) -> dict:
        """Run the Evidence Collector for the current control (deterministic, no LLM)."""
        control = ControlEntry.model_validate(state["controls"][state["control_idx"]])
        repo_root = Path(state["repo_root"])
        result = collect_evidence(repo_root, control)
        # Structural summary only — never the evidence/error content itself.
        log.log(
            "tool_call",
            control_id=control.id,
            tools=control.scanner_hints,
            evidence_count=len(result.evidence),
            error_count=len(result.errors),
            limitation_count=len(result.limitations),
        )
        return {
            "collection": result.model_dump(),
            # Reset per-control verifier state for each fresh evidence run.
            "verifier_attempts": 0,
            "verifier_notes": [],
            "draft_verdict": None,
        }

    def synthesize_node(state: ComplianceState) -> dict:
        """LLM Synthesizer: evidence → draft ControlVerdict (verdict + reasoning only)."""
        control = ControlEntry.model_validate(state["controls"][state["control_idx"]])
        collection = CollectionResult.model_validate(state["collection"])
        attempt = state["verifier_attempts"] + 1
        verifier_notes = state["verifier_notes"]

        messages = [
            ("system", _SYNTHESIZER_SYSTEM),
            ("human", _synthesizer_human(control, collection, verifier_notes, attempt)),
        ]
        output = cast(SynthesizerOutput, _get_synthesizer().invoke(messages))

        # Merge LLM output with provenance fields the LLM must not control.
        draft = ControlVerdict(
            control_id=control.id,
            verdict=output.verdict,
            evidence=collection.evidence,  # evidence always from scanner, never LLM-invented
            rationale=output.rationale,
            confidence=output.confidence,
            verifier_status="not_run",
            attempt=attempt,
        )
        return {"draft_verdict": draft.model_dump()}

    def verify_node(state: ComplianceState) -> dict:
        """LLM Verifier: approve or reject the draft verdict; increment attempt counter."""
        draft = ControlVerdict.model_validate(state["draft_verdict"])
        collection = CollectionResult.model_validate(state["collection"])
        attempts = state["verifier_attempts"] + 1

        messages = [
            ("system", _VERIFIER_SYSTEM),
            ("human", _verifier_human(draft, collection)),
        ]
        decision = cast(VerifierDecision, _get_verifier().invoke(messages))

        new_status = "passed" if decision.approved else "failed"
        updated_notes = state["verifier_notes"] + (
            [decision.notes] if not decision.approved else []
        )
        # notes_present, not the notes text itself — verifier rationale is freeform
        # LLM output and the log's job is to show that the loop ran, not to persist
        # a second copy of reasoning that belongs in the FinalReport.
        log.log(
            "verifier_attempt",
            control_id=draft.control_id,
            attempt=attempts,
            draft_verdict=draft.verdict.value,
            approved=decision.approved,
            notes_present=bool(decision.notes),
        )
        return {
            "verifier_attempts": attempts,
            "verifier_notes": updated_notes,
            "draft_verdict": {**draft.model_dump(), "verifier_status": new_status},
        }

    def finalize_control_node(state: ComplianceState) -> dict:
        """Commit the current verdict; enforce fail-closed invariants before emitting.

        Two downgrade paths:
        1. Fail-closed guard: any affirmative (non-not_assessable) verdict without scanner
           evidence or with collection errors is downgraded to not_assessable, regardless
           of what the LLM decided. Deterministic code check, not a prompt instruction.
        2. Verifier exhausted: loop cap reached without approval — downgrade to not_assessable
           with the accumulated verifier rejection notes.
        """
        draft = ControlVerdict.model_validate(state["draft_verdict"])
        collection = CollectionResult.model_validate(state["collection"])
        attempts = state["verifier_attempts"]

        # Guard 1 — fail-closed: any affirmative verdict requires scanner evidence and
        # no tool errors. not_assessable is exempt because the LLM already degraded.
        # This enforces AGENTS.md #7: every verdict must include evidence or be not_assessable.
        if draft.verdict != VerdictClass.not_assessable and (
            collection.errors or not collection.evidence
        ):
            error_detail = (
                "; ".join(collection.errors) if collection.errors else "no scanner evidence"
            )
            draft = draft.model_copy(
                update={
                    "verdict": VerdictClass.not_assessable,
                    "verifier_status": "failed",
                    "verifier_notes": f"[fail-closed: {error_detail}]",
                    "rationale": (
                        f"[fail-closed: {draft.verdict.value} requires concrete scanner evidence"
                        f" ({error_detail})] {draft.rationale}"
                    ),
                }
            )
        # Guard 2 — verifier exhausted: downgrade after cap is reached.
        elif draft.verifier_status != "passed" and attempts >= MAX_VERIFIER_ATTEMPTS:
            notes_str = "; ".join(state["verifier_notes"])
            draft = draft.model_copy(
                update={
                    "verdict": VerdictClass.not_assessable,
                    "verifier_status": "failed",
                    "verifier_notes": (
                        f"[verifier-exhausted after {attempts} attempts]"
                        + (f" {notes_str}" if notes_str else "")
                    ),
                    "rationale": (
                        f"[verifier-exhausted after {attempts} attempts] {draft.rationale}"
                        + (f" | Verifier notes: {notes_str}" if notes_str else "")
                    ),
                }
            )

        log.log(
            "verdict_finalized",
            control_id=draft.control_id,
            verdict=draft.verdict.value,
            verifier_status=draft.verifier_status,
        )
        return {
            "verdicts": [draft.model_dump()],  # operator.add appends to the accumulated list
            "control_idx": state["control_idx"] + 1,
            "draft_verdict": None,
            "collection": None,
        }

    def final_node(state: ComplianceState) -> dict:
        """Compile all finalized verdicts into a FinalReport with audit metadata."""
        verdicts = [ControlVerdict.model_validate(v) for v in state["verdicts"]]
        selection = SelectionResult.model_validate(state["selection"])
        report = FinalReport(
            repo_path=state["repo_root"],
            verdicts=verdicts,
            selection=selection,
            audit={
                "run_id": state["run_id"],
                "started_at": state["started_at"],
                "model_id": state["model_id"],
                "controls_assessed": len(verdicts),
                "satisfied_count": sum(1 for v in verdicts if v.verdict == VerdictClass.satisfied),
                "partial_count": sum(1 for v in verdicts if v.verdict == VerdictClass.partial),
                "gap_count": sum(1 for v in verdicts if v.verdict == VerdictClass.gap),
                "not_assessable_count": sum(
                    1 for v in verdicts if v.verdict == VerdictClass.not_assessable
                ),
            },
        )
        log.log("run_end", **report.audit)
        return {"final_report": report.model_dump()}

    # ── Routing ────────────────────────────────────────────────────────────────

    def route_supervisor(state: ComplianceState) -> str:
        """Route to 'collect' for the next control, or 'final' when all controls are done."""
        if state["control_idx"] >= len(state["controls"]):
            return "final"
        return "collect"

    def route_verify(state: ComplianceState) -> str:
        """Approve → finalize; rejected + retries remain → synthesize; exhausted → finalize."""
        draft = ControlVerdict.model_validate(state["draft_verdict"])
        if draft.verifier_status == "passed":
            return "finalize_control"
        if state["verifier_attempts"] >= MAX_VERIFIER_ATTEMPTS:
            return "finalize_control"  # exhausted; finalize_control handles downgrade
        return "synthesize"

    # ── Assemble ───────────────────────────────────────────────────────────────

    builder = StateGraph(ComplianceState)
    builder.add_node("supervisor", instrument_node("supervisor", supervisor_node, log))
    builder.add_node("collect", instrument_node("collect", collect_node, log))
    builder.add_node("synthesize", instrument_node("synthesize", synthesize_node, log))
    builder.add_node("verify", instrument_node("verify", verify_node, log))
    builder.add_node(
        "finalize_control", instrument_node("finalize_control", finalize_control_node, log)
    )
    builder.add_node("final", instrument_node("final", final_node, log))

    builder.add_edge(START, "supervisor")
    builder.add_conditional_edges(
        "supervisor", route_supervisor, {"collect": "collect", "final": "final"}
    )
    builder.add_edge("collect", "synthesize")
    builder.add_edge("synthesize", "verify")
    builder.add_conditional_edges(
        "verify",
        route_verify,
        {"finalize_control": "finalize_control", "synthesize": "synthesize"},
    )
    builder.add_edge("finalize_control", "supervisor")
    builder.add_edge("final", END)

    return builder.compile()


# ── Public API ─────────────────────────────────────────────────────────────────


def _initial_state(
    repo_root: Path,
    controls: list[ControlEntry],
    model_id: str = "unset",
    selection: SelectionResult | None = None,
) -> ComplianceState:
    """Build the initial ComplianceState for a fresh run.

    selection defaults to an explicit SelectionResult wrapping controls so tests
    can call _initial_state() directly without constructing one. run_assessment()
    always provides the proper SelectionResult (dynamic or explicit).
    """
    if selection is None:
        selection = explicit_selection(controls)
    return ComplianceState(
        repo_root=str(repo_root.resolve()),
        controls=[c.model_dump() for c in controls],
        control_idx=0,
        collection=None,
        draft_verdict=None,
        verifier_attempts=0,
        verifier_notes=[],
        verdicts=[],
        selection=selection.model_dump(),
        run_id=str(uuid.uuid4()),
        started_at=datetime.now(UTC).isoformat(),
        model_id=model_id,
        final_report=None,
    )


def run_assessment(
    repo_root: Path,
    controls: list[ControlEntry] | None = None,
    synthesizer: Any = None,
    verifier: Any = None,
    top_k_controls: int = 6,
    store_path: Path | None = None,
    logger: RunLogger | None = None,
) -> FinalReport:
    """Assess repo_root against controls and return a FinalReport.

    If controls is None (the default), selects controls dynamically from the
    persisted KB via semantic search over detected repo features. Missing KB
    raises FileNotFoundError — no silent fallback to all controls.

    If controls is provided, wraps them in an explicit SelectionResult and
    bypasses the retriever entirely.

    synthesizer and verifier can be injected for testing (pre-structured models).
    top_k_controls is the maximum number of controls to select in dynamic mode.
    store_path defaults to ./chroma_db (the ingest-controls default output).
    logger defaults to a real JSONLRunLogger writing artifacts/runs/<run_id>.jsonl;
    pass NoopRunLogger() or InMemoryRunLogger() to opt out (tests do this to avoid
    writing files for every assertion).
    """
    if controls is None:
        _store_path = store_path or Path("./chroma_db")
        retriever = ControlsRetriever.from_persisted(_store_path)
        selection = select_controls(repo_root, retriever, top_k=top_k_controls)
        # Entries are already in retriever._index — no second YAML read needed.
        controls = retriever.get_by_ids([sc.control_id for sc in selection.selected_controls])
    else:
        selection = explicit_selection(controls)

    model_id = os.environ.get("CHAT_MODEL", "unset")
    state = _initial_state(repo_root, controls, model_id=model_id, selection=selection)
    log = logger if logger is not None else JSONLRunLogger(run_id=state["run_id"])
    compiled = _build_graph(synthesizer=synthesizer, verifier=verifier, logger=log)

    log.log("run_start", repo_root=str(repo_root), model_id=model_id, num_controls=len(controls))
    try:
        result = compiled.invoke(state, config={"recursion_limit": GRAPH_RECURSION_LIMIT})
    except Exception as exc:
        log.log("run_error", **safe_error_fields(exc))
        raise
    return FinalReport.model_validate(result["final_report"])


# Module-level compiled graph for `langgraph dev` / Studio (matches langgraph.json).
# LLMs are initialized lazily on first node invocation — this line is safe without
# CHAT_MODEL set in the environment.
graph = _build_graph()
