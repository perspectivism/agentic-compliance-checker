"""LangGraph supervisor and verifier loop — routing, verdict lifecycle, and loop-cap tests."""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentic_compliance.graph import (
    MAX_VERIFIER_ATTEMPTS,
    _build_graph,
    _initial_state,
    _require_chat_model,
)
from agentic_compliance.kb import build_exact_index, load_controls
from agentic_compliance.schemas import (
    CollectionResult,
    ControlVerdict,
    FinalReport,
    SynthesizerOutput,
    VerdictClass,
    VerifierDecision,
)

FIXTURES = Path(__file__).parent / "fixtures" / "repos"
_CONTROLS = build_exact_index(load_controls())
GRAPH_RECURSION_LIMIT = 200


def _ctrl(cid: str):
    c = _CONTROLS.get(cid)
    assert c is not None, f"Control {cid!r} not found"
    return c


def _mock_synthesizer(*outputs: SynthesizerOutput):
    """Mock structured synthesizer: returns outputs in order, last repeated if exhausted."""
    m = MagicMock()
    outputs_list = list(outputs)
    call_count = 0

    def side_effect(messages):
        nonlocal call_count
        idx = min(call_count, len(outputs_list) - 1)
        call_count += 1
        return outputs_list[idx]

    m.invoke.side_effect = side_effect
    return m


def _mock_verifier(*decisions: VerifierDecision):
    """Mock structured verifier: returns decisions in order, last repeated if exhausted."""
    m = MagicMock()
    decisions_list = list(decisions)
    call_count = 0

    def side_effect(messages):
        nonlocal call_count
        idx = min(call_count, len(decisions_list) - 1)
        call_count += 1
        return decisions_list[idx]

    m.invoke.side_effect = side_effect
    return m


def _run(
    repo_root: Path,
    controls,
    synthesizer=None,
    verifier=None,
) -> FinalReport:
    """Run the graph with injected mock LLMs and return the FinalReport."""
    state = _initial_state(repo_root, controls)
    g = _build_graph(synthesizer=synthesizer, verifier=verifier)
    result = g.invoke(state, config={"recursion_limit": GRAPH_RECURSION_LIMIT})
    return FinalReport.model_validate(result["final_report"])


# ── Happy path ─────────────────────────────────────────────────────────────────


class TestHappyPath:
    def test_single_control_gap_verdict_completes(self):
        """Single control assessment: gap verdict approved on first attempt → one FinalReport verdict."""
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.gap, rationale="Wildcard IAM found")
        )
        ver = _mock_verifier(VerifierDecision(approved=True, notes="Evidence supports gap"))

        report = _run(FIXTURES / "insecure_terraform_app", [_ctrl("AC-6")], synth, ver)

        assert len(report.verdicts) == 1
        assert report.verdicts[0].verdict == VerdictClass.gap
        assert report.verdicts[0].control_id == "AC-6"
        assert report.verdicts[0].verifier_status == "passed"

    def test_multiple_controls_all_assessed(self):
        """Two controls produce two verdicts in the final report."""
        synth = _mock_synthesizer(SynthesizerOutput(verdict=VerdictClass.gap, rationale="finding"))
        ver = _mock_verifier(VerifierDecision(approved=True, notes="ok"))

        report = _run(
            FIXTURES / "insecure_terraform_app",
            [_ctrl("AC-6"), _ctrl("SC-8")],
            synth,
            ver,
        )

        assert len(report.verdicts) == 2
        ids = {v.control_id for v in report.verdicts}
        assert ids == {"AC-6", "SC-8"}

    def test_happy_path_verdict_attempt_is_one(self):
        """A first-pass approved verdict records attempt=1."""
        synth = _mock_synthesizer(SynthesizerOutput(verdict=VerdictClass.gap, rationale="gap"))
        ver = _mock_verifier(VerifierDecision(approved=True, notes="ok"))

        report = _run(FIXTURES / "insecure_terraform_app", [_ctrl("AC-6")], synth, ver)

        assert report.verdicts[0].attempt == 1

    def test_final_report_contains_audit_metadata(self):
        """FinalReport.audit has run_id, started_at, model_id, and verdict counts."""
        synth = _mock_synthesizer(SynthesizerOutput(verdict=VerdictClass.gap, rationale="gap"))
        ver = _mock_verifier(VerifierDecision(approved=True, notes="ok"))

        report = _run(FIXTURES / "insecure_terraform_app", [_ctrl("AC-6")], synth, ver)

        audit = report.audit
        assert "run_id" in audit
        assert "started_at" in audit
        assert "model_id" in audit
        assert "controls_assessed" in audit
        assert audit["controls_assessed"] == 1
        assert "gap_count" in audit
        assert audit["gap_count"] == 1
        assert "satisfied_count" in audit
        assert "not_assessable_count" in audit

    def test_audit_run_id_is_uuid(self):
        """Audit run_id is a valid UUID string."""
        synth = _mock_synthesizer(SynthesizerOutput(verdict=VerdictClass.gap, rationale="gap"))
        ver = _mock_verifier(VerifierDecision(approved=True, notes="ok"))

        report = _run(FIXTURES / "insecure_terraform_app", [_ctrl("AC-6")], synth, ver)

        # Raises ValueError if not a valid UUID.
        uuid.UUID(report.audit["run_id"])

    def test_empty_controls_produces_empty_report(self):
        """Zero controls → FinalReport with empty verdicts list (no LLM calls)."""
        report = _run(FIXTURES / "insecure_terraform_app", [])

        assert report.verdicts == []
        assert report.audit["controls_assessed"] == 0


# ── Verifier loop ──────────────────────────────────────────────────────────────


class TestVerifierLoop:
    def test_verifier_loop_retries_once_then_approves(self):
        """Verifier rejects on attempt 1, approves on attempt 2 → attempt=2 in verdict."""
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.gap, rationale="gap v1"),
            SynthesizerOutput(verdict=VerdictClass.gap, rationale="gap v2"),
        )
        ver = _mock_verifier(
            VerifierDecision(approved=False, notes="needs more detail"),
            VerifierDecision(approved=True, notes="ok now"),
        )

        report = _run(FIXTURES / "insecure_terraform_app", [_ctrl("AC-6")], synth, ver)

        assert len(report.verdicts) == 1
        v = report.verdicts[0]
        assert v.verdict == VerdictClass.gap
        assert v.verifier_status == "passed"
        assert v.attempt == 2

    def test_verifier_loop_stops_at_cap(self):
        """Verifier always rejects → after MAX_VERIFIER_ATTEMPTS the verdict is downgraded."""
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.gap, rationale="gap"),
        )
        ver = _mock_verifier(
            VerifierDecision(approved=False, notes="rejected"),
        )

        report = _run(FIXTURES / "insecure_terraform_app", [_ctrl("AC-6")], synth, ver)

        assert len(report.verdicts) == 1
        v = report.verdicts[0]
        # Exhausted verifier → downgraded to not_assessable
        assert v.verdict == VerdictClass.not_assessable
        assert v.verifier_status == "failed"
        assert "verifier-exhausted" in v.rationale

    def test_verifier_loop_cap_is_max_verifier_attempts(self):
        """The loop cap equals MAX_VERIFIER_ATTEMPTS (i.e., exactly that many verify calls)."""
        synth = _mock_synthesizer(SynthesizerOutput(verdict=VerdictClass.gap, rationale="gap"))
        # Track verify call count
        call_log: list[int] = []
        ver_mock = MagicMock()

        def ver_side(messages):
            call_log.append(1)
            return VerifierDecision(approved=False, notes="rejected")

        ver_mock.invoke.side_effect = ver_side

        _run(FIXTURES / "insecure_terraform_app", [_ctrl("AC-6")], synth, ver_mock)

        assert len(call_log) == MAX_VERIFIER_ATTEMPTS

    def test_unsupported_satisfied_is_rejected_and_downgraded(self):
        """Synthesizer always emits 'satisfied' with no real evidence and verifier always rejects it."""
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.satisfied, rationale="looks fine"),
        )
        ver = _mock_verifier(
            VerifierDecision(approved=False, notes="no evidence for satisfied"),
        )

        # Use a repo with no terraform — no scanner evidence for AC-6
        report = _run(FIXTURES / "secure_terraform_app", [_ctrl("AC-6")], synth, ver)

        v = report.verdicts[0]
        # Downgraded: no evidence → fail-closed guard fires before verifier-exhausted path.
        assert v.verdict == VerdictClass.not_assessable
        assert v.verifier_status == "failed"
        assert "[fail-closed" in v.rationale or "verifier-exhausted" in v.rationale


# ── Evidence provenance ────────────────────────────────────────────────────────


class TestEvidenceProvenance:
    def test_verdict_evidence_comes_from_scanner_not_llm(self):
        """Evidence in the verdict is always from the scanner (EvidenceRef list), never LLM-invented."""
        synth = _mock_synthesizer(SynthesizerOutput(verdict=VerdictClass.gap, rationale="gap"))
        ver = _mock_verifier(VerifierDecision(approved=True, notes="ok"))

        report = _run(FIXTURES / "insecure_terraform_app", [_ctrl("AC-6")], synth, ver)

        # The verdict must contain the scanner evidence, not an empty list invented by the LLM.
        v = report.verdicts[0]
        # insecure_terraform_app has wildcard IAM — AC-6 should have evidence
        assert v.evidence, "Expected scanner evidence in verdict"
        # All EvidenceRef must have source_type from the scanner
        for ref in v.evidence:
            assert ref.source_type in ("tool_result", "repo_file", "control_kb")

    def test_verdict_repo_path_matches_input(self):
        """FinalReport.repo_path is the resolved path of the assessed repository."""
        synth = _mock_synthesizer(SynthesizerOutput(verdict=VerdictClass.gap, rationale="gap"))
        ver = _mock_verifier(VerifierDecision(approved=True, notes="ok"))

        root = FIXTURES / "insecure_terraform_app"
        report = _run(root, [_ctrl("AC-6")], synth, ver)

        assert report.repo_path == str(root.resolve())

    def test_satisfied_without_evidence_is_fail_closed(self, tmp_path):
        """Verifier-approved 'satisfied' with no scanner evidence is downgraded deterministically."""
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.satisfied, rationale="looks fine"),
        )
        ver = _mock_verifier(VerifierDecision(approved=True, notes="approved"))

        # Empty repo — no Terraform/IaC files → guaranteed empty scanner evidence for any control.
        report = _run(tmp_path, [_ctrl("AC-6")], synth, ver)

        v = report.verdicts[0]
        assert v.verdict == VerdictClass.not_assessable
        assert v.verifier_status == "failed"
        assert "[fail-closed" in v.rationale

    def test_gap_without_evidence_is_fail_closed(self, tmp_path):
        """Verifier-approved 'gap' with no scanner evidence is downgraded — guard covers all verdicts."""
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.gap, rationale="no encryption config seen"),
        )
        ver = _mock_verifier(VerifierDecision(approved=True, notes="approved"))

        # Empty repo — no Terraform/IaC files → guaranteed empty scanner evidence for any control.
        report = _run(tmp_path, [_ctrl("AC-6")], synth, ver)

        v = report.verdicts[0]
        assert v.verdict == VerdictClass.not_assessable
        assert v.verifier_status == "failed"
        assert "[fail-closed" in v.rationale
        assert "gap" in v.rationale

    def test_tool_error_downgrades_affirmative_verdict(self):
        """Collection errors downgrade any affirmative verdict to not_assessable in code."""
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.gap, rationale="gap from error scan"),
        )
        ver = _mock_verifier(VerifierDecision(approved=True, notes="approved"))

        error_collection = CollectionResult(
            control_id="AC-6",
            evidence=[],
            errors=["scan_iac_security: timeout after 30s"],
            limitations=[],
        )
        with patch("agentic_compliance.graph.collect_evidence", return_value=error_collection):
            report = _run(FIXTURES / "insecure_terraform_app", [_ctrl("AC-6")], synth, ver)

        v = report.verdicts[0]
        assert v.verdict == VerdictClass.not_assessable
        assert v.verifier_status == "failed"
        assert "[fail-closed" in v.rationale
        assert "gap" in v.rationale

    def test_affirmative_verdict_with_evidence_is_not_fail_closed(self):
        """Verifier-approved verdict WITH scanner evidence is emitted unchanged."""
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.satisfied, rationale="IAM is scoped"),
        )
        ver = _mock_verifier(VerifierDecision(approved=True, notes="approved"))

        # insecure_terraform_app has wildcard IAM findings → non-empty evidence for AC-6.
        report = _run(FIXTURES / "insecure_terraform_app", [_ctrl("AC-6")], synth, ver)

        v = report.verdicts[0]
        assert v.verdict == VerdictClass.satisfied
        assert v.verifier_status == "passed"


# ── CHAT_MODEL backstop ──────────────────────────────────────────────────────


class TestRequireChatModel:
    def test_raises_clear_error_when_unset(self, monkeypatch):
        """Missing CHAT_MODEL raises RuntimeError with an actionable message, not a bare KeyError.

        Regression guard: this is the backstop for callers that bypass the CLI's own
        pre-flight check (tests calling run_assessment/the graph directly, langgraph dev).
        """
        monkeypatch.delenv("CHAT_MODEL", raising=False)
        with pytest.raises(RuntimeError, match="CHAT_MODEL"):
            _require_chat_model()

    def test_returns_value_when_set(self, monkeypatch):
        """CHAT_MODEL set → returned as-is."""
        monkeypatch.setenv("CHAT_MODEL", "anthropic:claude-sonnet-4-6")
        assert _require_chat_model() == "anthropic:claude-sonnet-4-6"


# ── State schema ───────────────────────────────────────────────────────────────


class TestStateSchema:
    def test_initial_state_is_well_formed(self):
        """_initial_state produces a valid ComplianceState with correct defaults."""
        controls = [_ctrl("AC-6")]
        state = _initial_state(FIXTURES / "insecure_terraform_app", controls)

        assert state["control_idx"] == 0
        assert state["verifier_attempts"] == 0
        assert state["verifier_notes"] == []
        assert state["verdicts"] == []
        assert state["collection"] is None
        assert state["draft_verdict"] is None
        assert state["final_report"] is None
        assert len(state["controls"]) == 1

    def test_control_verdict_round_trips(self):
        """ControlVerdict serialises and re-parses without data loss."""
        v = ControlVerdict(
            control_id="AC-6",
            verdict=VerdictClass.gap,
            evidence=[],
            rationale="wildcard IAM",
            verifier_status="passed",
            attempt=1,
        )
        assert ControlVerdict.model_validate(v.model_dump()) == v

    def test_final_report_round_trips(self):
        """FinalReport serialises and re-parses without data loss."""
        r = FinalReport(
            repo_path="/tmp/repo",
            verdicts=[],
            audit={"run_id": "abc", "controls_assessed": 0},
        )
        assert FinalReport.model_validate(r.model_dump()) == r
