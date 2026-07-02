"""Run logger — JSONL emission, node instrumentation, and the no-secret-leak guarantee."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agentic_compliance.graph import _build_graph, _initial_state
from agentic_compliance.kb import build_exact_index, load_controls
from agentic_compliance.run_log import (
    InMemoryRunLogger,
    JSONLRunLogger,
    NoopRunLogger,
    instrument_node,
    safe_error_fields,
)
from agentic_compliance.schemas import (
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


def _run_with_logger(repo_root: Path, controls, logger, synthesizer=None, verifier=None):
    state = _initial_state(repo_root, controls)
    g = _build_graph(synthesizer=synthesizer, verifier=verifier, logger=logger)
    result = g.invoke(state, config={"recursion_limit": GRAPH_RECURSION_LIMIT})
    return FinalReport.model_validate(result["final_report"])


class TestInstrumentNode:
    """Unit behavior of instrument_node() in isolation from the graph."""

    def test_wraps_and_returns_result_unchanged(self):
        """The wrapped function's return value passes through untouched."""
        logger = InMemoryRunLogger()
        fn = instrument_node("collect", lambda state: {"ok": True}, logger)
        assert fn({}) == {"ok": True}

    def test_emits_start_and_end_events(self):
        """node_start then node_end, both tagged with the node name."""
        logger = InMemoryRunLogger()
        fn = instrument_node("collect", lambda state: {}, logger)
        fn({})
        events = [e["event"] for e in logger.events]
        assert events == ["node_start", "node_end"]
        assert all(e["node"] == "collect" for e in logger.events)

    def test_end_event_has_duration(self):
        """node_end carries a numeric duration_ms field."""
        logger = InMemoryRunLogger()
        fn = instrument_node("collect", lambda state: {}, logger)
        fn({})
        end = logger.events[1]
        assert isinstance(end["duration_ms"], int | float)
        assert end["duration_ms"] >= 0

    def test_exception_logs_node_error_and_reraises(self):
        """A raised exception is logged (type only) and still propagates unchanged."""
        logger = InMemoryRunLogger()

        def boom(state):
            raise ValueError("boom")

        fn = instrument_node("collect", boom, logger)
        with pytest.raises(ValueError, match="boom"):
            fn({})
        events = [e["event"] for e in logger.events]
        assert events == ["node_start", "node_error"]
        assert logger.events[1]["error_type"] == "ValueError"

    def test_exception_message_is_never_logged(self):
        """The exception's str() never reaches the log, regardless of length.

        Length-capping a message only bounds size, not content — any secret-shaped
        text within the cap would still reach the log verbatim. Only the exception
        type name is logged.
        """
        logger = InMemoryRunLogger()
        secret = "AKIAIOSFODNN7EXAMPLE"

        def boom(state):
            raise ValueError(f"parse failed near {secret}")

        fn = instrument_node("collect", boom, logger)
        with contextlib.suppress(ValueError):
            fn({})
        assert secret not in json.dumps(logger.events)
        assert "error" not in logger.events[1]
        assert logger.events[1]["error_type"] == "ValueError"


class TestSafeErrorFields:
    """safe_error_fields() is the single source of truth for exception logging."""

    def test_returns_only_error_type(self):
        """The dict contains error_type and nothing derived from the message."""
        fields = safe_error_fields(ValueError("some secret-shaped text"))
        assert fields == {"error_type": "ValueError"}

    def test_message_content_never_appears_in_the_result(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        fields = safe_error_fields(RuntimeError(f"failed on {secret}"))
        assert secret not in json.dumps(fields)


class TestJSONLRunLogger:
    """File-writing behavior of JSONLRunLogger."""

    def test_writes_one_json_line_per_event(self, tmp_path):
        """Each log() call appends exactly one valid JSON line."""
        logger = JSONLRunLogger(run_id="abc123", out_dir=tmp_path)
        logger.log("run_start", repo_root="/tmp/x")
        logger.log("run_end", satisfied_count=1)

        lines = logger.path.read_text().splitlines()
        assert len(lines) == 2
        records = [json.loads(line) for line in lines]
        assert records[0]["event"] == "run_start"
        assert records[1]["event"] == "run_end"

    def test_path_is_named_by_run_id(self, tmp_path):
        """Log file path follows <out_dir>/<run_id>.jsonl."""
        logger = JSONLRunLogger(run_id="my-run-id", out_dir=tmp_path)
        assert logger.path == tmp_path / "my-run-id.jsonl"

    def test_every_record_has_run_id_and_timestamp(self, tmp_path):
        """run_id and ts are stamped on every event automatically."""
        logger = JSONLRunLogger(run_id="abc123", out_dir=tmp_path)
        logger.log("node_start", node="collect")
        record = json.loads(logger.path.read_text())
        assert record["run_id"] == "abc123"
        assert "ts" in record

    def test_creates_out_dir_if_missing(self, tmp_path):
        """out_dir is created on construction, not assumed to exist."""
        nested = tmp_path / "does" / "not" / "exist"
        JSONLRunLogger(run_id="abc123", out_dir=nested)
        assert nested.is_dir()


class TestNoopRunLogger:
    def test_log_is_a_no_op(self):
        """NoopRunLogger.log() does nothing observable and never raises."""
        NoopRunLogger().log("anything", foo="bar")  # must not raise


class TestGraphEmitsRunLog:
    """End-to-end: running the graph with a real logger produces the expected event shape."""

    def test_single_control_run_emits_expected_events(self):
        """A one-control approved run: collect's tool_call, verify's verifier_attempt,

        finalize's verdict_finalized, and node timing for every node all appear.
        """
        logger = InMemoryRunLogger()
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.gap, rationale="Wildcard IAM found")
        )
        verif = _mock_verifier(VerifierDecision(approved=True, notes="Grounded"))

        _run_with_logger(
            FIXTURES / "insecure_terraform_app",
            [_ctrl("AC-6")],
            logger,
            synthesizer=synth,
            verifier=verif,
        )

        events = [e["event"] for e in logger.events]
        assert "tool_call" in events
        assert "verifier_attempt" in events
        assert "verdict_finalized" in events
        assert "node_start" in events and "node_end" in events

    def test_tool_call_event_has_no_evidence_content(self):
        """tool_call carries counts and control/tool identifiers only, never excerpts."""
        logger = InMemoryRunLogger()
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.gap, rationale="Wildcard IAM found")
        )
        verif = _mock_verifier(VerifierDecision(approved=True, notes="Grounded"))

        _run_with_logger(
            FIXTURES / "insecure_terraform_app",
            [_ctrl("AC-6")],
            logger,
            synthesizer=synth,
            verifier=verif,
        )

        tool_call = next(e for e in logger.events if e["event"] == "tool_call")
        assert set(tool_call) == {
            "event",
            "control_id",
            "tools",
            "evidence_count",
            "error_count",
            "limitation_count",
        }

    def test_verifier_attempt_event_omits_raw_notes(self):
        """verifier_attempt logs notes_present, never the verifier's freeform notes text."""
        logger = InMemoryRunLogger()
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.gap, rationale="Wildcard IAM found")
        )
        verif = _mock_verifier(
            VerifierDecision(approved=False, notes="secret-shaped-text-should-not-be-logged"),
            VerifierDecision(approved=True, notes="ok"),
        )

        _run_with_logger(
            FIXTURES / "insecure_terraform_app",
            [_ctrl("AC-6")],
            logger,
            synthesizer=synth,
            verifier=verif,
        )

        attempts = [e for e in logger.events if e["event"] == "verifier_attempt"]
        assert len(attempts) == 2
        assert attempts[0]["notes_present"] is True
        for e in logger.events:
            assert "secret-shaped-text-should-not-be-logged" not in json.dumps(e)

    def test_no_raw_secret_in_run_log(self, tmp_path):
        """The fixture's hardcoded AWS example key never appears in any logged event,

        even when the assessed control is IA-5 (secrets handling) directly.
        """
        secret = "AKIAIOSFODNN7EXAMPLE"
        logger = JSONLRunLogger(run_id="secret-leak-check", out_dir=tmp_path)
        synth = _mock_synthesizer(
            SynthesizerOutput(verdict=VerdictClass.gap, rationale="Secret found")
        )
        verif = _mock_verifier(VerifierDecision(approved=True, notes="Grounded"))

        _run_with_logger(
            FIXTURES / "hardcoded_secret_app",
            [_ctrl("IA-5")],
            logger,
            synthesizer=synth,
            verifier=verif,
        )

        raw_log = logger.path.read_text()
        assert secret not in raw_log

    def test_no_raw_secret_in_run_log_when_a_node_raises(self, tmp_path):
        """A node that raises with secret-shaped text in its exception message must

        not leak that text into the run log — end to end, through the real graph,
        not just the isolated instrument_node() unit test above.
        """
        secret = "AKIAIOSFODNN7EXAMPLE"
        logger = JSONLRunLogger(run_id="secret-leak-on-exception", out_dir=tmp_path)

        def exploding_synthesizer_invoke(messages):
            raise RuntimeError(f"parse failed near {secret}")

        synth = MagicMock()
        synth.invoke.side_effect = exploding_synthesizer_invoke

        with pytest.raises(RuntimeError):
            _run_with_logger(
                FIXTURES / "hardcoded_secret_app",
                [_ctrl("IA-5")],
                logger,
                synthesizer=synth,
                verifier=_mock_verifier(VerifierDecision(approved=True, notes="ok")),
            )

        raw_log = logger.path.read_text()
        assert secret not in raw_log
        assert '"error_type": "RuntimeError"' in raw_log
