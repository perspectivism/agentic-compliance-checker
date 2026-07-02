"""Tests for the M7 evaluation harness (src/agentic_compliance/evaluation.py).

The fast-lane tests inject a fake assess function so no LLM, network, or KB is
involved — they exercise grouping, scoring, gating, fail-safe error handling, and
report serialization. The single live-graph test is marked @pytest.mark.agent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agentic_compliance.evaluation import (
    DEFAULT_THRESHOLD,
    LABELS,
    compute_metrics,
    evaluate_golden_set,
    resolve_threshold,
    run_eval,
)
from agentic_compliance.schemas import ControlVerdict, FinalReport, VerdictClass

FIXTURES_ROOT = Path(__file__).parent / "fixtures" / "repos"


def _case(
    case_id: str,
    fixture: str,
    control_id: str,
    expected: str,
    human_verified: bool = True,
) -> dict:
    return {
        "id": case_id,
        "repo_fixture": fixture,
        "control_id": control_id,
        "question": f"Is {control_id} satisfied?",
        "expected_verdict": expected,
        "expected_evidence_hints": [],
        "human_verified": human_verified,
    }


def _write_golden(tmp_path: Path, cases: list[dict]) -> Path:
    path = tmp_path / "golden.yaml"
    path.write_text(yaml.safe_dump({"cases": cases}))
    return path


def _make_fixtures(tmp_path: Path, names: list[str]) -> Path:
    root = tmp_path / "fixtures"
    for name in names:
        (root / name).mkdir(parents=True)
    return root


def _fake_report(repo_root: Path, verdicts: dict[str, str]) -> FinalReport:
    return FinalReport(
        repo_path=str(repo_root),
        verdicts=[
            ControlVerdict(
                control_id=cid,
                verdict=VerdictClass(v),
                evidence=[],
                rationale=f"fake rationale for {cid}",
                verifier_status="passed",
                attempt=1,
            )
            for cid, v in verdicts.items()
        ],
        audit={},
    )


def _fake_assess_fn(predictions: dict[str, dict[str, str]]):
    """Build an assess_fn returning canned verdicts keyed by fixture dir name."""

    def assess(repo_root: Path, control_ids: list[str]) -> FinalReport:
        fixture_verdicts = predictions[repo_root.name]
        return _fake_report(repo_root, {c: fixture_verdicts[c] for c in control_ids})

    return assess


# One case per verdict class, split across two fixtures — the smallest golden set
# that exercises every row of the confusion matrix.
_FOUR_CLASS_CASES = [
    _case("a_1", "fix_a", "SC-8", "satisfied"),
    _case("a_2", "fix_a", "AC-6", "gap"),
    _case("b_1", "fix_b", "SC-7", "partial"),
    _case("b_2", "fix_b", "CM-3", "not_assessable"),
]

_PERFECT_PREDICTIONS = {
    "fix_a": {"SC-8": "satisfied", "AC-6": "gap"},
    "fix_b": {"SC-7": "partial", "CM-3": "not_assessable"},
}


class TestGate:
    """Exit-code gating on macro-F1, errors, and configuration problems."""

    def test_perfect_predictions_pass(self, tmp_path, capsys):
        """All-correct predictions score macro-F1 1.0 and exit 0."""
        golden = _write_golden(tmp_path, _FOUR_CLASS_CASES)
        root = _make_fixtures(tmp_path, ["fix_a", "fix_b"])
        out = tmp_path / "eval" / "latest.json"

        code = run_eval(golden, root, out, assess_fn=_fake_assess_fn(_PERFECT_PREDICTIONS))

        assert code == 0
        report = json.loads(out.read_text())
        assert report["macro_f1"] == 1.0
        assert report["passed"] is True
        assert report["num_cases"] == 4
        assert report["num_errors"] == 0
        assert report["failures"] == []
        assert "PASSED" in capsys.readouterr().out

    def test_wrong_predictions_fail_gate(self, tmp_path):
        """Mispredictions below the threshold exit 1 but still write the report."""
        wrong = {
            "fix_a": {"SC-8": "gap", "AC-6": "satisfied"},
            "fix_b": {"SC-7": "not_assessable", "CM-3": "partial"},
        }
        golden = _write_golden(tmp_path, _FOUR_CLASS_CASES)
        root = _make_fixtures(tmp_path, ["fix_a", "fix_b"])
        out = tmp_path / "latest.json"

        code = run_eval(golden, root, out, assess_fn=_fake_assess_fn(wrong))

        assert code == 1
        report = json.loads(out.read_text())
        assert report["passed"] is False
        assert report["macro_f1"] == 0.0
        assert len(report["failures"]) == 4

    def test_gate_passes_at_exact_threshold(self, tmp_path):
        """macro_f1 == threshold passes — the gate is >=, not >."""
        golden = _write_golden(tmp_path, _FOUR_CLASS_CASES)
        root = _make_fixtures(tmp_path, ["fix_a", "fix_b"])

        code = run_eval(
            golden,
            root,
            tmp_path / "latest.json",
            threshold=1.0,
            assess_fn=_fake_assess_fn(_PERFECT_PREDICTIONS),
        )
        assert code == 0

    def test_missing_golden_is_config_error(self, tmp_path, capsys):
        """A missing golden set exits 2 (config), not 1 (quality)."""
        code = run_eval(
            tmp_path / "nope.yaml",
            tmp_path,
            tmp_path / "latest.json",
            assess_fn=_fake_assess_fn({}),
        )
        assert code == 2
        assert "configuration error" in capsys.readouterr().err

    def test_zero_verified_cases_is_config_error(self, tmp_path):
        """A golden set with no human_verified cases has no ground truth — exit 2."""
        golden = _write_golden(
            tmp_path, [_case("a_1", "fix_a", "SC-8", "satisfied", human_verified=False)]
        )
        code = run_eval(golden, tmp_path, tmp_path / "latest.json", assess_fn=_fake_assess_fn({}))
        assert code == 2

    def test_missing_chat_model_is_config_error(self, tmp_path, monkeypatch, capsys):
        """Default (real-graph) mode without CHAT_MODEL fails fast with exit 2."""
        monkeypatch.delenv("CHAT_MODEL", raising=False)
        code = run_eval(tmp_path / "golden.yaml", tmp_path, tmp_path / "latest.json")
        assert code == 2
        assert "CHAT_MODEL" in capsys.readouterr().err


class TestFailSafe:
    """Assessment errors are recorded per case and fail the run — never faked or fatal."""

    def test_fixture_assessment_error_fails_run_but_scores_the_rest(self, tmp_path):
        """One fixture raising records errors for its cases and exits 1; others still score."""

        def assess(repo_root: Path, control_ids: list[str]) -> FinalReport:
            if repo_root.name == "fix_b":
                raise RuntimeError("scanner exploded")
            return _fake_report(repo_root, {"SC-8": "satisfied", "AC-6": "gap"})

        golden = _write_golden(tmp_path, _FOUR_CLASS_CASES)
        root = _make_fixtures(tmp_path, ["fix_a", "fix_b"])
        out = tmp_path / "latest.json"

        code = run_eval(golden, root, out, assess_fn=assess)

        assert code == 1
        report = json.loads(out.read_text())
        assert report["num_errors"] == 2
        assert report["num_cases"] == 2  # fix_a's cases still scored
        assert report["passed"] is False
        errored = [c for c in report["cases"] if c["error"]]
        assert all("scanner exploded" in c["error"] for c in errored)
        assert all(c["predicted"] is None for c in errored)

    def test_missing_fixture_dir_records_error(self, tmp_path):
        """A golden case naming a nonexistent fixture directory errors, not crashes."""
        golden = _write_golden(tmp_path, [_case("a_1", "ghost_fixture", "SC-8", "satisfied")])
        root = _make_fixtures(tmp_path, [])  # no fixture dirs at all
        out = tmp_path / "latest.json"

        code = run_eval(golden, root, out, assess_fn=_fake_assess_fn({}))

        assert code == 1
        report = json.loads(out.read_text())
        assert report["num_errors"] == 1
        assert "not found" in report["cases"][0]["error"]

    def test_missing_verdict_for_control_records_error(self, tmp_path):
        """A report lacking a requested control's verdict errors that case only."""

        def assess(repo_root: Path, control_ids: list[str]) -> FinalReport:
            return _fake_report(repo_root, {"SC-8": "satisfied"})  # AC-6 missing

        golden = _write_golden(
            tmp_path,
            [_case("a_1", "fix_a", "SC-8", "satisfied"), _case("a_2", "fix_a", "AC-6", "gap")],
        )
        root = _make_fixtures(tmp_path, ["fix_a"])
        report = evaluate_golden_set(golden, root, assess_fn=assess)

        assert report.num_errors == 1
        assert report.num_cases == 1
        errored = [c for c in report.cases if c.error]
        assert errored[0].control_id == "AC-6"
        error = errored[0].error
        assert error is not None and "no verdict returned" in error


class TestReportContents:
    """Report structure matches the docs/EVAL_PLAN.md schema."""

    def test_report_has_required_schema_keys(self, tmp_path):
        """All EVAL_PLAN minimum-schema keys are present in the written JSON."""
        golden = _write_golden(tmp_path, _FOUR_CLASS_CASES)
        root = _make_fixtures(tmp_path, ["fix_a", "fix_b"])
        out = tmp_path / "latest.json"
        run_eval(golden, root, out, assess_fn=_fake_assess_fn(_PERFECT_PREDICTIONS))

        report = json.loads(out.read_text())
        for key in (
            "run_id",
            "timestamp",
            "num_cases",
            "macro_f1",
            "weighted_f1",
            "per_class",
            "confusion_matrix",
            "verifier_stats",
            "failures",
        ):
            assert key in report

    def test_confusion_matrix_is_stable_four_by_four(self, tmp_path):
        """Confusion matrix always uses the full 4-class canonical label order."""
        golden = _write_golden(tmp_path, _FOUR_CLASS_CASES[:1])  # single satisfied case
        root = _make_fixtures(tmp_path, ["fix_a"])
        report = evaluate_golden_set(
            golden, root, assess_fn=_fake_assess_fn({"fix_a": {"SC-8": "satisfied"}})
        )
        assert report.labels == LABELS
        assert len(report.confusion_matrix) == 4
        assert all(len(row) == 4 for row in report.confusion_matrix)

    def test_unverified_cases_are_excluded(self, tmp_path):
        """Only human_verified cases are assessed and scored (D8)."""
        seen: list[list[str]] = []

        def assess(repo_root: Path, control_ids: list[str]) -> FinalReport:
            seen.append(control_ids)
            return _fake_report(repo_root, {"SC-8": "satisfied"})

        golden = _write_golden(
            tmp_path,
            [
                _case("a_1", "fix_a", "SC-8", "satisfied"),
                _case("a_2", "fix_a", "AC-6", "gap", human_verified=False),
            ],
        )
        root = _make_fixtures(tmp_path, ["fix_a"])
        report = evaluate_golden_set(golden, root, assess_fn=assess)

        assert seen == [["SC-8"]]  # AC-6 never requested
        assert report.num_cases == 1

    def test_failures_include_rationale_for_analysis(self, tmp_path):
        """Mispredicted cases carry the predicted verdict's rationale."""
        golden = _write_golden(tmp_path, [_case("a_1", "fix_a", "SC-8", "satisfied")])
        root = _make_fixtures(tmp_path, ["fix_a"])
        report = evaluate_golden_set(
            golden, root, assess_fn=_fake_assess_fn({"fix_a": {"SC-8": "gap"}})
        )
        assert len(report.failures) == 1
        failure = report.failures[0]
        assert failure.expected == VerdictClass.satisfied
        assert failure.predicted == VerdictClass.gap
        assert "fake rationale" in failure.rationale


class TestThresholdResolution:
    """Threshold precedence: explicit arg > env var > 0.70 default; bad values fail loudly."""

    def test_default_is_070(self, monkeypatch):
        """No arg and no env var falls back to the EVAL_PLAN default."""
        monkeypatch.delenv("EVAL_MACRO_F1_THRESHOLD", raising=False)
        assert resolve_threshold() == DEFAULT_THRESHOLD == 0.70

    def test_env_var_is_used(self, monkeypatch):
        """EVAL_MACRO_F1_THRESHOLD overrides the default."""
        monkeypatch.setenv("EVAL_MACRO_F1_THRESHOLD", "0.85")
        assert resolve_threshold() == 0.85

    def test_explicit_arg_beats_env(self, monkeypatch):
        """A CLI-provided threshold wins over the env var."""
        monkeypatch.setenv("EVAL_MACRO_F1_THRESHOLD", "0.85")
        assert resolve_threshold(0.5) == 0.5

    def test_unparseable_env_raises(self, monkeypatch):
        """A typo'd env threshold must not silently weaken the gate."""
        monkeypatch.setenv("EVAL_MACRO_F1_THRESHOLD", "seventy")
        with pytest.raises(RuntimeError, match="EVAL_MACRO_F1_THRESHOLD"):
            resolve_threshold()

    def test_out_of_range_raises(self):
        """Thresholds outside [0, 1] are rejected."""
        with pytest.raises(RuntimeError, match="0, 1"):
            resolve_threshold(1.5)


class TestComputeMetrics:
    """Direct metric-function behavior on edge cases."""

    def test_zero_scored_cases_score_zero(self):
        """No scorable predictions yields all-zero metrics — the gate cannot pass."""
        metrics = compute_metrics([])
        assert metrics["macro_f1"] == 0.0
        assert metrics["weighted_f1"] == 0.0
        assert metrics["confusion_matrix"] == [[0] * 4 for _ in range(4)]

    def test_absent_class_does_not_zero_drag_macro_f1(self, tmp_path):
        """A class absent from both truth and predictions is excluded from macro-F1."""
        golden = _write_golden(tmp_path, [_case("a_1", "fix_a", "SC-8", "satisfied")])
        root = _make_fixtures(tmp_path, ["fix_a"])
        report = evaluate_golden_set(
            golden, root, assess_fn=_fake_assess_fn({"fix_a": {"SC-8": "satisfied"}})
        )
        # One correct case: macro over present labels only == 1.0, not 0.25.
        assert report.macro_f1 == 1.0


@pytest.mark.agent
class TestLiveEval:
    """A minimal real-graph run — costs a few LLM calls; skips without CHAT_MODEL."""

    def test_live_eval_single_deterministic_case(self, tmp_path):
        """no_iac_repo × SC-28 must come back not_assessable via the fail-closed guard.

        The fixture has no IaC files, so evidence collection is empty and
        finalize_control_node deterministically downgrades any affirmative verdict —
        the expected verdict does not depend on what the LLM answers.
        """
        import os

        from dotenv import find_dotenv, load_dotenv

        load_dotenv(find_dotenv(usecwd=True))
        if not os.environ.get("CHAT_MODEL"):
            pytest.skip("CHAT_MODEL not configured — live eval test needs a real model")

        golden = _write_golden(
            tmp_path, [_case("live_1", "no_iac_repo", "SC-28", "not_assessable")]
        )
        out = tmp_path / "latest.json"
        code = run_eval(golden, FIXTURES_ROOT, out)

        assert code == 0
        report = json.loads(out.read_text())
        assert report["num_cases"] == 1
        assert report["num_errors"] == 0
        assert report["cases"][0]["predicted"] == "not_assessable"
        assert report["verifier_stats"]["controls_assessed"] == 1
