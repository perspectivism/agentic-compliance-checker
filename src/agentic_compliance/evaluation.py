"""Evaluation harness: verdict accuracy of the graph against the frozen golden set.

Loads `data/golden_set.yaml`, runs the assessment graph once per fixture repo using
explicit control selection (exactly the controls that fixture's verified cases name —
this measures verdict quality given a control; selection quality has its own
regression tests), scores predictions with scikit-learn, and writes a JSON report
matching the schema in docs/EVAL_PLAN.md.

Grounding metrics (RAGAS) are the optional second evaluation layer (docs/DECISIONS.md
D7) and are deliberately not implemented here: they add an LLM-as-judge dependency
with its own cost/variance, and verdict accuracy is the required layer. See
docs/EVAL_PLAN.md → "Grounding metrics".

Fail-safe behavior:
- Only human_verified cases count as ground truth (docs/DECISIONS.md D8).
- A fixture whose assessment raises is recorded as an error (predicted=None),
  excluded from the metrics, and forces a nonzero exit — it never becomes a fake
  prediction and never aborts the rest of the run.
- Zero scorable cases can never "pass" the gate.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from .golden import GoldenSetError, load_golden_cases, verified_cases
from .schemas import FinalReport, GoldenCase, VerdictClass

# Canonical label order for the confusion matrix and per-class report, so rows/columns
# are stable across runs regardless of which classes appear in a given golden set.
LABELS: list[str] = [v.value for v in VerdictClass]

DEFAULT_THRESHOLD = 0.70  # docs/EVAL_PLAN.md: the default macro-F1 quality gate

# assess_fn contract: (fixture repo root, control IDs to assess) -> FinalReport.
# Injectable so the deterministic fast-lane tests never touch the real graph/LLM.
AssessFn = Callable[[Path, list[str]], FinalReport]

# Keep rationales in the report useful for failure analysis without letting one
# verbose LLM answer bloat the JSON.
_MAX_RATIONALE_CHARS = 300


class EvalCaseResult(BaseModel):
    """Outcome of evaluating one golden case against the agent's prediction."""

    case_id: str
    repo_fixture: str
    control_id: str
    expected: VerdictClass
    predicted: VerdictClass | None = None  # None when the assessment errored
    rationale: str = ""  # predicted verdict's rationale (truncated), for failure analysis
    error: str | None = None


class EvalReport(BaseModel):
    """Complete evaluation report — serialized to artifacts/eval/latest.json."""

    run_id: str
    timestamp: str
    num_cases: int  # scored cases (predicted is not None)
    num_errors: int
    macro_f1: float
    weighted_f1: float
    threshold: float
    passed: bool  # macro_f1 >= threshold AND no errors AND at least one scored case
    labels: list[str]
    per_class: dict
    confusion_matrix: list[list[int]]
    verifier_stats: dict
    failures: list[EvalCaseResult]  # mispredictions and errors only
    cases: list[EvalCaseResult]  # every case, for full auditability


def resolve_threshold(explicit: float | None = None) -> float:
    """Resolve the macro-F1 gate threshold: explicit arg > EVAL_MACRO_F1_THRESHOLD env > 0.70.

    An unparseable or out-of-range env value raises rather than silently falling back —
    a typo'd threshold must not quietly weaken (or fake-tighten) the CI gate.
    """
    if explicit is not None:
        value = explicit
    else:
        raw = os.environ.get("EVAL_MACRO_F1_THRESHOLD")
        if raw is None:
            return DEFAULT_THRESHOLD
        try:
            value = float(raw)
        except ValueError:
            raise RuntimeError(
                f"EVAL_MACRO_F1_THRESHOLD must be a number in [0, 1], got {raw!r}"
            ) from None
    if not 0.0 <= value <= 1.0:
        raise RuntimeError(f"macro-F1 threshold must be in [0, 1], got {value}")
    return value


def default_assess_fn() -> AssessFn:
    """Build the production assess function: the real graph with explicit controls.

    Explicit selection bypasses the retriever entirely (no persisted KB needed) and
    guarantees a verdict for every control a golden case names. Heavy imports are
    lazy so importing this module stays cheap for the fast lane.
    """
    from .graph import run_assessment  # noqa: PLC0415
    from .kb import build_exact_index, load_controls  # noqa: PLC0415

    index = build_exact_index(load_controls())

    def assess(repo_root: Path, control_ids: list[str]) -> FinalReport:
        missing = [c for c in control_ids if c not in index]
        if missing:
            raise ValueError(f"Golden cases name control IDs not in the rubric: {missing}")
        return run_assessment(repo_root, controls=[index[c] for c in control_ids])

    return assess


def evaluate_cases(
    cases: list[GoldenCase],
    fixtures_root: Path,
    assess_fn: AssessFn,
) -> tuple[list[EvalCaseResult], list[FinalReport]]:
    """Run the agent per fixture and pair each golden case with its predicted verdict.

    One assessment per fixture (not per case) — all of a fixture's controls go into
    a single explicit-selection run, matching how the CLI would assess that repo.
    Errors are recorded per case and never abort the remaining fixtures.
    """
    grouped: dict[str, list[GoldenCase]] = {}
    for case in cases:
        grouped.setdefault(case.repo_fixture, []).append(case)

    results: list[EvalCaseResult] = []
    reports: list[FinalReport] = []

    for fixture, fixture_cases in grouped.items():
        repo_root = fixtures_root / fixture

        def _errors(message: str, cs: list[GoldenCase] = fixture_cases) -> None:
            results.extend(
                EvalCaseResult(
                    case_id=c.id,
                    repo_fixture=c.repo_fixture,
                    control_id=c.control_id,
                    expected=c.expected_verdict,
                    error=message,
                )
                for c in cs
            )

        if not repo_root.is_dir():
            _errors(f"fixture directory not found: {repo_root}")
            continue

        # Dedupe while preserving case order, in case two cases share a control.
        control_ids = list(dict.fromkeys(c.control_id for c in fixture_cases))
        try:
            report = assess_fn(repo_root, control_ids)
        except Exception as exc:  # fail-safe: record, don't crash or fake a prediction
            _errors(f"assessment failed: {exc}")
            continue

        reports.append(report)
        by_control = {v.control_id: v for v in report.verdicts}
        for case in fixture_cases:
            verdict = by_control.get(case.control_id)
            if verdict is None:
                _errors(f"no verdict returned for control {case.control_id}", [case])
                continue
            results.append(
                EvalCaseResult(
                    case_id=case.id,
                    repo_fixture=case.repo_fixture,
                    control_id=case.control_id,
                    expected=case.expected_verdict,
                    predicted=verdict.verdict,
                    rationale=verdict.rationale[:_MAX_RATIONALE_CHARS],
                )
            )

    return results, reports


def compute_metrics(results: list[EvalCaseResult]) -> dict:
    """Score predictions with scikit-learn over the cases that produced a verdict.

    Confusion matrix and per-class report always use the full 4-label canonical order
    (stable shape). Macro/weighted F1 use only the labels actually present in the
    scored data — with the full frozen set all four classes are present so this is
    identical, but on a subset run a class with zero expected AND zero predicted
    cases must not zero-drag the average.
    """
    from sklearn.metrics import classification_report, confusion_matrix, f1_score  # noqa: PLC0415

    scored = [r for r in results if r.predicted is not None]
    if not scored:
        # No scorable predictions — report zeros; the gate can never pass on this.
        return {
            "macro_f1": 0.0,
            "weighted_f1": 0.0,
            "per_class": {},
            "confusion_matrix": [[0] * len(LABELS) for _ in LABELS],
        }

    y_true = [r.expected.value for r in scored]
    y_pred = [r.predicted.value for r in scored if r.predicted is not None]
    present = [label for label in LABELS if label in set(y_true) | set(y_pred)]

    return {
        "macro_f1": float(
            f1_score(y_true, y_pred, labels=present, average="macro", zero_division=0)
        ),
        "weighted_f1": float(
            f1_score(y_true, y_pred, labels=present, average="weighted", zero_division=0)
        ),
        "per_class": classification_report(
            y_true, y_pred, labels=LABELS, zero_division=0, output_dict=True
        ),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=LABELS).tolist(),
    }


def verifier_stats(reports: list[FinalReport]) -> dict:
    """Aggregate verifier-loop health across all assessment runs (docs/EVAL_PLAN.md)."""
    verdicts = [v for r in reports for v in r.verdicts]
    if not verdicts:
        return {"controls_assessed": 0}
    passed = sum(1 for v in verdicts if v.verifier_status == "passed")
    return {
        "controls_assessed": len(verdicts),
        "verifier_pass_rate": round(passed / len(verdicts), 4),
        "verifier_failed_count": sum(1 for v in verdicts if v.verifier_status == "failed"),
        "avg_attempts": round(sum(v.attempt for v in verdicts) / len(verdicts), 4),
        "max_attempts": max(v.attempt for v in verdicts),
    }


def evaluate_golden_set(
    golden_path: Path,
    fixtures_root: Path,
    threshold: float | None = None,
    assess_fn: AssessFn | None = None,
) -> EvalReport:
    """End-to-end evaluation: load, assess, score, and assemble the report.

    Raises GoldenSetError (missing/malformed golden set, or zero verified cases) and
    RuntimeError (bad threshold config) — the CLI wrapper maps these to exit code 2.
    """
    gate = resolve_threshold(threshold)
    cases = verified_cases(load_golden_cases(golden_path))
    if not cases:
        raise GoldenSetError(
            f"Golden set at {golden_path} has no human_verified cases — nothing counts "
            "as ground truth (docs/DECISIONS.md D8)."
        )

    fn = assess_fn if assess_fn is not None else default_assess_fn()
    results, reports = evaluate_cases(cases, fixtures_root, fn)
    metrics = compute_metrics(results)

    errors = [r for r in results if r.error is not None]
    mispredictions = [r for r in results if r.predicted is not None and r.predicted != r.expected]
    num_scored = len(results) - len(errors)

    return EvalReport(
        run_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC).isoformat(),
        num_cases=num_scored,
        num_errors=len(errors),
        macro_f1=round(metrics["macro_f1"], 4),
        weighted_f1=round(metrics["weighted_f1"], 4),
        threshold=gate,
        # An errored case must fail the run even if the scored subset clears the bar —
        # otherwise a broken fixture silently shrinks the eval until it passes.
        passed=(num_scored > 0 and not errors and metrics["macro_f1"] >= gate),
        labels=LABELS,
        per_class=metrics["per_class"],
        confusion_matrix=metrics["confusion_matrix"],
        verifier_stats=verifier_stats(reports),
        failures=mispredictions + errors,
        cases=results,
    )


def write_report(report: EvalReport, out_path: Path) -> None:
    """Serialize the report as JSON, creating parent directories as needed."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2))


def run_eval(
    golden_path: Path,
    fixtures_root: Path,
    out_path: Path,
    threshold: float | None = None,
    assess_fn: AssessFn | None = None,
) -> int:
    """CLI-facing runner: evaluate, write the report, print a summary, gate on macro-F1.

    Exit codes: 0 = passed; 1 = gate failed (below threshold, or any case errored);
    2 = configuration problem (missing/invalid golden set, threshold, or CHAT_MODEL).
    The report file is written even on failure — a failing run's numbers are exactly
    the ones worth inspecting.
    """
    # Pre-check CHAT_MODEL only when the real graph will run; a fake assess_fn
    # (tests) has no model dependency. Mirrors cmd_assess's fail-fast check.
    if assess_fn is None and not os.environ.get("CHAT_MODEL"):
        print(
            "[agentic-compliance] CHAT_MODEL is not set. Copy .env.example to .env "
            "and fill in CHAT_MODEL plus the matching provider API key, or export "
            "CHAT_MODEL directly in your shell.",
            file=sys.stderr,
        )
        return 2

    try:
        report = evaluate_golden_set(
            golden_path, fixtures_root, threshold=threshold, assess_fn=assess_fn
        )
    except (GoldenSetError, RuntimeError) as exc:
        print(f"[agentic-compliance] eval configuration error: {exc}", file=sys.stderr)
        return 2

    write_report(report, out_path)

    status = "PASSED" if report.passed else "FAILED"
    print(
        f"[agentic-compliance] eval {status}: macro-F1 {report.macro_f1:.4f} "
        f"(threshold {report.threshold:.2f}), weighted-F1 {report.weighted_f1:.4f}, "
        f"{report.num_cases} case(s) scored, {report.num_errors} error(s), "
        f"{len(report.failures)} failure(s)."
    )
    print(f"[agentic-compliance] report written to {out_path}")
    return 0 if report.passed else 1
