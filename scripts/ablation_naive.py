#!/usr/bin/env python
"""Ablation baseline: a naive single-prompt agent scored on the frozen golden set.

Answers "0.933 macro-F1 compared to what?" — the same chat model (CHAT_MODEL), the
same 54 golden cases, and the same bounded repo-read budgets as the pipeline's
golden generation, but with the architecture removed: NO deterministic scanners,
NO verifier loop, NO fail-closed guards. One LLM call per (fixture, control) —
raw repository text (comments included) plus the control rubric in, verdict out.
Scored by the same evaluation harness (`agentic_compliance.evaluation`) so the
numbers are directly comparable; results are recorded in docs/EVAL_PLAN.md →
"Baseline comparison (ablation)".

Like the eval itself, this is a manual, occasional experiment (real model calls;
54 of them) — it is NOT run in CI. Writes to artifacts/eval/ablation_naive.json
by default; it never touches the pipeline's artifacts/eval/latest.json.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import find_dotenv, load_dotenv

from agentic_compliance.evaluation import run_eval
from agentic_compliance.kb import build_exact_index, load_controls
from agentic_compliance.repo_loader import iter_repo_files, read_file_slice
from agentic_compliance.schemas import ControlVerdict, FinalReport, SynthesizerOutput

# Same budgets as golden_generation._repo_digest(), so the naive agent reads exactly
# as much of the repo as the labeler did — comparability, not coincidence.
_MAX_FILES = 20
_MAX_CHARS_PER_FILE = 4000
_MAX_TOTAL = 20000

# Deliberately minimal — the point of the baseline is "just ask the model".
_SYSTEM = (
    "You are assessing whether a software repository satisfies a security control. "
    "Read the repository contents and the control description, then return a verdict: "
    "'satisfied', 'partial', 'gap', or 'not_assessable', with a short rationale."
)


def _raw_digest(fixture_root: Path) -> str:
    """Bounded raw repo digest — same budgets as golden generation, but WITHOUT
    comment stripping: the naive agent reads the repo as-is, adversarial text and all.
    """
    parts: list[str] = []
    total = 0
    for rf in sorted(iter_repo_files(fixture_root), key=lambda f: str(f.path))[:_MAX_FILES]:
        rel = rf.path.relative_to(fixture_root)
        content = read_file_slice(fixture_root, rf.path, 1, 200).content[:_MAX_CHARS_PER_FILE]
        block = f"--- {rel} ---\n{content}\n"
        if total + len(block) > _MAX_TOTAL:
            break
        parts.append(block)
        total += len(block)
    return "\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    # Mirrors cli.py's main(): pick up CHAT_MODEL from .env without manual sourcing.
    load_dotenv(find_dotenv(usecwd=True))

    parser = argparse.ArgumentParser(description="Naive single-prompt ablation baseline.")
    parser.add_argument(
        "--out",
        default="artifacts/eval/ablation_naive.json",
        help="Output path for the metrics report (kept separate from latest.json).",
    )
    args = parser.parse_args(argv)

    if not os.environ.get("CHAT_MODEL"):
        print("[ablation] CHAT_MODEL is not set — see .env.example.", file=sys.stderr)
        return 2

    from langchain.chat_models import init_chat_model  # noqa: PLC0415

    llm = init_chat_model(os.environ["CHAT_MODEL"]).with_structured_output(SynthesizerOutput)
    index = build_exact_index(load_controls())
    digests: dict[str, str] = {}

    def naive_assess(repo_root: Path, control_ids: list[str]) -> FinalReport:
        key = str(repo_root)
        if key not in digests:
            digests[key] = _raw_digest(repo_root)
        verdicts = []
        for cid in control_ids:
            c = index[cid]
            out = llm.invoke(
                [
                    ("system", _SYSTEM),
                    (
                        "human",
                        f"Control {c.id} — {c.name}\n"
                        f"Positive evidence looks like: {c.positive_evidence}\n"
                        f"Gap evidence looks like: {c.gap_evidence}\n\n"
                        f"Repository contents:\n{digests[key]}\n\n"
                        "Return your verdict.",
                    ),
                ]
            )
            print(f"  {repo_root.name} x {cid}: {out.verdict.value}", flush=True)
            verdicts.append(
                ControlVerdict(
                    control_id=cid,
                    verdict=out.verdict,
                    evidence=[],  # the naive agent has no scanner evidence to attach
                    rationale=out.rationale,
                    confidence=out.confidence,
                    verifier_status="not_run",
                    attempt=1,
                )
            )
        return FinalReport(repo_path=str(repo_root), verdicts=verdicts, audit={})

    return run_eval(
        golden_path=Path("data/golden_set.yaml"),
        fixtures_root=Path("tests/fixtures/repos"),
        out_path=Path(args.out),
        assess_fn=naive_assess,
    )


if __name__ == "__main__":
    raise SystemExit(main())
