#!/usr/bin/env python
"""Evaluation harness entrypoint (M7).

When implemented, this loads the golden set, runs the assessment graph on each
fixture repo, and scores two layers:
  1. Verdict accuracy  — scikit-learn confusion_matrix + classification_report.
  2. Grounding quality — RAGAS faithfulness / context precision+recall (optional,
     sampled, since RAGAS metrics are LLM-as-judge and cost tokens).
It writes a JSON report to artifacts/eval/latest.json (schema in docs/EVAL_PLAN.md).

Until M7 lands, this is a smoke stub: it validates that the golden set parses,
then exits 0 so CI stays green. Replace the body as M7 is implemented.
"""

from __future__ import annotations

import sys
from pathlib import Path

GOLDEN = Path("data/golden_set_stub.yaml")


def main() -> int:
    if not GOLDEN.exists():
        print(f"Golden set not found at {GOLDEN}", file=sys.stderr)
        return 1
    try:
        import yaml

        cases = (yaml.safe_load(GOLDEN.read_text()) or {}).get("cases", [])
    except Exception as exc:  # pragma: no cover
        print(f"Failed to parse golden set: {exc}", file=sys.stderr)
        return 1

    print(f"[eval smoke] golden set parsed OK: {len(cases)} case(s).")
    print("[eval smoke] full evaluation is implemented at M7 (see docs/EVAL_PLAN.md).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
