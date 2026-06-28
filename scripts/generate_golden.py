#!/usr/bin/env python
"""Golden test-case generator (M6).

Produces candidate labeled eval cases (expected verdict + evidence hints) for each
fixture repo x relevant control, using a model DIFFERENT from the one the agent under
test uses (so we're not grading a model against its own opinion — see docs/DECISIONS.md
D8). The output is reviewed (spot-check ~20-30%, set human_verified: true) and frozen as
data/golden_set.yaml, which the evaluation harness (M7) consumes.

This is a manual/occasional data-production step — it is NOT run on every build. The
schema-validation tests over the frozen set DO run every check-in (see docs/TEST_PLAN.md).

`--dry-run` performs no LLM calls: it just verifies the fixtures and rubric are readable
and prints what would be generated, so the wiring can be checked cheaply.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

FIXTURES = Path("tests/fixtures/repos")
RUBRIC = Path("docs/RUBRIC.md")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate candidate golden eval cases.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Validate inputs; make no LLM calls."
    )
    parser.add_argument("--out", default="data/golden_set.yaml", help="Frozen output path.")
    args = parser.parse_args(argv)

    if not FIXTURES.exists():
        print(f"Fixtures not found at {FIXTURES}", file=sys.stderr)
        return 1
    if not RUBRIC.exists():
        print(f"Rubric not found at {RUBRIC}", file=sys.stderr)
        return 1

    repos = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir())
    if args.dry_run:
        print(f"[generate_golden --dry-run] fixtures: {len(repos)} -> {', '.join(repos)}")
        print(
            "[generate_golden --dry-run] would generate candidate cases per fixture x relevant control."
        )
        print(
            "[generate_golden --dry-run] generation itself is implemented at M6 (needs the agent stack + a labeler model)."
        )
        return 0

    print(
        "Generation is implemented at M6 — wire a different-model labeler here, then "
        "spot-check and freeze to",
        args.out,
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
