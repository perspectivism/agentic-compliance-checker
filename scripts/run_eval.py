#!/usr/bin/env python
"""Evaluation harness entrypoint — thin wrapper over the CLI's `eval` subcommand.

Delegating to the CLI keeps a single source of truth for argument parsing, .env
loading, and exit codes (0 = passed, 1 = macro-F1 gate failed or a case errored,
2 = configuration problem). Any flag the subcommand accepts works here too:

    python scripts/run_eval.py --threshold 0.6 --out artifacts/eval/latest.json

The real logic lives in src/agentic_compliance/evaluation.py; see docs/EVAL_PLAN.md
for the report schema and metric definitions.
"""

from __future__ import annotations

import sys

from agentic_compliance.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["eval", *sys.argv[1:]]))
