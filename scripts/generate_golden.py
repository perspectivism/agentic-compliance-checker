#!/usr/bin/env python
"""Golden test-case generator CLI — thin wrapper over golden_generation.py.

Deliberately a standalone script, not a CLI subcommand: golden generation is
dev-time dataset production (occasional, paid, produces a reviewed artifact), not
product surface. All the generation logic lives in
`agentic_compliance.golden_generation` so tests can import it normally; this file
owns only argument parsing and the overwrite/merge orchestration around it.

`--dry-run` performs no LLM calls: it just verifies the fixtures and rubric are
readable and prints what would be generated, so the wiring can be checked cheaply.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml
from dotenv import find_dotenv, load_dotenv

from agentic_compliance.golden_generation import (
    FIXTURES,
    RUBRIC,
    STORE_PATH,
    _LabelCandidate,
    _merge_regenerated_cases,
    _refuse_overwrite_reason,
    _require_labeler_model,
    generate_candidates,
)


def main(argv: list[str] | None = None) -> int:
    # Mirrors cli.py's main(): a plain script invocation from a shell should pick up
    # .env the same way the CLI does, without requiring GOLDEN_LABEL_MODEL to already
    # be exported in the shell.
    load_dotenv(find_dotenv(usecwd=True))

    parser = argparse.ArgumentParser(description="Generate candidate golden eval cases.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Validate inputs; make no LLM calls."
    )
    parser.add_argument(
        "--out",
        default="artifacts/golden_candidates.yaml",
        help=(
            "Output path. Defaults to a review workspace, NOT the frozen "
            "data/golden_set.yaml — freezing is a deliberate, separate copy step "
            "after review (see docs/EVAL_PLAN.md)."
        ),
    )
    parser.add_argument(
        "--top-k-controls",
        type=int,
        default=6,
        dest="top_k",
        help="Controls per fixture to label (dynamic selection, default 6).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite --out even if it already has human-verified cases.",
    )
    parser.add_argument(
        "--fixture",
        action="append",
        dest="fixtures",
        help=(
            "Restrict generation to this fixture directory name (repeatable). "
            "Default: all fixtures. Use to add one new fixture's cases without "
            "re-labeling (and re-billing) the whole set."
        ),
    )
    args = parser.parse_args(argv)

    if not FIXTURES.exists():
        print(f"Fixtures not found at {FIXTURES}", file=sys.stderr)
        return 1
    if not RUBRIC.exists():
        print(f"Rubric not found at {RUBRIC}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    if not args.dry_run:
        reason = _refuse_overwrite_reason(out_path, force=args.force)
        if reason is not None:
            print(f"[generate_golden] {reason}", file=sys.stderr)
            return 2

    repos = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir())
    if args.fixtures:
        repos = [r for r in repos if r in set(args.fixtures)]
    if args.dry_run:
        print(f"[generate_golden --dry-run] fixtures: {len(repos)} -> {', '.join(repos)}")
        print(
            "[generate_golden --dry-run] would generate candidate cases per fixture x "
            "relevant control (dynamic selection against the persisted KB)."
        )
        print(
            "[generate_golden --dry-run] a real run calls GOLDEN_LABEL_MODEL "
            "(see .env.example) and needs `make ingest`/`ingest-local` first."
        )
        return 0

    try:
        labeler_model = _require_labeler_model()
    except RuntimeError as exc:
        print(f"[generate_golden] {exc}", file=sys.stderr)
        return 2

    try:
        from agentic_compliance.retriever import ControlsRetriever  # noqa: PLC0415

        retriever = ControlsRetriever.from_persisted(STORE_PATH)
    except FileNotFoundError as exc:
        print(f"[generate_golden] {exc}", file=sys.stderr)
        return 2

    from langchain.chat_models import init_chat_model  # noqa: PLC0415

    labeler = init_chat_model(labeler_model).with_structured_output(_LabelCandidate)
    cases = generate_candidates(labeler, retriever, top_k=args.top_k, fixture_names=args.fixtures)

    # --fixture merges into an existing --out rather than replacing it.
    if args.fixtures:
        cases = _merge_regenerated_cases(out_path, cases, set(args.fixtures))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"cases": [c.model_dump(mode="json") for c in cases]}
    out_path.write_text(yaml.safe_dump(payload, sort_keys=False))
    print(f"[generate_golden] wrote {len(cases)} candidate case(s) to {out_path}")
    print("[generate_golden] all cases start human_verified: false — spot-check before freezing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
