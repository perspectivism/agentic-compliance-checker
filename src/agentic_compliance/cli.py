"""Command-line entrypoint and Docker ENTRYPOINT for the agentic compliance checker.

This is intentionally a thin dispatcher. Heavy modules (LangGraph, the MCP client,
the vector store) are imported lazily *inside* each subcommand so that `--help`
and not-yet-implemented milestones stay runnable from day one — `docker compose run`
works immediately, and each subcommand prints an honest "implemented at Mx" message
until the corresponding milestone lands.

As you implement each milestone, replace the `_not_implemented(...)` call in the
matching command with the real wiring (the import hints in each function show where).
"""

from __future__ import annotations

import argparse
import sys


def _not_implemented(feature: str, milestone: str) -> int:
    print(
        f"[agentic-compliance] '{feature}' is implemented at milestone {milestone}.\n"
        f"It is not wired up yet — see docs/MILESTONES.md.",
        file=sys.stderr,
    )
    return 2


def cmd_assess(args: argparse.Namespace) -> int:
    # M5 wiring:
    #   from .repo_loader import resolve_repo_input  # safe clone (URL) or local path
    #   from .graph import run_assessment            # supervisor + verifier loop (M5)
    #   path = resolve_repo_input(args.repo_url or args.repo_path)
    #   report = run_assessment(path, controls=args.controls)
    #   write_report(report, args.out, args.format)
    if not args.repo_url and not args.repo_path:
        print(
            "Provide --repo-url <public GitHub URL> or --repo-path <local path>.", file=sys.stderr
        )
        return 2
    return _not_implemented("assess", "M5")


def cmd_ingest(args: argparse.Namespace) -> int:
    # M3 wiring: load docs/RUBRIC.md + data/controls -> embed -> persist to ./chroma_db
    #   from .kb import ingest_controls; ingest_controls()
    return _not_implemented("ingest-controls", "M3")


def cmd_eval(args: argparse.Namespace) -> int:
    # M7 wiring: delegate to scripts/run_eval.py or import the eval module.
    #   from .eval import run_eval; return run_eval()
    return _not_implemented("eval", "M7")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentic-compliance",
        description="Self-verifying agentic compliance checker (assess a repo against a code-detectable control rubric).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("assess", help="Assess a repository against the control rubric.")
    grp = a.add_argument_group("input (choose one)")
    grp.add_argument(
        "--repo-url",
        help="Public GitHub URL. Cloned read-only, shallow, no submodules, never executed.",
    )
    grp.add_argument("--repo-path", help="Path to a local repository (e.g. a test fixture).")
    a.add_argument("--controls", help="Comma-separated control IDs (default: all in the rubric).")
    a.add_argument("--out", default="artifacts/report.json", help="Output path for the report.")
    a.add_argument("--format", choices=["json", "md"], default="json", help="Report format.")
    a.set_defaults(func=cmd_assess)

    i = sub.add_parser("ingest-controls", help="Build the controls knowledge base (vector store).")
    i.set_defaults(func=cmd_ingest)

    e = sub.add_parser("eval", help="Run the evaluation harness over the golden set.")
    e.set_defaults(func=cmd_eval)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
