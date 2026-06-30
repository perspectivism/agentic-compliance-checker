"""Command-line entrypoint and Docker ENTRYPOINT for the agentic compliance checker.

This is intentionally a thin dispatcher. Heavy modules (LangGraph, the MCP client,
the vector store) are imported lazily *inside* each subcommand so that `--help`
stays fast and runnable from day one without the full agent stack installed.
"""

from __future__ import annotations

import argparse
import sys


def cmd_assess(args: argparse.Namespace) -> int:
    import json  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    from .graph import run_assessment  # noqa: PLC0415
    from .kb import build_exact_index, load_controls  # noqa: PLC0415
    from .repo_loader import resolve_repo_input  # noqa: PLC0415

    if not args.repo_url and not args.repo_path:
        print(
            "Provide --repo-url <public GitHub URL> or --repo-path <local path>.", file=sys.stderr
        )
        return 2

    target = args.repo_url or args.repo_path
    repo_root = resolve_repo_input(target)

    controls = None
    if args.controls:
        index = build_exact_index(load_controls())
        ids = [c.strip() for c in args.controls.split(",")]
        controls = [index[i] for i in ids if i in index]
        missing = [i for i in ids if i not in index]
        if missing:
            print(f"[agentic-compliance] Unknown control IDs: {missing}", file=sys.stderr)
            return 2

    print(f"[agentic-compliance] Assessing {repo_root} …", flush=True)
    report = run_assessment(repo_root, controls=controls)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.format == "json":
        out_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2))
    else:
        lines = [f"# Compliance Report\n\nRepo: {report.repo_path}\n"]
        for v in report.verdicts:
            lines.append(f"## {v.control_id}: {v.verdict.value}")
            lines.append(f"{v.rationale}\n")
        out_path.write_text("\n".join(lines))

    print(f"[agentic-compliance] Report written to {out_path}", flush=True)
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    from pathlib import Path  # noqa: PLC0415

    from .kb import ingest_controls  # noqa: PLC0415

    store_path = Path(args.store_path)
    print(f"[agentic-compliance] Ingesting controls into {store_path} …", flush=True)
    kwargs = {"store_path": store_path}
    if args.controls_file:
        kwargs["controls_path"] = Path(args.controls_file)
    ingest_controls(**kwargs)
    print(f"[agentic-compliance] Done — {store_path} is ready.", flush=True)
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    # Implemented at M7.
    print(
        "[agentic-compliance] 'eval' is not yet implemented — see docs/MILESTONES.md M7.",
        file=sys.stderr,
    )
    return 2


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
    i.add_argument(
        "--controls-file",
        default=None,
        help="Path to controls YAML (default: data/controls.yaml in the package root).",
    )
    i.add_argument(
        "--store-path",
        default="./chroma_db",
        help="Directory to persist the Chroma vector store (default: ./chroma_db).",
    )
    i.set_defaults(func=cmd_ingest)

    e = sub.add_parser("eval", help="Run the evaluation harness over the golden set.")
    e.set_defaults(func=cmd_eval)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
