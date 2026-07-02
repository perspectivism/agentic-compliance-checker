"""Command-line entrypoint and Docker ENTRYPOINT for the agentic compliance checker.

This is intentionally a thin dispatcher. Heavy modules (LangGraph, the MCP client,
the vector store) are imported lazily *inside* each subcommand so that `--help`
stays fast and runnable from day one without the full agent stack installed.
"""

from __future__ import annotations

import argparse
import os
import sys

from dotenv import find_dotenv, load_dotenv


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

    if args.controls and args.top_k_controls is not None:
        print(
            "[agentic-compliance] --controls and --top-k-controls are mutually exclusive. "
            "Use --controls for explicit selection or --top-k-controls for dynamic selection.",
            file=sys.stderr,
        )
        return 2

    top_k = args.top_k_controls if args.top_k_controls is not None else 6
    if top_k < 1:
        print(
            "[agentic-compliance] --top-k-controls must be a positive integer (≥ 1).",
            file=sys.stderr,
        )
        return 2

    # Fail fast with an actionable message before any cloning/embedding work —
    # the raw KeyError from init_chat_model(os.environ["CHAT_MODEL"]) inside the
    # graph is otherwise opaque (only surfaces after the repo is already loaded).
    if not os.environ.get("CHAT_MODEL"):
        print(
            "[agentic-compliance] CHAT_MODEL is not set. Copy .env.example to .env "
            "and fill in CHAT_MODEL plus the matching provider API key (e.g. "
            "ANTHROPIC_API_KEY), or export CHAT_MODEL directly in your shell.",
            file=sys.stderr,
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
    try:
        report = run_assessment(repo_root, controls=controls, top_k_controls=top_k)
    except FileNotFoundError as exc:
        # Missing or uninitialised KB — user-fixable; exit 2.
        print(f"[agentic-compliance] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[agentic-compliance] Assessment failed: {exc}", file=sys.stderr)
        return 1

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
    run_id = report.audit.get("run_id")
    if run_id:
        print(f"[agentic-compliance] Run log: artifacts/runs/{run_id}.jsonl", flush=True)
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
    from pathlib import Path  # noqa: PLC0415

    from .evaluation import run_eval  # noqa: PLC0415

    return run_eval(
        golden_path=Path(args.golden),
        fixtures_root=Path(args.fixtures_root),
        out_path=Path(args.out),
        threshold=args.threshold,
    )


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
    a.add_argument(
        "--controls",
        help="Comma-separated control IDs for explicit selection. Cannot be used with --top-k-controls.",
    )
    a.add_argument(
        "--top-k-controls",
        dest="top_k_controls",
        type=int,
        default=None,
        metavar="K",
        help="Number of controls to select dynamically via semantic search (default: 6). Cannot be used with --controls.",
    )
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
    e.add_argument(
        "--golden",
        default="data/golden_set.yaml",
        help="Path to the frozen golden set (default: data/golden_set.yaml).",
    )
    e.add_argument(
        "--fixtures-root",
        dest="fixtures_root",
        default="tests/fixtures/repos",
        help="Directory containing the fixture repos golden cases reference.",
    )
    e.add_argument(
        "--out",
        default="artifacts/eval/latest.json",
        help="Output path for the JSON metrics report.",
    )
    e.add_argument(
        "--threshold",
        type=float,
        default=None,
        metavar="F1",
        help="Macro-F1 gate; falls back to EVAL_MACRO_F1_THRESHOLD, then 0.70.",
    )
    e.set_defaults(func=cmd_eval)

    return p


def main(argv: list[str] | None = None) -> int:
    # Mirrors Docker (--env-file) and the IDE launch configs (envFile), so a plain
    # CLI invocation from a shell picks up the same .env without manual sourcing.
    # usecwd=True: search from the shell's cwd, not this installed module's location
    # (the default search walks up from __file__, which for an installed console
    # script resolves under site-packages and would not find a project-local .env).
    # override=False (the default): real exported shell vars still win over .env.
    load_dotenv(find_dotenv(usecwd=True))
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
