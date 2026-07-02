#!/usr/bin/env python
"""Golden test-case generator (M6).

Produces candidate labeled eval cases (expected verdict + evidence hints) for each
fixture repo x relevant control, using a model DIFFERENT from the one the agent under
test uses (so we're not grading a model against its own opinion — see docs/DECISIONS.md
D8). "Relevant control" reuses the same dynamic selection the real agent uses
(control_selection.select_controls against the persisted KB), so candidates target the
controls the system would actually assess, not an arbitrary full cross-product.

The output is reviewed (spot-check ~20-30%, set human_verified: true) and frozen as
data/golden_set.yaml, which the evaluation harness (M7) consumes. All generated cases
start human_verified: false — this script never marks a case verified; that's a human
judgment call, not something to fake.

This is a manual/occasional data-production step — it is NOT run on every build. The
schema-validation tests over the frozen set DO run every check-in (see docs/TEST_PLAN.md).

`--dry-run` performs no LLM calls: it just verifies the fixtures and rubric are readable
and prints what would be generated, so the wiring can be checked cheaply.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import yaml
from dotenv import find_dotenv, load_dotenv
from pydantic import BaseModel

from agentic_compliance.golden import GoldenSetError, load_golden_cases, verified_cases
from agentic_compliance.schemas import GoldenCase, VerdictClass

FIXTURES = Path("tests/fixtures/repos")
RUBRIC = Path("docs/RUBRIC.md")
STORE_PATH = Path("./chroma_db")

_MAX_FILES_PER_FIXTURE = 20
_MAX_CHARS_PER_FILE = 4000
_MAX_TOTAL_CHARS = 20000

_LABELER_SYSTEM_PROMPT = (
    "You are labeling a compliance evaluation dataset. Given a control's rubric "
    "(what satisfied/gap evidence looks like) and a fixture repository's contents, "
    "decide: the expected verdict (satisfied, partial, gap, or not_assessable), a "
    "short question the label answers, and 1-3 short evidence hints (phrases you'd "
    "expect a reviewer to cite as evidence). Base the answer only on what a careful "
    "human reviewer would conclude from the repo contents shown; when genuinely "
    "unsure or the repo has nothing evidencing this control either way, prefer "
    "not_assessable over guessing."
)


class _LabelCandidate(BaseModel):
    """Structured output from the labeler model for one fixture/control pair."""

    question: str
    expected_verdict: VerdictClass
    expected_evidence_hints: list[str] = []


def _require_labeler_model() -> str:
    """Read GOLDEN_LABEL_MODEL from env; fail clearly if unset or same as CHAT_MODEL.

    D8 requires labeling with a model different from the one the agent under test
    uses, so grading isn't just a model agreeing with its own opinion. No default is
    provided deliberately — silently picking a specific provider/model would assume
    an API key that may not be configured (same fail-safe posture as CHAT_MODEL).
    """
    labeler = os.environ.get("GOLDEN_LABEL_MODEL")
    if not labeler:
        raise RuntimeError(
            "GOLDEN_LABEL_MODEL is not set. Set it in .env to a model different from "
            "CHAT_MODEL (e.g. openai:gpt-5.5) — see docs/DECISIONS.md D8."
        )
    agent_model = os.environ.get("CHAT_MODEL")
    if agent_model and labeler == agent_model:
        raise RuntimeError(
            f"GOLDEN_LABEL_MODEL ({labeler}) must differ from CHAT_MODEL ({agent_model}) — "
            "labeling with the agent's own model defeats D8's purpose."
        )
    return labeler


def _refuse_overwrite_reason(out_path: Path, force: bool) -> str | None:
    """Return a reason to refuse overwriting out_path, or None if it's safe to write.

    A rerun (e.g. after a rubric change) must not silently clobber a frozen,
    human-reviewed golden set with fresh unreviewed candidates — that would wipe out
    real review work with no warning. An existing file that isn't a valid golden set,
    or has no verified cases yet, isn't "frozen" data worth protecting, so only a
    parseable file with verified cases blocks the write.
    """
    if force or not out_path.exists():
        return None
    try:
        existing_verified = verified_cases(load_golden_cases(out_path))
    except GoldenSetError:
        return None
    if not existing_verified:
        return None
    return (
        f"{out_path} already has {len(existing_verified)} human-verified case(s) — "
        "refusing to overwrite. Pass --force to override, or use a different --out."
    )


def _merge_regenerated_cases(
    out_path: Path, new_cases: list[Any], regenerated_fixtures: set[str]
) -> list[Any]:
    """Merge freshly generated cases into out_path's existing cases.

    Drops any existing case whose repo_fixture is in regenerated_fixtures (so a
    rerun for the same fixture doesn't duplicate it), keeps every other existing
    case untouched, then appends new_cases. An out_path that doesn't exist or
    isn't a valid golden set yields just new_cases — there's nothing to merge with.
    """
    if not out_path.exists():
        return new_cases
    try:
        existing = load_golden_cases(out_path)
    except GoldenSetError:
        return new_cases
    return [c for c in existing if c.repo_fixture not in regenerated_fixtures] + new_cases


def _relevant_controls(fixture_root: Path, retriever: Any, top_k: int) -> list[Any]:
    """Controls the real agent would select for this fixture (dynamic selection)."""
    from agentic_compliance.control_selection import select_controls  # noqa: PLC0415

    selection = select_controls(fixture_root, retriever, top_k=top_k)
    return retriever.get_by_ids([sc.control_id for sc in selection.selected_controls])


def _repo_digest(fixture_root: Path) -> str:
    """Bounded, read-only text digest of a fixture repo for the labeler prompt.

    Reuses iter_repo_files()/read_file_slice() — the same allowlist, symlink-escape,
    and size-cap boundary the rest of the system uses for repo content — instead of a
    raw walk, so this script can't reintroduce the symlink-escape class of bug fixed
    in control_selection.py's Terraform resource detection.
    """
    from agentic_compliance.repo_loader import iter_repo_files, read_file_slice  # noqa: PLC0415

    parts: list[str] = []
    total = 0
    repo_files = sorted(iter_repo_files(fixture_root), key=lambda f: str(f.path))
    for repo_file in repo_files[:_MAX_FILES_PER_FIXTURE]:
        rel = repo_file.path.relative_to(fixture_root)
        excerpt = read_file_slice(fixture_root, repo_file.path, start_line=1, end_line=200)
        content = excerpt.content[:_MAX_CHARS_PER_FILE]
        block = f"--- {rel} ---\n{content}\n"
        if total + len(block) > _MAX_TOTAL_CHARS:
            break
        parts.append(block)
        total += len(block)
    return "\n".join(parts)


def _label_case(labeler: Any, fixture_root: Path, control: Any, case_id: str) -> Any:
    """Call the labeler model for one fixture/control pair and wrap the result.

    `labeler` is a structured-output-capable callable (normally
    `init_chat_model(...).with_structured_output(_LabelCandidate)`); tests inject a
    fake to stay deterministic and offline.
    """
    digest = _repo_digest(fixture_root)
    messages = [
        {"role": "system", "content": _LABELER_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Control {control.id} — {control.name}\n"
                f"Positive evidence looks like: {control.positive_evidence}\n"
                f"Gap evidence looks like: {control.gap_evidence}\n\n"
                f"Fixture repo contents:\n{digest}"
            ),
        },
    ]
    candidate = labeler.invoke(messages)
    return GoldenCase(
        id=case_id,
        repo_fixture=fixture_root.name,
        control_id=control.id,
        question=candidate.question,
        expected_verdict=candidate.expected_verdict,
        expected_evidence_hints=candidate.expected_evidence_hints,
        human_verified=False,
    )


def generate_candidates(
    labeler: Any, retriever: Any, top_k: int = 6, fixture_names: list[str] | None = None
) -> list[Any]:
    """Generate one candidate GoldenCase per fixture x relevant control.

    labeler and retriever are injected so tests can supply fakes and stay in the
    fast lane (no real model calls, no persisted Chroma store required).
    fixture_names restricts generation to only those fixture directory names —
    e.g. to add one new fixture's cases without re-labeling (and re-billing) the
    whole set. Unrecognised names are silently ignored (same safe-by-default
    posture as get_by_ids()'s unknown-ID handling).
    """
    cases = []
    fixture_roots = sorted(p for p in FIXTURES.iterdir() if p.is_dir())
    if fixture_names is not None:
        wanted = set(fixture_names)
        fixture_roots = [p for p in fixture_roots if p.name in wanted]
    for fixture_root in fixture_roots:
        controls = _relevant_controls(fixture_root, retriever, top_k=top_k)
        for i, control in enumerate(controls, start=1):
            case_id = f"{fixture_root.name}_{control.id.replace('/', '-')}_{i:03d}"
            cases.append(_label_case(labeler, fixture_root, control, case_id))
    return cases


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
