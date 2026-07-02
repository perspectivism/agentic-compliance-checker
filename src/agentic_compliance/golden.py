"""Golden evaluation set — schema validation and loading.

Golden cases are produced by scripts/generate_golden.py (a labeler model different
from the agent's own CHAT_MODEL, per docs/DECISIONS.md D8), hand-reviewed, and
frozen as data/golden_set.yaml. This module only parses and validates that file —
it must not read target repos, call any model, or produce verdicts.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from .schemas import GoldenCase, VerdictClass


class GoldenSetError(ValueError):
    """Raised when a golden set file is missing, unparsable, or has a malformed case."""


def load_golden_cases(path: Path) -> list[GoldenCase]:
    """Load and validate every case in a golden set YAML file.

    Fails closed: a missing file, invalid YAML, or any single malformed case
    raises GoldenSetError immediately rather than silently dropping bad entries —
    a golden set that quietly lost cases would skew eval metrics without anyone
    noticing.
    """
    if not path.exists():
        raise GoldenSetError(f"Golden set not found at {path}")

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise GoldenSetError(f"Golden set at {path} is not valid YAML: {exc}") from exc

    if raw is not None and not isinstance(raw, dict):
        raise GoldenSetError(
            f"Golden set at {path} must be a YAML mapping with a 'cases' key, "
            f"got top-level {type(raw).__name__}"
        )

    cases = (raw or {}).get("cases")
    if not isinstance(cases, list):
        raise GoldenSetError(f"Golden set at {path} has no top-level 'cases' list")

    result: list[GoldenCase] = []
    for i, entry in enumerate(cases):
        try:
            result.append(GoldenCase.model_validate(entry))
        except ValidationError as exc:
            case_id = entry.get("id", f"index {i}") if isinstance(entry, dict) else f"index {i}"
            raise GoldenSetError(f"Malformed golden case ({case_id}) in {path}: {exc}") from exc

    return result


def verified_cases(cases: list[GoldenCase]) -> list[GoldenCase]:
    """Return only human-reviewed cases — the only ones that count as ground truth."""
    return [c for c in cases if c.human_verified]


def class_coverage(cases: list[GoldenCase]) -> dict[str, int]:
    """Count cases per expected_verdict class, for minimum-coverage checks."""
    counts: dict[str, int] = {verdict.value: 0 for verdict in VerdictClass}
    for c in cases:
        counts[c.expected_verdict.value] += 1
    return counts
