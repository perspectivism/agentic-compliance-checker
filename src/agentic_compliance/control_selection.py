"""Dynamic control selection: detect repo features, build a semantic query, retrieve controls.

Public API:
    detect_features(repo_root)                        → list[str]
    build_selection_query(features)                   → str
    select_controls(repo_root, retriever, top_k)      → SelectionResult  (dynamic mode)
    explicit_selection(controls)                      → SelectionResult  (explicit mode)

Feature detection has two layers:
  1. Structural — file extensions and well-known names (no content reads).
  2. Terraform resource types — a bounded content read of .tf files to find
     resource declarations (e.g. aws_lb_listener → terraform_lb), enabling
     control-specific query terms like TLS/HTTPS or S3/SSE that the file-extension
     layer cannot produce. Files are sourced from iter_repo_files() so the same
     symlink-escape, size-cap, and binary-detection guarantees apply here as
     everywhere else repo content is read.

Must NOT call the LLM. Must NOT write files. Must NOT execute repository content.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .kb import ControlEntry
from .repo_loader import iter_repo_files
from .retriever import ControlsRetriever
from .schemas import SelectedControl, SelectionResult

_DEFAULT_TOP_K = 6

# Directories skipped during feature detection — not part of the authored codebase.
_SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}

# Per-feature semantic phrases used to build the retrieval query.
# Chosen to match vocabulary in data/controls.yaml embed_text fields.
_FEATURE_PHRASES: dict[str, str] = {
    "terraform": "Terraform infrastructure encryption IAM secrets access control least privilege",
    # Resource-type sub-features: added by _detect_terraform_resources() when found.
    "terraform_lb": "TLS HTTPS load balancer listener transmission encryption in-transit SSL certificate port 443",
    "terraform_s3": "S3 bucket encryption at rest public access block SSE KMS server-side encryption storage",
    "terraform_iam": "IAM policy least privilege scoped actions resources permissions role",
    "terraform_cloudtrail": "CloudTrail audit logging monitoring event record",
    "terraform_monitoring": "CloudWatch alarm monitoring alerting GuardDuty threat detection observability",
    "dockerfile": "Docker container image non-root user hardening secrets environment",
    "github_actions": "CI pipeline security dependency scanning SAST secret scanning permissions",
    "docker_compose": "Docker Compose secrets environment variables service exposure",
    "python": "Python dependency scanning secrets credentials hardcoded packages",
    "go": "Go dependency scanning secrets credentials",
    "java": "Java dependency scanning secrets credentials Maven Gradle",
    "javascript": "npm dependency scanning secrets credentials Node.js",
}

# Maps Terraform resource type names to sub-feature tags.
# Used by _detect_terraform_resources() to inject specific query vocabulary.
_TF_RESOURCE_FEATURE: dict[str, str] = {
    "aws_lb_listener": "terraform_lb",
    "aws_alb_listener": "terraform_lb",
    "aws_lb": "terraform_lb",
    "aws_alb": "terraform_lb",
    "aws_s3_bucket": "terraform_s3",
    "aws_s3_bucket_server_side_encryption_configuration": "terraform_s3",
    "aws_s3_bucket_public_access_block": "terraform_s3",
    "aws_iam_policy": "terraform_iam",
    "aws_iam_role": "terraform_iam",
    "aws_iam_role_policy": "terraform_iam",
    "aws_cloudtrail": "terraform_cloudtrail",
    "aws_cloudwatch_metric_alarm": "terraform_monitoring",
    "aws_guardduty_detector": "terraform_monitoring",
}

_TF_RESOURCE_RE = re.compile(r'resource\s+"([^"]+)"')
_MAX_TF_READ_BYTES = 64 * 1024  # 64 KB per file — bounded content inspection

# Fallback when no recognisable features are detected.
_FALLBACK_QUERY = "encryption secrets access control audit logging dependency scanning"


def detect_features(repo_root: Path) -> list[str]:
    """Identify tech features in repo_root by file extensions, names, and resource types.

    Returns a deduplicated list of feature tags in discovery order. For Terraform repos,
    a second bounded content pass inspects .tf files for resource type declarations so
    the query gains specific terms like TLS/HTTPS or S3/SSE rather than generic Terraform
    vocabulary. No code is executed; no file larger than _MAX_TF_READ_BYTES is read in full.
    """
    features: list[str] = []

    for dirpath_str, dirnames, filenames in os.walk(repo_root, followlinks=False):
        # Prune excluded directories in-place so os.walk won't descend into them.
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        dirpath = Path(dirpath_str)
        rel_dir = dirpath.relative_to(repo_root)
        # Cap traversal depth to avoid spending time on deep generated trees.
        if len(rel_dir.parts) > 5:
            dirnames.clear()
            continue

        for filename in filenames:
            _classify_file(rel_dir, filename, features)

    # Second pass: inspect Terraform resource types for finer-grained query terms.
    if "terraform" in features:
        _detect_terraform_resources(repo_root, features)

    return features


def build_selection_query(features: list[str]) -> str:
    """Build a single semantic query string from detected repo features.

    Concatenates per-feature phrases as-is. Words may repeat across phrases
    (e.g. "IAM" in both the base "terraform" phrase and "terraform_iam") —
    this is intentional: cross-phrase word deduplication previously stripped a
    sub-feature's strongest, most distinguishing terms whenever they overlapped
    with the broader Terraform phrase, diluting that control's embedding signal
    enough to drop it out of the top-k (e.g. AC-6 losing to zero-evidence
    controls). Repetition reinforces a shared concept rather than diluting it.
    Falls back to a general security query when no features are detected.
    """
    if not features:
        return _FALLBACK_QUERY

    parts = [_FEATURE_PHRASES.get(feature, feature) for feature in features]
    return " ".join(parts)


def select_controls(
    repo_root: Path,
    retriever: ControlsRetriever,
    top_k: int = _DEFAULT_TOP_K,
) -> SelectionResult:
    """Dynamically select the top_k most relevant controls for repo_root.

    Steps:
    1. Detect repo technology features from the file tree (structural pass) plus
       a bounded content read of .tf files for Terraform resource sub-features.
    2. Build a semantic query from those features.
    3. Retrieve controls ranked by relevance (highest relevance_score first).
    4. Return a fully populated SelectionResult.
    """
    if top_k < 1:
        raise ValueError(f"top_k must be a positive integer, got {top_k!r}")
    features = detect_features(repo_root)
    query = build_selection_query(features)
    hits = retriever.search_with_scores(query, k=top_k)
    return SelectionResult(
        mode="dynamic",
        top_k=top_k,
        detected_features=features,
        selection_query=query,
        selected_controls=[
            SelectedControl(control_id=entry.id, relevance_score=score) for entry, score in hits
        ],
    )


def explicit_selection(controls: list[ControlEntry]) -> SelectionResult:
    """Wrap an explicit user-specified control list in a SelectionResult.

    No retrieval is performed. relevance_score is None for every control — the
    scores field is meaningless when the user chose the controls directly.
    """
    return SelectionResult(
        mode="explicit",
        top_k=None,
        detected_features=[],
        selection_query="",
        selected_controls=[
            SelectedControl(control_id=c.id, relevance_score=None) for c in controls
        ],
    )


# ── Internal helpers ───────────────────────────────────────────────────────────


def _classify_file(rel_dir: Path, filename: str, features: list[str]) -> None:
    """Classify a single file by extension/name and append any new features."""
    name = filename.lower()
    suffix = Path(filename).suffix.lower()
    parts = rel_dir.parts  # tuple of directory components relative to repo root

    if suffix == ".tf":
        _add_once(features, "terraform")
    elif name.startswith("dockerfile"):
        _add_once(features, "dockerfile")
    elif suffix == ".py":
        _add_once(features, "python")
    elif suffix == ".go":
        _add_once(features, "go")
    elif suffix == ".java":
        _add_once(features, "java")
    elif suffix in (".js", ".ts", ".jsx", ".tsx"):
        _add_once(features, "javascript")
    elif suffix in (".yml", ".yaml"):
        # .github/workflows/*.yml is the canonical GitHub Actions location.
        if len(parts) >= 2 and parts[0] == ".github" and parts[1] == "workflows":
            _add_once(features, "github_actions")
        elif name in (
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ):
            _add_once(features, "docker_compose")


def _add_once(lst: list[str], item: str) -> None:
    """Append item to lst only if not already present."""
    if item not in lst:
        lst.append(item)


def _detect_terraform_resources(repo_root: Path, features: list[str]) -> None:
    """Scan .tf files for resource type declarations and add sub-feature tags.

    Sources candidate files from iter_repo_files() rather than walking repo_root
    directly, so symlink-escape protection, the size cap, and binary detection
    apply here exactly as they do for every other repo content read. Within each
    allowed file, reads at most _MAX_TF_READ_BYTES via a capped binary read — the
    file is never loaded into memory beyond that bound. Never executes content.
    """
    for rf in iter_repo_files(repo_root):
        if rf.path.suffix.lower() != ".tf":
            continue
        try:
            with rf.path.open("rb") as f:
                raw = f.read(_MAX_TF_READ_BYTES)
        except OSError:
            continue
        content = raw.decode("utf-8", errors="replace")
        for match in _TF_RESOURCE_RE.finditer(content):
            resource_type = match.group(1)
            sub_feature = _TF_RESOURCE_FEATURE.get(resource_type)
            if sub_feature:
                _add_once(features, sub_feature)
