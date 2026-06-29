"""Read-only MCP tool functions — directly callable Python, no MCP dependency.

Each function:
- accepts repo_root: Path (resolved, trusted)
- reads only files permitted by iter_repo_files / read_file_slice
- never executes repo content, never makes network calls
- returns a structured Pydantic object or list thereof
- on OSError or parse failure: skips the offending file (logs to limitations)
  and never raises an unhandled exception

The MCP server (mcp_server.py) wraps these with @mcp.tool() and converts
string repo_root parameters to Path before calling.

scan_iac_security is internally split by check family (Terraform, Dockerfile,
Kubernetes/YAML, logging/monitoring) — each family is an independently
testable private function even though they share one MCP tool boundary.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from .repo_loader import (
    FileSlice,
    RepoFile,
    iter_repo_files,
    read_file_slice as _read_file_slice_impl,
)
from .schemas import RepoFileListing, ToolFinding

_Severity = Literal["high", "medium", "low", "info"]

# ── list_repo_files ────────────────────────────────────────────────────────────


def list_repo_files(repo_root: Path) -> list[RepoFileListing]:
    """Return metadata for every allowed text file in repo_root.

    Delegates to iter_repo_files for allowlist/denylist/size/binary enforcement.
    Paths are repo-relative. Never executes files.
    """
    results: list[RepoFileListing] = []
    for rf in iter_repo_files(repo_root):
        try:
            rel = rf.path.relative_to(repo_root)
        except ValueError:
            continue
        results.append(
            RepoFileListing(
                path=str(rel),
                size=rf.size,
                extension=rf.path.suffix.lower(),
            )
        )
    return results


# ── read_file_slice ────────────────────────────────────────────────────────────


def read_file_slice(
    repo_root: Path,
    path: str,
    start_line: int = 1,
    end_line: int | None = None,
) -> FileSlice:
    """Return a bounded, root-checked line excerpt from a single allowed file.

    path is repo-relative. Raises ValueError if the path escapes repo_root
    OR if it is not in the file allowlist (denied dir, wrong extension, oversized,
    binary). This prevents callers from reading .git/config, compiled artefacts,
    or secret-store files even when they are inside the repo root.
    """
    repo_root = repo_root.resolve()  # normalize so relative roots don't break path comparison
    abs_path = (repo_root / path).resolve()
    # Enforce allowlist before any read — iter_repo_files applies the full
    # denylist/allowlist/size/binary pipeline, so we only proceed if the file
    # would be yielded during normal scanning.
    allowed = {rf.path for rf in iter_repo_files(repo_root)}
    if abs_path not in allowed:
        raise ValueError(
            f"Path {path!r} is not an allowed file in {repo_root!r} "
            "(denied directory, disallowed extension, oversized, or binary)"
        )
    return _read_file_slice_impl(repo_root, abs_path, start_line, end_line)


# ── Secrets scanner ────────────────────────────────────────────────────────────

# Each entry: (finding_type, compiled_re, redact_group, control_hints, severity)
# redact_group=0 → redact the entire match; redact_group=N → redact group N only.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], int, list[str], _Severity]] = [
    # AWS access key IDs follow the well-known AKIA prefix format.
    (
        "aws_access_key",
        re.compile(r"AKIA[0-9A-Z]{16}", re.ASCII),
        0,
        ["IA-5"],
        "high",
    ),
    # Generic variable assignments whose name suggests a credential.
    # Group 1 captures the value so only the value is redacted, keeping context.
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)(?:[a-z_]*(?:password|passwd|secret|api.?key|token|db.?pass|access.?key)[a-z_]*)"
            r'\s*=\s*["\']([^"\']{6,})["\']'
        ),
        1,
        ["IA-5"],
        "high",
    ),
]


def _redact_line(line: str, pattern: re.Pattern, redact_group: int) -> str:
    """Replace the secret value in line with [REDACTED], preserving context."""

    def replacer(m: re.Match) -> str:
        full = m.group(0)
        if redact_group == 0:
            return "[REDACTED]"
        val = m.group(redact_group)
        return full.replace(val, "[REDACTED]", 1)

    return pattern.sub(replacer, line).strip()


def scan_secrets(repo_root: Path) -> list[ToolFinding]:
    """Scan for hardcoded credentials using regex patterns.

    Secret values are masked in excerpt before returning — the raw value
    never appears in tool output. Returns ToolFinding list with check_family
    'secrets' and redacted=True for every finding.
    """
    findings: list[ToolFinding] = []
    seen: set[tuple[str, int, str]] = set()  # deduplicate (path, line, type)

    for rf in iter_repo_files(repo_root):
        try:
            content = rf.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel_path = str(rf.path.relative_to(repo_root))
        for lineno, line in enumerate(content.splitlines(), start=1):
            for finding_type, pattern, redact_group, hints, severity in _SECRET_PATTERNS:
                if not pattern.search(line):
                    continue
                key = (rel_path, lineno, finding_type)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    ToolFinding(
                        path=rel_path,
                        start_line=lineno,
                        end_line=lineno,
                        finding_type=finding_type,
                        check_family="secrets",
                        severity=severity,
                        message=f"Possible hardcoded credential ({finding_type})",
                        control_hints=hints,
                        excerpt=_redact_line(line, pattern, redact_group),
                        redacted=True,
                        limitations=[
                            "Regex-based; may false-positive on test fixtures or example values"
                        ],
                    )
                )

    return findings


# ── IaC scanner (internally split by check family) ─────────────────────────────


def _scan_terraform(repo_root: Path, files: list[RepoFile]) -> list[ToolFinding]:
    """Check Terraform .tf files for security misconfigurations."""
    findings: list[ToolFinding] = []

    for rf in files:
        if rf.path.suffix.lower() != ".tf":
            continue
        try:
            content = rf.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = content.splitlines()
        rel = str(rf.path.relative_to(repo_root))

        # Public ingress: security group ingress open to the internet
        for i, line in enumerate(lines, start=1):
            if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', line):
                findings.append(
                    ToolFinding(
                        path=rel,
                        start_line=i,
                        end_line=i,
                        finding_type="public_ingress",
                        check_family="terraform",
                        severity="high",
                        message="Security group allows ingress from 0.0.0.0/0 (internet-wide)",
                        control_hints=["AC-3", "AC-4", "SC-7"],
                        excerpt=line.strip(),
                        redacted=False,
                        limitations=["Cannot determine if filtered by NACLs or WAF downstream"],
                    )
                )

        # Wildcard IAM: Action="*" and Resource="*" in the same file
        _action_re = re.compile(r'(?i)(?:Action\s*=|"Action"\s*:)\s*"\*"')
        _resource_re = re.compile(r'(?i)(?:Resource\s*=|"Resource"\s*:)\s*"\*"')
        action_line = next((i for i, ln in enumerate(lines, 1) if _action_re.search(ln)), None)
        resource_line = next((i for i, ln in enumerate(lines, 1) if _resource_re.search(ln)), None)
        if action_line and resource_line:
            findings.append(
                ToolFinding(
                    path=rel,
                    start_line=action_line,
                    end_line=resource_line,
                    finding_type="wildcard_iam",
                    check_family="terraform",
                    severity="high",
                    message='IAM policy grants Action "*" on Resource "*" (overly permissive)',
                    control_hints=["AC-6"],
                    excerpt='Action = "*" ... Resource = "*"',
                    redacted=False,
                    limitations=["Cannot evaluate runtime SCP or permission boundary constraints"],
                )
            )

        # Locate S3 bucket resources (shared by SSE and versioning checks below)
        _s3_re = re.compile(r'resource\s+"aws_s3_bucket"\s+')
        has_s3_bucket = any(_s3_re.search(ln) for ln in lines)
        bucket_line = next((i for i, ln in enumerate(lines, 1) if _s3_re.search(ln)), None)

        # Unencrypted S3: aws_s3_bucket without sse_configuration in same file
        has_sse = any("aws_s3_bucket_server_side_encryption_configuration" in ln for ln in lines)
        if has_s3_bucket and not has_sse:
            findings.append(
                ToolFinding(
                    path=rel,
                    start_line=bucket_line,
                    end_line=bucket_line,
                    finding_type="unencrypted_s3",
                    check_family="terraform",
                    severity="high",
                    message="S3 bucket has no server-side encryption configuration",
                    control_hints=["SC-28"],
                    excerpt="aws_s3_bucket (no sse configuration found in file)",
                    redacted=False,
                    limitations=[
                        "SSE may be configured via bucket policy or default account settings"
                    ],
                )
            )

        # Missing S3 versioning
        has_versioning = any("aws_s3_bucket_versioning" in ln for ln in lines)
        if has_s3_bucket and not has_versioning:
            findings.append(
                ToolFinding(
                    path=rel,
                    start_line=bucket_line,
                    end_line=bucket_line,
                    finding_type="missing_s3_versioning",
                    check_family="terraform",
                    severity="medium",
                    message="S3 bucket has no versioning configuration",
                    control_hints=["SI-12", "CP-9"],
                    excerpt="aws_s3_bucket (no versioning found in file)",
                    redacted=False,
                    limitations=["Versioning may be enabled via management console or org policy"],
                )
            )

    return findings


def _scan_dockerfile(repo_root: Path, files: list[RepoFile]) -> list[ToolFinding]:
    """Check Dockerfiles for security misconfigurations."""
    findings: list[ToolFinding] = []

    for rf in files:
        if rf.path.name != "Dockerfile" and rf.path.suffix.lower() not in {
            ".dockerfile",
        }:
            continue
        try:
            content = rf.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = content.splitlines()
        rel = str(rf.path.relative_to(repo_root))

        for i, line in enumerate(lines, start=1):
            stripped = line.strip().upper()
            raw = line.strip()

            # Unpinned base image: :latest tag or no version/digest pin
            _from_m = re.match(
                r"^FROM\s+(?:--\S+\s+)*(\S+?)(?:\s+AS\s+\S+)?\s*$", raw, re.IGNORECASE
            )
            if _from_m:
                image = _from_m.group(1).lower()
                if image != "scratch" and (":" not in image or image.endswith(":latest")):
                    findings.append(
                        ToolFinding(
                            path=rel,
                            start_line=i,
                            end_line=i,
                            finding_type="dockerfile_unpinned_base_image",
                            check_family="dockerfile",
                            severity="medium",
                            message="Base image uses ':latest' or has no version pin — build is not reproducible",
                            control_hints=["CM-6", "SI-7"],
                            excerpt=raw,
                            redacted=False,
                            limitations=[
                                "Image may be pinned via digest in a build system, not visible here"
                            ],
                        )
                    )

            # Running as root — name "root", or numeric UID 0 (with optional :group suffix)
            if re.match(r"^USER\s+(?:ROOT|0)(?::\S+)?\s*$", stripped):
                findings.append(
                    ToolFinding(
                        path=rel,
                        start_line=i,
                        end_line=i,
                        finding_type="dockerfile_root_user",
                        check_family="dockerfile",
                        severity="high",
                        message="Container runs as root",
                        control_hints=["AC-6", "CM-6"],
                        excerpt=raw,
                        redacted=False,
                        limitations=["Cannot determine effective UID at runtime"],
                    )
                )

            # ADD with remote URL (prefer COPY + explicit download)
            if re.match(r"^ADD\s+https?://", stripped):
                findings.append(
                    ToolFinding(
                        path=rel,
                        start_line=i,
                        end_line=i,
                        finding_type="dockerfile_add_remote_url",
                        check_family="dockerfile",
                        severity="medium",
                        message="ADD with remote URL — content integrity not verified",
                        control_hints=["SI-7", "CM-6"],
                        excerpt=raw,
                        redacted=False,
                        limitations=["Cannot verify if URL content is pinned by hash"],
                    )
                )

            # Secrets in ENV or ARG instructions
            _env_secret_re = re.compile(
                r"^(?:ENV|ARG)\s+\S*(?:PASSWORD|SECRET|TOKEN|KEY|PASSWD)\S*(?:\s*=\S+)?",
                re.IGNORECASE,
            )
            if _env_secret_re.match(raw):
                excerpt = re.sub(r"(=)\S+", r"\1[REDACTED]", raw)
                findings.append(
                    ToolFinding(
                        path=rel,
                        start_line=i,
                        end_line=i,
                        finding_type="dockerfile_secret_in_build_arg",
                        check_family="dockerfile",
                        severity="high",
                        message="Secret-looking variable in ENV or ARG — may leak into image layers or history",
                        control_hints=["IA-5", "SC-28"],
                        excerpt=excerpt,
                        redacted=True,
                        limitations=["Cannot confirm the value is a real secret vs a placeholder"],
                    )
                )

        # No USER directive means the container defaults to root — file-level check.
        # Must be checked after the per-line loop so we have seen all lines.
        has_user_directive = any(
            re.match(r"^USER\b", line.strip(), re.IGNORECASE) for line in lines
        )
        if not has_user_directive:
            findings.append(
                ToolFinding(
                    path=rel,
                    start_line=1,
                    end_line=len(lines),
                    finding_type="dockerfile_missing_nonroot_user",
                    check_family="dockerfile",
                    severity="high",
                    message="No USER directive — container runs as root by default",
                    control_hints=["AC-6", "CM-6"],
                    excerpt="(no USER directive found)",
                    redacted=False,
                    limitations=["Cannot determine effective UID at runtime"],
                )
            )

    return findings


def _scan_kubernetes(repo_root: Path, files: list[RepoFile]) -> list[ToolFinding]:
    """Check Kubernetes YAML manifests for security misconfigurations."""
    findings: list[ToolFinding] = []

    for rf in files:
        if rf.path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        try:
            content = rf.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Only scan files that look like Kubernetes manifests
        if "apiVersion" not in content and "kind" not in content:
            continue

        lines = content.splitlines()
        rel = str(rf.path.relative_to(repo_root))

        for i, line in enumerate(lines, start=1):
            if re.search(r"privileged\s*:\s*true", line):
                findings.append(
                    ToolFinding(
                        path=rel,
                        start_line=i,
                        end_line=i,
                        finding_type="k8s_privileged_container",
                        check_family="kubernetes_yaml",
                        severity="high",
                        message="Container runs in privileged mode",
                        control_hints=["AC-6", "CM-6"],
                        excerpt=line.strip(),
                        redacted=False,
                        limitations=["Cannot determine if namespace-scoped policies restrict this"],
                    )
                )
            if re.search(r"hostNetwork\s*:\s*true", line):
                findings.append(
                    ToolFinding(
                        path=rel,
                        start_line=i,
                        end_line=i,
                        finding_type="k8s_host_network",
                        check_family="kubernetes_yaml",
                        severity="high",
                        message="Pod uses host network namespace — bypasses network isolation",
                        control_hints=["SC-7", "AC-4"],
                        excerpt=line.strip(),
                        redacted=False,
                        limitations=["Cannot determine if network policy restricts pod egress"],
                    )
                )
            if re.search(r"hostPID\s*:\s*true", line):
                findings.append(
                    ToolFinding(
                        path=rel,
                        start_line=i,
                        end_line=i,
                        finding_type="k8s_host_pid",
                        check_family="kubernetes_yaml",
                        severity="high",
                        message="Pod uses host PID namespace — can observe all host processes",
                        control_hints=["AC-6", "CM-6"],
                        excerpt=line.strip(),
                        redacted=False,
                        limitations=["Cannot determine if admission control prevents this"],
                    )
                )

        # File-level absence checks: heuristic, limited to files with containers:
        # These require YAML parsing for full accuracy; regex is a best-effort signal.
        if "containers:" in content:
            if "resources:" not in content:
                findings.append(
                    ToolFinding(
                        path=rel,
                        start_line=None,
                        end_line=None,
                        finding_type="k8s_missing_resource_limits",
                        check_family="kubernetes_yaml",
                        severity="medium",
                        message="No resource limits found in Kubernetes manifest",
                        control_hints=["SC-5", "CM-6"],
                        excerpt="",
                        redacted=False,
                        limitations=[
                            "Heuristic: limits may be set via LimitRange or admission webhook"
                        ],
                    )
                )
            if "securityContext:" not in content:
                findings.append(
                    ToolFinding(
                        path=rel,
                        start_line=None,
                        end_line=None,
                        finding_type="k8s_missing_security_context",
                        check_family="kubernetes_yaml",
                        severity="medium",
                        message="No securityContext found in Kubernetes manifest",
                        control_hints=["AC-6", "CM-6"],
                        excerpt="",
                        redacted=False,
                        limitations=[
                            "Heuristic: security context may be set at pod level or via admission webhook"
                        ],
                    )
                )

    return findings


def _scan_logging(repo_root: Path, files: list[RepoFile]) -> list[ToolFinding]:
    """Check IaC files for missing audit logging configuration."""
    findings: list[ToolFinding] = []

    tf_files = [rf for rf in files if rf.path.suffix.lower() == ".tf"]
    if not tf_files:
        return findings

    # Check if any Terraform file references CloudTrail or an equivalent audit log
    all_tf_content = ""
    for rf in tf_files:
        try:
            all_tf_content += rf.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

    _audit_patterns = re.compile(
        r"aws_cloudtrail|aws_config|google_logging|azurerm_monitor_log_profile",
        re.IGNORECASE,
    )
    if not _audit_patterns.search(all_tf_content):
        findings.append(
            ToolFinding(
                path="(terraform files)",
                start_line=None,
                end_line=None,
                finding_type="audit_logging_missing",
                check_family="logging_monitoring",
                severity="medium",
                message="No CloudTrail or equivalent audit logging resource found in Terraform",
                control_hints=["AU-2", "AU-12"],
                excerpt="",
                redacted=False,
                limitations=["Logging may be configured outside Terraform (console, org policies)"],
            )
        )

    return findings


def scan_iac_security(repo_root: Path) -> list[ToolFinding]:
    """Scan IaC files for security misconfigurations.

    Internally dispatches to four independently testable check families:
    Terraform, Dockerfile, Kubernetes/YAML, and logging/monitoring.
    All return ToolFinding records with the appropriate check_family.
    Never executes repo content.
    """
    files = list(iter_repo_files(repo_root))
    return (
        _scan_terraform(repo_root, files)
        + _scan_dockerfile(repo_root, files)
        + _scan_kubernetes(repo_root, files)
        + _scan_logging(repo_root, files)
    )


# ── CI security scanner ────────────────────────────────────────────────────────

# (tool_name, pattern, present_finding_type, missing_finding_type, control_hints)
_CI_TOOLS: list[tuple[str, re.Pattern[str], str, str, list[str]]] = [
    (
        "dependency audit (pip-audit / npm audit / dependabot)",
        re.compile(r"pip-audit|npm audit|dependabot", re.IGNORECASE),
        "dependency_audit_present",
        "dependency_audit_missing",
        ["SI-2", "RA-5"],
    ),
    (
        "container / filesystem scanner (trivy / snyk / grype)",
        re.compile(r"trivy|snyk|grype", re.IGNORECASE),
        "container_scan_present",
        "container_scan_missing",
        ["SI-2", "RA-5"],
    ),
    (
        "SAST tool (CodeQL / semgrep / bandit)",
        re.compile(r"codeql|semgrep|bandit", re.IGNORECASE),
        "sast_present",
        "sast_missing",
        ["SA-11", "SI-3"],
    ),
    (
        "secret-scanning hook (gitleaks / detect-secrets / truffleHog)",
        re.compile(r"gitleaks|detect.secrets|trufflehog", re.IGNORECASE),
        "secret_scan_present",
        "secret_scan_missing",
        ["IA-5", "SI-12"],
    ),
    (
        "permissions declaration",
        re.compile(r"^\s*permissions\s*:", re.MULTILINE),
        "permissions_declared",
        "missing_permissions_declaration",
        ["AC-2", "AC-6"],
    ),
]


def scan_ci_security(repo_root: Path) -> list[ToolFinding]:
    """Scan CI workflow files for security tool presence/absence.

    Looks for .github/workflows/*.yml|yaml. For each expected security tool
    category, emits an info finding when found and a medium finding when absent.
    Returns an empty list when no workflow files exist (absence of CI is not
    itself flagged here — the Evidence Collector decides how to weight it).
    """
    findings: list[ToolFinding] = []

    # Collect workflow files — iter_repo_files already applies the allowlist
    workflow_files = [
        rf
        for rf in iter_repo_files(repo_root)
        if ".github" in rf.path.parts
        and "workflows" in rf.path.parts
        and rf.path.suffix.lower() in {".yml", ".yaml"}
    ]

    if not workflow_files:
        return findings

    # Concatenate all workflow content for cross-file pattern matching
    combined = ""
    file_refs: dict[str, str] = {}  # pattern match → file path for citation
    for rf in workflow_files:
        try:
            text = rf.path.read_text(encoding="utf-8", errors="replace")
            combined += text
            file_refs[str(rf.path.relative_to(repo_root))] = text
        except OSError:
            continue

    for tool_label, pattern, present_type, missing_type, hints in _CI_TOOLS:
        if pattern.search(combined):
            # Find which file contains the match for citation
            citing_file = next(
                (p for p, txt in file_refs.items() if pattern.search(txt)),
                list(file_refs.keys())[0],
            )
            # Find the line number for the first match
            citing_text = file_refs.get(citing_file, "")
            match_line = next(
                (i for i, ln in enumerate(citing_text.splitlines(), 1) if pattern.search(ln)),
                None,
            )
            findings.append(
                ToolFinding(
                    path=citing_file,
                    start_line=match_line,
                    end_line=match_line,
                    finding_type=present_type,
                    check_family="ci",
                    severity="info",
                    message=f"{tool_label} found in CI workflow",
                    control_hints=hints,
                    excerpt=(
                        citing_text.splitlines()[match_line - 1].strip() if match_line else ""
                    ),
                    redacted=False,
                    limitations=[
                        "Cannot verify the tool is configured to fail the build on findings"
                    ],
                )
            )
        else:
            findings.append(
                ToolFinding(
                    path=list(file_refs.keys())[0],
                    start_line=None,
                    end_line=None,
                    finding_type=missing_type,
                    check_family="ci",
                    severity="medium",
                    message=f"No {tool_label} found in CI workflows",
                    control_hints=hints,
                    excerpt="",
                    redacted=False,
                    limitations=[
                        "Scanning may be configured in an external tool not visible in workflow YAML"
                    ],
                )
            )

    # Overly broad permissions: write-all grants maximum GITHUB_TOKEN scope
    _broad_re = re.compile(r"permissions\s*:\s*write-all", re.IGNORECASE)
    if _broad_re.search(combined):
        citing_file = next(
            (p for p, txt in file_refs.items() if _broad_re.search(txt)),
            list(file_refs.keys())[0],
        )
        citing_text = file_refs.get(citing_file, "")
        match_line = next(
            (i for i, ln in enumerate(citing_text.splitlines(), 1) if _broad_re.search(ln)),
            None,
        )
        findings.append(
            ToolFinding(
                path=citing_file,
                start_line=match_line,
                end_line=match_line,
                finding_type="overly_broad_permissions",
                check_family="ci",
                severity="high",
                message="Workflow uses 'permissions: write-all' — grants maximum GITHUB_TOKEN scope",
                control_hints=["AC-6"],
                excerpt=citing_text.splitlines()[match_line - 1].strip() if match_line else "",
                redacted=False,
                limitations=["Does not evaluate repository-level permission settings"],
            )
        )

    return findings
