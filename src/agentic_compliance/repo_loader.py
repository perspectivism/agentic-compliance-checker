"""Safe repository loader — the trust boundary between the system and untrusted repos.

Validates URLs before any clone attempt, enforces file allowlists/denylists,
symlink-escape protection, and size caps. Never executes repo content.

Public API:
    resolve_repo_input(source)   — dispatch URL→clone or local path→validate; return Path
    validate_repo_url(url)       — raise RepoURLError on invalid or unsafe URL
    validate_repo_path(path)     — raise RepoPathError on missing/non-directory local path
    safe_clone(url, target)      — validate then shallow-clone; raise on failure
    iter_repo_files(repo_root)   — yield RepoFile for each allowed text file
    read_file_slice(root, path)  — bounded, root-checked line excerpt; never executes

Must NOT make network calls except inside safe_clone.
Must NOT execute repo content at any point.
Must NOT follow symlinks outside repo_root.
"""

import ipaddress
import os
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# ── Exceptions ─────────────────────────────────────────────────────────────────


class RepoURLError(ValueError):
    """Raised when a repository URL is invalid or unsafe to clone."""


class RepoPathError(ValueError):
    """Raised when a local repository path is missing, not a directory, or unreadable."""


# ── Constants ──────────────────────────────────────────────────────────────────

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"https"})

# Only well-known public forge hosts; extend deliberately, not speculatively.
_ALLOWED_HOSTS: frozenset[str] = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

# Directory names that must never be descended into.
_DENIED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "vendor",
        "__pycache__",
        ".tox",
        ".eggs",
        "dist",
        "build",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".venv",
        "venv",
    }
)

# File extensions that are allowed for reading (text, code, IaC, config).
_ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".tf",
        ".tfvars",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".md",
        ".txt",
        ".sh",
        ".env",
    }
)

# File names without extensions that are allowed.
_ALLOWED_NAMES: frozenset[str] = frozenset(
    {
        "Dockerfile",
        "Makefile",
        "NOTICE",
        "LICENSE",
        "CODEOWNERS",
        ".gitignore",
        ".dockerignore",
        ".env.example",
    }
)

# 512 KiB — large enough for real IaC files, small enough to prevent DoS reads.
MAX_FILE_BYTES: int = 512 * 1024


# ── Data types ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RepoFile:
    """A single allowed, text file within the repo."""

    path: Path
    size: int  # bytes


@dataclass(frozen=True)
class FileSlice:
    """A bounded, line-cited excerpt from a file. Never contains executed output."""

    path: str
    start_line: int  # 1-indexed, inclusive
    end_line: int  # 1-indexed, inclusive
    content: str


# ── URL validation ─────────────────────────────────────────────────────────────


def validate_repo_url(url: str) -> None:
    """Validate a repository URL before any clone attempt.

    Allows only HTTPS to known forge hosts. Rejects file://, ext::, ssh://,
    git://, scp-like git@ syntax, IP literals, and any non-allowlisted host.
    Returns None on success; raises RepoURLError on any violation.
    """
    # Reject scp-like git syntax before urlparse (e.g. git@github.com:owner/repo)
    if url.startswith("git@"):
        raise RepoURLError(f"Rejected scp-like git URL: {url!r}")

    # Reject known dangerous transports that may confuse urlparse
    # (ext:: enables arbitrary transport helpers — potential RCE in git)
    url_lower = url.lower()
    for dangerous in ("ext::", "file://", "ssh://", "git://"):
        if url_lower.startswith(dangerous):
            raise RepoURLError(f"Rejected disallowed URL scheme: {url!r}")

    try:
        parsed = urlparse(url)
    except Exception as exc:  # pragma: no cover — urlparse rarely raises
        raise RepoURLError(f"Failed to parse URL {url!r}") from exc

    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise RepoURLError(f"Rejected scheme {parsed.scheme!r} in {url!r}; only HTTPS is allowed")

    # Reject embedded credentials (security smell; git credentials go in the
    # credential store, not the URL)
    if parsed.username or parsed.password:
        raise RepoURLError(f"Rejected URL with embedded credentials: {url!r}")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise RepoURLError(f"URL has no hostname: {url!r}")

    # Reject all IP literals — the host allowlist accepts named hosts only.
    # Defense-in-depth: even a public IP is an unusual pattern for a forge URL.
    try:
        ipaddress.ip_address(hostname)
        raise RepoURLError(f"Rejected IP-literal address in {url!r}; use a hostname")
    except ValueError:
        pass  # Not an IP literal — expected path

    if hostname not in _ALLOWED_HOSTS:
        raise RepoURLError(
            f"Rejected host {hostname!r} in {url!r}; allowed hosts: {sorted(_ALLOWED_HOSTS)}"
        )


# ── Clone ──────────────────────────────────────────────────────────────────────


def safe_clone(url: str, target: Path, *, timeout: int = 120) -> Path:
    """Validate URL then shallow-clone into target.

    Uses --depth 1, no submodules, no local-path optimisation, no tags,
    and disables ext:: transport helpers via git -c flags. Never runs hooks,
    install scripts, or any repo content.

    Raises RepoURLError on invalid URL; subprocess.CalledProcessError on
    clone failure.
    """
    validate_repo_url(url)
    target.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "git",
            # Disable ext:: transport helper at the process level regardless of
            # system/user git config (belt-and-suspenders with the URL check above)
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.file.allow=never",
            "clone",
            "--depth",
            "1",
            "--no-local",  # prevent fast-path for local paths
            "--no-tags",
            "--single-branch",
            url,
            str(target),
        ],
        check=True,
        capture_output=True,
        timeout=timeout,
    )
    return target


# ── Local path validation and input resolution ────────────────────────────────


def validate_repo_path(path: Path) -> None:
    """Validate that path is an accessible local repository directory.

    Raises RepoPathError if path does not exist, is not a directory, or
    is not readable. Returns None on success.
    """
    if not path.exists():
        raise RepoPathError(f"Repository path does not exist: {path}")
    if not path.is_dir():
        raise RepoPathError(f"Repository path is not a directory: {path}")
    if not os.access(path, os.R_OK):
        raise RepoPathError(f"Repository path is not readable: {path}")


def resolve_repo_input(
    source: str,
    *,
    clone_base: Path | None = None,
    clone_timeout: int = 120,
) -> Path:
    """Resolve a source string to a local repository path.

    If source contains :// or starts with git@ it is treated as a URL:
    validate_repo_url is called, then safe_clone fetches it into clone_base
    (a temp directory if clone_base is None — caller is responsible for cleanup).

    Otherwise source is treated as a local path: validate_repo_path is called
    and the Path is returned directly.

    Raises RepoURLError or RepoPathError on invalid input;
    subprocess.CalledProcessError on clone failure.
    """
    if "://" in source or source.startswith("git@") or source.lower().startswith("ext::"):
        if clone_base is None:
            clone_base = Path(tempfile.mkdtemp(prefix="agentic_compliance_"))
        slug = source.rstrip("/").rsplit("/", 1)[-1].replace(".git", "") or "repo"
        return safe_clone(source, clone_base / slug, timeout=clone_timeout)
    path = Path(source)
    validate_repo_path(path)
    return path


# ── File iteration ─────────────────────────────────────────────────────────────


def iter_repo_files(repo_root: Path) -> Iterator[RepoFile]:
    """Yield allowed, text files within repo_root.

    Skips: denied directories (.git, node_modules, …), symlinks that resolve
    outside repo_root, binary files, files exceeding MAX_FILE_BYTES, and
    disallowed extensions/names. Uses os.walk(followlinks=False) so directory
    symlinks can never pull in paths outside the repo.
    """
    root_resolved = repo_root.resolve()

    for dirpath_str, dirnames, filenames in os.walk(repo_root, followlinks=False):
        # Prune denied dirs in-place to prevent descent
        dirnames[:] = [d for d in dirnames if d not in _DENIED_DIRS]

        dirpath = Path(dirpath_str)
        for filename in filenames:
            path = dirpath / filename

            # Symlink escape check: file-level symlinks still need validation
            # because followlinks=False only blocks directory symlinks
            if path.is_symlink():
                try:
                    resolved = path.resolve()
                    resolved.relative_to(root_resolved)
                except (ValueError, OSError):
                    continue  # escapes root or broken — skip silently

            # Extension / name allowlist
            if path.name not in _ALLOWED_NAMES and path.suffix.lower() not in _ALLOWED_EXTENSIONS:
                continue

            # Size cap
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                continue

            # Binary detection: null bytes in the first 8 KiB (git's heuristic)
            if _is_binary(path):
                continue

            yield RepoFile(path=path, size=size)


def _is_binary(path: Path) -> bool:
    """Return True if path likely contains binary content (null bytes in first 8 KiB)."""
    try:
        return b"\x00" in path.read_bytes()[:8192]
    except OSError:
        return True  # unreadable → treat as binary


# ── Line reader ────────────────────────────────────────────────────────────────


def read_file_slice(
    repo_root: Path,
    path: Path,
    start_line: int = 1,
    end_line: int | None = None,
) -> FileSlice:
    """Return a bounded, root-checked, line-cited excerpt from path.

    path must resolve within repo_root — raises ValueError if it escapes.
    start_line and end_line are 1-indexed, inclusive. Stops at EOF if
    end_line exceeds the file length. Never executes the file.
    """
    # Enforce repo boundary before any read — path must not escape repo_root
    try:
        path.resolve().relative_to(repo_root.resolve())
    except ValueError:
        raise ValueError(f"Path {path!r} is outside repo root {repo_root!r}") from None

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise ValueError(f"Cannot read {path}: {exc}") from exc

    total = len(lines)
    start = max(1, start_line)
    end = min(total, end_line if end_line is not None else total)

    if start > total:
        # Past EOF — anchor end_line to the last real line so citations are accurate
        return FileSlice(path=str(path), start_line=start, end_line=total, content="")

    selected = lines[start - 1 : end]
    return FileSlice(
        path=str(path),
        start_line=start,
        end_line=start + len(selected) - 1,
        content="\n".join(selected),
    )
