"""Safe repository loader — URL validation, file filtering, and line reader."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentic_compliance.repo_loader import (
    MAX_FILE_BYTES,
    RepoPathError,
    RepoURLError,
    iter_repo_files,
    read_file_slice,
    resolve_repo_input,
    safe_clone,
    validate_repo_path,
    validate_repo_url,
)

FIXTURES = Path(__file__).parent / "fixtures" / "repos"


# ── URL validation ─────────────────────────────────────────────────────────────


class TestValidateRepoURL:
    def test_accepts_valid_github_https_url(self):
        """Valid HTTPS GitHub URL passes validation."""
        validate_repo_url("https://github.com/owner/repo.git")  # must not raise

    def test_accepts_valid_gitlab_https_url(self):
        """Valid HTTPS GitLab URL passes validation."""
        validate_repo_url("https://gitlab.com/owner/repo")

    def test_rejects_file_scheme(self):
        """file:// is rejected before any clone attempt."""
        with pytest.raises(RepoURLError):
            validate_repo_url("file:///etc/passwd")

    def test_rejects_ext_transport(self):
        """ext:: transport helper is rejected (arbitrary command execution in git)."""
        with pytest.raises(RepoURLError):
            validate_repo_url("ext::git-remote-helper /tmp/evil")

    def test_rejects_ssh_scheme(self):
        """ssh:// URLs are rejected."""
        with pytest.raises(RepoURLError):
            validate_repo_url("ssh://github.com/owner/repo.git")

    def test_rejects_git_scheme(self):
        """git:// URLs are rejected."""
        with pytest.raises(RepoURLError):
            validate_repo_url("git://github.com/owner/repo.git")

    def test_rejects_scp_syntax(self):
        """git@ scp-like syntax is rejected even for known forge hosts."""
        with pytest.raises(RepoURLError):
            validate_repo_url("git@github.com:owner/repo.git")

    def test_rejects_loopback_ip(self):
        """Loopback IP literal is rejected (internal/private/loopback rule)."""
        with pytest.raises(RepoURLError):
            validate_repo_url("https://127.0.0.1/owner/repo")

    def test_rejects_private_ip(self):
        """Private IP literal is rejected (internal/private/loopback rule)."""
        with pytest.raises(RepoURLError):
            validate_repo_url("https://192.168.1.100/owner/repo")

    def test_rejects_localhost_hostname(self):
        """localhost hostname is rejected (not in allowed-host list)."""
        with pytest.raises(RepoURLError):
            validate_repo_url("https://localhost/owner/repo")

    def test_rejects_unknown_host(self):
        """Arbitrary HTTPS hosts are rejected; allowlist only."""
        with pytest.raises(RepoURLError):
            validate_repo_url("https://evil.example.com/owner/repo")

    def test_rejects_plain_http(self):
        """HTTP (not HTTPS) is rejected; encryption is required."""
        with pytest.raises(RepoURLError):
            validate_repo_url("http://github.com/owner/repo")


# ── Safe clone ─────────────────────────────────────────────────────────────────


class TestSafeClone:
    def test_clone_uses_depth_1(self, tmp_path):
        """safe_clone invokes git with --depth 1 (no full history)."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            safe_clone("https://github.com/owner/repo.git", tmp_path / "cloned")
        cmd = mock_run.call_args[0][0]
        assert "--depth" in cmd
        idx = cmd.index("--depth")
        assert cmd[idx + 1] == "1"

    def test_clone_has_no_submodule_recursion(self, tmp_path):
        """safe_clone does not pass --recurse-submodules."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            safe_clone("https://github.com/owner/repo.git", tmp_path / "cloned")
        cmd = mock_run.call_args[0][0]
        assert not any("recurse-submodules" in arg for arg in cmd)

    def test_clone_rejects_invalid_url_before_subprocess(self, tmp_path):
        """Subprocess is never called when URL validation fails."""
        with patch("subprocess.run") as mock_run:
            with pytest.raises(RepoURLError):
                safe_clone("file:///etc/passwd", tmp_path / "cloned")
            mock_run.assert_not_called()

    def test_clone_rejects_scp_before_subprocess(self, tmp_path):
        """scp-like git@ syntax is rejected before any subprocess call."""
        with patch("subprocess.run") as mock_run:
            with pytest.raises(RepoURLError):
                safe_clone("git@github.com:owner/repo.git", tmp_path / "cloned")
            mock_run.assert_not_called()


# ── File iteration ─────────────────────────────────────────────────────────────


class TestIterRepoFiles:
    def test_skips_git_directory(self, tmp_path):
        """Files inside .git are never yielded."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("not real git config")
        (tmp_path / "main.py").write_text("x = 1")

        paths = [f.path for f in iter_repo_files(tmp_path)]
        assert not any(".git" in str(p) for p in paths)
        assert any("main.py" in str(p) for p in paths)

    def test_skips_node_modules(self, tmp_path):
        """Files inside node_modules are never yielded."""
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "index.js").write_text("module.exports = {}")
        (tmp_path / "app.py").write_text("x = 1")

        # Use relative paths so the pytest-generated tmp dir name doesn't
        # accidentally contain "node_modules" as a substring
        rel_paths = [f.path.relative_to(tmp_path) for f in iter_repo_files(tmp_path)]
        assert not any("node_modules" in str(p) for p in rel_paths)
        assert any("app.py" in str(p) for p in rel_paths)

    def test_skips_binary_file(self, tmp_path):
        """Binary files containing null bytes are excluded."""
        (tmp_path / "image.bin").write_bytes(b"\x00\x01\x02\x03PNG-like")
        (tmp_path / "code.py").write_text("x = 1")

        paths = [f.path for f in iter_repo_files(tmp_path)]
        assert not any("image.bin" in str(p) for p in paths)
        assert any("code.py" in str(p) for p in paths)

    def test_rejects_symlink_escaping_repo_root(self, tmp_path):
        """Symlinks that resolve outside repo_root are not yielded."""
        repo = tmp_path / "repo"
        repo.mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_text("top secret content")
        escape = repo / "escape.txt"
        os.symlink(secret, escape)

        paths = [f.path for f in iter_repo_files(repo)]
        assert not any("escape" in str(p) for p in paths)
        assert not any("secret" in str(p) for p in paths)

    def test_caps_oversized_file(self, tmp_path):
        """Files exceeding MAX_FILE_BYTES are excluded."""
        large = tmp_path / "large.py"
        large.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
        small = tmp_path / "small.py"
        small.write_text("x = 1")

        paths = [f.path for f in iter_repo_files(tmp_path)]
        assert not any("large.py" in str(p) for p in paths)
        assert any("small.py" in str(p) for p in paths)

    def test_reads_terraform_files(self):
        """Terraform .tf files from the secure_terraform_app fixture are yielded."""
        paths = [f.path for f in iter_repo_files(FIXTURES / "secure_terraform_app")]
        assert any(str(p).endswith(".tf") for p in paths)

    def test_reads_yaml_files(self):
        """YAML .yml files from the ci_scanning_repo fixture are yielded."""
        paths = [f.path for f in iter_repo_files(FIXTURES / "ci_scanning_repo")]
        assert any(str(p).endswith(".yml") for p in paths)

    def test_reads_dockerfile(self, tmp_path):
        """Dockerfile (no extension) is yielded."""
        (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n")
        paths = [f.path for f in iter_repo_files(tmp_path)]
        assert any("Dockerfile" in str(p) for p in paths)

    def test_reads_python_files(self):
        """Python .py files from the hardcoded_secret_app fixture are yielded."""
        paths = [f.path for f in iter_repo_files(FIXTURES / "hardcoded_secret_app")]
        assert any(str(p).endswith(".py") for p in paths)

    def test_reads_markdown_files(self):
        """Markdown .md files from the prompt_injection_repo fixture are yielded."""
        paths = [f.path for f in iter_repo_files(FIXTURES / "prompt_injection_repo")]
        assert any(str(p).endswith(".md") for p in paths)


# ── Local path validation ──────────────────────────────────────────────────────


class TestValidateRepoPath:
    def test_accepts_existing_directory(self, tmp_path):
        """A readable directory passes validation without error."""
        validate_repo_path(tmp_path)  # must not raise

    def test_accepts_fixture_directory(self):
        """A known fixture repo directory passes validation."""
        validate_repo_path(FIXTURES / "secure_terraform_app")

    def test_rejects_nonexistent_path(self, tmp_path):
        """A path that does not exist raises RepoPathError."""
        with pytest.raises(RepoPathError, match="does not exist"):
            validate_repo_path(tmp_path / "no_such_dir")

    def test_rejects_file_instead_of_directory(self, tmp_path):
        """A file path (not a directory) raises RepoPathError."""
        f = tmp_path / "file.txt"
        f.write_text("not a repo")
        with pytest.raises(RepoPathError, match="not a directory"):
            validate_repo_path(f)


class TestResolveRepoInput:
    def test_resolves_local_path(self):
        """A valid local path string is returned as a Path without cloning."""
        result = resolve_repo_input(str(FIXTURES / "secure_terraform_app"))
        assert result.is_dir()

    def test_local_path_is_always_absolute(self):
        """resolve_repo_input returns an absolute path even for a relative input."""
        original = os.getcwd()
        try:
            os.chdir(FIXTURES)
            result = resolve_repo_input("secure_terraform_app")
            assert result.is_absolute()
        finally:
            os.chdir(original)

    def test_rejects_nonexistent_local_path(self, tmp_path):
        """A nonexistent local path raises RepoPathError."""
        with pytest.raises(RepoPathError):
            resolve_repo_input(str(tmp_path / "no_such_dir"))

    def test_url_input_rejects_invalid_scheme(self, tmp_path):
        """A URL input with a disallowed scheme raises RepoURLError before cloning."""
        with patch("subprocess.run") as mock_run:
            with pytest.raises(RepoURLError):
                resolve_repo_input("file:///etc/passwd", clone_base=tmp_path)
            mock_run.assert_not_called()

    def test_url_input_validates_before_cloning(self, tmp_path):
        """A valid HTTPS URL triggers safe_clone (verified via mock)."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            resolve_repo_input("https://github.com/owner/repo.git", clone_base=tmp_path)
        assert mock_run.called

    def test_ext_transport_raises_repo_url_error(self, tmp_path):
        """ext:: is routed as a URL and raises RepoURLError, not RepoPathError."""
        with patch("subprocess.run") as mock_run:
            with pytest.raises(RepoURLError):
                resolve_repo_input("ext::git-remote-helper /tmp/evil", clone_base=tmp_path)
            mock_run.assert_not_called()


# ── Line reader ────────────────────────────────────────────────────────────────


class TestReadFileSlice:
    def test_reads_specified_line_range(self, tmp_path):
        """Returns the requested line range (1-indexed, inclusive)."""
        f = tmp_path / "sample.py"
        f.write_text("line1\nline2\nline3\nline4\nline5\n")

        result = read_file_slice(tmp_path, f, start_line=2, end_line=4)
        assert result.content == "line2\nline3\nline4"
        assert result.start_line == 2
        assert result.end_line == 4

    def test_stops_at_eof_when_end_exceeds_file(self, tmp_path):
        """end_line past EOF returns up to the last line without error."""
        f = tmp_path / "short.py"
        f.write_text("alpha\nbeta\ngamma\n")

        result = read_file_slice(tmp_path, f, start_line=2, end_line=999)
        assert result.end_line == 3
        assert "gamma" in result.content

    def test_past_eof_start_returns_empty_anchored_to_last_line(self, tmp_path):
        """start_line past EOF yields empty content; end_line is the last real line."""
        f = tmp_path / "tiny.py"
        f.write_text("only one line\n")

        result = read_file_slice(tmp_path, f, start_line=99)
        assert result.content == ""
        assert result.end_line == 1  # last valid line, not the requested start

    def test_records_file_path_in_result(self, tmp_path):
        """The result records the file path for evidence citation."""
        f = tmp_path / "cited.py"
        f.write_text("hello\n")
        result = read_file_slice(tmp_path, f)
        assert result.path == str(f)

    def test_reads_full_file_by_default(self, tmp_path):
        """Omitting start/end reads the entire file."""
        f = tmp_path / "full.py"
        f.write_text("a\nb\nc\n")
        result = read_file_slice(tmp_path, f)
        assert result.start_line == 1
        assert result.end_line == 3
        assert result.content == "a\nb\nc"

    def test_rejects_path_outside_repo_root(self, tmp_path):
        """read_file_slice refuses a path that escapes repo_root."""
        repo = tmp_path / "repo"
        repo.mkdir()
        outside = tmp_path / "outside.py"
        outside.write_text("secret\n")

        with pytest.raises(ValueError, match="outside repo root"):
            read_file_slice(repo, outside)
