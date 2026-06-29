"""MCP tool functions — schema validation and scanner behaviour."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from agentic_compliance.repo_loader import MAX_FILE_BYTES
from agentic_compliance.schemas import RepoFileListing, ToolFinding
from agentic_compliance.tools import (
    list_repo_files,
    read_file_slice,
    scan_ci_security,
    scan_iac_security,
    scan_secrets,
)

FIXTURES = Path(__file__).parent / "fixtures" / "repos"


# ── Schema validation ──────────────────────────────────────────────────────────


class TestToolFindingSchema:
    def test_valid_finding_round_trips(self):
        """ToolFinding serialises and re-parses without data loss."""
        f = ToolFinding(
            path="src/config.py",
            start_line=10,
            end_line=10,
            finding_type="aws_access_key",
            check_family="secrets",
            severity="high",
            message="Possible hardcoded credential",
            control_hints=["IA-5"],
            excerpt="AWS_ACCESS_KEY_ID = [REDACTED]",
            redacted=True,
            limitations=["Regex-based; may false-positive"],
        )
        assert ToolFinding.model_validate(f.model_dump()) == f

    def test_repo_file_listing_round_trips(self):
        """RepoFileListing serialises and re-parses without data loss."""
        r = RepoFileListing(path="main.tf", size=1024, extension=".tf")
        assert RepoFileListing.model_validate(r.model_dump()) == r

    def test_finding_rejects_unknown_check_family(self):
        """check_family must be one of the declared literals."""
        with pytest.raises(ValidationError):
            ToolFinding(
                path="x.py",
                finding_type="x",
                check_family="unknown_family",  # type: ignore[arg-type]
                severity="info",
                message="",
                control_hints=[],
                excerpt="",
            )

    def test_finding_rejects_unknown_severity(self):
        """severity must be one of high/medium/low/info."""
        with pytest.raises(ValidationError):
            ToolFinding(
                path="x.py",
                finding_type="x",
                check_family="ci",
                severity="critical",  # type: ignore[arg-type]
                message="",
                control_hints=[],
                excerpt="",
            )


# ── list_repo_files ────────────────────────────────────────────────────────────


class TestListRepoFiles:
    def test_returns_repo_file_listing_objects(self):
        """list_repo_files returns RepoFileListing instances."""
        results = list_repo_files(FIXTURES / "secure_terraform_app")
        assert results
        assert all(isinstance(r, RepoFileListing) for r in results)

    def test_paths_are_repo_relative(self):
        """Returned paths do not contain the repo_root prefix."""
        root = FIXTURES / "secure_terraform_app"
        results = list_repo_files(root)
        for r in results:
            assert not Path(r.path).is_absolute(), f"Expected relative path, got {r.path!r}"

    def test_size_is_positive(self):
        """All returned files have a positive byte size."""
        results = list_repo_files(FIXTURES / "secure_terraform_app")
        assert all(r.size > 0 for r in results)


# ── read_file_slice ────────────────────────────────────────────────────────────


class TestReadFileSliceTool:
    def test_returns_requested_lines(self, tmp_path):
        """Tool returns the requested line range."""
        f = tmp_path / "sample.py"
        f.write_text("line1\nline2\nline3\n")
        result = read_file_slice(tmp_path, "sample.py", start_line=2, end_line=2)
        assert result.content == "line2"
        assert result.start_line == 2
        assert result.end_line == 2

    def test_rejects_path_outside_root(self, tmp_path):
        """Tool raises when the path escapes repo_root."""
        repo = tmp_path / "repo"
        repo.mkdir()
        outside = tmp_path / "secret.py"
        outside.write_text("secret\n")
        with pytest.raises(ValueError):
            read_file_slice(repo, "../secret.py")

    def test_rejects_git_config(self, tmp_path):
        """Tool rejects .git/config even though it is inside repo_root."""
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("[core]\n\tbare = false\n")
        (tmp_path / "main.py").write_text("x = 1\n")
        with pytest.raises(ValueError):
            read_file_slice(tmp_path, ".git/config")

    def test_rejects_oversized_file(self, tmp_path):
        """Tool rejects a file exceeding MAX_FILE_BYTES."""
        (tmp_path / "huge.py").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
        with pytest.raises(ValueError):
            read_file_slice(tmp_path, "huge.py")

    def test_rejects_binary_file(self, tmp_path):
        """Tool rejects a binary file (null bytes in first 8 KiB)."""
        (tmp_path / "compiled.py").write_bytes(b"\x00\x01\x02" + b"x = 1")
        with pytest.raises(ValueError):
            read_file_slice(tmp_path, "compiled.py")

    def test_works_end_to_end_when_repo_root_from_resolve_repo_input(self):
        """Regression: read_file_slice succeeds when repo_root comes from resolve_repo_input.

        Before the path normalization fix, resolve_repo_input returned a relative Path for
        local inputs, causing the allowlist comparison in read_file_slice to always fail
        with 'not an allowed file' even for valid files.
        """
        import os  # noqa: PLC0415

        from agentic_compliance.repo_loader import resolve_repo_input  # noqa: PLC0415

        original = os.getcwd()
        try:
            # cd to the test root so the fixture path is a relative string
            os.chdir(Path(__file__).parent)
            root = resolve_repo_input("fixtures/repos/secure_terraform_app")
            assert root.is_absolute(), "resolve_repo_input must return an absolute path"
            # Must not raise — this was the regression path
            result = read_file_slice(root, "main.tf", 1, 1)
            assert result.start_line == 1
        finally:
            os.chdir(original)


# ── Secrets scanner ────────────────────────────────────────────────────────────


class TestScanSecrets:
    def test_finds_aws_access_key_in_fixture(self):
        """scan_secrets detects the AWS access key in hardcoded_secret_app."""
        findings = scan_secrets(FIXTURES / "hardcoded_secret_app")
        types = {f.finding_type for f in findings}
        assert "aws_access_key" in types

    def test_finds_generic_secret_in_fixture(self):
        """scan_secrets detects DB_PASSWORD and AWS_SECRET_ACCESS_KEY."""
        findings = scan_secrets(FIXTURES / "hardcoded_secret_app")
        types = {f.finding_type for f in findings}
        assert "generic_secret_assignment" in types

    def test_all_findings_are_redacted(self):
        """Every secrets finding has redacted=True."""
        findings = scan_secrets(FIXTURES / "hardcoded_secret_app")
        assert findings, "Expected at least one finding"
        assert all(f.redacted for f in findings)

    def test_raw_secret_value_not_in_excerpt(self):
        """The raw AWS key value does not appear in any excerpt."""
        findings = scan_secrets(FIXTURES / "hardcoded_secret_app")
        raw_values = [
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "hunter2-not-a-real-password",
        ]
        for f in findings:
            for raw in raw_values:
                assert raw not in f.excerpt, (
                    f"Raw secret value {raw!r} leaked into excerpt: {f.excerpt!r}"
                )

    def test_outputs_match_schema(self):
        """All findings round-trip through the ToolFinding schema."""
        for f in scan_secrets(FIXTURES / "hardcoded_secret_app"):
            assert ToolFinding.model_validate(f.model_dump()) == f

    def test_clean_repo_returns_no_secrets(self):
        """secure_terraform_app contains no credentials."""
        findings = scan_secrets(FIXTURES / "secure_terraform_app")
        secret_findings = [f for f in findings if f.check_family == "secrets"]
        assert not secret_findings


# ── IaC security scanner ───────────────────────────────────────────────────────


class TestScanIACSecurity:
    def test_finds_public_ingress_in_insecure_fixture(self):
        """scan_iac_security finds open 0.0.0.0/0 ingress in insecure_terraform_app."""
        findings = scan_iac_security(FIXTURES / "insecure_terraform_app")
        types = {f.finding_type for f in findings}
        assert "public_ingress" in types

    def test_finds_wildcard_iam_in_insecure_fixture(self):
        """scan_iac_security finds wildcard Action/Resource in insecure_terraform_app."""
        findings = scan_iac_security(FIXTURES / "insecure_terraform_app")
        types = {f.finding_type for f in findings}
        assert "wildcard_iam" in types

    def test_finds_unencrypted_s3_in_insecure_fixture(self):
        """scan_iac_security finds missing S3 SSE config in insecure_terraform_app."""
        findings = scan_iac_security(FIXTURES / "insecure_terraform_app")
        types = {f.finding_type for f in findings}
        assert "unencrypted_s3" in types

    def test_no_public_ingress_in_secure_fixture(self):
        """secure_terraform_app has no 0.0.0.0/0 ingress rules."""
        findings = scan_iac_security(FIXTURES / "secure_terraform_app")
        assert not any(f.finding_type == "public_ingress" for f in findings)

    def test_no_wildcard_iam_in_secure_fixture(self):
        """secure_terraform_app uses scoped IAM — no wildcard_iam finding."""
        findings = scan_iac_security(FIXTURES / "secure_terraform_app")
        assert not any(f.finding_type == "wildcard_iam" for f in findings)

    def test_all_findings_have_correct_check_family(self):
        """All terraform findings have check_family in the declared set."""
        valid = {"terraform", "dockerfile", "kubernetes_yaml", "logging_monitoring", "ci"}
        for f in scan_iac_security(FIXTURES / "insecure_terraform_app"):
            assert f.check_family in valid

    def test_outputs_match_schema(self):
        """All findings round-trip through the ToolFinding schema."""
        for f in scan_iac_security(FIXTURES / "insecure_terraform_app"):
            assert ToolFinding.model_validate(f.model_dump()) == f

    def test_finds_missing_s3_versioning_in_insecure_fixture(self):
        """scan_iac_security flags missing S3 versioning in insecure_terraform_app."""
        findings = scan_iac_security(FIXTURES / "insecure_terraform_app")
        assert any(f.finding_type == "missing_s3_versioning" for f in findings)

    def test_dockerfile_flags_unpinned_base_image(self, tmp_path):
        """scan_iac_security flags FROM image:latest in a Dockerfile."""
        (tmp_path / "Dockerfile").write_text("FROM python:latest\nRUN pip install flask\n")
        findings = scan_iac_security(tmp_path)
        assert any(f.finding_type == "dockerfile_unpinned_base_image" for f in findings)

    def test_dockerfile_does_not_flag_pinned_image(self, tmp_path):
        """scan_iac_security does not flag a pinned base image."""
        (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nRUN pip install flask\n")
        findings = scan_iac_security(tmp_path)
        assert not any(f.finding_type == "dockerfile_unpinned_base_image" for f in findings)

    def test_dockerfile_flags_env_secret(self, tmp_path):
        """scan_iac_security flags ENV with a secret-looking variable name."""
        (tmp_path / "Dockerfile").write_text("FROM python:3.12\nENV DB_PASSWORD=hunter2\n")
        findings = scan_iac_security(tmp_path)
        env_findings = [f for f in findings if f.finding_type == "dockerfile_secret_in_build_arg"]
        assert env_findings
        assert all(f.redacted for f in env_findings)
        assert not any("hunter2" in f.excerpt for f in env_findings)

    def test_k8s_flags_host_network(self, tmp_path):
        """scan_iac_security flags hostNetwork: true in a K8s manifest."""
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n    - name: app\n"
        )
        findings = scan_iac_security(tmp_path)
        assert any(f.finding_type == "k8s_host_network" for f in findings)

    def test_k8s_flags_host_pid(self, tmp_path):
        """scan_iac_security flags hostPID: true in a K8s manifest."""
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nspec:\n  hostPID: true\n  containers:\n    - name: app\n"
        )
        findings = scan_iac_security(tmp_path)
        assert any(f.finding_type == "k8s_host_pid" for f in findings)

    def test_k8s_flags_missing_resource_limits(self, tmp_path):
        """scan_iac_security flags missing resource limits in a K8s manifest."""
        (tmp_path / "deploy.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
            "      containers:\n        - name: app\n          image: python:3.12\n"
        )
        findings = scan_iac_security(tmp_path)
        assert any(f.finding_type == "k8s_missing_resource_limits" for f in findings)

    def test_k8s_flags_missing_security_context(self, tmp_path):
        """scan_iac_security flags missing securityContext in a K8s manifest."""
        (tmp_path / "deploy.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
            "      containers:\n        - name: app\n          image: python:3.12\n"
        )
        findings = scan_iac_security(tmp_path)
        assert any(f.finding_type == "k8s_missing_security_context" for f in findings)

    def test_terraform_flags_plain_http_listener(self, tmp_path):
        """scan_iac_security flags protocol = "HTTP" in a load balancer listener."""
        (tmp_path / "main.tf").write_text(
            'resource "aws_lb_listener" "http" {\n  port     = 80\n  protocol = "HTTP"\n}\n'
        )
        findings = scan_iac_security(tmp_path)
        assert any(f.finding_type == "plain_http_listener" for f in findings)

    def test_terraform_plain_http_listener_has_sc8_control_hint(self, tmp_path):
        """plain_http_listener finding is mapped to SC-8."""
        (tmp_path / "main.tf").write_text('  protocol = "HTTP"\n')
        findings = scan_iac_security(tmp_path)
        for f in findings:
            if f.finding_type == "plain_http_listener":
                assert "SC-8" in f.control_hints

    def test_dockerfile_flags_numeric_uid_zero(self, tmp_path):
        """scan_iac_security flags USER 0 (numeric root UID)."""
        (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nUSER 0\n")
        findings = scan_iac_security(tmp_path)
        assert any(f.finding_type == "dockerfile_root_user" for f in findings)

    def test_dockerfile_flags_numeric_uid_zero_with_gid(self, tmp_path):
        """scan_iac_security flags USER 0:0 (UID and GID both zero)."""
        (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nUSER 0:0\n")
        findings = scan_iac_security(tmp_path)
        assert any(f.finding_type == "dockerfile_root_user" for f in findings)

    def test_dockerfile_flags_missing_user_directive(self, tmp_path):
        """scan_iac_security flags a Dockerfile with no USER directive."""
        (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nRUN python --version\n")
        findings = scan_iac_security(tmp_path)
        assert any(f.finding_type == "dockerfile_missing_nonroot_user" for f in findings)

    def test_dockerfile_does_not_flag_nonroot_user(self, tmp_path):
        """scan_iac_security does not flag dockerfile_missing_nonroot_user when USER is set."""
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12-slim\nRUN useradd -m appuser\nUSER appuser\n"
        )
        findings = scan_iac_security(tmp_path)
        assert not any(f.finding_type == "dockerfile_missing_nonroot_user" for f in findings)

    def test_dockerfile_does_not_flag_uid_user(self, tmp_path):
        """scan_iac_security does not flag dockerfile_missing_nonroot_user for USER <uid>."""
        (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nUSER 10001\n")
        findings = scan_iac_security(tmp_path)
        assert not any(f.finding_type == "dockerfile_missing_nonroot_user" for f in findings)

    def test_empty_repo_returns_no_findings(self, tmp_path):
        """A repo with no IaC files returns an empty list."""
        (tmp_path / "README.md").write_text("nothing here\n")
        findings = scan_iac_security(tmp_path)
        # logging_monitoring check fires only when .tf files are present
        assert not any(f.check_family == "terraform" for f in findings)


# ── CI security scanner ────────────────────────────────────────────────────────


class TestScanCISecurity:
    def test_finds_pip_audit_in_secure_ci_fixture(self):
        """scan_ci_security reports pip-audit as present in ci_scanning_repo."""
        findings = scan_ci_security(FIXTURES / "ci_scanning_repo")
        types = {f.finding_type for f in findings}
        assert "dependency_audit_present" in types

    def test_finds_container_scanner_in_secure_ci_fixture(self):
        """scan_ci_security reports trivy as present in ci_scanning_repo."""
        findings = scan_ci_security(FIXTURES / "ci_scanning_repo")
        types = {f.finding_type for f in findings}
        assert "container_scan_present" in types

    def test_flags_missing_dependency_audit_in_no_security_fixture(self):
        """scan_ci_security flags missing dep scanner in ci_no_security_repo."""
        findings = scan_ci_security(FIXTURES / "ci_no_security_repo")
        types = {f.finding_type for f in findings}
        assert "dependency_audit_missing" in types

    def test_flags_missing_container_scanner_in_no_security_fixture(self):
        """scan_ci_security flags missing container scanner in ci_no_security_repo."""
        findings = scan_ci_security(FIXTURES / "ci_no_security_repo")
        types = {f.finding_type for f in findings}
        assert "container_scan_missing" in types

    def test_flags_missing_sast(self):
        """scan_ci_security flags missing SAST when no tool found in workflows."""
        # Neither ci fixture includes CodeQL/semgrep/bandit
        findings = scan_ci_security(FIXTURES / "ci_no_security_repo")
        assert any(f.finding_type == "sast_missing" for f in findings)

    def test_flags_missing_secret_scan_hook(self):
        """scan_ci_security flags missing secret-scanning hook."""
        findings = scan_ci_security(FIXTURES / "ci_no_security_repo")
        assert any(f.finding_type == "secret_scan_missing" for f in findings)

    def test_flags_missing_permissions_declaration(self):
        """scan_ci_security flags missing permissions: in workflow files."""
        # ci_scanning_repo has no permissions: declaration
        findings = scan_ci_security(FIXTURES / "ci_scanning_repo")
        assert any(f.finding_type == "missing_permissions_declaration" for f in findings)

    def test_finds_sast_when_present(self, tmp_path):
        """scan_ci_security reports sast_present when CodeQL is in the workflow."""
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "codeql.yml").write_text(
            "name: codeql\non: push\npermissions:\n  security-events: write\n"
            "jobs:\n  analyze:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: github/codeql-action/analyze@v3\n"
        )
        findings = scan_ci_security(tmp_path)
        assert any(f.finding_type == "sast_present" for f in findings)

    def test_flags_overly_broad_permissions(self, tmp_path):
        """scan_ci_security flags permissions: write-all as high severity."""
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "broad.yml").write_text(
            "name: broad\non: push\npermissions: write-all\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        )
        findings = scan_ci_security(tmp_path)
        broad = [f for f in findings if f.finding_type == "overly_broad_permissions"]
        assert broad
        assert all(f.severity == "high" for f in broad)

    def test_no_ci_repo_returns_empty(self):
        """A repo with no workflow files produces no CI findings."""
        findings = scan_ci_security(FIXTURES / "no_iac_repo")
        assert findings == []

    def test_outputs_match_schema(self):
        """All findings round-trip through the ToolFinding schema."""
        for f in scan_ci_security(FIXTURES / "ci_scanning_repo"):
            assert ToolFinding.model_validate(f.model_dump()) == f


# ── MCP server smoke test ──────────────────────────────────────────────────────


class TestMCPServer:
    @pytest.mark.agent
    def test_mcp_server_imports_without_error(self):
        """mcp_server module loads and exposes the FastMCP instance."""
        from agentic_compliance.mcp_server import mcp  # noqa: PLC0415

        assert mcp is not None
        assert mcp.name == "agentic-compliance"

    @pytest.mark.agent
    def test_mcp_server_exposes_five_tools(self):
        """FastMCP instance has exactly the five declared tools."""
        import asyncio  # noqa: PLC0415

        from agentic_compliance.mcp_server import mcp  # noqa: PLC0415

        tools = asyncio.run(mcp.list_tools())
        names = {t.name for t in tools}
        assert names == {
            "list_repo_files",
            "read_file_slice",
            "scan_secrets",
            "scan_iac_security",
            "scan_ci_security",
        }
