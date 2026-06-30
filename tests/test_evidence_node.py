"""Evidence collector node — tool selection, normalisation, and fail-closed behaviour."""

from pathlib import Path
from unittest.mock import patch

from agentic_compliance.evidence_collector import (
    collect_evidence,
    file_excerpt_to_evidence,
    finding_to_evidence,
)
from agentic_compliance.kb import ControlEntry, build_exact_index, load_controls
from agentic_compliance.schemas import CollectionResult, EvidenceRef, ToolFinding

FIXTURES = Path(__file__).parent / "fixtures" / "repos"
_CONTROLS = build_exact_index(load_controls())


def _control(control_id: str):
    entry = _CONTROLS.get(control_id)
    assert entry is not None, f"Control {control_id!r} not found in controls.yaml"
    return entry


# ── Schema ─────────────────────────────────────────────────────────────────────


class TestEvidenceRefSchema:
    def test_tool_result_round_trips(self):
        """EvidenceRef with source_type tool_result serialises cleanly."""
        ref = EvidenceRef(
            source_type="tool_result",
            path_or_id="main.tf",
            start_line=10,
            end_line=12,
            excerpt='cidr_blocks = ["0.0.0.0/0"]',
        )
        assert EvidenceRef.model_validate(ref.model_dump()) == ref

    def test_repo_file_round_trips(self):
        """EvidenceRef with source_type repo_file serialises cleanly."""
        ref = EvidenceRef(
            source_type="repo_file",
            path_or_id="src/config.py",
            start_line=1,
            end_line=5,
            excerpt="HOST = 'localhost'",
        )
        assert EvidenceRef.model_validate(ref.model_dump()) == ref

    def test_control_kb_round_trips(self):
        """EvidenceRef with source_type control_kb serialises cleanly."""
        ref = EvidenceRef(source_type="control_kb", path_or_id="SC-8", excerpt="TLS required")
        assert EvidenceRef.model_validate(ref.model_dump()) == ref


class TestCollectionResultSchema:
    def test_empty_result_round_trips(self):
        """CollectionResult with no evidence serialises cleanly."""
        r = CollectionResult(
            control_id="SC-8", evidence=[], errors=[], limitations=["no IaC files found"]
        )
        assert CollectionResult.model_validate(r.model_dump()) == r

    def test_result_with_evidence_round_trips(self):
        """CollectionResult with evidence items serialises cleanly."""
        ref = EvidenceRef(source_type="tool_result", path_or_id="main.tf", excerpt="0.0.0.0/0")
        r = CollectionResult(control_id="AC-6", evidence=[ref], errors=[], limitations=[])
        assert CollectionResult.model_validate(r.model_dump()) == r


# ── Normalisation ──────────────────────────────────────────────────────────────


class TestNormalisation:
    def test_finding_to_evidence_sets_tool_result_source_type(self):
        """finding_to_evidence produces source_type='tool_result'."""
        f = ToolFinding(
            path="main.tf",
            start_line=5,
            end_line=5,
            finding_type="wildcard_iam",
            check_family="terraform",
            severity="high",
            message="Wildcard IAM action",
            control_hints=["AC-6"],
            excerpt='Action = "*"',
        )
        ref = finding_to_evidence(f)
        assert ref.source_type == "tool_result"
        assert ref.path_or_id == "main.tf"
        assert ref.start_line == 5
        assert ref.end_line == 5
        assert ref.excerpt == 'Action = "*"'

    def test_finding_to_evidence_preserves_redacted_excerpt(self):
        """finding_to_evidence does not unmask a redacted secrets excerpt."""
        f = ToolFinding(
            path="config.py",
            start_line=3,
            end_line=3,
            finding_type="aws_access_key",
            check_family="secrets",
            severity="high",
            message="AWS key",
            control_hints=["IA-5"],
            excerpt="AWS_KEY = [REDACTED]",
            redacted=True,
        )
        ref = finding_to_evidence(f)
        assert ref.excerpt == "AWS_KEY = [REDACTED]"
        assert "AKIA" not in ref.excerpt

    def test_file_excerpt_to_evidence_sets_repo_file_source_type(self, tmp_path):
        """file_excerpt_to_evidence produces source_type='repo_file'."""
        (tmp_path / "main.tf").write_text("resource aws_s3_bucket x {}\n")
        ref = file_excerpt_to_evidence(tmp_path, "main.tf", 1, 1)
        assert ref.source_type == "repo_file"
        assert ref.start_line == 1
        assert ref.end_line == 1
        assert "aws_s3_bucket" in ref.excerpt

    def test_file_excerpt_path_or_id_is_repo_relative(self, tmp_path):
        """file_excerpt_to_evidence stores a repo-relative path, not an absolute one."""
        (tmp_path / "app.py").write_text("x = 1\n")
        ref = file_excerpt_to_evidence(tmp_path, "app.py")
        assert not Path(ref.path_or_id).is_absolute(), (
            f"Expected repo-relative path, got absolute: {ref.path_or_id!r}"
        )
        assert ref.path_or_id == "app.py"


# ── collect_evidence — fixture-backed integration tests ───────────────────────


class TestCollectEvidenceSC8:
    def test_sc8_finds_plain_http_listener(self):
        """collect_evidence finds the plain HTTP listener in insecure_terraform_app for SC-8."""
        result = collect_evidence(FIXTURES / "insecure_terraform_app", _control("SC-8"))
        assert result.errors == []
        assert result.evidence, "Expected SC-8 evidence from plain HTTP listener"
        types = {ref.path_or_id + ":" + ref.excerpt for ref in result.evidence}
        assert any("HTTP" in t or "http" in t.lower() for t in types)

    def test_sc8_evidence_is_control_relevant(self):
        """SC-8 evidence contains only findings mapped to SC-8, not AC-6 or SC-28."""
        result = collect_evidence(FIXTURES / "insecure_terraform_app", _control("SC-8"))
        # wildcard_iam (AC-6) and unencrypted_s3 (SC-28) must not appear
        finding_excerpts = " ".join(ref.excerpt for ref in result.evidence)
        assert "wildcard" not in finding_excerpts.lower()
        assert "Action" not in finding_excerpts

    def test_sc8_evidence_items_are_evidence_refs(self):
        """All evidence items are EvidenceRef instances."""
        result = collect_evidence(FIXTURES / "insecure_terraform_app", _control("SC-8"))
        assert all(isinstance(e, EvidenceRef) for e in result.evidence)

    def test_sc8_evidence_source_type_is_tool_result(self):
        """SC-8 findings come from scan_iac_security and are tagged tool_result."""
        result = collect_evidence(FIXTURES / "insecure_terraform_app", _control("SC-8"))
        assert result.evidence
        for ref in result.evidence:
            assert ref.source_type == "tool_result"


class TestCollectEvidenceAC6:
    def test_ac6_finds_wildcard_iam_evidence(self):
        """collect_evidence finds wildcard IAM evidence in insecure_terraform_app for AC-6."""
        result = collect_evidence(FIXTURES / "insecure_terraform_app", _control("AC-6"))
        assert result.errors == []
        assert result.evidence, "Expected at least one finding for wildcard IAM"
        types = {e.excerpt for e in result.evidence}
        # The wildcard IAM excerpt contains '*'
        assert any("*" in exc for exc in types)

    def test_ac6_does_not_run_ci_or_secrets_tools(self):
        """Collector only calls tools matching AC-6 scanner_hints (terraform only)."""
        # Patch at the tools module — the collector imports lazily from there.
        with (
            patch("agentic_compliance.tools.scan_ci_security") as mock_ci,
            patch("agentic_compliance.tools.scan_secrets") as mock_sec,
        ):
            collect_evidence(FIXTURES / "insecure_terraform_app", _control("AC-6"))
        mock_ci.assert_not_called()
        mock_sec.assert_not_called()


class TestCollectEvidenceSecrets:
    def test_secrets_fixture_has_evidence(self):
        """collect_evidence finds credential evidence in hardcoded_secret_app for IA-5/SI."""
        result = collect_evidence(FIXTURES / "hardcoded_secret_app", _control("IA-5/SI"))
        assert result.errors == []
        assert result.evidence, "Expected at least one secrets finding"

    def test_secrets_excerpts_are_redacted(self):
        """No raw secret value appears in any EvidenceRef excerpt."""
        result = collect_evidence(FIXTURES / "hardcoded_secret_app", _control("IA-5/SI"))
        raw_values = [
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "hunter2-not-a-real-password",
        ]
        for ref in result.evidence:
            for raw in raw_values:
                assert raw not in ref.excerpt, (
                    f"Raw secret {raw!r} leaked into EvidenceRef.excerpt: {ref.excerpt!r}"
                )


class TestCollectEvidenceNoEvidence:
    def test_no_relevant_evidence_returns_empty_list_not_error(self, tmp_path):
        """Repo with no IaC returns empty evidence with a limitation, not an error."""
        (tmp_path / "README.md").write_text("# project\n")
        result = collect_evidence(tmp_path, _control("AC-6"))
        assert result.errors == []
        assert result.evidence == []
        assert result.limitations, "Expected at least one limitation note"

    def test_limitation_note_is_informative(self, tmp_path):
        """The limitation note names the scanner family that was searched."""
        (tmp_path / "README.md").write_text("# project\n")
        result = collect_evidence(tmp_path, _control("AC-6"))
        combined = " ".join(result.limitations)
        assert "terraform" in combined.lower()

    def test_no_scanner_hints_overlap_records_limitation(self):
        """A control whose scanner_hints have no matching tools records a limitation."""
        no_tool_control = ControlEntry(
            id="CM-3",
            name="Change control",
            positive_evidence="CODEOWNERS",
            gap_evidence="No CODEOWNERS",
            notes="Often not-assessable",
            scanner_hints=[],  # no hints → no tools
            evidence_hints=[],
            embed_text="change control",
        )
        result = collect_evidence(FIXTURES / "secure_terraform_app", no_tool_control)
        assert result.evidence == []
        assert result.errors == []
        assert result.limitations


class TestCollectEvidenceFailClosed:
    def test_tool_error_recorded_in_errors_not_raised(self):
        """A tool exception is captured in errors — the collector does not crash."""
        with patch(
            "agentic_compliance.tools.scan_iac_security",
            side_effect=RuntimeError("disk error"),
        ):
            result = collect_evidence(FIXTURES / "insecure_terraform_app", _control("SC-8"))
        assert any("scan_iac_security" in e for e in result.errors)
        assert "disk error" in " ".join(result.errors)

    def test_tool_error_produces_no_evidence(self):
        """When a tool fails the evidence list stays empty (not populated with garbage)."""
        with patch(
            "agentic_compliance.tools.scan_iac_security",
            side_effect=RuntimeError("timeout"),
        ):
            result = collect_evidence(FIXTURES / "insecure_terraform_app", _control("SC-8"))
        assert result.evidence == []

    def test_errors_and_evidence_can_coexist(self):
        """Partial failure: one tool errors, another succeeds — both are recorded."""
        result_before = collect_evidence(FIXTURES / "hardcoded_secret_app", _control("IA-5/SI"))
        # IA-5/SI uses secrets + ci tools; secrets succeeds, mock ci to fail
        with patch(
            "agentic_compliance.tools.scan_ci_security",
            side_effect=RuntimeError("ci tool broke"),
        ):
            result = collect_evidence(FIXTURES / "hardcoded_secret_app", _control("IA-5/SI"))
        # secrets evidence still present
        assert result.evidence
        # ci error recorded
        assert any("scan_ci_security" in e for e in result.errors)
        # same secrets evidence as without the mock
        assert len(result.evidence) == len(result_before.evidence)
