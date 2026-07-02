"""Semantic control selection: feature detection, query building, retrieval, CLI."""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentic_compliance.control_selection import (
    build_selection_query,
    detect_features,
    explicit_selection,
    select_controls,
)
from agentic_compliance.kb import build_exact_index, load_controls
from agentic_compliance.retriever import ControlsRetriever
from agentic_compliance.schemas import (
    SelectedControl,
    SelectionResult,
    SynthesizerOutput,
    VerdictClass,
    VerifierDecision,
)

FIXTURES = Path(__file__).parent / "fixtures" / "repos"
_CONTROLS_PATH = Path(__file__).parent.parent / "data" / "controls.yaml"
_CONTROLS = build_exact_index(load_controls())


def _ctrl(cid: str):
    c = _CONTROLS.get(cid)
    assert c is not None, f"Control {cid!r} not found"
    return c


# ── Fake vector store ──────────────────────────────────────────────────────────


class _FakeVectorStore:
    """In-memory store returning pre-configured (Document, distance) pairs.

    Distances are in [0, 1] (lower=better), mirroring Chroma's typical output.
    """

    def __init__(self, pairs):
        # pairs: list of (Document, float) in intended ranking order
        self._pairs = pairs

    def similarity_search_with_score(self, query: str, k: int = 3):
        return self._pairs[:k]

    def similarity_search(self, query: str, k: int = 3):
        return [doc for doc, _ in self._pairs[:k]]


def _fake_doc(control_id: str):
    """Create a minimal LangChain Document-like object for the fake store."""
    doc = MagicMock()
    doc.metadata = {"control_id": control_id}
    return doc


# ── Feature detection ──────────────────────────────────────────────────────────


class TestDetectFeatures:
    def test_detects_terraform(self, tmp_path):
        """Terraform .tf file → 'terraform' feature detected."""
        (tmp_path / "main.tf").write_text("resource {} {}")
        assert "terraform" in detect_features(tmp_path)

    def test_detects_dockerfile(self, tmp_path):
        """Dockerfile → 'dockerfile' feature detected."""
        (tmp_path / "Dockerfile").write_text("FROM ubuntu")
        assert "dockerfile" in detect_features(tmp_path)

    def test_detects_github_actions(self, tmp_path):
        """YAML under .github/workflows/ → 'github_actions' feature detected."""
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("on: push")
        assert "github_actions" in detect_features(tmp_path)

    def test_detects_python(self, tmp_path):
        """Python .py file → 'python' feature detected."""
        (tmp_path / "main.py").write_text("print('hello')")
        assert "python" in detect_features(tmp_path)

    def test_empty_repo_detects_no_features(self, tmp_path):
        """Empty directory → no features detected."""
        assert detect_features(tmp_path) == []

    def test_multiple_features_detected(self, tmp_path):
        """Repo with Terraform + Dockerfile → both features detected."""
        (tmp_path / "main.tf").write_text("resource {} {}")
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        features = detect_features(tmp_path)
        assert "terraform" in features
        assert "dockerfile" in features

    def test_git_dir_skipped(self, tmp_path):
        """Files under .git/ are not classified."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "main.tf").write_text("resource {} {}")
        assert detect_features(tmp_path) == []

    def test_yaml_not_in_workflows_is_not_github_actions(self, tmp_path):
        """A YAML file outside .github/workflows/ is not classified as github_actions."""
        (tmp_path / "config.yml").write_text("key: value")
        assert "github_actions" not in detect_features(tmp_path)


class TestDetectTerraformResources:
    def test_lb_listener_adds_terraform_lb_feature(self, tmp_path):
        """aws_lb_listener resource in .tf → terraform_lb feature detected."""
        (tmp_path / "main.tf").write_text('resource "aws_lb_listener" "https" {}\n')
        features = detect_features(tmp_path)
        assert "terraform_lb" in features

    def test_s3_bucket_adds_terraform_s3_feature(self, tmp_path):
        """aws_s3_bucket resource in .tf → terraform_s3 feature detected."""
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "data" {}\n')
        features = detect_features(tmp_path)
        assert "terraform_s3" in features

    def test_iam_policy_adds_terraform_iam_feature(self, tmp_path):
        """aws_iam_policy resource in .tf → terraform_iam feature detected."""
        (tmp_path / "main.tf").write_text('resource "aws_iam_policy" "p" {}\n')
        features = detect_features(tmp_path)
        assert "terraform_iam" in features

    def test_cloudtrail_adds_terraform_cloudtrail_feature(self, tmp_path):
        """aws_cloudtrail resource in .tf → terraform_cloudtrail feature detected."""
        (tmp_path / "main.tf").write_text('resource "aws_cloudtrail" "trail" {}\n')
        features = detect_features(tmp_path)
        assert "terraform_cloudtrail" in features

    def test_security_group_adds_terraform_network_feature(self, tmp_path):
        """aws_security_group resource in .tf → terraform_network feature detected."""
        (tmp_path / "main.tf").write_text('resource "aws_security_group" "web" {}\n')
        features = detect_features(tmp_path)
        assert "terraform_network" in features

    def test_subnet_adds_terraform_network_feature(self, tmp_path):
        """aws_subnet resource in .tf → terraform_network feature detected."""
        (tmp_path / "main.tf").write_text('resource "aws_subnet" "app" {}\n')
        features = detect_features(tmp_path)
        assert "terraform_network" in features

    def test_partial_network_fixture_detects_network_feature(self):
        """partial_network_app's subnets/security groups → terraform_network feature."""
        features = detect_features(FIXTURES / "partial_network_app")
        assert "terraform_network" in features

    def test_partial_network_fixture_query_contains_boundary_terms(self):
        """Query built from partial_network_app features includes SC-7 vocabulary."""
        features = detect_features(FIXTURES / "partial_network_app")
        query = build_selection_query(features)
        assert any(term in query for term in ("boundary", "segmentation", "security group"))

    def test_no_tf_resources_adds_no_sub_features(self, tmp_path):
        """Empty .tf file → only 'terraform' feature, no sub-features."""
        (tmp_path / "main.tf").write_text("# empty\n")
        features = detect_features(tmp_path)
        assert "terraform" in features
        assert "terraform_lb" not in features
        assert "terraform_s3" not in features

    def test_secure_fixture_detects_lb_and_s3(self):
        """secure_terraform_app has aws_lb_listener and aws_s3_bucket → both sub-features."""
        features = detect_features(FIXTURES / "secure_terraform_app")
        assert "terraform_lb" in features
        assert "terraform_s3" in features

    def test_secure_fixture_query_contains_tls_terms(self):
        """Query built from secure_terraform_app features includes TLS/HTTPS vocab."""
        features = detect_features(FIXTURES / "secure_terraform_app")
        query = build_selection_query(features)
        assert any(term in query for term in ("TLS", "HTTPS", "load balancer"))

    def test_secure_fixture_query_contains_s3_terms(self):
        """Query built from secure_terraform_app features includes S3/encryption vocab."""
        features = detect_features(FIXTURES / "secure_terraform_app")
        query = build_selection_query(features)
        assert any(term in query for term in ("S3", "SSE", "encryption"))

    def test_symlink_escape_is_not_followed(self, tmp_path):
        """A .tf symlink pointing outside repo_root must not be read.

        Regression test: _detect_terraform_resources() previously walked the repo
        with its own os.walk() instead of iter_repo_files(), bypassing symlink-escape
        protection. A symlinked .tf file pointing outside the repo root must not
        contribute sub-features derived from the external file's content.
        """
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.tf").write_text('resource "aws_cloudtrail" "trail" {}\n')

        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        (repo_root / "main.tf").write_text("# empty\n")
        (repo_root / "escape.tf").symlink_to(outside / "secret.tf")

        features = detect_features(repo_root)
        assert "terraform_cloudtrail" not in features


# ── Query construction ─────────────────────────────────────────────────────────


class TestBuildSelectionQuery:
    def test_empty_features_returns_fallback(self):
        """No features → non-empty fallback query."""
        q = build_selection_query([])
        assert len(q) > 0

    def test_terraform_feature_produces_query(self):
        """Terraform feature → query contains relevant terms."""
        q = build_selection_query(["terraform"])
        assert len(q) > 0
        # Query should reference infrastructure or IAM concepts.
        q_lower = q.lower()
        assert any(term in q_lower for term in ("terraform", "iam", "encryption", "access"))

    def test_multiple_features_produce_longer_query(self):
        """More features → more terms in query (deduplication aside)."""
        q_single = build_selection_query(["terraform"])
        q_multi = build_selection_query(["terraform", "dockerfile", "github_actions"])
        assert len(q_multi) >= len(q_single)

    def test_overlapping_words_across_features_are_preserved(self):
        """Words shared between a base feature and its sub-feature (e.g. "IAM" in
        both "terraform" and "terraform_iam") are not stripped.

        Regression test: cross-phrase word dedup previously stripped a sub-feature's
        strongest terms whenever they overlapped with the broader "terraform" phrase,
        diluting that control's embedding signal enough to drop AC-6 out of the top-k
        for secure_terraform_app in favor of zero-evidence controls.
        """
        q = build_selection_query(["terraform", "terraform_iam"])
        words = q.lower().split()
        assert words.count("iam") >= 2


# ── Dynamic selection ──────────────────────────────────────────────────────────


class TestSelectControls:
    def _make_retriever(self, control_ids_with_distances):
        """Build a ControlsRetriever backed by a fake in-memory store."""
        controls = load_controls()
        pairs = [(_fake_doc(cid), dist) for cid, dist in control_ids_with_distances]
        store = _FakeVectorStore(pairs)
        return ControlsRetriever(controls, store)

    def test_dynamic_mode_returned(self, tmp_path):
        """select_controls returns mode='dynamic'."""
        retriever = self._make_retriever([("AC-6", 0.2)])
        result = select_controls(tmp_path, retriever, top_k=3)
        assert result.mode == "dynamic"

    def test_top_k_recorded_in_result(self, tmp_path):
        """top_k value is recorded in SelectionResult even when fewer controls match."""
        retriever = self._make_retriever([("AC-6", 0.3)])
        result = select_controls(tmp_path, retriever, top_k=5)
        assert result.top_k == 5

    def test_ranking_order_preserved(self, tmp_path):
        """Controls are returned in descending relevance order (lowest distance first)."""
        retriever = self._make_retriever([("AC-6", 0.1), ("SC-8", 0.4)])
        result = select_controls(tmp_path, retriever, top_k=5)
        ids = [sc.control_id for sc in result.selected_controls]
        assert ids == ["AC-6", "SC-8"]

    def test_score_normalization(self, tmp_path):
        """Distance 0.2 → relevance_score ≈ 0.9 (1 - distance/2, clamped to [0, 1])."""
        retriever = self._make_retriever([("AC-6", 0.2)])
        result = select_controls(tmp_path, retriever, top_k=3)
        score = result.selected_controls[0].relevance_score
        assert score is not None
        assert abs(score - 0.9) < 1e-9

    def test_scores_in_valid_range(self, tmp_path):
        """All relevance scores are in [0, 1]."""
        retriever = self._make_retriever([("AC-6", 0.0), ("SC-8", 0.5), ("IA-5", 0.95)])
        result = select_controls(tmp_path, retriever, top_k=5)
        for sc in result.selected_controls:
            assert sc.relevance_score is not None
            assert 0.0 <= sc.relevance_score <= 1.0

    def test_top_k_limits_results(self, tmp_path):
        """select_controls returns at most top_k results."""
        retriever = self._make_retriever([("AC-6", 0.1), ("SC-8", 0.2), ("IA-5", 0.3)])
        result = select_controls(tmp_path, retriever, top_k=2)
        assert len(result.selected_controls) <= 2

    def test_top_k_zero_raises_value_error(self, tmp_path):
        """select_controls raises ValueError when top_k=0."""
        retriever = self._make_retriever([("AC-6", 0.1)])
        with pytest.raises(ValueError, match="positive integer"):
            select_controls(tmp_path, retriever, top_k=0)

    def test_top_k_negative_raises_value_error(self, tmp_path):
        """select_controls raises ValueError when top_k is negative."""
        retriever = self._make_retriever([("AC-6", 0.1)])
        with pytest.raises(ValueError, match="positive integer"):
            select_controls(tmp_path, retriever, top_k=-2)

    def test_detected_features_populated(self, tmp_path):
        """detected_features reflects what was found in the repo."""
        (tmp_path / "main.tf").write_text("resource {} {}")
        retriever = self._make_retriever([("AC-6", 0.2)])
        result = select_controls(tmp_path, retriever, top_k=3)
        assert "terraform" in result.detected_features

    def test_selection_query_non_empty(self, tmp_path):
        """selection_query is always a non-empty string."""
        retriever = self._make_retriever([("AC-6", 0.2)])
        result = select_controls(tmp_path, retriever, top_k=3)
        assert len(result.selection_query) > 0


# ── Real-embedding selection accuracy (agent lane) ─────────────────────────────


class TestSelectControlsSemanticAccuracy:
    @pytest.mark.agent
    def test_secure_terraform_app_selects_ac6(self):
        """Dynamic selection for secure_terraform_app's real top-k includes AC-6.

        Regression test: cross-phrase word dedup in build_selection_query() previously
        stripped AC-6/terraform_iam's strongest terms (they overlapped with the base
        "terraform" phrase), diluting its embedding signal enough that AC-6 dropped out
        of the top-6 in favor of zero-evidence controls (IA-5, IA-2, CM-2/CM-6). Nothing
        else in the fast lane exercises real embeddings against this fixture, so this is
        the only guard against that regression recurring.
        """
        retriever = ControlsRetriever.from_yaml(_CONTROLS_PATH)
        result = select_controls(FIXTURES / "secure_terraform_app", retriever, top_k=6)
        ids = [c.control_id for c in result.selected_controls]
        assert "AC-6" in ids, f"AC-6 not in top-6 for secure_terraform_app; got: {ids}"

    @pytest.mark.agent
    def test_partial_network_app_selects_sc7(self):
        """Dynamic selection for partial_network_app's real top-k includes SC-7.

        Before the terraform_network sub-feature (aws_security_group/aws_subnet/
        aws_db_subnet_group/aws_vpc), SC-7 never appeared in any fixture's top-k —
        no resource-type boost existed for it, unlike SC-8/SC-28/AC-6/AU-2/AU-12.
        This is the regression guard for that gap: partial_network_app is the one
        fixture built specifically to need SC-7 selected.
        """
        retriever = ControlsRetriever.from_yaml(_CONTROLS_PATH)
        result = select_controls(FIXTURES / "partial_network_app", retriever, top_k=6)
        ids = [c.control_id for c in result.selected_controls]
        assert "SC-7" in ids, f"SC-7 not in top-6 for partial_network_app; got: {ids}"


# ── Explicit selection ─────────────────────────────────────────────────────────


class TestExplicitSelection:
    def test_explicit_mode(self):
        """explicit_selection returns mode='explicit'."""
        result = explicit_selection([_ctrl("AC-6")])
        assert result.mode == "explicit"

    def test_no_relevance_scores(self):
        """Explicit selection has relevance_score=None for every control."""
        result = explicit_selection([_ctrl("AC-6"), _ctrl("SC-8")])
        for sc in result.selected_controls:
            assert sc.relevance_score is None

    def test_control_ids_preserved(self):
        """Explicit selection preserves control IDs in user order."""
        result = explicit_selection([_ctrl("SC-8"), _ctrl("AC-6")])
        ids = [sc.control_id for sc in result.selected_controls]
        assert ids == ["SC-8", "AC-6"]

    def test_empty_list(self):
        """Explicit selection of zero controls is valid."""
        result = explicit_selection([])
        assert result.selected_controls == []
        assert result.mode == "explicit"

    def test_metadata_fields_empty(self):
        """Explicit mode has empty detected_features and selection_query."""
        result = explicit_selection([_ctrl("AC-6")])
        assert result.detected_features == []
        assert result.selection_query == ""
        assert result.top_k is None


# ── CLI flag validation ────────────────────────────────────────────────────────


class TestCLI:
    def test_controls_and_top_k_mutually_exclusive(self, tmp_path):
        """--controls and --top-k-controls together return exit code 2."""
        from agentic_compliance.cli import cmd_assess

        args = argparse.Namespace(
            repo_url=None,
            repo_path=str(tmp_path),
            controls="AC-6",
            top_k_controls=3,
            out=str(tmp_path / "report.json"),
            format="json",
        )
        assert cmd_assess(args) == 2

    def test_controls_without_top_k_is_valid(self, tmp_path, monkeypatch):
        """--controls without --top-k-controls passes all checks and reaches run_assessment."""
        from agentic_compliance.cli import cmd_assess
        from agentic_compliance.schemas import FinalReport, SelectionResult

        monkeypatch.setenv("CHAT_MODEL", "anthropic:claude-sonnet-4-6")
        args = argparse.Namespace(
            repo_url=None,
            repo_path=str(tmp_path),
            controls="AC-6",
            top_k_controls=None,
            out=str(tmp_path / "report.json"),
            format="json",
        )
        fake_report = FinalReport(
            repo_path=str(tmp_path),
            verdicts=[],
            selection=SelectionResult(mode="explicit", selected_controls=[]),
            audit={},
        )
        with patch("agentic_compliance.graph.run_assessment", return_value=fake_report):
            result = cmd_assess(args)
        assert result == 0

    def test_parser_has_top_k_controls_flag(self):
        """build_parser registers --top-k-controls on the assess subcommand."""
        from agentic_compliance.cli import build_parser

        p = build_parser()
        args = p.parse_args(["assess", "--repo-path", "/tmp/repo", "--top-k-controls", "8"])
        assert args.top_k_controls == 8

    def test_parser_top_k_default_is_none(self):
        """--top-k-controls defaults to None so explicit and default can be distinguished."""
        from agentic_compliance.cli import build_parser

        p = build_parser()
        args = p.parse_args(["assess", "--repo-path", "/tmp/repo"])
        assert args.top_k_controls is None

    def test_top_k_zero_returns_exit_2(self, tmp_path):
        """CLI rejects --top-k-controls 0 with exit code 2."""
        from agentic_compliance.cli import cmd_assess

        args = argparse.Namespace(
            repo_url=None,
            repo_path=str(tmp_path),
            controls=None,
            top_k_controls=0,
            out=str(tmp_path / "report.json"),
            format="json",
        )
        assert cmd_assess(args) == 2

    def test_top_k_negative_returns_exit_2(self, tmp_path):
        """CLI rejects --top-k-controls with a negative value with exit code 2."""
        from agentic_compliance.cli import cmd_assess

        args = argparse.Namespace(
            repo_url=None,
            repo_path=str(tmp_path),
            controls=None,
            top_k_controls=-2,
            out=str(tmp_path / "report.json"),
            format="json",
        )
        assert cmd_assess(args) == 2

    def test_missing_chat_model_returns_exit_2(self, tmp_path, capsys, monkeypatch):
        """CLI returns exit code 2 with an actionable message when CHAT_MODEL is unset.

        Regression guard for the .env-loading fix: without this check, a user running
        the CLI directly from a shell (no IDE envFile, no Docker --env-file) would hit
        a bare KeyError deep inside the graph instead of a clear, fixable message.
        """
        from agentic_compliance.cli import cmd_assess

        monkeypatch.delenv("CHAT_MODEL", raising=False)
        args = argparse.Namespace(
            repo_url=None,
            repo_path=str(tmp_path),
            controls=None,
            top_k_controls=None,
            out=str(tmp_path / "report.json"),
            format="json",
        )
        result = cmd_assess(args)
        assert result == 2
        captured = capsys.readouterr()
        assert "CHAT_MODEL" in captured.err
        assert ".env.example" in captured.err

    def test_missing_kb_returns_exit_2(self, tmp_path, capsys, monkeypatch):
        """CLI returns exit code 2 with a clean message when the KB is missing."""
        from unittest.mock import patch

        from agentic_compliance.cli import cmd_assess

        monkeypatch.setenv("CHAT_MODEL", "anthropic:claude-sonnet-4-6")
        args = argparse.Namespace(
            repo_url=None,
            repo_path=str(tmp_path),
            controls=None,
            top_k_controls=None,
            out=str(tmp_path / "report.json"),
            format="json",
        )
        with patch(
            "agentic_compliance.graph.run_assessment",
            side_effect=FileNotFoundError("No KB. Run 'ingest-controls' first."),
        ):
            result = cmd_assess(args)

        assert result == 2
        captured = capsys.readouterr()
        assert "ingest-controls" in captured.err


# ── Graph integration ──────────────────────────────────────────────────────────


class TestGraphSelectionIntegration:
    def test_final_report_has_selection(self, tmp_path):
        """FinalReport.selection is set after a graph run with explicit controls."""
        from agentic_compliance.graph import _build_graph, _initial_state
        from agentic_compliance.schemas import FinalReport

        controls = [_ctrl("AC-6")]
        synth = MagicMock()
        synth.invoke.return_value = SynthesizerOutput(verdict=VerdictClass.gap, rationale="test")
        ver = MagicMock()
        ver.invoke.return_value = VerifierDecision(approved=True, notes="ok")

        state = _initial_state(tmp_path, controls)
        g = _build_graph(synthesizer=synth, verifier=ver)
        result = g.invoke(state, config={"recursion_limit": 200})
        report = FinalReport.model_validate(result["final_report"])

        assert isinstance(report.selection, SelectionResult)
        assert report.selection.mode == "explicit"
        assert len(report.selection.selected_controls) == 1
        assert report.selection.selected_controls[0].control_id == "AC-6"

    def test_run_assessment_explicit_selection_mode(self, tmp_path):
        """run_assessment with explicit controls sets selection.mode='explicit'."""
        from agentic_compliance.graph import run_assessment

        synth = MagicMock()
        synth.invoke.return_value = SynthesizerOutput(verdict=VerdictClass.gap, rationale="test")
        ver = MagicMock()
        ver.invoke.return_value = VerifierDecision(approved=True, notes="ok")

        report = run_assessment(tmp_path, controls=[], synthesizer=synth, verifier=ver)

        assert report.selection.mode == "explicit"
        assert report.selection.selected_controls == []

    def test_run_assessment_dynamic_mode(self, tmp_path):
        """run_assessment with controls=None uses dynamic selection (patched retriever)."""
        from agentic_compliance.graph import run_assessment

        ac6 = _ctrl("AC-6")
        fake_selection = SelectionResult(
            mode="dynamic",
            top_k=3,
            detected_features=["python"],
            selection_query="Python secrets",
            selected_controls=[SelectedControl(control_id="AC-6", relevance_score=0.85)],
        )

        synth = MagicMock()
        synth.invoke.return_value = SynthesizerOutput(verdict=VerdictClass.gap, rationale="test")
        ver = MagicMock()
        ver.invoke.return_value = VerifierDecision(approved=True, notes="ok")

        mock_retriever = MagicMock()
        mock_retriever.get_by_ids.return_value = [ac6]

        with (
            patch(
                "agentic_compliance.graph.ControlsRetriever.from_persisted",
                return_value=mock_retriever,
            ),
            patch("agentic_compliance.graph.select_controls", return_value=fake_selection),
        ):
            report = run_assessment(tmp_path, synthesizer=synth, verifier=ver)

        assert report.selection.mode == "dynamic"
        assert report.selection.top_k == 3
        assert report.selection.selected_controls[0].relevance_score == pytest.approx(0.85)
