"""Golden evaluation set: schema validation/loading (M6) and the candidate generator."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

from agentic_compliance.golden import (
    GoldenSetError,
    class_coverage,
    load_golden_cases,
    verified_cases,
)
from agentic_compliance.kb import load_controls
from agentic_compliance.retriever import ControlsRetriever
from agentic_compliance.schemas import GoldenCase, VerdictClass

_STUB_PATH = Path(__file__).parent.parent / "data" / "golden_set_stub.yaml"
_FROZEN_PATH = Path(__file__).parent.parent / "data" / "golden_set.yaml"
_CONTROLS_PATH = Path(__file__).parent.parent / "data" / "controls.yaml"
_SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "generate_golden.py"


def _load_script_module():
    """Load scripts/generate_golden.py by path — it's a standalone CLI, not a package.

    Must register in sys.modules before exec_module: Pydantic resolves the
    `from __future__ import annotations` string annotation on _LabelCandidate via
    sys.modules[cls.__module__], so without this the class is left "not fully
    defined" and construction fails.
    """
    import sys

    spec = importlib.util.spec_from_file_location("generate_golden", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None, f"could not load spec for {_SCRIPT_PATH}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _case(
    *,
    id: str = "c1",
    repo_fixture: str = "secure_terraform_app",
    control_id: str = "SC-8",
    question: str = "Does the repo show encryption in transit?",
    expected_verdict: VerdictClass = VerdictClass.satisfied,
    expected_evidence_hints: list[str] | None = None,
    human_verified: bool = False,
) -> GoldenCase:
    return GoldenCase(
        id=id,
        repo_fixture=repo_fixture,
        control_id=control_id,
        question=question,
        expected_verdict=expected_verdict,
        expected_evidence_hints=(
            expected_evidence_hints if expected_evidence_hints is not None else ["TLS"]
        ),
        human_verified=human_verified,
    )


# ── Loader (M6 required tests) ──────────────────────────────────────────────────


class TestGoldenLoader:
    def test_stub_parses_and_conforms_to_schema(self):
        """The committed stub loads as a list of valid GoldenCase records."""
        cases = load_golden_cases(_STUB_PATH)
        assert len(cases) >= 1
        assert all(isinstance(c, GoldenCase) for c in cases)
        assert all(isinstance(c.expected_verdict, VerdictClass) for c in cases)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(GoldenSetError, match="not found"):
            load_golden_cases(tmp_path / "does_not_exist.yaml")

    def test_rejects_malformed_case(self, tmp_path):
        """A case with an invalid expected_verdict is rejected, not silently dropped."""
        bad = tmp_path / "bad_golden.yaml"
        bad.write_text(
            yaml.safe_dump(
                {
                    "cases": [
                        {
                            "id": "bad_001",
                            "repo_fixture": "secure_terraform_app",
                            "control_id": "SC-8",
                            "question": "x?",
                            "expected_verdict": "not_a_real_verdict",
                            "expected_evidence_hints": [],
                            "human_verified": False,
                        }
                    ]
                }
            )
        )
        with pytest.raises(GoldenSetError, match="bad_001"):
            load_golden_cases(bad)

    def test_rejects_missing_required_field(self, tmp_path):
        bad = tmp_path / "bad_golden.yaml"
        bad.write_text(yaml.safe_dump({"cases": [{"id": "no_control_id"}]}))
        with pytest.raises(GoldenSetError, match="no_control_id"):
            load_golden_cases(bad)

    def test_rejects_missing_cases_key(self, tmp_path):
        bad = tmp_path / "bad_golden.yaml"
        bad.write_text(yaml.safe_dump({"not_cases": []}))
        with pytest.raises(GoldenSetError, match="cases"):
            load_golden_cases(bad)

    def test_rejects_top_level_list_not_mapping(self, tmp_path):
        """A top-level YAML list (not a {cases: [...]} mapping) fails closed, not AttributeError."""
        bad = tmp_path / "bad_golden.yaml"
        bad.write_text(yaml.safe_dump(["a", "b"]))
        with pytest.raises(GoldenSetError, match="top-level"):
            load_golden_cases(bad)


class TestVerifiedCases:
    def test_only_human_verified_count_as_ground_truth(self):
        cases = [
            _case(id="a", human_verified=True),
            _case(id="b", human_verified=False),
            _case(id="c", human_verified=True),
        ]
        verified = verified_cases(cases)
        assert {c.id for c in verified} == {"a", "c"}


class TestClassCoverage:
    def test_counts_each_verdict_class(self):
        cases = [
            _case(id="a", expected_verdict=VerdictClass.satisfied),
            _case(id="b", expected_verdict=VerdictClass.satisfied),
            _case(id="c", expected_verdict=VerdictClass.gap),
        ]
        coverage = class_coverage(cases)
        assert coverage["satisfied"] == 2
        assert coverage["gap"] == 1
        assert coverage["partial"] == 0
        assert coverage["not_assessable"] == 0


class TestFrozenGoldenSet:
    """M6: the frozen data/golden_set.yaml meets the v1 minimum size/coverage bar.

    Skips cleanly until the real generate_golden.py run + human spot-check produces
    data/golden_set.yaml (a deliberate, occasional data-production step — not part of
    every check-in; see docs/MILESTONES.md M6 and docs/TEST_PLAN.md).
    """

    def test_meets_minimum_size_and_coverage(self):
        if not _FROZEN_PATH.exists():
            pytest.skip(
                "data/golden_set.yaml not generated yet — run scripts/generate_golden.py "
                "and spot-check before this check applies (docs/MILESTONES.md M6)."
            )
        cases = load_golden_cases(_FROZEN_PATH)
        verified = verified_cases(cases)
        assert len(verified) >= 20, f"expected >=20 human-verified cases, got {len(verified)}"
        coverage = class_coverage(verified)
        for verdict in VerdictClass:
            assert coverage[verdict.value] >= 3, (
                f"expected >=3 verified cases for {verdict.value}, got "
                f"{coverage[verdict.value]} (docs/EVAL_PLAN.md minimum)"
            )


# ── Generator script (fast lane: fake retriever + fake labeler, no model calls) ─


@pytest.fixture(scope="module")
def _script():
    return _load_script_module()


@pytest.fixture(scope="module")
def fake_retriever():
    """ControlsRetriever backed by DeterministicFakeEmbedding — no model download."""
    from langchain_chroma import Chroma
    from langchain_core.documents import Document
    from langchain_core.embeddings.fake import DeterministicFakeEmbedding

    controls = load_controls(_CONTROLS_PATH)
    docs = [
        Document(page_content=c.embed_text, metadata={"control_id": c.id, "name": c.name})
        for c in controls
    ]
    embeddings = DeterministicFakeEmbedding(size=384)
    vs = Chroma.from_documents(docs, embedding=embeddings, collection_name="test_golden_controls")
    return ControlsRetriever(controls, vs)


class TestRequireLabelerModel:
    def test_errors_when_unset(self, monkeypatch, _script):
        monkeypatch.delenv("GOLDEN_LABEL_MODEL", raising=False)
        with pytest.raises(RuntimeError, match="GOLDEN_LABEL_MODEL is not set"):
            _script._require_labeler_model()

    def test_errors_when_same_as_chat_model(self, monkeypatch, _script):
        monkeypatch.setenv("GOLDEN_LABEL_MODEL", "anthropic:claude-sonnet-5")
        monkeypatch.setenv("CHAT_MODEL", "anthropic:claude-sonnet-5")
        with pytest.raises(RuntimeError, match="must differ from CHAT_MODEL"):
            _script._require_labeler_model()

    def test_returns_value_when_valid_and_distinct(self, monkeypatch, _script):
        monkeypatch.setenv("GOLDEN_LABEL_MODEL", "openai:gpt-5.5")
        monkeypatch.setenv("CHAT_MODEL", "anthropic:claude-sonnet-5")
        assert _script._require_labeler_model() == "openai:gpt-5.5"


class TestRefuseOverwriteReason:
    """main() must not silently clobber a frozen file that already has verified cases."""

    @staticmethod
    def _write(path: Path, *, verified: bool) -> None:
        path.write_text(
            yaml.safe_dump(
                {
                    "cases": [
                        {
                            "id": "existing_001",
                            "repo_fixture": "secure_terraform_app",
                            "control_id": "SC-8",
                            "question": "x?",
                            "expected_verdict": "satisfied",
                            "expected_evidence_hints": [],
                            "human_verified": verified,
                        }
                    ]
                }
            )
        )

    def test_blocks_when_existing_file_has_verified_cases(self, tmp_path, _script):
        out = tmp_path / "golden.yaml"
        self._write(out, verified=True)
        reason = _script._refuse_overwrite_reason(out, force=False)
        assert reason is not None
        assert "human-verified" in reason

    def test_force_bypasses_the_block(self, tmp_path, _script):
        out = tmp_path / "golden.yaml"
        self._write(out, verified=True)
        assert _script._refuse_overwrite_reason(out, force=True) is None

    def test_allows_when_existing_file_has_no_verified_cases(self, tmp_path, _script):
        out = tmp_path / "golden.yaml"
        self._write(out, verified=False)
        assert _script._refuse_overwrite_reason(out, force=False) is None

    def test_allows_when_out_path_does_not_exist(self, tmp_path, _script):
        assert _script._refuse_overwrite_reason(tmp_path / "new.yaml", force=False) is None

    def test_allows_when_existing_file_is_malformed(self, tmp_path, _script):
        out = tmp_path / "golden.yaml"
        out.write_text("not: [valid, golden, - set")
        assert _script._refuse_overwrite_reason(out, force=False) is None


class TestMergeRegeneratedCases:
    """--fixture merges into an existing --out rather than replacing the whole file."""

    @staticmethod
    def _write_multi_fixture_file(path: Path) -> None:
        path.write_text(
            yaml.safe_dump(
                {
                    "cases": [
                        {
                            "id": "secure_terraform_app_SC-8_001",
                            "repo_fixture": "secure_terraform_app",
                            "control_id": "SC-8",
                            "question": "x?",
                            "expected_verdict": "satisfied",
                            "expected_evidence_hints": [],
                            "human_verified": False,
                        },
                        {
                            "id": "ci_no_security_repo_SI-2-RA-5_001",
                            "repo_fixture": "ci_no_security_repo",
                            "control_id": "SI-2/RA-5",
                            "question": "old, stale?",
                            "expected_verdict": "gap",
                            "expected_evidence_hints": [],
                            "human_verified": False,
                        },
                    ]
                }
            )
        )

    def test_preserves_other_fixtures_and_replaces_regenerated_one(self, tmp_path, _script):
        out = tmp_path / "golden.yaml"
        self._write_multi_fixture_file(out)
        new_case = _case(
            id="ci_no_security_repo_SI-2-RA-5_NEW",
            repo_fixture="ci_no_security_repo",
            control_id="SI-2/RA-5",
            question="regenerated",
        )

        merged = _script._merge_regenerated_cases(out, [new_case], {"ci_no_security_repo"})

        by_fixture = {c.repo_fixture: c for c in merged}
        assert len(merged) == 2
        assert by_fixture["secure_terraform_app"].id == "secure_terraform_app_SC-8_001", (
            "case from an untouched fixture must survive the merge unchanged"
        )
        assert by_fixture["ci_no_security_repo"].id == "ci_no_security_repo_SI-2-RA-5_NEW", (
            "stale case for the regenerated fixture must be replaced, not duplicated"
        )

    def test_out_path_missing_returns_just_new_cases(self, tmp_path, _script):
        new_case = _case(id="a")
        merged = _script._merge_regenerated_cases(
            tmp_path / "missing.yaml", [new_case], {"secure_terraform_app"}
        )
        assert merged == [new_case]

    def test_malformed_out_path_returns_just_new_cases(self, tmp_path, _script):
        out = tmp_path / "golden.yaml"
        out.write_text("not: [valid, golden, - set")
        new_case = _case(id="a")
        merged = _script._merge_regenerated_cases(out, [new_case], {"secure_terraform_app"})
        assert merged == [new_case]


class TestGenerateCandidates:
    @staticmethod
    def _fake_labeler(script_module):
        candidate = script_module._LabelCandidate(
            question="Does this fixture satisfy the control?",
            expected_verdict=VerdictClass.not_assessable,
            expected_evidence_hints=["fake hint"],
        )

        class _FakeLabeler:
            def invoke(self, messages):
                return candidate

        return _FakeLabeler()

    def test_generates_one_case_per_fixture_times_top_k(self, _script, fake_retriever):
        num_fixtures = len([p for p in _script.FIXTURES.iterdir() if p.is_dir()])
        cases = _script.generate_candidates(self._fake_labeler(_script), fake_retriever, top_k=2)
        assert len(cases) == num_fixtures * 2
        assert all(isinstance(c, GoldenCase) for c in cases)
        assert all(c.human_verified is False for c in cases)
        assert all(c.expected_verdict == VerdictClass.not_assessable for c in cases)

    def test_case_ids_are_unique(self, _script, fake_retriever):
        cases = _script.generate_candidates(self._fake_labeler(_script), fake_retriever, top_k=2)
        ids = [c.id for c in cases]
        assert len(ids) == len(set(ids))

    def test_fixture_names_restricts_generation(self, _script, fake_retriever):
        """fixture_names limits generation to just those fixtures — for adding one
        new fixture's cases without re-labeling (and re-billing) the whole set."""
        cases = _script.generate_candidates(
            self._fake_labeler(_script),
            fake_retriever,
            top_k=2,
            fixture_names=["secure_terraform_app"],
        )
        assert len(cases) == 2
        assert all(c.repo_fixture == "secure_terraform_app" for c in cases)

    def test_unknown_fixture_name_yields_no_cases(self, _script, fake_retriever):
        cases = _script.generate_candidates(
            self._fake_labeler(_script),
            fake_retriever,
            top_k=2,
            fixture_names=["does_not_exist"],
        )
        assert cases == []
