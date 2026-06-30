"""Controls knowledge base retriever — exact lookup and semantic search."""

import subprocess
import sys
from pathlib import Path

import pytest

from agentic_compliance.kb import ControlEntry, build_exact_index, ingest_controls, load_controls
from agentic_compliance.retriever import ControlsRetriever

_CONTROLS_PATH = Path(__file__).parent.parent / "data" / "controls.yaml"


# ── YAML loading ───────────────────────────────────────────────────────────────


class TestLoadControls:
    def test_loads_at_least_ten_controls(self):
        """YAML contains the full v1 rubric (14 controls)."""
        controls = load_controls(_CONTROLS_PATH)
        assert len(controls) >= 10

    def test_each_control_has_required_fields(self):
        """Every control entry has a non-empty id, name, embed_text, and nist_refs."""
        for c in load_controls(_CONTROLS_PATH):
            assert c.id, f"control missing id: {c}"
            assert c.name, f"control {c.id} missing name"
            assert c.embed_text, f"control {c.id} has empty embed_text"
            assert c.nist_refs, (
                f"control {c.id} has empty nist_refs (schema defaults to [] — add entries to controls.yaml)"
            )

    def test_controls_include_key_ids(self):
        """Spot-check that rubric IDs from SPEC.md are present."""
        ids = {c.id for c in load_controls(_CONTROLS_PATH)}
        for expected in ("SC-8", "AC-6", "SI-2/RA-5", "IA-5", "CM-2/CM-6"):
            assert expected in ids, f"Control {expected!r} missing from controls.yaml"

    def test_control_entry_is_pydantic_model(self):
        """load_controls returns validated ControlEntry objects."""
        controls = load_controls(_CONTROLS_PATH)
        assert all(isinstance(c, ControlEntry) for c in controls)


# ── Exact index ────────────────────────────────────────────────────────────────


class TestBuildExactIndex:
    def test_exact_id_lookup_returns_matching_control(self):
        """get_by_id returns the correct ControlEntry for a known ID."""
        index = build_exact_index(load_controls(_CONTROLS_PATH))
        entry = index.get("SC-8")
        assert entry is not None
        assert entry.id == "SC-8"
        assert "TLS" in entry.embed_text or "HTTPS" in entry.embed_text

    def test_exact_id_lookup_returns_none_for_unknown_id(self):
        """Missing IDs return None — no KeyError."""
        index = build_exact_index(load_controls(_CONTROLS_PATH))
        assert index.get("XX-999") is None

    def test_index_contains_all_loaded_controls(self):
        """Index has one entry per control (no duplicates, no missing)."""
        controls = load_controls(_CONTROLS_PATH)
        index = build_exact_index(controls)
        assert len(index) == len(controls)


# ── Ingest (fast lane, fake embeddings) ─────────────────────────────────────────


class TestIngestControls:
    def _fake_embeddings(self):
        from langchain_core.embeddings.fake import DeterministicFakeEmbedding

        return DeterministicFakeEmbedding(size=384)

    def test_creates_store_path_when_missing(self, tmp_path):
        """ingest_controls creates store_path when it doesn't exist yet."""
        store_path = tmp_path / "chroma_db"
        assert not store_path.exists()
        ingest_controls(
            controls_path=_CONTROLS_PATH, store_path=store_path, embeddings=self._fake_embeddings()
        )
        assert store_path.exists()
        assert any(store_path.iterdir()), "store_path should contain persisted Chroma files"

    def test_reingest_clears_contents_not_directory_entry(self, tmp_path):
        """Re-ingesting clears store_path's contents but never removes the directory itself.

        Regression test: ingest_controls() previously did shutil.rmtree(store_path)
        followed by Chroma recreating it — removing/recreating the directory entry
        requires write access to store_path's *parent*, and fails outright with
        EBUSY when store_path is a mount point (Docker named volume or bind mount),
        since the kernel refuses to rmdir an active mount regardless of permissions.
        Clearing contents in place avoids ever touching the directory entry itself.
        """
        store_path = tmp_path / "chroma_db"
        store_path.mkdir()
        sentinel = store_path / "stale_leftover.txt"
        sentinel.write_text("from a previous ingest")

        ingest_controls(
            controls_path=_CONTROLS_PATH, store_path=store_path, embeddings=self._fake_embeddings()
        )

        assert store_path.exists(), "store_path directory entry itself must survive re-ingest"
        assert not sentinel.exists(), "stale contents from the previous ingest must be cleared"

    def test_reingest_across_separate_processes_is_idempotent(self, tmp_path):
        """A second, independent ingest-controls run against an already-populated
        store_path succeeds — the real-world guarantee the CLI relies on.

        Deliberately runs two subprocesses rather than calling ingest_controls()
        twice in-process: chromadb's internal client cache is keyed by path, and
        reopening a persist_directory in the same process after its files were
        deleted and recreated underneath it confuses that cache (a chromadb
        same-process quirk, not a property of real usage — the CLI always exits
        after one ingest call, so this never happens in production). Two
        subprocesses reproduce the actual usage pattern.
        """
        store_path = tmp_path / "chroma_db"
        script = (
            "from pathlib import Path\n"
            "from agentic_compliance.kb import ingest_controls\n"
            "from langchain_core.embeddings.fake import DeterministicFakeEmbedding\n"
            "ingest_controls(\n"
            f"    controls_path=Path({str(_CONTROLS_PATH)!r}),\n"
            f"    store_path=Path({str(store_path)!r}),\n"
            "    embeddings=DeterministicFakeEmbedding(size=384),\n"
            ")\n"
        )
        for _ in range(2):
            result = subprocess.run(
                [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
            )
            assert result.returncode == 0, result.stderr

        assert store_path.exists()


# ── Retriever with fake embeddings (fast lane) ─────────────────────────────────


@pytest.fixture(scope="module")
def fake_retriever():
    """ControlsRetriever backed by DeterministicFakeEmbedding — no model download."""
    from langchain_chroma import Chroma
    from langchain_core.documents import Document
    from langchain_core.embeddings.fake import DeterministicFakeEmbedding

    controls = load_controls(_CONTROLS_PATH)
    docs = [
        Document(
            page_content=c.embed_text,
            metadata={"control_id": c.id, "name": c.name},
        )
        for c in controls
    ]
    embeddings = DeterministicFakeEmbedding(size=384)
    vs = Chroma.from_documents(docs, embedding=embeddings, collection_name="test_controls")
    return ControlsRetriever(controls, vs)


class TestRetrieverExact:
    def test_get_by_id_returns_sc8(self, fake_retriever):
        """get_by_id returns SC-8 entry."""
        entry = fake_retriever.get_by_id("SC-8")
        assert entry is not None
        assert entry.id == "SC-8"

    def test_get_by_id_returns_none_for_unknown(self, fake_retriever):
        """get_by_id returns None for an unrecognised control ID."""
        assert fake_retriever.get_by_id("XX-999") is None

    def test_get_by_id_returns_ac6(self, fake_retriever):
        """get_by_id returns AC-6 (least privilege)."""
        entry = fake_retriever.get_by_id("AC-6")
        assert entry is not None
        assert "privilege" in entry.name.lower() or "privilege" in entry.embed_text.lower()

    def test_get_by_id_returns_compound_id(self, fake_retriever):
        """Compound IDs like SI-2/RA-5 are stored and retrieved verbatim."""
        entry = fake_retriever.get_by_id("SI-2/RA-5")
        assert entry is not None
        assert entry.id == "SI-2/RA-5"

    def test_get_by_ids_preserves_order(self, fake_retriever):
        """get_by_ids returns entries in the requested order."""
        entries = fake_retriever.get_by_ids(["SC-8", "AC-6"])
        assert [e.id for e in entries] == ["SC-8", "AC-6"]

    def test_get_by_ids_drops_unknown(self, fake_retriever):
        """get_by_ids silently drops unrecognised IDs."""
        entries = fake_retriever.get_by_ids(["AC-6", "XX-999", "SC-8"])
        assert [e.id for e in entries] == ["AC-6", "SC-8"]

    def test_get_by_ids_empty_input(self, fake_retriever):
        """get_by_ids returns an empty list for empty input."""
        assert fake_retriever.get_by_ids([]) == []


class TestRetrieverSearch:
    def test_search_returns_list_of_control_entries(self, fake_retriever):
        """search() returns ControlEntry objects."""
        results = fake_retriever.search("encryption", k=3)
        assert all(isinstance(r, ControlEntry) for r in results)

    def test_search_respects_k_limit(self, fake_retriever):
        """search() returns at most k results."""
        results = fake_retriever.search("security", k=2)
        assert len(results) <= 2

    def test_search_stable_top_k(self, fake_retriever):
        """Same query twice returns the same ordered results (deterministic embeddings)."""
        r1 = fake_retriever.search("network transmission encryption", k=3)
        r2 = fake_retriever.search("network transmission encryption", k=3)
        assert [c.id for c in r1] == [c.id for c in r2]

    def test_search_returns_no_duplicates(self, fake_retriever):
        """Each result appears at most once."""
        results = fake_retriever.search("access control privilege", k=5)
        ids = [r.id for r in results]
        assert len(ids) == len(set(ids))

    def test_search_with_scores_all_in_range(self, fake_retriever):
        """All relevance scores from search_with_scores are in [0, 1]."""
        results = fake_retriever.search_with_scores("encryption access control TLS", k=5)
        assert results, "Expected at least one result"
        for _, score in results:
            assert 0.0 <= score <= 1.0, f"Score {score} out of [0, 1] range"


# ── Semantic accuracy (needs real embeddings — agent lane) ─────────────────────


class TestSemanticAccuracy:
    @pytest.mark.agent
    def test_tls_query_returns_sc8(self):
        """Semantic search for TLS/HTTPS retrieves SC-8 in the top results."""
        retriever = ControlsRetriever.from_yaml(_CONTROLS_PATH)
        results = retriever.search("TLS HTTPS transmission confidentiality encryption", k=5)
        ids = [r.id for r in results]
        assert "SC-8" in ids, f"SC-8 not in top-5 for TLS query; got: {ids}"

    @pytest.mark.agent
    def test_secrets_query_returns_ia5(self):
        """Semantic search for hardcoded secrets retrieves IA-5 in the top results."""
        retriever = ControlsRetriever.from_yaml(_CONTROLS_PATH)
        results = retriever.search(
            "hardcoded credentials API key password secret token committed", k=5
        )
        ids = [r.id for r in results]
        assert "IA-5" in ids, f"IA-5 not in top-5 for secrets query; got: {ids}"

    @pytest.mark.agent
    def test_vulnerability_scanning_query_returns_si2(self):
        """Semantic search for dependency scanning retrieves SI-2/RA-5."""
        retriever = ControlsRetriever.from_yaml(_CONTROLS_PATH)
        results = retriever.search("dependency vulnerability scanning pip-audit Trivy CVE", k=5)
        ids = [r.id for r in results]
        assert "SI-2/RA-5" in ids, f"SI-2/RA-5 not in top-5 for vuln-scan query; got: {ids}"


class TestFromPersisted:
    def test_missing_directory_raises_file_not_found(self, tmp_path):
        """from_persisted raises FileNotFoundError when the store directory does not exist."""
        missing = tmp_path / "no_such_db"
        with pytest.raises(FileNotFoundError, match="ingest-controls"):
            ControlsRetriever.from_persisted(missing)

    def test_empty_directory_raises_file_not_found(self, tmp_path):
        """from_persisted raises FileNotFoundError when the directory exists but is empty.

        An empty directory passes os.path.exists() but contains no Chroma data —
        the sqlite sentinel file is absent. This is the case when chroma_db/ is
        pre-created (e.g. by Docker volume) but ingest-controls has not been run.
        """
        empty_dir = tmp_path / "empty_chroma"
        empty_dir.mkdir()
        with pytest.raises(FileNotFoundError, match="ingest-controls"):
            ControlsRetriever.from_persisted(empty_dir)
