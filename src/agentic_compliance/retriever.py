"""ControlsRetriever — exact and semantic lookup over the controls knowledge base.

Public API:
    ControlsRetriever(controls, vector_store)  — construct from pre-built parts
    .get_by_id(control_id)                    — exact O(1) lookup; None if not found
    .get_by_ids(control_ids)                  — ordered batch lookup; unknown IDs dropped
    .search(query, k)                         — semantic top-k; returns ControlEntry list
    .search_with_scores(query, k)             — same but with normalized relevance scores
    ControlsRetriever.from_yaml(...)           — build retriever from YAML + embeddings
    ControlsRetriever.from_persisted(...)      — load retriever from persisted Chroma store

The class accepts a vector_store parameter so tests can inject any store (including
fake implementations) without loading a real model or making API calls.

Must NOT read repository files. Must NOT produce verdicts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .kb import (
    _DEFAULT_CONTROLS_PATH,
    ControlEntry,
    build_exact_index,
    ingest_controls,
    init_embeddings,
    load_controls,
)


class ControlsRetriever:
    """Wraps exact-ID lookup and semantic search over the controls KB."""

    def __init__(self, controls: list[ControlEntry], vector_store: Any) -> None:
        self._index = build_exact_index(controls)
        self._store = vector_store

    def get_by_id(self, control_id: str) -> ControlEntry | None:
        """Return the ControlEntry for control_id, or None if not in the rubric."""
        return self._index.get(control_id)

    def get_by_ids(self, control_ids: list[str]) -> list[ControlEntry]:
        """Return ControlEntry objects for the given IDs, preserving order.

        Unknown IDs are silently dropped (same safe-by-default policy as search).
        The entries come from the in-memory _index — no file I/O.
        """
        return [self._index[cid] for cid in control_ids if cid in self._index]

    def search(self, query: str, k: int = 3) -> list[ControlEntry]:
        """Return up to k controls ranked by semantic similarity to query.

        Results that lack a recognised control_id in metadata are silently dropped
        (shouldn't happen with a well-formed ingest, but safe by default).
        """
        docs = self._store.similarity_search(query, k=k)
        results: list[ControlEntry] = []
        for doc in docs:
            cid = doc.metadata.get("control_id", "")
            entry = self._index.get(cid)
            if entry is not None:
                results.append(entry)
        return results

    def search_with_scores(self, query: str, k: int = 3) -> list[tuple[ControlEntry, float]]:
        """Return up to k controls with normalized relevance scores (0–1, higher=better).

        Chroma's similarity_search_with_score returns L2 distance (lower=better). For
        unit-normalized embeddings (e.g. all-MiniLM-L6-v2) L2 distances are in [0, 2],
        so `1 - distance` collapses most real-world scores to 0.0. The correct linear
        mapping is `1 - distance / 2`, which maps [0, 2] → [1, 0]. Results with an
        unrecognised control_id in metadata are silently dropped.
        """
        docs_and_scores = self._store.similarity_search_with_score(query, k=k)
        results: list[tuple[ControlEntry, float]] = []
        for doc, distance in docs_and_scores:
            cid = doc.metadata.get("control_id", "")
            entry = self._index.get(cid)
            if entry is not None:
                relevance = max(0.0, min(1.0, 1.0 - distance / 2.0))
                results.append((entry, relevance))
        return results

    @classmethod
    def from_yaml(
        cls,
        controls_path: Path | None = None,
        embeddings: Any = None,
        store_path: Path | None = None,
    ) -> ControlsRetriever:
        """Build a retriever from the YAML rubric, embedding on the fly.

        controls_path defaults to data/controls.yaml relative to the package root.
        embeddings defaults to init_embeddings() (reads EMBEDDINGS_MODEL env var).
        store_path is optional; omit for an ephemeral in-memory store.
        """
        if controls_path is None:
            controls_path = _DEFAULT_CONTROLS_PATH
        controls = load_controls(controls_path)
        vector_store = ingest_controls(
            controls_path=controls_path,
            store_path=store_path,
            embeddings=embeddings,
        )
        return cls(controls, vector_store)

    @classmethod
    def from_persisted(
        cls,
        store_path: Path,
        embeddings: Any = None,
        controls_path: Path | None = None,
    ) -> ControlsRetriever:
        """Load a retriever from a persisted Chroma store without re-ingesting.

        Raises FileNotFoundError if store_path does not exist — callers should
        surface this as "run 'ingest-controls' first." No silent fallback.
        """
        from langchain_chroma import Chroma  # noqa: PLC0415

        # Check for the Chroma SQLite file, not just the directory — an empty
        # directory passes os.path.exists() but has no ingested data.
        if not (store_path / "chroma.sqlite3").exists():
            raise FileNotFoundError(
                f"No persisted knowledge base at {store_path!r}. "
                "Run 'agentic-compliance ingest-controls' first."
            )
        if controls_path is None:
            controls_path = _DEFAULT_CONTROLS_PATH
        if embeddings is None:
            embeddings = init_embeddings()
        controls = load_controls(controls_path)
        vector_store = Chroma(
            persist_directory=str(store_path),
            embedding_function=embeddings,
            collection_name="controls",
        )
        return cls(controls, vector_store)
