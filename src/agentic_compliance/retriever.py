"""ControlsRetriever — exact and semantic lookup over the controls knowledge base.

Public API:
    ControlsRetriever(controls, vector_store)  — construct from pre-built parts
    .get_by_id(control_id)                    — exact O(1) lookup; None if not found
    .search(query, k)                         — semantic top-k; returns ControlEntry list
    ControlsRetriever.from_yaml(...)           — convenience constructor from YAML + embeddings

The class accepts a vector_store parameter so tests can inject DeterministicFakeEmbedding
(or any Embeddings) without loading a real model or making API calls.

Must NOT read repository files. Must NOT produce verdicts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .kb import _DEFAULT_CONTROLS_PATH, ControlEntry, build_exact_index, load_controls


class ControlsRetriever:
    """Wraps exact-ID lookup and semantic search over the controls KB."""

    def __init__(self, controls: list[ControlEntry], vector_store: Any) -> None:
        self._index = build_exact_index(controls)
        self._store = vector_store

    def get_by_id(self, control_id: str) -> ControlEntry | None:
        """Return the ControlEntry for control_id, or None if not in the rubric."""
        return self._index.get(control_id)

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
        from .kb import ingest_controls  # noqa: PLC0415

        if controls_path is None:
            controls_path = _DEFAULT_CONTROLS_PATH
        controls = load_controls(controls_path)
        vector_store = ingest_controls(
            controls_path=controls_path,
            store_path=store_path,
            embeddings=embeddings,
        )
        return cls(controls, vector_store)
