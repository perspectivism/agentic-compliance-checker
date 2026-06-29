"""Controls knowledge base — loads the YAML rubric and builds a retrieval-ready store.

Public API:
    load_controls(path)              — parse data/controls.yaml into ControlEntry list
    build_exact_index(controls)      — O(1) dict keyed by control ID
    init_embeddings()                — build an Embeddings object from EMBEDDINGS_MODEL env var
    ingest_controls(...)             — embed controls and return (or persist) a Chroma store

Must NOT make network calls except inside the embeddings model (API-backed providers).
Must NOT read repository content — this module only touches the controls YAML.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

_DEFAULT_CONTROLS_PATH = Path(__file__).parent.parent.parent / "data" / "controls.yaml"
_DEFAULT_STORE_PATH = Path("./chroma_db")


class ControlEntry(BaseModel):
    """A single control from the rubric, loaded from data/controls.yaml."""

    id: str
    name: str
    positive_evidence: str
    gap_evidence: str
    notes: str
    scanner_hints: list[str]
    evidence_hints: list[str]
    embed_text: str


def load_controls(path: Path = _DEFAULT_CONTROLS_PATH) -> list[ControlEntry]:
    """Parse and validate the controls YAML. Raises on missing or malformed file."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [ControlEntry.model_validate(c) for c in raw["controls"]]


def build_exact_index(controls: list[ControlEntry]) -> dict[str, ControlEntry]:
    """Build an O(1) control-ID → ControlEntry dict for exact lookup."""
    return {c.id: c for c in controls}


def init_embeddings():
    """Instantiate an Embeddings object driven by the EMBEDDINGS_MODEL env var.

    EMBEDDINGS_MODEL=local (default)               → HuggingFaceEmbeddings all-MiniLM-L6-v2
    EMBEDDINGS_MODEL=openai:text-embedding-3-small → OpenAIEmbeddings (reads OPENAI_API_KEY)

    Import lazily so the module is importable without the agent stack installed.
    """
    model = os.environ.get("EMBEDDINGS_MODEL", "local")
    if model == "local":
        from langchain_huggingface import HuggingFaceEmbeddings  # noqa: PLC0415

        return HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    if model.startswith("openai:"):
        from langchain_openai import OpenAIEmbeddings  # noqa: PLC0415

        return OpenAIEmbeddings(model=model[len("openai:") :])
    raise ValueError(f"Unknown EMBEDDINGS_MODEL: {model!r}. Use 'local' or 'openai:<model-name>'.")


def ingest_controls(
    controls_path: Path = _DEFAULT_CONTROLS_PATH,
    store_path: Path | None = None,
    embeddings: Any = None,
) -> Any:
    """Embed controls and return a Chroma vector store.

    If store_path is None the store is ephemeral (in-memory) — suitable for tests
    and one-shot agent runs. If store_path is given, the directory is wiped and
    recreated so the call is always idempotent.

    embeddings defaults to init_embeddings() when not provided.
    Returns the langchain_chroma.Chroma instance.
    """
    from langchain_chroma import Chroma  # noqa: PLC0415
    from langchain_core.documents import Document  # noqa: PLC0415

    controls = load_controls(controls_path)
    if embeddings is None:
        embeddings = init_embeddings()

    docs = [
        Document(
            page_content=c.embed_text,
            metadata={"control_id": c.id, "name": c.name},
        )
        for c in controls
    ]

    kwargs: dict[str, Any] = {
        "documents": docs,
        "embedding": embeddings,
        "collection_name": "controls",
    }
    if store_path is not None:
        # Wipe the old store so repeated ingest is idempotent.
        if store_path.exists():
            shutil.rmtree(store_path)
        kwargs["persist_directory"] = str(store_path)

    return Chroma.from_documents(**kwargs)
