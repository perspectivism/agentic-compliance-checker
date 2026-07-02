"""Structured JSONL run logging for the compliance graph.

Each assessment run writes one line per event to artifacts/runs/<run_id>.jsonl via
instrument_node(), plus the direct log() calls in graph.py's collect/verify/finalize
nodes.

Security boundary, not an incidental design choice: every event carries structural
fields only — control IDs, tool names, finding/error counts, durations, verdict
labels, exception type names — never raw EvidenceRef/ToolFinding excerpts, repo file
content, verifier rationale text, or exception messages (see safe_error_fields).
The FinalReport already carries cited evidence; this log's job is to show what ran,
not to duplicate what was found.
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def safe_error_fields(exc: Exception) -> dict[str, Any]:
    """Structural, secret-safe fields describing an exception for the run log.

    Deliberately omits str(exc) entirely rather than truncating it: an exception
    message is unbounded, unpredictable free text, and length-capping only bounds
    size, not content — any secret-shaped text within the cap still reaches the log
    verbatim (e.g. a parse error that happens to quote the offending line). Only the
    exception's class name is logged, which can never carry evidence content. The
    real message still reaches the operator through normal exception propagation
    (stderr / CLI error output) — a separate stream from this auditable log, which
    exists to record *that* and *where* something failed, not to duplicate *what*
    the failure said.
    """
    return {"error_type": type(exc).__name__}


class RunLogger(ABC):
    """Emits one structured event per call. Implementations must never be handed
    raw evidence content — callers are responsible for passing only structural
    fields (control_id, tool name, finding counts, durations, verdict labels).
    """

    @abstractmethod
    def log(self, event: str, **fields: Any) -> None:
        """Record one event with the given structural fields."""


class JSONLRunLogger(RunLogger):
    """Appends one JSON object per line to artifacts/runs/<run_id>.jsonl."""

    def __init__(self, run_id: str, out_dir: Path = Path("artifacts/runs")) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        self.path = out_dir / f"{run_id}.jsonl"
        self._run_id = run_id

    def log(self, event: str, **fields: Any) -> None:
        record = {
            "event": event,
            "run_id": self._run_id,
            "ts": datetime.now(UTC).isoformat(),
            **fields,
        }
        with self.path.open("a") as f:
            f.write(json.dumps(record) + "\n")


class NoopRunLogger(RunLogger):
    """Discards every event — the default for callers that don't need a run log."""

    def log(self, event: str, **fields: Any) -> None:
        pass


class InMemoryRunLogger(RunLogger):
    """Collects events in a list instead of writing a file — for tests."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def log(self, event: str, **fields: Any) -> None:
        self.events.append({"event": event, **fields})


def instrument_node(
    node_name: str, fn: Callable[..., dict], logger: RunLogger
) -> Callable[..., dict]:
    """Wrap a graph node function with node_start/node_end timing and node_error events.

    Typed loosely (Callable[..., dict]) rather than generic over the node's state
    type: LangGraph's add_node() overloads pattern-match the wrapped callable's exact
    parameter kind (positional-only vs. keyword) against a Protocol, and a closure
    returned from a generic function doesn't preserve that shape precisely enough for
    static analysis to match it — every node here is ComplianceState-typed anyway, so
    there's no real genericity to preserve. Callable[..., dict] accepts any parameter
    list, which sidesteps the mismatch; runtime behavior is unaffected either way.

    On exception, logs the exception type (never its message — see
    safe_error_fields) and re-raises unchanged — this wrapper only observes node
    execution, it must not alter graph behavior.
    """

    def wrapped(state: Any) -> dict:
        logger.log("node_start", node=node_name)
        started = time.monotonic()
        try:
            result = fn(state)
        except Exception as exc:
            logger.log("node_error", node=node_name, **safe_error_fields(exc))
            raise
        logger.log(
            "node_end", node=node_name, duration_ms=round((time.monotonic() - started) * 1000, 2)
        )
        return result

    return wrapped
