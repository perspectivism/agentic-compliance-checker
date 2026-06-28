# Architecture

> **Living architecture doc.** The core topology is stable. Component descriptions and
> diagrams update as milestones are implemented — node contracts, state shape, and tool
> schemas fill in as each milestone lands.

## Core design choice

Deterministic evidence collection is separated from LLM reasoning. The LLM never
inspects arbitrary files or executes repo logic — it receives **structured evidence**
from read-only MCP tools and **retrieved control context** from the knowledge base,
then reasons over those. This is what makes verdicts auditable and the system safe
against untrusted input.

## Components

```mermaid
flowchart TD
    CLI([CLI<br/>assess target])

    CLI -->|"① validate + prepare target"| LOADER[Safe Repo Loader<br/>validate · bound · no execution]
    LOADER -->|produces| REPO[(target repo<br/>untrusted · never executed)]

    CLI -->|"② run assessment"| SUPERVISOR

    subgraph GRAPH [assessment graph]
        SUPERVISOR[Supervisor<br/>routing · iteration count · stop conditions]

        SUPERVISOR -->|1 · retrieve context| RETRIEVER[Control Retriever<br/>RAG / exact+semantic lookup]
        RETRIEVER -->|retrieve| KB[(controls KB<br/>trusted)]

        SUPERVISOR -->|2 · collect evidence| COLLECTOR[Evidence Collector<br/>deterministic MCP tools]
        COLLECTOR -. stdio .-> MCP[[MCP server<br/>read + scan tools · read-only]]

        SUPERVISOR -->|3 · synthesize| SYNTH[Synthesizer<br/>LLM · structured verdict]
        SUPERVISOR -->|4 · verify| VERIFIER{Verifier · LLM<br/>claim backed by evidence?}

        VERIFIER -->|yes| PASS([evidence-backed report + audit log])
        VERIFIER -->|no · attempts remain| SUPERVISOR
        VERIFIER -->|no · cap reached| FAIL([downgraded report<br/>verifier failed])
    end

    MCP -->|read-only| REPO
```

The two data sources are kept on opposite sides of a trust boundary: the **controls
KB is trusted**, the **target repo is untrusted**. The MCP server is the only layer
permitted to read repository files, and it returns structured fields, not raw dumps.

## Control flow (the verifier loop)

```mermaid
stateDiagram-v2
    [*] --> Supervisor
    Supervisor --> Retrieve: select control
    Retrieve --> Collect: control text ready
    Collect --> Synthesize: evidence collected
    Synthesize --> Verify: draft verdict
    Verify --> Final: passed (evidence backs the claim)
    Verify --> Supervisor: failed & attempts remain
    Verify --> Final: failed & attempts exhausted (downgrade + verifier notes)
    Final --> [*]
```

Required conditional behavior:
- Verifier **passes** → emit the verdict.
- Verifier **fails and attempts remain** → route back to evidence/retrieval and revise.
- Verifier **fails and attempts exhausted** → emit a downgraded verdict with verifier notes.

The loop is bounded by **two** independent caps: a `max_verifier_attempts` counter in
state and the LangGraph `recursion_limit`. It can never loop forever.

## LangGraph

Use `StateGraph` for explicit state transitions and conditional edges. Specialist
nodes are `create_agent` agents (which compile to subgraphs) added as graph nodes;
the supervisor and verifier routing are plain conditional edges. See typed state in
[`docs/SPEC.md`](SPEC.md).

## MCP server

Bounded, read-only tools. The initial tool surface is `list_repo_files`, `read_file_slice`,
`scan_secrets`, `scan_iac_security`, and `scan_ci_security`. Scanner tools return structured
`ToolFinding` records; the Evidence Collector normalizes these into `EvidenceRef` entries
before the Synthesizer reasons over them. Recommended transport for local v1 is **stdio**
(spawned as a subprocess by `langchain-mcp-adapters` inside the same container).
`streamable-http` is the option if it's ever deployed as a separate service.

## RAG store

Small, versioned controls KB. **Chroma** with a persist directory is the default
(local, survives restarts); FAISS or an in-memory store is fine for tests. Each KB
entry carries: control ID, family, plain-English requirement, expected positive
evidence, negative evidence, not-assessable notes, and scanner hints.

Retrieval is **hybrid**: semantic over the control text, deterministic/structured over
the repo (regex/AST via MCP tools). Embedding Terraform and hoping is *not* how repo
evidence is found — see [`docs/DECISIONS.md`](DECISIONS.md) D2.

**Embeddings are a separate model type from the chat model.** The chat model is freely
swappable (LangChain `init_chat_model`), but switching chat providers doesn't supply an
embedding model, and Anthropic doesn't offer one (Voyage AI is their recommendation).
Default to a local, no-API-key embedding model (FastEmbed/onnx or sentence-transformers)
so only one cloud key is needed; OpenAI `text-embedding-3-small` is the alternative.
Changing the embedding model means re-running `ingest-controls` — vectors from different
models aren't comparable, so the KB must be rebuilt.

## Observability

Capture per run: request ID, selected controls, node timings, tool calls, verifier
attempts, final verdicts, token/cost estimates when available, and errors. Minimum v1
is structured JSONL logs; LangSmith traces or OpenTelemetry/Phoenix are the upgrade.
Secret values are masked/hashed before they ever reach a log or report.
