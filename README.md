# Agentic Compliance Checker

A self-verifying, multi-agent system that assesses source repositories and IaC against a
**code-detectable subset of NIST 800-53-inspired technical controls**, producing
evidence-backed `satisfied`, `partial`, `gap`, or `not_assessable` verdicts. It uses
explicit orchestration, tools, grounded verification, evaluation, and observability
rather than prompt engineering.

Point it at a public GitHub URL (shallow clone, read-only) or a local path; it
never executes repo content, pre-loads a rubric of controls from the knowledge base,
runs deterministic evidence scans against the repo, drafts a verdict per control, and
a **verifier loop** rejects any verdict that isn't backed by concrete scanner evidence
— re-synthesizing with the verifier's notes until the claim is grounded or a cap is hit.

## What it does
Multi-agent orchestration on LangGraph · typed state and explicit control flow · a
conditional verifier self-correction loop · a self-built MCP server for structured
repo analysis · a controls KB with semantic retriever (pre-loaded at assess time for the v1 rubric; dynamic control selection planned) · deterministic MCP tools over the repo ·
evidence-backed verdicts · a two-layer evaluation harness (grounding + verdict
accuracy) · unit tests and milestone gates · observability · and secure-by-default,
fail-closed ingestion of untrusted repositories.

## Architecture (orientation)

```mermaid
flowchart TD
    CLI([CLI<br/>assess target])

    CLI -->|validate + prepare target| LOADER[Safe Repo Loader<br/>validate · bound · no execution]
    LOADER -->|produces| REPO[(target repo<br/>untrusted · never executed)]

    CLI -->|run assessment| SUPERVISOR

    subgraph GRAPH [assessment graph · controls in state]
        SUPERVISOR[Supervisor<br/>routing · control_idx · stop]

        SUPERVISOR -->|collect evidence| COLLECTOR[Evidence Collector<br/>deterministic MCP tools]
        COLLECTOR -. stdio .-> MCP[[read-only MCP tools]]

        COLLECTOR -->|synthesize| SYNTH[Synthesizer<br/>LLM · structured verdict]
        SYNTH -->|verify| VERIFIER{Verifier · LLM<br/>claim backed by evidence?}

        VERIFIER -->|approved or cap reached| FINALIZE[FinalizeControl<br/>commit · downgrade if exhausted]
        FINALIZE -->|"advance to next control"| SUPERVISOR
        VERIFIER -->|"rejected · retries remain"| SYNTH
    end

    SUPERVISOR -->|all controls assessed| FINAL([FinalReport + audit log])

    KB[(controls KB<br/>trusted)] -->|"loaded before graph starts"| SUPERVISOR
    MCP -->|read-only| REPO
```

The repo URL or local path enters the **Safe Repo Loader** (not the graph); the loader validates it and safe-clones only URL inputs, then the graph runs. Only the **Evidence Collector** reads the target repo, and only through read-only MCP tools. The two data sources sit on opposite sides of a trust boundary — **controls KB trusted, target repo untrusted**. When the verifier cap is reached without a supported claim, the verdict is **downgraded** — `satisfied` cannot survive verifier failure.

Detailed component diagram and the deterministic-vs-LLM split: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## How it works

**Two data sources, two trust levels.** The controls knowledge base (Chroma by default) holds a rubric of NIST 800-53-inspired controls with definitions, evidence expectations, and pass/fail thresholds. It is trusted, static, and ingested once (`make ingest`). The target repository is untrusted and is never embedded into the vector store; it is inspected read-only through deterministic MCP tools.

**Per-control flow.** The Supervisor routes each control through three nodes in sequence:

1. **Evidence Collector** (deterministic MCP tools) — runs structured, read-only scanners against the repo: credential patterns, IaC misconfigurations, CI workflow gaps. Evidence facts come from tool outputs, not LLM inference. Control rubric context is pre-loaded into graph state before the graph starts (from `data/controls.yaml`), so no per-control retrieval step is needed in the graph.
2. **Synthesizer** (LLM) — takes control rubric context and evidence refs from the tools and produces a structured `ControlVerdict`: verdict class, rationale, confidence, and file/line citations.
3. **Verifier** (LLM) — checks whether the cited evidence actually supports the verdict. It operates only on what the Synthesizer provided; it makes no new tool calls.

**Verifier loop exit conditions.** If the verifier passes, the verdict moves to `FinalizeControl`. If it fails and attempts remain, the graph routes back to re-synthesize (evidence was already collected; the Synthesizer gets the verifier's rejection notes in its next prompt). If the cap is reached, the verdict is **downgraded** — `verifier_status: "failed"` with notes explaining why the claim was unsupported. There is also a **deterministic fail-closed guard**: any verifier-approved affirmative verdict (`satisfied`, `partial`, `gap`) is downgraded to `not_assessable` if scanner evidence is empty or collection errors occurred — this is enforced in code, not just in a prompt.

## Quickstart (Docker)

```bash
cp .env.example .env        # set CHAT_MODEL + the matching provider key (embeddings default to local)

make build                  # build the image
make test                   # fast test suite (-m "not agent")
make ingest                 # build the controls knowledge base
make assess REPO=https://github.com/OWNER/REPO  # assess a public repo
make eval                   # run the evaluation harness  [M7+]
```

Or with Compose directly:

```bash
docker compose build
docker compose run --rm app assess --repo-url https://github.com/OWNER/REPO
docker compose run --rm test
```

The image runs as non-root and spawns the MCP server as an in-container stdio
subprocess (no separate service). Subcommands print an honest "implemented at Mx"
message until that milestone lands, so the container is runnable from day one.

## Develop (langgraph dev)

The inner dev loop is the LangGraph dev server + Studio, not Docker — it hot-reloads and
lets you step through the graph, inspect state, and watch the verifier loop visually.

```bash
python3 -m venv .venv && source .venv/bin/activate  # Python 3.12+
pip install -e ".[dev,agent,studio]"
pre-commit install  # wire git hooks once per clone
langgraph dev  # in-memory server on http://127.0.0.1:2024 + opens LangGraph Studio
```

`langgraph dev` reads `langgraph.json` (which points at the compiled graph,
`src/agentic_compliance/graph.py:graph`), so it works once the graph exists (M5 onward).
State is in-memory and resets on restart — that's expected for dev.

**Docker vs. dev vs. Platform.** Three distinct things, don't conflate them:
- `langgraph dev` — local development/debugging (above). Your day-to-day loop.
- The `Dockerfile` here — packages the **CLI** for reproducible one-shot runs ("clone and
  it just works"). This is the run/ship artifact, not a dev tool, and not required to develop.
- `langgraph build` / LangGraph **Platform** — builds an API *server* image (needs
  Postgres/Redis) to serve the graph as a hosted agent. Intentionally **not used** here:
  the chosen interface is a CLI + report (see `docs/DECISIONS.md` D11), not a server.

## Why this isn't just RAG
A RAG app retrieves documents and writes an answer. Here, RAG is used only for the
controls KB — to answer "what does this control require?" The target repo is never
embedded or retrieved; it is inspected by deterministic, read-only MCP tools that
return structured evidence with file paths and line numbers. The LLM reasons over
those two bounded inputs, it does not freely browse the repo. On top of that: explicit
graph orchestration, typed tools, structured state, **a verifier loop that rejects
unsupported claims**, metrics, and milestone-gated tests.

## Build order
Milestone-gated M1→M8 — see [`docs/MILESTONES.md`](docs/MILESTONES.md). Do not advance
a milestone until its tests pass.

## Documentation
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, control flow, diagrams
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — design decisions and rejected alternatives
- [`docs/DEFINITION_OF_DONE.md`](docs/DEFINITION_OF_DONE.md) — completion checklist across implementation, tests, security, and docs
- [`docs/EVAL_PLAN.md`](docs/EVAL_PLAN.md) — golden set, verdict metrics (macro-F1), grounding metrics (RAGAS)
- [`docs/MILESTONES.md`](docs/MILESTONES.md) — gated build plan with acceptance checks
- [`docs/RUBRIC.md`](docs/RUBRIC.md) — the code-detectable control rubric
- [`docs/SPEC.md`](docs/SPEC.md) — system spec, schemas, tools, security
- [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md) — test strategy, markers, fast vs full lane
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — STRIDE analysis, trust boundaries, security acceptance tests

## Scope and limitations
**This is not a compliance tool.** It produces code-derived evidence mapped to a subset of
NIST 800-53 Rev. 5 technical control IDs; it does not assess procedural/organizational
controls or certify compliance against NIST 800-53, FedRAMP, SOC 2, HIPAA, CMMC, or ISO 27001.

Point-in-time static analysis of a repo, not continuous monitoring of live infra.
Restricted to technical controls evidenceable from code/IaC; procedural controls
return `not_assessable`. A passing scan is *evidence*, not an audit verdict — outputs
are decision-support, and golden labels are LLM-generated and spot-checked.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Copyright 2026 Pero Matic.

Provided "as is", without warranty of any kind (LICENSE §7–8). **Not a compliance tool** —
it produces evidence, not assurance; see "Scope and limitations" above. Use at your own risk.