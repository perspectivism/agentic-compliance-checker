# Design Decisions (and Rejected Alternatives)

This records the design decisions and the alternatives considered. What was rejected and
why is as important as what was chosen. Each entry is pre-filled with the reasoning behind
the design; mark `Status` as you confirm or revise during implementation.

Keep this honest. If the build proves a decision wrong, update the entry rather than hiding
it — a revised decision with a reason is part of the record.

---

### D1 — Orchestration: an explicit LangGraph `StateGraph`, not a prebuilt agent harness
**Context.** The output is a bounded, known-shape pipeline (collect → synthesize
→ verify → loop-if-weak) with a hard cap. The Lang stack offers three levels of
abstraction for this, and they are layers, not rivals: LangGraph (the graph runtime),
`create_agent` (a light prebuilt agent loop on top of it), and `deepagents` (a heavy
harness on top of that, bundling a planner, subagents, and a virtual filesystem).
**Decision.** Build the orchestration as an explicit `StateGraph` — a supervisor routing
to specialist nodes, with a conditional edge implementing the verifier loop. LLM leaf
nodes (Synthesizer, Verifier) are plain Python functions calling
`llm.with_structured_output(Schema).invoke(messages)`; `create_agent` is not needed
because each node makes a single structured call, not a multi-turn tool-use loop.
**Rejected.**
- (a) A single `create_agent` with all tools + a long system prompt — collapses the
  topology into one model-driven loop and *hides* the control-flow engineering that is
  the whole point; reads closer to prompt engineering than engineered orchestration.
- (b) `deepagents` — built for open-ended, long-horizon, context-heavy tasks (the
  Claude Code / Deep Research / Manus pattern) where the agent must plan its own path.
  This task is the opposite: the path is known, so the planner/subagent/filesystem
  machinery is overhead, and its "trust-the-LLM" default is the wrong posture when
  bounded, auditable, evidence-backed verdicts are the entire point.
- (c) A linear collect-then-generate chain — no way to re-synthesize (or later
  re-retrieve) when a verdict is unsupported.
**Why this is right here, not dogma.** For a single agent with a couple of tools,
`create_agent` alone would be correct and a graph would be over-engineering. The verifier
self-correction loop is the control-flow requirement that tips it to an explicit graph
(LangChain's own guidance: drop to LangGraph when the agent loop isn't the right shape).
If a sub-task ever became genuinely open-ended (e.g. "investigate this sprawling
monorepo"), a deep-agent could slot in as a single node without changing the spine.
**Status:** confirmed (M5). Explicit `StateGraph` with conditional edges; verifier loop
capped by `MAX_VERIFIER_ATTEMPTS` counter and `GRAPH_RECURSION_LIMIT`.

### D2 — Hybrid RAG: semantic over controls, deterministic over the repo
**Context.** Two very different inputs: control *text* (fuzzy) and repo *evidence* (exact).
**Decision.** Semantic retrieval over the control/rubric KB for dynamic control
selection; deterministic regex/AST/structured scans over the repo via MCP tools.
For the fixed v1 rubric (14 controls), the KB is pre-loaded at assess time — semantic
retrieval is built and available but not yet on the assess critical path.
**Rejected.** (a) Embed everything — vector search over Terraform is unreliable for
exact attributes ("is `storage_encrypted = true` present"). (b) Pure structured —
misses fuzzy "which control is relevant" matching. Naming this split is a deliberate
design choice, not an accident.
**Status:** confirmed (M3/M4). M5 pre-loads all controls into graph state via exact
`load_controls()` lookup; semantic retrieval via `ControlsRetriever` is available but
not yet wired as a graph node — sufficient for the fixed 14-control rubric.

### D3 — Tools exposed over a self-built MCP server (not in-process functions)
**Context.** The agent needs read-only repo-inspection tools; control lookup is handled by RAG over the controls KB, not an MCP tool.
**Decision.** Serve them from a FastMCP server, consumed via `langchain-mcp-adapters`.
**Rejected.** Plain in-process `@tool` functions — which would work identically for a
single-process POC. **Honest note:** MCP is *not strictly required* here. It is chosen
for two real reasons: it exercises MCP (a relevant skill), and it mirrors how the category
exposes this (Vanta ships its own MCP server). Being able to say *why* MCP, including
that it's not load-bearing, is the point.
**Status:** confirm after M2.

### D4 — Verifier self-correction loop as the trust mechanism
**Context.** For a compliance tool, a confidently-wrong "satisfied" is the failure
mode that matters most.
**Decision.** Every affirmative verdict must cite real scanner evidence; the verifier
rejects unsupported verdicts and routes back to re-synthesize (evidence already in state;
no re-scan needed), capped by an attempt counter **and** the LangGraph recursion limit.
**Rejected.** Single-pass generation — plausible but ungrounded verdicts. The loop is
the centerpiece differentiator.
**Status:** confirmed (M5). Loop capped at `MAX_VERIFIER_ATTEMPTS=3`; exhausted loop
force-downgrades to `not_assessable` with verifier notes in the rationale field.

### D5 — Scope: ~15 code-detectable technical controls, not a full baseline
**Context.** Most NIST 800-53 controls are procedural and not evidenceable from code.
**Decision.** Restrict v1 to a fixed technical subset (encryption, IAM least-privilege,
public exposure, audit logging, secrets, CI scanning, container hardening, …) and treat
procedural controls as a first-class `not_assessable` verdict.
**Rejected.** Running the full baseline — ~80% would come back "not assessable" and look
broken. Narrow-and-deep beats broad-and-shallow, especially with an agent generating code
at volume (quality degrades with scope).
**Status:** locked for v1; see D9 for thresholds.

### D6 — Static analysis of an ingested repo; read-only, never executed
**Context.** Input is an arbitrary, untrusted public repo.
**Decision.** Shallow clone (no submodules), read-only static analysis, never run install/
build/hooks. Treat all repo content as data, never instructions (indirect prompt injection).
**Rejected.** (a) Running or installing the repo — arbitrary code execution / RCE. (b) Live
cloud integration à la Vanta — that's data-engineering plumbing, not agentic AI, and the
wrong focus for this PoC. The static, point-in-time slice keeps the agentic
work central.
**Status:** locked; enforced by M1 + security fixtures.

### D7 — Evaluation: two layers (grounding + verdict accuracy)
**Context.** RAGAS scores RAG grounding, but the real output is a *classification*.
**Decision.** RAGAS (faithfulness, context precision/recall) for the grounding layer +
scikit-learn confusion matrix / `classification_report` for verdict accuracy.
**Rejected.** (a) RAGAS alone — necessary but not sufficient for a decision output.
(b) Verdict accuracy alone — doesn't measure whether retrieval/grounding was sound.
**Status:** confirm after M7; see D9.

### D8 — Golden labels: LLM-generated + spot-checked, by a *different* model
**Context.** Hand-labeling was the original blocker; we accept "good enough, not perfect."
**Decision.** Generate candidate labels with a strong model *different* from the one the
agent uses, hand-verify ~20–30%, then freeze. Report numbers as indicative, not certified.
**Rejected.** (a) Hand-labeling everything — too slow. (b) Same model labels and runs —
grades the model against its own opinion.
**Status:** confirm after M6.

### D9 — Held open until the first real run: eval-metric selection + rubric thresholds
**Context.** You don't know which metrics distinguish good from bad, or where verdict
boundaries should sit, until you've seen real outputs.
**Decision.** Treat the metric set and the rubric's satisfied/partial/gap thresholds as
"v1 — revise after first run." Build the harness, run it, *read the outputs*, then tighten.
**Rejected.** Freezing metrics/thresholds up front — locks in pre-contact guesses that an
agent will then faithfully implement, blind spots and all.
**Status:** revisit after first end-to-end run.

### D10 — Packaging: single Docker image; MCP server as a stdio subprocess
**Context.** "Launchable from Docker" with the least operational surface.
**Decision.** One image; the MCP server is spawned as a stdio subprocess by the app.
A non-root container (which also happens to satisfy control CM-2/CM-6). KB and reports
are volumes; API keys via `.env`.
**Rejected.** A separate MCP container — an unnecessary process boundary for a stdio server.
**Status:** confirmed (M2/M5). MCP server implemented; CLI `assess` subcommand wired to
`run_assessment` in M5. Docker packaging deferred to M8.

### D11 — Interface: CLI + rendered report, no custom web frontend
**Context.** The output is a structured report, consumed programmatically.
**Decision.** A CLI entrypoint (`assess` / `ingest-controls` / `eval`) plus a rendered
JSON/Markdown report. Traces and the eval output do the demoing.
**Rejected.** A hand-built React frontend — off-target: the interface is a CLI + report,
and a web frontend is scope this PoC doesn't need.
**Status:** locked for v1.

### D12 — Secure and fail-safe by default
**Context.** The input is an arbitrary untrusted repo, and the output is a tool that makes
compliance *claims*. Both raise the cost of an insecure or over-confident default.
**Decision.** Adopt a secure-by-default posture as a first-class principle, not a checklist:
fail closed (errors/timeouts/ambiguity → `not_assessable`, never `satisfied`, never a crash);
deny by default (allowlist file access; validate the repo URL's scheme/host before cloning);
least privilege (read-only tools, non-root container, scoped credentials); no egress beyond
the clone and the model/embeddings API; and dogfood the rubric — the project's own CI runs
dependency and secret scanning, the same bar it assesses others against.
**Rejected.** (a) Best-effort / fail-open — a tool that guesses `satisfied` when a scanner
errors is worse than useless for compliance. (b) Trusting the input URL — invites SSRF and
`ext::`/`file://` transport RCE. (c) Treating security as a list of point fixes rather than a
default posture — leaves the gaps the list didn't enumerate.
**Status:** enforced across M1 (URL validation, loader), M4/M5 (fail-closed), and CI (dogfooding).
