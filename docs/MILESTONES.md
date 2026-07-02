# Milestone-Gated Implementation Plan

Do not advance until the current milestone passes acceptance checks. A milestone is
not complete until affected docs match the implemented behavior.

Every milestone completion requires `make format`, `make lint-local`, and
`make test-local` to pass, in addition to the focused milestone test file listed
in each acceptance gate below.

## M1 — Safe repository loader

### Build
- Input resolution: accept a **public GitHub URL** (safe shallow clone — `--depth 1`,
  no submodules, never execute, into scratch space) **or** a local path.
- **URL validation before clone**: allow only `https` to permitted forge hosts; reject
  `file://`, `ext::`, `ssh://`, `git://`, and internal/private/loopback addresses.
- Repo path validation.
- File allowlist.
- Directory denylist.
- Symlink escape protection.
- File size caps.
- Text/binary detection.
- Line-indexed file reader.

### Unit tests
- Skips `.git`.
- Skips `node_modules`.
- Skips binary file.
- Rejects symlink escaping repo root (create the symlink in-test; see TEST_PLAN).
- **Rejects `file://`, `ext::`, `ssh://`, `git://`, scp-like `git@` syntax, and internal/private/loopback URLs before cloning.**
- Caps large files.
- Reads valid Terraform/YAML/Dockerfile/Python/Markdown files.
- Does not execute anything (and never runs install/build/hooks on clone).

### Acceptance gate
```bash
make test-local
```

Pass condition:
- all M1 tests green.

---

## M2 — MCP server with read-only tools

### Build
- FastMCP server.
- `list_repo_files`
- `read_file_slice`
- `scan_secrets`
- `scan_iac_security`
- `scan_ci_security`
- Scanner tools return `ToolFinding` records; all tools return structured outputs.
- `ToolFinding` records include `check_family`, `message`, `redacted`, and `limitations` fields.
- `scan_secrets` masks secret values (`redacted: true`); the raw value must never appear in tool output.
- Scanner checks are independently testable; `scan_iac_security` is internally split by Terraform, Dockerfile, Kubernetes/YAML, and logging/monitoring checks.

### Unit tests
- MCP tool functions can be called directly.
- Tool outputs match Pydantic schemas.
- Secret scanner finds fixture secret.
- IaC scanner finds public ingress fixture.
- CI scanner finds missing/present security scanner fixture.

### Acceptance gate
```bash
make test-all-local  # test-local would skip this file's @pytest.mark.agent checks
```

Pass condition:
- tools return structured, bounded outputs.
- no tool executes repo code.

---

## M3 — Controls knowledge base and retriever

### Build
- Control rubric as YAML/JSON.
- Ingestion script.
- Local vector store.
- Exact control-ID lookup.
- Semantic lookup.
- Test in-memory vector store option.

### Unit tests
- Control ID lookup returns exact control.
- Query for TLS returns SC-8.
- Query for secrets returns IA-5 secrets handling.
- Retriever returns stable top-k for fixtures.

### Acceptance gate
```bash
make test-all-local  # test-local would skip this file's @pytest.mark.agent checks
```

Pass condition:
- exact and semantic retrieval work.

---

## M4 — Evidence collector node

### Build
- Evidence collector node.
- Selects read-only MCP tools from the current control context / `scanner_hints`.
- Calls only deterministic MCP tools; no LLM and no direct filesystem access.
- Normalizes `ToolFinding` and file excerpts into `EvidenceRef` records.
- Records collection limitations/errors separately from evidence.
- Does not draft final verdicts yet.

### Unit tests
- SC-8 fixture collects plain-HTTP/TLS-gap evidence (`plain_http_listener` finding).
- AC-6 fixture collects wildcard IAM evidence.
- Secret fixture collects hardcoded secret evidence with redacted excerpt.
- No relevant evidence returns empty evidence plus a clear limitation/reason.
- Tool/scanner error or timeout records a fail-closed collection error for the control — no crash, no `satisfied`, and enough information for M5 to emit `not_assessable`.
- Collector uses control scanner hints to avoid irrelevant tools.
- `ToolFinding` fields normalize into `EvidenceRef` with repo-relative path, line range, excerpt, and `source_type: "tool_result"`.
- File excerpts from `read_file_slice` normalize into `EvidenceRef` with `source_type: "repo_file"`.

### Acceptance gate
```bash
make test-local
```

Pass condition:
- deterministic evidence collection works before LLM synthesis.

---

## M5 — LangGraph supervisor and verifier loop

### Build
- `ComplianceState`.
- Supervisor node.
- Synthesizer node using structured output.
- Verifier node.
- Conditional edge from verifier:
  - pass -> FinalizeControl
  - fail and attempts remain -> synthesize again (controls pre-loaded in state; no re-collect)
  - fail and attempts exhausted -> FinalizeControl downgrades to not_assessable
- Recursion limit.
- Max verifier attempts.
- Expose the compiled graph as a module-level `graph` in `src/agentic_compliance/graph.py` so `langgraph dev` / Studio can load it (matches `langgraph.json`).

### Unit tests
- Happy path completes.
- Unsupported `satisfied` verdict is rejected.
- Verifier loop retries once.
- Verifier loop stops at cap.
- Final state contains audit metadata.

### Acceptance gate
```bash
make test-local
# langgraph dev requires the studio extras (pip install -e ".[dev,agent,studio]"):
# langgraph.json must use module path "agentic_compliance.graph:graph" (not file path)
.venv/bin/langgraph dev  # Studio renders the supervisor + verifier-loop topology
```

Pass condition:
- graph cannot loop forever.
- unsupported claims are not silently accepted.
- Studio renders the graph (visual confirmation during development; no README
  screenshot required).

---

## M5.5 — Semantic control selection

### Build
- `control_selection.py`: `detect_features`, `build_selection_query`, `select_controls`, `explicit_selection`.
- `SelectedControl` and `SelectionResult` schemas in `schemas.py`.
- `ControlsRetriever.from_persisted(store_path)` — loads a persisted Chroma store without re-ingesting; raises `FileNotFoundError` with a clear "run ingest-controls first" message when missing.
- `ControlsRetriever.search_with_scores(query, k)` — returns `list[tuple[ControlEntry, float]]` with normalized relevance scores (0–1, higher=better).
- `run_assessment(controls=None)` uses dynamic selection from the persisted KB via `select_controls`.
- `run_assessment(controls=[...])` uses explicit selection — bypasses retriever loading entirely.
- CLI `--top-k-controls K` (default 6) for dynamic mode; rejected with a clear error when combined with `--controls`.
- Missing persisted KB with `controls=None` raises `FileNotFoundError` — no silent fallback to all controls.
- `FinalReport.selection: SelectionResult` as a typed first-class field (not buried in `audit`).

### Unit tests
- Feature detection finds Terraform (`.tf`), Dockerfile, GitHub Actions (`.github/workflows/`), Python files.
- Terraform resource-type sub-feature detection (bounded `.tf` content read) finds `aws_lb_listener`, `aws_s3_bucket`/`aws_s3_bucket_public_access_block`, `aws_iam_policy`, `aws_cloudtrail` and injects resource-specific query terms (TLS/HTTPS, S3/SSE, IAM, CloudTrail).
- Empty repo detects no features.
- Query construction from features produces a non-empty string; empty features returns the fallback query.
- Dynamic selection returns controls in ranking order with normalized relevance scores.
- `top_k` parameter is respected (at most k results returned).
- Relevance scores are in [0, 1] with higher = more relevant.
- Explicit selection produces `mode="explicit"` with no relevance scores (`None`).
- CLI rejects `--controls` combined with `--top-k-controls`.
- `FinalReport.selection` from a graph run matches the assessed controls.

### Acceptance gate

```bash
make lint-local
make test-all-local  # test-local would skip the real-embedding AC-6 selection regression
```

Pass condition:
- RAG control selection is on the `assess` path by default.
- Missing KB fails clearly — no silent fallback to all controls.
- Fast lane remains deterministic and credential-free (fake vector store in tests).

---

## M6 — Golden test-case generation

Produce the labeled evaluation set as a deliberate, reviewable step — not by
hand-writing every case, and not by trusting an LLM blindly (see `docs/DECISIONS.md` D8).

### Build
- A generator (`scripts/generate_golden.py`) that, for each fixture repo × relevant
  control, produces candidate cases (expected verdict + evidence hints) using a model
  **different from the one the agent under test uses**.
- A spot-check workflow: review a sample, correct disagreements, set `human_verified: true`.
- Freeze the reviewed cases as `data/golden_set.yaml` (separate from the committed
  `data/golden_set_stub.yaml`). Aim for ≥3 cases per verdict class where possible.
- Schema/shape validation for both files.

### Unit tests (deterministic — run every check-in)
- Golden set parses and conforms to the case schema.
- Loader rejects a malformed case.
- Frozen set has the minimum case count and class coverage.
- `human_verified` flag is respected (only verified cases count as ground truth).

### Note on cadence
The **generation step is manual/occasional** (it makes LLM calls and produces data you
review), so it is NOT run on every build. The **validation tests above are deterministic
and DO run every check-in**. The frozen `golden_set.yaml` is the committed artifact the
evaluation (M7) consumes. See `docs/TEST_PLAN.md` → "Test cadence".

### Acceptance gate
```bash
make test-local
.venv/bin/python scripts/generate_golden.py --dry-run
```

Pass condition:
- a frozen, schema-valid, spot-checked `data/golden_set.yaml` exists;
- validation tests are green in the fast lane.

---

## M7 — Evaluation harness

### Build
- Golden dataset loader (reads the frozen `data/golden_set.yaml` from M6).
- Run agent on fixture repos.
- Compute verdict accuracy using scikit-learn.
- Optional RAGAS grounding metrics.
- Save JSON metrics report.

### Unit tests
- Dataset schema validates (deterministic — fast lane).
- Classification report generated (mark live-agent runs `@pytest.mark.agent`).
- CI gate fails below configured macro-F1 threshold.
- Metrics file is written.

### Cadence
The eval runs the real LLM graph (costs tokens, non-deterministic), so it runs on
**manual dispatch only — when the graph, prompts, or rubric change** (see
`.github/workflows/eval.yml`), NOT on every check-in. Only the schema/loader tests run
in the fast lane.

### Acceptance gate
```bash
make test-local  # schema/loader portion in fast lane
make eval-local  # full run needs the agent stack + keys
```

Pass condition:
- eval runner works and reports results.

---

## M8 — Observability and demo polish

### Build
- JSONL run log.
- Node timing.
- Tool-call log.
- Verifier-attempt log.
- README architecture diagram (text/mermaid, already in `docs/ARCHITECTURE.md` —
  keep current with any node/state changes; no Studio screenshot needed).
- Demo sample repo.
- Optional LangSmith/OpenTelemetry integration.
- Hygiene: hoist golden-generation logic into `src/agentic_compliance/` (e.g.
  `golden_generation.py`); keep `scripts/generate_golden.py` as a thin wrapper
  (not a new CLI subcommand — golden generation is dev-time dataset production,
  not product surface). Payoff: tests import the module normally and the
  `importlib.util.spec_from_file_location` loader in `tests/test_golden.py` goes away.
- Hygiene: `generate_golden.py`'s `_repo_digest()` passes fixture files to the
  labeler LLM verbatim, including label-revealing header comments (e.g. "Intended
  GAP evidence for AC-3..."), which can bias candidate labels (does not affect the
  runtime assessment pipeline — that only ever sees scanner-derived `EvidenceRef`
  excerpts, confirmed during M7 review). Either strip comments in the digest or
  move label-revealing language out of fixture source files into
  `tests/fixtures/repos/README.md`. Bundle with the golden-generation hoist above.

### Unit tests
- Run log is emitted.
- Tool call is logged.
- Verifier attempt is logged.
- Errors are logged without leaking secrets.

### Acceptance gate
```bash
make test-local
```

Pass condition:
- a reviewer can inspect one run and understand what happened.

---

## Final release gate

```bash
make test-all-local
make eval-local
make build
make assess REPO=https://github.com/OWNER/REPO
```

Manual checks:
- The project builds and runs an assessment **from Docker** end-to-end.
- Run demo on sample repo.
- README explains limitations.
- Screenshots/traces added if available.
- No real secrets committed.
- No generated dependency/vendor folders committed.
