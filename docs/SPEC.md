# Specification: Agentic Compliance Reference Implementation

> **Living specification.** This is the target contract for v1. It should evolve only
> when implementation or milestone tests prove the contract incomplete, unsafe, or
> inaccurate. Do not change it to match aspirational behavior — change it to match
> proven behavior.

## Problem statement

Build a small but production-shaped agentic AI system that can assess a software repository against a defined set of code-detectable technical security controls.

The project must show the difference between:
- prompt engineering around an LLM, and
- engineered agentic workflow design with state, tools, verification, tests, evaluation, and observability.

## Scope boundary

**This is not a compliance tool.** It produces code-derived evidence mapped to a subset of
NIST 800-53 Rev. 5 technical control IDs. It does not assess procedural or organizational
controls, and it does not certify compliance against NIST 800-53, FedRAMP, SOC 2, HIPAA,
CMMC, or ISO 27001. Control IDs are used as a rubric for evidence, not as an assurance claim;
a `satisfied` verdict means "code-derived evidence supports this control," not "this control
is met" in an audit sense.

## Goals

1. Implement multi-agent orchestration using LangGraph.
2. Implement a self-built MCP server with structured tools.
3. Implement RAG over a control knowledge base.
4. Produce evidence-backed verdicts for code-detectable controls.
5. Verify that every claim is supported by retrieved evidence.
6. Gate the implementation by milestones and unit tests.
7. Provide an evaluation harness that measures verdict accuracy and grounding.
8. Include safe handling of untrusted repositories.

## Non-goals

1. Do not build a full GRC platform.
2. Do not claim authoritative audit conclusions.
3. Do not attempt to assess procedural controls such as training, background checks, IR tabletop exercises, or physical security.
4. Do not execute code from analyzed repositories.
5. Do not build a large UI before the core workflow works.
6. Do not integrate real enterprise systems in v1.

## Primary user journey

A user provides **a public GitHub repository URL** (cloned read-only, shallow, no
submodules, never executed) **or** a local repository path (e.g. a test fixture).

The system:
1. Safely indexes allowed files (after a safe clone, if a URL was given).
2. Selects relevant code-detectable controls.
3. Retrieves control guidance from the controls KB.
4. Runs MCP evidence tools against the repository.
5. Drafts verdicts using a structured schema.
6. Verifies each verdict against file/line evidence.
7. Loops once or twice when evidence is weak; when the cap is reached, unsupported claims are downgraded.
8. Emits a final report with:
   - control ID,
   - verdict,
   - evidence file/line,
   - rationale,
   - confidence,
   - verifier status,
   - audit metadata.

## Verdict classes

- `satisfied`: sufficient concrete evidence supports the control.
- `partial`: some evidence exists but the control is incomplete.
- `gap`: evidence indicates the control is missing or violated.
- `not_assessable`: the control cannot be assessed from code/IaC alone.

## Required structured output

Each assessed control must produce:

```python
class ControlVerdict(BaseModel):
    control_id: str
    verdict: Literal["satisfied", "partial", "gap", "not_assessable"]
    evidence: list[EvidenceRef]
    rationale: str
    confidence: float
    verifier_status: Literal["passed", "failed", "not_run"]
    verifier_notes: str
```

```python
class EvidenceRef(BaseModel):
    source_type: Literal["repo_file", "control_kb", "tool_result"]
    path_or_id: str
    start_line: int | None
    end_line: int | None
    excerpt: str
```

## Agent topology

```text
Supervisor
  ├── Control Retriever
  ├── Evidence Collector
  ├── Synthesizer
  └── Verifier
```

### Supervisor
Owns graph routing, iteration count, and stop conditions. It does not make compliance
judgments — routing decisions are mechanical (check verifier result, check attempt
counter, select next node).

### Control Retriever
Retrieves control context (requirement text, evidence hints, scanner hints) from the
controls KB for the current control ID. It does not access the target repo or produce
repo evidence.

### Evidence Collector
Calls read-only MCP tools against the target repo and normalizes tool results into
`EvidenceRef` records. It does not assign verdicts and does not let LLMs read repository
files directly.

### Synthesizer
Drafts a `ControlVerdict` by reasoning over retrieved control context and collected
evidence. It must not invent evidence — every cited `EvidenceRef` must originate from
the Evidence Collector's output.

### Verifier
Checks whether the draft verdict's claims are supported by cited evidence. It does not
call tools or discover new facts. On failure, it reports the unsupported claim. The
Supervisor may route back to retrieval or collection, up to `max_verifier_attempts`.
When the cap is reached, it emits a downgraded verdict with `verifier_status: "failed"`
and notes explaining what was unsupported.

## Typed graph state

Minimum fields:

```python
class ComplianceState(TypedDict):
    request_id: str
    repo_path: str
    selected_controls: list[str]
    current_control_id: str | None
    control_contexts: list[dict]
    evidence: list[dict]
    draft_verdicts: list[dict]
    final_verdicts: list[dict]
    verifier_attempts: int
    max_verifier_attempts: int
    remaining_steps: int
    errors: list[dict]
    next_node: str
```

`max_verifier_attempts` defaults to `3`, set at graph initialization from the
positive-integer `MAX_VERIFIER_ATTEMPTS` environment variable if present. The LangGraph
`recursion_limit` is an independent hard cap that bounds the loop regardless of this
value.

## Required MCP tools

The tool surface is fixed at five for v1. New tools require a milestone justification —
do not add speculatively.

### Common finding schema

Scanner tools (`scan_secrets`, `scan_iac_security`, `scan_ci_security`) return a list of
`ToolFinding` records. The Evidence Collector normalizes findings into `EvidenceRef`
entries, and the Synthesizer decides which evidence supports a verdict.

```python
class ToolFinding(BaseModel):
    path: str                   # repo-relative file path
    start_line: int | None
    end_line: int | None
    finding_type: str           # specific finding, e.g. "public_ingress_admin_port"
    check_family: Literal[      # scanner family — for filtering and internal modularity
        "terraform", "dockerfile", "kubernetes_yaml",
        "logging_monitoring", "ci", "secrets",
    ]
    severity: Literal["high", "medium", "low", "info"]
    message: str                # human-readable explanation, e.g. "S3 bucket allows public access"
    control_hints: list[str]    # control IDs this finding maps to
    excerpt: str                # matched text; redacted if a secret value
    redacted: bool              # True if excerpt was masked before returning
    limitations: list[str]      # what this finding cannot determine
```

`list_repo_files` and `read_file_slice` do not produce `ToolFinding`. `list_repo_files`
returns structural file metadata the collector uses for discovery; `read_file_slice`
excerpts are normalized into `EvidenceRef` records with `source_type: "repo_file"`.

### `list_repo_files`
Returns repo-relative paths and metadata (size, extension) for allowed files, filtered
by the allowlist and size cap. The listing never includes `.git/`, binaries, generated
output, or files exceeding the size limit.

### `read_file_slice`
Returns a bounded, line-cited excerpt from a single allowed file. Inputs: path,
start_line, end_line. Output: the excerpt plus the actual start and end lines returned;
requests past EOF stop at the file's last line. Never executes the file.

### `scan_secrets`
Detects likely hardcoded credentials using regex patterns. Returns `ToolFinding` records
with `check_family: "secrets"`, `redacted: true`, and the secret value masked in
`excerpt`. The raw value is never returned.

### `scan_iac_security`
Detects IaC security patterns across multiple check families. Each family is internally
modular — independently testable — even though they share one MCP tool boundary:

- **Terraform:** public exposure (open ingress/egress), unencrypted storage, overly broad
  IAM (wildcards), missing encryption or versioning on S3, insecure security group rules.
- **Dockerfile:** running as root, `ADD` with remote URL, unpinned base images, secrets
  in `ENV` or `ARG`.
- **Kubernetes / YAML:** `privileged: true`, missing resource limits, `hostNetwork` /
  `hostPID`, missing security context.
- **Logging / monitoring signals:** absence of audit logging config, missing CloudTrail
  or equivalent where detectable in IaC.

Returns `ToolFinding` records with `check_family` set to `"terraform"`, `"dockerfile"`,
`"kubernetes_yaml"`, or `"logging_monitoring"` depending on the originating check family.

### `scan_ci_security`
Detects CI workflow security posture: presence of dependency scanning (pip-audit,
npm audit, Dependabot), container / image scanning (Trivy, Snyk, Grype), SAST steps,
and secret-scanning hooks. Also flags workflows with overly broad permissions or missing
`permissions:` declarations. Returns `ToolFinding` records with `check_family: "ci"`.

## Security requirements

1. Read-only repo access only.
2. Do not follow symlinks outside repo root.
3. Skip `.git`, `node_modules`, `vendor`, binary files, large files, and generated output.
4. Do not execute any repo file.
5. Treat README, comments, markdown, YAML, and config as untrusted content.
6. Strip or isolate imperative prompt-injection content in tool outputs.
7. All tools return structured data, not arbitrary raw dumps.
8. Step budget and recursion limit are mandatory.
9. **Fail closed.** On any tool error, timeout, or unparseable output, the affected control is `not_assessable` with an error note — never `satisfied`, and never an unhandled exception.
10. **Validate the repo URL before cloning.** Allow only `https` to permitted forge hosts; reject `file://`, `ext::`, `ssh://`, `git://`, scp-like `git@` syntax, and internal/private/loopback addresses.
11. **Egress allowlist.** The only outbound network calls are the clone and the model/embeddings API; analysis tools perform no network I/O.

## Held open until the first real run (resolve at M7)

Two parts of this spec are intentionally provisional and should be revised after the
first end-to-end run at M7, not frozen now (see `docs/DECISIONS.md` D9):
- **Eval-metric selection** — which grounding/verdict metrics actually distinguish
  good from bad is learned by reading real outputs.
- **Rubric thresholds** — the satisfied/partial/gap boundaries per control will be
  tuned once real repos surface ambiguous cases.

Build the harness and rubric to v1, run it, inspect outputs, then tighten.

## Acceptance criteria

The v1 project is complete when:

1. All milestones in `docs/MILESTONES.md` pass.
2. Unit tests pass.
3. A sample repo can be assessed end-to-end.
4. Final report includes evidence-backed verdicts.
5. Verifier rejects at least one unsupported claim in a fixture test.
6. Evaluation runner produces a metrics report.
7. README explains architecture and limitations clearly.
