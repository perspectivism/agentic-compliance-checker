# Threat Model

> **Living v1 threat model.** This starts with design-level risks and required
> mitigations. It should be updated as milestones turn those mitigations into concrete
> mechanisms and tests: M1 (URL validation, loader), M2 (MCP tool boundaries), M4
> (fail-closed evidence), M5 (capped verifier loop), M8 (log security, secret masking).

## Scope

This threat model covers v1 of the reference implementation:
- local repository ingestion,
- MCP read-only tools,
- RAG over controls KB,
- LangGraph agent workflow,
- final report generation,
- evaluation and logs.

## Assets

- host filesystem,
- user-provided repository,
- API keys/model credentials,
- evaluation data,
- tool outputs,
- final reports,
- logs/traces.

## Trust boundaries

1. User input crosses into the API/CLI.
2. Repository content crosses into repo loader.
3. Tool output crosses into LLM context.
4. LLM output crosses into report/evaluation.
5. Logs/traces may leave local machine if external observability is enabled.

## Secure-by-default posture

The system's defaults are the safe ones; unsafe behavior requires explicit, narrow opt-in:
- **Fail closed.** Errors, timeouts, parse failures, and ambiguity degrade to `not_assessable` (or `gap`), never `satisfied`, and never an unhandled crash.
- **Deny by default.** File access is allowlist-based; the repo URL is validated against an allowed scheme/host list before any clone.
- **Least privilege.** Read-only tools, non-root container, scoped credentials.
- **No egress.** The only outbound network calls are the clone and the model/embeddings API; tools make none.
- **Untrusted input.** Repo content is data, never instructions; trusted KB is kept separate.

## STRIDE analysis

### Spoofing
Risk:
- malicious repo pretends to contain trusted policy files or agent config.

Mitigations:
- do not load in-repo `.mcp.json`, `.claude`, hooks, or agent configs;
- separate trusted controls KB from untrusted repo content.

### Tampering
Risk:
- repo content attempts to alter verdicts through prompt injection.

Mitigations:
- label repo content as untrusted data;
- structured extraction;
- verifier requires evidence;
- no raw repo text as instructions.

### Repudiation
Risk:
- user cannot tell why a verdict was produced.

Mitigations:
- file/line evidence;
- tool-call logs;
- verifier notes;
- run IDs.

### Information disclosure
Risk:
- secret scanner leaks secrets into logs or reports;
- injection attempts to exfiltrate data via an outbound request from a tool.

Mitigations:
- redact secret values;
- store only hashes or masked excerpts;
- avoid full raw file dumps;
- **egress allowlist: tools make no network calls; the only outbound traffic is the clone and the model/embeddings API.**

### Denial of service
Risk:
- huge repos, binary files, recursive symlinks, many tool calls, graph loops.

Mitigations:
- file size caps;
- total byte caps;
- denylist;
- symlink checks;
- step budgets;
- recursion limit;
- timeout per tool call.

### Elevation of privilege
Risk:
- repo code executes on host;
- malicious Git features/hooks run;
- tools access files outside repo;
- malicious repo URL targets internal services (SSRF) or uses `file://` / `ext::` / `ssh` transport (`ext::` RCE, CVE-2022-24439).

Mitigations:
- never execute repo code;
- no install/build;
- **validate the repo URL before cloning: allow only `https` to permitted forge hosts; reject `file://`, `ext::`, `ssh://`, `git://`, and internal/private/loopback addresses;**
- shallow clone without submodules if cloning is implemented (clone-time RCE via crafted
  submodules/symlinks is real — e.g. CVE-2024-32002, CVE-2025-48384 — so never use
  `--recursive`, keep git patched, and set `core.symlinks=false` / `protocol.ext.allow=never`);
- path normalization;
- root containment checks;
- least-privileged environment variables.

## Security acceptance tests

1. Prompt-injection README does not control the agent.
2. Symlink outside root is rejected.
3. Binary/large files are skipped.
4. Secrets are masked in logs and reports.
5. Verifier rejects unsupported satisfied verdict.
6. Graph stops at iteration cap.
7. Malicious/invalid repo URL (`file://`, `ext::`, `ssh://`, internal/loopback address) is rejected before any clone.
8. A failing scanner/tool yields `not_assessable` — never `satisfied`, never an unhandled crash.
9. The analysis path opens no outbound network connections beyond the clone and the model/embeddings API.
