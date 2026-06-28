# Definition of Done

The project is done when all items below are true.

## Core implementation

- [ ] Safe repo loader implemented.
- [ ] MCP server implemented.
- [ ] MCP tools return structured outputs.
- [ ] Controls KB exists.
- [ ] Retriever supports exact and semantic lookup.
- [ ] LangGraph `StateGraph` implemented.
- [ ] Typed graph state implemented.
- [ ] Synthesizer produces structured verdicts.
- [ ] Verifier loop implemented.
- [ ] Loop has attempt cap and recursion limit.
- [ ] Final report generated.

## Tests

- [ ] M1 tests pass.
- [ ] M2 tests pass.
- [ ] M3 tests pass.
- [ ] M4 tests pass.
- [ ] M5 tests pass.
- [ ] M6 tests pass.
- [ ] M7 tests pass.
- [ ] M8 tests pass.
- [ ] Full `pytest` passes.

## Evaluation

- [ ] Golden dataset stub exists.
- [ ] Golden set generated with a different model, spot-checked, and frozen (`data/golden_set.yaml`).
- [ ] Golden-set validation tests run in the fast lane (every check-in).
- [ ] Evaluation runner works.
- [ ] Classification report generated.
- [ ] Macro-F1 threshold documented.
- [ ] Failure cases are readable.

## Security

- [ ] **Secure and fail-safe by default** is stated and enforced (see AGENTS.md / THREAT_MODEL.md).
- [ ] No repo code execution.
- [ ] Symlink escape test passes.
- [ ] Prompt injection fixture test passes.
- [ ] Secret redaction test passes.
- [ ] Logs do not expose full secrets.
- [ ] **Fail-closed:** a tool/scanner error yields `not_assessable`, never `satisfied` or a crash (tested).
- [ ] **URL validation:** `file://`, `ext::`, `ssh://`, and internal/loopback URLs are rejected before clone (tested).
- [ ] **Egress:** analysis tools make no network calls; only the clone + model/embeddings API reach the network.
- [ ] **Dogfooding:** the project's own CI runs a dependency audit (pip-audit) and a secret scan (gitleaks).

## Packaging / Docker

- [ ] `docker compose build` succeeds.
- [ ] `make test` (fast lane) passes in the container.
- [ ] `docker compose run --rm app assess --repo-url <url>` runs end-to-end.
- [ ] Image runs as non-root.
- [ ] `.env.example` documents required keys; `.env` is gitignored.
- [ ] KB and reports persist via volumes (not baked into the image).

## Documentation and demo

- [ ] Affected docs match implemented behavior and tested limitations.
- [ ] Living-doc header notes removed from all docs.
- [ ] README explains the architecture.
- [ ] Architecture diagram included.
- [ ] Demo command included.
- [ ] Limitations stated.
- [ ] `LICENSE` (Apache-2.0) and `NOTICE` present; copyright holder filled in.
- [ ] Screenshots/traces included if available.
- [ ] 2–3 minute demo video recorded if desired.
