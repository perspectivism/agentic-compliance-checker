# Definition of Done

The project is done when all items below are true.

## Core implementation

- [x] Safe repo loader implemented.
- [x] MCP server implemented.
- [x] MCP tools return structured outputs.
- [x] Controls KB exists.
- [x] Retriever supports exact and semantic lookup.
- [x] LangGraph `StateGraph` implemented.
- [x] Typed graph state implemented.
- [x] Synthesizer produces structured verdicts.
- [x] Verifier loop implemented.
- [x] Loop has attempt cap and recursion limit.
- [x] Final report generated.

## Tests

- [x] M1 tests pass.
- [x] M2 tests pass.
- [x] M3 tests pass.
- [x] M4 tests pass.
- [x] M5 tests pass.
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

- [ ] `make build` succeeds.
- [ ] `make test` (fast lane) passes in the container.
- [ ] `make assess REPO=<url>` runs end-to-end.
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
