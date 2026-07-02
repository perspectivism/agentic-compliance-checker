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
- [x] M6 tests pass.
- [x] M7 tests pass.
- [x] M8 tests pass.
- [x] Full `pytest` passes.

## Evaluation

- [x] Golden dataset stub exists.
- [x] Golden set generated with a different model, spot-checked, and frozen (`data/golden_set.yaml`).
- [x] Golden-set validation tests run in the fast lane (every check-in).
- [x] Evaluation runner works.
- [x] Classification report generated.
- [x] Macro-F1 threshold documented.
- [x] Failure cases are readable.

## Security

- [x] **Secure and fail-safe by default** is stated and enforced (see AGENTS.md / THREAT_MODEL.md).
- [x] No repo code execution.
- [x] Symlink escape test passes.
- [x] Prompt injection fixture test passes.
- [x] Secret redaction test passes.
- [x] Logs do not expose full secrets.
- [x] **Fail-closed:** a tool/scanner error yields `not_assessable`, never `satisfied` or a crash (tested).
- [x] **URL validation:** `file://`, `ext::`, `ssh://`, and internal/loopback URLs are rejected before clone (tested).
- [x] **Egress:** analysis tools make no network calls; only the clone + model/embeddings API reach the network.
- [x] **Dogfooding:** the project's own CI runs a dependency audit (pip-audit) and a secret scan (gitleaks).

## Packaging / Docker

- [x] `make build` succeeds.
- [x] `make test` (fast lane) passes in the container.
- [x] `make assess REPO=<url>` runs end-to-end (verified against
      `bridgecrewio/terragoat`: dynamic selection, 6 controls, 3 evidenced gaps,
      2 partials, secrets masked, verifier loop engaged, run log written).
- [x] Image runs as non-root.
- [x] `.env.example` documents required keys; `.env` is gitignored.
- [x] KB and reports persist via volumes (not baked into the image).

## Documentation and demo

- [x] Affected docs match implemented behavior and tested limitations.
- [x] Living-doc header notes removed from all docs.
- [x] README explains the architecture.
- [x] Architecture diagram included.
- [x] Demo command included.
- [x] Limitations stated.
- [x] `LICENSE` (Apache-2.0) and `NOTICE` present; copyright holder filled in.
- [x] Run inspection surface documented (JSONL run log; a Studio screenshot was
      deliberately not included).
- [ ] 2–3 minute demo video recorded if desired.
