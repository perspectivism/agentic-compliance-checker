# Tests

Tests should be added milestone-by-milestone.

Required files:
- `test_scaffold.py`     (import/CLI canary — keeps the suite green from day one)
- `test_repo_loader.py`
- `test_mcp_tools.py`
- `test_controls_retriever.py`
- `test_evidence_node.py`
- `test_graph.py`
- `test_golden.py`       (schema/shape validation — fast lane, every check-in)
- `test_eval.py`
- `test_observability.py`

Mark tests that need a live model/network with `@pytest.mark.agent`; the CI fast lane
runs `pytest -m "not agent"` directly (no Docker/Make involved in CI itself). Reproduce
it locally with `make test-local`, or in Docker with `make test`. See `docs/TEST_PLAN.md`
→ "Test cadence".

Fixture repos should live under:

```text
tests/fixtures/repos/
```
