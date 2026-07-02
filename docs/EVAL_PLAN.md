# Evaluation Plan

> **Living evaluation plan.** Metric thresholds, grounding metric selection, and failure
> analysis are intentionally provisional until M7 produces real outputs to inspect.
> Update this doc after the first end-to-end eval run.

## Why evaluation matters

The system is not complete when it produces plausible answers. It is complete when it can be measured.

This project evaluates two different layers:

1. Grounding quality: Are answers supported by retrieved control context and tool evidence?
2. Verdict quality: Are the compliance classifications correct?

## Golden dataset

`data/golden_set_stub.yaml` is the committed starting point. The full labeled set is
**generated and frozen in M6** as `data/golden_set.yaml` (different-model labels,
spot-checked) and consumed here in M7. Run the eval against the frozen set rather than
regenerating labels each time.

Each row contains:
- fixture repo,
- control ID,
- question (what the label answers),
- expected verdict,
- expected evidence hints,
- whether human-verified.

As of M6, `data/golden_set.yaml` is frozen: 54 cases, all `human_verified: true`,
distribution `satisfied: 5, partial: 3, gap: 7, not_assessable: 39` — every class
clears the ≥3 minimum. A few candidates were corrected post-generation for reasons
beyond subjective spot-check: some controls (e.g. `CM-3`, `SI-4`, `SC-12`) have no
scanner support anywhere in `tools.py`, so no verdict but `not_assessable` is
achievable by the real pipeline regardless of what the labeler concluded from reading
the fixture directly.

### Golden generation workflow

```bash
make ingest-local
.venv/bin/python scripts/generate_golden.py --dry-run   # validate wiring, no LLM calls
make golden-local                                       # writes artifacts/golden_candidates.yaml
make golden-local FIXTURE=<fixture_name>                # add one fixture without re-billing the rest
.venv/bin/python -m pytest tests/test_golden.py
cp artifacts/golden_candidates.yaml data/golden_set.yaml # after reviewing and setting human_verified: true
```

Requires `GOLDEN_LABEL_MODEL` set in `.env` to a model different from `CHAT_MODEL`
(`docs/DECISIONS.md` D8) — the generator refuses to run otherwise.

Lifecycle:
- `artifacts/golden_candidates.yaml` — generated, unreviewed workspace (gitignored,
  never committed).
- `data/golden_set.yaml` — reviewed, frozen, committed ground truth.
- `human_verified: true` is the only thing M7 counts as ground truth — an unverified
  candidate is a provisional label, not an assertion of correctness.

## Verdict metrics

Use scikit-learn:

- confusion matrix,
- per-class precision,
- per-class recall,
- macro F1,
- weighted F1.

Initial CI threshold:
- macro F1 >= 0.70 once M7 is complete.

Before M7, the eval command may be a stub but should still run.

## Grounding metrics

Optional but valuable:
- RAGAS faithfulness,
- context precision,
- context recall,
- response relevancy.

Caveat:
RAGAS metrics are LLM-as-judge and can vary. Pin the judge model and sample runs.

## Agent-specific metrics

Track:
- verifier pass rate,
- verifier rejection count,
- average verifier attempts,
- max verifier attempts hit,
- tool-call count,
- tool-call errors,
- latency per node,
- total run latency.

## Evaluation output

Write JSON to:

```text
artifacts/eval/latest.json
```

Minimum schema:

```json
{
  "run_id": "string",
  "timestamp": "ISO-8601",
  "num_cases": 0,
  "macro_f1": 0.0,
  "weighted_f1": 0.0,
  "per_class": {},
  "confusion_matrix": [],
  "verifier_stats": {},
  "failures": []
}
```

## Human review

Use LLM-generated labels only as candidates, then freeze a verified subset:
- **Generate labels with a different model than the one the agent runs**, so you're not
  grading a model against its own opinion.
- Spot-check ~20–30% by hand; fix disagreements; freeze the verified set as ground truth.
- Report results as **indicative, not certified** — the labels carry the labeler model's
  errors (see `docs/DECISIONS.md` D8).

Minimum for v1:
- 20 to 40 labeled examples.
- At least 3 examples per verdict class when possible.
