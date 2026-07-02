# Evaluation Plan

> **Living evaluation plan.** The first end-to-end eval run has now happened (see
> "First real run results" below) — the metric set and gate mechanics are confirmed.
> Grounding metrics (RAGAS) remain an open, deferred question; update this doc again
> if that changes, or if a future run's failure pattern warrants a threshold change.

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
the fixture directly. A separate M7 audit re-derived all 54 labels directly from
scanner output (independent of the labeler's own reasoning) and confirmed all 54 are
consistent with what the deterministic tools actually produce.

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
- macro F1 >= 0.70 (default; override per run with `--threshold` or persistently with
  `EVAL_MACRO_F1_THRESHOLD` in `.env` — an invalid value fails loudly rather than
  silently weakening the gate).

Macro/weighted F1 are computed over the classes actually present in the scored data
(with the full frozen set that is all four); the confusion matrix and per-class report
always use the fixed 4-class label order for a stable shape across runs.

### Running the evaluation

Implemented in `src/agentic_compliance/evaluation.py`; `scripts/run_eval.py` and the
`eval` CLI subcommand are thin wrappers over the same logic.

```bash
make eval-local                 # venv; needs the agent stack + CHAT_MODEL/API key in .env
make eval-local THRESHOLD=0.6   # override the macro-F1 gate for one run
make eval                       # same, inside Docker (report lands in the artifacts volume)
```

How it works: only `human_verified` cases count; cases are grouped by fixture and the
real graph runs **once per fixture** with explicit control selection (exactly the
controls that fixture's cases name — no persisted KB needed, and every case is
guaranteed a prediction). Exit codes: `0` passed; `1` below the macro-F1 gate **or any
case errored** (a broken fixture must not silently shrink the eval until it passes);
`2` configuration problem (missing/malformed golden set, no verified cases, bad
threshold, unset `CHAT_MODEL`). A fixture whose assessment raises records an error for
its cases and never becomes a fake prediction. The JSON report is written even on
failure — a failing run's numbers are exactly the ones worth inspecting.

### Reading the metrics

Per class in `per_class` (each row is one verdict class):

- **precision** — of the cases the agent *called* this class, how many truly were.
  Low precision = false positives for that class.
- **recall** — of the cases that *truly are* this class, how many the agent found.
  Low recall = missed cases (false negatives) for that class.
- **support** — how many golden cases have that class as ground truth; a class with
  tiny support swings hard on a single miss, so read its precision/recall with that
  denominator in mind.

Which numbers matter most for *this* system:

- **`satisfied` precision is the overclaim-risk metric.** A drop means the agent is
  granting `satisfied` to cases that are really `partial`/`gap` — the one failure
  direction the fail-safe design exists to prevent. Treat regressions here as
  blockers, not tuning noise.
- **`gap` recall is the missed-gap metric.** A drop means real control failures are
  being reported as another class (`not_assessable`, `partial`, or worst-case
  `satisfied` — check the confusion matrix row to see which). Degrading to
  `not_assessable` is the safe direction, but this number shows the cost of that
  bias — watch the trend.
- **`partial` recall catches mixed evidence collapsing into a neighboring class**
  (`satisfied` or `gap`). This was exactly the first real run's failure mode: 0/3
  partials, all collapsed.
- **macro-F1 (the CI gate) weights every class equally**, which is deliberate:
  `not_assessable` dominates the golden set (39/54), so a plain accuracy or
  weighted-F1 number stays flattering even when a minority class is completely
  broken. The first real run showed the gap concretely: weighted-F1 0.90 while
  `partial` F1 was 0.00 and macro-F1 (0.67) correctly failed the gate.

The confusion matrix (rows = truth, columns = prediction, in `labels` order) tells
you *where* the misses went; `failures[]` carries each miss's predicted-verdict
rationale so you can tell a prompt problem from an evidence problem — check whether
the rationale is reasoning badly about evidence it had, or reasoning correctly about
evidence it never got.

### First real run results

Three runs against the frozen 54-case set, read in order (the D9 "build it, run it,
read the outputs, then tighten" loop):

| Run | macro-F1 | weighted-F1 | Failures | What changed after |
|---|---|---|---|---|
| 1 (baseline) | 0.674 | 0.901 | 4 (`partial`: 0/3; 1 SI-2/RA-5 miss) | Synthesizer/Verifier prompts had no definition of `partial` at all — mixed evidence always collapsed to `satisfied` or `gap`. Added an explicit `partial` definition to both prompts. |
| 2 | 0.905 | 0.961 | 2 (both SI-2/RA-5) | Both `partial_network_app` cases fixed. Remaining misses traced to absence findings (`container_scan_missing`, etc.) having *empty* excerpts — the Synthesizer could not see gap evidence that had no matched text. Added a message-fallback in `finding_to_evidence()`. Separately, golden-set audit (evidence-derived re-check of all 54 labels, not a re-run of the labeler) found `scan_ci_security`'s `secret_scan_missing` finding was mistagged `IA-5` — harmless while excerpts were empty, but would have flipped 3 correct `IA-5` `not_assessable` cases to false `gap` once excerpts became readable. Fixed the `control_hints` mapping before the fallback could surface the bug. |
| 3 (current) | **0.933** | **0.980** | 1 (`partial_network_app` AC-3: expected `partial`, got `gap`) | Both SI-2/RA-5 misses resolved; `not_assessable` row is 39/39 clean (the IA-5 fix caused zero regressions). The one remaining miss is a genuine close call, not a bug: AC-3's rubric gap text ("0.0.0.0/0 exposure") is a more literal match to the evidence than its positive text ("scoped security groups"), so the model under-weights the mixed signal for this specific control. Left as-is — chasing the single remaining `partial` case (support = 3) risks overfitting the prompt to one fixture. |

Per-class on the current run: `satisfied` P/R/F1 1.0/1.0/1.0 (n=5), `partial`
1.0/0.667/0.8 (n=3), `gap` 0.875/1.0/0.933 (n=7), `not_assessable` 1.0/1.0/1.0 (n=39).
Verifier: final pass rate stayed 1.0 across all runs (every control eventually gets an
approved verdict). What changed on the current run is first-pass behavior: ~98% of
controls were approved on attempt 1 (avg attempts 1.02, max 2) — down from 100% on the
baseline run — once the `partial` verifier rule gave it something to reject. A real
signal the loop is doing work, not just rubber-stamping.

Read against "Which numbers matter most" above: `satisfied` precision is 1.0 (no
overclaims) and `gap` recall is 1.0 (no missed gaps) — both of the failure directions
the fail-safe design most needs to prevent are clean on this run. The one open gap is
entirely within `partial` recall, the least safety-critical of the four cells.

## Grounding metrics

Optional but valuable:
- RAGAS faithfulness,
- context precision,
- context recall,
- response relevancy.

Caveat:
RAGAS metrics are LLM-as-judge and can vary. Pin the judge model and sample runs.

Status (M7): **deferred — not implemented in the v1 harness.** Verdict accuracy is the
required layer; RAGAS adds a judge-model dependency with its own cost and variance, and
with only ~15 non-`not_assessable` cases in the frozen set, sampled grounding scores
risk more noise than signal. If added later, sample it over affirmative verdicts only
(`not_assessable` has no answer to check faithfulness against) as a separate pass, not
bundled into the macro-F1 gate. The `ragas` dependency stays provisioned in the
`[agent]` extra. See `docs/DECISIONS.md` D7.

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

The verifier metrics ship in the M7 report's `verifier_stats` (aggregated from each
run's `ControlVerdict` records). Tool-call counts and per-node latency need the M8
observability layer (run/tool logs) and are added there.

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

The implemented report extends this minimum with `num_errors`, `threshold`, `passed`,
`labels` (the confusion-matrix row/column order), and `cases` (every case's
expected/predicted/rationale, not just the failures) for full auditability.

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
