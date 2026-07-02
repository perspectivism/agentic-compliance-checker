# Test Fixture Repositories

Small synthetic repos used by the test suite and the evaluation harness. Each
targets specific controls/behaviors. They are **not** real projects.

| Fixture | Exercises | Expected signal |
|---|---|---|
| `ci_no_security_repo` | SI-2/RA-5 CI scanning (gap) | CI present but no security scanner → `gap` |
| `ci_partial_scanning_repo` | SI-2/RA-5 CI scanning (partial) | dependency audit present, no container/filesystem scanner → `partial` |
| `ci_scanning_repo` | SI-2/RA-5 CI scanning | Trivy/pip-audit present → `satisfied` |
| `hardcoded_secret_app` | IA-5 secrets handling | secret detected → `gap`; value MASKED in logs/report |
| `insecure_terraform_app` | AC-3, AC-6, SC-7, SC-28, SC-8 | negative evidence → `gap` |
| `no_iac_repo` | graceful degradation | infra controls → `not_assessable` (not `gap`) |
| `partial_network_app` | SC-7 boundary protection | app tier uses an SG reference, db tier allows internet-wide CIDR ingress → `partial` |
| `prompt_injection_repo` | indirect prompt injection | payload treated as data; verdicts unchanged |
| `secure_terraform_app` | SC-8, SC-28, AC-3, AC-6 | positive evidence → `satisfied` |

## Safety notes
- The "secret" in `hardcoded_secret_app` is AWS's **documented, non-functional
  example key** plus an obviously fake password. The scanner must detect the
  pattern; tests must assert the value is masked/hashed in any output.
- The injection text in `prompt_injection_repo` is deliberately adversarial. The
  test must prove it does **not** alter behavior.

## The symlink-escape fixture is created in-test, not committed
A symlink that escapes the repo root does not round-trip portably through a zip,
and its target is environment-specific. Create it inside the test (e.g. with
`tmp_path` and `os.symlink(tmp_path.parent / "secret", repo / "escape")`) and
assert the loader rejects/skips it. See `docs/TEST_PLAN.md`.

## Comment style in fixture source files
Header comments describing a fixture's intended verdict/control (e.g. "Intended GAP
evidence for AC-3...") are useful for a human reading the file, but golden-set
generation (`scripts/generate_golden.py`) reads fixture content verbatim to prompt
the labeler model — so that same text can hand the labeler the answer instead of
letting it reason from evidence. `golden_generation._strip_comment_lines()` filters
these out before they reach the labeler, but it only strips whole-line `#` comments;
it does not handle block comments (e.g. Terraform's `/* ... */`). Prefer `#` line
comments for this kind of explanatory header, and keep in mind golden labels are
human-reviewed regardless (`docs/DECISIONS.md` D8) — that review is the real
backstop, not the stripper.
