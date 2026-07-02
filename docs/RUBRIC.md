# Code-Detectable Control Rubric

**This is not a compliance rubric.** These are NIST 800-53 Rev. 5 control IDs used as a
rubric for *code-derived evidence* — not an assurance claim. The tool does not certify
compliance against 800-53, FedRAMP, SOC 2, HIPAA, CMMC, or ISO 27001, and does not assess
procedural or organizational controls (those return `not_assessable`).

This rubric intentionally limits v1 to technical controls that can be reasonably assessed from source code, IaC, container definitions, and CI configuration.

> The satisfied/partial/gap boundaries below were confirmed by the first end-to-end
> evaluation runs — no threshold changes were needed (see
> [DECISIONS.md](DECISIONS.md#d9--evaluation-metrics-and-rubric-thresholds-resolved-after-the-first-real-run)
> D9). If future runs surface ambiguous cases, change the criteria here, deliberately,
> rather than letting the agent invent inconsistent rules.

Verdicts:
- `satisfied`
- `partial`
- `gap`
- `not_assessable`

## Controls

| ID | Name | Positive evidence | Gap evidence | Notes |
|---|---|---|---|---|
| SC-8 | Transmission confidentiality and integrity | HTTPS listeners, TLS 1.2+, HTTP-to-HTTPS redirect, secure ingress config | Plain HTTP listener exposed, weak TLS, no redirect | IaC-focused |
| SC-28 | Encryption at rest | S3 SSE, RDS/EBS encryption, storage encryption enabled | encryption disabled or absent on storage resources | Context-dependent |
| SC-12 | Cryptographic key management | KMS key, key rotation, managed key references | hardcoded keys, disabled rotation | Avoid claiming procedural key governance |
| IA-2 | MFA for privileged access | MFA condition in IAM policy, SSO/MFA config | privileged policy lacks MFA condition | Often partial/not-assessable |
| AC-6 | Least privilege | scoped IAM actions/resources | `Action: *`, `Resource: *`, broad admin policies | Strong code-detectable signal |
| AC-3 | Access enforcement/public exposure | S3 public access block, scoped security groups | public buckets, 0.0.0.0/0 to admin ports | High-confidence IaC evidence |
| SC-7 | Boundary protection | private subnets, security group references, segmented tiers | flat network, public DB, permissive ingress | Partial if only some tiers protected |
| AU-2/AU-12 | Audit logging | CloudTrail, ALB/S3 access logs, app audit logger | logging disabled or absent | Code/IaC only |
| AU-9 | Audit log protection | immutable/versioned log bucket, validation enabled | mutable log store, no validation | Often partial |
| SI-2/RA-5 | Vulnerability scanning | Trivy/Snyk/pip-audit/Dependabot in CI | no dependency scanning config | CI evidence |
| IA-5 | Secrets handling | env vars, secrets manager, OIDC, no committed secrets | hardcoded API keys/passwords/tokens | Scanner-backed |
| CM-2/CM-6 | Container baseline hardening | non-root USER, pinned base, minimal image | root user, latest tag, privileged | Docker/K8s evidence |
| CM-3 | Change control | CODEOWNERS, branch protection config, required reviews in CI metadata | no review/change gate evidence | May be not-assessable from repo alone |
| SI-4 | Monitoring and alerting | CloudWatch alarms, GuardDuty, alert rules, app metrics | no monitoring resources | Context-dependent |

## Not assessable controls

Always mark these as `not_assessable` unless external evidence is explicitly provided:
- personnel screening,
- security awareness training,
- incident response exercises,
- physical security,
- contingency plan tests,
- access review cadence,
- management approvals not represented in code.

## Evidence rules

A `satisfied` verdict requires:
1. at least one positive repo evidence item with a file path and line range,
2. verifier approval.

Control KB references explain the requirement but do not satisfy it on their own.

A `gap` verdict requires either:
1. direct negative evidence, or
2. absence of required evidence after a bounded search, with clear limitations.

A `partial` verdict is used when:
1. one part of the control is satisfied,
2. implementation is incomplete,
3. evidence exists but is not enough for `satisfied`.

A `not_assessable` verdict is used when:
1. evidence would require runtime/cloud/account access,
2. evidence is procedural,
3. the repo does not contain relevant implementation/IaC.
